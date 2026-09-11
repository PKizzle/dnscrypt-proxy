package main

import (
	"crypto/subtle"
	"encoding/json"
	"fmt"
	"html"
	"net"
	"net/http"
	"net/url"
	"os"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
	"unsafe"

	"codeberg.org/miekg/dns"
	"github.com/gorilla/websocket"
	"github.com/jedisct1/dlog"
)

// MonitoringUIConfig - Configuration for the monitoring UI
type MonitoringUIConfig struct {
	Enabled            bool   `toml:"enabled"`
	ListenAddress      string `toml:"listen_address"`
	Username           string `toml:"username"`
	Password           string `toml:"password"`
	TLSCertificate     string `toml:"tls_certificate"`
	TLSKey             string `toml:"tls_key"`
	EnableQueryLog     bool   `toml:"enable_query_log"`
	PrivacyLevel       int    `toml:"privacy_level"`         // 0: show all details, 1: anonymize client IPs, 2: aggregate only (no individual queries or domains)
	MaxQueryLogEntries int    `toml:"max_query_log_entries"` // Maximum number of recent queries to keep in memory (default: 100)
	MaxMemoryMB        int    `toml:"max_memory_mb"`         // Maximum memory usage in MB for recent queries (default: 1MB)
	PrometheusEnabled  bool   `toml:"prometheus_enabled"`    // Enable Prometheus metrics endpoint
	PrometheusPath     string `toml:"prometheus_path"`       // Path for Prometheus metrics endpoint (default: /metrics)
	// Peers are other instances of this proxy serving the same clients. When
	// set, the page shows the fleet rather than whichever instance happened to
	// answer the request for it.
	Peers            []string `toml:"peers"`
	PeerDiscoveryDNS string   `toml:"peer_discovery_dns"` // A name resolving to one address per instance
	// PeerDiscoveryResolver is the resolver to look that name up with. A proxy
	// is often configured not to use the system resolver at all -- the whole
	// point of it being the resolver -- which leaves discovery unable to
	// resolve a name that only a local resolver knows.
	PeerDiscoveryResolver string `toml:"peer_discovery_resolver"`
	// PeerToken authenticates requests between instances before they are given
	// the local detail used to construct the browser's aggregate.
	PeerToken string `toml:"peer_token"`
}

const (
	maxTopDomains               = 1000
	monitoringBroadcastMinDelay = 5 * time.Second
)

// MetricsCollector - Collects and stores metrics for the monitoring UI
type MetricsCollector struct {
	// Split locks for better concurrency
	countersMutex   sync.RWMutex // For totalQueries, cacheHits, cacheMisses, blockCount, QPS
	serverMutex     sync.RWMutex // For serverResponseTime, serverQueryCount
	domainMutex     sync.RWMutex // For topDomains
	queryLogMutex   sync.RWMutex // For recentQueries
	queryTypesMutex sync.RWMutex // For queryTypes

	startTime          time.Time
	totalQueries       uint64
	queriesPerSecond   float64
	lastQueriesCount   uint64
	lastQueriesTime    time.Time
	cacheHits          uint64
	cacheMisses        uint64
	blockCount         uint64
	queryTypes         map[string]uint64
	responseTimeSum    uint64
	responseTimeCount  uint64
	serverResponseTime map[string]uint64
	serverQueryCount   map[string]uint64
	topDomains         map[string]uint64
	recentQueries      []QueryLogEntry
	recentQueriesHead  int
	recentQueriesCount int
	maxRecentQueries   int
	maxMemoryBytes     int64
	currentMemoryBytes int64
	privacyLevel       int

	// events carries work off the serving goroutines; a single collector drains
	// it. Buffered so a burst is absorbed rather than felt by the queries that
	// caused it, and dropped rather than blocking when even that is not enough.
	events        chan metricEvent
	collectorStop chan struct{}
	droppedEvents uint64

	// Caching for expensive calculations
	cacheMutex      sync.RWMutex
	cachedMetrics   map[string]any
	cacheLastUpdate time.Time
	cacheTTL        time.Duration
	// dataVersion counts the changes the counters have seen. Computing a set of
	// metrics takes long enough for a query to be recorded while it happens, and
	// storing that set afterwards would otherwise put back numbers taken before
	// the change and keep them for a whole TTL.
	dataVersion atomic.Uint64

	// Prometheus metrics (optional)
	prometheusEnabled bool

	// Runtime context
	proxy *Proxy
}

// QueryLogEntry - Entry for the query log
type QueryLogEntry struct {
	Timestamp    time.Time `json:"timestamp"`
	ClientIP     string    `json:"client_ip"`
	Domain       string    `json:"domain"`
	Type         string    `json:"type"`
	ResponseCode string    `json:"response_code"`
	ResponseTime int64     `json:"response_time"`
	Server       string    `json:"server"`
	CacheHit     bool      `json:"cache_hit"`
	// DNSSECVerdict is empty when validation is switched off, which is not the
	// same as an answer nothing was concluded about.
	DNSSECVerdict string `json:"dnssec_verdict,omitempty"`
	DNSSECReason  string `json:"dnssec_reason,omitempty"`
}

// EstimateMemoryUsage estimates the memory usage of a QueryLogEntry in bytes
func (q *QueryLogEntry) EstimateMemoryUsage() int64 {
	// The slice owns the struct and keeps every string backing array reachable.
	// Keep this accounting in sync automatically when fields are added.
	return int64(unsafe.Sizeof(*q)) + q.estimateStringMemoryUsage()
}

func (q *QueryLogEntry) estimateStringMemoryUsage() int64 {
	return int64(
		len(q.ClientIP) +
			len(q.Domain) +
			len(q.Type) +
			len(q.ResponseCode) +
			len(q.Server) +
			len(q.DNSSECVerdict) +
			len(q.DNSSECReason))
}

func (mc *MetricsCollector) recentQueryCountLocked() int {
	return mc.recentQueriesCount
}

func (mc *MetricsCollector) evictOldestRecentQueryLocked() {
	if mc.recentQueryCountLocked() == 0 {
		return
	}
	oldest := &mc.recentQueries[mc.recentQueriesHead]
	mc.currentMemoryBytes -= oldest.estimateStringMemoryUsage()
	*oldest = QueryLogEntry{}
	mc.recentQueriesHead = (mc.recentQueriesHead + 1) % len(mc.recentQueries)
	mc.recentQueriesCount--
}

func (mc *MetricsCollector) appendRecentQueryLocked(entry QueryLogEntry) {
	if len(mc.recentQueries) == 0 || mc.maxRecentQueries <= 0 {
		return
	}
	entryStringsSize := entry.estimateStringMemoryUsage()
	ringMemoryBytes := int64(len(mc.recentQueries)) * int64(unsafe.Sizeof(QueryLogEntry{}))
	if ringMemoryBytes+entryStringsSize > mc.maxMemoryBytes {
		return
	}
	for mc.recentQueryCountLocked() > 0 &&
		(mc.currentMemoryBytes+entryStringsSize > mc.maxMemoryBytes ||
			mc.recentQueryCountLocked() >= mc.maxRecentQueries) {
		mc.evictOldestRecentQueryLocked()
	}
	if mc.currentMemoryBytes+entryStringsSize > mc.maxMemoryBytes {
		return
	}
	index := (mc.recentQueriesHead + mc.recentQueriesCount) % len(mc.recentQueries)
	mc.recentQueries[index] = entry
	mc.recentQueriesCount++
	mc.currentMemoryBytes += entryStringsSize
}

func (mc *MetricsCollector) snapshotRecentQueries(limit int) []QueryLogEntry {
	mc.queryLogMutex.RLock()
	defer mc.queryLogMutex.RUnlock()
	count := mc.recentQueryCountLocked()
	if limit <= 0 || limit > count {
		limit = count
	}
	recent := make([]QueryLogEntry, limit)
	for i := range recent {
		index := (mc.recentQueriesHead + count - limit + i) % len(mc.recentQueries)
		recent[i] = mc.recentQueries[index]
	}
	return recent
}

type resolverSnapshot struct {
	name          string
	proto         string
	total         uint64
	failed        uint64
	success       float64
	avgObservedMs float64
	lastUpdate    time.Time
	lastAction    time.Time
	status        string
	score         float64
	ageSeconds    float64
}

// MonitoringUI - Handles the monitoring UI
type MonitoringUI struct {
	config           MonitoringUIConfig
	metricsCollector *MetricsCollector
	httpServer       *http.Server
	upgrader         websocket.Upgrader
	clients          map[*websocket.Conn]bool
	clientsMutex     sync.Mutex
	proxy            *Proxy

	// Mutex for all WebSocket write operations to prevent races
	writesMutex sync.Mutex

	// WebSocket broadcast rate limiting
	broadcastMutex    sync.Mutex
	lastBroadcast     time.Time
	broadcastMinDelay time.Duration
	pendingBroadcast  bool

	// Prometheus metrics
	prometheusPath string
	peers          *peerCollector
}

// NewMonitoringUI - Creates a new monitoring UI
func NewMonitoringUI(proxy *Proxy) *MonitoringUI {
	dlog.Debugf("Creating new monitoring UI instance")

	if proxy == nil {
		dlog.Errorf("Proxy is nil in NewMonitoringUI")
		return nil
	}
	config := proxy.monitoringUI
	if config.PeerToken == "" {
		config.PeerToken = os.Getenv("DNSCRYPT_MONITORING_PEER_TOKEN")
	}

	// Set defaults for memory limits if not configured
	maxEntries := proxy.monitoringUI.MaxQueryLogEntries
	if maxEntries <= 0 {
		maxEntries = 100
	}
	maxMemoryMB := proxy.monitoringUI.MaxMemoryMB
	if maxMemoryMB <= 0 {
		maxMemoryMB = 1
	}
	maxMemoryBytes := int64(maxMemoryMB) * 1024 * 1024
	// Do not reserve a backing array whose structs alone exceed the configured
	// query-log budget. String contents are accounted as entries are appended.
	if memoryEntries := int(maxMemoryBytes / int64(unsafe.Sizeof(QueryLogEntry{}))); maxEntries > memoryEntries {
		maxEntries = memoryEntries
	}
	if maxEntries < 1 {
		maxEntries = 1
	}

	// Initialize metrics collector
	metricsCollector := &MetricsCollector{
		events:             make(chan metricEvent, 4096),
		collectorStop:      make(chan struct{}),
		startTime:          time.Now(),
		queryTypes:         make(map[string]uint64),
		serverResponseTime: make(map[string]uint64),
		serverQueryCount:   make(map[string]uint64),
		topDomains:         make(map[string]uint64),
		recentQueries:      make([]QueryLogEntry, maxEntries),
		maxRecentQueries:   maxEntries,
		maxMemoryBytes:     maxMemoryBytes,
		// The fixed ring's struct storage is resident even while it is empty.
		currentMemoryBytes: int64(maxEntries) * int64(unsafe.Sizeof(QueryLogEntry{})),
		privacyLevel:       proxy.monitoringUI.PrivacyLevel,
		// Initialize caching with 1 second TTL
		cacheTTL:      time.Second,
		cachedMetrics: make(map[string]any),
		// Initialize Prometheus
		prometheusEnabled: proxy.monitoringUI.PrometheusEnabled,
		proxy:             proxy,
	}

	dlog.Debugf("Metrics collector initialized with privacy level: %d", metricsCollector.privacyLevel)

	// Create and return the monitoring UI instance
	ui := &MonitoringUI{
		config:           config,
		metricsCollector: metricsCollector,
		upgrader: websocket.Upgrader{
			ReadBufferSize:  1024,
			WriteBufferSize: 1024,
			CheckOrigin: func(r *http.Request) bool {
				origin := r.Header.Get("Origin")
				if origin == "" {
					return true // Allow requests without Origin header (direct connections)
				}
				originURL, err := url.Parse(origin)
				if err != nil || originURL.User != nil || originURL.Host == "" ||
					originURL.Path != "" || originURL.RawQuery != "" || originURL.Fragment != "" {
					return false
				}
				return originURL.Scheme == requestScheme(r) && strings.EqualFold(originURL.Host, r.Host)
			},
		},
		clients: make(map[*websocket.Conn]bool),
		proxy:   proxy,
		// A dashboard is operational telemetry, not part of the DNS hot path.
		// Full fleet snapshots can contain thousands of retained queries.
		broadcastMinDelay: monitoringBroadcastMinDelay,
		// Initialize Prometheus path
		prometheusPath: func() string {
			if proxy.monitoringUI.PrometheusPath != "" {
				return proxy.monitoringUI.PrometheusPath
			}
			return "/metrics"
		}(),
	}

	ui.peers = newPeerCollector(ui)

	// Started with the instance rather than with the HTTP server: queries are
	// recorded whether or not anyone is currently serving the page.
	go ui.runCollector()

	return ui
}

// Start - Starts the monitoring UI
func (ui *MonitoringUI) Start() error {
	if !ui.config.Enabled {
		return nil
	}

	// Setup HTTP server
	mux := http.NewServeMux()
	mux.HandleFunc("/", ui.handleRoot)
	mux.HandleFunc("/api/metrics", ui.handleMetrics)
	mux.HandleFunc("/api/ws", ui.handleWebSocket)
	mux.HandleFunc("/static/monitoring.js", ui.handleStaticJS)
	mux.HandleFunc("/static/", ui.handleStatic)

	// Add Prometheus endpoint if enabled
	if ui.metricsCollector.prometheusEnabled {
		mux.HandleFunc(ui.prometheusPath, ui.handlePrometheus)
		dlog.Debugf("Prometheus metrics endpoint enabled at %s", ui.prometheusPath)
	}

	ui.httpServer = &http.Server{
		Addr:         ui.config.ListenAddress,
		Handler:      ui.basicAuthMiddleware(mux),
		ReadTimeout:  10 * time.Second,
		WriteTimeout: 10 * time.Second,
	}

	// Start HTTP server
	go func() {
		var err error
		if ui.config.TLSCertificate != "" && ui.config.TLSKey != "" {
			dlog.Noticef("Starting monitoring UI on https://%s", ui.config.ListenAddress)
			err = ui.httpServer.ListenAndServeTLS(ui.config.TLSCertificate, ui.config.TLSKey)
		} else {
			dlog.Noticef("Starting monitoring UI on http://%s", ui.config.ListenAddress)
			err = ui.httpServer.ListenAndServe()
		}
		if err != nil && err != http.ErrServerClosed {
			dlog.Errorf("Monitoring UI server error: %v", err)
		}
	}()

	return nil
}

// Stop - Stops the monitoring UI
// Flush waits until every event recorded before the call has been applied.
//
// The counters are updated on another goroutine, so a reader that has just
// recorded something and wants to see it -- a test, or a metrics scrape taken
// right after a query -- needs a point to wait on.
func (ui *MonitoringUI) Flush() {
	mc := ui.metricsCollector
	if mc == nil || mc.events == nil {
		return
	}
	done := make(chan struct{})
	select {
	case mc.events <- metricEvent{done: done}:
	case <-mc.collectorStop:
		return
	}
	select {
	case <-done:
	case <-mc.collectorStop:
	}
}

func (ui *MonitoringUI) Stop() error {
	if ui.metricsCollector != nil && ui.metricsCollector.collectorStop != nil {
		select {
		case <-ui.metricsCollector.collectorStop:
			// already stopped
		default:
			close(ui.metricsCollector.collectorStop)
		}
	}
	if ui.httpServer != nil {
		return ui.httpServer.Close()
	}
	return nil
}

// metricEvent is everything the metrics need from a query.
//
// The fields are copied out on the serving goroutine and the rest of the work
// happens elsewhere, so a query pays for one channel send instead of four
// mutexes and a struct copy. It is small and owns its strings: nothing here
// points back into state the query is about to reuse.
type metricEvent struct {
	at           time.Time
	qName        string
	qType        string
	serverName   string
	clientIP     string
	returnCode   string
	responseTime int64
	// dnssecVerdict is empty when validation is off, which is not the same as
	// an answer nothing could be concluded about.
	dnssecVerdict string
	dnssecReason  string
	cacheHit      bool
	countCache    bool
	blocked       bool
	logQuery      bool
	// done, when set, is closed once this event has been applied. It carries no
	// measurement: it is how a caller waits for everything queued before it.
	done chan struct{}
}

// UpdateMetrics records one query.
//
// Called on the goroutine answering the query, so it does as little as it can:
// read the fields it needs and hand them on. If the collector is behind, the
// event is dropped and counted rather than made to wait -- metrics falling
// behind is a smaller problem than answers doing so.
func (ui *MonitoringUI) UpdateMetrics(pluginsState *PluginsState, msg *dns.Msg) {
	if !ui.config.Enabled || pluginsState == nil {
		return
	}
	// DNSSEC chain fetches pass through the normal query pipeline so that they
	// retain DNS records needed by the validator. They are implementation
	// detail, not client queries: recording them here inflates dashboard totals
	// and top domains, and presents their deliberately absent verdict as
	// "unchecked" traffic.
	if pluginsState.clientProto == dnssecInternalProto {
		return
	}
	mc := ui.metricsCollector
	now := time.Now()

	responseTime := now.Sub(pluginsState.requestStart).Milliseconds()
	// Cap at the timeout: a suspended machine otherwise reports the time it
	// spent asleep as query latency.
	if maxResponseTime := pluginsState.timeout.Milliseconds(); responseTime > maxResponseTime {
		responseTime = maxResponseTime
	}

	ev := metricEvent{
		at:           now,
		qName:        pluginsState.qName,
		serverName:   pluginsState.serverName,
		responseTime: responseTime,
		cacheHit:     pluginsState.cacheHit,
		countCache:   pluginsState.cacheHit || pluginsState.serverName != "-",
		blocked: pluginsState.returnCode == PluginsReturnCodeReject ||
			pluginsState.returnCode == PluginsReturnCodeDrop,
		logQuery: ui.config.EnableQueryLog && mc.privacyLevel < 2,
	}
	if verdict, ok := pluginsState.sessionData[dnssecVerdictKey].(string); ok {
		ev.dnssecVerdict = verdict
		if reason, ok := pluginsState.sessionData[dnssecReasonKey].(string); ok {
			ev.dnssecReason = reason
		}
	}
	if msg != nil && len(msg.Question) > 0 {
		rrType := dns.RRToType(msg.Question[0])
		qType, ok := dns.TypeToString[rrType]
		if !ok {
			qType = strconv.FormatUint(uint64(rrType), 10)
		}
		ev.qType = qType
	}
	if ev.logQuery {
		ev.clientIP = clientIPForLog(pluginsState, mc.privacyLevel)
		returnCode, ok := PluginsReturnCodeToString[pluginsState.returnCode]
		if !ok {
			returnCode = strconv.Itoa(int(pluginsState.returnCode))
		}
		ev.returnCode = returnCode
	}

	select {
	case mc.events <- ev:
	default:
		atomic.AddUint64(&mc.droppedEvents, 1)
	}
}

// clientIPForLog renders the client address for the query log, honouring the
// privacy level.
func clientIPForLog(pluginsState *PluginsState, privacyLevel int) string {
	if privacyLevel >= 1 {
		return "anonymized"
	}
	if pluginsState.clientAddr == nil {
		return "no-client-addr"
	}
	switch pluginsState.clientProto {
	case "udp":
		if udpAddr, ok := (*pluginsState.clientAddr).(*net.UDPAddr); ok && udpAddr != nil {
			return udpAddr.IP.String()
		}
		return "unknown-udp"
	case "tcp", "local_doh":
		if tcpAddr, ok := (*pluginsState.clientAddr).(*net.TCPAddr); ok && tcpAddr != nil {
			return tcpAddr.IP.String()
		}
		return "unknown-tcp"
	}
	return "internal"
}

// runCollector applies events one at a time. Being the only writer is what
// keeps the counters consistent without the serving goroutines ever waiting.
func (ui *MonitoringUI) runCollector() {
	mc := ui.metricsCollector
	for {
		select {
		case ev := <-mc.events:
			if ev.done != nil {
				close(ev.done)
				continue
			}
			ui.applyMetrics(ev)
		case <-mc.collectorStop:
			return
		}
	}
}

func (ui *MonitoringUI) applyMetrics(ev metricEvent) {
	mc := ui.metricsCollector
	now := ev.at

	// Update counters (total queries, cache, QPS) - separate lock
	mc.countersMutex.Lock()
	mc.totalQueries++

	// Update queries per second
	elapsed := now.Sub(mc.lastQueriesTime).Seconds()
	if elapsed >= 1.0 || mc.lastQueriesTime.IsZero() {
		if mc.lastQueriesTime.IsZero() {
			// First query, initialize
			mc.lastQueriesTime = now
			mc.lastQueriesCount = 0
			mc.queriesPerSecond = 0
		} else {
			mc.queriesPerSecond = float64(mc.totalQueries-mc.lastQueriesCount) / elapsed
			mc.lastQueriesCount = mc.totalQueries
			mc.lastQueriesTime = now
		}
	}

	// Update cache hits/misses
	// Only count cache statistics for queries that participate in caching:
	// - Cache hits (cacheHit == true)
	// - Cache misses (queries that went to a DNS server: serverName != "-")
	// This excludes blocked queries (REJECT/DROP) that never reach the cache or server
	if ev.countCache {
		if ev.cacheHit {
			mc.cacheHits++
		} else {
			mc.cacheMisses++
		}
	}

	// Update blocked queries count
	// Only count truly blocked queries: REJECT (blocked by name/IP) and DROP (dropped)
	// CLOAK is not counted as it redirects queries rather than blocking them
	if ev.blocked {
		mc.blockCount++
	}
	mc.countersMutex.Unlock()

	// Invalidate cache since counters changed
	mc.invalidateCache()

	// Update query types - separate lock
	if ev.qType != "" {
		mc.queryTypesMutex.Lock()
		mc.queryTypes[ev.qType]++
		mc.queryTypesMutex.Unlock()
	}

	responseTime := ev.responseTime
	mc.countersMutex.Lock()
	mc.responseTimeSum += uint64(responseTime)
	mc.responseTimeCount++
	mc.countersMutex.Unlock()

	// Update server stats - separate lock
	if ev.serverName != "" && ev.serverName != "-" {
		mc.serverMutex.Lock()
		mc.serverQueryCount[ev.serverName]++
		mc.serverResponseTime[ev.serverName] += uint64(responseTime)
		mc.serverMutex.Unlock()
	}

	// Update top domains - separate lock
	if mc.privacyLevel < 2 {
		// Store domain name directly - no sanitization needed for internal metrics
		domainName := ev.qName
		mc.domainMutex.Lock()
		if _, found := mc.topDomains[domainName]; !found && len(mc.topDomains) >= maxTopDomains {
			mc.pruneTopDomainsLocked()
		}
		mc.topDomains[domainName]++
		mc.domainMutex.Unlock()
	}

	// Update recent queries if enabled, but only if privacy level < 2
	if ev.logQuery {
		clientIP := ev.clientIP
		returnCode := ev.returnCode
		qType := ev.qType
		if qType == "" {
			qType = "unknown"
		}

		entry := QueryLogEntry{
			Timestamp: now,
			ClientIP:  clientIP,
			// HTML escape only the fields that will be displayed in web UI
			Domain:       html.EscapeString(ev.qName),
			Type:         qType,      // DNS types are safe, no escaping needed
			ResponseCode: returnCode, // DNS response codes are safe, no escaping needed
			ResponseTime: responseTime,
			Server:       html.EscapeString(ev.serverName),
			CacheHit:     ev.cacheHit,
			// Escaped: the reason quotes names taken from the answer.
			DNSSECVerdict: html.EscapeString(ev.dnssecVerdict),
			DNSSECReason:  html.EscapeString(ev.dnssecReason),
		}

		mc.queryLogMutex.Lock()
		mc.appendRecentQueryLocked(entry)
		mc.queryLogMutex.Unlock()
	}

	// Broadcast updates to WebSocket clients (rate limited)
	ui.scheduleBroadcast()
}

func (mc *MetricsCollector) pruneTopDomainsLocked() {
	type domainCount struct {
		domain string
		count  uint64
	}
	counts := make([]domainCount, 0, len(mc.topDomains))
	for domain, hits := range mc.topDomains {
		counts = append(counts, domainCount{domain, hits})
	}
	sort.Slice(counts, func(i, j int) bool {
		if counts[i].count != counts[j].count {
			return counts[i].count > counts[j].count
		}
		return counts[i].domain < counts[j].domain
	})
	for _, dc := range counts[maxTopDomains/2:] {
		delete(mc.topDomains, dc.domain)
	}
}

// generatePrometheusMetrics - Generates Prometheus-formatted metrics
func (mc *MetricsCollector) generatePrometheusMetrics() string {
	if !mc.prometheusEnabled {
		return ""
	}

	mc.countersMutex.RLock()
	totalQueries := mc.totalQueries
	queriesPerSecond := mc.queriesPerSecond
	cacheHits := mc.cacheHits
	cacheMisses := mc.cacheMisses
	blockCount := mc.blockCount
	responseTimeSum := mc.responseTimeSum
	responseTimeCount := mc.responseTimeCount
	startTime := mc.startTime
	mc.countersMutex.RUnlock()

	// Calculate derived metrics
	var avgResponseTime float64
	if responseTimeCount > 0 {
		avgResponseTime = float64(responseTimeSum) / float64(responseTimeCount)
	}

	var cacheHitRatio float64
	totalCacheQueries := cacheHits + cacheMisses
	if totalCacheQueries > 0 {
		cacheHitRatio = float64(cacheHits) / float64(totalCacheQueries)
	}

	uptime := time.Since(startTime).Seconds()

	var result strings.Builder

	// Write help and type information for each metric
	result.WriteString("# HELP dnscrypt_proxy_build_info A metric with a constant '1' value labeled by version, goversion from which dnscrypt_proxy was built, and the goos and goarch for the build.\n")
	result.WriteString("# TYPE dnscrypt_proxy_build_info gauge\n")
	result.WriteString(fmt.Sprintf("dnscrypt_proxy_build_info{goarch=\"%s\", goos=\"%s\", goversion=\"%s\", version=\"%s\"} 1\n", runtime.GOARCH, runtime.GOOS, runtime.Version(), AppVersion))

	result.WriteString("# HELP dnscrypt_proxy_queries_total Total number of DNS queries processed\n")
	result.WriteString("# TYPE dnscrypt_proxy_queries_total counter\n")
	result.WriteString(fmt.Sprintf("dnscrypt_proxy_queries_total %d\n", totalQueries))

	result.WriteString("# HELP dnscrypt_proxy_queries_per_second Current queries per second rate\n")
	result.WriteString("# TYPE dnscrypt_proxy_queries_per_second gauge\n")
	result.WriteString(fmt.Sprintf("dnscrypt_proxy_queries_per_second %.2f\n", queriesPerSecond))

	result.WriteString("# HELP dnscrypt_proxy_uptime_seconds Uptime in seconds\n")
	result.WriteString("# TYPE dnscrypt_proxy_uptime_seconds counter\n")
	result.WriteString(fmt.Sprintf("dnscrypt_proxy_uptime_seconds %.0f\n", uptime))

	result.WriteString("# HELP dnscrypt_proxy_cache_hits_total Total number of cache hits\n")
	result.WriteString("# TYPE dnscrypt_proxy_cache_hits_total counter\n")
	result.WriteString(fmt.Sprintf("dnscrypt_proxy_cache_hits_total %d\n", cacheHits))

	result.WriteString("# HELP dnscrypt_proxy_cache_misses_total Total number of cache misses\n")
	result.WriteString("# TYPE dnscrypt_proxy_cache_misses_total counter\n")
	result.WriteString(fmt.Sprintf("dnscrypt_proxy_cache_misses_total %d\n", cacheMisses))

	result.WriteString("# HELP dnscrypt_proxy_cache_hit_ratio Current cache hit ratio\n")
	result.WriteString("# TYPE dnscrypt_proxy_cache_hit_ratio gauge\n")
	result.WriteString(fmt.Sprintf("dnscrypt_proxy_cache_hit_ratio %.4f\n", cacheHitRatio))

	result.WriteString("# HELP dnscrypt_proxy_blocked_queries_total Total number of blocked queries\n")
	result.WriteString("# TYPE dnscrypt_proxy_blocked_queries_total counter\n")
	result.WriteString(fmt.Sprintf("dnscrypt_proxy_blocked_queries_total %d\n", blockCount))

	result.WriteString("# HELP dnscrypt_proxy_response_time_average_ms Average response time in milliseconds\n")
	result.WriteString("# TYPE dnscrypt_proxy_response_time_average_ms gauge\n")
	result.WriteString(fmt.Sprintf("dnscrypt_proxy_response_time_average_ms %.2f\n", avgResponseTime))

	// Add server-specific metrics
	mc.serverMutex.RLock()
	result.WriteString("# HELP dnscrypt_proxy_server_queries_total Total queries per server\n")
	result.WriteString("# TYPE dnscrypt_proxy_server_queries_total counter\n")
	for server, count := range mc.serverQueryCount {
		// For Prometheus labels, escape quotes and backslashes to prevent label injection
		escapedServer := strings.ReplaceAll(strings.ReplaceAll(server, "\\", "\\\\"), "\"", "\\\"")
		result.WriteString(fmt.Sprintf("dnscrypt_proxy_server_queries_total{server=\"%s\"} %d\n", escapedServer, count))
	}

	result.WriteString("# HELP dnscrypt_proxy_server_response_time_average_ms Average response time per server in milliseconds\n")
	result.WriteString("# TYPE dnscrypt_proxy_server_response_time_average_ms gauge\n")
	for server, count := range mc.serverQueryCount {
		if count > 0 {
			avgTime := float64(mc.serverResponseTime[server]) / float64(count)
			// For Prometheus labels, escape quotes and backslashes to prevent label injection
			escapedServer := strings.ReplaceAll(strings.ReplaceAll(server, "\\", "\\\\"), "\"", "\\\"")
			result.WriteString(fmt.Sprintf("dnscrypt_proxy_server_response_time_average_ms{server=\"%s\"} %.2f\n", escapedServer, avgTime))
		}
	}
	mc.serverMutex.RUnlock()

	// Add query type metrics
	mc.queryTypesMutex.RLock()
	result.WriteString("# HELP dnscrypt_proxy_query_type_total Total queries per DNS record type\n")
	result.WriteString("# TYPE dnscrypt_proxy_query_type_total counter\n")
	for qtype, count := range mc.queryTypes {
		// DNS query types are safe alphanumeric values, no escaping needed
		result.WriteString(fmt.Sprintf("dnscrypt_proxy_query_type_total{type=\"%s\"} %d\n", qtype, count))
	}
	mc.queryTypesMutex.RUnlock()

	// Add memory usage metrics if available
	mc.queryLogMutex.RLock()
	queryLogEntries := mc.recentQueryCountLocked()
	memoryUsage := mc.currentMemoryBytes
	mc.queryLogMutex.RUnlock()

	result.WriteString("# HELP dnscrypt_proxy_query_log_entries Current number of query log entries in memory\n")
	result.WriteString("# TYPE dnscrypt_proxy_query_log_entries gauge\n")
	result.WriteString(fmt.Sprintf("dnscrypt_proxy_query_log_entries %d\n", queryLogEntries))

	result.WriteString("# HELP dnscrypt_proxy_memory_usage_bytes Estimated retained memory in bytes for query logs\n")
	result.WriteString("# TYPE dnscrypt_proxy_memory_usage_bytes gauge\n")
	result.WriteString(fmt.Sprintf("dnscrypt_proxy_memory_usage_bytes %d\n", memoryUsage))

	var memStats runtime.MemStats
	runtime.ReadMemStats(&memStats)
	result.WriteString("# HELP dnscrypt_proxy_go_heap_alloc_bytes Bytes of live Go heap allocations\n")
	result.WriteString("# TYPE dnscrypt_proxy_go_heap_alloc_bytes gauge\n")
	result.WriteString(fmt.Sprintf("dnscrypt_proxy_go_heap_alloc_bytes %d\n", memStats.Alloc))
	result.WriteString("# HELP dnscrypt_proxy_go_memory_sys_bytes Bytes of memory obtained from the operating system by the Go runtime\n")
	result.WriteString("# TYPE dnscrypt_proxy_go_memory_sys_bytes gauge\n")
	result.WriteString(fmt.Sprintf("dnscrypt_proxy_go_memory_sys_bytes %d\n", memStats.Sys))
	result.WriteString("# HELP dnscrypt_proxy_go_goroutines Current number of Go goroutines\n")
	result.WriteString("# TYPE dnscrypt_proxy_go_goroutines gauge\n")
	result.WriteString(fmt.Sprintf("dnscrypt_proxy_go_goroutines %d\n", runtime.NumGoroutine()))

	// Events discarded because the collector was behind. Non-zero means the
	// numbers above undercount, which is worth knowing before trusting them.
	result.WriteString("# HELP dnscrypt_proxy_metric_events_dropped_total Metric events discarded because the collector queue was full\n")
	result.WriteString("# TYPE dnscrypt_proxy_metric_events_dropped_total counter\n")
	result.WriteString(fmt.Sprintf("dnscrypt_proxy_metric_events_dropped_total %d\n", atomic.LoadUint64(&mc.droppedEvents)))

	// Whether this machine accelerates AES in hardware. The cipher a TLS
	// connection ends up using follows from it, and on a mixed fleet the answer
	// differs per host -- which is exactly when it is worth being able to see.
	aesHW := 0
	if hasAESGCMHardwareSupport {
		aesHW = 1
	}
	result.WriteString("# HELP dnscrypt_proxy_aes_hardware_support Whether the CPU accelerates AES-GCM, which decides the preferred TLS cipher\n")
	result.WriteString("# TYPE dnscrypt_proxy_aes_hardware_support gauge\n")
	result.WriteString(fmt.Sprintf("dnscrypt_proxy_aes_hardware_support %d\n", aesHW))

	// Export the active policy separately from the outcomes. A quiet counter
	// stream cannot tell an operator whether validation was logging, enforcing,
	// or disabled, and the pre-enforcement gate must be able to prove that every
	// replica was actually observing traffic in the intended mode.
	mode := dnssecMode.Load().(string)
	result.WriteString("# HELP dnscrypt_proxy_dnssec_validation_mode Active DNSSEC validation policy (exactly one labelled series is 1)\n")
	result.WriteString("# TYPE dnscrypt_proxy_dnssec_validation_mode gauge\n")
	result.WriteString(fmt.Sprintf("dnscrypt_proxy_dnssec_validation_mode{mode=\"%s\"} 1\n", mode))

	// Split by verdict rather than counted as one, because the four outcomes
	// mean different things. Both Bogus and Indeterminate are refused while
	// enforcing; the latter is kept separate because it is a local inability to
	// decide rather than evidence that the zone's data failed authentication.
	result.WriteString("# HELP dnscrypt_proxy_dnssec_verdicts_total DNSSEC validation results by verdict\n")
	result.WriteString("# TYPE dnscrypt_proxy_dnssec_verdicts_total counter\n")
	result.WriteString(fmt.Sprintf("dnscrypt_proxy_dnssec_verdicts_total{verdict=\"secure\"} %d\n", dnssecVerdicts.secure.Load()))
	result.WriteString(fmt.Sprintf("dnscrypt_proxy_dnssec_verdicts_total{verdict=\"bogus\"} %d\n", dnssecVerdicts.bogus.Load()))
	result.WriteString(fmt.Sprintf("dnscrypt_proxy_dnssec_verdicts_total{verdict=\"insecure\"} %d\n", dnssecVerdicts.insecure.Load()))
	result.WriteString(fmt.Sprintf("dnscrypt_proxy_dnssec_verdicts_total{verdict=\"indeterminate\"} %d\n", dnssecVerdicts.indeterminate.Load()))

	return result.String()
}

func determineResolverStatus(total uint64, successRate float64, lastUpdate, lastAction, now time.Time) string {
	staleThreshold := 5 * time.Minute
	refTime := lastUpdate
	if refTime.IsZero() {
		refTime = lastAction
	}

	if total == 0 {
		if refTime.IsZero() {
			return "idle"
		}
		if !refTime.IsZero() && now.Sub(refTime) > staleThreshold {
			return "stale"
		}
		return "warming"
	}

	status := "healthy"
	switch {
	case successRate >= 0.97:
		status = "healthy"
	case successRate >= 0.9:
		status = "degraded"
	default:
		status = "failing"
	}

	if !refTime.IsZero() && now.Sub(refTime) > staleThreshold {
		status = "stale"
	}

	return status
}

func resolverStatusRank(status string) int {
	switch status {
	case "failing":
		return 0
	case "degraded":
		return 1
	case "stale":
		return 2
	case "warming":
		return 3
	case "healthy":
		return 4
	case "idle":
		return 5
	default:
		return 6
	}
}

func (mc *MetricsCollector) collectResolverSnapshots() ([]resolverSnapshot, map[string]resolverSnapshot) {
	snapshots := make([]resolverSnapshot, 0)
	index := make(map[string]resolverSnapshot)

	if mc.proxy == nil {
		return snapshots, index
	}

	mc.proxy.serversInfo.RLock()
	defer mc.proxy.serversInfo.RUnlock()

	now := time.Now()
	for _, server := range mc.proxy.serversInfo.inner {
		if server == nil {
			continue
		}

		total := server.totalQueries
		failed := server.failedQueries
		successRate := 1.0
		if total > 0 {
			successRate = float64(total-failed) / float64(total)
		}

		lastUpdate := server.lastUpdateTime
		lastAction := server.lastActionTS
		score := mc.proxy.serversInfo.calculateServerScore(server)
		status := determineResolverStatus(total, successRate, lastUpdate, lastAction, now)
		ageSeconds := -1.0
		refTime := lastUpdate
		if refTime.IsZero() {
			refTime = lastAction
		}
		if !refTime.IsZero() {
			ageSeconds = now.Sub(refTime).Seconds()
		}

		snapshot := resolverSnapshot{
			name:       server.Name,
			proto:      server.Proto.String(),
			total:      total,
			failed:     failed,
			success:    successRate,
			lastUpdate: lastUpdate,
			lastAction: lastAction,
			status:     status,
			score:      score,
			ageSeconds: ageSeconds,
		}

		snapshots = append(snapshots, snapshot)
		index[server.Name] = snapshot
	}

	sort.Slice(snapshots, func(i, j int) bool {
		if rankI, rankJ := resolverStatusRank(snapshots[i].status), resolverStatusRank(snapshots[j].status); rankI != rankJ {
			return rankI < rankJ
		}
		if snapshots[i].score != snapshots[j].score {
			return snapshots[i].score > snapshots[j].score
		}
		return snapshots[i].name < snapshots[j].name
	})

	return snapshots, index
}

func (mc *MetricsCollector) collectCacheStats(cacheHitRatio float64, cacheHits, cacheMisses uint64) map[string]any {
	stats := map[string]any{
		"enabled":         false,
		"configured_size": 0,
		"entries":         0,
		"capacity":        0,
		"cache_hit_ratio": cacheHitRatio,
		"cache_hits":      cacheHits,
		"cache_misses":    cacheMisses,
	}

	if mc.proxy == nil {
		return stats
	}

	stats["enabled"] = mc.proxy.cache
	stats["configured_size"] = mc.proxy.cacheSize
	stats["max_ttl"] = mc.proxy.cacheMaxTTL
	stats["min_ttl"] = mc.proxy.cacheMinTTL
	stats["neg_max_ttl"] = mc.proxy.cacheNegMaxTTL
	stats["neg_min_ttl"] = mc.proxy.cacheNegMinTTL

	if cachedResponses != nil {
		stats["entries"] = cachedResponses.Len()
		stats["capacity"] = cachedResponses.Capacity()
	}

	return stats
}

func (mc *MetricsCollector) collectSourceRefresh() []map[string]any {
	if mc.proxy == nil || len(mc.proxy.sources) == 0 {
		return nil
	}

	results := make([]map[string]any, 0, len(mc.proxy.sources))
	now := time.Now()

	for _, source := range mc.proxy.sources {
		if source == nil {
			continue
		}

		source.RLock()
		name := source.name
		cacheFile := source.cacheFile
		nextRefresh := source.refresh
		cacheTTL := source.cacheTTL
		source.RUnlock()

		var lastRefresh time.Time
		var errorMessage string
		if cacheFile != "" {
			if fi, err := os.Stat(cacheFile); err == nil {
				lastRefresh = fi.ModTime()
			} else {
				errorMessage = err.Error()
			}
		}

		ageSeconds := -1.0
		if !lastRefresh.IsZero() {
			ageSeconds = now.Sub(lastRefresh).Seconds()
		}

		status := "ok"
		switch {
		case errorMessage != "":
			status = "error"
		case lastRefresh.IsZero():
			status = "unknown"
		case !nextRefresh.IsZero() && nextRefresh.Before(now):
			status = "due"
		case cacheTTL > 0 && lastRefresh.Add(cacheTTL).Before(now):
			status = "stale"
		}

		entry := map[string]any{
			"name":        name,
			"cache_file":  cacheFile,
			"age_seconds": ageSeconds,
			"status":      status,
		}
		if !lastRefresh.IsZero() {
			entry["last_refresh"] = lastRefresh
		}
		if !nextRefresh.IsZero() {
			entry["next_refresh"] = nextRefresh
		}
		if errorMessage != "" {
			entry["error"] = errorMessage
		}

		results = append(results, entry)
	}

	sort.Slice(results, func(i, j int) bool {
		return results[i]["name"].(string) < results[j]["name"].(string)
	})

	return results
}

// invalidateCache - Marks the cache as stale (call when data changes)
func (mc *MetricsCollector) invalidateCache() {
	mc.dataVersion.Add(1)
	mc.cacheMutex.Lock()
	mc.cacheLastUpdate = time.Time{} // Zero time to force refresh
	mc.cacheMutex.Unlock()
}

// GetMetrics - Returns the current metrics
func (mc *MetricsCollector) GetMetrics() map[string]any {
	// Check cache first
	mc.cacheMutex.RLock()
	if time.Since(mc.cacheLastUpdate) < mc.cacheTTL && mc.cachedMetrics != nil {
		cached := mc.cachedMetrics
		mc.cacheMutex.RUnlock()
		return cached
	}
	mc.cacheMutex.RUnlock()

	// Read before the counters, so that any change made while they are read and
	// the rest is computed is seen as a change when the result is stored.
	version := mc.dataVersion.Load()

	// Read basic counters first
	mc.countersMutex.RLock()
	totalQueries := mc.totalQueries
	queriesPerSecond := mc.queriesPerSecond
	cacheHits := mc.cacheHits
	cacheMisses := mc.cacheMisses
	blockCount := mc.blockCount
	responseTimeSum := mc.responseTimeSum
	responseTimeCount := mc.responseTimeCount
	startTime := mc.startTime
	mc.countersMutex.RUnlock()

	// Calculate average response time
	var avgResponseTime float64
	if responseTimeCount > 0 {
		avgResponseTime = float64(responseTimeSum) / float64(responseTimeCount)
	}

	// Calculate cache hit ratio (as decimal 0-1, not percentage)
	var cacheHitRatio float64
	totalCacheQueries := cacheHits + cacheMisses
	if totalCacheQueries > 0 {
		cacheHitRatio = float64(cacheHits) / float64(totalCacheQueries)
	}

	cacheStats := mc.collectCacheStats(cacheHitRatio, cacheHits, cacheMisses)
	resolverSnapshots, resolverIndex := mc.collectResolverSnapshots()

	// Update resolver snapshots with observed average response times.
	mc.serverMutex.RLock()
	for server, count := range mc.serverQueryCount {
		avgTime := float64(0)
		if count > 0 {
			avgTime = float64(mc.serverResponseTime[server]) / float64(count)
		}
		if snapshot, ok := resolverIndex[server]; ok {
			snapshot.avgObservedMs = avgTime
			resolverIndex[server] = snapshot
		}
	}
	mc.serverMutex.RUnlock()

	for i, snapshot := range resolverSnapshots {
		if updated, ok := resolverIndex[snapshot.name]; ok {
			resolverSnapshots[i] = updated
		}
	}

	// Get top domains (limited to 20) sorted by decreasing count
	topDomainsList := make([]map[string]any, 0)
	if mc.privacyLevel < 2 {
		// Create a slice of domain-count pairs
		type domainCount struct {
			domain string
			count  uint64
		}
		// Read domain data with its own lock
		mc.domainMutex.RLock()
		domainCounts := make([]domainCount, 0, len(mc.topDomains))
		for domain, hits := range mc.topDomains {
			domainCounts = append(domainCounts, domainCount{domain, hits})
		}
		mc.domainMutex.RUnlock()

		// Sort by decreasing count
		sort.Slice(domainCounts, func(i, j int) bool {
			if domainCounts[i].count != domainCounts[j].count {
				return domainCounts[i].count > domainCounts[j].count
			}
			return domainCounts[i].domain < domainCounts[j].domain
		})

		// Take top 20
		count := 0
		for _, dc := range domainCounts {
			topDomainsList = append(topDomainsList, map[string]any{
				"domain": html.EscapeString(dc.domain),
				"count":  dc.count,
			})
			count++
			if count >= 20 {
				break
			}
		}
	}

	// Get query type distribution sorted by decreasing count and limited to 10
	queryTypesList := make([]map[string]any, 0)

	// Create a slice of query type-count pairs
	type queryTypeCount struct {
		qtype string
		count uint64
	}
	// Read query types with its own lock
	mc.queryTypesMutex.RLock()
	queryTypeCounts := make([]queryTypeCount, 0, len(mc.queryTypes))
	for qtype, count := range mc.queryTypes {
		queryTypeCounts = append(queryTypeCounts, queryTypeCount{qtype, count})
	}
	mc.queryTypesMutex.RUnlock()

	// Sort by decreasing count
	sort.Slice(queryTypeCounts, func(i, j int) bool {
		if queryTypeCounts[i].count != queryTypeCounts[j].count {
			return queryTypeCounts[i].count > queryTypeCounts[j].count
		}
		return queryTypeCounts[i].qtype < queryTypeCounts[j].qtype
	})

	// Take top 10
	count := 0
	for _, qtc := range queryTypeCounts {
		queryTypesList = append(queryTypesList, map[string]any{
			"type":  qtc.qtype,
			"count": qtc.count,
		})
		count++
		if count >= 10 {
			break
		}
	}

	// Read recent queries with its own lock.
	recentQueries := mc.snapshotRecentQueries(0)

	resolverHealth := make([]map[string]any, 0, len(resolverSnapshots))
	for _, snapshot := range resolverSnapshots {
		entry := map[string]any{
			"name":           snapshot.name,
			"proto":          snapshot.proto,
			"status":         snapshot.status,
			"success_rate":   snapshot.success,
			"total_queries":  snapshot.total,
			"failed_queries": snapshot.failed,
			"score":          snapshot.score,
		}
		if snapshot.avgObservedMs > 0 {
			entry["avg_response_ms"] = snapshot.avgObservedMs
		}
		if snapshot.ageSeconds >= 0 {
			entry["age_seconds"] = snapshot.ageSeconds
		}
		if !snapshot.lastUpdate.IsZero() {
			entry["last_update"] = snapshot.lastUpdate
		}
		if !snapshot.lastAction.IsZero() {
			entry["last_action"] = snapshot.lastAction
		}
		resolverHealth = append(resolverHealth, entry)
	}

	sourceRefresh := mc.collectSourceRefresh()
	generatedAt := time.Now().UTC()

	// Return all metrics and cache the result
	metrics := map[string]any{
		"total_queries":      totalQueries,
		"queries_per_second": queriesPerSecond,
		"uptime_seconds":     time.Since(startTime).Seconds(),
		"cache_hit_ratio":    cacheHitRatio,
		"cache_hits":         cacheHits,
		"cache_misses":       cacheMisses,
		"avg_response_time":  avgResponseTime,
		"blocked_queries":    blockCount,
		"top_domains":        topDomainsList,
		"query_types":        queryTypesList,
		"recent_queries":     recentQueries,
		"cache_stats":        cacheStats,
		"resolver_health":    resolverHealth,
		"sources":            sourceRefresh,
		"generated_at":       generatedAt,
		"instance_id":        instanceID,
		// Counted apart because they mean different things: insecure is a zone
		// that signs nothing, indeterminate is this resolver failing to check.
		"dnssec": map[string]any{
			"secure":        dnssecVerdicts.secure.Load(),
			"bogus":         dnssecVerdicts.bogus.Load(),
			"insecure":      dnssecVerdicts.insecure.Load(),
			"indeterminate": dnssecVerdicts.indeterminate.Load(),
			"mode":          dnssecMode.Load(),
		},
	}

	// Cache the computed metrics, unless a query was recorded while they were
	// being computed: they no longer describe the counters, and storing them
	// would discard that change rather than merely miss it.
	mc.cacheMutex.Lock()
	if mc.dataVersion.Load() == version {
		mc.cachedMetrics = metrics
		mc.cacheLastUpdate = generatedAt
	}
	mc.cacheMutex.Unlock()

	return metrics
}

// GetPeerMetrics returns the local data needed to build an accurate fleet view.
// It is deliberately only used for requests between monitoring peers. The
// browser gets the merged result instead, so it never receives a serving pod's
// private per-instance view.
func (mc *MetricsCollector) GetPeerMetrics() map[string]any {
	metrics := mc.GetMetrics()
	peerMetrics := make(map[string]any, len(metrics)+2)
	for key, value := range metrics {
		peerMetrics[key] = value
	}

	// The public lists are deliberately short. Merging only each node's top
	// entries can produce an incorrect fleet-wide ranking, so peers exchange the
	// bounded raw counters and the browser sees the global top entries only.
	peerMetrics["peer_top_domains"] = mc.peerTopDomains()
	peerMetrics["peer_query_types"] = mc.peerQueryTypes()
	return peerMetrics
}

func (mc *MetricsCollector) peerTopDomains() map[string]uint64 {
	if mc.privacyLevel >= 2 {
		return nil
	}

	mc.domainMutex.RLock()
	defer mc.domainMutex.RUnlock()
	counts := make(map[string]uint64, len(mc.topDomains))
	for domain, count := range mc.topDomains {
		counts[domain] = count
	}
	return counts
}

func (mc *MetricsCollector) peerQueryTypes() map[string]uint64 {
	mc.queryTypesMutex.RLock()
	defer mc.queryTypesMutex.RUnlock()
	counts := make(map[string]uint64, len(mc.queryTypes))
	for queryType, count := range mc.queryTypes {
		counts[queryType] = count
	}
	return counts
}

// requestScheme - Returns the scheme the client used, which a TLS-terminating
// proxy reports in X-Forwarded-Proto. Browsers cannot forge that header on a
// WebSocket handshake.
func requestScheme(r *http.Request) string {
	forwarded := r.Header.Get("X-Forwarded-Proto")
	if comma := strings.IndexByte(forwarded, ','); comma >= 0 {
		forwarded = forwarded[:comma]
	}
	switch strings.ToLower(strings.TrimSpace(forwarded)) {
	case "http":
		return "http"
	case "https":
		return "https"
	}
	if r.TLS != nil {
		return "https"
	}
	return "http"
}

// setDynamicCacheHeaders - Sets cache headers for dynamic content (metrics, API)
func setDynamicCacheHeaders(w http.ResponseWriter) {
	w.Header().Set("Cache-Control", "no-cache, no-store, must-revalidate")
	w.Header().Set("Pragma", "no-cache")
	w.Header().Set("Expires", "0")
}

// setStaticCacheHeaders - Sets cache headers for static content
func setStaticCacheHeaders(w http.ResponseWriter, maxAge int) {
	w.Header().Set("Cache-Control", fmt.Sprintf("public, max-age=%d", maxAge))
	w.Header().Set("Expires", time.Now().Add(time.Duration(maxAge)*time.Second).Format(http.TimeFormat))
}

// handleTestQuery - Handles test query requests for debugging
func (ui *MonitoringUI) handleTestQuery(w http.ResponseWriter, r *http.Request) {
	// Test queries modify state - no cache
	setDynamicCacheHeaders(w)

	// Create a fake DNS message
	msg := dns.NewMsg("test.example.com.", dns.TypeA)

	// Create a fake plugin state
	testStart := time.Now().Add(-10 * time.Millisecond)
	pluginsState := PluginsState{
		qName:        "test.example.com",
		serverName:   "cloudflare",
		clientProto:  "udp",
		questionMsg:  msg,
		cacheHit:     false,
		requestStart: testStart,
	}

	// Update metrics
	ui.UpdateMetrics(&pluginsState, msg)

	// Return success
	w.Header().Set("Content-Type", "text/plain")
	w.Write([]byte("Test query added"))
}

// handleRoot - Handles the root path
func (ui *MonitoringUI) handleRoot(w http.ResponseWriter, r *http.Request) {
	// Handle preflight OPTIONS request
	if r.Method == "OPTIONS" {
		w.WriteHeader(http.StatusOK)
		return
	}

	// Test function to add a fake query for debugging
	if r.URL.Query().Get("test") == "1" {
		ui.handleTestQuery(w, r)
		return
	}

	if r.URL.Path != "/" {
		http.NotFound(w, r)
		return
	}

	// Don't cache: ensures the browser revalidates auth before the JS issues /api/metrics and WebSocket calls.
	setDynamicCacheHeaders(w)
	w.Header().Set("Content-Type", "text/html")
	body := strings.ReplaceAll(MainHTMLTemplate, "{{VERSION}}", AppVersion)
	w.Write([]byte(body))
}

// browserMetrics returns only the fleet view rendered by a browser. Local
// metrics stay on the peer path: exposing them alongside the aggregate makes
// it too easy for a stale WebSocket frame or UI change to turn the page back
// into a single-node view.
func (ui *MonitoringUI) browserMetrics() map[string]any {
	if ui.peers == nil || !ui.peers.configured() {
		return ui.metricsCollector.GetMetrics()
	}
	if !ui.peers.enabled() {
		return unavailableFleetMetrics("peer authentication is not configured")
	}

	fleet := ui.peers.Fleet(ui.metricsCollector.GetPeerMetrics())
	return browserFleetMetrics(fleet, ui.metricsCollector.maxRecentQueries)
}

func unavailableFleetMetrics(reason string) map[string]any {
	return map[string]any{
		"total_queries":      float64(0),
		"queries_per_second": float64(0),
		"cache_hit_ratio":    float64(0),
		"cache_hits":         float64(0),
		"cache_misses":       float64(0),
		"blocked_queries":    float64(0),
		"avg_response_time":  float64(0),
		"cache_stats": map[string]any{
			"enabled":         false,
			"configured_size": float64(0),
			"entries":         float64(0),
			"capacity":        float64(0),
		},
		"query_types":     []map[string]any{},
		"top_domains":     []map[string]any{},
		"resolver_health": []map[string]any{},
		"sources":         []map[string]any{},
		"recent_queries":  []QueryLogEntry{},
		"generated_at":    time.Now().UTC(),
		"fleet": map[string]any{
			"mode":     "unavailable",
			"totals":   map[string]any{"instances": 0, "instances_reachable": 0},
			"degraded": true,
			"error":    reason,
		},
	}
}

func (ui *MonitoringUI) isAuthenticatedPeerRequest(r *http.Request) bool {
	if r.Header.Get("X-Dnscrypt-Peer") == "" || ui.config.PeerToken == "" {
		return false
	}
	return subtle.ConstantTimeCompare(
		[]byte(r.Header.Get("X-Dnscrypt-Peer-Token")),
		[]byte(ui.config.PeerToken),
	) == 1
}

// handleMetrics - Handles the metrics API endpoint
func (ui *MonitoringUI) handleMetrics(w http.ResponseWriter, r *http.Request) {
	dlog.Debugf("Received metrics request from %s", r.RemoteAddr)

	// Set dynamic cache headers for API
	setDynamicCacheHeaders(w)

	// Handle preflight OPTIONS request
	if r.Method == "OPTIONS" {
		w.WriteHeader(http.StatusOK)
		return
	}

	// A request from another instance is answered with this instance's own
	// numbers: aggregating in turn would have every instance asking every other
	// one for every page view. The marker without the shared token is rejected
	// rather than treated as a browser request: during a rolling upgrade an old
	// peer would otherwise count this instance's whole aggregate as one peer.
	var metrics map[string]any
	if r.Header.Get("X-Dnscrypt-Peer") != "" {
		if !ui.isAuthenticatedPeerRequest(r) {
			http.Error(w, "Forbidden", http.StatusForbidden)
			return
		}
		metrics = ui.metricsCollector.GetPeerMetrics()
	} else {
		metrics = ui.browserMetrics()
	}

	w.Header().Set("Content-Type", "application/json")

	// Marshal the data to JSON
	jsonData, err := json.Marshal(metrics)
	if err != nil {
		dlog.Errorf("Error marshaling metrics: %v", err)
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}

	w.Write(jsonData)
}

// handleWebSocket - Handles WebSocket connections
func (ui *MonitoringUI) handleWebSocket(w http.ResponseWriter, r *http.Request) {
	// Handle preflight OPTIONS request
	if r.Method == "OPTIONS" {
		w.WriteHeader(http.StatusOK)
		return
	}

	conn, err := ui.upgrader.Upgrade(w, r, nil)
	if err != nil {
		dlog.Warnf("WebSocket upgrade error: %v", err)
		return
	}

	// Register the client
	ui.clientsMutex.Lock()
	ui.clients[conn] = true
	ui.clientsMutex.Unlock()

	// Send initial metrics
	metrics := ui.browserMetrics()
	ui.writesMutex.Lock()
	conn.SetWriteDeadline(time.Now().Add(10 * time.Second))
	err = conn.WriteJSON(metrics)
	ui.writesMutex.Unlock()

	if err != nil {
		dlog.Warnf("WebSocket initial write error: %v", err)
		conn.Close()
		ui.clientsMutex.Lock()
		delete(ui.clients, conn)
		ui.clientsMutex.Unlock()
		return
	}

	// Handle client messages and disconnection
	go func() {
		defer func() {
			ui.clientsMutex.Lock()
			delete(ui.clients, conn)
			ui.clientsMutex.Unlock()
			conn.Close()
			dlog.Debugf("WebSocket connection closed and cleaned up")
		}()

		// Set up ping/pong handlers for keep-alive (using WebSocket protocol level)
		conn.SetReadDeadline(time.Now().Add(120 * time.Second))
		conn.SetPongHandler(func(string) error {
			dlog.Debugf("Received pong from client")
			conn.SetReadDeadline(time.Now().Add(120 * time.Second))
			return nil
		})

		for {
			// Read message from client
			var msg map[string]any
			err := conn.ReadJSON(&msg)
			if err != nil {
				if websocket.IsUnexpectedCloseError(err, websocket.CloseGoingAway, websocket.CloseAbnormalClosure) {
					dlog.Warnf("WebSocket unexpected close error: %v", err)
				}
				break
			}

			// Handle ping message from client (application level)
			if msgType, ok := msg["type"].(string); ok && msgType == "ping" {
				dlog.Debugf("Received ping message from client")

				// Send pong response and updated metrics
				metrics := ui.browserMetrics()
				ui.writesMutex.Lock()
				conn.SetWriteDeadline(time.Now().Add(5 * time.Second))
				if err := conn.WriteJSON(map[string]string{"type": "pong"}); err != nil {
					ui.writesMutex.Unlock()
					dlog.Warnf("Error sending pong: %v", err)
					break
				}

				conn.SetWriteDeadline(time.Now().Add(5 * time.Second))
				if err := conn.WriteJSON(metrics); err != nil {
					dlog.Warnf("Error sending metrics after ping: %v", err)
				}
				ui.writesMutex.Unlock()
			}
		}
	}()
}

// handleStatic - Handles static files
func (ui *MonitoringUI) handleStatic(w http.ResponseWriter, r *http.Request) {
	// This is a placeholder for serving static files
	// In this implementation, we're embedding everything in the HTML
	http.NotFound(w, r)
}

// handleStaticJS - Serves the JavaScript for the monitoring UI
func (ui *MonitoringUI) handleStaticJS(w http.ResponseWriter, r *http.Request) {
	// JavaScript is static - cache for 1 hour
	setStaticCacheHeaders(w, 3600)
	w.Header().Set("Content-Type", "application/javascript")
	w.Write([]byte(MonitoringJSContent))
}

// handlePrometheus - Serves Prometheus metrics
func (ui *MonitoringUI) handlePrometheus(w http.ResponseWriter, r *http.Request) {
	dlog.Debugf("Received Prometheus metrics request from %s", r.RemoteAddr)

	if !ui.metricsCollector.prometheusEnabled {
		http.NotFound(w, r)
		return
	}

	// Generate Prometheus metrics
	metrics := ui.metricsCollector.generatePrometheusMetrics()

	// Set appropriate headers for Prometheus
	w.Header().Set("Content-Type", "text/plain; version=0.0.4; charset=utf-8")
	setDynamicCacheHeaders(w) // Always fresh for metrics

	// Write metrics
	w.WriteHeader(http.StatusOK)
	w.Write([]byte(metrics))
}

// basicAuthMiddleware - Adds basic authentication to the HTTP server
func (ui *MonitoringUI) basicAuthMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Skip auth if username is empty
		if ui.config.Username == "" {
			next.ServeHTTP(w, r)
			return
		}

		user, pass, ok := r.BasicAuth()
		if !ok || subtle.ConstantTimeCompare([]byte(user), []byte(ui.config.Username)) != 1 ||
			subtle.ConstantTimeCompare([]byte(pass), []byte(ui.config.Password)) != 1 {
			w.Header().Set("WWW-Authenticate", `Basic realm="DNSCrypt Proxy Monitoring"`)
			w.WriteHeader(401)
			w.Write([]byte("Unauthorized"))
			return
		}

		next.ServeHTTP(w, r)
	})
}

// scheduleBroadcast - Rate-limited scheduling of WebSocket broadcasts
func (ui *MonitoringUI) scheduleBroadcast() {
	if !ui.hasClients() {
		return
	}
	ui.broadcastMutex.Lock()
	defer ui.broadcastMutex.Unlock()

	now := time.Now()
	timeSinceLastBroadcast := now.Sub(ui.lastBroadcast)

	if timeSinceLastBroadcast >= ui.broadcastMinDelay {
		// Enough time has passed, broadcast immediately
		ui.lastBroadcast = now
		ui.pendingBroadcast = false
		go ui.broadcastMetrics()
	} else {
		// Too soon, schedule a delayed broadcast if not already pending
		if !ui.pendingBroadcast {
			ui.pendingBroadcast = true
			delay := ui.broadcastMinDelay - timeSinceLastBroadcast
			go func() {
				time.Sleep(delay)
				ui.broadcastMutex.Lock()
				if ui.pendingBroadcast {
					ui.lastBroadcast = time.Now()
					ui.pendingBroadcast = false
					ui.broadcastMutex.Unlock()
					ui.broadcastMetrics()
				} else {
					ui.broadcastMutex.Unlock()
				}
			}()
		}
	}
}

// broadcastMetrics - Broadcasts metrics to all connected WebSocket clients
func (ui *MonitoringUI) broadcastMetrics() {
	// Avoid building, copying and fleet-aggregating the full query history when
	// nobody can receive it. Recheck here because the last client may disconnect
	// after a delayed broadcast was scheduled.
	if !ui.hasClients() {
		return
	}
	metrics := ui.browserMetrics()

	ui.writesMutex.Lock()
	defer ui.writesMutex.Unlock()

	ui.clientsMutex.Lock()
	defer ui.clientsMutex.Unlock()

	for client := range ui.clients {
		client.SetWriteDeadline(time.Now().Add(5 * time.Second))
		err := client.WriteJSON(metrics)
		if err != nil {
			dlog.Debugf("WebSocket write error: %v", err)
			client.Close()
			delete(ui.clients, client)
		}
	}
}

func (ui *MonitoringUI) hasClients() bool {
	ui.clientsMutex.Lock()
	defer ui.clientsMutex.Unlock()
	return len(ui.clients) > 0
}
