package main

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"sort"
	"sync"
	"time"

	"github.com/jedisct1/dlog"
)

// Several instances of dnscrypt-proxy behind one address answer a share of the
// traffic each, and each set of numbers describes only its own share. A page
// showing one of them tells you about a fraction of what happened, which is
// misleading precisely when it matters -- comparing instances, or looking for
// where the queries went.
//
// The instance serving the page therefore asks the others for their numbers and
// presents the fleet: totals, and the per-instance breakdown behind them.
// Nothing is asked for unless someone is looking, so an unattended proxy pays
// nothing for this.

const (
	peerFetchTimeout = 2 * time.Second
	// Held briefly so that a page refreshing every few seconds, or several
	// people watching at once, does not multiply into requests to every peer.
	peerCacheTTL = 3 * time.Second

	maxFleetTopDomains = 20
	maxFleetQueryTypes = 10
)

// peerMetrics is one instance's answer, or the reason there was not one.
type peerMetrics struct {
	Address string `json:"address"`
	// Aliases are the other addresses that reached this same instance. A name
	// that resolves to both an A and a AAAA record, or to a service address as
	// well as a host address, yields one instance under several addresses;
	// counting it once per address is how totals silently become wrong.
	Aliases   []string       `json:"aliases,omitempty"`
	Reachable bool           `json:"reachable"`
	Error     string         `json:"error,omitempty"`
	Metrics   map[string]any `json:"metrics,omitempty"`
}

// instanceOf reports which instance answered, so that the same one arriving by
// two addresses is recognised. Empty for an instance too old to say.
func (p peerMetrics) instanceOf() string {
	id, _ := p.Metrics["instance_id"].(string)
	return id
}

// FleetMetrics is what the page is drawn from: the totals, and who contributed.
type FleetMetrics struct {
	Totals    map[string]any `json:"totals"`
	Instances []peerMetrics  `json:"instances"`
	// Degraded reports that at least one instance did not answer, so the totals
	// are of those that did. Saying so is the difference between a number that
	// is low and a number that is wrong.
	Degraded bool `json:"degraded"`
}

type peerCollector struct {
	ui     *MonitoringUI
	client *http.Client

	mu       sync.Mutex
	cached   *FleetMetrics
	cachedAt time.Time
}

func newPeerCollector(ui *MonitoringUI) *peerCollector {
	return &peerCollector{
		ui:     ui,
		client: &http.Client{Timeout: peerFetchTimeout},
	}
}

func (pc *peerCollector) enabled() bool {
	return pc.ui.config.PeerToken != "" && pc.configured()
}

func (pc *peerCollector) configured() bool {
	return len(pc.ui.config.Peers) > 0 || pc.ui.config.PeerDiscoveryDNS != ""
}

// peerAddresses returns the instances to ask, discovered from a name when one
// is configured and from the static list otherwise.
//
// A name is the more useful of the two wherever instances come and go: in
// Kubernetes a headless Service resolves to one address per pod, and anywhere
// else a name with several addresses does the same job. Neither requires this
// process to know anything about the platform it runs on.
func (pc *peerCollector) peerAddresses() []string {
	cfg := pc.ui.config
	seen := map[string]bool{}
	var out []string

	add := func(addr string) {
		if addr == "" || seen[addr] {
			return
		}
		seen[addr] = true
		out = append(out, addr)
	}

	for _, p := range cfg.Peers {
		add(p)
	}

	if cfg.PeerDiscoveryDNS != "" {
		host, port, err := net.SplitHostPort(cfg.PeerDiscoveryDNS)
		if err != nil {
			host, port = cfg.PeerDiscoveryDNS, pc.listenPort()
		}
		ctx, cancel := context.WithTimeout(context.Background(), peerFetchTimeout)
		defer cancel()
		addrs, err := pc.resolver().LookupHost(ctx, host)
		if err != nil {
			dlog.Debugf("Monitoring peer discovery for [%s] failed: %v", host, err)
		}
		sort.Strings(addrs)
		for _, a := range preferredPeerAddresses(addrs) {
			add(net.JoinHostPort(a, port))
		}
	}
	return out
}

// A dual-stack headless Service exposes two addresses for every pod. A healthy
// response is deduplicated by instance ID, but a pod that is starting cannot
// identify itself yet; counting its failed A and AAAA requests separately
// inflates the fleet during a rollout. Prefer IPv4 when it exists, falling
// back to the full IPv6 set for IPv6-only deployments. Explicit static peers
// are left untouched above.
func preferredPeerAddresses(addrs []string) []string {
	ipv4 := make([]string, 0, len(addrs))
	for _, addr := range addrs {
		if ip := net.ParseIP(addr); ip != nil && ip.To4() != nil {
			ipv4 = append(ipv4, addr)
		}
	}
	if len(ipv4) > 0 {
		return ipv4
	}
	return addrs
}

// resolver looks up the discovery name.
//
// A proxy is commonly configured not to use the system resolver, since it is
// the resolver; that leaves it unable to look up a name only a local resolver
// knows, which is exactly what a discovery name tends to be. Naming one here
// keeps discovery working without giving the rest of the process a dependency
// it was configured not to have.
func (pc *peerCollector) resolver() *net.Resolver {
	addr := pc.ui.config.PeerDiscoveryResolver
	if addr == "" {
		return net.DefaultResolver
	}
	if _, _, err := net.SplitHostPort(addr); err != nil {
		addr = net.JoinHostPort(addr, "53")
	}
	return &net.Resolver{
		PreferGo: true,
		Dial: func(ctx context.Context, network, _ string) (net.Conn, error) {
			d := net.Dialer{Timeout: peerFetchTimeout}
			return d.DialContext(ctx, network, addr)
		},
	}
}

// listenPort is the port this instance serves on, which peers are assumed to
// use as well -- they are copies of this process.
func (pc *peerCollector) listenPort() string {
	if _, port, err := net.SplitHostPort(pc.ui.config.ListenAddress); err == nil && port != "" {
		return port
	}
	return "8080"
}

// Fleet returns the aggregate, asking each peer at most once per cache window.
func (pc *peerCollector) Fleet(own map[string]any) *FleetMetrics {
	pc.mu.Lock()
	defer pc.mu.Unlock()
	if pc.cached != nil && time.Since(pc.cachedAt) < peerCacheTTL {
		return pc.cached
	}

	peers := pc.peerAddresses()
	results := make([]peerMetrics, len(peers))
	var wg sync.WaitGroup
	for i, addr := range peers {
		wg.Add(1)
		go func(i int, addr string) {
			defer wg.Done()
			results[i] = pc.fetch(addr)
		}(i, addr)
	}
	wg.Wait()

	fleet := &FleetMetrics{Totals: map[string]any{}}
	// This instance's own numbers are counted without being fetched over the
	// network: it is one of the instances, and asking itself would be a request
	// that can fail for reasons the answer already rules out.
	//
	// Held as a copy, because the caller puts this result back into the very map
	// it passed in. Keeping the original would make the fleet contain the map
	// that contains the fleet, and encoding it would not terminate.
	self := make(map[string]any, len(own))
	for k, v := range own {
		if k == "fleet" {
			continue
		}
		self[k] = v
	}
	fleet.Instances = append(fleet.Instances, peerMetrics{
		Address: "self", Reachable: true, Metrics: self,
	})
	// This instance is already counted, and it answers on every address it
	// listens on -- including the ones discovery just handed back.
	byInstance := map[string]int{instanceID: 0}
	for _, r := range results {
		if !r.Reachable {
			fleet.Degraded = true
			fleet.Instances = append(fleet.Instances, r)
			continue
		}
		if id := r.instanceOf(); id != "" {
			if at, seen := byInstance[id]; seen {
				fleet.Instances[at].Aliases = append(fleet.Instances[at].Aliases, r.Address)
				continue
			}
			byInstance[id] = len(fleet.Instances)
		}
		fleet.Instances = append(fleet.Instances, r)
	}
	fleet.Totals = sumMetrics(fleet.Instances)

	pc.cached, pc.cachedAt = fleet, time.Now()
	return fleet
}

func (pc *peerCollector) fetch(addr string) peerMetrics {
	res := peerMetrics{Address: addr}
	scheme := "http"
	if pc.ui.config.TLSCertificate != "" {
		scheme = "https"
	}
	req, err := http.NewRequest("GET", fmt.Sprintf("%s://%s/api/metrics", scheme, addr), nil)
	if err != nil {
		res.Error = err.Error()
		return res
	}
	// The peers are copies of this process, so they expect the credentials this
	// one was configured with.
	if pc.ui.config.Username != "" {
		req.SetBasicAuth(pc.ui.config.Username, pc.ui.config.Password)
	}
	// Marks the request as one instance asking another, so the peer does not
	// aggregate in turn and ask everyone back. The token keeps an arbitrary
	// browser client from forging that marker to obtain one pod's raw details.
	req.Header.Set("X-Dnscrypt-Peer", "1")
	req.Header.Set("X-Dnscrypt-Peer-Token", pc.ui.config.PeerToken)

	resp, err := pc.client.Do(req)
	if err != nil {
		res.Error = err.Error()
		return res
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		res.Error = fmt.Sprintf("peer returned %s", resp.Status)
		return res
	}
	var m map[string]any
	if err := json.NewDecoder(resp.Body).Decode(&m); err != nil {
		res.Error = err.Error()
		return res
	}
	res.Reachable = true
	res.Metrics = m
	return res
}

// summableMetrics are the counters that mean something added together. A rate
// or an average does not survive being summed, so those are recomputed or left
// out rather than reported wrongly.
var summableMetrics = []string{
	"total_queries", "cache_hits", "cache_misses", "blocked_queries",
}

// sumMetrics adds the counters across instances and rebuilds the derived
// figures from the sums.
func sumMetrics(instances []peerMetrics) map[string]any {
	totals := map[string]any{}
	for _, key := range summableMetrics {
		var sum float64
		for _, inst := range instances {
			if !inst.Reachable {
				continue
			}
			if v, ok := toFloat(inst.Metrics[key]); ok {
				sum += v
			}
		}
		totals[key] = sum
	}
	cacheHits, _ := toFloat(totals["cache_hits"])
	cacheMisses, _ := toFloat(totals["cache_misses"])
	if cacheHits+cacheMisses > 0 {
		totals["cache_hit_ratio"] = cacheHits / (cacheHits + cacheMisses)
	} else {
		totals["cache_hit_ratio"] = float64(0)
	}

	if dnssec, present := sumDNSSEC(instances); present {
		totals["dnssec"] = dnssec
	}

	// Queries per second add up: each instance measures its own share of a rate
	// they are serving between them.
	var qps float64
	for _, inst := range instances {
		if !inst.Reachable {
			continue
		}
		if v, ok := toFloat(inst.Metrics["queries_per_second"]); ok {
			qps += v
		}
	}
	totals["queries_per_second"] = qps

	// Response time is averaged over queries, not over instances: an instance
	// that answered ten queries should not weigh as much as one that answered
	// ten thousand.
	var weighted, queries float64
	for _, inst := range instances {
		if !inst.Reachable {
			continue
		}
		avg, ok1 := toFloat(inst.Metrics["avg_response_time"])
		n, ok2 := toFloat(inst.Metrics["total_queries"])
		if ok1 && ok2 {
			weighted += avg * n
			queries += n
		}
	}
	if queries > 0 {
		totals["avg_response_time"] = weighted / queries
	} else {
		totals["avg_response_time"] = float64(0)
	}

	totals["instances"] = len(instances)
	reachable := 0
	for _, inst := range instances {
		if inst.Reachable {
			reachable++
		}
	}
	totals["instances_reachable"] = reachable
	return totals
}

// sumDNSSEC adds verdict counters across the peers. They are counters, not
// rates, so summing them is meaningful; the verified share is rebuilt by the
// page from those sums. A mode disagreement is reported instead of choosing
// whichever pod happened to answer the browser's request.
func sumDNSSEC(instances []peerMetrics) (map[string]any, bool) {
	totals := map[string]any{
		"secure":        float64(0),
		"bogus":         float64(0),
		"insecure":      float64(0),
		"indeterminate": float64(0),
	}
	modes := map[string]bool{}
	present := false
	for _, inst := range instances {
		if !inst.Reachable {
			continue
		}
		dnssec, ok := inst.Metrics["dnssec"].(map[string]any)
		if !ok {
			continue
		}
		present = true
		for _, verdict := range []string{"secure", "bogus", "insecure", "indeterminate"} {
			if n, ok := toFloat(dnssec[verdict]); ok {
				current, _ := toFloat(totals[verdict])
				totals[verdict] = current + n
			}
		}
		if mode, ok := dnssec["mode"].(string); ok && mode != "" {
			modes[mode] = true
		}
	}
	if !present {
		return nil, false
	}
	if len(modes) == 1 {
		for mode := range modes {
			totals["mode"] = mode
		}
	} else {
		totals["mode"] = "mixed"
	}
	return totals, true
}

// browserFleetMetrics creates the only schema sent to browsers when peers are
// configured. Its top-level fields are fleet aggregates, and the envelope
// contains health metadata only; per-instance metrics never leave the peer
// collection path.
func browserFleetMetrics(fleet *FleetMetrics, recentLimit int) map[string]any {
	if fleet == nil {
		return map[string]any{}
	}

	metrics := make(map[string]any, len(fleet.Totals)+8)
	for key, value := range fleet.Totals {
		metrics[key] = value
	}
	metrics["cache_stats"] = aggregateFleetCacheStats(fleet.Instances)
	metrics["query_types"] = aggregateFleetNamedCounts(
		fleet.Instances, "peer_query_types", "query_types", "type", maxFleetQueryTypes,
	)
	metrics["top_domains"] = aggregateFleetNamedCounts(
		fleet.Instances, "peer_top_domains", "top_domains", "domain", maxFleetTopDomains,
	)
	metrics["resolver_health"] = aggregateFleetResolverHealth(fleet.Instances)
	metrics["sources"] = aggregateFleetSources(fleet.Instances)
	metrics["recent_queries"] = aggregateFleetRecentQueries(fleet.Instances, recentLimit)
	metrics["generated_at"] = time.Now().UTC()
	metrics["fleet"] = map[string]any{
		"mode":         "aggregate",
		"totals":       fleet.Totals,
		"degraded":     fleet.Degraded,
		"collected_at": time.Now().UTC(),
	}
	return metrics
}

func aggregateFleetCacheStats(instances []peerMetrics) map[string]any {
	stats := map[string]any{
		"enabled":         false,
		"configured_size": float64(0),
		"entries":         float64(0),
		"capacity":        float64(0),
	}

	seenStats := false
	seenEnabled := false
	allEnabled := true
	anyEnabled := false
	ttlKeys := []string{"min_ttl", "max_ttl", "neg_min_ttl", "neg_max_ttl"}
	ttlValues := make(map[string]float64, len(ttlKeys))
	ttlSeen := make(map[string]bool, len(ttlKeys))
	ttlMixed := false

	for _, instance := range instances {
		if !instance.Reachable {
			continue
		}
		cacheStats, ok := instance.Metrics["cache_stats"].(map[string]any)
		if !ok {
			continue
		}
		seenStats = true

		if enabled, ok := cacheStats["enabled"].(bool); ok {
			seenEnabled = true
			allEnabled = allEnabled && enabled
			anyEnabled = anyEnabled || enabled
		}
		for _, key := range []string{"configured_size", "entries", "capacity"} {
			if value, ok := toFloat(cacheStats[key]); ok {
				current, _ := toFloat(stats[key])
				stats[key] = current + value
			}
		}
		for _, key := range ttlKeys {
			value, ok := toFloat(cacheStats[key])
			if !ok {
				ttlMixed = true
				continue
			}
			if previous, exists := ttlValues[key]; exists && previous != value {
				ttlMixed = true
			}
			ttlValues[key] = value
			ttlSeen[key] = true
		}
	}

	if !seenStats {
		return stats
	}
	if seenEnabled {
		switch {
		case allEnabled:
			stats["enabled"] = true
		case !anyEnabled:
			stats["enabled"] = false
		default:
			stats["enabled"] = "mixed"
		}
	}
	for _, key := range ttlKeys {
		if !ttlSeen[key] {
			ttlMixed = true
		}
		if ttlSeen[key] && !ttlMixed {
			stats[key] = ttlValues[key]
		}
	}
	stats["ttl_mixed"] = ttlMixed
	return stats
}

// aggregateFleetNamedCounts sums a complete counter map from every reachable
// peer, then ranks the resulting fleet totals. The fallback is retained for
// backwards-compatible tests and old peers during a rolling upgrade.
func aggregateFleetNamedCounts(instances []peerMetrics, preferredKey, fallbackKey, nameKey string, limit int) []map[string]any {
	counts := map[string]float64{}
	for _, instance := range instances {
		if !instance.Reachable {
			continue
		}
		value, ok := instance.Metrics[preferredKey]
		if !ok {
			value = instance.Metrics[fallbackKey]
		}
		for name, count := range metricNamedCounts(value, nameKey) {
			counts[name] += count
		}
	}

	type namedCount struct {
		name  string
		count float64
	}
	rows := make([]namedCount, 0, len(counts))
	for name, count := range counts {
		rows = append(rows, namedCount{name: name, count: count})
	}
	sort.Slice(rows, func(i, j int) bool {
		if rows[i].count != rows[j].count {
			return rows[i].count > rows[j].count
		}
		return rows[i].name < rows[j].name
	})
	if limit > 0 && len(rows) > limit {
		rows = rows[:limit]
	}

	result := make([]map[string]any, 0, len(rows))
	for _, row := range rows {
		result = append(result, map[string]any{nameKey: row.name, "count": row.count})
	}
	return result
}

func metricNamedCounts(value any, nameKey string) map[string]float64 {
	counts := map[string]float64{}
	add := func(name string, count any) {
		if name == "" {
			return
		}
		if value, ok := toFloat(count); ok {
			counts[name] += value
		}
	}

	switch values := value.(type) {
	case map[string]uint64:
		for name, count := range values {
			add(name, count)
		}
	case map[string]any:
		for name, count := range values {
			add(name, count)
		}
	case []map[string]any:
		for _, row := range values {
			name, _ := row[nameKey].(string)
			add(name, row["count"])
		}
	case []any:
		for _, value := range values {
			row, ok := value.(map[string]any)
			if !ok {
				continue
			}
			name, _ := row[nameKey].(string)
			add(name, row["count"])
		}
	}
	return counts
}

func aggregateFleetResolverHealth(instances []peerMetrics) []map[string]any {
	type aggregate struct {
		name          string
		proto         string
		status        string
		total         float64
		failed        float64
		latencySum    float64
		latencyWeight float64
		lastUpdate    time.Time
		ageSeconds    float64
		hasAge        bool
	}

	aggregates := map[string]*aggregate{}
	for _, instance := range instances {
		if !instance.Reachable {
			continue
		}
		for _, row := range metricRows(instance.Metrics["resolver_health"]) {
			name, _ := row["name"].(string)
			if name == "" {
				continue
			}
			proto, _ := row["proto"].(string)
			key := name + "\x00" + proto
			entry := aggregates[key]
			if entry == nil {
				entry = &aggregate{name: name, proto: proto}
				aggregates[key] = entry
			}
			total, _ := toFloat(row["total_queries"])
			failed, _ := toFloat(row["failed_queries"])
			entry.total += total
			entry.failed += failed
			if avg, ok := toFloat(row["avg_response_ms"]); ok && total > 0 {
				entry.latencySum += avg * total
				entry.latencyWeight += total
			}
			if status, _ := row["status"].(string); status != "" &&
				(entry.status == "" || resolverStatusRank(status) < resolverStatusRank(entry.status)) {
				entry.status = status
			}
			if updated, ok := metricTime(row["last_update"]); ok &&
				(entry.lastUpdate.IsZero() || updated.Before(entry.lastUpdate)) {
				entry.lastUpdate = updated
			}
			if age, ok := toFloat(row["age_seconds"]); ok &&
				(!entry.hasAge || age > entry.ageSeconds) {
				entry.ageSeconds = age
				entry.hasAge = true
			}
		}
	}

	entries := make([]*aggregate, 0, len(aggregates))
	for _, entry := range aggregates {
		entries = append(entries, entry)
	}
	sort.Slice(entries, func(i, j int) bool {
		if resolverStatusRank(entries[i].status) != resolverStatusRank(entries[j].status) {
			return resolverStatusRank(entries[i].status) < resolverStatusRank(entries[j].status)
		}
		if entries[i].total != entries[j].total {
			return entries[i].total > entries[j].total
		}
		if entries[i].name != entries[j].name {
			return entries[i].name < entries[j].name
		}
		return entries[i].proto < entries[j].proto
	})

	result := make([]map[string]any, 0, len(entries))
	for _, entry := range entries {
		status := entry.status
		if status == "" {
			status = "unknown"
		}
		successRate := float64(1)
		if entry.total > 0 {
			successRate = (entry.total - entry.failed) / entry.total
		}
		row := map[string]any{
			"name":           entry.name,
			"proto":          entry.proto,
			"status":         status,
			"success_rate":   successRate,
			"total_queries":  entry.total,
			"failed_queries": entry.failed,
		}
		if entry.latencyWeight > 0 {
			row["avg_response_ms"] = entry.latencySum / entry.latencyWeight
		}
		if !entry.lastUpdate.IsZero() {
			row["last_update"] = entry.lastUpdate
		}
		if entry.hasAge {
			row["age_seconds"] = entry.ageSeconds
		}
		result = append(result, row)
	}
	return result
}

func aggregateFleetSources(instances []peerMetrics) []map[string]any {
	type aggregate struct {
		name        string
		status      string
		instances   int
		okInstances int
		errors      int
		lastRefresh time.Time
		nextRefresh time.Time
		ageSeconds  float64
		hasAge      bool
	}

	aggregates := map[string]*aggregate{}
	for _, instance := range instances {
		if !instance.Reachable {
			continue
		}
		for _, row := range metricRows(instance.Metrics["sources"]) {
			name, _ := row["name"].(string)
			if name == "" {
				continue
			}
			entry := aggregates[name]
			if entry == nil {
				entry = &aggregate{name: name}
				aggregates[name] = entry
			}
			entry.instances++
			status, _ := row["status"].(string)
			if status == "" {
				status = "unknown"
			}
			if status == "ok" {
				entry.okInstances++
			}
			if entry.status == "" || sourceStatusRank(status) < sourceStatusRank(entry.status) {
				entry.status = status
			}
			if _, present := row["error"]; present {
				entry.errors++
			}
			if refreshed, ok := metricTime(row["last_refresh"]); ok &&
				(entry.lastRefresh.IsZero() || refreshed.Before(entry.lastRefresh)) {
				entry.lastRefresh = refreshed
			}
			if next, ok := metricTime(row["next_refresh"]); ok &&
				(entry.nextRefresh.IsZero() || next.Before(entry.nextRefresh)) {
				entry.nextRefresh = next
			}
			if age, ok := toFloat(row["age_seconds"]); ok &&
				(!entry.hasAge || age > entry.ageSeconds) {
				entry.ageSeconds = age
				entry.hasAge = true
			}
		}
	}

	entries := make([]*aggregate, 0, len(aggregates))
	for _, entry := range aggregates {
		entries = append(entries, entry)
	}
	sort.Slice(entries, func(i, j int) bool { return entries[i].name < entries[j].name })

	result := make([]map[string]any, 0, len(entries))
	for _, entry := range entries {
		row := map[string]any{
			"name":         entry.name,
			"status":       entry.status,
			"instances":    entry.instances,
			"ok_instances": entry.okInstances,
		}
		if !entry.lastRefresh.IsZero() {
			row["last_refresh"] = entry.lastRefresh
		}
		if !entry.nextRefresh.IsZero() {
			row["next_refresh"] = entry.nextRefresh
		}
		if entry.hasAge {
			row["age_seconds"] = entry.ageSeconds
		}
		if entry.errors > 0 {
			row["error"] = fmt.Sprintf("%d instance(s) reported an error", entry.errors)
		}
		result = append(result, row)
	}
	return result
}

func aggregateFleetRecentQueries(instances []peerMetrics, limit int) []QueryLogEntry {
	if limit <= 0 {
		limit = 100
	}
	queries := make([]QueryLogEntry, 0)
	for _, instance := range instances {
		if !instance.Reachable {
			continue
		}
		value := instance.Metrics["recent_queries"]
		if value == nil {
			continue
		}
		encoded, err := json.Marshal(value)
		if err != nil {
			continue
		}
		var entries []QueryLogEntry
		if err := json.Unmarshal(encoded, &entries); err != nil {
			continue
		}
		queries = append(queries, entries...)
	}
	sort.SliceStable(queries, func(i, j int) bool {
		return queries[i].Timestamp.Before(queries[j].Timestamp)
	})
	if len(queries) > limit {
		queries = queries[len(queries)-limit:]
	}
	return queries
}

func metricRows(value any) []map[string]any {
	switch rows := value.(type) {
	case []map[string]any:
		return rows
	case []any:
		result := make([]map[string]any, 0, len(rows))
		for _, value := range rows {
			if row, ok := value.(map[string]any); ok {
				result = append(result, row)
			}
		}
		return result
	default:
		return nil
	}
}

func metricTime(value any) (time.Time, bool) {
	switch timestamp := value.(type) {
	case time.Time:
		return timestamp, !timestamp.IsZero()
	case string:
		parsed, err := time.Parse(time.RFC3339Nano, timestamp)
		return parsed, err == nil
	default:
		return time.Time{}, false
	}
}

func sourceStatusRank(status string) int {
	switch status {
	case "error":
		return 0
	case "stale":
		return 1
	case "due":
		return 2
	case "unknown":
		return 3
	case "ok":
		return 4
	default:
		return 5
	}
}

func toFloat(v any) (float64, bool) {
	switch n := v.(type) {
	case float64:
		return n, true
	case float32:
		return float64(n), true
	case int:
		return float64(n), true
	case int64:
		return float64(n), true
	case uint64:
		return float64(n), true
	case uint:
		return float64(n), true
	}
	return 0, false
}
