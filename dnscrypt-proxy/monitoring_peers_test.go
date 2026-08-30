package main

import (
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/gorilla/websocket"
)

func TestSumMetricsAddsCounters(t *testing.T) {
	totals := sumMetrics([]peerMetrics{
		{Address: "self", Reachable: true, Metrics: map[string]any{
			"total_queries": float64(100), "cache_hits": float64(80),
			"cache_misses": float64(20), "blocked_queries": float64(5),
		}},
		{Address: "b", Reachable: true, Metrics: map[string]any{
			"total_queries": float64(50), "cache_hits": float64(40),
			"cache_misses": float64(10), "blocked_queries": float64(2),
		}},
	})
	for key, want := range map[string]float64{
		"total_queries": 150, "cache_hits": 120, "cache_misses": 30, "blocked_queries": 7,
	} {
		if got, _ := toFloat(totals[key]); got != want {
			t.Errorf("%s = %v, want %v", key, totals[key], want)
		}
	}
}

func TestSumMetricsAddsDNSSECVerdicts(t *testing.T) {
	totals := sumMetrics([]peerMetrics{
		{Reachable: true, Metrics: map[string]any{"dnssec": map[string]any{
			"mode": "log", "secure": float64(10), "insecure": float64(20),
			"indeterminate": float64(1), "bogus": float64(0),
		}}},
		{Reachable: true, Metrics: map[string]any{"dnssec": map[string]any{
			"mode": "log", "secure": float64(30), "insecure": float64(40),
			"indeterminate": float64(2), "bogus": float64(3),
		}}},
	})
	dnssec, ok := totals["dnssec"].(map[string]any)
	if !ok {
		t.Fatal("fleet totals omit DNSSEC")
	}
	for verdict, want := range map[string]float64{
		"secure": 40, "insecure": 60, "indeterminate": 3, "bogus": 3,
	} {
		if got, _ := toFloat(dnssec[verdict]); got != want {
			t.Errorf("%s = %v, want %v", verdict, dnssec[verdict], want)
		}
	}
	if mode, _ := dnssec["mode"].(string); mode != "log" {
		t.Errorf("mode = %q, want log", mode)
	}
}

func TestSumMetricsReportsMixedDNSSECModes(t *testing.T) {
	totals := sumMetrics([]peerMetrics{
		{Reachable: true, Metrics: map[string]any{"dnssec": map[string]any{"mode": "log"}}},
		{Reachable: true, Metrics: map[string]any{"dnssec": map[string]any{"mode": "enforce"}}},
	})
	dnssec := totals["dnssec"].(map[string]any)
	if mode, _ := dnssec["mode"].(string); mode != "mixed" {
		t.Errorf("mode = %q, want mixed", mode)
	}
}

// An average cannot be averaged: an instance that answered ten queries must not
// weigh as much as one that answered ten thousand.
func TestSumMetricsWeightsTheAverageByQueries(t *testing.T) {
	totals := sumMetrics([]peerMetrics{
		{Reachable: true, Metrics: map[string]any{
			"total_queries": float64(10000), "avg_response_time": float64(1),
		}},
		{Reachable: true, Metrics: map[string]any{
			"total_queries": float64(10), "avg_response_time": float64(1000),
		}},
	})
	got, _ := toFloat(totals["avg_response_time"])
	// Weighted: (10000*1 + 10*1000) / 10010 ~= 2.0. A plain mean would say 500.5.
	if got < 1.9 || got > 2.1 {
		t.Errorf("avg_response_time = %v, want ~2 (weighted), not the mean of the averages", got)
	}
}

// Totals must come from the instances that answered, and the gap must be
// visible rather than silently reducing the numbers.
func TestSumMetricsIgnoresUnreachableInstances(t *testing.T) {
	instances := []peerMetrics{
		{Reachable: true, Metrics: map[string]any{"total_queries": float64(100)}},
		{Reachable: false, Error: "connection refused"},
	}
	totals := sumMetrics(instances)
	if got, _ := toFloat(totals["total_queries"]); got != 100 {
		t.Errorf("total_queries = %v, want 100 from the reachable instance", got)
	}
	if got, _ := toFloat(totals["instances"]); got != 2 {
		t.Errorf("instances = %v, want 2", got)
	}
	if got, _ := toFloat(totals["instances_reachable"]); got != 1 {
		t.Errorf("instances_reachable = %v, want 1", got)
	}
}

func TestFleetMarksItselfDegradedWhenAPeerIsDown(t *testing.T) {
	ui := newTestMonitoringUI(t)
	defer func() { _ = ui.Stop() }()
	// A port nothing is listening on.
	ui.config.Peers = []string{"127.0.0.1:1"}
	pc := newPeerCollector(ui)

	fleet := pc.Fleet(map[string]any{"total_queries": float64(7)})
	if !fleet.Degraded {
		t.Error("a fleet with an unreachable instance should say so")
	}
	if got, _ := toFloat(fleet.Totals["total_queries"]); got != 7 {
		t.Errorf("totals = %v, want this instance's own 7 to still be counted", got)
	}
	if len(fleet.Instances) != 2 {
		t.Errorf("instances = %d, want self plus the unreachable peer", len(fleet.Instances))
	}
}

// A peer answers with its own numbers and must not aggregate in turn, or every
// page view would fan out across the whole fleet repeatedly.
func TestPeerRequestIsNotAggregatedAgain(t *testing.T) {
	ui := newTestMonitoringUI(t)
	defer func() { _ = ui.Stop() }()
	ui.config.Peers = []string{"127.0.0.1:1"}
	ui.config.PeerToken = "test-peer-token"
	ui.peers = newPeerCollector(ui)

	req := httptest.NewRequest(http.MethodGet, "/api/metrics", nil)
	req.Header.Set("X-Dnscrypt-Peer", "1")
	req.Header.Set("X-Dnscrypt-Peer-Token", ui.config.PeerToken)
	rec := httptest.NewRecorder()
	ui.handleMetrics(rec, req)

	var body map[string]any
	if err := json.NewDecoder(rec.Body).Decode(&body); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if _, aggregated := body["fleet"]; aggregated {
		t.Error("a request from a peer should be answered without aggregating")
	}
}

func newFleetTestUI(t *testing.T) (*MonitoringUI, func()) {
	t.Helper()
	peer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("X-Dnscrypt-Peer") != "1" {
			t.Error("a request to a peer should identify itself as one")
		}
		if r.Header.Get("X-Dnscrypt-Peer-Token") != "test-peer-token" {
			t.Error("a request to a peer should authenticate itself")
		}
		_ = json.NewEncoder(w).Encode(map[string]any{
			"instance_id":   "test-peer",
			"total_queries": float64(33),
			"cache_hits":    float64(30),
		})
	}))

	ui := newTestMonitoringUI(t)
	ui.config.Peers = []string{peer.Listener.Addr().String()}
	ui.config.PeerToken = "test-peer-token"
	ui.peers = newPeerCollector(ui)
	return ui, func() {
		peer.Close()
		_ = ui.Stop()
	}
}

func assertFleetPayload(t *testing.T, payload map[string]any) {
	t.Helper()
	var totals map[string]any
	switch fleet := payload["fleet"].(type) {
	case *FleetMetrics:
		totals = fleet.Totals
	case map[string]any:
		totals, _ = fleet["totals"].(map[string]any)
		if mode, _ := fleet["mode"].(string); mode != "aggregate" {
			t.Errorf("browser fleet mode = %q, want aggregate", mode)
		}
		if _, exposesInstances := fleet["instances"]; exposesInstances {
			t.Error("browser fleet metadata must not expose per-instance metrics")
		}
	}
	if totals == nil {
		t.Fatalf("browser payload has no fleet totals: %#v", payload)
	}
	if instances, _ := toFloat(totals["instances"]); instances != 2 {
		t.Errorf("fleet totals instances = %v, want 2", instances)
	}
	if reachable, _ := toFloat(totals["instances_reachable"]); reachable != 2 {
		t.Errorf("fleet totals reachable instances = %v, want 2", reachable)
	}
}

func assertFleetOnlyBrowserPayload(t *testing.T, payload map[string]any) {
	t.Helper()
	assertFleetPayload(t, payload)
	for _, key := range []string{"instance_id", "peer_top_domains", "peer_query_types", "uptime_seconds"} {
		if _, present := payload[key]; present {
			t.Errorf("browser payload exposes local-only %q", key)
		}
	}
}

func TestBrowserMetricsAlwaysAddsFleetWithoutMutatingLocalMetrics(t *testing.T) {
	ui, cleanup := newFleetTestUI(t)
	defer cleanup()

	local := ui.metricsCollector.GetMetrics()
	payload := ui.browserMetrics()
	assertFleetOnlyBrowserPayload(t, payload)
	if _, hasFleet := local["fleet"]; hasFleet {
		t.Error("adding fleet to a browser payload must not mutate cached local metrics")
	}

	browserReq := httptest.NewRequest(http.MethodGet, "/api/metrics", nil)
	browserRec := httptest.NewRecorder()
	ui.handleMetrics(browserRec, browserReq)
	var browserPayload map[string]any
	if err := json.NewDecoder(browserRec.Body).Decode(&browserPayload); err != nil {
		t.Fatalf("decode browser payload: %v", err)
	}
	assertFleetOnlyBrowserPayload(t, browserPayload)

	req := httptest.NewRequest(http.MethodGet, "/api/metrics", nil)
	req.Header.Set("X-Dnscrypt-Peer", "1")
	req.Header.Set("X-Dnscrypt-Peer-Token", ui.config.PeerToken)
	rec := httptest.NewRecorder()
	ui.handleMetrics(rec, req)
	var peerPayload map[string]any
	if err := json.NewDecoder(rec.Body).Decode(&peerPayload); err != nil {
		t.Fatalf("decode peer payload: %v", err)
	}
	if _, hasFleet := peerPayload["fleet"]; hasFleet {
		t.Error("a peer response must remain local")
	}
}

func TestUntrustedPeerHeaderCannotExposeLocalMetrics(t *testing.T) {
	ui, cleanup := newFleetTestUI(t)
	defer cleanup()

	req := httptest.NewRequest(http.MethodGet, "/api/metrics", nil)
	req.Header.Set("X-Dnscrypt-Peer", "1")
	req.Header.Set("X-Dnscrypt-Peer-Token", "wrong-token")
	rec := httptest.NewRecorder()
	ui.handleMetrics(rec, req)

	if rec.Code != http.StatusForbidden {
		t.Fatalf("untrusted peer request status = %d, want %d", rec.Code, http.StatusForbidden)
	}
	if strings.Contains(rec.Body.String(), "instance_id") {
		t.Error("untrusted peer request exposed local metrics")
	}
}

func TestMissingPeerTokenNeverFallsBackToLocalMetrics(t *testing.T) {
	ui := newTestMonitoringUI(t)
	defer func() { _ = ui.Stop() }()
	ui.config.Peers = []string{"127.0.0.1:1"}
	ui.peers = newPeerCollector(ui)

	payload := ui.browserMetrics()
	fleet, _ := payload["fleet"].(map[string]any)
	if mode, _ := fleet["mode"].(string); mode != "unavailable" {
		t.Fatalf("fleet mode = %q, want unavailable", mode)
	}
	for _, key := range []string{"instance_id", "peer_top_domains", "peer_query_types", "uptime_seconds"} {
		if _, present := payload[key]; present {
			t.Errorf("missing peer token exposed local-only %q", key)
		}
	}
}

func TestWebSocketMetricsAlwaysCarryFleet(t *testing.T) {
	ui, cleanup := newFleetTestUI(t)
	defer cleanup()

	server := httptest.NewServer(http.HandlerFunc(ui.handleWebSocket))
	defer server.Close()
	wsURL := "ws" + strings.TrimPrefix(server.URL, "http")
	conn, _, err := websocket.DefaultDialer.Dial(wsURL, nil)
	if err != nil {
		t.Fatalf("dial websocket: %v", err)
	}
	defer conn.Close()

	readPayload := func() map[string]any {
		t.Helper()
		_ = conn.SetReadDeadline(time.Now().Add(5 * time.Second))
		var payload map[string]any
		if err := conn.ReadJSON(&payload); err != nil {
			t.Fatalf("read websocket payload: %v", err)
		}
		return payload
	}

	assertFleetOnlyBrowserPayload(t, readPayload())
	if err := conn.WriteJSON(map[string]string{"type": "ping"}); err != nil {
		t.Fatalf("write ping: %v", err)
	}
	if pong := readPayload(); pong["type"] != "pong" {
		t.Fatalf("got %#v, want pong", pong)
	}
	assertFleetOnlyBrowserPayload(t, readPayload())

	ui.broadcastMetrics()
	assertFleetOnlyBrowserPayload(t, readPayload())
}

func TestBrowserFleetMetricsAggregatesAllDashboardPanels(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	instances := []peerMetrics{
		{
			Address: "self", Reachable: true, Metrics: map[string]any{
				"instance_id":       "local-only",
				"total_queries":     float64(100),
				"cache_hits":        float64(80),
				"cache_misses":      float64(20),
				"blocked_queries":   float64(4),
				"avg_response_time": float64(2),
				"cache_stats": map[string]any{
					"enabled": true, "configured_size": float64(10), "entries": float64(3),
					"capacity": float64(10), "min_ttl": float64(60), "max_ttl": float64(600),
					"neg_min_ttl": float64(30), "neg_max_ttl": float64(300),
				},
				"peer_query_types": map[string]uint64{"A": 7, "AAAA": 2},
				"peer_top_domains": map[string]uint64{"one.example": 4, "two.example": 9},
				"resolver_health": []map[string]any{{
					"name": "resolver", "proto": "dnscrypt", "status": "healthy",
					"total_queries": float64(100), "failed_queries": float64(1),
					"avg_response_ms": float64(2), "last_update": now,
				}},
				"sources": []map[string]any{{
					"name": "public-resolvers", "status": "ok", "last_refresh": now,
					"next_refresh": now.Add(time.Hour), "age_seconds": float64(2),
				}},
				"recent_queries": []QueryLogEntry{
					{Timestamp: now.Add(-3 * time.Second), Domain: "old.example"},
					{Timestamp: now.Add(-1 * time.Second), Domain: "new.example"},
				},
			},
		},
		{
			Address: "peer", Reachable: true, Metrics: map[string]any{
				"instance_id":       "peer-only",
				"total_queries":     float64(50),
				"cache_hits":        float64(30),
				"cache_misses":      float64(20),
				"blocked_queries":   float64(3),
				"avg_response_time": float64(10),
				"cache_stats": map[string]any{
					"enabled": true, "configured_size": float64(10), "entries": float64(5),
					"capacity": float64(10), "min_ttl": float64(60), "max_ttl": float64(600),
					"neg_min_ttl": float64(30), "neg_max_ttl": float64(300),
				},
				"peer_query_types": map[string]any{"A": float64(5), "TXT": float64(3)},
				"peer_top_domains": map[string]any{"one.example": float64(8), "three.example": float64(7)},
				"resolver_health": []map[string]any{{
					"name": "resolver", "proto": "dnscrypt", "status": "degraded",
					"total_queries": float64(50), "failed_queries": float64(2),
					"avg_response_ms": float64(10), "last_update": now.Add(-time.Minute),
				}},
				"sources": []map[string]any{{
					"name": "public-resolvers", "status": "due", "last_refresh": now.Add(-time.Minute),
					"next_refresh": now.Add(-time.Minute), "age_seconds": float64(62),
				}},
				"recent_queries": []QueryLogEntry{
					{Timestamp: now.Add(-2 * time.Second), Domain: "middle.example"},
				},
			},
		},
	}
	fleet := &FleetMetrics{Instances: instances}
	fleet.Totals = sumMetrics(instances)
	payload := browserFleetMetrics(fleet, 2)

	assertFleetOnlyBrowserPayload(t, payload)
	if got, _ := toFloat(payload["total_queries"]); got != 150 {
		t.Errorf("total queries = %v, want 150", got)
	}
	cacheStats, _ := payload["cache_stats"].(map[string]any)
	if entries, _ := toFloat(cacheStats["entries"]); entries != 8 {
		t.Errorf("cache entries = %v, want 8", entries)
	}
	queryTypes := metricRows(payload["query_types"])
	if len(queryTypes) != 3 || queryTypes[0]["type"] != "A" {
		t.Errorf("query types = %#v, want fleet aggregate led by A", queryTypes)
	}
	domains := metricRows(payload["top_domains"])
	if len(domains) != 3 || domains[0]["domain"] != "one.example" {
		t.Errorf("top domains = %#v, want fleet aggregate led by one.example", domains)
	}
	resolvers := metricRows(payload["resolver_health"])
	if len(resolvers) != 1 {
		t.Fatalf("resolver health = %#v, want one fleet row", resolvers)
	}
	if status, _ := resolvers[0]["status"].(string); status != "degraded" {
		t.Errorf("resolver status = %q, want conservative degraded", status)
	}
	if total, _ := toFloat(resolvers[0]["total_queries"]); total != 150 {
		t.Errorf("resolver total = %v, want 150", total)
	}
	sources := metricRows(payload["sources"])
	if len(sources) != 1 {
		t.Fatalf("sources = %#v, want one fleet row", sources)
	}
	if status, _ := sources[0]["status"].(string); status != "due" {
		t.Errorf("source status = %q, want conservative due", status)
	}
	if coverage, _ := toFloat(sources[0]["instances"]); coverage != 2 {
		t.Errorf("source coverage = %v, want 2", coverage)
	}
	queries, _ := payload["recent_queries"].([]QueryLogEntry)
	if len(queries) != 2 || queries[0].Domain != "middle.example" || queries[1].Domain != "new.example" {
		t.Errorf("recent queries = %#v, want two newest fleet entries", queries)
	}
}

func TestPeerCollectorAggregatesARealPeer(t *testing.T) {
	peer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("X-Dnscrypt-Peer") != "1" {
			t.Error("a request to a peer should identify itself as one")
		}
		_ = json.NewEncoder(w).Encode(map[string]any{
			"total_queries": float64(33), "cache_hits": float64(30),
		})
	}))
	defer peer.Close()

	ui := newTestMonitoringUI(t)
	defer func() { _ = ui.Stop() }()
	ui.config.Peers = []string{peer.Listener.Addr().String()}
	pc := newPeerCollector(ui)

	fleet := pc.Fleet(map[string]any{"total_queries": float64(7), "cache_hits": float64(5)})
	if fleet.Degraded {
		t.Error("a reachable peer should not mark the fleet degraded")
	}
	if got, _ := toFloat(fleet.Totals["total_queries"]); got != 40 {
		t.Errorf("total_queries = %v, want 40 (7 own + 33 peer)", got)
	}
	if got, _ := toFloat(fleet.Totals["cache_hits"]); got != 35 {
		t.Errorf("cache_hits = %v, want 35", got)
	}
}

// A proxy configured not to use the system resolver must still be able to look
// up the discovery name, which is the whole reason this setting exists.
func TestPeerDiscoveryUsesTheConfiguredResolver(t *testing.T) {
	ui := newTestMonitoringUI(t)
	defer func() { _ = ui.Stop() }()

	if got := newPeerCollector(ui).resolver(); got != net.DefaultResolver {
		t.Error("with nothing configured, discovery should use the system resolver")
	}

	ui.config.PeerDiscoveryResolver = "10.43.0.10"
	if got := newPeerCollector(ui).resolver(); got == net.DefaultResolver {
		t.Error("a configured resolver should be used instead of the system one")
	}
}

// Static peers need no resolution at all, so they work regardless.
func TestStaticPeersNeedNoResolver(t *testing.T) {
	ui := newTestMonitoringUI(t)
	defer func() { _ = ui.Stop() }()
	ui.config.Peers = []string{"10.0.0.2:8080", "10.0.0.3:8080"}

	addrs := newPeerCollector(ui).peerAddresses()
	if len(addrs) != 2 {
		t.Fatalf("peerAddresses() = %v, want the two configured peers", addrs)
	}
}

func TestPreferredPeerAddressesUseOneFamilyPerDualStackInstance(t *testing.T) {
	addresses := []string{"10.42.0.2", "fd01::2", "10.42.0.3", "fd01::3"}
	got := preferredPeerAddresses(addresses)
	want := []string{"10.42.0.2", "10.42.0.3"}
	if len(got) != len(want) {
		t.Fatalf("preferredPeerAddresses(%v) = %v, want %v", addresses, got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("preferredPeerAddresses(%v)[%d] = %q, want %q", addresses, i, got[i], want[i])
		}
	}

	ipv6Only := []string{"fd01::2", "fd01::3"}
	if got := preferredPeerAddresses(ipv6Only); len(got) != len(ipv6Only) || got[0] != ipv6Only[0] {
		t.Errorf("preferredPeerAddresses(%v) = %v, want IPv6-only addresses unchanged", ipv6Only, got)
	}
}

// The same instance listed twice, or discovered twice, is still one instance:
// counting it twice would inflate every total.
func TestPeerAddressesAreDeduplicated(t *testing.T) {
	ui := newTestMonitoringUI(t)
	defer func() { _ = ui.Stop() }()
	ui.config.Peers = []string{"10.0.0.2:8080", "10.0.0.2:8080", "10.0.0.3:8080"}

	addrs := newPeerCollector(ui).peerAddresses()
	if len(addrs) != 2 {
		t.Errorf("peerAddresses() = %v, want duplicates collapsed", addrs)
	}
}

// The caller puts the fleet back into the map it passed in, so the fleet must
// not hold that same map: encoding a structure that contains itself does not
// terminate, and the endpoint returned nothing at all when it did.
func TestFleetResultCanBeEncodedAfterBeingStoredInItsOwnInput(t *testing.T) {
	ui := newTestMonitoringUI(t)
	defer func() { _ = ui.Stop() }()
	pc := newPeerCollector(ui)

	own := map[string]any{"total_queries": float64(7)}
	fleet := pc.Fleet(own)
	// Exactly what the handler does.
	own["fleet"] = fleet

	if _, err := json.Marshal(own); err != nil {
		t.Fatalf("encoding the metrics with the fleet in them failed: %v", err)
	}
}

// One instance listening on several addresses is handed back once per address
// by discovery. Counted once per address, the totals come out a multiple of the
// truth -- which reads as traffic that never happened.
func TestOneInstanceReachedByTwoAddressesIsCountedOnce(t *testing.T) {
	serve := func() *httptest.Server {
		return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			_ = json.NewEncoder(w).Encode(map[string]any{
				"instance_id":   "the-same-proxy",
				"total_queries": float64(33), "cache_hits": float64(30),
			})
		}))
	}
	v4, v6 := serve(), serve()
	defer v4.Close()
	defer v6.Close()

	ui := newTestMonitoringUI(t)
	defer func() { _ = ui.Stop() }()
	ui.config.Peers = []string{v4.Listener.Addr().String(), v6.Listener.Addr().String()}
	pc := newPeerCollector(ui)

	fleet := pc.Fleet(map[string]any{"total_queries": float64(7), "cache_hits": float64(5)})
	if got, _ := toFloat(fleet.Totals["total_queries"]); got != 40 {
		t.Errorf("total_queries = %v, want 40 (7 own + 33 from the one peer)", got)
	}
	if len(fleet.Instances) != 2 {
		t.Fatalf("instances = %d, want 2 (self and the one peer)", len(fleet.Instances))
	}
	if aliases := fleet.Instances[1].Aliases; len(aliases) != 1 {
		t.Errorf("the second address should be recorded as an alias, got %v", aliases)
	}
}

// Discovery hands this instance its own addresses along with everyone else's,
// and it has already counted itself.
func TestThisInstanceIsNotCountedTwiceWhenDiscoveryReturnsIt(t *testing.T) {
	me := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{
			"instance_id": instanceID, "total_queries": float64(7),
		})
	}))
	defer me.Close()

	ui := newTestMonitoringUI(t)
	defer func() { _ = ui.Stop() }()
	ui.config.Peers = []string{me.Listener.Addr().String()}
	pc := newPeerCollector(ui)

	fleet := pc.Fleet(map[string]any{"instance_id": instanceID, "total_queries": float64(7)})
	if got, _ := toFloat(fleet.Totals["total_queries"]); got != 7 {
		t.Errorf("total_queries = %v, want 7 -- this instance counted once", got)
	}
	if len(fleet.Instances) != 1 {
		t.Errorf("instances = %d, want 1", len(fleet.Instances))
	}
}
