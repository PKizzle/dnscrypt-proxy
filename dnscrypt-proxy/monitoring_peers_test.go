package main

import (
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
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
	ui.peers = newPeerCollector(ui)

	req := httptest.NewRequest(http.MethodGet, "/api/metrics", nil)
	req.Header.Set("X-Dnscrypt-Peer", "1")
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
