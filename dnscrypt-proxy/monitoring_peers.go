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
)

// peerMetrics is one instance's answer, or the reason there was not one.
type peerMetrics struct {
	Address   string         `json:"address"`
	Reachable bool           `json:"reachable"`
	Error     string         `json:"error,omitempty"`
	Metrics   map[string]any `json:"metrics,omitempty"`
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
		for _, a := range addrs {
			add(net.JoinHostPort(a, port))
		}
	}
	return out
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
	if pc.cached != nil && time.Since(pc.cachedAt) < peerCacheTTL {
		cached := pc.cached
		pc.mu.Unlock()
		return cached
	}
	pc.mu.Unlock()

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
	fleet.Instances = append(fleet.Instances, peerMetrics{
		Address: "self", Reachable: true, Metrics: own,
	})
	for _, r := range results {
		if !r.Reachable {
			fleet.Degraded = true
		}
		fleet.Instances = append(fleet.Instances, r)
	}
	fleet.Totals = sumMetrics(fleet.Instances)

	pc.mu.Lock()
	pc.cached, pc.cachedAt = fleet, time.Now()
	pc.mu.Unlock()
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
	// aggregate in turn and ask everyone back.
	req.Header.Set("X-Dnscrypt-Peer", "1")

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
