package main

import (
	"testing"
	"time"

	"github.com/VividCortex/ewma"
)

func retryTestServer(name string) *ServerInfo {
	return &ServerInfo{Name: name, rtt: ewma.NewMovingAverage(RTTEwmaDecay)}
}

func TestGetOneExceptNeverReturnsExcludedServer(t *testing.T) {
	serversInfo := NewServersInfo()
	serversInfo.inner = []*ServerInfo{
		retryTestServer("excluded"),
		retryTestServer("eligible-a"),
		retryTestServer("eligible-b"),
	}

	for range 100 {
		server := serversInfo.getOneExcept("excluded")
		if server == nil {
			t.Fatal("getOneExcept() returned nil with eligible servers")
		}
		if server.Name == "excluded" {
			t.Fatal("getOneExcept() returned the excluded server")
		}
	}
}

func TestGetOneKeepsConfiguredSelectorForOrdinaryQueries(t *testing.T) {
	serversInfo := NewServersInfo()
	serversInfo.lbStrategy = LBStrategyFirst{}
	serversInfo.inner = []*ServerInfo{
		retryTestServer("first"),
		retryTestServer("second"),
	}

	server := serversInfo.getOne()
	if server == nil {
		t.Fatal("getOne() returned nil")
	}
	if server.Name != "first" {
		t.Fatalf("getOne() = %q, want configured first candidate", server.Name)
	}
}

func TestFirstStrategyPromotesAlternativeAfterFailure(t *testing.T) {
	proxy := NewProxy()
	proxy.timeout = time.Second
	proxy.serversInfo.lbStrategy = LBStrategyFirst{}
	proxy.serversInfo.lbEstimator = false
	proxy.serversInfo.inner = []*ServerInfo{
		retryTestServer("first"),
		retryTestServer("second"),
	}
	proxy.serversInfo.inner[0].rtt.Set(10)
	proxy.serversInfo.inner[1].rtt.Set(20)

	failed := proxy.serversInfo.getOne()
	if failed == nil || failed.Name != "first" {
		t.Fatalf("initial getOne() = %v, want first", failed)
	}
	failed.noticeFailure(proxy)

	next := proxy.serversInfo.getOne()
	if next == nil || next.Name != "second" {
		t.Fatalf("getOne() after failure = %v, want second", next)
	}
}

func TestGetOneExceptReturnsNilWhenNoAlternativeExists(t *testing.T) {
	serversInfo := NewServersInfo()
	serversInfo.inner = []*ServerInfo{retryTestServer("only")}
	if server := serversInfo.getOneExcept("only"); server != nil {
		t.Fatalf("getOneExcept() = %q, want nil", server.Name)
	}
}

func TestGetOneExcludingNeverReusesATriedServer(t *testing.T) {
	serversInfo := NewServersInfo()
	serversInfo.inner = []*ServerInfo{
		retryTestServer("original"),
		retryTestServer("alternate-a"),
		retryTestServer("alternate-b"),
	}
	excluded := map[string]struct{}{"original": {}}

	for range 2 {
		server := serversInfo.getOneExcluding(excluded)
		if server == nil {
			t.Fatal("getOneExcluding() exhausted eligible servers too early")
		}
		if _, wasTried := excluded[server.Name]; wasTried {
			t.Fatalf("getOneExcluding() reused tried server %q", server.Name)
		}
		excluded[server.Name] = struct{}{}
	}
	if server := serversInfo.getOneExcluding(excluded); server != nil {
		t.Fatalf("getOneExcluding() = %q after all servers were tried, want nil", server.Name)
	}
}

func refreshTestServer(name string, initialRtt int) *ServerInfo {
	server := retryTestServer(name)
	server.initialRtt = initialRtt
	server.rtt.Set(float64(initialRtt))
	return server
}

func serverNames(inner []*ServerInfo) []string {
	names := make([]string, len(inner))
	for i, server := range inner {
		names[i] = server.Name
	}
	return names
}

func TestRefreshKeepsFirstStrategyOrderDespiteLowerProbeRtt(t *testing.T) {
	// The preferred server's latest probe happened to be slower than the
	// backup's. With `first`, that single sample must not switch upstreams.
	inner := []*ServerInfo{
		refreshTestServer("preferred", 80),
		refreshTestServer("backup", 20),
	}
	previous := map[string]int{"preferred": 0, "backup": 1}

	orderAfterRefresh(inner, previous, true)

	if got := serverNames(inner); got[0] != "preferred" || got[1] != "backup" {
		t.Fatalf("order after refresh = %v, want [preferred backup]", got)
	}
}

func TestRefreshKeepsFailureDemotion(t *testing.T) {
	proxy := NewProxy()
	proxy.timeout = time.Second
	proxy.serversInfo.lbStrategy = LBStrategyFirst{}
	proxy.serversInfo.inner = []*ServerInfo{
		refreshTestServer("fast-probe", 10),
		refreshTestServer("alternate", 20),
	}
	proxy.serversInfo.inner[0].noticeFailure(proxy)
	if got := serverNames(proxy.serversInfo.inner); got[0] != "alternate" {
		t.Fatalf("order after failure = %v, want alternate first", got)
	}

	previous := map[string]int{}
	for i, server := range proxy.serversInfo.inner {
		previous[server.Name] = i
	}
	orderAfterRefresh(proxy.serversInfo.inner, previous, proxy.serversInfo.keepsOrderAcrossRefresh())

	if got := serverNames(proxy.serversInfo.inner); got[0] != "alternate" {
		t.Fatalf("order after refresh = %v, want the demotion kept", got)
	}
}

func TestRefreshOrdersNewServersByProbeRtt(t *testing.T) {
	// At startup nothing is known yet, so every strategy starts from the
	// lowest probe RTT. Servers added later queue behind the known ones.
	inner := []*ServerInfo{
		refreshTestServer("slow", 90),
		refreshTestServer("known", 50),
		refreshTestServer("fast", 10),
	}

	orderAfterRefresh(inner, map[string]int{}, true)
	if got := serverNames(inner); got[0] != "fast" || got[1] != "known" || got[2] != "slow" {
		t.Fatalf("startup order = %v, want [fast known slow]", got)
	}

	orderAfterRefresh(inner, map[string]int{"known": 0}, true)
	if got := serverNames(inner); got[0] != "known" || got[1] != "fast" || got[2] != "slow" {
		t.Fatalf("order with one known server = %v, want [known fast slow]", got)
	}
}

func TestRefreshResortsByProbeRttForOtherStrategies(t *testing.T) {
	inner := []*ServerInfo{
		refreshTestServer("was-first", 80),
		refreshTestServer("faster", 20),
	}
	orderAfterRefresh(inner, map[string]int{"was-first": 0, "faster": 1}, false)
	if got := serverNames(inner); got[0] != "faster" {
		t.Fatalf("order = %v, want probe-RTT order when not keeping existing", got)
	}
}
