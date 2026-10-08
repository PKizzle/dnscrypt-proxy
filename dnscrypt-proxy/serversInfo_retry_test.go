package main

import (
	"errors"
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

func firstStrategyFailbackProxy() *Proxy {
	proxy := NewProxy()
	proxy.timeout = time.Second
	proxy.serversInfo.lbStrategy = LBStrategyFirst{}
	proxy.serversInfo.lbEstimator = false
	proxy.serversInfo.inner = []*ServerInfo{
		refreshTestServer("fast", 14),
		refreshTestServer("slow", 90),
	}
	return proxy
}

func TestFirstStrategyFailsBackAfterDelay(t *testing.T) {
	proxy := firstStrategyFailbackProxy()
	fast := proxy.serversInfo.inner[0]
	fast.noticeFailure(proxy)
	if got := proxy.serversInfo.getOne().Name; got != "slow" {
		t.Fatalf("after failure getOne() = %q, want slow", got)
	}

	proxy.serversInfo.Lock()
	proxy.serversInfo.failBackFirstStrategy(fast.demotedAt.Add(firstStrategyFailbackDelay - time.Second))
	proxy.serversInfo.Unlock()
	if got := serverNames(proxy.serversInfo.inner)[0]; got != "slow" {
		t.Fatalf("failed back before the delay: head = %q", got)
	}

	proxy.serversInfo.Lock()
	proxy.serversInfo.failBackFirstStrategy(fast.demotedAt.Add(firstStrategyFailbackDelay))
	proxy.serversInfo.Unlock()
	if got := serverNames(proxy.serversInfo.inner)[0]; got != "fast" {
		t.Fatalf("after the delay head = %q, want fast", got)
	}
	if !fast.demotedAt.IsZero() {
		t.Fatal("failback did not clear the demotion")
	}
}

func TestFirstStrategyRepeatedFailureKeepsOriginalEstimate(t *testing.T) {
	proxy := firstStrategyFailbackProxy()
	fast := proxy.serversInfo.inner[0]
	fast.noticeFailure(proxy)
	fast.noticeFailure(proxy)
	if fast.preFailureRtt != 14 {
		t.Fatalf("preFailureRtt = %v, want the estimate before the first failure", fast.preFailureRtt)
	}
}

func TestFirstStrategyNeverPromotesServerThatDidNotFail(t *testing.T) {
	// The backup's stale estimate is lower than the head's live one, but it
	// never failed, so nothing may swap them. Only failures move the head.
	proxy := firstStrategyFailbackProxy()
	proxy.serversInfo.inner[0].rtt.Set(120)
	proxy.serversInfo.Lock()
	proxy.serversInfo.failBackFirstStrategy(time.Now().Add(time.Hour))
	proxy.serversInfo.Unlock()
	if got := serverNames(proxy.serversInfo.inner)[0]; got != "fast" {
		t.Fatalf("head = %q, want fast to stay", got)
	}
}

func TestFirstStrategyFailbackKeepsBetterReplacement(t *testing.T) {
	// If the replacement measures faster than the failed server ever did,
	// failback restores the old estimate but the replacement keeps the head.
	proxy := firstStrategyFailbackProxy()
	proxy.serversInfo.inner[1].rtt.Set(30)
	proxy.serversInfo.inner[0].rtt.Set(40)
	fast := proxy.serversInfo.inner[0]
	fast.noticeFailure(proxy)
	proxy.serversInfo.Lock()
	proxy.serversInfo.failBackFirstStrategy(fast.demotedAt.Add(firstStrategyFailbackDelay))
	proxy.serversInfo.Unlock()
	if got := serverNames(proxy.serversInfo.inner)[0]; got != "slow" {
		t.Fatalf("head = %q, want the faster replacement kept", got)
	}
}

func TestFirstStrategyIgnoresIsolatedServfail(t *testing.T) {
	proxy := firstStrategyFailbackProxy()
	fast := proxy.serversInfo.inner[0]
	for range firstStrategyServfailDemotion - 1 {
		fast.noticeFailureReason(proxy, failureReasonServfail)
	}
	if got := serverNames(proxy.serversInfo.inner)[0]; got != "fast" {
		t.Fatalf("isolated SERVFAILs moved the head to %q", got)
	}
	if got := fast.rtt.Value(); got != 14 {
		t.Fatalf("isolated SERVFAILs changed the RTT estimate to %v", got)
	}
}

func TestFirstStrategySuccessResetsServfailRun(t *testing.T) {
	proxy := firstStrategyFailbackProxy()
	fast := proxy.serversInfo.inner[0]
	for range firstStrategyServfailDemotion - 1 {
		fast.noticeFailureReason(proxy, failureReasonServfail)
	}
	fast.noticeBegin(proxy)
	fast.noticeSuccess(proxy)
	fast.noticeFailureReason(proxy, failureReasonServfail)
	if got := serverNames(proxy.serversInfo.inner)[0]; got != "fast" {
		t.Fatalf("SERVFAILs separated by a success moved the head to %q", got)
	}
}

func TestFirstStrategyDemotesServerThatOnlyServfails(t *testing.T) {
	proxy := firstStrategyFailbackProxy()
	fast := proxy.serversInfo.inner[0]
	for range firstStrategyServfailDemotion {
		fast.noticeFailureReason(proxy, failureReasonServfail)
	}
	if got := serverNames(proxy.serversInfo.inner)[0]; got != "slow" {
		t.Fatalf("a server answering only SERVFAIL kept the head: %q", got)
	}
}

func TestFirstStrategyTimeoutStillFailsOverImmediately(t *testing.T) {
	proxy := firstStrategyFailbackProxy()
	proxy.serversInfo.inner[0].noticeFailureReason(proxy, failureReasonTimeout)
	if got := serverNames(proxy.serversInfo.inner)[0]; got != "slow" {
		t.Fatalf("head after a timeout = %q, want slow", got)
	}
}

type timeoutError struct{}

func (timeoutError) Error() string   { return "i/o timeout" }
func (timeoutError) Timeout() bool   { return true }
func (timeoutError) Temporary() bool { return true }

func TestFirstStrategyKeepsServerThatAnsweredOtherQueries(t *testing.T) {
	// A slow zone: the query was sent, other queries were answered while it
	// waited, then it timed out. Another upstream would wait just as long.
	proxy := firstStrategyFailbackProxy()
	fast := proxy.serversInfo.inner[0]
	sentAt := time.Now()
	fast.noticeBegin(proxy)
	fast.noticeSuccess(proxy)
	fast.noticeExchangeError(proxy, timeoutError{}, sentAt.Add(-time.Millisecond))

	if got := serverNames(proxy.serversInfo.inner)[0]; got != "fast" {
		t.Fatalf("an isolated timeout moved the head to %q", got)
	}
	counts := proxy.serversInfo.failureCounts()
	if counts[serverFailureKey{"fast", failureReasonIsolatedTimeout}] != 1 || counts[serverFailureKey{"fast", failureReasonTimeout}] != 0 {
		t.Fatalf("failure counts = %v, want one isolated timeout", counts)
	}
}

func TestFirstStrategyFailsOverWhenNothingWasAnswered(t *testing.T) {
	proxy := firstStrategyFailbackProxy()
	fast := proxy.serversInfo.inner[0]
	fast.noticeBegin(proxy)
	fast.noticeSuccess(proxy) // answered before the query was sent
	time.Sleep(2 * time.Millisecond)
	fast.noticeExchangeError(proxy, timeoutError{}, time.Now())

	if got := serverNames(proxy.serversInfo.inner)[0]; got != "slow" {
		t.Fatalf("head after a timeout on a silent server = %q, want slow", got)
	}
}

func TestFirstStrategyCountsServfailAsAnAnswer(t *testing.T) {
	// A SERVFAIL is still a response: the server is reachable.
	proxy := firstStrategyFailbackProxy()
	fast := proxy.serversInfo.inner[0]
	sentAt := time.Now().Add(-time.Millisecond)
	fast.noticeFailureReason(proxy, failureReasonServfail)
	fast.noticeExchangeError(proxy, timeoutError{}, sentAt)
	if got := serverNames(proxy.serversInfo.inner)[0]; got != "fast" {
		t.Fatalf("head = %q, want fast kept after it answered with SERVFAIL", got)
	}
}

func TestFirstStrategyNetworkErrorStillFailsOver(t *testing.T) {
	proxy := firstStrategyFailbackProxy()
	fast := proxy.serversInfo.inner[0]
	fast.noticeBegin(proxy)
	fast.noticeSuccess(proxy)
	fast.noticeExchangeError(proxy, errors.New("connection reset"), time.Now().Add(-time.Second))
	if got := serverNames(proxy.serversInfo.inner)[0]; got != "slow" {
		t.Fatalf("head after a network error = %q, want slow", got)
	}
}
