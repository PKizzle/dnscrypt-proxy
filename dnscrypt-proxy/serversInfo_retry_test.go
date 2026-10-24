package main

import (
	"errors"
	"slices"
	"sync"
	"testing"
	"time"

	"github.com/VividCortex/ewma"
)

func retryTestServer(name string) *ServerInfo {
	return &ServerInfo{Name: name, rtt: ewma.NewMovingAverage(RTTEwmaDecay)}
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

// refreshFirstServer replaces the head the way a certificate refresh does and
// returns the ServerInfo it replaced, which exchanges still running keep using.
func refreshFirstServer(proxy *Proxy) (replaced, installed *ServerInfo) {
	proxy.serversInfo.Lock()
	defer proxy.serversInfo.Unlock()
	replaced = proxy.serversInfo.inner[0]
	installed = refreshTestServer(replaced.Name, replaced.initialRtt+5)
	proxy.serversInfo.installRefreshedServerLocked(installed)
	return replaced, installed
}

func TestRefreshKeepsAFailureOfAnExchangeStillRunning(t *testing.T) {
	// The exchange was sent before the refresh and fails after it. The server
	// it demotes must still fail back, or it stays behind the slower one.
	proxy := firstStrategyFailbackProxy()
	replaced, _ := refreshFirstServer(proxy)
	replaced.noticeFailure(proxy)
	if got := serverNames(proxy.serversInfo.inner)[0]; got != "slow" {
		t.Fatalf("head after the failure = %q, want slow", got)
	}

	failBackAt(proxy, time.Now().Add(firstStrategyFailbackDelay))
	if got := serverNames(proxy.serversInfo.inner)[0]; got != "fast" {
		t.Fatalf("head after the failback delay = %q, want fast", got)
	}
}

func TestRefreshKeepsAnAnswerToAnExchangeStillRunning(t *testing.T) {
	// The answer arrived on the replaced ServerInfo after the timed-out query
	// was sent, so the server was still answering: the timeout is isolated.
	proxy := firstStrategyFailbackProxy()
	replaced, installed := refreshFirstServer(proxy)
	sentAt := time.Now().Add(-time.Millisecond)
	replaced.noticeBegin(proxy)
	replaced.noticeSuccess(proxy)
	installed.noticeExchangeError(proxy, timeoutError{}, sentAt)
	if got := serverNames(proxy.serversInfo.inner)[0]; got != "fast" {
		t.Fatalf("head = %q, want fast kept after an isolated timeout", got)
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
	// Probes measure every server at its initial RTT unless a test says
	// otherwise.
	proxy.serversInfo.probeRtt = func(server *ServerInfo) (float64, error) {
		return float64(server.initialRtt), nil
	}
	return proxy
}

// fakeProbe answers probes from a table that tests can change between
// re-evaluations. A server missing from the table does not answer.
type fakeProbe struct {
	sync.Mutex
	rtt   map[string]float64
	calls map[string]int
}

func installFakeProbe(proxy *Proxy, rtt map[string]float64) *fakeProbe {
	probe := &fakeProbe{rtt: rtt, calls: map[string]int{}}
	proxy.serversInfo.probeRtt = func(server *ServerInfo) (float64, error) {
		probe.Lock()
		defer probe.Unlock()
		probe.calls[server.Name]++
		rtt, ok := probe.rtt[server.Name]
		if !ok {
			return 0, errors.New("no answer")
		}
		return rtt, nil
	}
	return probe
}

func (probe *fakeProbe) set(name string, rtt float64) {
	probe.Lock()
	defer probe.Unlock()
	probe.rtt[name] = rtt
}

func (probe *fakeProbe) callCount(name string) int {
	probe.Lock()
	defer probe.Unlock()
	return probe.calls[name]
}

// failBackAt runs the failback check as getOne does at now and waits for any
// probe round it started to finish.
func failBackAt(proxy *Proxy, now time.Time) {
	proxy.serversInfo.Lock()
	proxy.serversInfo.failBackFirstStrategy(now)
	proxy.serversInfo.Unlock()
	for {
		proxy.serversInfo.Lock()
		probing := proxy.serversInfo.probing
		proxy.serversInfo.Unlock()
		if !probing {
			return
		}
		time.Sleep(time.Millisecond)
	}
}

func headName(proxy *Proxy) string {
	proxy.serversInfo.Lock()
	defer proxy.serversInfo.Unlock()
	return proxy.serversInfo.inner[0].Name
}

// answerAfter records a successful answer that took d.
func answerAfter(proxy *Proxy, server *ServerInfo, d time.Duration) {
	proxy.serversInfo.Lock()
	server.lastActionTS = time.Now().Add(-d)
	proxy.serversInfo.Unlock()
	server.noticeSuccess(proxy)
}

// stalledOverToQuad9 builds the production failure: Cloudflare answers late
// but under the timeout while it stalls, then times out, and Quad9 takes over
// and serves five minutes of live traffic.
func stalledOverToQuad9(t *testing.T) (*Proxy, *ServerInfo) {
	t.Helper()
	proxy := firstStrategyFailbackProxy()
	cf, q9 := refreshTestServer("cloudflare", 18), refreshTestServer("quad9", 82)
	proxy.serversInfo.inner = []*ServerInfo{cf, q9}
	for range 50 {
		answerAfter(proxy, cf, 18*time.Millisecond)
	}
	answerAfter(proxy, cf, 900*time.Millisecond)
	answerAfter(proxy, cf, 850*time.Millisecond)
	sentAt := time.Now().Add(time.Millisecond)
	time.Sleep(2 * time.Millisecond)
	for range 3 {
		cf.noticeExchangeError(proxy, timeoutError{}, sentAt)
	}
	if got := headName(proxy); got != "quad9" {
		t.Fatalf("after the stall head = %q, want quad9", got)
	}
	for range 600 {
		answerAfter(proxy, q9, 82*time.Millisecond)
	}
	return proxy, cf
}

func TestFirstStrategyFailbackReprobesAfterAStall(t *testing.T) {
	// The answers that came back late during the stall leave Cloudflare's
	// estimate far above Quad9's. The probes show it as fast again, so it
	// regains the head after one failback delay.
	proxy, cf := stalledOverToQuad9(t)
	installFakeProbe(proxy, map[string]float64{"cloudflare": 18, "quad9": 82})
	failBackAt(proxy, cf.failover.demotedAt.Add(firstStrategyFailbackDelay))
	if got := headName(proxy); got != "cloudflare" {
		t.Fatalf("head after the failback delay = %q, want cloudflare", got)
	}
	if !cf.failover.demotedAt.IsZero() {
		t.Fatal("failback did not clear the demotion")
	}
	if got := cf.rtt.Value(); got != 18 {
		t.Fatalf("cloudflare RTT estimate = %v, want the probe's 18", got)
	}
}

func TestFirstStrategyFailbackReevaluatesASlowerServer(t *testing.T) {
	proxy, cf := stalledOverToQuad9(t)
	probe := installFakeProbe(proxy, map[string]float64{"cloudflare": 300, "quad9": 82})
	start := cf.failover.demotedAt
	failBackAt(proxy, start.Add(firstStrategyFailbackDelay))
	if got := headName(proxy); got != "quad9" {
		t.Fatalf("head after a slower probe = %q, want quad9", got)
	}
	probe.set("cloudflare", 18)
	failBackAt(proxy, start.Add(2*firstStrategyFailbackDelay-time.Second))
	if got := probe.callCount("cloudflare"); got != 2 {
		t.Fatalf("cloudflare probed %d times before the next delay, want 2", got)
	}
	failBackAt(proxy, start.Add(2*firstStrategyFailbackDelay))
	if got := headName(proxy); got != "cloudflare" {
		t.Fatalf("head once the probe shows cloudflare faster = %q, want cloudflare", got)
	}
}

func TestFirstStrategyFailbackRetriesADeadServer(t *testing.T) {
	proxy := firstStrategyFailbackProxy()
	fast := proxy.serversInfo.inner[0]
	fast.noticeFailure(proxy)
	probe := installFakeProbe(proxy, map[string]float64{"slow": 90})
	start := fast.failover.demotedAt
	failBackAt(proxy, start.Add(firstStrategyFailbackDelay))
	if got := headName(proxy); got != "slow" {
		t.Fatalf("head after an unanswered probe = %q, want slow", got)
	}
	if got := probe.callCount("slow"); got != 0 {
		t.Fatalf("head probed %d times after the demoted server failed its probe, want 0", got)
	}
	probe.set("fast", 14)
	failBackAt(proxy, start.Add(2*firstStrategyFailbackDelay))
	if got := headName(proxy); got != "fast" {
		t.Fatalf("head once the server answers again = %q, want fast", got)
	}
}

func TestFirstStrategyFailbackFavoursTheDemotedServerWithinTolerance(t *testing.T) {
	proxy := firstStrategyFailbackProxy()
	fast := proxy.serversInfo.inner[0]
	fast.noticeFailure(proxy)
	installFakeProbe(proxy, map[string]float64{"fast": 95, "slow": 90})
	failBackAt(proxy, fast.failover.demotedAt.Add(firstStrategyFailbackDelay))
	if got := headName(proxy); got != "fast" {
		t.Fatalf("head with probes 95 vs 90 ms = %q, want fast", got)
	}
}

func TestFirstStrategyProbesNothingWithoutFailover(t *testing.T) {
	proxy := firstStrategyFailbackProxy()
	probe := installFakeProbe(proxy, map[string]float64{"fast": 14, "slow": 90})
	for _, after := range []time.Duration{firstStrategyFailbackDelay, time.Hour} {
		failBackAt(proxy, time.Now().Add(after))
	}
	if got := probe.callCount("fast") + probe.callCount("slow"); got != 0 {
		t.Fatalf("%d probes sent with no failover in effect, want 0", got)
	}
}

func TestFirstStrategyRunsOneProbeRoundAtATime(t *testing.T) {
	proxy := firstStrategyFailbackProxy()
	fast := proxy.serversInfo.inner[0]
	fast.noticeFailure(proxy)
	release := make(chan struct{})
	var mu sync.Mutex
	started := 0
	proxy.serversInfo.probeRtt = func(server *ServerInfo) (float64, error) {
		mu.Lock()
		started++
		mu.Unlock()
		<-release
		return float64(server.initialRtt), nil
	}
	due := fast.failover.demotedAt.Add(firstStrategyFailbackDelay)
	for range 3 {
		proxy.serversInfo.Lock()
		proxy.serversInfo.failBackFirstStrategy(due)
		proxy.serversInfo.Unlock()
	}
	inFlight := 0
	for deadline := time.Now().Add(time.Second); inFlight == 0 && time.Now().Before(deadline); {
		time.Sleep(time.Millisecond)
		mu.Lock()
		inFlight = started
		mu.Unlock()
	}
	time.Sleep(10 * time.Millisecond)
	mu.Lock()
	inFlight = started
	mu.Unlock()
	close(release)
	failBackAt(proxy, due.Add(-time.Second))
	if inFlight != 1 {
		t.Fatalf("%d probes in flight, want one round probing one server at a time", inFlight)
	}
	if got := headName(proxy); got != "fast" {
		t.Fatalf("head after the round = %q, want fast", got)
	}
}

func TestFirstStrategyFailsBackAfterDelay(t *testing.T) {
	proxy := firstStrategyFailbackProxy()
	fast := proxy.serversInfo.inner[0]
	fast.noticeFailure(proxy)
	if got := proxy.serversInfo.getOne().Name; got != "slow" {
		t.Fatalf("after failure getOne() = %q, want slow", got)
	}

	failBackAt(proxy, fast.failover.demotedAt.Add(firstStrategyFailbackDelay-time.Second))
	if got := serverNames(proxy.serversInfo.inner)[0]; got != "slow" {
		t.Fatalf("failed back before the delay: head = %q", got)
	}

	failBackAt(proxy, fast.failover.demotedAt.Add(firstStrategyFailbackDelay))
	if got := serverNames(proxy.serversInfo.inner)[0]; got != "fast" {
		t.Fatalf("after the delay head = %q, want fast", got)
	}
	if !fast.failover.demotedAt.IsZero() {
		t.Fatal("failback did not clear the demotion")
	}
}

func TestFirstStrategyNeverPromotesServerThatDidNotFail(t *testing.T) {
	// The backup's stale estimate is lower than the head's live one, but it
	// never failed, so nothing may swap them. Only failures move the head.
	proxy := firstStrategyFailbackProxy()
	proxy.serversInfo.inner[0].rtt.Set(120)
	failBackAt(proxy, time.Now().Add(time.Hour))
	if got := serverNames(proxy.serversInfo.inner)[0]; got != "fast" {
		t.Fatalf("head = %q, want fast to stay", got)
	}
}

func TestFirstStrategyFailbackKeepsBetterReplacement(t *testing.T) {
	// If the probes measure the replacement clearly faster than the failed
	// server, the replacement keeps the head.
	proxy := firstStrategyFailbackProxy()
	fast := proxy.serversInfo.inner[0]
	fast.noticeFailure(proxy)
	installFakeProbe(proxy, map[string]float64{"fast": 40, "slow": 30})
	failBackAt(proxy, fast.failover.demotedAt.Add(firstStrategyFailbackDelay))
	if got := serverNames(proxy.serversInfo.inner)[0]; got != "slow" {
		t.Fatalf("head = %q, want the faster replacement kept", got)
	}
}

func TestFirstStrategyFailbackNeverPromotesAServerThatDidNotFail(t *testing.T) {
	// The failed server's probe does not beat the replacement's, so it stays
	// behind. The backup never failed and its estimate is lower than the
	// replacement's but was never measured on live traffic. Failback must not
	// hand it the head: only failures move the head.
	proxy := firstStrategyFailbackProxy()
	proxy.serversInfo.inner = []*ServerInfo{
		refreshTestServer("failed", 70),
		refreshTestServer("replacement", 60),
		refreshTestServer("backup", 50),
	}
	proxy.serversInfo.inner[0].noticeFailure(proxy)
	if got := serverNames(proxy.serversInfo.inner)[0]; got != "replacement" {
		t.Fatalf("head after the failure = %q, want replacement", got)
	}

	failBackAt(proxy, time.Now().Add(firstStrategyFailbackDelay))
	if got := serverNames(proxy.serversInfo.inner)[0]; got != "replacement" {
		t.Fatalf("head after failback = %q, want replacement", got)
	}
}

func TestFirstStrategyFailbackKeepsTheOrderOfTheOtherServers(t *testing.T) {
	proxy := firstStrategyFailbackProxy()
	proxy.serversInfo.inner = []*ServerInfo{
		refreshTestServer("failed", 14),
		refreshTestServer("replacement", 90),
		refreshTestServer("backup", 50),
	}
	proxy.serversInfo.inner[0].noticeFailure(proxy)

	failBackAt(proxy, time.Now().Add(firstStrategyFailbackDelay))

	want := []string{"failed", "replacement", "backup"}
	if got := serverNames(proxy.serversInfo.inner); !slices.Equal(got, want) {
		t.Fatalf("order after failback = %v, want %v", got, want)
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
