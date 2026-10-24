package main

import (
	crypto_rand "crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"math"
	"math/bits"
	"math/rand"
	"net"
	"net/url"
	"slices"
	"sort"
	"strings"
	"sync"
	"time"

	"codeberg.org/miekg/dns"
	"github.com/VividCortex/ewma"
	"github.com/jedisct1/dlog"
	clocksmith "github.com/jedisct1/go-clocksmith"
	stamps "github.com/jedisct1/go-dnsstamps"
	"golang.org/x/crypto/ed25519"
)

const (
	RTTEwmaDecay = 10.0

	// firstStrategyFailbackDelay is how long a server demoted by a failure
	// under the `first` strategy waits before it may take the head again.
	firstStrategyFailbackDelay = 5 * time.Minute

	// firstStrategyFailbackTolerance is how much slower than the head a
	// demoted server may probe and still regain the head. Single probes
	// jitter by a few milliseconds, and the demoted server held the head
	// before it failed.
	firstStrategyFailbackTolerance = 1.1

	// firstStrategyServfailDemotion is how many SERVFAILs in a row, with no
	// successful answer between them, demote a server under the `first`
	// strategy. A single SERVFAIL is usually a broken domain, which every
	// upstream answers the same way, and must not move all traffic. SERVFAILs
	// the server attributes to the zone through an extended DNS error do not
	// count here, and retries of one name count once.
	firstStrategyServfailDemotion = 3

	// firstStrategyAttributedServfailDemotion and
	// firstStrategyAttributedServfailDuration demote a server whose answers
	// have been nothing but SERVFAILs, however attributed, for that many
	// names over at least that long. A resolver that can reach no authority
	// blames every failure on the zone; a burst of lookups for zones that
	// really are unreachable is over before the duration passes.
	firstStrategyAttributedServfailDemotion = 16
	firstStrategyAttributedServfailDuration = 30 * time.Second
)

type RegisteredServer struct {
	name        string
	stamp       stamps.ServerStamp
	description string
}

type ServerBugs struct {
	fragmentsBlocked bool
}

type DOHClientCreds struct {
	clientCert string
	clientKey  string
	rootCA     string
}

type ServerInfo struct {
	DOHClientCreds     DOHClientCreds
	lastActionTS       time.Time
	rtt                ewma.MovingAverage
	Name               string
	HostName           string
	UDPAddr            *net.UDPAddr
	TCPAddr            *net.TCPAddr
	Relay              *Relay
	URL                *url.URL
	initialRtt         int
	Timeout            time.Duration
	CryptoConstruction CryptoConstruction
	ServerPk           [32]byte
	SharedKey          [32]byte
	MagicQuery         [8]byte
	PqPublicKey        []byte
	PqCertContext      []byte
	pqSession          *pqSessionState
	knownBugs          ServerBugs
	Proto              stamps.StampProtoType
	useGet             bool
	odohTargetConfigs  []ODoHTargetConfig

	// WP2 strategy fields
	totalQueries   uint64    // Total queries sent to this server
	failedQueries  uint64    // Failed queries count
	lastUpdateTime time.Time // Last time metrics were updated
	lastDecayTS    time.Time // Last time RTT was decayed for recovery

	// failover is what the `first` strategy has recorded about the server's
	// failures and answers. Use failoverLocked to reach it.
	failover *failoverState
}

// failoverState is the `first` strategy's record of a server's failures and
// answers. A certificate refresh replaces a ServerInfo while exchanges started
// on the old one may still be running, so the replacement shares this record by
// pointer, as it shares the RTT estimate. An outcome recorded through either
// ServerInfo is then seen through both. The ServersInfo lock guards it.
type failoverState struct {
	// demotedAt is when a failure demoted the server, or when a probe round
	// last found it no faster than the head. It is zero while the server is
	// not demoted.
	demotedAt time.Time
	// consecutiveServfails counts SERVFAILs since the last successful answer,
	// retries of one name counted once; consecutiveServerServfails counts
	// those among them that the server did not blame on the zone.
	// servfailRunStartedAt is when the run began and lastServfailQName is the
	// name of its latest SERVFAIL, so a stub retrying that name adds nothing.
	consecutiveServfails       int
	consecutiveServerServfails int
	servfailRunStartedAt       time.Time
	lastServfailQName          string
	// lastResponseTS is when the server last returned any DNS response,
	// SERVFAIL included. It separates a server that stopped answering from
	// one that is slow for a particular name.
	lastResponseTS time.Time
}

// failoverLocked returns the server's failover record, creating it on first
// use. The ServersInfo lock must be held.
func (serverInfo *ServerInfo) failoverLocked() *failoverState {
	if serverInfo.failover == nil {
		serverInfo.failover = &failoverState{}
	}
	return serverInfo.failover
}

type LBStrategy interface {
	getCandidate(serversCount int) int
	getActiveCount(serversCount int) int
}

type LBStrategyP2 struct{}

func (LBStrategyP2) getCandidate(serversCount int) int {
	return rand.Intn(Min(serversCount, 2))
}

func (LBStrategyP2) getActiveCount(serversCount int) int {
	return Min(serversCount, 2)
}

type LBStrategyPN struct{ n int }

func (s LBStrategyPN) getCandidate(serversCount int) int {
	return rand.Intn(Min(serversCount, s.n))
}

func (s LBStrategyPN) getActiveCount(serversCount int) int {
	return Min(serversCount, s.n)
}

type LBStrategyPH struct{}

func (LBStrategyPH) getCandidate(serversCount int) int {
	return rand.Intn((serversCount + 1) / 2)
}

func (LBStrategyPH) getActiveCount(serversCount int) int {
	return (serversCount + 1) / 2
}

type LBStrategyFirst struct{}

func (LBStrategyFirst) getCandidate(int) int {
	return 0
}

func (LBStrategyFirst) getActiveCount(int) int {
	return 1
}

type LBStrategyRandom struct{}

func (LBStrategyRandom) getCandidate(serversCount int) int {
	return rand.Intn(serversCount)
}

func (LBStrategyRandom) getActiveCount(serversCount int) int {
	return serversCount
}

type LBStrategyWP2 struct{}

func (LBStrategyWP2) getCandidate(serversCount int) int {
	// This function is not used for WP2 - getWeightedCandidate is used instead
	// But we need to implement it to satisfy the LBStrategy interface
	if serversCount <= 1 {
		return 0
	}
	return rand.Intn(serversCount)
}

func (LBStrategyWP2) getActiveCount(serversCount int) int {
	return serversCount // All servers are considered active for WP2
}

var DefaultLBStrategy = LBStrategyWP2{}

type DNSCryptRelay struct {
	RelayUDPAddr *net.UDPAddr
	RelayTCPAddr *net.TCPAddr
}

type ODoHRelay struct {
	URL *url.URL
}

type Relay struct {
	Proto    stamps.StampProtoType
	Dnscrypt *DNSCryptRelay
	ODoH     *ODoHRelay
	Name     string
}

type ServersInfo struct {
	sync.RWMutex
	inner               []*ServerInfo
	registeredServers   []RegisteredServer
	registeredRelays    []RegisteredServer
	lbStrategy          LBStrategy
	lbEstimator         bool
	odohRefreshMu       sync.Mutex
	odohRefreshInFlight map[string]bool
	odohLastFailureAt   map[string]time.Time
	// failures counts upstream failures by server name and reason. It lives
	// here rather than on ServerInfo because a certificate refresh replaces
	// the ServerInfo, and a counter must not reset with it.
	failures map[serverFailureKey]uint64
	// probeRtt measures a server outside the client query path, in
	// milliseconds; probing is set while a failback probe round runs.
	probeRtt func(*ServerInfo) (float64, error)
	probing  bool
}

// Reasons an upstream exchange counts as failed.
const (
	failureReasonTimeout = "timeout"
	// failureReasonIsolatedTimeout is a timeout on a server that answered
	// other queries after the timed-out one was sent: the name is slow, not
	// the server, so it is counted but does not move traffic.
	failureReasonIsolatedTimeout = "isolated_timeout"
	failureReasonNetwork         = "network"
	failureReasonServfail        = "servfail"
	// failureReasonZoneServfail is a SERVFAIL the server attributed to the
	// zone through an extended DNS error: counted, but evidence about the
	// zone rather than the server.
	failureReasonZoneServfail = "zone_servfail"
	failureReasonBadResponse  = "bad_response"
	failureReasonOther        = "other"
)

type serverFailureKey struct {
	server string
	reason string
}

// failureReasonForError classifies a transport error.
func failureReasonForError(err error) string {
	var netErr net.Error
	if errors.As(err, &netErr) && netErr.Timeout() {
		return failureReasonTimeout
	}
	return failureReasonNetwork
}

func NewServersInfo() ServersInfo {
	return ServersInfo{
		lbStrategy:          DefaultLBStrategy,
		lbEstimator:         true,
		registeredServers:   make([]RegisteredServer, 0),
		registeredRelays:    make([]RegisteredServer, 0),
		odohRefreshInFlight: make(map[string]bool),
		odohLastFailureAt:   make(map[string]time.Time),
		failures:            make(map[serverFailureKey]uint64),
	}
}

// failureCounts returns a copy of the failure counters.
func (serversInfo *ServersInfo) failureCounts() map[serverFailureKey]uint64 {
	serversInfo.RLock()
	defer serversInfo.RUnlock()
	counts := make(map[serverFailureKey]uint64, len(serversInfo.failures))
	for key, count := range serversInfo.failures {
		counts[key] = count
	}
	return counts
}

// serverOrder returns the server names in selection order. With the `first`
// strategy the first name is the server that receives every query.
func (serversInfo *ServersInfo) serverOrder() []string {
	serversInfo.RLock()
	defer serversInfo.RUnlock()
	names := make([]string, len(serversInfo.inner))
	for i, server := range serversInfo.inner {
		names[i] = server.Name
	}
	return names
}

// beginODoHRefresh returns true if the caller should perform an ODoH key
// refresh for the named server. It returns false when another refresh is
// already in flight or when the previous attempt failed within the
// failureCooldown window. Successful claims must be paired with a call to
// endODoHRefresh, ideally via defer so a panic in the refresh path does
// not leak the in-flight slot.
func (serversInfo *ServersInfo) beginODoHRefresh(name string, failureCooldown time.Duration) bool {
	now := time.Now()
	serversInfo.odohRefreshMu.Lock()
	defer serversInfo.odohRefreshMu.Unlock()
	if serversInfo.odohRefreshInFlight == nil {
		serversInfo.odohRefreshInFlight = make(map[string]bool)
	}
	if serversInfo.odohLastFailureAt == nil {
		serversInfo.odohLastFailureAt = make(map[string]time.Time)
	}
	if serversInfo.odohRefreshInFlight[name] {
		return false
	}
	if last, ok := serversInfo.odohLastFailureAt[name]; ok && now.Sub(last) < failureCooldown {
		return false
	}
	serversInfo.odohRefreshInFlight[name] = true
	return true
}

// endODoHRefresh releases the in-flight slot claimed by beginODoHRefresh and
// records whether the refresh succeeded. On success the failure timestamp is
// cleared so the next 401 can trigger a fresh refresh immediately if needed.
// On failure the timestamp is stamped to throttle a hostile-relay retry
// loop. Callers that claim a slot but then discover they have no refresh to
// perform (e.g. the server is no longer registered) should use
// cancelODoHRefresh instead so the cooldown state is not mutated.
func (serversInfo *ServersInfo) endODoHRefresh(name string, success bool) {
	serversInfo.odohRefreshMu.Lock()
	defer serversInfo.odohRefreshMu.Unlock()
	delete(serversInfo.odohRefreshInFlight, name)
	if success {
		delete(serversInfo.odohLastFailureAt, name)
	} else {
		if serversInfo.odohLastFailureAt == nil {
			serversInfo.odohLastFailureAt = make(map[string]time.Time)
		}
		serversInfo.odohLastFailureAt[name] = time.Now()
	}
}

// cancelODoHRefresh releases the in-flight slot without touching the failure
// cooldown. It is used when beginODoHRefresh was claimed but no refresh
// actually ran, so neither stamping a failure nor clearing a prior one is
// appropriate.
func (serversInfo *ServersInfo) cancelODoHRefresh(name string) {
	serversInfo.odohRefreshMu.Lock()
	defer serversInfo.odohRefreshMu.Unlock()
	delete(serversInfo.odohRefreshInFlight, name)
}

func (serversInfo *ServersInfo) registerServer(name string, stamp stamps.ServerStamp) {
	newRegisteredServer := RegisteredServer{name: name, stamp: stamp}
	serversInfo.Lock()
	defer serversInfo.Unlock()
	for i, oldRegisteredServer := range serversInfo.registeredServers {
		if oldRegisteredServer.name == name {
			serversInfo.registeredServers[i] = newRegisteredServer
			return
		}
	}
	serversInfo.registeredServers = append(serversInfo.registeredServers, newRegisteredServer)
}

func (serversInfo *ServersInfo) registerRelay(name string, stamp stamps.ServerStamp) {
	newRegisteredServer := RegisteredServer{name: name, stamp: stamp}
	serversInfo.Lock()
	defer serversInfo.Unlock()
	for i, oldRegisteredServer := range serversInfo.registeredRelays {
		if oldRegisteredServer.name == name {
			serversInfo.registeredRelays[i] = newRegisteredServer
			return
		}
	}
	serversInfo.registeredRelays = append(serversInfo.registeredRelays, newRegisteredServer)
}

func (serversInfo *ServersInfo) refreshServer(proxy *Proxy, name string, stamp stamps.ServerStamp) error {
	serversInfo.RLock()
	isNew := true
	for _, oldServer := range serversInfo.inner {
		if oldServer.Name == name {
			isNew = false
			break
		}
	}
	serversInfo.RUnlock()
	newServer, err := fetchServerInfo(proxy, name, stamp, isNew)
	if err != nil {
		return err
	}
	if name != newServer.Name {
		dlog.Fatalf("[%s] != [%s]", name, newServer.Name)
	}
	newServer.rtt = ewma.NewMovingAverage(RTTEwmaDecay)
	newServer.rtt.Set(float64(newServer.initialRtt))
	proxy.cryptoKeyMu.RLock()
	proxy.recomputeServerSharedKeyLocked(&newServer)
	serversInfo.Lock()
	found := serversInfo.installRefreshedServerLocked(&newServer)
	serversInfo.Unlock()
	proxy.cryptoKeyMu.RUnlock()
	if !found {
		proxy.serversInfo.registerServer(name, stamp)
	}

	return nil
}

// installRefreshedServerLocked puts a server fetched by a certificate refresh
// in place of the known server with the same name, or appends it if there is
// none. It reports whether the server was known. serversInfo must be locked.
func (serversInfo *ServersInfo) installRefreshedServerLocked(newServer *ServerInfo) bool {
	for i, oldServer := range serversInfo.inner {
		if oldServer.Name != newServer.Name {
			continue
		}
		if serversInfo.keepsOrderAcrossRefresh() && oldServer.rtt != nil {
			// A certificate refresh is not new evidence about latency. The
			// probe RTT is a single sample and would undo a failure demotion.
			newServer.rtt = oldServer.rtt
			newServer.lastActionTS = oldServer.lastActionTS
			newServer.lastDecayTS = oldServer.lastDecayTS
			newServer.failover = oldServer.failoverLocked()
		}
		serversInfo.inner[i] = newServer
		return true
	}
	serversInfo.inner = append(serversInfo.inner, newServer)
	return false
}

func (serversInfo *ServersInfo) refresh(proxy *Proxy) (int, error) {
	dlog.Debug("Refreshing certificates")
	serversInfo.RLock()
	// Appending registeredServers slice from sources may allocate new memory.
	serversCount := len(serversInfo.registeredServers)
	registeredServers := make([]RegisteredServer, serversCount)
	copy(registeredServers, serversInfo.registeredServers)
	previousOrder := make(map[string]int, len(serversInfo.inner))
	for i, server := range serversInfo.inner {
		previousOrder[server.Name] = i
	}
	serversInfo.RUnlock()
	rand.Shuffle(len(registeredServers), func(i, j int) {
		registeredServers[i], registeredServers[j] = registeredServers[j], registeredServers[i]
	})
	countChannel := make(chan struct{}, proxy.certRefreshConcurrency)
	errorChannel := make(chan error, serversCount)
	for i := range registeredServers {
		countChannel <- struct{}{}
		go func(registeredServer *RegisteredServer) {
			err := serversInfo.refreshServer(proxy, registeredServer.name, registeredServer.stamp)
			if err == nil {
				proxy.xTransport.internalResolverReady.Store(true)
			}
			errorChannel <- err
			<-countChannel
		}(&registeredServers[i])
	}
	liveServers := 0
	var err error
	for range serversCount {
		err = <-errorChannel
		if err == nil {
			liveServers++
		}
	}
	if liveServers > 0 {
		err = nil
	}
	serversInfo.Lock()
	orderAfterRefresh(serversInfo.inner, previousOrder, serversInfo.keepsOrderAcrossRefresh())
	inner := serversInfo.inner
	innerLen := len(inner)
	if innerLen > 1 {
		dlog.Notice("Sorted latencies:")
		for i := range innerLen {
			dlog.Noticef("- %5dms %s", inner[i].initialRtt, inner[i].Name)
		}
	}
	if innerLen > 0 {
		dlog.Noticef("Server with the lowest initial latency: %s (rtt: %dms), live servers: %d", inner[0].Name, inner[0].initialRtt, innerLen)
	}
	serversInfo.Unlock()
	return liveServers, err
}

// keepsOrderAcrossRefresh reports whether the server order is a decision that
// periodic certificate refreshes must preserve. With the `first` strategy the
// order is the server choice: index zero receives every query, and it changes
// only when that server fails. Re-sorting by each refresh's probe RTT would
// switch upstreams every refresh interval on a single noisy sample.
func (serversInfo *ServersInfo) keepsOrderAcrossRefresh() bool {
	_, isFirst := serversInfo.lbStrategy.(LBStrategyFirst)
	return isFirst
}

// orderAfterRefresh sorts servers after a refresh. Servers that are new to this
// refresh are ordered by their initial probe RTT. When keepExisting is set,
// servers that were already known keep their previous relative order and stay
// ahead of new ones; otherwise every server is ordered by its probe RTT.
func orderAfterRefresh(inner []*ServerInfo, previousOrder map[string]int, keepExisting bool) {
	sort.SliceStable(inner, func(i, j int) bool {
		if keepExisting {
			pi, iKnown := previousOrder[inner[i].Name]
			pj, jKnown := previousOrder[inner[j].Name]
			if iKnown && jKnown {
				return pi < pj
			}
			if iKnown != jKnown {
				return iKnown
			}
		}
		return inner[i].initialRtt < inner[j].initialRtt
	})
}

func (serversInfo *ServersInfo) estimatorUpdate(currentActive int) {
	// serversInfo.RWMutex is assumed to be Locked
	serversCount := len(serversInfo.inner)
	activeCount := serversInfo.lbStrategy.getActiveCount(serversCount)
	if activeCount == serversCount {
		return
	}
	candidate := rand.Intn(serversCount-activeCount) + activeCount
	candidateRtt, currentActiveRtt := serversInfo.inner[candidate].rtt.Value(), serversInfo.inner[currentActive].rtt.Value()
	if currentActiveRtt < 0 {
		currentActiveRtt = candidateRtt
		serversInfo.inner[currentActive].rtt.Set(currentActiveRtt)
		return
	}
	if candidateRtt < currentActiveRtt {
		serversInfo.inner[candidate], serversInfo.inner[currentActive] = serversInfo.inner[currentActive], serversInfo.inner[candidate]
		dlog.Debugf(
			"New preferred candidate: %s (RTT: %d vs previous: %d)",
			serversInfo.inner[currentActive].Name,
			int(candidateRtt),
			int(currentActiveRtt),
		)
		serversInfo.sortByRtt()
	}
}

func (serversInfo *ServersInfo) sortByRtt() {
	for i := 1; i < len(serversInfo.inner); i++ {
		if serversInfo.inner[i-1].rtt.Value() > serversInfo.inner[i].rtt.Value() {
			serversInfo.inner[i-1], serversInfo.inner[i] = serversInfo.inner[i], serversInfo.inner[i-1]
		}
	}
}

// failBackFirstStrategy re-evaluates a server that a failure moved off the
// head under the `first` strategy, once firstStrategyFailbackDelay has passed
// since it was demoted or last re-evaluated. The server gets no traffic while
// it is demoted, so its estimate says nothing about how it answers now: a
// background round probes it and the head instead. Nothing is probed while no
// failover is in effect, and at most one round runs at a time.
func (serversInfo *ServersInfo) failBackFirstStrategy(now time.Time) {
	// serversInfo.RWMutex is assumed to be Locked
	if _, isFirst := serversInfo.lbStrategy.(LBStrategyFirst); !isFirst || serversInfo.probeRtt == nil || serversInfo.probing {
		return
	}
	head := serversInfo.inner[0]
	// A failure that left the server at the head did not fail it over.
	head.failoverLocked().demotedAt = time.Time{}
	for _, server := range serversInfo.inner[1:] {
		failover := server.failoverLocked()
		if failover.demotedAt.IsZero() || now.Sub(failover.demotedAt) < firstStrategyFailbackDelay {
			continue
		}
		serversInfo.probing = true
		go serversInfo.probeFailback(server, head, now)
		return
	}
}

// probeFailback probes the demoted server and then the head, and gives the
// demoted server the head back if it answered within
// firstStrategyFailbackTolerance of the head's time. Otherwise it stays
// demoted and is re-evaluated after another firstStrategyFailbackDelay. No
// other server changes place, so a server that never failed is never promoted.
func (serversInfo *ServersInfo) probeFailback(demoted, head *ServerInfo, startedAt time.Time) {
	demotedRtt, headRtt := serversInfo.bestProbeRtt(demoted), math.Inf(1)
	if !math.IsInf(demotedRtt, 1) {
		headRtt = serversInfo.bestProbeRtt(head)
	}
	serversInfo.Lock()
	defer serversInfo.Unlock()
	serversInfo.probing = false
	if len(serversInfo.inner) == 0 || serversInfo.inner[0].Name != head.Name {
		// The head changed during the round, so the comparison is stale.
		return
	}
	failover := demoted.failoverLocked()
	if math.IsInf(demotedRtt, 1) || demotedRtt > headRtt*firstStrategyFailbackTolerance {
		dlog.Debugf("[%s] probed at %.0fms against %.0fms for [%s]; keeping it demoted", demoted.Name,
			demotedRtt, headRtt, head.Name)
		failover.demotedAt = startedAt
		return
	}
	dlog.Infof("[%s] probed at %.0fms against %.0fms for [%s]; restoring it as the preferred server",
		demoted.Name, demotedRtt, headRtt, head.Name)
	failover.demotedAt = time.Time{}
	demoted.rtt.Set(demotedRtt)
	for _, server := range serversInfo.inner {
		// A refresh may have replaced the ServerInfo since the round started.
		if server.Name == demoted.Name {
			serversInfo.moveToHead(server)
			return
		}
	}
}

// bestProbeRtt returns the faster of two probes of server, or +Inf if neither
// was answered. The first probe may pay for a connection that live traffic
// keeps open for the head but not for a server it has left.
func (serversInfo *ServersInfo) bestProbeRtt(server *ServerInfo) float64 {
	best := math.Inf(1)
	for range 2 {
		rtt, err := serversInfo.probeRtt(server)
		if err != nil {
			dlog.Debugf("[%s] failback probe: %v", server.Name, err)
			continue
		}
		best = min(best, rtt)
	}
	return best
}

// moveToHead puts server first. The servers that were ahead of it move back by
// one place and keep their order.
func (serversInfo *ServersInfo) moveToHead(server *ServerInfo) {
	// serversInfo.RWMutex is assumed to be Locked
	for i, candidate := range serversInfo.inner {
		if candidate == server {
			copy(serversInfo.inner[1:i+1], serversInfo.inner[:i])
			serversInfo.inner[0] = server
			return
		}
	}
}

func (serversInfo *ServersInfo) recoverDormantServers() {
	if len(serversInfo.inner) <= 1 {
		return
	}
	serversInfo.failBackFirstStrategy(time.Now())
	bestRtt := serversInfo.inner[0].rtt.Value()
	for _, server := range serversInfo.inner {
		if rtt := server.rtt.Value(); rtt > 0 && rtt < bestRtt {
			bestRtt = rtt
		}
	}
	if bestRtt <= 0 {
		return
	}
	now := time.Now()
	needsSort := false
	for _, server := range serversInfo.inner {
		currentRtt := server.rtt.Value()
		if currentRtt <= bestRtt*4.0 {
			continue
		}
		if now.Sub(server.lastActionTS) <= time.Minute {
			continue
		}
		if now.Sub(server.lastDecayTS) <= 10*time.Second {
			continue
		}
		targetRtt := float64(server.initialRtt)
		if targetRtt <= 0 {
			targetRtt = bestRtt
		}
		server.rtt.Add(targetRtt)
		newRtt := server.rtt.Value()
		server.totalQueries = 0
		server.failedQueries = 0
		server.lastDecayTS = now
		needsSort = true
		dlog.Debugf(
			"Giving a new chance to [%s], lowering its RTT from %d to %d (best: %d)",
			server.Name,
			int(currentRtt),
			int(newRtt),
			int(bestRtt),
		)
	}
	if needsSort {
		serversInfo.sortByRtt()
	}
}

func (serversInfo *ServersInfo) getOne() *ServerInfo {
	serversInfo.Lock()
	serversCount := len(serversInfo.inner)
	if serversCount <= 0 {
		serversInfo.Unlock()
		return nil
	}

	serversInfo.recoverDormantServers()

	var candidate int

	// Check if using WP2 strategy
	if _, isWP2 := serversInfo.lbStrategy.(LBStrategyWP2); isWP2 {
		candidate = serversInfo.getWeightedCandidate(serversCount)
	} else {
		candidate = serversInfo.lbStrategy.getCandidate(serversCount)
		if serversInfo.lbEstimator {
			serversInfo.estimatorUpdate(candidate)
		}
	}

	serverInfo := serversInfo.inner[candidate]
	dlog.Debugf("Using candidate [%s] RTT: %d Score: %.3f",
		serverInfo.Name,
		int(serverInfo.rtt.Value()),
		serversInfo.calculateServerScore(serverInfo))
	serversInfo.Unlock()

	return serverInfo
}

// getWeightedCandidate implements the WP2 algorithm
func (serversInfo *ServersInfo) getWeightedCandidate(serversCount int) int {
	if serversCount <= 1 {
		return 0
	}

	// Select two random servers
	first := rand.Intn(serversCount)
	second := rand.Intn(serversCount)

	// Ensure we have two different servers
	for second == first {
		second = rand.Intn(serversCount)
	}

	server1 := serversInfo.inner[first]
	server2 := serversInfo.inner[second]

	// Calculate weighted scores
	score1 := serversInfo.calculateServerScore(server1)
	score2 := serversInfo.calculateServerScore(server2)

	// Select the better performing server with small randomization
	if score1 > score2 {
		return first
	} else if score2 > score1 {
		return second
	} else {
		// Tie-breaker: random selection
		if rand.Float64() < 0.5 {
			return first
		}
		return second
	}
}

// calculateServerScore computes a performance score for server selection
func (serversInfo *ServersInfo) calculateServerScore(server *ServerInfo) float64 {
	// Base score from RTT (lower RTT = higher score)
	rtt := server.rtt.Value()
	if rtt <= 0 {
		rtt = 1000 // Default high RTT for servers without data
	}

	// Normalize RTT to a 0-1 scale (1000ms max)
	rttScore := 1.0 - (rtt / 1000.0)
	if rttScore < 0.0 {
		rttScore = 0.0
	}

	// Success rate score
	successRate := 1.0 // Default to perfect success rate
	if server.totalQueries > 0 {
		successRate = float64(server.totalQueries-server.failedQueries) / float64(server.totalQueries)
	}

	// Combine scores (RTT weighted 70%, success rate 30%)
	finalScore := (rttScore * 0.7) + (successRate * 0.3)

	return finalScore
}

// updateServerStats updates server statistics after each query
func (serversInfo *ServersInfo) updateServerStats(serverName string, success bool) {
	serversInfo.Lock()
	defer serversInfo.Unlock()

	for _, server := range serversInfo.inner {
		if server.Name == serverName {
			server.totalQueries++
			if !success {
				server.failedQueries++
			}
			server.lastUpdateTime = time.Now()

			// Reset counters periodically to prevent overflow and adapt to changes
			if server.totalQueries > 10000 {
				server.totalQueries = server.totalQueries / 2
				server.failedQueries = server.failedQueries / 2
			}
			break
		}
	}
}

// logWP2Stats logs WP2 performance statistics for debugging
func (serversInfo *ServersInfo) logWP2Stats() {
	if _, isWP2 := serversInfo.lbStrategy.(LBStrategyWP2); !isWP2 {
		return
	}

	serversInfo.RLock()
	defer serversInfo.RUnlock()

	dlog.Debug("WP2 Strategy Server Statistics:")
	for i, server := range serversInfo.inner {
		score := serversInfo.calculateServerScore(server)
		successRate := 1.0
		if server.totalQueries > 0 {
			successRate = float64(server.totalQueries-server.failedQueries) / float64(server.totalQueries)
		}

		dlog.Debugf("[%d] %s: RTT=%dms, Score=%.3f, Success=%.2f%%, Queries=%d",
			i, server.Name, int(server.rtt.Value()), score, successRate*100, server.totalQueries)
	}
}

func fetchServerInfo(proxy *Proxy, name string, stamp stamps.ServerStamp, isNew bool) (ServerInfo, error) {
	if stamp.Proto == stamps.StampProtoTypeDNSCrypt {
		return fetchDNSCryptServerInfo(proxy, name, stamp, isNew)
	} else if stamp.Proto == stamps.StampProtoTypeDoH {
		return fetchDoHServerInfo(proxy, name, stamp, isNew)
	} else if stamp.Proto == stamps.StampProtoTypeODoHTarget {
		return fetchODoHTargetInfo(proxy, name, stamp, isNew)
	}
	return ServerInfo{}, fmt.Errorf("Unsupported protocol for [%s]: [%s]", name, stamp.Proto.String())
}

func findFarthestRoute(proxy *Proxy, name string, relayStamps []stamps.ServerStamp) *stamps.ServerStamp {
	serverIdx := -1
	proxy.serversInfo.RLock()
	for i, registeredServer := range proxy.serversInfo.registeredServers {
		if registeredServer.name == name {
			serverIdx = i
			break
		}
	}
	if serverIdx < 0 {
		proxy.serversInfo.RUnlock()
		return nil
	}
	server := proxy.serversInfo.registeredServers[serverIdx]
	proxy.serversInfo.RUnlock()

	// Fall back to random relays until the logic is implemented for non-DNSCrypt relays
	if server.stamp.Proto == stamps.StampProtoTypeODoHTarget {
		candidates := make([]int, 0)
		for relayIdx, relayStamp := range relayStamps {
			if relayStamp.Proto != stamps.StampProtoTypeODoHRelay {
				continue
			}
			candidates = append(candidates, relayIdx)
		}
		if len(candidates) == 0 {
			return nil
		}
		return &relayStamps[candidates[rand.Intn(len(candidates))]]
	} else if server.stamp.Proto != stamps.StampProtoTypeDNSCrypt {
		return nil
	}

	// Anonymized DNSCrypt relays
	serverAddrStr, _ := ExtractHostAndPort(server.stamp.ServerAddrStr, 443)
	serverAddr := net.ParseIP(serverAddrStr)
	if serverAddr == nil {
		return nil
	}
	if len(proxy.serversInfo.registeredRelays) == 0 {
		return nil
	}
	bestRelayIdxs := make([]int, 0)
	bestRelaySamePrefixBits := 128
	for relayIdx, relayStamp := range relayStamps {
		if relayStamp.Proto != stamps.StampProtoTypeDNSCryptRelay {
			continue
		}
		relayAddrStr, _ := ExtractHostAndPort(relayStamp.ServerAddrStr, 443)
		relayAddr := net.ParseIP(relayAddrStr)
		if relayAddr == nil {
			continue
		}
		relayIsIPv6 := relayAddr.To4() == nil
		if relayIsIPv6 != (serverAddr.To4() == nil) {
			continue
		}
		firstByte := 0
		if !relayIsIPv6 {
			firstByte = 12
		}
		samePrefixBits := 0
		for i := firstByte; i < 16; i++ {
			x := serverAddr[i] ^ relayAddr[i]
			samePrefixBits += bits.LeadingZeros8(x)
			if x != 0 {
				break
			}
		}
		if samePrefixBits < bestRelaySamePrefixBits {
			bestRelaySamePrefixBits = samePrefixBits
			bestRelayIdxs = []int{relayIdx}
		} else if samePrefixBits == bestRelaySamePrefixBits {
			bestRelayIdxs = append(bestRelayIdxs, relayIdx)
		}
	}
	if len(bestRelayIdxs) == 0 {
		return nil
	}
	return &relayStamps[bestRelayIdxs[rand.Intn(len(bestRelayIdxs))]]
}

func relayProtoForServerProto(proto stamps.StampProtoType) (stamps.StampProtoType, error) {
	switch proto {
	case stamps.StampProtoTypeDNSCrypt:
		return stamps.StampProtoTypeDNSCryptRelay, nil
	case stamps.StampProtoTypeODoHTarget:
		return stamps.StampProtoTypeODoHRelay, nil
	default:
		return 0, errors.New("protocol cannot be anonymized")
	}
}

func route(proxy *Proxy, name string, serverProto stamps.StampProtoType) (*Relay, error) {
	routes := proxy.routes
	if routes == nil {
		return nil, nil
	}
	wildcard := false
	relayNames, ok := (*routes)[name]
	if !ok {
		wildcard = true
		relayNames, ok = (*routes)["*"]
	}
	if !ok || len(relayNames) == 0 {
		return nil, nil
	}

	relayProto, err := relayProtoForServerProto(serverProto)
	if err != nil {
		dlog.Errorf("Server [%v]'s protocol doesn't support anonymization", name)
		return nil, nil
	}
	relayStamps := make([]stamps.ServerStamp, 0)
	relayStampToName := make(map[string]string)
	for _, relayName := range relayNames {
		if relayStamp, err := stamps.NewServerStampFromString(relayName); err == nil {
			if relayStamp.Proto == relayProto {
				relayStamps = append(relayStamps, relayStamp)
				relayStampToName[relayStamp.String()] = relayName
			}
		} else if relayName == "*" {
			proxy.serversInfo.RLock()
			for _, registeredServer := range proxy.serversInfo.registeredRelays {
				if registeredServer.stamp.Proto == relayProto {
					relayStamps = append(relayStamps, registeredServer.stamp)
					relayStampToName[registeredServer.stamp.String()] = registeredServer.name
				}
			}
			proxy.serversInfo.RUnlock()
			wildcard = true
			break
		} else {
			proxy.serversInfo.RLock()
			for _, registeredServer := range proxy.serversInfo.registeredRelays {
				if registeredServer.name == relayName && registeredServer.stamp.Proto == relayProto {
					relayStamps = append(relayStamps, registeredServer.stamp)
					relayStampToName[registeredServer.stamp.String()] = relayName
					break
				}
			}
			proxy.serversInfo.RUnlock()
		}
	}
	if len(relayStamps) == 0 {
		err := fmt.Errorf("Non-existent relay set for server [%v]", name)
		return nil, err
	}
	var relayCandidateStamp *stamps.ServerStamp
	if !wildcard || len(relayStamps) == 1 {
		relayCandidateStamp = &relayStamps[rand.Intn(len(relayStamps))]
	} else {
		relayCandidateStamp = findFarthestRoute(proxy, name, relayStamps)
	}
	if relayCandidateStamp == nil {
		return nil, fmt.Errorf("No valid relay for server [%v]", name)
	}
	relayName := relayStampToName[relayCandidateStamp.String()]
	switch relayCandidateStamp.Proto {
	case stamps.StampProtoTypeDNSCrypt, stamps.StampProtoTypeDNSCryptRelay:
		relayUDPAddr, err := net.ResolveUDPAddr("udp", relayCandidateStamp.ServerAddrStr)
		if err != nil {
			return nil, err
		}
		relayTCPAddr, err := net.ResolveTCPAddr("tcp", relayCandidateStamp.ServerAddrStr)
		if err != nil {
			return nil, err
		}
		dlog.Noticef("Anonymizing queries for [%v] via [%v]", name, relayName)
		return &Relay{
			Proto:    stamps.StampProtoTypeDNSCryptRelay,
			Dnscrypt: &DNSCryptRelay{RelayUDPAddr: relayUDPAddr, RelayTCPAddr: relayTCPAddr},
			Name:     relayName,
		}, nil
	case stamps.StampProtoTypeODoHRelay:
		relayBaseURL, err := url.Parse(
			"https://" + url.PathEscape(relayCandidateStamp.ProviderName) + relayCandidateStamp.Path,
		)
		if err != nil {
			return nil, err
		}
		var relayURLforTarget *url.URL
		proxy.serversInfo.RLock()
		for _, server := range proxy.serversInfo.registeredServers {
			if server.name != name || server.stamp.Proto != stamps.StampProtoTypeODoHTarget {
				continue
			}
			qs := relayBaseURL.Query()
			qs.Add("targethost", server.stamp.ProviderName)
			qs.Add("targetpath", server.stamp.Path)
			tmp := *relayBaseURL
			tmp.RawQuery = qs.Encode()
			relayURLforTarget = &tmp
			break
		}
		proxy.serversInfo.RUnlock()
		if relayURLforTarget == nil {
			return nil, fmt.Errorf("Relay [%v] not found", relayName)
		}
		if len(relayCandidateStamp.ServerAddrStr) > 0 {
			ipOnly, _ := ExtractHostAndPort(relayCandidateStamp.ServerAddrStr, -1)
			if ip := ParseIP(ipOnly); ip != nil {
				host, _ := ExtractHostAndPort(relayCandidateStamp.ProviderName, -1)
				proxy.xTransport.saveCachedIP(host, ip, -1*time.Second)
			}
		}
		dlog.Noticef("Anonymizing queries for [%v] via [%v]", name, relayName)
		return &Relay{Proto: stamps.StampProtoTypeODoHRelay, ODoH: &ODoHRelay{
			URL: relayURLforTarget,
		}, Name: relayName}, nil
	}
	return nil, fmt.Errorf("Invalid relay set for server [%v]", name)
}

func fetchDNSCryptServerInfo(proxy *Proxy, name string, stamp stamps.ServerStamp, isNew bool) (ServerInfo, error) {
	if len(stamp.ServerPk) != ed25519.PublicKeySize {
		serverPk, err := hex.DecodeString(strings.ReplaceAll(string(stamp.ServerPk), ":", ""))
		if err != nil || len(serverPk) != ed25519.PublicKeySize {
			dlog.Fatalf("Unsupported public key for [%s]: [%s]", name, stamp.ServerPk)
		}
		dlog.Warnf("Public key [%s] shouldn't be hex-encoded any more", string(stamp.ServerPk))
		stamp.ServerPk = serverPk
	}
	knownBugs := ServerBugs{}
	if slices.Contains(proxy.serversBlockingFragments, name) {
		knownBugs.fragmentsBlocked = true
		dlog.Infof("Known bug in [%v]: fragmented questions over UDP are blocked", name)
	}
	relay, err := route(proxy, name, stamp.Proto)
	if err != nil {
		return ServerInfo{}, err
	}
	var dnscryptRelay *DNSCryptRelay
	if relay != nil {
		dnscryptRelay = relay.Dnscrypt
	}
	certInfo, rtt, fragmentsBlocked, err := FetchCurrentDNSCryptCert(
		proxy,
		&name,
		proxy.xTransport.mainProto,
		stamp.ServerPk,
		stamp.ServerAddrStr,
		stamp.ProviderName,
		isNew,
		dnscryptRelay,
		knownBugs,
	)
	if !knownBugs.fragmentsBlocked && fragmentsBlocked {
		dlog.Debugf("[%v] drops fragmented queries", name)
		knownBugs.fragmentsBlocked = true
	}
	if knownBugs.fragmentsBlocked && relay != nil && relay.Dnscrypt != nil {
		relay = nil
		if proxy.skipAnonIncompatibleResolvers {
			dlog.Infof("[%v] couldn't be reached anonymously, it will be ignored", name)
			return ServerInfo{}, errors.New("Resolver couldn't be reached anonymously")
		}
		dlog.Warnf("[%v] couldn't be reached anonymously", name)
	}
	if err != nil {
		return ServerInfo{}, err
	}
	if certInfo.CryptoConstruction == XWingPQ {
		dlog.Noticef("[%v] using the post-quantum X-Wing key exchange", name)
	}
	remoteUDPAddr, err := net.ResolveUDPAddr("udp", stamp.ServerAddrStr)
	if err != nil {
		return ServerInfo{}, err
	}
	remoteTCPAddr, err := net.ResolveTCPAddr("tcp", stamp.ServerAddrStr)
	if err != nil {
		return ServerInfo{}, err
	}

	if certInfo.CryptoConstruction == XSalsa20Poly1305 {
		query := plainNXTestPacket(0xcafe)
		msg, _, _, err := DNSExchange(
			proxy,
			proxy.xTransport.mainProto,
			query,
			stamp.ServerAddrStr,
			dnscryptRelay,
			&name,
			false,
		)
		if err == nil {
			dlog.Debugf("[%s] also serves plaintext DNS", name)
			for _, rr := range msg.Answer {
				rrType := dns.RRToType(rr)
				if rrType == dns.TypeA || rrType == dns.TypeAAAA {
					dlog.Warnf("[%s] may be a lying resolver -- skipping", name)
					return ServerInfo{}, fmt.Errorf("[%s] unexpected record: [%s]", name, rr.String())
				}
			}
			for _, rr := range msg.Extra {
				if dns.RRToType(rr) == dns.TypeTXT {
					dlog.Warnf("[%s] may be a dummy resolver -- skipping", name)
					txts := rr.(*dns.TXT).Txt
					cause := ""
					if len(txts) > 0 {
						cause = txts[0]
					}
					return ServerInfo{}, fmt.Errorf("[%s] unexpected record: [%s]", name, cause)
				}
			}
		}
	}

	return ServerInfo{
		Proto:              stamps.StampProtoTypeDNSCrypt,
		MagicQuery:         certInfo.MagicQuery,
		ServerPk:           certInfo.ServerPk,
		SharedKey:          certInfo.SharedKey,
		CryptoConstruction: certInfo.CryptoConstruction,
		PqPublicKey:        certInfo.PqPublicKey,
		PqCertContext:      certInfo.PqCertContext,
		pqSession:          newPqSessionState(certInfo.CryptoConstruction),
		Name:               name,
		Timeout:            proxy.timeout,
		UDPAddr:            remoteUDPAddr,
		TCPAddr:            remoteTCPAddr,
		Relay:              relay,
		initialRtt:         rtt,
		knownBugs:          knownBugs,
	}, nil
}

func dohTestPacket(msgID uint16) *dns.Msg {
	msg := dns.NewMsg(".", dns.TypeNS)
	msg.ID = msgID
	msg.RecursionDesired = true
	msg.UDPSize = uint16(MaxDNSUDPPacketSize)
	msg.Security = false
	paddingData := make([]byte, 16)
	_, _ = crypto_rand.Read(paddingData)
	padding := &dns.PADDING{Padding: hex.EncodeToString(paddingData)}
	msg.Pseudo = append(msg.Pseudo, padding)
	if err := msg.Pack(); err != nil {
		dlog.Fatal(err)
	}
	return msg
}

func dohNXTestPacket(msgID uint16) *dns.Msg {
	qName := make([]byte, 16)
	charset := "abcdefghijklmnopqrstuvwxyz"
	for i := range qName {
		qName[i] = charset[rand.Intn(len(charset))]
	}
	msg := dns.NewMsg(string(qName)+".test.dnscrypt.", dns.TypeNS)
	msg.ID = msgID
	msg.RecursionDesired = true
	msg.UDPSize = uint16(MaxDNSUDPPacketSize)
	msg.Security = false
	paddingData := make([]byte, 16)
	_, _ = crypto_rand.Read(paddingData)
	padding := &dns.PADDING{Padding: hex.EncodeToString(paddingData)}
	msg.Pseudo = append(msg.Pseudo, padding)
	if err := msg.Pack(); err != nil {
		dlog.Fatal(err)
	}
	return msg
}

func plainNXTestPacket(msgID uint16) *dns.Msg {
	qName := make([]byte, 16)
	charset := "abcdefghijklmnopqrstuvwxyz"
	for i := range qName {
		qName[i] = charset[rand.Intn(len(charset))]
	}
	msg := dns.NewMsg(string(qName)+".test.dnscrypt.", dns.TypeNS)
	msg.ID = msgID
	msg.RecursionDesired = true
	return msg
}

// probeServerRtt sends the root NS query that refresh tests servers with to
// server, over the server's own protocol, and returns how long the answer
// took in milliseconds. It records nothing on the server: no counters and no
// RTT estimate, so a probe is not a client query.
func probeServerRtt(proxy *Proxy, server *ServerInfo) (float64, error) {
	query := dohTestPacket(0xcafe)
	start := time.Now()
	var response []byte
	var err error
	switch server.Proto {
	case stamps.StampProtoTypeDNSCrypt:
		sharedKey, encryptedQuery, clientNonce, queryEpoch, encryptErr := proxy.Encrypt(server, query.Data, "udp")
		if encryptErr != nil {
			return 0, encryptErr
		}
		response, err = proxy.exchangeWithUDPServer(server, sharedKey, encryptedQuery, clientNonce, queryEpoch)
	case stamps.StampProtoTypeDoH:
		dohResponse, _, tlsState, _, dohErr := proxy.xTransport.DoHQuery(server.useGet, server.URL, query.Data, proxy.timeout)
		response, err = dohResponse, dohErr
		if err == nil && (tlsState == nil || !tlsState.HandshakeComplete) {
			err = errors.New("TLS handshake failed")
		}
	case stamps.StampProtoTypeODoHTarget:
		if len(server.odohTargetConfigs) == 0 {
			return 0, errors.New("no ODoH target configuration")
		}
		target := server.odohTargetConfigs[rand.Intn(len(server.odohTargetConfigs))]
		odohQuery, encryptErr := target.encryptQuery(query.Data)
		if encryptErr != nil {
			return 0, encryptErr
		}
		targetURL := server.URL
		if server.Relay != nil && server.Relay.ODoH != nil {
			targetURL = server.Relay.ODoH.URL
		}
		var body []byte
		var status int
		body, status, _, _, err = proxy.xTransport.ObliviousDoHQuery(server.useGet, targetURL, odohQuery.odohMessage, proxy.timeout)
		if err == nil && status != 200 {
			err = fmt.Errorf("HTTP status %d", status)
		}
		if err == nil {
			response, err = odohQuery.decryptResponse(body)
		}
	default:
		return 0, fmt.Errorf("unsupported protocol %v", server.Proto)
	}
	if err != nil {
		return 0, err
	}
	elapsed := time.Since(start)
	msg := dns.Msg{Data: response}
	if err := msg.Unpack(); err != nil {
		return 0, err
	}
	if err := validateResponseForQuery(query, &msg); err != nil {
		return 0, err
	}
	if msg.Rcode != dns.RcodeSuccess {
		return 0, fmt.Errorf("rcode %d", msg.Rcode)
	}
	return float64(elapsed.Microseconds()) / 1000, nil
}

func fetchDoHServerInfo(proxy *Proxy, name string, stamp stamps.ServerStamp, isNew bool) (ServerInfo, error) {
	// If an IP has been provided, use it forever.
	// Or else, if the fallback server and the DoH server are operated
	// by the same entity, it could provide a unique IPv6 for each client
	// in order to fingerprint clients across multiple IP addresses.
	if len(stamp.ServerAddrStr) > 0 {
		ipOnly, _ := ExtractHostAndPort(stamp.ServerAddrStr, -1)
		if ip := ParseIP(ipOnly); ip != nil {
			host, _ := ExtractHostAndPort(stamp.ProviderName, -1)
			proxy.xTransport.saveCachedIP(host, ip, -1*time.Second)
		}
	}
	url := &url.URL{
		Scheme: "https",
		Host:   stamp.ProviderName,
		Path:   stamp.Path,
	}
	body := dohTestPacket(0xcafe).Data
	useGet := false
	if _, _, _, _, err := proxy.xTransport.DoHQuery(useGet, url, body, proxy.timeout); err != nil {
		useGet = true
		if _, _, _, _, err := proxy.xTransport.DoHQuery(useGet, url, body, proxy.timeout); err != nil {
			return ServerInfo{}, err
		}
		dlog.Debugf("Server [%s] doesn't appear to support POST; falling back to GET requests", name)
	}
	queryMsg := dohNXTestPacket(0xcafe)
	serverResponse, _, tls, rtt, err := proxy.xTransport.DoHQuery(useGet, url, queryMsg.Data, proxy.timeout)
	if err != nil {
		dlog.Infof("[%s] [%s]: %v", name, url, err)
		return ServerInfo{}, err
	}
	if tls == nil || !tls.HandshakeComplete {
		return ServerInfo{}, errors.New("TLS handshake failed")
	}
	msg := dns.Msg{Data: serverResponse}
	if err := msg.Unpack(); err != nil {
		dlog.Warnf("[%s]: %v", name, err)
		return ServerInfo{}, err
	}
	if err := validateResponseForQuery(queryMsg, &msg); err != nil {
		return ServerInfo{}, err
	}
	if msg.Rcode != dns.RcodeNameError {
		return ServerInfo{}, fmt.Errorf("[%s] may be a lying resolver -- skipping", name)
	}
	protocol := tls.NegotiatedProtocol
	if len(protocol) == 0 {
		protocol = "http/1.x"
	}
	if strings.HasPrefix(protocol, "http/1.") {
		dlog.Warnf("[%s] does not support HTTP/2 nor HTTP/3", name)
	}
	dlog.Infof("[%s] TLS version: %x - Protocol: %v - Cipher suite: %v", name, tls.Version, protocol, tls.CipherSuite)
	showCerts := proxy.showCerts
	found := false
	var wantedHash [32]byte
	for _, cert := range tls.PeerCertificates {
		h := sha256.Sum256(cert.RawTBSCertificate)
		if showCerts {
			dlog.Noticef("Advertised cert: [%s] [%x]", cert.Subject, h)
		} else {
			dlog.Debugf("Advertised cert: [%s] [%x]", cert.Subject, h)
		}
		for _, hash := range stamp.Hashes {
			if len(hash) == len(wantedHash) {
				copy(wantedHash[:], hash)
				if h == wantedHash {
					found = true
					break
				}
			}
		}
		if found {
			break
		}
	}
	if !found && len(stamp.Hashes) > 0 {
		dlog.Criticalf("[%s] Certificate hash [%x] not found", name, wantedHash)
		return ServerInfo{}, fmt.Errorf("Certificate hash not found")
	}
	if len(serverResponse) < MinDNSPacketSize || len(serverResponse) > MaxDNSPacketSize ||
		serverResponse[0] != 0xca || serverResponse[1] != 0xfe || serverResponse[4] != 0x00 || serverResponse[5] != 0x01 {
		dlog.Info("Webserver returned an unexpected response")
		return ServerInfo{}, errors.New("Webserver returned an unexpected response")
	}
	xrtt := int(rtt.Nanoseconds() / 1000000)
	if isNew {
		dlog.Noticef("[%s] OK (DoH) - rtt: %dms", name, xrtt)
	} else {
		dlog.Infof("[%s] OK (DoH) - rtt: %dms", name, xrtt)
	}
	return ServerInfo{
		Proto:      stamps.StampProtoTypeDoH,
		Name:       name,
		Timeout:    proxy.timeout,
		URL:        url,
		HostName:   stamp.ProviderName,
		initialRtt: xrtt,
		useGet:     useGet,
	}, nil
}

func fetchTargetConfigsFromWellKnown(proxy *Proxy, url *url.URL) ([]ODoHTargetConfig, error) {
	bin, statusCode, _, _, err := proxy.xTransport.Get(url, "application/binary", 0)
	if err != nil {
		return nil, err
	}
	if statusCode < 200 || statusCode >= 300 {
		return nil, fmt.Errorf("HTTP status code was %v", statusCode)
	}
	return parseODoHTargetConfigs(bin)
}

func _fetchODoHTargetInfo(proxy *Proxy, name string, stamp stamps.ServerStamp, isNew bool) (ServerInfo, error) {
	configURL := &url.URL{Scheme: "https", Host: stamp.ProviderName, Path: "/.well-known/odohconfigs"}
	odohTargetConfigs, err := fetchTargetConfigsFromWellKnown(proxy, configURL)
	if err != nil {
		dlog.Debug(configURL)
		return ServerInfo{}, fmt.Errorf("[%s] didn't return an ODoH configuration - [%v]", name, err)
	} else if len(odohTargetConfigs) == 0 {
		dlog.Debug(configURL)
		return ServerInfo{}, fmt.Errorf("[%s] has an empty ODoH configuration", name)
	}

	relay, err := route(proxy, name, stamp.Proto)
	if err != nil {
		return ServerInfo{}, err
	}

	if relay == nil {
		dlog.Criticalf(
			"No relay defined for [%v] - Configuring an ODoH relay is required for ODoH servers (see the `[anonymized_dns]` section)",
			name,
		)
		return ServerInfo{}, errors.New("No ODoH relay")
	} else {
		if relay.ODoH == nil {
			dlog.Criticalf("Wrong relay type defined for [%v] - ODoH servers require an ODoH relay", name)
			return ServerInfo{}, errors.New("Wrong ODoH relay type")
		}
	}

	dlog.Debugf("Pausing after ODoH configuration retrieval")
	delay := time.Duration(rand.Intn(5*1000)) * time.Millisecond
	clocksmith.Sleep(time.Duration(delay))
	dlog.Debugf("Pausing done")

	targetURL := &url.URL{
		Scheme: "https",
		Host:   stamp.ProviderName,
		Path:   stamp.Path,
	}

	workingConfigs := make([]ODoHTargetConfig, 0)
	var lastProbeErr error
	rand.Shuffle(len(odohTargetConfigs), func(i, j int) {
		odohTargetConfigs[i], odohTargetConfigs[j] = odohTargetConfigs[j], odohTargetConfigs[i]
	})
	for _, odohTargetConfig := range odohTargetConfigs {
		url := relay.ODoH.URL

		odohQuery, err := odohTargetConfig.encryptQuery(dohTestPacket(0xcafe).Data)
		if err != nil {
			lastProbeErr = fmt.Errorf("failed to encrypt ODoH probe: %w", err)
			continue
		}

		useGet := false
		_, postStatusCode, _, _, postErr := proxy.xTransport.ObliviousDoHQuery(useGet, url, odohQuery.odohMessage, proxy.timeout)
		if postErr != nil {
			useGet = true
			_, getStatusCode, _, _, getErr := proxy.xTransport.ObliviousDoHQuery(useGet, url, odohQuery.odohMessage, proxy.timeout)
			if getErr != nil {
				lastProbeErr = fmt.Errorf(
					"ODoH relay probe via POST and GET failed: POST HTTP status %d: %w; GET HTTP status %d: %w",
					postStatusCode,
					postErr,
					getStatusCode,
					getErr,
				)
				continue
			}
			dlog.Debugf("Server [%s] doesn't appear to support POST; falling back to GET requests", name)
		}

		queryMsg := dohNXTestPacket(0xcafe)
		odohQuery, err = odohTargetConfig.encryptQuery(queryMsg.Data)
		if err != nil {
			lastProbeErr = fmt.Errorf("failed to encrypt ODoH DNS probe: %w", err)
			continue
		}

		responseBody, responseCode, tls, rtt, err := proxy.xTransport.ObliviousDoHQuery(
			useGet,
			url,
			odohQuery.odohMessage,
			proxy.timeout,
		)
		if err != nil {
			lastProbeErr = fmt.Errorf("ODoH DNS probe failed with HTTP status %d: %w", responseCode, err)
			continue
		}
		if responseCode == 401 {
			return ServerInfo{}, fmt.Errorf("configuration changed during ODoH probe")
		}
		if responseCode < 200 || responseCode >= 300 {
			lastProbeErr = fmt.Errorf("ODoH DNS probe returned HTTP status %d", responseCode)
			continue
		}
		serverResponse, err := odohQuery.decryptResponse(responseBody)
		if err != nil {
			dlog.Warnf("Unable to decrypt response from [%v]: [%v]", name, err)
			lastProbeErr = fmt.Errorf("failed to decrypt ODoH DNS probe response: %w", err)
			continue
		}
		workingConfigs = append(workingConfigs, odohTargetConfig)

		msg := dns.Msg{Data: serverResponse}
		if err := msg.Unpack(); err != nil {
			dlog.Warnf("[%s]: %v", name, err)
			return ServerInfo{}, err
		}
		if err := validateResponseForQuery(queryMsg, &msg); err != nil {
			return ServerInfo{}, err
		}
		if msg.Rcode != dns.RcodeNameError {
			return ServerInfo{}, fmt.Errorf("[%s] may be a lying resolver -- skipping", name)
		}
		protocol := "http"
		tlsVersion := uint16(0)
		tlsCipherSuite := uint16(0)
		if tls != nil {
			protocol = tls.NegotiatedProtocol
			if len(protocol) == 0 {
				protocol = "http/1.x"
			} else {
				tlsVersion = tls.Version
				tlsCipherSuite = tls.CipherSuite
			}
		}
		if strings.HasPrefix(protocol, "http/1.") {
			dlog.Warnf("[%s] does not support HTTP/2", name)
		}
		dlog.Infof(
			"[%s] TLS version: %x - Protocol: %v - Cipher suite: %v",
			name,
			tlsVersion,
			protocol,
			tlsCipherSuite,
		)
		showCerts := proxy.showCerts
		found := false
		var wantedHash [32]byte
		if tls != nil {
			for _, cert := range tls.PeerCertificates {
				h := sha256.Sum256(cert.RawTBSCertificate)
				if showCerts {
					dlog.Noticef("Advertised relay cert: [%s] [%x]", cert.Subject, h)
				} else {
					dlog.Debugf("Advertised relay cert: [%s] [%x]", cert.Subject, h)
				}
				for _, hash := range stamp.Hashes {
					if len(hash) == len(wantedHash) {
						copy(wantedHash[:], hash)
						if h == wantedHash {
							found = true
							break
						}
					}
				}
				if found {
					break
				}
			}
			if !found && len(stamp.Hashes) > 0 {
				dlog.Criticalf("[%s] Certificate hash [%x] not found", name, wantedHash)
				return ServerInfo{}, fmt.Errorf("Certificate hash not found")
			}
		}
		if len(serverResponse) < MinDNSPacketSize || len(serverResponse) > MaxDNSPacketSize ||
			serverResponse[0] != 0xca || serverResponse[1] != 0xfe || serverResponse[4] != 0x00 || serverResponse[5] != 0x01 {
			dlog.Info("Webserver returned an unexpected response")
			return ServerInfo{}, errors.New("Webserver returned an unexpected response")
		}
		xrtt := int(rtt.Nanoseconds() / 1000000)
		if isNew {
			dlog.Noticef("[%s] OK (ODoH) - rtt: %dms", name, xrtt)
		} else {
			dlog.Infof("[%s] OK (ODoH) - rtt: %dms", name, xrtt)
		}
		return ServerInfo{
			Proto:             stamps.StampProtoTypeODoHTarget,
			Name:              name,
			Timeout:           proxy.timeout,
			URL:               targetURL,
			HostName:          stamp.ProviderName,
			initialRtt:        xrtt,
			useGet:            useGet,
			Relay:             relay,
			odohTargetConfigs: workingConfigs,
		}, nil
	}
	if lastProbeErr != nil {
		return ServerInfo{}, fmt.Errorf("ODoH initialization probe failed for [%v]: %w", name, lastProbeErr)
	}
	return ServerInfo{}, fmt.Errorf("no valid ODoH configuration for [%v]", name)
}

func fetchODoHTargetInfo(proxy *Proxy, name string, stamp stamps.ServerStamp, isNew bool) (ServerInfo, error) {
	var err error
	var serverInfo ServerInfo
	for i := 0; i < 3; i += 1 {
		serverInfo, err = _fetchODoHTargetInfo(proxy, name, stamp, isNew)
		if err == nil {
			break
		}
		if i < 2 {
			dlog.Infof("Retrying ODoH initialization for [%v] after failure: [%v]", name, err)
		}
	}
	return serverInfo, err
}

func (serverInfo *ServerInfo) noticeFailure(proxy *Proxy) {
	serverInfo.noticeFailureReason(proxy, failureReasonOther)
}

func (serverInfo *ServerInfo) noticeFailureReason(proxy *Proxy, reason string) {
	proxy.serversInfo.Lock()
	defer proxy.serversInfo.Unlock()
	serverInfo.countFailureLocked(proxy, reason)
	if _, isFirst := proxy.serversInfo.lbStrategy.(LBStrategyFirst); isFirst && reason == failureReasonServfail {
		// A SERVFAIL reported without its response: the name is unknown and
		// the server is answerable for it.
		if !serverInfo.failoverLocked().recordServfail(time.Now(), "", false) {
			return
		}
	}
	serverInfo.demoteLocked(proxy)
}

// noticeServfail records a SERVFAIL answer for qName. blamesZone says whether
// the server attributed it to the zone through an extended DNS error; such an
// answer is evidence about the zone, not the server, and only a sustained run
// of nothing else demotes the server.
func (serverInfo *ServerInfo) noticeServfail(proxy *Proxy, qName string, blamesZone bool) {
	reason := failureReasonServfail
	if blamesZone {
		reason = failureReasonZoneServfail
	}
	proxy.serversInfo.Lock()
	defer proxy.serversInfo.Unlock()
	serverInfo.countFailureLocked(proxy, reason)
	if _, isFirst := proxy.serversInfo.lbStrategy.(LBStrategyFirst); isFirst {
		if !serverInfo.failoverLocked().recordServfail(time.Now(), qName, blamesZone) {
			return
		}
	} else if blamesZone {
		return
	}
	serverInfo.demoteLocked(proxy)
}

// recordServfail notes a SERVFAIL for qName and reports whether the run it
// belongs to has become evidence that the server is failing: enough SERVFAILs
// the server did not blame on the zone, or a sustained run of any kind.
func (failover *failoverState) recordServfail(now time.Time, qName string, blamesZone bool) bool {
	failover.lastResponseTS = now
	if failover.consecutiveServfails == 0 {
		failover.servfailRunStartedAt = now
	}
	retried := qName != "" && qName == failover.lastServfailQName
	failover.lastServfailQName = qName
	if retried {
		return false
	}
	failover.consecutiveServfails++
	if !blamesZone {
		failover.consecutiveServerServfails++
	}
	if failover.consecutiveServerServfails >= firstStrategyServfailDemotion {
		return true
	}
	return failover.consecutiveServfails >= firstStrategyAttributedServfailDemotion &&
		now.Sub(failover.servfailRunStartedAt) >= firstStrategyAttributedServfailDuration
}

// countFailureLocked adds the failure to the per-server, per-reason counters.
// The ServersInfo lock must be held.
func (serverInfo *ServerInfo) countFailureLocked(proxy *Proxy, reason string) {
	if proxy.serversInfo.failures == nil {
		proxy.serversInfo.failures = make(map[serverFailureKey]uint64)
	}
	proxy.serversInfo.failures[serverFailureKey{server: serverInfo.Name, reason: reason}]++
}

// demoteLocked applies a failure the server is answerable for. The
// ServersInfo lock must be held.
func (serverInfo *ServerInfo) demoteLocked(proxy *Proxy) {
	if _, isFirst := proxy.serversInfo.lbStrategy.(LBStrategyFirst); isFirst {
		// A repeated failure restarts the failback delay.
		serverInfo.failoverLocked().demotedAt = time.Now()
	}
	serverInfo.rtt.Add(float64(proxy.timeout.Nanoseconds() / 1000000))
	// The first strategy normally keeps using index zero. Move a failed
	// preferred resolver behind a healthier alternative immediately so that
	// disabling the background estimator provides sticky selection without
	// also disabling failover.
	if _, isFirst := proxy.serversInfo.lbStrategy.(LBStrategyFirst); isFirst {
		proxy.serversInfo.sortByRtt()
	}
}

func (serverInfo *ServerInfo) noticeBegin(proxy *Proxy) {
	proxy.serversInfo.Lock()
	serverInfo.lastActionTS = time.Now()
	proxy.serversInfo.Unlock()
}

func (serverInfo *ServerInfo) noticeSuccess(proxy *Proxy) {
	now := time.Now()
	proxy.serversInfo.Lock()
	elapsed := now.Sub(serverInfo.lastActionTS)
	elapsedMs := elapsed.Nanoseconds() / 1000000
	if elapsedMs > 0 && elapsed < proxy.timeout {
		serverInfo.rtt.Add(float64(elapsedMs))
	}
	failover := serverInfo.failoverLocked()
	failover.consecutiveServfails = 0
	failover.consecutiveServerServfails = 0
	failover.lastServfailQName = ""
	failover.lastResponseTS = now
	proxy.serversInfo.Unlock()
}

// noticeExchangeError records a transport error for a query sent at sentAt.
//
// Under the `first` strategy a timeout fails over only when the server has
// returned nothing since sentAt. A connection that died answers nothing; a
// zone with slow or refusing nameservers times out while the same server keeps
// answering everything else, and another upstream would wait just as long.
func (serverInfo *ServerInfo) noticeExchangeError(proxy *Proxy, err error, sentAt time.Time) {
	reason := failureReasonForError(err)
	if reason == failureReasonTimeout {
		proxy.serversInfo.Lock()
		_, isFirst := proxy.serversInfo.lbStrategy.(LBStrategyFirst)
		if isFirst && serverInfo.failoverLocked().lastResponseTS.After(sentAt) {
			if proxy.serversInfo.failures == nil {
				proxy.serversInfo.failures = make(map[serverFailureKey]uint64)
			}
			proxy.serversInfo.failures[serverFailureKey{server: serverInfo.Name, reason: failureReasonIsolatedTimeout}]++
			proxy.serversInfo.Unlock()
			return
		}
		proxy.serversInfo.Unlock()
	}
	serverInfo.noticeFailureReason(proxy, reason)
}
