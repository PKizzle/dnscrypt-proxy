package main

import (
	"encoding/binary"
	"net"
	"net/url"
	"sync"
	"testing"
	"time"

	"codeberg.org/miekg/dns"
	stamps "github.com/jedisct1/go-dnsstamps"
	hpkecompact "github.com/jedisct1/go-hpke-compact"
)

// testXTransport is a transport with no HTTP/3 and the given request timeout.
func testXTransport(timeout time.Duration) *XTransport {
	xTransport := NewXTransport()
	xTransport.timeout = timeout
	xTransport.rebuildTransport()
	return xTransport
}

// refusedURL is a DoH URL on a local port where nothing listens, so every
// exchange fails at once with a network error.
func refusedURL(t *testing.T) *url.URL {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := listener.Addr().String()
	listener.Close()
	return &url.URL{Scheme: "https", Host: addr, Path: "/dns-query"}
}

// silentURL is a DoH URL on a local port that accepts connections and never
// answers, so every exchange times out.
func silentURL(t *testing.T) *url.URL {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	var mu sync.Mutex
	var conns []net.Conn
	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			mu.Lock()
			conns = append(conns, conn)
			mu.Unlock()
		}
	}()
	t.Cleanup(func() {
		listener.Close()
		mu.Lock()
		defer mu.Unlock()
		for _, conn := range conns {
			conn.Close()
		}
	})
	return &url.URL{Scheme: "https", Host: listener.Addr().String(), Path: "/dns-query"}
}

// withoutPlugins gives proxy empty plugin chains.
func withoutPlugins(proxy *Proxy) {
	proxy.pluginsGlobals.queryPlugins = &[]Plugin{}
	proxy.pluginsGlobals.responsePlugins = &[]Plugin{}
	proxy.pluginsGlobals.loggingPlugins = &[]Plugin{}
}

// testQuestion returns a query for example.test. with the given ID, parsed and
// packed.
func testQuestion(t *testing.T, id uint16) (*dns.Msg, []byte) {
	t.Helper()
	msg := dns.NewMsg("example.test.", dns.TypeA)
	msg.ID = id
	if err := msg.Pack(); err != nil {
		t.Fatal(err)
	}
	return msg, append([]byte(nil), msg.Data...)
}

// answerTo returns an empty NOERROR answer to question.
func answerTo(question *dns.Msg) *dns.Msg {
	answer := dns.NewMsg("example.test.", dns.TypeA)
	answer.ID = question.ID
	answer.Response = true
	return answer
}

// timeoutTestProxy is firstStrategyFailbackProxy with a timeout short enough
// to wait for. A recorded failure adds the timeout to the head's RTT estimate,
// so the backup's estimate is lowered to stay below what one failure leaves.
func timeoutTestProxy() *Proxy {
	proxy := firstStrategyFailbackProxy()
	proxy.timeout = 300 * time.Millisecond
	proxy.xTransport = testXTransport(proxy.timeout)
	withoutPlugins(proxy)
	proxy.serversInfo.inner[1].rtt.Set(30)
	return proxy
}

// dohServer turns the head of proxy into a DoH server at u.
func dohServer(proxy *Proxy, u *url.URL) *ServerInfo {
	server := proxy.serversInfo.inner[0]
	server.Proto = stamps.StampProtoTypeDoH
	server.URL = u
	return server
}

func TestStaleAnswerStillCountsTheFailedExchange(t *testing.T) {
	// The server is gone, but the cache still holds an expired answer. The
	// client gets that answer, and the server must still be failed over.
	proxy := firstStrategyFailbackProxy()
	proxy.xTransport = testXTransport(proxy.timeout)
	withoutPlugins(proxy)
	fast := dohServer(proxy, refusedURL(t))

	question, query := testQuestion(t, 0x1234)
	pluginsState := NewPluginsState(proxy, "udp", nil, "udp", time.Now())
	pluginsState.questionMsg = question
	pluginsState.sessionData["stale"] = answerTo(question)

	response, err := processDoHQuery(proxy, fast, &pluginsState, query)
	if err != nil || len(response) == 0 {
		t.Fatalf("the stale answer was not served: response=%v err=%v", response, err)
	}
	if got := serverNames(proxy.serversInfo.inner)[0]; got != "slow" {
		t.Fatalf("head = %q: a server that refused the exchange kept the head because the cache answered", got)
	}
}

func TestStaleAnswerIsNotCreditedToTheServer(t *testing.T) {
	// A query is still waiting for the server when another one fails and is
	// answered from the stale cache. That answer is not the server's, so when
	// the waiting query times out, the server has answered nothing since.
	proxy := firstStrategyFailbackProxy()
	withoutPlugins(proxy)
	fast := proxy.serversInfo.inner[0]
	waitingSince := time.Now().Add(-time.Millisecond)

	question, query := testQuestion(t, 0x1234)
	pluginsState := NewPluginsState(proxy, "udp", nil, "udp", time.Now())
	pluginsState.questionMsg = question
	pluginsState.servedStale = true
	stale := answerTo(question)
	if err := stale.Pack(); err != nil {
		t.Fatal(err)
	}
	if _, err := processPlugins(proxy, &pluginsState, query, fast, stale.Data); err != nil {
		t.Fatal(err)
	}

	fast.noticeExchangeError(proxy, timeoutError{}, waitingSince)
	if got := serverNames(proxy.serversInfo.inner)[0]; got != "slow" {
		t.Fatalf("head = %q: a stale answer made a silent server look like it was still answering", got)
	}
}

func TestCollapsedCallerKnowsItsAnswerWasStale(t *testing.T) {
	// The second caller joins the first one's exchange. When that exchange
	// fails and the first caller's stale answer is shared, the second caller
	// must know the answer was stale too, or it credits the server with it.
	proxy := timeoutTestProxy()
	fast := dohServer(proxy, silentURL(t))

	leaderQuestion, leaderQuery := testQuestion(t, 0x1111)
	leader := NewPluginsState(proxy, "udp", nil, "udp", time.Now())
	leader.questionMsg = leaderQuestion
	leader.sessionData["stale"] = answerTo(leaderQuestion)
	_, followerQuery := testQuestion(t, 0x2222)
	follower := NewPluginsState(proxy, "udp", nil, "udp", time.Now())

	done := make(chan struct{})
	go func() {
		defer close(done)
		handleDNSExchange(proxy, fast, &leader, leaderQuery, "udp")
	}()
	time.Sleep(50 * time.Millisecond)
	if _, err := handleDNSExchange(proxy, fast, &follower, followerQuery, "udp"); err != nil {
		t.Fatalf("the second caller did not share the first caller's exchange: %v", err)
	}
	<-done
	if !follower.servedStale {
		t.Fatal("the second caller does not know its answer came from the stale cache")
	}
}

// odohServer turns the head of proxy into an ODoH target at u, with a valid
// configuration for a fresh key.
func odohServer(t *testing.T, proxy *Proxy, u *url.URL) *ServerInfo {
	t.Helper()
	kem, kdf, aead := hpkecompact.KemX25519HkdfSha256, hpkecompact.KdfHkdfSha256, hpkecompact.AeadAes128Gcm
	suite, err := hpkecompact.NewSuite(kem, kdf, aead)
	if err != nil {
		t.Fatal(err)
	}
	keyPair, err := suite.GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	config := binary.BigEndian.AppendUint16(nil, uint16(kem))
	config = binary.BigEndian.AppendUint16(config, uint16(kdf))
	config = binary.BigEndian.AppendUint16(config, uint16(aead))
	config = binary.BigEndian.AppendUint16(config, uint16(len(keyPair.PublicKey)))
	target, err := parseODoHTargetConfig(append(config, keyPair.PublicKey...))
	if err != nil {
		t.Fatal(err)
	}
	server := proxy.serversInfo.inner[0]
	server.Proto = stamps.StampProtoTypeODoHTarget
	server.URL = u
	server.odohTargetConfigs = []ODoHTargetConfig{target}
	return server
}

func TestODoHTimeoutOnAServerThatKeptAnsweringIsIsolated(t *testing.T) {
	// While this query waited, the server answered another one: the name is
	// slow, not the server, and another target would wait just as long.
	proxy := timeoutTestProxy()
	fast := odohServer(t, proxy, silentURL(t))

	answered := make(chan struct{})
	go func() {
		defer close(answered)
		time.Sleep(100 * time.Millisecond)
		fast.noticeBegin(proxy)
		fast.noticeSuccess(proxy)
	}()
	_, query := testQuestion(t, 0x1234)
	pluginsState := NewPluginsState(proxy, "udp", nil, "udp", time.Now())
	if _, err := processODoHQuery(proxy, fast, &pluginsState, query); err == nil {
		t.Fatal("the exchange with a silent target did not fail")
	}
	<-answered
	if got := serverNames(proxy.serversInfo.inner)[0]; got != "fast" {
		t.Fatalf("head = %q: a timeout on one slow name failed over a server that kept answering", got)
	}
}

func TestODoHTimeoutOnASilentServerFailsOver(t *testing.T) {
	proxy := timeoutTestProxy()
	fast := odohServer(t, proxy, silentURL(t))

	_, query := testQuestion(t, 0x1234)
	pluginsState := NewPluginsState(proxy, "udp", nil, "udp", time.Now())
	if _, err := processODoHQuery(proxy, fast, &pluginsState, query); err == nil {
		t.Fatal("the exchange with a silent target did not fail")
	}
	if got := serverNames(proxy.serversInfo.inner)[0]; got != "slow" {
		t.Fatalf("head = %q, want slow after a timeout on a server that answered nothing", got)
	}
}
