package main

import (
	"fmt"
	"testing"
	"time"

	"codeberg.org/miekg/dns"
)

// packedServfail returns a packed SERVFAIL with the given transaction ID for
// name that carries one extended DNS error option per code.
func packedServfail(t *testing.T, id uint16, name string, codes ...uint16) []byte {
	t.Helper()
	msg := dns.NewMsg(name, dns.TypeA)
	msg.ID = id
	msg.Response = true
	msg.Rcode = dns.RcodeServerFailure
	if len(codes) > 0 {
		msg.UDPSize = 1232
	}
	for _, code := range codes {
		msg.Pseudo = append(msg.Pseudo, &dns.EDE{InfoCode: code})
	}
	if err := msg.Pack(); err != nil {
		t.Fatal(err)
	}
	return msg.Data
}

func TestExtendedErrorAttributionTable(t *testing.T) {
	// RFC 8914 code points that attribute the failure to the queried name,
	// its zone or its DNSSEC chain. Everything else, unassigned codes
	// included, is attributed to the server.
	zone := map[uint16]bool{
		1: true, 2: true, 5: true, 6: true, 7: true, 8: true, 9: true,
		10: true, 11: true, 12: true, 13: true, 15: true, 16: true,
		17: true, 18: true, 22: true, 24: true, 25: true, 27: true, 30: true,
	}
	for code := uint16(0); code <= 40; code++ {
		if got := extendedErrorBlamesZone(code); got != zone[code] {
			t.Errorf("extended error %d: blames zone = %v, want %v", code, got, zone[code])
		}
	}
}

func TestServfailBlamesZoneReadsExtendedError(t *testing.T) {
	cases := []struct {
		name     string
		response []byte
		want     bool
	}{
		{"no extended error", packedServfail(t, 0, "example.test."), false},
		{"no reachable authority", packedServfail(t, 0, "example.test.", 22), true},
		{"network error", packedServfail(t, 0, "example.test.", 23), false},
		{"other next to a zone code", packedServfail(t, 0, "example.test.", 0, 22), true},
		{"not a SERVFAIL", packedResponseWithRcode(t, dns.RcodeSuccess), false},
		{"truncated packet", []byte{0, 1, 2}, false},
	}
	for _, c := range cases {
		if got := servfailBlamesZone(c.response); got != c.want {
			t.Errorf("%s: servfailBlamesZone = %v, want %v", c.name, got, c.want)
		}
	}
}

func TestFirstStrategyIgnoresZoneAttributedServfailRun(t *testing.T) {
	proxy := firstStrategyFailbackProxy()
	fast := proxy.serversInfo.inner[0]
	for i := range firstStrategyAttributedServfailDemotion - 1 {
		fast.noticeServfail(proxy, fmt.Sprintf("bl%d.example.test.", i), true)
	}
	if got := serverNames(proxy.serversInfo.inner)[0]; got != "fast" {
		t.Fatalf("SERVFAILs the server blamed on the zones moved the head to %q", got)
	}
	if got := fast.rtt.Value(); got != 14 {
		t.Fatalf("zone-attributed SERVFAILs changed the RTT estimate to %v", got)
	}
	key := serverFailureKey{server: "fast", reason: failureReasonZoneServfail}
	if got := proxy.serversInfo.failures[key]; got != uint64(firstStrategyAttributedServfailDemotion-1) {
		t.Fatalf("zone_servfail count = %d, want %d", got, firstStrategyAttributedServfailDemotion-1)
	}
	if got := proxy.serversInfo.failures[serverFailureKey{server: "fast", reason: failureReasonServfail}]; got != 0 {
		t.Fatalf("zone-attributed SERVFAILs were also counted as servfail: %d", got)
	}
}

func TestFirstStrategyDemotesOnServerAttributedServfailsAmongZoneOnes(t *testing.T) {
	proxy := firstStrategyFailbackProxy()
	fast := proxy.serversInfo.inner[0]
	for i := range firstStrategyServfailDemotion {
		fast.noticeServfail(proxy, fmt.Sprintf("zone%d.example.test.", i), true)
		fast.noticeServfail(proxy, fmt.Sprintf("server%d.example.test.", i), false)
	}
	if got := serverNames(proxy.serversInfo.inner)[0]; got != "slow" {
		t.Fatalf("SERVFAILs without a zone attribution did not demote the server: head = %q", got)
	}
}

func TestFirstStrategyDemotesServerThatOnlyBlamesZones(t *testing.T) {
	// A server whose every answer is a SERVFAIL blaming the zone is failing,
	// however it labels it. A burst does not prove that; a sustained run does.
	proxy := firstStrategyFailbackProxy()
	fast := proxy.serversInfo.inner[0]
	for i := range firstStrategyAttributedServfailDemotion {
		fast.noticeServfail(proxy, fmt.Sprintf("bl%d.example.test.", i), true)
	}
	if got := serverNames(proxy.serversInfo.inner)[0]; got != "fast" {
		t.Fatalf("a burst of zone-attributed SERVFAILs demoted the server: head = %q", got)
	}
	proxy.serversInfo.Lock()
	fast.failover.servfailRunStartedAt = time.Now().Add(-firstStrategyAttributedServfailDuration)
	proxy.serversInfo.Unlock()
	fast.noticeServfail(proxy, "late.example.test.", true)
	if got := serverNames(proxy.serversInfo.inner)[0]; got != "slow" {
		t.Fatalf("a sustained run of zone-attributed SERVFAILs kept the head: %q", got)
	}
}

func TestFirstStrategyRetriedNameCountsOnce(t *testing.T) {
	// A stub that retries one failing name makes one failure look like a run.
	proxy := firstStrategyFailbackProxy()
	fast := proxy.serversInfo.inner[0]
	for range firstStrategyServfailDemotion {
		fast.noticeServfail(proxy, "retried.example.test.", false)
	}
	if got := serverNames(proxy.serversInfo.inner)[0]; got != "fast" {
		t.Fatalf("retries of one name demoted the server: head = %q", got)
	}
	fast.noticeServfail(proxy, "second.example.test.", false)
	fast.noticeServfail(proxy, "third.example.test.", false)
	if got := serverNames(proxy.serversInfo.inner)[0]; got != "slow" {
		t.Fatalf("SERVFAILs for distinct names did not demote the server: head = %q", got)
	}
}

func TestFirstStrategySuccessResetsServfailRunState(t *testing.T) {
	proxy := firstStrategyFailbackProxy()
	fast := proxy.serversInfo.inner[0]
	fast.noticeServfail(proxy, "a.example.test.", true)
	fast.noticeServfail(proxy, "b.example.test.", false)
	fast.noticeBegin(proxy)
	fast.noticeSuccess(proxy)
	proxy.serversInfo.Lock()
	defer proxy.serversInfo.Unlock()
	f := fast.failover
	if f.consecutiveServfails != 0 || f.consecutiveServerServfails != 0 || f.lastServfailQName != "" {
		t.Fatalf("a success left SERVFAIL run state behind: %+v", *f)
	}
}

func TestUpstreamServfailIsAttributedFromItsExtendedError(t *testing.T) {
	for _, c := range []struct {
		name   string
		codes  []uint16
		reason string
	}{
		{"zone", []uint16{22}, failureReasonZoneServfail},
		{"server", nil, failureReasonServfail},
	} {
		proxy := firstStrategyFailbackProxy()
		withoutPlugins(proxy)
		fast := proxy.serversInfo.inner[0]
		question, query := testQuestion(t, 0x1234)
		pluginsState := NewPluginsState(proxy, "udp", nil, "udp", time.Now())
		pluginsState.questionMsg = question
		pluginsState.qName = "example.test."
		response := packedServfail(t, 0x1234, "example.test.", c.codes...)
		if _, err := processPlugins(proxy, &pluginsState, query, fast, response); err != nil {
			t.Fatalf("%s: %v", c.name, err)
		}
		if got := proxy.serversInfo.failures[serverFailureKey{server: "fast", reason: c.reason}]; got != 1 {
			t.Fatalf("%s: %s count = %d, want 1 (failures: %v)", c.name, c.reason, got, proxy.serversInfo.failures)
		}
	}
}
