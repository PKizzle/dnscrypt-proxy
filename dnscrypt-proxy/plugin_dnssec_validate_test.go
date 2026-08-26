package main

import (
	"fmt"
	"net/netip"
	"strings"
	"testing"

	"codeberg.org/miekg/dns"
	"codeberg.org/miekg/dns/rdata"
)

func TestParseValidationMode(t *testing.T) {
	for _, tc := range []struct {
		in   string
		want ValidationMode
	}{
		{"", ValidationOff},
		{"off", ValidationOff},
		{"disabled", ValidationOff},
		{"log", ValidationLog},
		{"audit", ValidationLog},
		{"enforce", ValidationEnforce},
		{"strict", ValidationEnforce},
		{" Enforce ", ValidationEnforce},
		{"LOG", ValidationLog},
	} {
		got, err := parseValidationMode(tc.in)
		if err != nil {
			t.Errorf("parseValidationMode(%q) = error %v", tc.in, err)
			continue
		}
		if got != tc.want {
			t.Errorf("parseValidationMode(%q) = %v, want %v", tc.in, got, tc.want)
		}
	}
}

// A misspelled mode must be refused rather than quietly read as "off": a
// resolver that believes it is validating and is not is worse than one that
// knows it is not.
func TestParseValidationModeRejectsNonsense(t *testing.T) {
	for _, in := range []string{"enforced", "yes", "true", "on"} {
		if _, err := parseValidationMode(in); err == nil {
			t.Errorf("parseValidationMode(%q) should be an error, not a silent off", in)
		}
	}
}

func TestIsInsecureZoneCoversTheZoneAndBelow(t *testing.T) {
	plugin := &PluginDNSSECValidate{insecureZones: []string{"broken.test.", "example.org."}}
	for _, tc := range []struct {
		name string
		want bool
	}{
		{"broken.test.", true},
		{"www.broken.test.", true},
		{"deep.down.broken.test.", true},
		{"example.org.", true},
		{"other.test.", false},
		{"test.", false},
		// The suffix must fall on a label boundary: this is a different zone
		// that merely ends in the same letters.
		{"notbroken.test.", false},
	} {
		if got := plugin.isInsecureZone(tc.name); got != tc.want {
			t.Errorf("isInsecureZone(%q) = %v, want %v", tc.name, got, tc.want)
		}
	}
}

func TestIsInsecureZoneWithNoneConfigured(t *testing.T) {
	plugin := &PluginDNSSECValidate{}
	if plugin.isInsecureZone("anything.test.") {
		t.Error("no zones configured should mean nothing is exempt")
	}
}

// The move from logging refusals to making them rests on how often a refusal
// would have happened, so a verdict that never reaches the counters is a
// refusal nobody sees coming.
func TestBogusVerdictsReachTheExportedCounter(t *testing.T) {
	before := dnssecVerdicts.bogus.Load()
	dnssecVerdicts.bogus.Add(1)
	defer dnssecVerdicts.bogus.Store(before)

	ui := newTestMonitoringUI(t)
	defer func() { _ = ui.Stop() }()

	ui.metricsCollector.prometheusEnabled = true
	exported := ui.metricsCollector.generatePrometheusMetrics()
	want := fmt.Sprintf(`dnscrypt_proxy_dnssec_verdicts_total{verdict="bogus"} %d`, before+1)
	if !strings.Contains(exported, want) {
		t.Errorf("the bogus counter is not exported as %q", want)
	}
	for _, verdict := range []string{"secure", "insecure", "indeterminate"} {
		if !strings.Contains(exported, `dnscrypt_proxy_dnssec_verdicts_total{verdict="`+verdict+`"}`) {
			t.Errorf("the %s verdict is not exported", verdict)
		}
	}
}

func answerWithSignature(t *testing.T) *dns.Msg {
	t.Helper()
	msg := dns.NewMsg("www.example.test.", dns.TypeA)
	if msg == nil {
		t.Fatal("cannot build a message")
	}
	msg.Answer = []dns.RR{
		&dns.A{
			Hdr: dns.Header{Name: "www.example.test.", Class: dns.ClassINET, TTL: 300},
			A:   rdata.A{Addr: netip.MustParseAddr("192.0.2.1")},
		},
		&dns.RRSIG{
			Hdr:   dns.Header{Name: "www.example.test.", Class: dns.ClassINET, TTL: 300},
			RRSIG: rdata.RRSIG{TypeCovered: dns.TypeA, SignerName: "example.test."},
		},
	}
	msg.AuthenticatedData = true
	return msg
}

func countRRSIG(rrs []dns.RR) int {
	n := 0
	for _, rr := range rrs {
		if dns.RRToType(rr) == dns.TypeRRSIG {
			n++
		}
	}
	return n
}

// The records the validator needed are kept for a client that asked for them,
// and the answer reaches that client unchanged.
func TestAClientThatAskedForSignaturesKeepsThem(t *testing.T) {
	state := PluginsState{sessionData: map[string]any{dnssecClientWantedKey: true}}
	msg := answerWithSignature(t)

	stripDNSSECForClient(&state, msg)

	if countRRSIG(msg.Answer) != 1 {
		t.Error("a client that set DO did not get the signature it asked for")
	}
	if !msg.AuthenticatedData {
		t.Error("the verdict was withheld from a client that asked for it")
	}
}

// A client that asked for none of this gets the answer it expected, and the
// verdict is withheld: RFC 6840 section 5.8 reserves the AD bit for clients
// that set DO or AD, and to anything else it is a bit nobody can act on.
func TestAClientThatAskedForNothingGetsNeitherRecordsNorVerdict(t *testing.T) {
	state := PluginsState{sessionData: map[string]any{}}
	msg := answerWithSignature(t)

	stripDNSSECForClient(&state, msg)

	if countRRSIG(msg.Answer) != 0 {
		t.Error("records the client never asked for were passed through")
	}
	if msg.AuthenticatedData {
		t.Error("the AD bit was set for a client that set neither DO nor AD")
	}
}

// A client that wants the verdict but not the records gets exactly that.
func TestAClientThatAskedOnlyForTheVerdictGetsIt(t *testing.T) {
	state := PluginsState{sessionData: map[string]any{dnssecClientAskedADKey: true}}
	msg := answerWithSignature(t)

	stripDNSSECForClient(&state, msg)

	if countRRSIG(msg.Answer) != 0 {
		t.Error("records were passed to a client that only wanted the verdict")
	}
	if !msg.AuthenticatedData {
		t.Error("the verdict was withheld from a client that set AD")
	}
}

// The validator's own fetches carry exactly the records it needs to build a
// chain. Trimming those leaves it unable to check anything at all: every answer
// comes back insecure for want of the keys, and nothing says why.
func TestTheValidatorsOwnFetchesAreNotTrimmed(t *testing.T) {
	state := PluginsState{
		clientProto: dnssecInternalProto,
		sessionData: map[string]any{},
	}
	msg := answerWithSignature(t)

	if err := (&PluginDNSSECStrip{}).Eval(&state, msg); err != nil {
		t.Fatalf("Eval() = %v", err)
	}
	if countRRSIG(msg.Answer) != 1 {
		t.Error("the validator's own fetch was stripped of the records it needs")
	}
}
