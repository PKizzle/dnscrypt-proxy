package main

import (
	"crypto"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"strings"
	"testing"
	"time"

	"codeberg.org/miekg/dns"
	"codeberg.org/miekg/dns/rdata"
	"github.com/dnscrypt/dnscrypt-proxy/dnscrypt-proxy/dnssec"
)

type validatorTestZone struct {
	t    *testing.T
	name string
	key  *dns.DNSKEY
	priv crypto.Signer
}

// dnssecFailureTestPlugin simulates the response-plugin contract used by the
// validator. It makes the pipeline test cover the important detail that a
// plugin-provided DNSSEC SERVFAIL is not replaced with the configurable generic
// blocked-query response.
type dnssecFailureTestPlugin struct {
	response *dns.Msg
}

func (plugin *dnssecFailureTestPlugin) Name() string { return "dnssec-failure-test" }
func (plugin *dnssecFailureTestPlugin) Description() string {
	return "test-only DNSSEC failure response"
}
func (plugin *dnssecFailureTestPlugin) Init(*Proxy) error { return nil }
func (plugin *dnssecFailureTestPlugin) Drop() error       { return nil }
func (plugin *dnssecFailureTestPlugin) Reload() error     { return nil }
func (plugin *dnssecFailureTestPlugin) Eval(state *PluginsState, _ *dns.Msg) error {
	state.synthResponse = plugin.response
	state.action = PluginsActionReject
	return nil
}

func newValidatorTestZone(t *testing.T, name string) *validatorTestZone {
	return newValidatorTestZoneWithAlgorithm(t, name, dns.ECDSAP256SHA256)
}

func newValidatorTestZoneWithAlgorithm(t *testing.T, name string, algorithm uint8) *validatorTestZone {
	t.Helper()
	key := dns.NewDNSKEY(name, algorithm)
	key.Hdr.TTL = 300
	key.Flags = dns.FlagZONE
	key.Protocol = 3
	bits := 256
	if algorithm == dns.RSASHA1 || algorithm == dns.RSASHA1NSEC3SHA1 {
		bits = 1024
	}
	priv, err := key.Generate(bits)
	if err != nil {
		t.Fatalf("generate DNSKEY for %s: %v", name, err)
	}
	signer, ok := priv.(crypto.Signer)
	if !ok {
		t.Fatalf("generated DNSKEY for %s is not a signer", name)
	}
	return &validatorTestZone{t: t, name: name, key: key, priv: signer}
}

// The top-level answer validator must preserve the RFC 9905 policy result from
// the RRset verifier. Converting it to Bogus would make enforce mode refuse a
// response that the RFC requires the operator to treat as Insecure.
func TestValidatorTreatsDeprecatedRSASHA1AnswerAsInsecure(t *testing.T) {
	now := time.Now()
	root := newValidatorTestZone(t, ".")
	accepted := newValidatorTestZone(t, "example.")
	deprecated := newValidatorTestZoneWithAlgorithm(t, "example.", dns.RSASHA1)
	rootKeySig := root.sign([]dns.RR{root.key}, now)
	ds := accepted.key.ToDS(dns.SHA256)
	dsSig := root.sign([]dns.RR{ds}, now)
	zoneKeys := []dns.RR{accepted.key, deprecated.key}
	zoneKeySig := accepted.sign(zoneKeys, now)
	gap := &dns.NSEC{
		Hdr:  dns.Header{Name: "a.example.", Class: dns.ClassINET, TTL: 300},
		NSEC: rdata.NSEC{NextDomain: "z.example.", TypeBitMap: []uint16{dns.TypeNSEC, dns.TypeRRSIG}},
	}
	gapSig := accepted.sign([]dns.RR{gap}, now)
	fetcher := dnssec.NewCachingFetcher(func(qname string, qtype uint16) (*dns.Msg, error) {
		switch {
		case qtype == dns.TypeDNSKEY && qname == ".":
			return testDNSMessage(dns.RcodeSuccess, []dns.RR{root.key, rootKeySig}, nil), nil
		case qtype == dns.TypeDS && qname == "example.":
			return testDNSMessage(dns.RcodeSuccess, []dns.RR{ds, dsSig}, nil), nil
		case qtype == dns.TypeDNSKEY && qname == "example.":
			return testDNSMessage(dns.RcodeSuccess, append(zoneKeys, zoneKeySig), nil), nil
		case qtype == dns.TypeDS && qname == "www.example.":
			return testDNSMessage(dns.RcodeSuccess, nil, []dns.RR{gap, gapSig}), nil
		}
		return nil, fmt.Errorf("unexpected DNSSEC fetch %s/%d", qname, qtype)
	})
	plugin := &PluginDNSSECValidate{
		fetcher: fetcher,
		anchors: []*dns.DS{root.key.ToDS(dns.SHA256)},
	}
	record := &dns.A{
		Hdr: dns.Header{Name: "www.example.", Class: dns.ClassINET, TTL: 300},
		A:   rdata.A{Addr: netip.MustParseAddr("192.0.2.1")},
	}
	sig := deprecated.sign([]dns.RR{record}, now)
	msg := testDNSMessage(dns.RcodeSuccess, []dns.RR{record, sig}, nil)
	msg.Question = []dns.RR{&dns.A{Hdr: dns.Header{Name: record.Header().Name, Class: dns.ClassINET}}}

	result, why := plugin.judge(msg, record.Header().Name)
	if result != dnssec.Insecure || !errors.Is(why, dnssec.ErrUnsupportedSignatureAlgorithm) {
		t.Fatalf("judge() = %v (%v), want Insecure/unsupported algorithm", result, why)
	}
}

func TestValidatorTreatsDeprecatedRSASHA1DenialAsInsecure(t *testing.T) {
	now := time.Now()
	accepted := newValidatorTestZone(t, "example.")
	deprecated := newValidatorTestZoneWithAlgorithm(t, "example.", dns.RSASHA1)
	rr := &dns.NSEC{
		Hdr:  dns.Header{Name: "www.example.", Class: dns.ClassINET, TTL: 300},
		NSEC: rdata.NSEC{NextDomain: "x.example.", TypeBitMap: []uint16{dns.TypeNSEC, dns.TypeRRSIG}},
	}
	sig := deprecated.sign([]dns.RR{rr}, now)
	msg := testDNSMessage(dns.RcodeSuccess, nil, []dns.RR{rr, sig})
	msg.Question = []dns.RR{&dns.A{Hdr: dns.Header{Name: rr.Header().Name, Class: dns.ClassINET}}}
	plugin := &PluginDNSSECValidate{}
	chain := dnssec.ChainResult{
		Status: dnssec.Secure,
		Zone:   "example.",
		Keys:   []*dns.DNSKEY{accepted.key, deprecated.key},
	}

	result, why := plugin.judgeNegativeWithChain(msg, rr.Header().Name, chain, now)
	if result != dnssec.Insecure || why == nil || !strings.Contains(why.Error(), "unsupported signing algorithm") {
		t.Fatalf("negative answer = %v (%v), want Insecure/unsupported algorithm", result, why)
	}
}

func (z *validatorTestZone) sign(rrset []dns.RR, now time.Time) *dns.RRSIG {
	z.t.Helper()
	sig := dns.NewRRSIG(z.name, z.key.Algorithm, z.key.KeyTag(), uint32(now.Add(-time.Hour).Unix()), uint32(now.Add(time.Hour).Unix()))
	if err := sig.Sign(z.priv, rrset, &dns.SignOption{}); err != nil {
		z.t.Fatalf("sign RRset for %s: %v", z.name, err)
	}
	return sig
}

// RFC 6840 section 5.12 requires the extra RRSIG to be ignored. Because the
// containing zone is securely authenticated, that leaves the RRset without a
// usable signature: Bogus to the client, but incomplete evidence worth
// retrying against another upstream before enforcement returns SERVFAIL.
func TestValidatorTreatsUnknownKeySignatureAsRetryableMissingEvidence(t *testing.T) {
	now := time.Now()
	zone := newValidatorTestZone(t, "example.")
	retired := newValidatorTestZone(t, "example.")
	record := &dns.A{
		Hdr: dns.Header{Name: "example.", Class: dns.ClassINET, TTL: 300},
		A:   rdata.A{Addr: netip.MustParseAddr("192.0.2.1")},
	}
	sig := retired.sign([]dns.RR{record}, now)
	msg := testDNSMessage(dns.RcodeSuccess, []dns.RR{record, sig}, nil)
	msg.Question = []dns.RR{&dns.A{Hdr: dns.Header{Name: record.Header().Name, Class: dns.ClassINET}}}
	set := dnssec.GroupRRSets(msg.Answer)[0]
	chain := dnssec.ChainResult{
		Status: dnssec.Secure,
		Zone:   zone.name,
		Keys:   []*dns.DNSKEY{zone.key},
	}

	result, why := (&PluginDNSSECValidate{}).judgeSet(set, chain, msg, now)
	if result != dnssec.Bogus || !errors.Is(why, errDNSSECIncompleteEvidence) {
		t.Fatalf("unknown-key signature = %v (%v), want retryable Bogus", result, why)
	}
}

func TestValidatorDoesNotRetryAConclusiveBadSignatureBecauseOfAnUnknownExtra(t *testing.T) {
	now := time.Now()
	zone := newValidatorTestZone(t, "example.")
	retired := newValidatorTestZone(t, "example.")
	original := &dns.A{
		Hdr: dns.Header{Name: "example.", Class: dns.ClassINET, TTL: 300},
		A:   rdata.A{Addr: netip.MustParseAddr("192.0.2.1")},
	}
	badSig := zone.sign([]dns.RR{original}, now)
	tampered := &dns.A{
		Hdr: dns.Header{Name: original.Header().Name, Class: dns.ClassINET, TTL: 300},
		A:   rdata.A{Addr: netip.MustParseAddr("198.51.100.66")},
	}
	extraSig := retired.sign([]dns.RR{tampered}, now)
	msg := testDNSMessage(dns.RcodeSuccess, []dns.RR{tampered, extraSig, badSig}, nil)
	msg.Question = []dns.RR{&dns.A{Hdr: dns.Header{Name: tampered.Header().Name, Class: dns.ClassINET}}}
	set := dnssec.GroupRRSets(msg.Answer)[0]
	chain := dnssec.ChainResult{
		Status: dnssec.Secure,
		Zone:   zone.name,
		Keys:   []*dns.DNSKEY{zone.key},
	}

	result, why := (&PluginDNSSECValidate{}).judgeSet(set, chain, msg, now)
	if result != dnssec.Bogus || errors.Is(why, errDNSSECIncompleteEvidence) || retryableDNSSECFailure(result, why) {
		t.Fatalf("bad known-key plus unknown-key signatures = %v (%v), want conclusive non-retryable Bogus", result, why)
	}
}

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

// Query plugins store qName without a trailing dot, whereas decoded DNS RRs
// carry fully-qualified owner names. The CNAME walk must bridge those two
// representations without calling dns.EqualName, whose FQDN-only contract
// would panic on the normalized query name.
func TestCNAMEChainTerminalAcceptsNormalizedQueryName(t *testing.T) {
	cname := &dns.CNAME{
		Hdr:   dns.Header{Name: "alias.example.", Class: dns.ClassINET},
		CNAME: rdata.CNAME{Target: "target.example."},
	}
	terminal, followed, err := cnameChainTerminal("alias.example", []dnssec.RRSet{{
		Name:    "alias.example.",
		Type:    dns.TypeCNAME,
		Records: []dns.RR{cname},
	}})
	if err != nil {
		t.Fatalf("cnameChainTerminal() = error %v", err)
	}
	if !followed || terminal != "target.example." {
		t.Fatalf("cnameChainTerminal() = (%q, followed=%v), want (target.example., true)", terminal, followed)
	}
}

func TestDNSSECEnforceRejectsOnlyValidationFailuresWithoutCD(t *testing.T) {
	plugin := &PluginDNSSECValidate{mode: ValidationEnforce}
	withoutCD := dns.NewMsg("example.test.", dns.TypeA)
	withCD := dns.NewMsg("example.test.", dns.TypeA)
	withCD.CheckingDisabled = true

	for _, tc := range []struct {
		name             string
		mode             ValidationMode
		result           dnssec.Result
		checkingDisabled bool
		want             bool
	}{
		{"bogus", ValidationEnforce, dnssec.Bogus, withoutCD.CheckingDisabled, true},
		{"indeterminate", ValidationEnforce, dnssec.Indeterminate, withoutCD.CheckingDisabled, true},
		{"insecure", ValidationEnforce, dnssec.Insecure, withoutCD.CheckingDisabled, false},
		{"secure", ValidationEnforce, dnssec.Secure, withoutCD.CheckingDisabled, false},
		{"CD", ValidationEnforce, dnssec.Bogus, withCD.CheckingDisabled, false},
		{"log", ValidationLog, dnssec.Bogus, withoutCD.CheckingDisabled, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			plugin.mode = tc.mode
			if got := plugin.mustReject(tc.result, tc.checkingDisabled); got != tc.want {
				t.Errorf("mustReject(%v) = %v, want %v", tc.result, got, tc.want)
			}
		})
	}
}

func TestRetryableDNSSECFailure(t *testing.T) {
	if !retryableDNSSECFailure(dnssec.Indeterminate, errors.New("temporary lookup failure")) {
		t.Fatal("an indeterminate lookup failure should be retried")
	}
	if retryableDNSSECFailure(dnssec.Indeterminate, dnssec.ErrUnsupportedNSEC3Iterations) {
		t.Fatal("an unsupported NSEC3 iteration count is not retryable")
	}
	if !retryableDNSSECFailure(dnssec.Bogus, fmt.Errorf("%w: no denial", errDNSSECIncompleteEvidence)) {
		t.Fatal("missing DNSSEC evidence should be retried")
	}
	if !retryableDNSSECFailure(dnssec.Bogus, fmt.Errorf("relay response: %w", dnssec.ErrSignatureOutsideValidity)) {
		t.Fatal("an expired relay signature should be retried through another upstream")
	}
	if retryableDNSSECFailure(dnssec.Bogus, errors.New("invalid signature")) {
		t.Fatal("a cryptographic failure must not be retried")
	}
}

func TestDNSSECUpstreamSERVFAILRetriesDistinctResolvers(t *testing.T) {
	original := dns.NewMsg("example.test.", dns.TypeRRSIG)
	original.ID = 1234
	original.Response = true
	original.Rcode = dns.RcodeServerFailure
	if err := original.Pack(); err != nil {
		t.Fatal(err)
	}

	recovered := dns.NewMsg("example.test.", dns.TypeRRSIG)
	recovered.ID = 9999
	recovered.Response = true
	recovered.Answer = []dns.RR{&dns.RRSIG{
		Hdr:   dns.Header{Name: "example.test.", Class: dns.ClassINET, TTL: 300},
		RRSIG: rdata.RRSIG{TypeCovered: dns.TypeSOA, SignerName: "example.test."},
	}}
	if err := recovered.Pack(); err != nil {
		t.Fatal(err)
	}

	calls := 0
	returnCode, serverName, ok := retryDNSSECUpstreamSERVFAIL(
		original,
		"example.test.",
		dns.TypeRRSIG,
		"first",
		func(qname string, qtype uint16, excluded map[string]struct{}) (*dns.Msg, string, error) {
			calls++
			if qname != "example.test." || qtype != dns.TypeRRSIG {
				t.Fatalf("retry query = %s/%d", qname, qtype)
			}
			if _, ok := excluded["first"]; !ok {
				t.Fatal("original SERVFAIL resolver was not excluded")
			}
			switch calls {
			case 1:
				excluded["second"] = struct{}{}
				failed := dns.NewMsg(qname, qtype)
				failed.Response = true
				failed.Rcode = dns.RcodeServerFailure
				if err := failed.Pack(); err != nil {
					t.Fatal(err)
				}
				return failed, "second", nil
			case 2:
				if _, ok := excluded["second"]; !ok {
					t.Fatal("the second SERVFAIL resolver was not excluded")
				}
				excluded["third"] = struct{}{}
				failed := dns.NewMsg(qname, qtype)
				failed.Response = true
				failed.Rcode = dns.RcodeServerFailure
				if err := failed.Pack(); err != nil {
					t.Fatal(err)
				}
				return failed, "third", nil
			case 3:
				if _, ok := excluded["third"]; !ok {
					t.Fatal("the third SERVFAIL resolver was not excluded")
				}
				excluded["fourth"] = struct{}{}
				return recovered, "fourth", nil
			default:
				t.Fatalf("unexpected retry call %d", calls)
				return nil, "", errors.New("unreachable")
			}
		},
	)
	if !ok || returnCode != PluginsReturnCodePass {
		t.Fatalf("retry result = (%v, %v), want PASS/recovered", returnCode, ok)
	}
	if calls != 3 {
		t.Fatalf("retry calls = %d, want 3", calls)
	}
	if serverName != "fourth" {
		t.Fatalf("recovered response source = %q, want fourth", serverName)
	}
	if original.ID != 1234 || len(original.Question) != 1 || dns.RRToType(original.Question[0]) != dns.TypeRRSIG {
		t.Fatalf("retry replaced the client transaction: %#v", original)
	}
	if original.Rcode != dns.RcodeSuccess || len(original.Answer) != 1 || dns.RRToType(original.Answer[0]) != dns.TypeRRSIG {
		t.Fatalf("retry did not install the successful response: %#v", original)
	}
}

func TestDNSSECResponseSourceReplacesStaleResolverProvenance(t *testing.T) {
	state := PluginsState{serverName: "first", relayName: "first-relay"}

	setDNSSECResponseSource(&state, "second")

	if state.serverName != "second" {
		t.Fatalf("response source = %q, want second", state.serverName)
	}
	if state.relayName != "" {
		t.Fatalf("stale relay provenance was retained: %q", state.relayName)
	}
}

func TestDNSSECFailureEDEIdentifiesUnsupportedNSEC3Iterations(t *testing.T) {
	if got := dnssecFailureEDE(dnssec.Indeterminate, dnssec.ErrUnsupportedNSEC3Iterations); got != dns.ExtendedErrorUnsupportedNSEC3IterValue {
		t.Fatalf("EDE for unsupported NSEC3 iterations = %d, want %d", got, dns.ExtendedErrorUnsupportedNSEC3IterValue)
	}
	if got := dnssecFailureEDE(dnssec.Indeterminate, fmt.Errorf("fetch: %w", dnssec.ErrUnsupportedNSEC3Iterations)); got != dns.ExtendedErrorUnsupportedNSEC3IterValue {
		t.Fatalf("wrapped unsupported-NSEC3 EDE = %d, want %d", got, dns.ExtendedErrorUnsupportedNSEC3IterValue)
	}
	if got := dnssecFailureEDE(dnssec.Indeterminate, fmt.Errorf("network timeout")); got != dns.ExtendedErrorDNSSECIndeterminate {
		t.Fatalf("ordinary indeterminate EDE = %d, want %d", got, dns.ExtendedErrorDNSSECIndeterminate)
	}
}

func TestDNSSECRequestUsesCDUpstreamButRemembersTheClientBit(t *testing.T) {
	for _, clientCD := range []bool{false, true} {
		state := PluginsState{sessionData: map[string]any{}}
		query := dns.NewMsg("example.test.", dns.TypeA)
		query.CheckingDisabled = clientCD
		query.AuthenticatedData = true
		if err := (&PluginDNSSECRequest{}).Eval(&state, query); err != nil {
			t.Fatal(err)
		}
		if !query.Security || !query.CheckingDisabled {
			t.Fatalf("outgoing query has DO=%v CD=%v, want both true", query.Security, query.CheckingDisabled)
		}
		if query.AuthenticatedData {
			t.Fatal("outgoing query retained the client AD bit")
		}
		remembered, ok := state.sessionData[dnssecClientCheckingDisabledKey].(bool)
		if !ok || remembered != clientCD {
			t.Fatalf("remembered client CD = %v (present %v), want %v", remembered, ok, clientCD)
		}
		if askedForVerdict, ok := state.sessionData[dnssecClientAskedADKey].(bool); !ok || !askedForVerdict {
			t.Fatalf("remembered client AD = %v (present %v), want true", askedForVerdict, ok)
		}
	}
}

func TestDNSSECValidatorDoesNotLeakEDNSToAnUnawareClient(t *testing.T) {
	state := PluginsState{sessionData: map[string]any{}}
	query := dns.NewMsg("example.test.", dns.TypeA)
	if messageHasEDNS(query) {
		t.Fatal("fresh query unexpectedly uses EDNS")
	}
	if err := (&PluginDNSSECRequest{}).Eval(&state, query); err != nil {
		t.Fatal(err)
	}
	if !messageHasEDNS(query) || !query.Security {
		t.Fatal("validator did not add EDNS and DO to its upstream query")
	}

	response := dns.NewMsg("example.test.", dns.TypeA)
	response.Response = true
	response.UDPSize = 1232
	response.Security = true
	response.Pseudo = []dns.RR{&dns.EDE{InfoCode: dns.ExtendedErrorDNSBogus}}
	stripDNSSECForClient(&state, response)

	if messageHasEDNS(response) || response.UDPSize != 0 || len(response.Pseudo) != 0 {
		t.Fatalf("upstream EDNS leaked to unaware client: %#v", response)
	}
	if err := response.Pack(); err != nil {
		t.Fatal(err)
	}
	wire := &dns.Msg{Data: response.Data}
	if err := wire.Unpack(); err != nil {
		t.Fatal(err)
	}
	if messageHasEDNS(wire) {
		t.Fatalf("packed response contains an OPT RR: %#v", wire)
	}
}

func TestDNSSECValidatorReturnsOPTToAnEDNSClient(t *testing.T) {
	state := PluginsState{sessionData: map[string]any{}}
	query := dns.NewMsg("example.test.", dns.TypeA)
	// Exercise the minimum-size empty OPT case as well as the ordinary path.
	query.UDPSize = dns.MinMsgSize
	if err := (&PluginDNSSECRequest{}).Eval(&state, query); err != nil {
		t.Fatal(err)
	}

	// Even if a nonconforming upstream omitted OPT, our client-side
	// transaction must honor the OPT request independently.
	response := dns.NewMsg("example.test.", dns.TypeA)
	response.Response = true
	stripDNSSECForClient(&state, response)

	if !messageHasEDNS(response) || response.UDPSize != 1232 {
		t.Fatalf("EDNS client response has UDP size %d, want an OPT advertising 1232", response.UDPSize)
	}
	if response.Security {
		t.Fatal("internally-added DO bit leaked to an EDNS client that did not set it")
	}
	if err := response.Pack(); err != nil {
		t.Fatal(err)
	}
	wire := &dns.Msg{Data: response.Data}
	if err := wire.Unpack(); err != nil {
		t.Fatal(err)
	}
	if !messageHasEDNS(wire) || wire.UDPSize != 1232 {
		t.Fatalf("packed response did not contain the required OPT RR: %#v", wire)
	}
}

func TestDNSSECValidatorNormalizesAnInvalidUpstreamEDNSPayloadSize(t *testing.T) {
	state := PluginsState{sessionData: map[string]any{}}
	query := dns.NewMsg("example.test.", dns.TypeA)
	query.UDPSize = 1232
	query.Security = true
	if err := (&PluginDNSSECRequest{}).Eval(&state, query); err != nil {
		t.Fatal(err)
	}

	response := dns.NewMsg("example.test.", dns.TypeA)
	response.Response = true
	response.Security = true
	response.UDPSize = 0
	stripDNSSECForClient(&state, response)

	if response.UDPSize != 1232 || !response.Security {
		t.Fatalf("restored EDNS response has udp=%d DO=%v, want udp=1232 DO=true", response.UDPSize, response.Security)
	}
}

func TestDNSSECResponseChainNormalizesSERVFAILForAnEDNSClient(t *testing.T) {
	state := PluginsState{
		action:      PluginsActionContinue,
		qName:       "example.test.",
		questionMsg: dns.NewMsg("example.test.", dns.TypeA),
		sessionData: map[string]any{},
	}
	query := dns.NewMsg("example.test.", dns.TypeA)
	query.UDPSize = 1232
	query.Security = true
	query.CheckingDisabled = true
	if err := (&PluginDNSSECRequest{}).Eval(&state, query); err != nil {
		t.Fatal(err)
	}

	response := dns.NewMsg("example.test.", dns.TypeA)
	response.ID = state.questionMsg.ID
	response.Response = true
	response.Rcode = dns.RcodeServerFailure
	response.Security = true
	response.CheckingDisabled = true
	response.UDPSize = 0
	if err := response.Pack(); err != nil {
		t.Fatal(err)
	}

	responsePlugins := []Plugin{
		&PluginDNSSECValidate{mode: ValidationLog},
		&PluginDNSSECStrip{},
	}
	globals := PluginsGlobals{responsePlugins: &responsePlugins}
	packet, err := state.ApplyResponsePlugins(&globals, response.Data)
	if err != nil {
		t.Fatal(err)
	}
	got := &dns.Msg{Data: packet}
	if err := got.Unpack(); err != nil {
		t.Fatal(err)
	}
	if got.Rcode != dns.RcodeServerFailure || got.UDPSize != 1232 {
		t.Fatalf("SERVFAIL response has rcode=%d udp=%d, want SERVFAIL/1232", got.Rcode, got.UDPSize)
	}
	if !got.Security || !got.CheckingDisabled {
		t.Fatalf("client bits were not restored: DO=%v CD=%v", got.Security, got.CheckingDisabled)
	}
}

func TestDNSSECIngressKeepsClientEDNSStateBeforeECSMutation(t *testing.T) {
	_, ecsNet, err := net.ParseCIDR("0.0.0.0/0")
	if err != nil {
		t.Fatal(err)
	}
	queryPlugins := []Plugin{
		&PluginECS{nets: []*net.IPNet{ecsNet}},
		&PluginDNSSECRequest{},
		&PluginGetSetPayloadSize{},
	}
	responsePlugins := []Plugin{&PluginDNSSECStrip{}}
	globals := &PluginsGlobals{
		queryPlugins:    &queryPlugins,
		responsePlugins: &responsePlugins,
	}
	state := NewPluginsState(&Proxy{}, "udp", nil, "", time.Now())
	query := dns.NewMsg("example.test.", dns.TypeA)
	query.ID = 2345
	if err := query.Pack(); err != nil {
		t.Fatal(err)
	}

	outboundPacket, err := state.ApplyQueryPlugins(globals, query.Data, nil)
	if err != nil {
		t.Fatal(err)
	}
	outbound := &dns.Msg{Data: outboundPacket}
	if err := outbound.Unpack(); err != nil {
		t.Fatal(err)
	}
	if !messageHasEDNS(outbound) || !outbound.Security {
		t.Fatalf("upstream query lacks internally required EDNS/DO: %#v", outbound)
	}
	if hadEDNS, ok := state.sessionData[dnssecClientHadEDNSKey].(bool); !ok || hadEDNS {
		t.Fatalf("recorded client EDNS = %v (present %v), want false", hadEDNS, ok)
	}
	if state.maxUnencryptedUDPSafePayloadSize != dns.MinMsgSize {
		t.Fatalf("legacy client UDP limit = %d, want %d", state.maxUnencryptedUDPSafePayloadSize, dns.MinMsgSize)
	}

	response := dns.NewMsg("example.test.", dns.TypeA)
	response.ID = query.ID
	response.Response = true
	response.UDPSize = 1232
	response.Security = true
	if err := response.Pack(); err != nil {
		t.Fatal(err)
	}
	clientPacket, err := state.ApplyResponsePlugins(globals, response.Data)
	if err != nil {
		t.Fatal(err)
	}
	clientResponse := &dns.Msg{Data: clientPacket}
	if err := clientResponse.Unpack(); err != nil {
		t.Fatal(err)
	}
	if messageHasEDNS(clientResponse) {
		t.Fatalf("internally added EDNS leaked to the client: %#v", clientResponse)
	}
}

func TestDNSSECFailureResponseIsSERVFAILAndKeepsCD(t *testing.T) {
	query := dns.NewMsg("example.test.", dns.TypeA)
	query.ID = 1234
	query.RecursionDesired = true
	query.CheckingDisabled = true
	query.UDPSize = 1232

	response := DNSSECFailureResponseFromMessage(query, dns.ExtendedErrorDNSBogus)
	if response.Rcode != dns.RcodeServerFailure {
		t.Fatalf("rcode = %d, want SERVFAIL", response.Rcode)
	}
	if response.ID != query.ID || !response.CheckingDisabled || response.AuthenticatedData {
		t.Fatalf("response flags/ID do not preserve DNSSEC failure semantics: %#v", response)
	}
	if len(response.Pseudo) != 1 {
		t.Fatalf("EDE count = %d, want 1", len(response.Pseudo))
	}
	ede, ok := response.Pseudo[0].(*dns.EDE)
	if !ok || ede.InfoCode != dns.ExtendedErrorDNSBogus {
		t.Fatalf("EDE = %#v, want DNSSEC Bogus", response.Pseudo[0])
	}
}

func TestResponsePipelineKeepsDNSSECFailureResponse(t *testing.T) {
	query := dns.NewMsg("example.test.", dns.TypeA)
	query.ID = 4321
	query.UDPSize = 1232
	upstream := dns.NewMsg("example.test.", dns.TypeA)
	upstream.ID = query.ID
	upstream.Response = true
	if err := upstream.Pack(); err != nil {
		t.Fatal(err)
	}

	dnssecFailure := DNSSECFailureResponseFromMessage(query, dns.ExtendedErrorDNSBogus)
	responsePlugins := []Plugin{&dnssecFailureTestPlugin{response: dnssecFailure}}
	globals := &PluginsGlobals{
		responsePlugins:        &responsePlugins,
		refusedCodeInResponses: false, // The deployment's HINFO setting.
		respondWithIPv4:        nil,
		respondWithIPv6:        nil,
	}
	state := PluginsState{
		action:      PluginsActionContinue,
		questionMsg: query,
	}
	if _, err := state.ApplyResponsePlugins(globals, upstream.Data); err != nil {
		t.Fatal(err)
	}
	if state.synthResponse != dnssecFailure {
		t.Fatal("response pipeline replaced the DNSSEC-specific synthesized response")
	}
	if state.synthResponse.Rcode != dns.RcodeServerFailure {
		t.Fatalf("synthesized rcode = %d, want SERVFAIL", state.synthResponse.Rcode)
	}
	packet, err := handleSynthesizedResponse(&state, state.synthResponse)
	if err != nil {
		t.Fatal(err)
	}
	got := &dns.Msg{Data: packet}
	if err := got.Unpack(); err != nil {
		t.Fatal(err)
	}
	if got.Rcode != dns.RcodeServerFailure {
		t.Fatalf("wire rcode = %d, want SERVFAIL", got.Rcode)
	}
	if len(got.Pseudo) != 1 {
		t.Fatalf("wire EDE count = %d, want 1", len(got.Pseudo))
	}
	ede, ok := got.Pseudo[0].(*dns.EDE)
	if !ok || ede.InfoCode != dns.ExtendedErrorDNSBogus {
		t.Fatalf("wire EDE = %#v, want DNSSEC Bogus", got.Pseudo[0])
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

// A configured exception means this validator did not authenticate the data;
// it must never pass through an AD bit asserted by the upstream. It is still a
// client query and therefore belongs in both exported and dashboard verdict
// totals instead of disappearing as an unaccounted-for request.
func TestConfiguredInsecureZoneClearsUpstreamADAndRecordsVerdict(t *testing.T) {
	plugin := &PluginDNSSECValidate{
		mode:          ValidationEnforce,
		insecureZones: []string{"local."},
	}
	msg := dns.NewMsg("printer.local.", dns.TypeA)
	msg.AuthenticatedData = true
	state := PluginsState{
		qName:       "printer.local",
		returnCode:  PluginsReturnCodePass,
		sessionData: map[string]any{},
		questionMsg: dns.NewMsg("printer.local.", dns.TypeA),
	}
	before := dnssecVerdicts.insecure.Load()

	if err := plugin.Eval(&state, msg); err != nil {
		t.Fatalf("Eval() = %v", err)
	}
	if msg.AuthenticatedData {
		t.Fatal("configured insecure zone retained an upstream AD assertion")
	}
	if got := state.sessionData[dnssecVerdictKey]; got != "insecure" {
		t.Fatalf("verdict = %v, want insecure", got)
	}
	if reason, _ := state.sessionData[dnssecReasonKey].(string); reason == "" {
		t.Fatal("configured insecure verdict has no attributable reason")
	}
	if got := dnssecVerdicts.insecure.Load(); got != before+1 {
		t.Fatalf("insecure counter = %d, want %d", got, before+1)
	}
	if state.action == PluginsActionReject || state.returnCode == PluginsReturnCodeServFail {
		t.Fatal("configured insecure zone was rejected in enforce mode")
	}
}

// Trust anchors are scoped by owner and class. This validator is configured
// with the IN root anchor, so applying its IN chain walk to a CHAOS answer can
// only manufacture a false DNSSEC failure (and an internal retry would even
// ask an IN question in place of the client's CHAOS question). Treat classes
// outside the configured validation scope as local-policy insecure: return the
// data without AD and do not reject it in enforce mode.
func TestNonINClassIsOutsideValidationScope(t *testing.T) {
	plugin := &PluginDNSSECValidate{mode: ValidationEnforce}
	msg := dns.NewMsg("version.bind.", dns.TypeTXT)
	msg.Question[0].Header().Class = dns.ClassCHAOS
	msg.AuthenticatedData = true
	msg.Answer = []dns.RR{&dns.TXT{
		Hdr: dns.Header{Name: "version.bind.", Class: dns.ClassCHAOS, TTL: 0},
		TXT: rdata.TXT{Txt: []string{"test"}},
	}}
	state := PluginsState{
		qName:       "version.bind",
		returnCode:  PluginsReturnCodePass,
		sessionData: map[string]any{},
		questionMsg: dns.NewMsg("version.bind.", dns.TypeTXT),
	}
	state.questionMsg.Question[0].Header().Class = dns.ClassCHAOS

	if err := plugin.Eval(&state, msg); err != nil {
		t.Fatalf("Eval() = %v", err)
	}
	if msg.AuthenticatedData {
		t.Fatal("non-IN answer retained an upstream AD assertion")
	}
	if got := state.sessionData[dnssecVerdictKey]; got != "insecure" {
		t.Fatalf("verdict = %v, want insecure", got)
	}
	if state.action == PluginsActionReject || state.returnCode == PluginsReturnCodeServFail {
		t.Fatal("non-IN answer was rejected in enforce mode")
	}
}

// RFC 4035 section 5.3.1 requires the signer name to identify the zone that
// contains the RRset. A cryptographically genuine parent signature below a
// delegated child is therefore not an authentication of the child's record.
func TestValidatorRejectsAParentSignatureBelowADelegation(t *testing.T) {
	now := time.Now()
	root := newValidatorTestZone(t, ".")
	child := newValidatorTestZone(t, "example.")
	ds := child.key.ToDS(dns.SHA256)
	dsSig := root.sign([]dns.RR{ds}, now)
	rootKeySig := root.sign([]dns.RR{root.key}, now)
	childKeySig := child.sign([]dns.RR{child.key}, now)
	notACut := &dns.NSEC{
		Hdr:  dns.Header{Name: "www.example.", Class: dns.ClassINET, TTL: 300},
		NSEC: rdata.NSEC{NextDomain: "x.example.", TypeBitMap: []uint16{dns.TypeA, dns.TypeNSEC, dns.TypeRRSIG}},
	}
	notACutSig := child.sign([]dns.RR{notACut}, now)

	fetcher := dnssec.NewCachingFetcher(func(qname string, qtype uint16) (*dns.Msg, error) {
		switch qtype {
		case dns.TypeDNSKEY:
			switch qname {
			case ".":
				return testDNSMessage(dns.RcodeSuccess, []dns.RR{root.key, rootKeySig}, nil), nil
			case "example.":
				return testDNSMessage(dns.RcodeSuccess, []dns.RR{child.key, childKeySig}, nil), nil
			}
		case dns.TypeDS:
			switch qname {
			case "example.":
				return testDNSMessage(dns.RcodeSuccess, []dns.RR{ds, dsSig}, nil), nil
			case "www.example.":
				return testDNSMessage(dns.RcodeSuccess, nil, []dns.RR{notACut, notACutSig}), nil
			}
		}
		return nil, fmt.Errorf("unexpected DNSSEC fetch %s/%d", qname, qtype)
	})
	plugin := &PluginDNSSECValidate{fetcher: fetcher, anchors: []*dns.DS{root.key.ToDS(dns.SHA256)}}
	record := &dns.A{
		Hdr: dns.Header{Name: "www.example.", Class: dns.ClassINET, TTL: 300},
		A:   rdata.A{Addr: netip.MustParseAddr("192.0.2.1")},
	}
	parentSig := root.sign([]dns.RR{record}, now)
	msg := testDNSMessage(dns.RcodeSuccess, []dns.RR{record, parentSig}, nil)
	msg.Question = []dns.RR{&dns.A{Hdr: dns.Header{Name: "www.example.", Class: dns.ClassINET}}}

	result, _ := plugin.judge(msg, "www.example.")
	if result != dnssec.Bogus {
		t.Fatalf("judge() = %v, want bogus for the parent-zone signature", result)
	}
}

// RFC 4035 sections 3.2.3 and 5.5 require AD to cover the answer to the
// question, not merely some authentic RRset that happens to be in the Answer
// section. A recursive upstream (or an attacker replaying its signed data)
// must not be able to replace the requested RRset and its denial proof with an
// unrelated, validly signed RRset and still receive a Secure verdict.
func TestValidatorRejectsSignedButUnrelatedPositiveAnswer(t *testing.T) {
	now := time.Now()
	root := newValidatorTestZone(t, ".")
	rootKeySig := root.sign([]dns.RR{root.key}, now)
	notADelegation := &dns.NSEC{
		Hdr: dns.Header{Name: "unrelated.", Class: dns.ClassINET, TTL: 300},
		NSEC: rdata.NSEC{
			NextDomain: "z.",
			TypeBitMap: []uint16{dns.TypeA, dns.TypeNSEC, dns.TypeRRSIG},
		},
	}
	notADelegationSig := root.sign([]dns.RR{notADelegation}, now)
	fetcher := dnssec.NewCachingFetcher(func(qname string, qtype uint16) (*dns.Msg, error) {
		switch {
		case qtype == dns.TypeDNSKEY && qname == ".":
			return testDNSMessage(dns.RcodeSuccess, []dns.RR{root.key, rootKeySig}, nil), nil
		case qtype == dns.TypeDS && qname == "unrelated.":
			return testDNSMessage(dns.RcodeSuccess, nil, []dns.RR{notADelegation, notADelegationSig}), nil
		}
		return nil, fmt.Errorf("unexpected DNSSEC fetch %s/%d", qname, qtype)
	})
	plugin := &PluginDNSSECValidate{fetcher: fetcher, anchors: []*dns.DS{root.key.ToDS(dns.SHA256)}}
	unrelated := &dns.A{
		Hdr: dns.Header{Name: "unrelated.", Class: dns.ClassINET, TTL: 300},
		A:   rdata.A{Addr: netip.MustParseAddr("192.0.2.1")},
	}
	msg := testDNSMessage(dns.RcodeSuccess, []dns.RR{unrelated, root.sign([]dns.RR{unrelated}, now)}, nil)
	msg.Question = []dns.RR{&dns.A{Hdr: dns.Header{Name: ".", Class: dns.ClassINET}}}

	result, why := plugin.judge(msg, ".")
	if result != dnssec.Bogus {
		t.Fatalf("signed unrelated answer = %v (%v), want bogus", result, why)
	}
	if why == nil || !strings.Contains(why.Error(), "proved nothing") {
		t.Fatalf("signed unrelated answer reason = %v, want missing-denial diagnosis", why)
	}
}

// RFC 4035 sections 4.5 and 5.3.1 bind validation and caching to QCLASS as
// well as QNAME/QTYPE. Even a cryptographically valid CH RRset at the requested
// owner does not answer an IN question and cannot receive AD for it.
func TestValidatorRejectsSignedAnswerFromAnotherClass(t *testing.T) {
	now := time.Now()
	root := newValidatorTestZone(t, ".")
	rootKeySig := root.sign([]dns.RR{root.key}, now)
	fetcher := dnssec.NewCachingFetcher(func(qname string, qtype uint16) (*dns.Msg, error) {
		if qname == "." && qtype == dns.TypeDNSKEY {
			return testDNSMessage(dns.RcodeSuccess, []dns.RR{root.key, rootKeySig}, nil), nil
		}
		return nil, fmt.Errorf("unexpected DNSSEC fetch %s/%d", qname, qtype)
	})
	plugin := &PluginDNSSECValidate{fetcher: fetcher, anchors: []*dns.DS{root.key.ToDS(dns.SHA256)}}
	wrongClass := &dns.A{
		Hdr: dns.Header{Name: ".", Class: dns.ClassCHAOS, TTL: 300},
		A:   rdata.A{Addr: netip.MustParseAddr("192.0.2.1")},
	}
	msg := testDNSMessage(dns.RcodeSuccess, []dns.RR{wrongClass, root.sign([]dns.RR{wrongClass}, now)}, nil)
	msg.Question = []dns.RR{&dns.A{Hdr: dns.Header{Name: ".", Class: dns.ClassINET}}}

	result, why := plugin.judge(msg, ".")
	if result != dnssec.Bogus {
		t.Fatalf("other-class answer = %v (%v), want bogus", result, why)
	}
}

func TestValidatorClassifiesProvablyBadSignatureWhenOwnerWalkIsIncomplete(t *testing.T) {
	now := time.Now()
	root := newValidatorTestZone(t, ".")
	zone := newValidatorTestZone(t, "example.")
	rootKeySig := root.sign([]dns.RR{root.key}, now)
	zoneDS := zone.key.ToDS(dns.SHA256)
	zoneDSSig := root.sign([]dns.RR{zoneDS}, now)
	zoneKeySig := zone.sign([]dns.RR{zone.key}, now)
	notADelegation := &dns.NSEC{
		Hdr:  dns.Header{Name: "www.example.", Class: dns.ClassINET, TTL: 300},
		NSEC: rdata.NSEC{NextDomain: "x.example.", TypeBitMap: []uint16{dns.TypeA, dns.TypeNSEC, dns.TypeRRSIG}},
	}
	notADelegationSig := zone.sign([]dns.RR{notADelegation}, now)

	fetcher := dnssec.NewCachingFetcher(func(qname string, qtype uint16) (*dns.Msg, error) {
		switch {
		case qtype == dns.TypeDNSKEY && qname == ".":
			return testDNSMessage(dns.RcodeSuccess, []dns.RR{root.key, rootKeySig}, nil), nil
		case qtype == dns.TypeDS && qname == "example.":
			return testDNSMessage(dns.RcodeSuccess, []dns.RR{zoneDS, zoneDSSig}, nil), nil
		case qtype == dns.TypeDNSKEY && qname == "example.":
			return testDNSMessage(dns.RcodeSuccess, []dns.RR{zone.key, zoneKeySig}, nil), nil
		case qtype == dns.TypeDS && qname == "www.example.":
			return testDNSMessage(dns.RcodeSuccess, nil, []dns.RR{notADelegation, notADelegationSig}), nil
		case qtype == dns.TypeDS && qname == "bad.www.example.":
			// Model a broken authority which omits the authenticated DS
			// denial at the exact owner. The owner walk cannot safely accept
			// anything, but the signer's authenticated keys can still prove
			// that an offered signature is invalid.
			return testDNSMessage(dns.RcodeSuccess, nil, nil), nil
		}
		return nil, fmt.Errorf("unexpected DNSSEC fetch %s/%d", qname, qtype)
	})
	plugin := &PluginDNSSECValidate{fetcher: fetcher, anchors: []*dns.DS{root.key.ToDS(dns.SHA256)}}
	record := &dns.A{
		Hdr: dns.Header{Name: "bad.www.example.", Class: dns.ClassINET, TTL: 300},
		A:   rdata.A{Addr: netip.MustParseAddr("192.0.2.1")},
	}
	validSig := zone.sign([]dns.RR{record}, now)
	question := []dns.RR{&dns.A{Hdr: dns.Header{Name: record.Header().Name, Class: dns.ClassINET}}}

	for _, tc := range []struct {
		name       string
		sig        *dns.RRSIG
		want       dnssec.Result
		wantReason string
	}{
		{name: "valid signature cannot repair missing delegation proof", sig: validSig, want: dnssec.Bogus, wantReason: "DS response omitted"},
		{name: "bad cryptographic signature", sig: func() *dns.RRSIG {
			bad := *validSig
			bad.Signature = "AAAA"
			return &bad
		}(), want: dnssec.Bogus, wantReason: "signature over"},
		{name: "expired signature", sig: func() *dns.RRSIG {
			expired := *validSig
			expired.Inception = uint32(now.Add(-2 * time.Hour).Unix())
			expired.Expiration = uint32(now.Add(-time.Hour).Unix())
			return &expired
		}(), want: dnssec.Bogus, wantReason: "signature over"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			msg := testDNSMessage(dns.RcodeSuccess, []dns.RR{record, tc.sig}, nil)
			msg.Question = question
			result, why := plugin.judge(msg, record.Header().Name)
			if result != tc.want {
				t.Fatalf("judge() = %v, want %v", result, tc.want)
			}
			if why == nil || !strings.Contains(why.Error(), tc.wantReason) {
				t.Fatalf("judge() reason = %v, want substring %q", why, tc.wantReason)
			}
		})
	}
}

// RFC 4035 section 2.2 says that RRSIG records do not form RRsets and that an
// RRSIG record itself must not be signed.  A positive explicit RRSIG query is
// consequently returned without AD, matching Unbound, instead of being
// mistaken for a signed negative response with a missing denial proof.
func TestValidatorTreatsPositiveRRSIGQueryAsInsecure(t *testing.T) {
	plugin := &PluginDNSSECValidate{mode: ValidationEnforce}
	msg := dns.NewMsg("example.", dns.TypeRRSIG)
	msg.Answer = []dns.RR{&dns.RRSIG{
		Hdr: dns.Header{Name: "example.", Class: dns.ClassINET, TTL: 300},
		RRSIG: rdata.RRSIG{
			TypeCovered: dns.TypeSOA,
			SignerName:  "example.",
		},
	}}

	result, why := plugin.judge(msg, "example.")
	if result != dnssec.Insecure {
		t.Fatalf("positive RRSIG query = %v (%v), want insecure", result, why)
	}
	if !errors.Is(why, errDNSSECRRSIGNotAuthenticated) {
		t.Fatalf("positive RRSIG reason = %v, want RRSIG-not-authenticated", why)
	}

	msg.AuthenticatedData = true
	state := PluginsState{
		qName:       "example.",
		returnCode:  PluginsReturnCodePass,
		sessionData: map[string]any{},
		questionMsg: dns.NewMsg("example.", dns.TypeRRSIG),
	}
	if err := plugin.Eval(&state, msg); err != nil {
		t.Fatalf("Eval() = %v", err)
	}
	if state.action == PluginsActionReject || state.returnCode == PluginsReturnCodeServFail {
		t.Fatal("positive RRSIG query was rejected in enforce mode")
	}
	if msg.AuthenticatedData {
		t.Fatal("positive RRSIG query retained an AD assertion")
	}
	if got := state.sessionData[dnssecVerdictKey]; got != "insecure" {
		t.Fatalf("positive RRSIG verdict = %v, want insecure", got)
	}
}

// The RRSIG exception must not become a blanket bypass.  Ordinary answer data
// accompanying the requested signatures still has to authenticate normally.
func TestPositiveRRSIGQueryStillRejectsBogusOrdinaryData(t *testing.T) {
	now := time.Now()
	root := newValidatorTestZone(t, ".")
	rootKeySig := root.sign([]dns.RR{root.key}, now)
	notADelegation := &dns.NSEC{
		Hdr:  dns.Header{Name: "alias.", Class: dns.ClassINET, TTL: 300},
		NSEC: rdata.NSEC{NextDomain: "b.", TypeBitMap: []uint16{dns.TypeCNAME, dns.TypeNSEC, dns.TypeRRSIG}},
	}
	notADelegationSig := root.sign([]dns.RR{notADelegation}, now)
	fetcher := dnssec.NewCachingFetcher(func(qname string, qtype uint16) (*dns.Msg, error) {
		switch {
		case qtype == dns.TypeDNSKEY && qname == ".":
			return testDNSMessage(dns.RcodeSuccess, []dns.RR{root.key, rootKeySig}, nil), nil
		case qtype == dns.TypeDS && qname == "alias.":
			return testDNSMessage(dns.RcodeSuccess, nil, []dns.RR{notADelegation, notADelegationSig}), nil
		}
		return nil, fmt.Errorf("unexpected DNSSEC fetch %s/%d", qname, qtype)
	})
	plugin := &PluginDNSSECValidate{fetcher: fetcher, anchors: []*dns.DS{root.key.ToDS(dns.SHA256)}}
	cname := &dns.CNAME{
		Hdr:   dns.Header{Name: "alias.", Class: dns.ClassINET, TTL: 300},
		CNAME: rdata.CNAME{Target: "target."},
	}
	badSig := root.sign([]dns.RR{cname}, now)
	badSig.Signature = "AAAA"
	msg := testDNSMessage(dns.RcodeSuccess, []dns.RR{cname, badSig}, nil)
	msg.Question = []dns.RR{&dns.RRSIG{Hdr: dns.Header{Name: "alias.", Class: dns.ClassINET}}}

	result, _ := plugin.judge(msg, "alias.")
	if result != dnssec.Bogus {
		t.Fatalf("RRSIG query with bogus CNAME = %v, want bogus", result)
	}
}

// DS data is the exception to the ordinary owner-zone rule: the RRset is at
// the child zone cut, but RFC 4035 sections 2.4 and 5.2 put it in the parent
// zone and require the parent's signature. This is the positive counterpart
// of the parent-side DS-denial tests below.
func TestValidatorAuthenticatesPositiveDSWithParentKeys(t *testing.T) {
	now := time.Now()
	root := newValidatorTestZone(t, ".")
	parent := newValidatorTestZone(t, "example.")
	child := newValidatorTestZone(t, "child.example.")
	rootKeySig := root.sign([]dns.RR{root.key}, now)
	parentDS := parent.key.ToDS(dns.SHA256)
	parentDSSig := root.sign([]dns.RR{parentDS}, now)
	parentKeySig := parent.sign([]dns.RR{parent.key}, now)
	childDS := child.key.ToDS(dns.SHA256)
	childDSSig := parent.sign([]dns.RR{childDS}, now)

	fetcher := dnssec.NewCachingFetcher(func(qname string, qtype uint16) (*dns.Msg, error) {
		switch {
		case qtype == dns.TypeDNSKEY && qname == ".":
			return testDNSMessage(dns.RcodeSuccess, []dns.RR{root.key, rootKeySig}, nil), nil
		case qtype == dns.TypeDS && qname == "example.":
			return testDNSMessage(dns.RcodeSuccess, []dns.RR{parentDS, parentDSSig}, nil), nil
		case qtype == dns.TypeDNSKEY && qname == "example.":
			return testDNSMessage(dns.RcodeSuccess, []dns.RR{parent.key, parentKeySig}, nil), nil
		}
		return nil, fmt.Errorf("unexpected DNSSEC fetch %s/%d", qname, qtype)
	})
	plugin := &PluginDNSSECValidate{fetcher: fetcher, anchors: []*dns.DS{root.key.ToDS(dns.SHA256)}}
	question := []dns.RR{&dns.DS{Hdr: dns.Header{Name: "child.example.", Class: dns.ClassINET}}}

	msg := testDNSMessage(dns.RcodeSuccess, []dns.RR{childDS, childDSSig}, nil)
	msg.Question = question
	if result, why := plugin.judge(msg, "child.example."); result != dnssec.Secure {
		t.Fatalf("parent-signed DS = %v (%v), want secure", result, why)
	}

	// A higher ancestor cannot bypass the actual parent merely because its key
	// can produce a cryptographically valid signature over the same bytes.
	ancestorSig := root.sign([]dns.RR{childDS}, now)
	msg = testDNSMessage(dns.RcodeSuccess, []dns.RR{childDS, ancestorSig}, nil)
	msg.Question = question
	if result, _ := plugin.judge(msg, "child.example."); result != dnssec.Bogus {
		t.Fatalf("ancestor-signed DS = %v, want bogus", result)
	}
}

// RFC 4035 section 3.2.3 allows a CNAME generated by an authenticated DNAME
// to be unsigned. Treating it as forged makes standard DNAME redirection fail
// under enforcement; accepting an arbitrary unsigned CNAME would be worse.
func TestValidatorAcceptsOnlyCNAMEsSynthesizedByASecureDNAME(t *testing.T) {
	now := time.Now()
	root := newValidatorTestZone(t, ".")
	rootKeySig := root.sign([]dns.RR{root.key}, now)
	dname := &dns.DNAME{
		Hdr:   dns.Header{Name: "foo.", Class: dns.ClassINET, TTL: 300},
		DNAME: rdata.DNAME{Target: "bar."},
	}
	dnameSig := root.sign([]dns.RR{dname}, now)
	notADelegation := &dns.NSEC{
		Hdr:  dns.Header{Name: "foo.", Class: dns.ClassINET, TTL: 300},
		NSEC: rdata.NSEC{NextDomain: "g.", TypeBitMap: []uint16{dns.TypeDNAME, dns.TypeNSEC, dns.TypeRRSIG}},
	}
	notADelegationSig := root.sign([]dns.RR{notADelegation}, now)

	fetcher := dnssec.NewCachingFetcher(func(qname string, qtype uint16) (*dns.Msg, error) {
		switch {
		case qtype == dns.TypeDNSKEY && qname == ".":
			return testDNSMessage(dns.RcodeSuccess, []dns.RR{root.key, rootKeySig}, nil), nil
		case qtype == dns.TypeDS && qname == "foo.":
			return testDNSMessage(dns.RcodeSuccess, nil, []dns.RR{notADelegation, notADelegationSig}), nil
		case qtype == dns.TypeDS && qname == "www.foo.":
			return testDNSMessage(dns.RcodeSuccess, nil, []dns.RR{notADelegation, notADelegationSig}), nil
		}
		return nil, fmt.Errorf("unexpected DNSSEC fetch %s/%d", qname, qtype)
	})
	plugin := &PluginDNSSECValidate{fetcher: fetcher, anchors: []*dns.DS{root.key.ToDS(dns.SHA256)}}

	for _, tc := range []struct {
		name   string
		target string
		want   dnssec.Result
	}{
		{"synthesized", "www.bar.", dnssec.Secure},
		{"forged", "www.invalid.", dnssec.Bogus},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cname := &dns.CNAME{
				Hdr:   dns.Header{Name: "www.foo.", Class: dns.ClassINET, TTL: 300},
				CNAME: rdata.CNAME{Target: tc.target},
			}
			msg := testDNSMessage(dns.RcodeSuccess, []dns.RR{dname, dnameSig, cname}, nil)
			msg.Question = []dns.RR{&dns.A{Hdr: dns.Header{Name: "www.foo.", Class: dns.ClassINET}}}
			result, _ := plugin.judge(msg, "www.foo.")
			if result != tc.want {
				t.Fatalf("judge() = %v, want %v", result, tc.want)
			}
		})
	}
}

// RFC 4592 section 4.4 and RFC 6672 sections 3.3 and 8 warn that a DNAME
// synthesized from a wildcard is non-deterministic: different caches can
// derive different rewrite rules, and the generated CNAME has no signature
// of its own. Match Unbound's conservative validator policy and refuse such a
// DNAME when it is being used for redirection (a literal QTYPE=DNAME lookup is
// still an exact request for the DNAME data itself).
func TestValidatorRejectsWildcardSynthesizedDNAMEForRedirection(t *testing.T) {
	now := time.Now()
	root := newValidatorTestZone(t, ".")
	zone := newValidatorTestZone(t, "example.")
	rootKeySig := root.sign([]dns.RR{root.key}, now)
	zoneDS := zone.key.ToDS(dns.SHA256)
	zoneDSSig := root.sign([]dns.RR{zoneDS}, now)
	zoneKeySig := zone.sign([]dns.RR{zone.key}, now)
	gap := &dns.NSEC{
		Hdr: dns.Header{Name: "a.example.", Class: dns.ClassINET, TTL: 300},
		NSEC: rdata.NSEC{
			NextDomain: "z.example.",
			TypeBitMap: []uint16{dns.TypeNSEC, dns.TypeRRSIG},
		},
	}
	gapSig := zone.sign([]dns.RR{gap}, now)
	fetcher := dnssec.NewCachingFetcher(func(qname string, qtype uint16) (*dns.Msg, error) {
		switch {
		case qtype == dns.TypeDNSKEY && qname == ".":
			return testDNSMessage(dns.RcodeSuccess, []dns.RR{root.key, rootKeySig}, nil), nil
		case qtype == dns.TypeDS && qname == "example.":
			return testDNSMessage(dns.RcodeSuccess, []dns.RR{zoneDS, zoneDSSig}, nil), nil
		case qtype == dns.TypeDNSKEY && qname == "example.":
			return testDNSMessage(dns.RcodeSuccess, []dns.RR{zone.key, zoneKeySig}, nil), nil
		case qtype == dns.TypeDS && qname == "x.example.":
			return testDNSMessage(dns.RcodeSuccess, nil, []dns.RR{gap, gapSig}), nil
		}
		return nil, fmt.Errorf("unexpected DNSSEC fetch %s/%d", qname, qtype)
	})
	plugin := &PluginDNSSECValidate{fetcher: fetcher, anchors: []*dns.DS{root.key.ToDS(dns.SHA256)}}

	wildcard := &dns.DNAME{
		Hdr:   dns.Header{Name: "*.example.", Class: dns.ClassINET, TTL: 300},
		DNAME: rdata.DNAME{Target: "target."},
	}
	sig := zone.sign([]dns.RR{wildcard}, now)
	expanded := &dns.DNAME{
		Hdr:   dns.Header{Name: "x.example.", Class: dns.ClassINET, TTL: 300},
		DNAME: rdata.DNAME{Target: "target."},
	}
	sig.Hdr.Name = expanded.Header().Name
	msg := testDNSMessage(dns.RcodeSuccess, []dns.RR{expanded, sig}, []dns.RR{gap, gapSig})
	msg.Question = []dns.RR{&dns.A{Hdr: dns.Header{Name: "www.x.example.", Class: dns.ClassINET}}}
	set := dnssec.GroupRRSets(msg.Answer)[0]

	result, why := plugin.judgeSet(set, dnssec.ChainResult{}, msg, now)
	if result != dnssec.Bogus {
		t.Fatalf("wildcard-synthesized DNAME = %v (%v), want bogus", result, why)
	}
}

// RFC 6672 section 2.3: a DNAME redirects names subordinate to its owner, not
// the owner itself. A signed exact-owner NSEC may consequently prove ordinary
// NODATA there; rejecting its DNAME bitmap misclassifies a valid answer bogus.
func TestValidatorAcceptsSignedNoDataAtExactDNAMEOwner(t *testing.T) {
	now := time.Now()
	root := newValidatorTestZone(t, ".")
	rootKeySig := root.sign([]dns.RR{root.key}, now)
	dnameOwner := &dns.NSEC{
		Hdr:  dns.Header{Name: "foo.", Class: dns.ClassINET, TTL: 300},
		NSEC: rdata.NSEC{NextDomain: "g.", TypeBitMap: []uint16{dns.TypeDNAME, dns.TypeNSEC, dns.TypeRRSIG}},
	}
	dnameOwnerSig := root.sign([]dns.RR{dnameOwner}, now)

	fetcher := dnssec.NewCachingFetcher(func(qname string, qtype uint16) (*dns.Msg, error) {
		switch {
		case qtype == dns.TypeDNSKEY && qname == ".":
			return testDNSMessage(dns.RcodeSuccess, []dns.RR{root.key, rootKeySig}, nil), nil
		case qtype == dns.TypeDS && qname == "foo.":
			return testDNSMessage(dns.RcodeSuccess, nil, []dns.RR{dnameOwner, dnameOwnerSig}), nil
		}
		return nil, fmt.Errorf("unexpected DNSSEC fetch %s/%d", qname, qtype)
	})
	plugin := &PluginDNSSECValidate{fetcher: fetcher, anchors: []*dns.DS{root.key.ToDS(dns.SHA256)}}
	msg := testDNSMessage(dns.RcodeSuccess, nil, []dns.RR{dnameOwner, dnameOwnerSig})
	msg.Question = []dns.RR{&dns.A{Hdr: dns.Header{Name: "foo.", Class: dns.ClassINET}}}

	result, why := plugin.judge(msg, "foo.")
	if result != dnssec.Secure {
		t.Fatalf("judge() = %v (%v), want secure exact-owner DNAME NODATA", result, why)
	}
}

// RFC 4035 appendix B.7: a wildcard NODATA response is secure when an NSEC
// proves no closer name exists and the wildcard's own NSEC omits the requested
// type. Treating it as an ordinary exact-name NODATA would reject a valid
// negative response as soon as enforcement is enabled.
func TestValidatorAcceptsASignedWildcardNoDataResponse(t *testing.T) {
	now := time.Now()
	root := newValidatorTestZone(t, ".")
	rootKeySig := root.sign([]dns.RR{root.key}, now)

	noCutExample := &dns.NSEC{
		Hdr:  dns.Header{Name: "example.", Class: dns.ClassINET, TTL: 300},
		NSEC: rdata.NSEC{NextDomain: "a.example.", TypeBitMap: []uint16{dns.TypeA, dns.TypeNSEC, dns.TypeRRSIG}},
	}
	gap := &dns.NSEC{
		Hdr:  dns.Header{Name: "a.example.", Class: dns.ClassINET, TTL: 300},
		NSEC: rdata.NSEC{NextDomain: "z.example.", TypeBitMap: []uint16{dns.TypeNSEC, dns.TypeRRSIG}},
	}
	wildcard := &dns.NSEC{
		Hdr:  dns.Header{Name: "*.example.", Class: dns.ClassINET, TTL: 300},
		NSEC: rdata.NSEC{NextDomain: "x.example.", TypeBitMap: []uint16{dns.TypeA, dns.TypeNSEC, dns.TypeRRSIG}},
	}
	noCutExampleSig := root.sign([]dns.RR{noCutExample}, now)
	gapSig := root.sign([]dns.RR{gap}, now)
	wildcardSig := root.sign([]dns.RR{wildcard}, now)

	fetcher := dnssec.NewCachingFetcher(func(qname string, qtype uint16) (*dns.Msg, error) {
		switch {
		case qtype == dns.TypeDNSKEY && qname == ".":
			return testDNSMessage(dns.RcodeSuccess, []dns.RR{root.key, rootKeySig}, nil), nil
		case qtype == dns.TypeDS && qname == "example.":
			return testDNSMessage(dns.RcodeSuccess, nil, []dns.RR{noCutExample, noCutExampleSig}), nil
		case qtype == dns.TypeDS && qname == "x.example.":
			return testDNSMessage(dns.RcodeSuccess, nil, []dns.RR{gap, gapSig}), nil
		}
		return nil, fmt.Errorf("unexpected DNSSEC fetch %s/%d", qname, qtype)
	})
	plugin := &PluginDNSSECValidate{fetcher: fetcher, anchors: []*dns.DS{root.key.ToDS(dns.SHA256)}}
	msg := testDNSMessage(dns.RcodeSuccess, nil, []dns.RR{gap, gapSig, wildcard, wildcardSig})
	msg.Question = []dns.RR{&dns.AAAA{Hdr: dns.Header{Name: "x.example.", Class: dns.ClassINET}}}

	result, why := plugin.judge(msg, "x.example.")
	if result != dnssec.Secure {
		t.Fatalf("judge() = %v (%v), want secure wildcard NODATA", result, why)
	}
}

// A wildcard RRset can be cryptographically genuine while the NSEC3 proof
// that made it applicable crosses an Opt-Out span. RFC 5155 section 9.2 says
// that response is usable but MUST NOT carry AD: the span may hide an unsigned
// delegation closer to QNAME than the wildcard.
func TestValidatorTreatsNSEC3OptOutWildcardAnswerAsInsecure(t *testing.T) {
	now := time.Now()
	root := newValidatorTestZone(t, ".")
	zone := newValidatorTestZone(t, "example.")
	rootKeySig := root.sign([]dns.RR{root.key}, now)
	ds := zone.key.ToDS(dns.SHA256)
	dsSig := root.sign([]dns.RR{ds}, now)
	zoneKeySig := zone.sign([]dns.RR{zone.key}, now)

	// Give the chain walk separate, non-Opt-Out proof that QNAME is not a zone
	// cut. The response itself then exercises only the wildcard applicability
	// rule, rather than being classified insecure before its RRset is checked.
	notACut := &dns.NSEC{
		Hdr:  dns.Header{Name: "a.example.", Class: dns.ClassINET, TTL: 300},
		NSEC: rdata.NSEC{NextDomain: "z.example.", TypeBitMap: []uint16{dns.TypeNSEC, dns.TypeRRSIG}},
	}
	notACutSig := zone.sign([]dns.RR{notACut}, now)

	const qname = "anything.example."
	qhash := dnssec.NSEC3Hash(qname, 1, 0, "-")
	before := adjacentValidatorNSEC3Hash(t, qhash, -1)
	after := adjacentValidatorNSEC3Hash(t, qhash, 1)
	proof := &dns.NSEC3{
		Hdr: dns.Header{Name: before + ".example.", Class: dns.ClassINET, TTL: 300},
		NSEC3: rdata.NSEC3{
			Hash: 1, Flags: 1, Iterations: 0, Salt: "-", NextDomain: after,
			TypeBitMap: []uint16{dns.TypeRRSIG, dns.TypeNSEC3},
		},
	}
	proofSig := zone.sign([]dns.RR{proof}, now)

	fetcher := dnssec.NewCachingFetcher(func(name string, qtype uint16) (*dns.Msg, error) {
		switch {
		case qtype == dns.TypeDNSKEY && name == ".":
			return testDNSMessage(dns.RcodeSuccess, []dns.RR{root.key, rootKeySig}, nil), nil
		case qtype == dns.TypeDS && name == "example.":
			return testDNSMessage(dns.RcodeSuccess, []dns.RR{ds, dsSig}, nil), nil
		case qtype == dns.TypeDNSKEY && name == "example.":
			return testDNSMessage(dns.RcodeSuccess, []dns.RR{zone.key, zoneKeySig}, nil), nil
		case qtype == dns.TypeDS && name == qname:
			return testDNSMessage(dns.RcodeSuccess, nil, []dns.RR{notACut, notACutSig}), nil
		}
		return nil, fmt.Errorf("unexpected DNSSEC fetch %s/%d", name, qtype)
	})
	plugin := &PluginDNSSECValidate{fetcher: fetcher, anchors: []*dns.DS{root.key.ToDS(dns.SHA256)}}

	wildcard := &dns.A{
		Hdr: dns.Header{Name: "*.example.", Class: dns.ClassINET, TTL: 300},
		A:   rdata.A{Addr: netip.MustParseAddr("192.0.2.1")},
	}
	wildcardSig := zone.sign([]dns.RR{wildcard}, now)
	expanded := &dns.A{
		Hdr: dns.Header{Name: qname, Class: dns.ClassINET, TTL: 300},
		A:   wildcard.A,
	}
	wildcardSig.Hdr.Name = qname
	msg := testDNSMessage(dns.RcodeSuccess, []dns.RR{expanded, wildcardSig}, []dns.RR{proof, proofSig})
	msg.Question = []dns.RR{&dns.A{Hdr: dns.Header{Name: qname, Class: dns.ClassINET}}}

	result, why := plugin.judge(msg, qname)
	if result != dnssec.Insecure {
		t.Fatalf("Opt-Out wildcard answer = %v (%v), want insecure", result, why)
	}
	if why == nil || !strings.Contains(why.Error(), "Opt-Out") {
		t.Fatalf("Opt-Out wildcard reason = %v, want attributable reason", why)
	}
}

// A negative answer is signed by the zone that supplied the NSEC proof, not by
// every textual ancestor of the queried name.  This is the shape used by the
// signed tor.dan.me.uk. zones: several address labels below the actual zone
// are ordinary nonexistent names, not zone cuts.  RFC 4035 sections 5.3.1 and
// 5.4 require validating that zone's chain and its authenticated denial;
// probing for DS at the fabricated intermediate labels instead leaves a valid
// NXDOMAIN indeterminate.
func TestValidatorAcceptsDeepNegativeAnswerSignedByEnclosingZone(t *testing.T) {
	now := time.Now()
	root := newValidatorTestZone(t, ".")
	zone := newValidatorTestZone(t, "example.")
	rootKeySig := root.sign([]dns.RR{root.key}, now)
	ds := zone.key.ToDS(dns.SHA256)
	dsSig := root.sign([]dns.RR{ds}, now)
	zoneKeySig := zone.sign([]dns.RR{zone.key}, now)

	// The first NSEC covers four.three.two.one.example.; the second denies
	// the wildcard at the closest encloser, example.
	nameCover := &dns.NSEC{
		Hdr:  dns.Header{Name: "a.example.", Class: dns.ClassINET, TTL: 300},
		NSEC: rdata.NSEC{NextDomain: "z.example.", TypeBitMap: []uint16{dns.TypeNSEC, dns.TypeRRSIG}},
	}
	wildcardCover := &dns.NSEC{
		Hdr:  dns.Header{Name: "example.", Class: dns.ClassINET, TTL: 300},
		NSEC: rdata.NSEC{NextDomain: "a.example.", TypeBitMap: []uint16{dns.TypeSOA, dns.TypeNSEC, dns.TypeRRSIG}},
	}
	nameCoverSig := zone.sign([]dns.RR{nameCover}, now)
	wildcardCoverSig := zone.sign([]dns.RR{wildcardCover}, now)

	fetcher := dnssec.NewCachingFetcher(func(qname string, qtype uint16) (*dns.Msg, error) {
		switch {
		case qtype == dns.TypeDNSKEY && qname == ".":
			return testDNSMessage(dns.RcodeSuccess, []dns.RR{root.key, rootKeySig}, nil), nil
		case qtype == dns.TypeDS && qname == "example.":
			return testDNSMessage(dns.RcodeSuccess, []dns.RR{ds, dsSig}, nil), nil
		case qtype == dns.TypeDNSKEY && qname == "example.":
			return testDNSMessage(dns.RcodeSuccess, []dns.RR{zone.key, zoneKeySig}, nil), nil
		}
		return nil, fmt.Errorf("unexpected DNSSEC fetch %s/%d", qname, qtype)
	})
	plugin := &PluginDNSSECValidate{fetcher: fetcher, anchors: []*dns.DS{root.key.ToDS(dns.SHA256)}}
	msg := testDNSMessage(dns.RcodeNameError, nil, []dns.RR{nameCover, nameCoverSig, wildcardCover, wildcardCoverSig})
	msg.Question = []dns.RR{&dns.A{Hdr: dns.Header{Name: "four.three.two.one.example.", Class: dns.ClassINET}}}

	result, why := plugin.judge(msg, "four.three.two.one.example")
	if result != dnssec.Secure {
		t.Fatalf("judge() = %v (%v), want secure deep signed NXDOMAIN", result, why)
	}
}

// This is the proof shape returned by .com for an unregistered second-level
// name: the next-closer NSEC3 span has Opt-Out set. All RRsets are genuinely
// signed, but RFC 5155 section 9.2 says the response MUST NOT carry AD because
// that span may hide an unsigned delegation.
func TestValidatorTreatsNSEC3OptOutNameErrorAsInsecure(t *testing.T) {
	now := time.Now()
	root := newValidatorTestZone(t, ".")
	zone := newValidatorTestZone(t, "com.")
	rootKeySig := root.sign([]dns.RR{root.key}, now)
	ds := zone.key.ToDS(dns.SHA256)
	dsSig := root.sign([]dns.RR{ds}, now)
	zoneKeySig := zone.sign([]dns.RR{zone.key}, now)

	makeNSEC3 := func(owner, next string, types ...uint16) *dns.NSEC3 {
		return &dns.NSEC3{
			Hdr: dns.Header{Name: owner + ".com.", Class: dns.ClassINET, TTL: 300},
			NSEC3: rdata.NSEC3{
				Hash: 1, Flags: 1, Iterations: 0, Salt: "-", NextDomain: next, TypeBitMap: types,
			},
		}
	}
	proofs := []*dns.NSEC3{
		makeNSEC3("3RL2Q58205687C8I9KC9MV46DGHCNS45", "3RL2VRNHRTNQP2ACB7JK3K0OGV4ST3U3", dns.TypeNS, dns.TypeDS, dns.TypeRRSIG),
		makeNSEC3("CK0POJMG874LJREF7EFN8430QVIT8BSM", "CK0Q35HRS4H76G6CHNB9414CJN6S5UPL", dns.TypeNS, dns.TypeSOA, dns.TypeRRSIG, dns.TypeDNSKEY, dns.TypeNSEC3PARAM),
		makeNSEC3("I21IF42A9NB7V5OK4VRNLQLNMGHL4BVV", "I21IRK5DOD1MUK8JOJKQNSQCGUANBO7N", dns.TypeNS, dns.TypeDS, dns.TypeRRSIG),
	}
	soa := &dns.SOA{
		Hdr: dns.Header{Name: "com.", Class: dns.ClassINET, TTL: 300},
		SOA: rdata.SOA{Ns: "a.gtld-servers.net.", Mbox: "nstld.verisign-grs.com."},
	}
	authority := []dns.RR{soa, zone.sign([]dns.RR{soa}, now)}
	for _, proof := range proofs {
		authority = append(authority, proof, zone.sign([]dns.RR{proof}, now))
	}

	fetcher := dnssec.NewCachingFetcher(func(qname string, qtype uint16) (*dns.Msg, error) {
		switch {
		case qtype == dns.TypeDNSKEY && qname == ".":
			return testDNSMessage(dns.RcodeSuccess, []dns.RR{root.key, rootKeySig}, nil), nil
		case qtype == dns.TypeDS && qname == "com.":
			return testDNSMessage(dns.RcodeSuccess, []dns.RR{ds, dsSig}, nil), nil
		case qtype == dns.TypeDNSKEY && qname == "com.":
			return testDNSMessage(dns.RcodeSuccess, []dns.RR{zone.key, zoneKeySig}, nil), nil
		}
		return nil, fmt.Errorf("unexpected DNSSEC fetch %s/%d", qname, qtype)
	})
	plugin := &PluginDNSSECValidate{fetcher: fetcher, anchors: []*dns.DS{root.key.ToDS(dns.SHA256)}}
	const qname = "no-such-name-20260907.com."
	msg := testDNSMessage(dns.RcodeNameError, nil, authority)
	msg.Question = []dns.RR{&dns.A{Hdr: dns.Header{Name: qname, Class: dns.ClassINET}}}

	result, why := plugin.judge(msg, qname)
	if result != dnssec.Insecure {
		t.Fatalf("Opt-Out NXDOMAIN = %v (%v), want insecure", result, why)
	}
	if why == nil || !strings.Contains(why.Error(), "Opt-Out") {
		t.Fatalf("Opt-Out NXDOMAIN reason = %v, want attributable reason", why)
	}
}

// DS is the exception to the rule that a delegation NSEC cannot deny data at
// a child zone cut. RFC 4035 section 5.2 requires the parent's NSEC for this
// decision, and RFC 6840 sections 4.1 and 4.4 identify the exact bitmap:
// parent-side NS present, with SOA and DS absent. The child's equally genuine
// apex NSEC says nothing about whether the parent publishes a DS and must not
// be accepted as a downgrade.
func TestValidatorUsesOnlyParentSideDenialForDSNoData(t *testing.T) {
	now := time.Now()
	root := newValidatorTestZone(t, ".")
	zone := newValidatorTestZone(t, "example.")
	rootKeySig := root.sign([]dns.RR{root.key}, now)
	ds := zone.key.ToDS(dns.SHA256)
	dsSig := root.sign([]dns.RR{ds}, now)
	zoneKeySig := zone.sign([]dns.RR{zone.key}, now)

	fetcher := dnssec.NewCachingFetcher(func(qname string, qtype uint16) (*dns.Msg, error) {
		switch {
		case qtype == dns.TypeDNSKEY && qname == ".":
			return testDNSMessage(dns.RcodeSuccess, []dns.RR{root.key, rootKeySig}, nil), nil
		case qtype == dns.TypeDS && qname == "example.":
			return testDNSMessage(dns.RcodeSuccess, []dns.RR{ds, dsSig}, nil), nil
		case qtype == dns.TypeDNSKEY && qname == "example.":
			return testDNSMessage(dns.RcodeSuccess, []dns.RR{zone.key, zoneKeySig}, nil), nil
		}
		return nil, fmt.Errorf("unexpected DNSSEC fetch %s/%d", qname, qtype)
	})
	plugin := &PluginDNSSECValidate{fetcher: fetcher, anchors: []*dns.DS{root.key.ToDS(dns.SHA256)}}

	parentNSEC := &dns.NSEC{
		Hdr:  dns.Header{Name: "child.example.", Class: dns.ClassINET, TTL: 300},
		NSEC: rdata.NSEC{NextDomain: "d.example.", TypeBitMap: []uint16{dns.TypeNS, dns.TypeRRSIG, dns.TypeNSEC}},
	}
	parentSig := zone.sign([]dns.RR{parentNSEC}, now)
	parentMsg := testDNSMessage(dns.RcodeSuccess, nil, []dns.RR{parentNSEC, parentSig})
	parentMsg.Question = []dns.RR{&dns.DS{Hdr: dns.Header{Name: "child.example.", Class: dns.ClassINET}}}
	if result, why := plugin.judge(parentMsg, "child.example."); result != dnssec.Secure {
		t.Fatalf("parent-side DS denial = %v (%v), want secure", result, why)
	}

	childNSEC := &dns.NSEC{
		Hdr: dns.Header{Name: "example.", Class: dns.ClassINET, TTL: 300},
		NSEC: rdata.NSEC{NextDomain: "a.example.", TypeBitMap: []uint16{
			dns.TypeNS, dns.TypeSOA, dns.TypeRRSIG, dns.TypeNSEC, dns.TypeDNSKEY,
		}},
	}
	childSig := zone.sign([]dns.RR{childNSEC}, now)
	childMsg := testDNSMessage(dns.RcodeSuccess, nil, []dns.RR{childNSEC, childSig})
	childMsg.Question = []dns.RR{&dns.DS{Hdr: dns.Header{Name: "example.", Class: dns.ClassINET}}}
	result, why := plugin.judge(childMsg, "example.")
	if result != dnssec.Bogus || !errors.Is(why, errDNSSECIncompleteEvidence) {
		t.Fatalf("child-side DS denial = %v (%v), want retryable bogus", result, why)
	}
}

// RFC 5155 section 8.9 permits an Opt-Out span to prove the absence of DS for
// an unsigned delegation, but section 9.2 forbids AD on a response that relies
// on that span. This must be Insecure, not Bogus and not Secure.
func TestValidatorTreatsNSEC3OptOutDSDenialAsInsecure(t *testing.T) {
	now := time.Now()
	root := newValidatorTestZone(t, ".")
	parent := newValidatorTestZone(t, "example.")
	rootKeySig := root.sign([]dns.RR{root.key}, now)
	ds := parent.key.ToDS(dns.SHA256)
	dsSig := root.sign([]dns.RR{ds}, now)
	parentKeySig := parent.sign([]dns.RR{parent.key}, now)

	const qname = "child.example."
	qhash := dnssec.NSEC3Hash(qname, 1, 0, "-")
	before := adjacentValidatorNSEC3Hash(t, qhash, -1)
	after := adjacentValidatorNSEC3Hash(t, qhash, 1)
	proof := &dns.NSEC3{
		Hdr: dns.Header{Name: before + ".example.", Class: dns.ClassINET, TTL: 300},
		NSEC3: rdata.NSEC3{
			Hash: 1, Flags: 1, Iterations: 0, Salt: "-", NextDomain: after,
			TypeBitMap: []uint16{dns.TypeNS, dns.TypeRRSIG, dns.TypeNSEC3},
		},
	}
	proofSig := parent.sign([]dns.RR{proof}, now)
	closestHash := dnssec.NSEC3Hash(parent.name, 1, 0, "-")
	closest := &dns.NSEC3{
		Hdr: dns.Header{Name: closestHash + ".example.", Class: dns.ClassINET, TTL: 300},
		NSEC3: rdata.NSEC3{
			Hash: 1, Flags: 1, Iterations: 0, Salt: "-",
			NextDomain: adjacentValidatorNSEC3Hash(t, closestHash, 1),
			TypeBitMap: []uint16{
				dns.TypeNS, dns.TypeSOA, dns.TypeRRSIG, dns.TypeDNSKEY, dns.TypeNSEC3PARAM,
			},
		},
	}
	closestSig := parent.sign([]dns.RR{closest}, now)
	soa := &dns.SOA{
		Hdr: dns.Header{Name: "example.", Class: dns.ClassINET, TTL: 300},
		SOA: rdata.SOA{Ns: "ns.example.", Mbox: "hostmaster.example."},
	}
	soaSig := parent.sign([]dns.RR{soa}, now)

	fetcher := dnssec.NewCachingFetcher(func(name string, qtype uint16) (*dns.Msg, error) {
		switch {
		case qtype == dns.TypeDNSKEY && name == ".":
			return testDNSMessage(dns.RcodeSuccess, []dns.RR{root.key, rootKeySig}, nil), nil
		case qtype == dns.TypeDS && name == "example.":
			return testDNSMessage(dns.RcodeSuccess, []dns.RR{ds, dsSig}, nil), nil
		case qtype == dns.TypeDNSKEY && name == "example.":
			return testDNSMessage(dns.RcodeSuccess, []dns.RR{parent.key, parentKeySig}, nil), nil
		}
		return nil, fmt.Errorf("unexpected DNSSEC fetch %s/%d", name, qtype)
	})
	plugin := &PluginDNSSECValidate{fetcher: fetcher, anchors: []*dns.DS{root.key.ToDS(dns.SHA256)}}
	msg := testDNSMessage(dns.RcodeSuccess, nil, []dns.RR{soa, soaSig, closest, closestSig, proof, proofSig})
	msg.Question = []dns.RR{&dns.DS{Hdr: dns.Header{Name: qname, Class: dns.ClassINET}}}

	result, why := plugin.judge(msg, qname)
	if result != dnssec.Insecure {
		t.Fatalf("Opt-Out DS denial = %v (%v), want insecure", result, why)
	}
	if why == nil || !strings.Contains(why.Error(), "Opt-Out") {
		t.Fatalf("Opt-Out DS-denial reason = %v, want attributable reason", why)
	}
}

func adjacentValidatorNSEC3Hash(t *testing.T, hash string, direction int) string {
	t.Helper()
	const alphabet = "0123456789ABCDEFGHIJKLMNOPQRSTUV"
	if direction != -1 && direction != 1 {
		t.Fatalf("invalid NSEC3 hash direction %d", direction)
	}
	out := []byte(strings.ToUpper(hash))
	for i := len(out) - 1; i >= 0; i-- {
		digit := strings.IndexByte(alphabet, out[i])
		if digit < 0 {
			t.Fatalf("invalid base32hex digit %q in %q", out[i], hash)
		}
		next := digit + direction
		if 0 <= next && next < len(alphabet) {
			out[i] = alphabet[next]
			return string(out)
		}
		if direction > 0 {
			out[i] = alphabet[0]
		} else {
			out[i] = alphabet[len(alphabet)-1]
		}
	}
	t.Fatalf("cannot move %q one base32hex value in direction %d", hash, direction)
	return ""
}

// A CNAME is only an intermediate answer to an A query. RFC 4035 section
// 3.2.3 requires the final negative answer to be authenticated before AD can
// be set; accepting just the signed alias would make a stripped NODATA proof
// look secure.
func TestValidatorAuthenticatesNegativeCNAMEChainTerminals(t *testing.T) {
	now := time.Now()
	root := newValidatorTestZone(t, ".")
	rootKeySig := root.sign([]dns.RR{root.key}, now)
	aliasNoCut := &dns.NSEC{
		Hdr:  dns.Header{Name: "alias.", Class: dns.ClassINET, TTL: 300},
		NSEC: rdata.NSEC{NextDomain: "target.", TypeBitMap: []uint16{dns.TypeCNAME, dns.TypeNSEC, dns.TypeRRSIG}},
	}
	targetNoA := &dns.NSEC{
		Hdr:  dns.Header{Name: "target.", Class: dns.ClassINET, TTL: 300},
		NSEC: rdata.NSEC{NextDomain: "z.", TypeBitMap: []uint16{dns.TypeNSEC, dns.TypeRRSIG}},
	}
	aliasNoCutSig := root.sign([]dns.RR{aliasNoCut}, now)
	targetNoASig := root.sign([]dns.RR{targetNoA}, now)
	cname := &dns.CNAME{
		Hdr:   dns.Header{Name: "alias.", Class: dns.ClassINET, TTL: 300},
		CNAME: rdata.CNAME{Target: "target."},
	}
	cnameSig := root.sign([]dns.RR{cname}, now)
	unsignedSOA := &dns.SOA{Hdr: dns.Header{Name: ".", Class: dns.ClassINET, TTL: 300}}

	fetcher := dnssec.NewCachingFetcher(func(qname string, qtype uint16) (*dns.Msg, error) {
		switch {
		case qtype == dns.TypeDNSKEY && qname == ".":
			return testDNSMessage(dns.RcodeSuccess, []dns.RR{root.key, rootKeySig}, nil), nil
		case qtype == dns.TypeDS && qname == "alias.":
			return testDNSMessage(dns.RcodeSuccess, nil, []dns.RR{aliasNoCut, aliasNoCutSig}), nil
		case qtype == dns.TypeDS && qname == "target.":
			return testDNSMessage(dns.RcodeSuccess, nil, []dns.RR{targetNoA, targetNoASig}), nil
		}
		return nil, fmt.Errorf("unexpected DNSSEC fetch %s/%d", qname, qtype)
	})
	plugin := &PluginDNSSECValidate{fetcher: fetcher, anchors: []*dns.DS{root.key.ToDS(dns.SHA256)}}

	for _, tc := range []struct {
		name string
		ns   []dns.RR
		want dnssec.Result
	}{
		{"signed target NODATA", []dns.RR{targetNoA, targetNoASig}, dnssec.Secure},
		{"unsigned negative SOA", []dns.RR{targetNoA, targetNoASig, unsignedSOA}, dnssec.Bogus},
		{"missing target proof", []dns.RR{&dns.SOA{Hdr: dns.Header{Name: ".", Class: dns.ClassINET, TTL: 300}}}, dnssec.Bogus},
	} {
		t.Run(tc.name, func(t *testing.T) {
			msg := testDNSMessage(dns.RcodeSuccess, []dns.RR{cname, cnameSig}, tc.ns)
			msg.Question = []dns.RR{&dns.A{Hdr: dns.Header{Name: "alias.", Class: dns.ClassINET}}}
			result, why := plugin.judge(msg, "alias.")
			if result != tc.want {
				t.Fatalf("judge() = %v (%v), want %v", result, why, tc.want)
			}
		})
	}
}

func testDNSMessage(rcode uint16, answer, ns []dns.RR) *dns.Msg {
	msg := &dns.Msg{Answer: answer, Ns: ns}
	msg.Rcode = rcode
	return msg
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
	if !msg.Security {
		t.Error("the client DO bit was not copied to the response")
	}
}

// RFC 4035 section 3.2.1: DO=0 suppresses auxiliary authentication records,
// but never a DNSSEC RR type the initiating query explicitly requested.
func TestAClientKeepsAnExplicitlyRequestedDNSSECTypeWithoutDO(t *testing.T) {
	const name = "example.test."
	records := []dns.RR{
		&dns.DS{Hdr: dns.Header{Name: name, Class: dns.ClassINET}},
		&dns.DNSKEY{Hdr: dns.Header{Name: name, Class: dns.ClassINET}},
		&dns.NSEC{Hdr: dns.Header{Name: name, Class: dns.ClassINET}},
		&dns.NSEC3{Hdr: dns.Header{Name: "hash." + name, Class: dns.ClassINET}},
		&dns.RRSIG{Hdr: dns.Header{Name: name, Class: dns.ClassINET}},
	}
	for _, requested := range []uint16{
		dns.TypeDS,
		dns.TypeDNSKEY,
		dns.TypeNSEC,
		dns.TypeNSEC3,
		dns.TypeRRSIG,
	} {
		t.Run(dns.TypeToString[requested], func(t *testing.T) {
			question := dns.NewMsg(name, requested)
			msg := dns.NewMsg(name, requested)
			msg.Answer = append([]dns.RR(nil), records...)
			msg.AuthenticatedData = true
			state := PluginsState{
				questionMsg: question,
				sessionData: map[string]any{
					dnssecClientWantedKey: false,
				},
			}

			stripDNSSECForClient(&state, msg)

			if len(msg.Answer) != 1 || dns.RRToType(msg.Answer[0]) != requested {
				t.Fatalf("answer after DO=0 stripping = %v, want only explicitly requested %s",
					msg.Answer, dns.TypeToString[requested])
			}
			if msg.AuthenticatedData {
				t.Fatal("AD survived for a client that requested neither DO nor AD")
			}
		})
	}
}

// RFC 5155 section 4 says that NSEC3PARAM is apex zone data and is not used
// by validators or resolvers.  It therefore is not an auxiliary
// authentication RR to remove under RFC 4035 section 3.2.1.
func TestAClientKeepsNSEC3PARAMWithoutDO(t *testing.T) {
	const name = "example.test."
	msg := dns.NewMsg(name, dns.TypeA)
	msg.Answer = []dns.RR{
		&dns.NSEC3PARAM{Hdr: dns.Header{Name: name, Class: dns.ClassINET}},
		&dns.NSEC3{Hdr: dns.Header{Name: "hash." + name, Class: dns.ClassINET}},
	}
	state := PluginsState{
		questionMsg: dns.NewMsg(name, dns.TypeA),
		sessionData: map[string]any{
			dnssecClientWantedKey: false,
		},
	}

	stripDNSSECForClient(&state, msg)

	if len(msg.Answer) != 1 || dns.RRToType(msg.Answer[0]) != dns.TypeNSEC3PARAM {
		t.Fatalf("answer after DO=0 stripping = %v, want only NSEC3PARAM", msg.Answer)
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

func TestDNSSECStripRestoresTheClientCDBit(t *testing.T) {
	state := PluginsState{sessionData: map[string]any{
		dnssecClientCheckingDisabledKey: false,
		dnssecClientWantedKey:           false,
	}}
	msg := answerWithSignature(t)
	msg.CheckingDisabled = true // CD set on the upstream validation query.
	msg.Security = true         // DO set on the upstream validation query.

	stripDNSSECForClient(&state, msg)

	if msg.CheckingDisabled {
		t.Error("the internally-set upstream CD bit leaked to the client response")
	}
	if msg.Security {
		t.Error("the internally-set upstream DO bit leaked to the client response")
	}
}

func TestDNSSECFailureRestoresTheClientDOAndCDBits(t *testing.T) {
	state := PluginsState{sessionData: map[string]any{
		dnssecClientCheckingDisabledKey: false,
		dnssecClientWantedKey:           false,
	}}
	upstreamQuery := dns.NewMsg("example.test.", dns.TypeA)
	upstreamQuery.Security = true
	upstreamQuery.CheckingDisabled = true

	failure := DNSSECFailureResponseFromMessage(upstreamQuery, dns.ExtendedErrorDNSBogus)
	restoreDNSSECClientBits(&state, failure)
	if failure.Security || failure.CheckingDisabled {
		t.Fatalf("SERVFAIL leaked upstream bits: DO=%v CD=%v", failure.Security, failure.CheckingDisabled)
	}
}

func TestSynthesizedResponsesRestoreTheClientDOAndCDBits(t *testing.T) {
	state := PluginsState{
		questionMsg: dns.NewMsg("example.test.", dns.TypeA),
		sessionData: map[string]any{
			dnssecClientCheckingDisabledKey: false,
			dnssecClientWantedKey:           false,
		},
	}
	state.questionMsg.Security = true
	state.questionMsg.CheckingDisabled = true
	synth := EmptyResponseFromMessage(state.questionMsg)

	packet, err := handleSynthesizedResponse(&state, synth)
	if err != nil {
		t.Fatal(err)
	}
	response := &dns.Msg{Data: packet}
	if err := response.Unpack(); err != nil {
		t.Fatal(err)
	}
	if response.Security || response.CheckingDisabled {
		t.Fatalf("synthesized response leaked upstream bits: DO=%v CD=%v", response.Security, response.CheckingDisabled)
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

// Chain material is queried through the regular proxy path, but it is not a
// client query and carries no DNSSEC verdict of its own. It must not therefore
// distort the dashboard's query, domain, or unchecked-verdict figures.
func TestTheValidatorsOwnFetchesAreNotRecordedByMonitoring(t *testing.T) {
	ui := newTestMonitoringUI(t)
	defer func() { _ = ui.Stop() }()
	ui.config.EnableQueryLog = true

	state := PluginsState{
		clientProto: dnssecInternalProto,
		qName:       "key.example.",
		serverName:  "test-server",
		returnCode:  PluginsReturnCodePass,
		sessionData: map[string]any{},
	}
	msg := dns.NewMsg("key.example.", dns.TypeDNSKEY)
	if msg == nil {
		t.Fatal("cannot build DNSKEY query")
	}

	ui.UpdateMetrics(&state, msg)
	ui.Flush()

	metrics := ui.metricsCollector.GetMetrics()
	if total, _ := metrics["total_queries"].(uint64); total != 0 {
		t.Errorf("internal DNSSEC fetches recorded as %d client queries, want 0", total)
	}
	if recent, _ := metrics["recent_queries"].([]QueryLogEntry); len(recent) != 0 {
		t.Errorf("internal DNSSEC fetches leaked into recent queries: %#v", recent)
	}
	if domains, _ := metrics["top_domains"].([]map[string]any); len(domains) != 0 {
		t.Errorf("internal DNSSEC fetches leaked into top domains: %#v", domains)
	}
}

// The verdict has to reach whatever reports on the query. On the wire there is
// room for it as one bit; someone looking at a dashboard to find out why a name
// will not resolve needs the sentence that goes with it.
func TestTheVerdictAndItsReasonReachTheQueryLog(t *testing.T) {
	ui := newTestMonitoringUI(t)
	defer func() { _ = ui.Stop() }()
	ui.config.EnableQueryLog = true

	state := PluginsState{
		qName:      "example.test.",
		serverName: "test-server",
		returnCode: PluginsReturnCodePass,
		sessionData: map[string]any{
			dnssecVerdictKey: "bogus",
			dnssecReasonKey:  "example.test. is signed, but this answer is not",
		},
	}
	msg := dns.NewMsg("example.test.", dns.TypeA)
	if msg == nil {
		t.Fatal("cannot build a message")
	}

	ui.UpdateMetrics(&state, msg)
	ui.Flush()

	metrics := ui.metricsCollector.GetMetrics()
	recent, _ := metrics["recent_queries"].([]QueryLogEntry)
	if len(recent) == 0 {
		t.Fatal("the query was not recorded at all")
	}
	last := recent[len(recent)-1]
	if last.DNSSECVerdict != "bogus" {
		t.Errorf("verdict = %q, want bogus", last.DNSSECVerdict)
	}
	if last.DNSSECReason == "" {
		t.Error("the reason was dropped, so the page can only say that something failed")
	}
}

// The summary the page draws from must separate the four, since three of them
// mean entirely different things about who is at fault.
func TestTheMetricsCarryEachVerdictSeparately(t *testing.T) {
	ui := newTestMonitoringUI(t)
	defer func() { _ = ui.Stop() }()

	summary, ok := ui.metricsCollector.GetMetrics()["dnssec"].(map[string]any)
	if !ok {
		t.Fatal("the page has no DNSSEC figures to draw")
	}
	for _, key := range []string{"secure", "bogus", "insecure", "indeterminate", "mode"} {
		if _, present := summary[key]; !present {
			t.Errorf("%q is missing from the summary", key)
		}
	}
}
