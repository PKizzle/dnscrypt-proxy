package main

import (
	"crypto"
	"errors"
	"fmt"
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
	t.Helper()
	key := dns.NewDNSKEY(name, dns.ECDSAP256SHA256)
	key.Flags = dns.FlagZONE
	key.Protocol = 3
	priv, err := key.Generate(256)
	if err != nil {
		t.Fatalf("generate DNSKEY for %s: %v", name, err)
	}
	signer, ok := priv.(crypto.Signer)
	if !ok {
		t.Fatalf("generated DNSKEY for %s is not a signer", name)
	}
	return &validatorTestZone{t: t, name: name, key: key, priv: signer}
}

func (z *validatorTestZone) sign(rrset []dns.RR, now time.Time) *dns.RRSIG {
	z.t.Helper()
	sig := dns.NewRRSIG(z.name, z.key.Algorithm, z.key.KeyTag(), uint32(now.Add(-time.Hour).Unix()), uint32(now.Add(time.Hour).Unix()))
	if err := sig.Sign(z.priv, rrset, &dns.SignOption{}); err != nil {
		z.t.Fatalf("sign RRset for %s: %v", z.name, err)
	}
	return sig
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
	if retryableDNSSECFailure(dnssec.Bogus, errors.New("invalid signature")) {
		t.Fatal("a cryptographic failure must not be retried")
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
