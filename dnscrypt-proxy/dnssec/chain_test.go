package dnssec

import (
	"fmt"
	"testing"
	"time"

	"codeberg.org/miekg/dns"
	"codeberg.org/miekg/dns/rdata"
)

// hierarchy is a signed tree built for a test: each zone has a key, each child
// is delegated by a DS its parent signs. Walking it exercises the same steps a
// walk over the real root does, without a network.
type hierarchy struct {
	t     *testing.T
	zones map[string]*zone
	// unsigned zones exist but their parent publishes no DS for them.
	unsigned map[string]bool
	// broken zones have a DS whose signature does not verify.
	brokenDS map[string]bool
	now      time.Time
	// Names that are not zone cuts at all: the parent publishes no DS because
	// there is nothing delegated there.
	notACut map[string]bool
	// Names whose parent offers a denial that settles nothing either way.
	unproven map[string]bool
}

// tamperedHierarchy removes the RRSIG from one denial. It models an upstream
// that sends a plausible NSEC but not the signed proof the chain requires.
type tamperedHierarchy struct {
	*hierarchy
	unsignedProof string
}

func (h tamperedHierarchy) DS(zoneName string) ([]*dns.DS, []*dns.RRSIG, Denial, error) {
	dss, sigs, denial, err := h.hierarchy.DS(zoneName)
	if zoneName == h.unsignedProof {
		denial.sigs = nil
	}
	return dss, sigs, denial, err
}

// flakyDelegationHierarchy returns one invalid signed DS response, then the
// real parent-signed one. It models a single inconsistent recursive upstream
// in a pool; the validator must re-fetch rather than retain that response as
// the fate of the whole child zone.
type flakyDelegationHierarchy struct {
	*hierarchy
	zone  string
	calls int
}

// flakyRootHierarchy supplies one root key set whose signature does not match
// the configured anchor, then the valid root response. It represents one
// inconsistent upstream in a recursive pool; an invalid reply must be evicted
// and retried, never accepted.
type flakyRootHierarchy struct {
	*hierarchy
	calls int
}

func (h *flakyRootHierarchy) DNSKEY(zoneName string) ([]*dns.DNSKEY, []*dns.RRSIG, error) {
	if canonicalName(zoneName) != "." {
		return h.hierarchy.DNSKEY(zoneName)
	}
	h.calls++
	if h.calls != 1 {
		return h.hierarchy.DNSKEY(zoneName)
	}
	root := h.zones["."]
	stranger := h.zones["test."]
	return []*dns.DNSKEY{root.key}, []*dns.RRSIG{stranger.sign([]dns.RR{root.key}, h.now.Add(-time.Hour), h.now.Add(time.Hour))}, nil
}

// cnameDelegationHierarchy models a DS query that is answered by a CNAME in
// the signed parent zone. This is what real recursive resolvers return for a
// CNAME-bearing Microsoft service name: it is positive evidence that the
// queried name is not a delegation, but only after the parent signature is
// checked.
type cnameDelegationHierarchy struct {
	*hierarchy
	name   string
	signed bool
}

// absentAncestorHierarchy returns a complete signed NSEC3 name-error proof
// for one label, then fails if the chain asks about a descendant. A complete
// name-error means that descendant cannot be a zone cut: if it had a child,
// the supposedly absent label would be an existing empty non-terminal.
type absentAncestorHierarchy struct {
	*hierarchy
	absent          string
	descendantCalls int
}

func (h *absentAncestorHierarchy) DS(zoneName string) ([]*dns.DS, []*dns.RRSIG, Denial, error) {
	if canonicalName(zoneName) == canonicalName(h.absent) {
		parentName := h.parentOf(zoneName)
		parent := h.zones[parentName]
		if parent == nil {
			return nil, nil, Denial{}, fmt.Errorf("no parent for %s", zoneName)
		}

		// RFC 5155 sections 8.3 and 8.4: the exact closest encloser,
		// plus one NSEC3 span covering both next-closer and wildcard.
		// The synthetic span is intentionally non-opt-out: it proves the
		// absent names rather than concealing an unsigned delegation.
		closest := NSEC3Hash(parentName, 1, 0, "-")
		ce := nsec3(closest, "VVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVV", 0, dns.TypeNS, dns.TypeSOA, dns.TypeRRSIG, dns.TypeNSEC3)
		cover := nsec3("00000000000000000000000000000000", "VVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVV", 0, dns.TypeRRSIG, dns.TypeNSEC3)
		return nil, nil, Denial{
			NSEC3: []*dns.NSEC3{ce, cover},
			sigs: []*dns.RRSIG{
				parent.sign([]dns.RR{ce}, h.now.Add(-time.Hour), h.now.Add(time.Hour)),
				parent.sign([]dns.RR{cover}, h.now.Add(-time.Hour), h.now.Add(time.Hour)),
			},
		}, nil
	}
	if WithinZone(zoneName, h.absent) {
		h.descendantCalls++
		return nil, nil, Denial{}, fmt.Errorf("unexpected DS lookup below proven-absent %s: %s", h.absent, zoneName)
	}
	return h.hierarchy.DS(zoneName)
}

func (h *cnameDelegationHierarchy) DS(zoneName string) ([]*dns.DS, []*dns.RRSIG, Denial, error) {
	if zoneName != h.name {
		return h.hierarchy.DS(zoneName)
	}
	parentName := h.parentOf(zoneName)
	parent := h.zones[parentName]
	if parent == nil {
		return nil, nil, Denial{}, fmt.Errorf("no parent for CNAME %s", zoneName)
	}
	cname := &dns.CNAME{
		Hdr:   dns.Header{Name: zoneName, Class: dns.ClassINET, TTL: 300},
		CNAME: rdata.CNAME{Target: "target."},
	}
	evidence := Denial{cnames: []*dns.CNAME{cname}}
	if h.signed {
		evidence.cnameSigs = []*dns.RRSIG{parent.sign([]dns.RR{cname}, h.now.Add(-time.Hour), h.now.Add(time.Hour))}
	}
	return nil, nil, evidence, nil
}

func (h *flakyDelegationHierarchy) DS(zoneName string) ([]*dns.DS, []*dns.RRSIG, Denial, error) {
	if zoneName != h.zone {
		return h.hierarchy.DS(zoneName)
	}
	h.calls++
	if h.calls != 1 {
		return h.hierarchy.DS(zoneName)
	}
	h.brokenDS[zoneName] = true
	dss, sigs, denial, err := h.hierarchy.DS(zoneName)
	delete(h.brokenDS, zoneName)
	return dss, sigs, denial, err
}

func newHierarchy(t *testing.T, names ...string) *hierarchy {
	t.Helper()
	h := &hierarchy{
		t: t, zones: map[string]*zone{},
		unsigned: map[string]bool{}, brokenDS: map[string]bool{},
		notACut: map[string]bool{}, unproven: map[string]bool{},
		now: time.Now(),
	}
	for _, n := range names {
		h.zones[n] = newZone(t, n)
	}
	return h
}

func (h *hierarchy) parentOf(zoneName string) string {
	zones := AncestorZones(zoneName)
	if len(zones) < 2 {
		return ""
	}
	return zones[len(zones)-2]
}

func (h *hierarchy) DNSKEY(zoneName string) ([]*dns.DNSKEY, []*dns.RRSIG, error) {
	z, ok := h.zones[zoneName]
	if !ok {
		return nil, nil, fmt.Errorf("no such zone %s", zoneName)
	}
	keys := []*dns.DNSKEY{z.key}
	sig := z.sign([]dns.RR{z.key}, h.now.Add(-time.Hour), h.now.Add(time.Hour))
	return keys, []*dns.RRSIG{sig}, nil
}

// nsecProving builds the signed denial a parent offers in place of a DS: the
// types present at that name decide whether there is a delegation there at all.
func (h *hierarchy) nsecProving(name string, types ...uint16) Denial {
	rr := &dns.NSEC{
		Hdr:  dns.Header{Name: name, Class: dns.ClassINET, TTL: 300},
		NSEC: rdata.NSEC{NextDomain: "\\000." + name, TypeBitMap: types},
	}
	ancestors := AncestorZones(name)
	for i := len(ancestors) - 2; i >= 0; i-- {
		if parent := h.zones[ancestors[i]]; parent != nil {
			sig := parent.sign([]dns.RR{rr}, h.now.Add(-time.Hour), h.now.Add(time.Hour))
			return Denial{NSEC: []*dns.NSEC{rr}, sigs: []*dns.RRSIG{sig}}
		}
	}
	h.t.Fatalf("no parent zone available to sign denial for %s", name)
	return Denial{}
}

func (h *hierarchy) DS(zoneName string) ([]*dns.DS, []*dns.RRSIG, Denial, error) {
	if h.unproven[zoneName] {
		// Something came back, but nothing that settles whether anything is
		// delegated here -- an opt-out span, or a proof about another name.
		return nil, nil, h.nsecProving("other."+zoneName, dns.TypeA), nil
	}
	if h.notACut[zoneName] {
		// A name inside its parent: records, but nothing delegated.
		return nil, nil, h.nsecProving(zoneName, dns.TypeA, dns.TypeRRSIG, dns.TypeNSEC), nil
	}
	if h.unsigned[zoneName] {
		// A real delegation the parent does not sign for.
		return nil, nil, h.nsecProving(zoneName, dns.TypeNS, dns.TypeRRSIG, dns.TypeNSEC), nil
	}
	z, ok := h.zones[zoneName]
	if !ok {
		return nil, nil, Denial{}, fmt.Errorf("no such zone %s", zoneName)
	}
	parent, ok := h.zones[h.parentOf(zoneName)]
	if !ok {
		return nil, nil, Denial{}, fmt.Errorf("no parent for %s", zoneName)
	}
	ds := z.key.ToDS(dns.SHA256)
	ds.Hdr.Name = zoneName
	signer := parent
	if h.brokenDS[zoneName] {
		// Signed by the child rather than the parent: a DS the delegating zone
		// never vouched for.
		signer = z
	}
	sig := signer.sign([]dns.RR{ds}, h.now.Add(-time.Hour), h.now.Add(time.Hour))
	return []*dns.DS{ds}, []*dns.RRSIG{sig}, Denial{}, nil
}

// anchors returns trust anchors for this hierarchy's root, standing in for the
// IANA ones.
func (h *hierarchy) anchors() []*dns.DS {
	return []*dns.DS{h.zones["."].key.ToDS(dns.SHA256)}
}

func TestAncestorZones(t *testing.T) {
	for _, tc := range []struct {
		name string
		want []string
	}{
		{"www.example.com.", []string{".", "com.", "example.com.", "www.example.com."}},
		{"example.com", []string{".", "com.", "example.com."}},
		{"WWW.Example.COM.", []string{".", "com.", "example.com.", "www.example.com."}},
		{".", []string{"."}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := AncestorZones(tc.name)
			if len(got) != len(tc.want) {
				t.Fatalf("AncestorZones(%q) = %v, want %v", tc.name, got, tc.want)
			}
			for i := range got {
				if got[i] != tc.want[i] {
					t.Fatalf("AncestorZones(%q) = %v, want %v", tc.name, got, tc.want)
				}
			}
		})
	}
}

func TestBuildChainReachesASignedZone(t *testing.T) {
	h := newHierarchy(t, ".", "test.", "example.test.")
	res := BuildChain(h, "example.test.", h.anchors(), h.now)
	if res.Status != Secure {
		t.Fatalf("BuildChain() = %v (%v), want secure", res.Status, res.Why)
	}
	if res.Zone != "example.test." {
		t.Errorf("zone = %q, want example.test.", res.Zone)
	}
	if len(res.Keys) != 1 || res.Keys[0].KeyTag() != h.zones["example.test."].key.KeyTag() {
		t.Errorf("chain returned the wrong zone's keys")
	}
}

// A zone whose parent publishes no DS is unsigned, which is ordinary and not a
// failure -- but the walk must stop there rather than pretend to have keys.
func TestBuildChainStopsAtAnUnsignedDelegation(t *testing.T) {
	h := newHierarchy(t, ".", "test.", "example.test.")
	h.unsigned["example.test."] = true

	res := BuildChain(h, "example.test.", h.anchors(), h.now)
	if res.Status != Insecure {
		t.Fatalf("BuildChain() = %v (%v), want insecure", res.Status, res.Why)
	}
	if len(res.Keys) != 0 {
		t.Errorf("insecure chain returned %d keys, want none", len(res.Keys))
	}
	if res.Zone != "test." {
		t.Errorf("zone = %q, want the last signed zone test.", res.Zone)
	}
}

// A signed NXDOMAIN answer to a DS lookup proves that a label is not a zone
// cut; it is not an unsigned delegation. The chain must retain the parent's
// keys so it can authenticate the original negative response.
func TestBuildChainWalksPastASignedNameErrorForDS(t *testing.T) {
	root := newZone(t, ".")
	now := time.Now()
	proof := &dns.NSEC{
		Hdr:  dns.Header{Name: "a.", Class: dns.ClassINET, TTL: 300},
		NSEC: rdata.NSEC{NextDomain: "z.", TypeBitMap: []uint16{dns.TypeNSEC, dns.TypeRRSIG}},
	}
	proofSig := root.sign([]dns.RR{proof}, now.Add(-time.Hour), now.Add(time.Hour))
	rootSig := root.sign([]dns.RR{root.key}, now.Add(-time.Hour), now.Add(time.Hour))

	f := NewCachingFetcher(func(qname string, qtype uint16) (*dns.Msg, error) {
		switch qtype {
		case dns.TypeDNSKEY:
			if canonicalName(qname) == "." {
				return msgWith(dns.RcodeSuccess, []dns.RR{root.key, rootSig}, nil), nil
			}
		case dns.TypeDS:
			if canonicalName(qname) == "kolbergs-nas." {
				return msgWith(dns.RcodeNameError, nil, []dns.RR{proof, proofSig}), nil
			}
		}
		return nil, fmt.Errorf("unexpected %s/%d", qname, qtype)
	})

	res := BuildChain(f, "kolbergs-nas.", []*dns.DS{root.key.ToDS(dns.SHA256)}, now)
	if res.Status != Secure || res.Zone != "." || len(res.Keys) != 1 {
		t.Fatalf("BuildChain() = %v at %q (%v), want root secure", res.Status, res.Zone, res.Why)
	}
}

// A complete RFC 5155 name-error proof makes all descendants impossible. In
// particular, the walk must not require a redundant DS proof for each label
// below it; recursive resolvers normally provide the one closest-encloser
// proof for the entire negative answer.
func TestBuildChainSkipsDescendantsOfAProvenAbsentNSEC3Name(t *testing.T) {
	h := newHierarchy(t, ".", "test.", "example.test.")
	f := &absentAncestorHierarchy{hierarchy: h, absent: "missing.example.test."}

	res := BuildChain(f, "leaf.missing.example.test.", h.anchors(), h.now)
	if res.Status != Secure || res.Zone != "example.test." {
		t.Fatalf("BuildChain() = %v at %q (%v), want secure at example.test.", res.Status, res.Zone, res.Why)
	}
	if f.descendantCalls != 0 {
		t.Fatalf("DS lookups below proven-absent name = %d, want 0", f.descendantCalls)
	}
}

// The delegation is the parent's statement about the child. A DS the parent did
// not sign is not that statement, whoever else signed it.
func TestBuildChainRejectsADelegationTheParentDidNotSign(t *testing.T) {
	h := newHierarchy(t, ".", "test.", "example.test.")
	h.brokenDS["example.test."] = true

	res := BuildChain(h, "example.test.", h.anchors(), h.now)
	if res.Status != Bogus {
		t.Fatalf("BuildChain() = %v (%v), want bogus", res.Status, res.Why)
	}
}

func TestBuildChainRefetchesAnInvalidDelegationSigner(t *testing.T) {
	h := newHierarchy(t, ".", "test.")
	f := &flakyDelegationHierarchy{hierarchy: h, zone: "test."}
	res := BuildChain(f, "test.", h.anchors(), h.now)
	if res.Status != Secure {
		t.Fatalf("BuildChain() = %v (%v), want secure after refetch", res.Status, res.Why)
	}
	if f.calls != 2 {
		t.Fatalf("DS calls = %d, want 2 (invalid response then refetch)", f.calls)
	}
}

func TestBuildChainRefetchesAnInvalidRootKeySet(t *testing.T) {
	h := newHierarchy(t, ".", "test.")
	f := &flakyRootHierarchy{hierarchy: h}

	res := BuildChain(f, "test.", h.anchors(), h.now)
	if res.Status != Secure {
		t.Fatalf("BuildChain() = %v (%v), want secure after refetch", res.Status, res.Why)
	}
	if f.calls != 2 {
		t.Fatalf("root DNSKEY calls = %d, want 2 (invalid response then refetch)", f.calls)
	}
}

func TestBuildChainWalksPastASignedCNAMEForDS(t *testing.T) {
	h := newHierarchy(t, ".", "test.", "example.test.")
	const alias = "alias.example.test."
	res := BuildChain(&cnameDelegationHierarchy{hierarchy: h, name: alias, signed: true}, alias, h.anchors(), h.now)
	if res.Status != Secure || res.Zone != "example.test." {
		t.Fatalf("BuildChain() = %v at %q (%v), want secure parent zone", res.Status, res.Zone, res.Why)
	}
}

func TestBuildChainDoesNotTrustAnUnsignedCNAMEForDS(t *testing.T) {
	h := newHierarchy(t, ".", "test.", "example.test.")
	const alias = "alias.example.test."
	res := BuildChain(&cnameDelegationHierarchy{hierarchy: h, name: alias}, alias, h.anchors(), h.now)
	if res.Status != Indeterminate {
		t.Fatalf("BuildChain() = %v (%v), want indeterminate for unsigned CNAME evidence", res.Status, res.Why)
	}
}

// An anchor that does not match the root's key breaks everything below it,
// which is the whole point of anchoring there.
func TestBuildChainRejectsAMismatchedAnchor(t *testing.T) {
	h := newHierarchy(t, ".", "test.", "example.test.")
	stranger := newZone(t, ".")

	res := BuildChain(h, "example.test.", []*dns.DS{stranger.key.ToDS(dns.SHA256)}, h.now)
	if res.Status != Bogus {
		t.Fatalf("BuildChain() = %v (%v), want bogus", res.Status, res.Why)
	}
}

// A chain that was valid yesterday is not valid evidence today.
func TestBuildChainRejectsExpiredSignatures(t *testing.T) {
	h := newHierarchy(t, ".", "test.", "example.test.")
	res := BuildChain(h, "example.test.", h.anchors(), h.now.Add(48*time.Hour))
	if res.Status != Bogus {
		t.Fatalf("BuildChain() with expired signatures = %v (%v), want bogus", res.Status, res.Why)
	}
}

func TestBuildChainWalksToTheRootItself(t *testing.T) {
	h := newHierarchy(t, ".")
	res := BuildChain(h, ".", h.anchors(), h.now)
	if res.Status != Secure || res.Zone != "." {
		t.Fatalf("BuildChain(.) = %v %q (%v), want secure at .", res.Status, res.Zone, res.Why)
	}
}

// The published anchors are the ones the root actually uses; a typo here would
// fail closed on every query, so it is worth asserting they parse and describe
// the root.
func TestRootAnchorsAreWellFormed(t *testing.T) {
	if len(RootAnchors) < 2 {
		t.Fatalf("expected both current root keys, got %d", len(RootAnchors))
	}
	seen := map[uint16]bool{}
	for _, ds := range RootAnchors {
		if ds.Hdr.Name != "." {
			t.Errorf("anchor %d is for %q, want the root", ds.KeyTag, ds.Hdr.Name)
		}
		if ds.DigestType != 2 || len(ds.Digest) != 64 {
			t.Errorf("anchor %d is not a SHA-256 digest", ds.KeyTag)
		}
		seen[ds.KeyTag] = true
	}
	if !seen[20326] {
		t.Error("KSK-2017 (tag 20326) is missing")
	}
}

// Most names are not zone cuts. "www.example.test." is a record inside
// "example.test.", and its parent publishes no delegation signer for it because
// nothing is delegated there. Reading that absence as an unsigned delegation
// stops the walk one zone too deep and leaves the name unvalidated -- which is
// nearly every name anyone actually looks up.
func TestBuildChainStopsAtTheZoneThatOwnsTheName(t *testing.T) {
	h := newHierarchy(t, ".", "test.", "example.test.")
	h.notACut["www.example.test."] = true

	res := BuildChain(h, "www.example.test.", h.anchors(), h.now)
	if res.Status != Secure {
		t.Fatalf("BuildChain() = %v (%v), want secure", res.Status, res.Why)
	}
	if res.Zone != "example.test." {
		t.Errorf("zone = %q, want example.test. -- the zone that signs the name", res.Zone)
	}
	if len(res.Keys) == 0 {
		t.Error("no keys returned, so nothing below the zone could be verified")
	}
}

// The other reading of a missing delegation signer must survive: a delegation
// that genuinely exists and is genuinely unsigned is still insecure, and must
// not be handed its parent's keys.
func TestBuildChainStillStopsAtAGenuinelyUnsignedDelegation(t *testing.T) {
	h := newHierarchy(t, ".", "test.", "example.test.")
	h.unsigned["example.test."] = true

	res := BuildChain(h, "www.example.test.", h.anchors(), h.now)
	if res.Status != Insecure {
		t.Fatalf("BuildChain() = %v (%v), want insecure", res.Status, res.Why)
	}
	if len(res.Keys) != 0 {
		t.Error("an unsigned delegation was handed keys to verify with")
	}
}

// The NSEC which makes an absent DS an unsigned delegation has to be signed
// by the parent. Without that check, an upstream can manufacture a downgrade
// for any signed child simply by removing its DS and attaching a made-up NSEC.
func TestBuildChainDoesNotTrustAnUnsignedNoDSProof(t *testing.T) {
	h := newHierarchy(t, ".", "test.", "example.test.")
	h.unsigned["example.test."] = true

	res := BuildChain(tamperedHierarchy{hierarchy: h, unsignedProof: "example.test."}, "example.test.", h.anchors(), h.now)
	if res.Status != Indeterminate {
		t.Fatalf("BuildChain() = %v (%v), want indeterminate", res.Status, res.Why)
	}
	if len(res.Keys) != 0 {
		t.Error("keys were kept after an unverifiable delegation proof")
	}
}

// RFC 4035 section 5.3.1: a signature is only evidence about a record if the
// zone that signed it is the zone that contains the record. Without that check,
// a signature naming any zone the attacker controls would be accepted for any
// name, since that zone's own chain to the root verifies perfectly well.
func TestWithinZoneRejectsASignerThatDoesNotContainTheName(t *testing.T) {
	for _, tc := range []struct {
		name, zone string
		want       bool
	}{
		{"www.example.test.", "example.test.", true},
		{"example.test.", "example.test.", true},
		{"www.example.test.", ".", true},
		{"deep.sub.example.test.", "example.test.", true},
		// The case a plain suffix test gets wrong.
		{"notexample.test.", "example.test.", false},
		{"example.test.evil.test.", "example.test.", false},
		{"example.test.", "www.example.test.", false},
		{"attacker.test.", "example.test.", false},
		// Case must not matter; the wrong answer here is a missed match.
		{"WWW.Example.Test.", "example.test.", true},
		{"www.example.test", "example.test", true},
	} {
		if got := WithinZone(tc.name, tc.zone); got != tc.want {
			t.Errorf("WithinZone(%q, %q) = %v, want %v", tc.name, tc.zone, got, tc.want)
		}
	}
}

// A parent that offers something, but nothing that settles whether a name is a
// delegation, has established nothing. Reading that as "not a delegation" hands
// the parent's keys to what may be a child zone, and then refuses that zone's
// unsigned answers as forged -- which is what a reverse-DNS delegation sitting
// under an NSEC3 opt-out span looks like from here.
func TestBuildChainWillNotGuessWhenTheParentSettlesNothing(t *testing.T) {
	h := newHierarchy(t, ".", "test.", "example.test.")
	h.unproven["sub.example.test."] = true

	res := BuildChain(h, "sub.example.test.", h.anchors(), h.now)
	if res.Status == Secure {
		t.Fatal("the walk carried on into a name nothing was shown about")
	}
	if res.Status != Indeterminate {
		t.Errorf("status = %v, want indeterminate", res.Status)
	}
	if len(res.Keys) != 0 {
		t.Error("keys were handed to a name that may belong to another zone")
	}
}

// A zone cut can sit below a label that is not one. Stopping the walk at the
// first ordinary name hands the signed zone's keys to a child zone further
// down, and that child's unsigned answers are then refused as forged.
//
// This is the shape of a CDN name under a signed corporate zone --
// "f.c2r.ts.cdn.office.net", where office.net signs, "cdn" is an ordinary name
// inside it, and "ts.cdn" is delegated to an unsigned zone. Refusing it takes
// the CDN off the network for everyone behind this resolver.
func TestBuildChainFindsADelegationBelowAnOrdinaryName(t *testing.T) {
	h := newHierarchy(t, ".", "test.", "example.test.")
	// "cdn.example.test." is a plain name inside the signed zone...
	h.notACut["cdn.example.test."] = true
	// ...and the zone below it is delegated, and unsigned.
	h.unsigned["ts.cdn.example.test."] = true

	res := BuildChain(h, "f.ts.cdn.example.test.", h.anchors(), h.now)
	if res.Status == Secure {
		t.Fatal("the walk stopped above the delegation and claimed the parent signs for it")
	}
	if res.Status != Insecure {
		t.Errorf("status = %v (%v), want insecure", res.Status, res.Why)
	}
	if len(res.Keys) != 0 {
		t.Error("the signed parent's keys were carried into an unsigned child zone")
	}
}

// The walk must still reach the deepest signed zone when the labels above it
// are ordinary names, rather than stopping at the first of them.
func TestBuildChainWalksPastOrdinaryNamesToTheSignedZone(t *testing.T) {
	h := newHierarchy(t, ".", "test.", "example.test.")
	h.notACut["a.example.test."] = true
	h.notACut["b.a.example.test."] = true

	res := BuildChain(h, "b.a.example.test.", h.anchors(), h.now)
	if res.Status != Secure {
		t.Fatalf("status = %v (%v), want secure", res.Status, res.Why)
	}
	if res.Zone != "example.test." {
		t.Errorf("zone = %q, want example.test.", res.Zone)
	}
}
