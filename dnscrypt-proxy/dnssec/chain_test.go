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
}

func newHierarchy(t *testing.T, names ...string) *hierarchy {
	t.Helper()
	h := &hierarchy{
		t: t, zones: map[string]*zone{},
		unsigned: map[string]bool{}, brokenDS: map[string]bool{},
		notACut: map[string]bool{},
		now:     time.Now(),
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

// nsecProving builds the denial a parent offers in place of a DS: the types
// present at that name decide whether there is a delegation there at all.
func nsecProving(name string, types ...uint16) Denial {
	return Denial{NSEC: []*dns.NSEC{{
		Hdr:  dns.Header{Name: name, Class: dns.ClassINET, TTL: 300},
		NSEC: rdata.NSEC{NextDomain: "\\000." + name, TypeBitMap: types},
	}}}
}

func (h *hierarchy) DS(zoneName string) ([]*dns.DS, []*dns.RRSIG, Denial, error) {
	if h.notACut[zoneName] {
		// A name inside its parent: records, but nothing delegated.
		return nil, nil, nsecProving(zoneName, dns.TypeA, dns.TypeRRSIG, dns.TypeNSEC), nil
	}
	if h.unsigned[zoneName] {
		// A real delegation the parent does not sign for.
		return nil, nil, nsecProving(zoneName, dns.TypeNS, dns.TypeRRSIG, dns.TypeNSEC), nil
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
