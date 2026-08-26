package dnssec

import (
	"testing"

	"codeberg.org/miekg/dns"
	"codeberg.org/miekg/dns/rdata"
)

func nsec(owner, next string, types ...uint16) *dns.NSEC {
	rr := &dns.NSEC{Hdr: dns.Header{Name: owner, Class: dns.ClassINET, TTL: 300}}
	rr.NextDomain = next
	rr.TypeBitMap = types
	return rr
}

func nsec3(ownerHash, nextHash string, flags uint8, types ...uint16) *dns.NSEC3 {
	rr := &dns.NSEC3{Hdr: dns.Header{Name: ownerHash + ".example.test.", Class: dns.ClassINET, TTL: 300}}
	rr.Hash = 1
	rr.Flags = flags
	rr.Iterations = 0
	rr.Salt = "-"
	rr.NextDomain = nextHash
	rr.TypeBitMap = types
	return rr
}

// DNSSEC orders names by label from the right. Comparing the strings instead
// gets the gaps wrong, and a wrong gap accepts a denial that proves nothing.
func TestCanonicalCompareOrdersByLabelFromTheRight(t *testing.T) {
	for _, tc := range []struct {
		a, b string
		want int
	}{
		{"example.", "example.", 0},
		{"a.example.", "b.example.", -1},
		{"example.", "a.example.", -1},  // the apex sorts before its children
		{"A.example.", "a.example.", 0}, // case does not matter
		// RFC 4034 section 6.1 gives this ordering explicitly: comparison
		// starts at the rightmost label, so z.example. follows a.b.example.
		// even though the strings compare the other way round.
		{"z.example.", "a.b.example.", 1},
		{"a.example.", "zABC.a.EXAMPLE.", -1},
		{"zABC.a.example.", "z.example.", -1},
	} {
		got := canonicalCompare(tc.a, tc.b)
		if (got < 0) != (tc.want < 0) || (got > 0) != (tc.want > 0) {
			t.Errorf("canonicalCompare(%q, %q) = %d, want sign %d", tc.a, tc.b, got, tc.want)
		}
	}
}

func TestNSECCoversTheGap(t *testing.T) {
	rr := nsec("a.example.", "c.example.", dns.TypeA)
	for _, tc := range []struct {
		name string
		want bool
	}{
		{"b.example.", true},
		{"a.example.", false}, // the owner exists; it is not in the gap
		{"c.example.", false}, // the next name exists either
		{"d.example.", false},
	} {
		if got := nsecCovers(rr, tc.name); got != tc.want {
			t.Errorf("nsecCovers(%q) = %v, want %v", tc.name, got, tc.want)
		}
	}
}

// The last record of a zone wraps back to the apex. Without that, every name
// after the final one is unprovable.
func TestNSECCoversTheWrapAtTheEndOfAZone(t *testing.T) {
	rr := nsec("z.example.", "example.", dns.TypeA)
	if !nsecCovers(rr, "zz.example.") {
		t.Error("the wrapping record should cover names after its owner")
	}
	if nsecCovers(rr, "b.example.") {
		t.Error("the wrapping record should not cover names before it")
	}
}

func TestProvesNoData(t *testing.T) {
	d := Denial{NSEC: []*dns.NSEC{nsec("www.example.", "x.example.", dns.TypeA, dns.TypeRRSIG, dns.TypeNSEC)}}
	if !d.ProvesNoData("www.example.", dns.TypeAAAA) {
		t.Error("a matching record without AAAA should prove there is none")
	}
	if d.ProvesNoData("www.example.", dns.TypeA) {
		t.Error("a record listing A must not prove A is absent")
	}
	if d.ProvesNoData("other.example.", dns.TypeAAAA) {
		t.Error("a record for another name proves nothing about this one")
	}
}

// A name that is really a CNAME must not be deniable: the answer should have
// followed the redirect instead.
func TestProvesNoDataRefusesToDenyACNAME(t *testing.T) {
	d := Denial{NSEC: []*dns.NSEC{nsec("www.example.", "x.example.", dns.TypeCNAME, dns.TypeRRSIG)}}
	if d.ProvesNoData("www.example.", dns.TypeA) {
		t.Error("a name holding a CNAME must not be denied")
	}
}

// This is the denial that decides whether everything below a delegation is
// outside DNSSEC, so it is the one an attacker forges to downgrade a zone.
func TestProvesNoDS(t *testing.T) {
	delegation := Denial{NSEC: []*dns.NSEC{nsec("child.example.", "d.example.", dns.TypeNS, dns.TypeRRSIG, dns.TypeNSEC)}}
	if !delegation.ProvesNoDS("child.example.") {
		t.Error("a delegation listing NS and no DS should prove the child is unsigned")
	}

	signed := Denial{NSEC: []*dns.NSEC{nsec("child.example.", "d.example.", dns.TypeNS, dns.TypeDS, dns.TypeRRSIG)}}
	if signed.ProvesNoDS("child.example.") {
		t.Error("a record listing DS must never prove there is none")
	}

	// The zone's own apex lists SOA. Mistaking it for a delegation would let a
	// zone deny the signer of a child it never delegated.
	apex := Denial{NSEC: []*dns.NSEC{nsec("example.", "a.example.", dns.TypeSOA, dns.TypeNS, dns.TypeRRSIG)}}
	if apex.ProvesNoDS("example.") {
		t.Error("an apex record must not be read as an unsigned delegation")
	}

	// A name with no NS is not a delegation at all.
	plain := Denial{NSEC: []*dns.NSEC{nsec("child.example.", "d.example.", dns.TypeA, dns.TypeRRSIG)}}
	if plain.ProvesNoDS("child.example.") {
		t.Error("a name without NS is not a delegation")
	}
}

// A name error needs the wildcard denied too: a zone holding *.example. would
// have answered, so covering the name alone proves nothing.
func TestProvesNameErrorRequiresTheWildcardDenied(t *testing.T) {
	covering := nsec("a.example.", "c.example.", dns.TypeA)
	wildcardDenial := nsec("example.", "a.example.", dns.TypeSOA)

	full := Denial{NSEC: []*dns.NSEC{covering, wildcardDenial}}
	if !full.ProvesNameError("b.example.", "example.") {
		t.Error("name covered and wildcard denied should prove the name error")
	}

	partial := Denial{NSEC: []*dns.NSEC{covering}}
	if partial.ProvesNameError("b.example.", "example.") {
		t.Error("covering the name alone must not prove a name error: a wildcard could answer it")
	}
}

func TestNSEC3HashMatchesTheKnownVector(t *testing.T) {
	// RFC 5155 appendix A: "a.example" with salt aabbccdd and 12 iterations.
	got := NSEC3Hash("a.example.", 1, 12, "aabbccdd")
	const want = "35MTHGPGCU1QG68FAB165KLNSNK3DPVL"
	if got != want {
		t.Errorf("NSEC3Hash() = %q, want %q", got, want)
	}
}

// An algorithm this build cannot compute must prove nothing rather than be
// mistaken for a mismatch or a match.
func TestNSEC3HashRefusesAnUnknownAlgorithm(t *testing.T) {
	if got := NSEC3Hash("a.example.", 99, 0, "-"); got != "" {
		t.Errorf("NSEC3Hash() with an unknown algorithm = %q, want empty", got)
	}
}

// Opt-out lets a zone leave unsigned delegations without records of their own,
// but only where the flag says so.
func TestProvesNoDSUnderOptOut(t *testing.T) {
	name := "child.example.test."
	h := NSEC3Hash(name, 1, 0, "-")
	// A gap that contains the name, flagged opt-out.
	before, after := "0000000000000000000000000000000A", "ZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZ"
	if h < before || h > after {
		t.Skipf("hash %s falls outside the constructed gap", h)
	}

	optOut := Denial{NSEC3: []*dns.NSEC3{nsec3(before, after, 1, dns.TypeNS)}}
	if !optOut.ProvesNoDS(name) {
		t.Error("an opt-out gap containing the delegation should prove there is no signer")
	}

	notOptOut := Denial{NSEC3: []*dns.NSEC3{nsec3(before, after, 0, dns.TypeNS)}}
	if notOptOut.ProvesNoDS(name) {
		t.Error("without the opt-out flag, a covering gap proves nothing about a delegation")
	}
}

func TestCollectDenialAndEmpty(t *testing.T) {
	if !(Denial{}).Empty() {
		t.Error("a denial with no records should be empty")
	}
	d := CollectDenial([]dns.RR{
		nsec("a.example.", "c.example.", dns.TypeA),
		aRecord("www.example.test.", "192.0.2.1"),
	})
	if len(d.NSEC) != 1 || !(len(d.NSEC3) == 0) {
		t.Errorf("CollectDenial() = %d NSEC, %d NSEC3; want 1 and 0", len(d.NSEC), len(d.NSEC3))
	}
	if d.Empty() {
		t.Error("a denial holding a record is not empty")
	}
}

var _ = rdata.NSEC{}
