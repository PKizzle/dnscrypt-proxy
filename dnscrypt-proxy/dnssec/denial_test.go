package dnssec

import (
	"testing"
	"time"

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

// DNAME redirects all names below its owner. It cannot coexist with ordinary
// data, so a denial that ignores it would accept a NODATA reply where the zone
// should have supplied the redirection.
func TestProvesNoDataRefusesToDenyADNAME(t *testing.T) {
	d := Denial{NSEC: []*dns.NSEC{nsec("www.example.", "x.example.", dns.TypeDNAME, dns.TypeRRSIG)}}
	if d.ProvesNoData("www.example.", dns.TypeA) {
		t.Error("a name holding a DNAME must not be denied")
	}
}

// RFC 6840 section 4.1/4.4: an NSEC at a delegation point cannot turn a
// referral into NODATA. Its NS-without-SOA bitmap identifies parent-side data,
// not an authoritative answer for ordinary types.
func TestProvesNoDataRefusesToDenyAtADelegation(t *testing.T) {
	d := Denial{NSEC: []*dns.NSEC{nsec("child.example.", "d.example.", dns.TypeNS, dns.TypeNSEC, dns.TypeRRSIG)}}
	if d.ProvesNoData("child.example.", dns.TypeA) {
		t.Error("a delegation NSEC must not prove child.example. has no A record")
	}
}

func TestProvesWildcardNoDataRequiresBothTheClosestEncloserAndWildcard(t *testing.T) {
	// RFC 4035 appendix B.7: the gap proves x is below the closest encloser
	// example.test.; the matching wildcard record proves that wildcard exists
	// but has no AAAA record.
	gap := nsec("a.example.test.", "z.example.test.", dns.TypeNSEC, dns.TypeRRSIG)
	wildcard := nsec("*.example.test.", "x.example.test.", dns.TypeA, dns.TypeNSEC, dns.TypeRRSIG)
	d := Denial{NSEC: []*dns.NSEC{gap, wildcard}}
	if !d.ProvesWildcardNoData("x.example.test.", "example.test.", dns.TypeAAAA) {
		t.Fatal("a complete NSEC wildcard NODATA proof was not accepted")
	}
	if d.ProvesWildcardNoData("x.example.test.", "example.test.", dns.TypeA) {
		t.Fatal("a wildcard containing the requested type proved NODATA")
	}
	if (Denial{NSEC: []*dns.NSEC{gap}}).ProvesWildcardNoData("x.example.test.", "example.test.", dns.TypeAAAA) {
		t.Fatal("the closest-encloser proof alone proved wildcard NODATA")
	}
	if (Denial{NSEC: []*dns.NSEC{wildcard}}).ProvesWildcardNoData("x.example.test.", "example.test.", dns.TypeAAAA) {
		t.Fatal("the wildcard proof alone proved wildcard NODATA")
	}
}

func TestProvesNSEC3WildcardNoData(t *testing.T) {
	name, zone := "x.example.test.", "example.test."
	closestHash := NSEC3Hash(zone, 1, 0, "-")
	wildcardHash := NSEC3Hash("*."+zone, 1, 0, "-")
	nextCloserHash := NSEC3Hash(name, 1, 0, "-")
	before, after := "0000000000000000000000000000000A", "ZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZ"
	if nextCloserHash < before || nextCloserHash > after {
		t.Skipf("hash %s falls outside the constructed gap", nextCloserHash)
	}
	d := Denial{NSEC3: []*dns.NSEC3{
		nsec3(closestHash, "VVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVV", 0, dns.TypeNSEC3, dns.TypeRRSIG),
		nsec3(before, after, 0, dns.TypeNSEC3, dns.TypeRRSIG),
		nsec3(wildcardHash, "WWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWW", 0, dns.TypeA, dns.TypeNSEC3, dns.TypeRRSIG),
	}}
	if !d.ProvesWildcardNoData(name, zone, dns.TypeAAAA) {
		t.Fatal("a complete NSEC3 wildcard NODATA proof was not accepted")
	}
	if d.ProvesWildcardNoData(name, zone, dns.TypeA) {
		t.Fatal("an NSEC3 wildcard containing the requested type proved NODATA")
	}
	// An Opt-Out span can conceal an unsigned delegation and therefore cannot
	// prove that the next-closer name is absent for a wildcard response.
	d.NSEC3[1].Flags = 1
	if d.ProvesWildcardNoData(name, zone, dns.TypeAAAA) {
		t.Fatal("an Opt-Out span proved wildcard NODATA")
	}
}

// abuse.ch returns this RFC 5155 section 8.7 shape for DNSBL DS lookups: an
// exact closest encloser, a non-Opt-Out span over the next closer name, and a
// matching wildcard that omits DS. It proves the queried label is not a
// delegation, even though no NSEC3 directly covers the queried leaf.
func TestProvesNotADelegationFromNSEC3WildcardNoData(t *testing.T) {
	const (
		name = "65.spam.abuse.ch."
		zone = "abuse.ch."
	)
	makeRR := func(owner, next string, types ...uint16) *dns.NSEC3 {
		rr := &dns.NSEC3{Hdr: dns.Header{Name: owner + "." + zone, Class: dns.ClassINET, TTL: 300}}
		rr.Hash = 1
		rr.Iterations = 1
		rr.Salt = "7CFB068B53AA9CBF"
		rr.NextDomain = next
		rr.TypeBitMap = types
		return rr
	}
	d := Denial{zone: zone, NSEC3: []*dns.NSEC3{
		makeRR("O187VO66FPKO7RD6PV6223BDH0I5UTNU", "O363CMUV83PO814A2N1V1OT4AGRBANF4", dns.TypeA, dns.TypeNS, dns.TypeSOA, dns.TypeNSEC3, dns.TypeRRSIG),
		makeRR("6T0M3GD658T7HOUUUES6KM1HQNL4P0CV", "76A7M4UMTM9GUJLBS0FC14DQB2PFVKGN", dns.TypeCNAME, dns.TypeRRSIG),
		makeRR("U28E8TRO47LAJEQQVDNMV8NI3RB59TO5", "UBLSRVMCRAOA64REHUI09SUPF0KKI3EF", dns.TypeTXT, dns.TypeRRSIG),
	}}
	if !d.ProvesWildcardNoData(name, zone, dns.TypeDS) {
		t.Fatal("the complete wildcard DS NODATA proof was not accepted")
	}
	if !d.ProvesNotADelegation(name) {
		t.Fatal("a wildcard DS NODATA proof did not establish that the name is not a delegation")
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

func TestProvesNotADelegationWhenNSECCoversANonexistentName(t *testing.T) {
	d := Denial{NSEC: []*dns.NSEC{nsec("a.example.", "c.example.", dns.TypeNSEC, dns.TypeRRSIG)}}
	if !d.ProvesNotADelegation("b.example.") {
		t.Error("a covering NSEC should prove a nonexistent name is not a delegation")
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

// RFC 4035 section 5.4 requires denial of the wildcard that would actually be
// consulted. Denying only *.example. must not turn a real *.b.example. answer
// into an accepted NXDOMAIN for x.b.example.
func TestProvesNameErrorUsesTheClosestNSECEncloser(t *testing.T) {
	nameCover := nsec("a.b.example.", "z.b.example.", dns.TypeA)
	apexWildcardCover := nsec("example.", "a.example.", dns.TypeSOA)
	wrong := Denial{NSEC: []*dns.NSEC{nameCover, apexWildcardCover}}
	if wrong.ProvesNameError("x.b.example.", "example.") {
		t.Fatal("a proof for *.example. must not deny the relevant *.b.example. wildcard")
	}

	closestWildcardCover := nsec("b.example.", "c.b.example.", dns.TypeNS)
	valid := Denial{NSEC: []*dns.NSEC{nameCover, closestWildcardCover}}
	if !valid.ProvesNameError("x.b.example.", "example.") {
		t.Fatal("a proof for the closest-encloser wildcard should validate the name error")
	}
}

func TestAncestorDNAMEProofCannotDenyItsDescendant(t *testing.T) {
	// d.example. -> z.example. covers x.d.example. and *.d.example., but
	// RFC 6840 section 4.1 says the DNAME bit prevents it proving either
	// absent: the response must contain the DNAME synthesis instead.
	d := Denial{NSEC: []*dns.NSEC{nsec("d.example.", "z.example.", dns.TypeDNAME, dns.TypeNSEC, dns.TypeRRSIG)}}
	if d.ProvesNameError("x.d.example.", "example.") {
		t.Fatal("an NSEC at a DNAME must not prove its descendant NXDOMAIN")
	}
	if d.ProvesNoCloserMatch("x.d.example.") {
		t.Fatal("an NSEC at a DNAME must not prove a wildcard expansion below it absent")
	}
}

// Query plugins retain an internal QNAME without the trailing root label.
// NSEC owner names are DNS RRs and therefore always fully qualified. The
// absence check must compare those representations without calling the DNS
// library's FQDN-only EqualName helper, which otherwise panics on real NXDOMAIN
// traffic before the RFC 6840 DNAME/delegation exclusions can be applied.
func TestNSECAbsenceCheckAcceptsAnInternalQName(t *testing.T) {
	rr := nsec("a.example.", "c.example.", dns.TypeNSEC, dns.TypeRRSIG)
	d := Denial{NSEC: []*dns.NSEC{rr}}
	if !d.nsecMayProveAbsence(rr, "b.example") {
		t.Fatal("NSEC should cover the internal, non-FQDN query name")
	}
}

func TestNSEC3AncestorDNAMECannotProveAbsence(t *testing.T) {
	ancestor := "d.example.test."
	owner := NSEC3Hash(ancestor, 1, 0, "-")
	rr := nsec3(owner, "ZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZ", 0, dns.TypeDNAME)
	d := Denial{NSEC3: []*dns.NSEC3{rr}, zone: "example.test."}
	if d.nsec3MayProveAbsence(rr, "x.d.example.test.") {
		t.Fatal("NSEC3 at a DNAME must not deny a descendant")
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

func TestNSEC3HashRefusesAnOddLengthSalt(t *testing.T) {
	if got := NSEC3Hash("a.example.", 1, 0, "a"); got != "" {
		t.Errorf("NSEC3Hash() with an odd-length salt = %q, want empty", got)
	}
}

func TestDenialIdentifiesOnlyUnsupportedNSEC3Iterations(t *testing.T) {
	high := nsec3("AAAA", "ZZZZ", 0, dns.TypeRRSIG, dns.TypeNSEC3)
	high.Iterations = maxNSEC3Iterations + 1
	if !(Denial{NSEC3: []*dns.NSEC3{high}}).HasOnlyUnsupportedNSEC3Iterations() {
		t.Fatal("a denial consisting only of high-iteration NSEC3 records was not identified")
	}
	low := nsec3("BBBB", "ZZZZ", 0, dns.TypeRRSIG, dns.TypeNSEC3)
	low.Iterations = maxNSEC3Iterations
	if (Denial{NSEC3: []*dns.NSEC3{high, low}}).HasOnlyUnsupportedNSEC3Iterations() {
		t.Fatal("a usable NSEC3 record made the whole denial look unsupported")
	}
	plain := nsec("a.example.test.", "z.example.test.", dns.TypeRRSIG, dns.TypeNSEC)
	if (Denial{NSEC: []*dns.NSEC{plain}, NSEC3: []*dns.NSEC3{high}}).HasOnlyUnsupportedNSEC3Iterations() {
		t.Fatal("an NSEC proof made the whole denial look unsupported")
	}
	unknownHash := *high
	unknownHash.Hash = 2
	if (Denial{NSEC3: []*dns.NSEC3{&unknownHash}}).HasOnlyUnsupportedNSEC3Iterations() {
		t.Fatal("an unknown NSEC3 hash was incorrectly attributed to iterations")
	}
}

func TestNSEC3ClosestEncloserRefusesDNAMEAndDelegationRecords(t *testing.T) {
	owner := NSEC3Hash("example.test.", 1, 0, "-")
	for _, types := range [][]uint16{
		{dns.TypeDNAME},
		{dns.TypeNS},
	} {
		d := Denial{NSEC3: []*dns.NSEC3{nsec3(owner, "VVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVV", 0, types...)}}
		if _, ok := d.closestEncloser("missing.example.test.", "example.test."); ok {
			t.Errorf("NSEC3 bitmap %v was accepted as a closest encloser", types)
		}
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

// Denial records make negative answers and unsigned delegations trustworthy;
// without their own RRSIG, an upstream could manufacture either conclusion.
func TestOnlyASignedDenialCanProveAbsence(t *testing.T) {
	z := newZone(t, "example.test.")
	now := time.Now()
	rr := nsec("www.example.test.", "x.example.test.", dns.TypeRRSIG, dns.TypeNSEC)
	sig := z.sign([]dns.RR{rr}, now.Add(-time.Hour), now.Add(time.Hour))

	verified := CollectDenial([]dns.RR{rr, sig}).Verified([]*dns.DNSKEY{z.key}, z.name, now)
	if !verified.ProvesNoData("www.example.test.", dns.TypeA) {
		t.Error("a denial signed by the zone's key did not verify")
	}

	forged := CollectDenial([]dns.RR{rr}).Verified([]*dns.DNSKEY{z.key}, z.name, now)
	if !forged.Empty() {
		t.Error("an unsigned denial was accepted as proof")
	}
}

// RFC 4035 section 5.4 permits a matching NSEC to establish that wildcard
// expansion was not used only when the signature's label count matches the
// NSEC owner. A wildcard-expanded NSEC is cryptographically valid but does
// not establish that the expanded owner exists.
func TestVerifiedDenialRejectsWildcardExpandedNSEC(t *testing.T) {
	z := newZone(t, "example.test.")
	now := time.Now()
	wildcard := nsec("*.example.test.", "z.example.test.", dns.TypeNSEC, dns.TypeRRSIG)
	sig := z.sign([]dns.RR{wildcard}, now.Add(-time.Hour), now.Add(time.Hour))

	wildcard.Hdr.Name = "missing.example.test."
	sig.Hdr.Name = "missing.example.test."
	verified := CollectDenial([]dns.RR{wildcard, sig}).Verified([]*dns.DNSKEY{z.key}, z.name, now)
	if !verified.Empty() {
		t.Fatal("a wildcard-expanded NSEC was accepted as an exact denial proof")
	}
}

func TestVerifiedDenialRejectsARecordOutsideTheSignerZone(t *testing.T) {
	z := newZone(t, "example.test.")
	now := time.Now()
	rr := nsec("a.invalid.", "z.invalid.", dns.TypeNSEC, dns.TypeRRSIG)
	sig := z.sign([]dns.RR{rr}, now.Add(-time.Hour), now.Add(time.Hour))

	verified := CollectDenial([]dns.RR{rr, sig}).Verified([]*dns.DNSKEY{z.key}, z.name, now)
	if !verified.Empty() {
		t.Error("a signer must not establish denial for data outside its zone")
	}
}

func TestVerifiedDenialRejectsNSEC3WithUnknownFlags(t *testing.T) {
	z := newZone(t, "example.test.")
	now := time.Now()
	rr := nsec3("0000000000000000000000000000000A", "VVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVV", 2)
	sig := z.sign([]dns.RR{rr}, now.Add(-time.Hour), now.Add(time.Hour))

	verified := CollectDenial([]dns.RR{rr, sig}).Verified([]*dns.DNSKEY{z.key}, z.name, now)
	if !verified.Empty() {
		t.Error("an NSEC3 with an unknown flag bit must not prove absence")
	}
}

// The key must sign as the zone that owns the denial. A signature with the
// right key tag but a different signer name is not a statement by that zone.
func TestDenialRequiresTheExpectedSignerName(t *testing.T) {
	z := newZone(t, "example.test.")
	now := time.Now()
	rr := nsec("www.example.test.", "x.example.test.", dns.TypeRRSIG, dns.TypeNSEC)
	sig := z.sign([]dns.RR{rr}, now.Add(-time.Hour), now.Add(time.Hour))
	sig.SignerName = "other.example.test."

	verified := CollectDenial([]dns.RR{rr, sig}).Verified([]*dns.DNSKEY{z.key}, z.name, now)
	if !verified.Empty() {
		t.Error("a denial with the wrong signer name was accepted")
	}
}

var _ = rdata.NSEC{}
