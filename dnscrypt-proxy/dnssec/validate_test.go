package dnssec

import (
	"crypto"
	"net/netip"
	"testing"
	"time"

	"codeberg.org/miekg/dns"
	"codeberg.org/miekg/dns/rdata"
)

// zone is a signed zone built for a test: a key pair and the means to sign an
// RRset with it, so the tests exercise real signatures rather than fixtures.
type zone struct {
	t    *testing.T
	name string
	key  *dns.DNSKEY
	priv crypto.Signer
}

func newZone(t *testing.T, name string) *zone {
	t.Helper()
	key := dns.NewDNSKEY(name, dns.ECDSAP256SHA256)
	key.Flags = dns.FlagZONE
	key.Protocol = 3
	priv, err := key.Generate(256)
	if err != nil {
		t.Fatalf("generate key for %s: %v", name, err)
	}
	signer, ok := priv.(crypto.Signer)
	if !ok {
		t.Fatalf("generated key for %s is not a signer", name)
	}
	return &zone{t: t, name: name, key: key, priv: signer}
}

// sign returns a signature over rrset, valid in the window given.
func (z *zone) sign(rrset []dns.RR, inception, expiration time.Time) *dns.RRSIG {
	z.t.Helper()
	sig := dns.NewRRSIG(z.name, z.key.Algorithm, z.key.KeyTag(),
		uint32(inception.Unix()), uint32(expiration.Unix()))
	if err := sig.Sign(z.priv, rrset, &dns.SignOption{}); err != nil {
		z.t.Fatalf("sign rrset for %s: %v", z.name, err)
	}
	return sig
}

func aRecord(name string, addr string) dns.RR {
	return &dns.A{
		Hdr: dns.Header{Name: name, Class: dns.ClassINET, TTL: 300},
		A:   rdata.A{Addr: netip.MustParseAddr(addr)},
	}
}

func TestVerifyRRSetAcceptsAGenuineSignature(t *testing.T) {
	z := newZone(t, "example.test.")
	rrset := []dns.RR{aRecord("www.example.test.", "192.0.2.1")}
	now := time.Now()
	sig := z.sign(rrset, now.Add(-time.Hour), now.Add(time.Hour))

	res, err := VerifyRRSet(rrset, []*dns.RRSIG{sig}, []*dns.DNSKEY{z.key}, now)
	if res != Secure {
		t.Fatalf("VerifyRRSet() = %v (%v), want secure", res, err)
	}
}

// The point of the exercise: an answer altered after signing must not verify.
func TestVerifyRRSetRejectsAlteredData(t *testing.T) {
	z := newZone(t, "example.test.")
	rrset := []dns.RR{aRecord("www.example.test.", "192.0.2.1")}
	now := time.Now()
	sig := z.sign(rrset, now.Add(-time.Hour), now.Add(time.Hour))

	tampered := []dns.RR{aRecord("www.example.test.", "198.51.100.66")}
	res, _ := VerifyRRSet(tampered, []*dns.RRSIG{sig}, []*dns.DNSKEY{z.key}, now)
	if res != Bogus {
		t.Fatalf("VerifyRRSet() on altered data = %v, want bogus", res)
	}
}

// A signature from a key the chain does not reach proves nothing, however
// well-formed it is.
func TestVerifyRRSetRejectsAForeignKey(t *testing.T) {
	real, attacker := newZone(t, "example.test."), newZone(t, "example.test.")
	rrset := []dns.RR{aRecord("www.example.test.", "192.0.2.1")}
	now := time.Now()
	sig := attacker.sign(rrset, now.Add(-time.Hour), now.Add(time.Hour))

	res, _ := VerifyRRSet(rrset, []*dns.RRSIG{sig}, []*dns.DNSKEY{real.key}, now)
	if res != Bogus {
		t.Fatalf("VerifyRRSet() with a foreign key = %v, want bogus", res)
	}
}

func TestVerifyRRSetRejectsOutsideValidity(t *testing.T) {
	z := newZone(t, "example.test.")
	rrset := []dns.RR{aRecord("www.example.test.", "192.0.2.1")}
	now := time.Now()

	for _, tc := range []struct {
		name                  string
		inception, expiration time.Time
	}{
		{"expired", now.Add(-48 * time.Hour), now.Add(-24 * time.Hour)},
		{"not yet valid", now.Add(24 * time.Hour), now.Add(48 * time.Hour)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			sig := z.sign(rrset, tc.inception, tc.expiration)
			res, _ := VerifyRRSet(rrset, []*dns.RRSIG{sig}, []*dns.DNSKEY{z.key}, now)
			if res != Bogus {
				t.Fatalf("VerifyRRSet() = %v, want bogus", res)
			}
		})
	}
}

// An unsigned answer is not a failed one: most of the internet is unsigned, and
// the caller decides what that means from the delegation above it.
func TestVerifyRRSetReportsAMissingSignatureSeparately(t *testing.T) {
	z := newZone(t, "example.test.")
	rrset := []dns.RR{aRecord("www.example.test.", "192.0.2.1")}

	res, err := VerifyRRSet(rrset, nil, []*dns.DNSKEY{z.key}, time.Now())
	if res != Indeterminate {
		t.Fatalf("VerifyRRSet() without signatures = %v, want indeterminate", res)
	}
	if err != ErrNoSignature {
		t.Fatalf("error = %v, want ErrNoSignature", err)
	}
}

// A signature over some other name or type says nothing about this RRset, and
// must not be mistaken for cover.
func TestVerifyRRSetIgnoresASignatureOverSomethingElse(t *testing.T) {
	z := newZone(t, "example.test.")
	other := []dns.RR{aRecord("other.example.test.", "192.0.2.9")}
	now := time.Now()
	sig := z.sign(other, now.Add(-time.Hour), now.Add(time.Hour))

	rrset := []dns.RR{aRecord("www.example.test.", "192.0.2.1")}
	res, err := VerifyRRSet(rrset, []*dns.RRSIG{sig}, []*dns.DNSKEY{z.key}, now)
	if res != Indeterminate || err != ErrNoSignature {
		t.Fatalf("VerifyRRSet() = %v (%v), want indeterminate/no-signature", res, err)
	}
}

func TestVerifyDNSKEYsAcceptsAnAnchoredSet(t *testing.T) {
	z := newZone(t, "example.test.")
	keys := []*dns.DNSKEY{z.key}
	rrset := []dns.RR{z.key}
	now := time.Now()
	sig := z.sign(rrset, now.Add(-time.Hour), now.Add(time.Hour))
	ds := z.key.ToDS(dns.SHA256)

	res, err := VerifyDNSKEYs(keys, []*dns.RRSIG{sig}, []*dns.DS{ds}, now)
	if res != Secure {
		t.Fatalf("VerifyDNSKEYs() = %v (%v), want secure", res, err)
	}
}

// The parent's delegation is what makes a key the zone's. A key the parent
// never vouched for is not, even when it signs the set convincingly.
func TestVerifyDNSKEYsRejectsAKeyTheParentDidNotDelegate(t *testing.T) {
	real, attacker := newZone(t, "example.test."), newZone(t, "example.test.")
	keys := []*dns.DNSKEY{attacker.key}
	rrset := []dns.RR{attacker.key}
	now := time.Now()
	sig := attacker.sign(rrset, now.Add(-time.Hour), now.Add(time.Hour))
	ds := real.key.ToDS(dns.SHA256)

	res, _ := VerifyDNSKEYs(keys, []*dns.RRSIG{sig}, []*dns.DS{ds}, now)
	if res != Bogus {
		t.Fatalf("VerifyDNSKEYs() with an undelegated key = %v, want bogus", res)
	}
}

// Smuggling: the attacker's key rides along in the set beside the genuine one,
// and signs the set. Only the anchored key may vouch for the set, so this must
// not turn the attacker's key into a valid signer.
func TestVerifyDNSKEYsRejectsASetSignedOnlyByASmuggledKey(t *testing.T) {
	real, attacker := newZone(t, "example.test."), newZone(t, "example.test.")
	keys := []*dns.DNSKEY{real.key, attacker.key}
	rrset := []dns.RR{real.key, attacker.key}
	now := time.Now()
	sig := attacker.sign(rrset, now.Add(-time.Hour), now.Add(time.Hour))
	ds := real.key.ToDS(dns.SHA256)

	res, _ := VerifyDNSKEYs(keys, []*dns.RRSIG{sig}, []*dns.DS{ds}, now)
	if res != Bogus {
		t.Fatalf("VerifyDNSKEYs() = %v, want bogus: only an anchored key may sign the set", res)
	}
}

// Timestamps are serial numbers, so the comparison has to survive the wrap that
// plain integer comparison does not.
func TestValidAtHandlesSerialWraparound(t *testing.T) {
	// A window straddling 2^32: inception before the wrap, expiration after.
	sig := &dns.RRSIG{RRSIG: rdata.RRSIG{
		Inception:  0xFFFFFF00,
		Expiration: 0x00000100,
	}}
	for _, tc := range []struct {
		name string
		ts   uint32
		want bool
	}{
		{"just before the wrap", 0xFFFFFF80, true},
		{"just after the wrap", 0x00000080, true},
		{"well outside", 0x40000000, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := ValidAt(sig, time.Unix(int64(tc.ts), 0)); got != tc.want {
				t.Errorf("ValidAt(%#x) = %v, want %v", tc.ts, got, tc.want)
			}
		})
	}
}

func TestSplitSignatures(t *testing.T) {
	z := newZone(t, "example.test.")
	rrset := []dns.RR{aRecord("www.example.test.", "192.0.2.1")}
	now := time.Now()
	sig := z.sign(rrset, now.Add(-time.Hour), now.Add(time.Hour))

	records, sigs := SplitSignatures([]dns.RR{rrset[0], sig})
	if len(records) != 1 || len(sigs) != 1 {
		t.Fatalf("SplitSignatures() = %d records, %d sigs; want 1 and 1", len(records), len(sigs))
	}
}

// A zone signed with an algorithm this build cannot check is unsigned as far as
// this validator is concerned, not forged. Refusing it would take zones off the
// air as signing algorithms turn over -- and enforcement would do exactly that.
func TestDelegationThisBuildCannotCheckIsInsecureNotBogus(t *testing.T) {
	z := newZone(t, "example.test.")
	// A digest type no build computes, so nothing about this delegation can be
	// established either way.
	ds := z.key.ToDS(dns.SHA256)
	ds.DigestType = 99

	res, err := VerifyDNSKEYs([]*dns.DNSKEY{z.key}, nil, []*dns.DS{ds}, time.Now())
	if res == Bogus {
		t.Fatalf("an uncheckable delegation was refused as forged: %v", err)
	}
	if res != Insecure {
		t.Errorf("result = %v, want Insecure", res)
	}
}

// A delegation that CAN be checked and does not match is still forged, and must
// stay refused: treating the uncheckable case as unsigned must not soften this.
func TestCheckableDelegationThatDoesNotMatchIsStillBogus(t *testing.T) {
	z := newZone(t, "example.test.")
	ds := z.key.ToDS(dns.SHA256)
	ds.Digest = "0000000000000000000000000000000000000000000000000000000000000000"

	res, _ := VerifyDNSKEYs([]*dns.DNSKEY{z.key}, nil, []*dns.DS{ds}, time.Now())
	if res != Bogus {
		t.Errorf("result = %v, want Bogus -- a checkable mismatch is still forged", res)
	}
}
