package dnssec

import (
	"crypto"
	"encoding/base64"
	"errors"
	"fmt"
	"net/netip"
	"strings"
	"sync"
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
	return newZoneWithAlgorithm(t, name, dns.ECDSAP256SHA256)
}

func newZoneWithAlgorithm(t *testing.T, name string, algorithm uint8) *zone {
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
	return z.signAs(z.name, rrset, inception, expiration)
}

// signAs creates a cryptographically genuine signature while letting a test
// exercise the RRSIG Signer's Name validation separately.
func (z *zone) signAs(signerName string, rrset []dns.RR, inception, expiration time.Time) *dns.RRSIG {
	z.t.Helper()
	sig := dns.NewRRSIG(signerName, z.key.Algorithm, z.key.KeyTag(),
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

// This independently signed production RRset guards the RFC 4034 section 6.3
// ordering rule that exposed the original failure. RFC 8659 section 4.1 gives
// CAA Value no length octet, so canonical order compares its bytes directly.
// A signer and verifier sharing the same broken sorter would make a generated
// test vector pass, which is why this fixture comes from the public zone.
func TestVerifyRRSetAcceptsIndependentlySignedCAASet(t *testing.T) {
	mustRR := func(text string) dns.RR {
		t.Helper()
		rr, err := dns.New(text)
		if err != nil {
			t.Fatalf("parse DNS fixture: %v", err)
		}
		return rr
	}
	key := mustRR("cloudflare.com. 3600 IN DNSKEY 256 3 13 oJMRESz5E4gYzS/q6XDrvU1qMPYIjCWzJaOau8XNEZeqCYKD5ar0IRd8KqXXFJkqmVfRvMGPmM1x8fGAa2XhSA==").(*dns.DNSKEY)
	sig := mustRR("cloudflare.com. 300 IN RRSIG CAA 13 2 300 20260908113506 20260906093506 34505 cloudflare.com. YQGLdNWiEvMvQp+Zrz7+k0jBma9ocT1aWNTaLo8Pl47GHjdFdNdm6cMV5ZdK/CTQKBh1dljb97pgvWlgC8f59w==").(*dns.RRSIG)
	rrset := []dns.RR{
		mustRR(`cloudflare.com. 300 IN CAA 0 iodef "mailto:tls-abuse@cloudflare.com"`),
		mustRR(`cloudflare.com. 300 IN CAA 0 issue "comodoca.com"`),
		mustRR(`cloudflare.com. 300 IN CAA 0 issue "digicert.com; cansignhttpexchanges=yes"`),
		mustRR(`cloudflare.com. 300 IN CAA 0 issue "letsencrypt.org"`),
		mustRR(`cloudflare.com. 300 IN CAA 0 issue "pki.goog; cansignhttpexchanges=yes"`),
		mustRR(`cloudflare.com. 300 IN CAA 0 issue "ssl.com"`),
		mustRR(`cloudflare.com. 300 IN CAA 0 issuewild "comodoca.com"`),
		mustRR(`cloudflare.com. 300 IN CAA 0 issuewild "digicert.com; cansignhttpexchanges=yes"`),
		mustRR(`cloudflare.com. 300 IN CAA 0 issuewild "letsencrypt.org"`),
		mustRR(`cloudflare.com. 300 IN CAA 0 issuewild "pki.goog; cansignhttpexchanges=yes"`),
		mustRR(`cloudflare.com. 300 IN CAA 0 issuewild "ssl.com"`),
	}
	now := time.Date(2026, time.September, 7, 10, 0, 0, 0, time.UTC)

	res, err := VerifyRRSet(rrset, []*dns.RRSIG{sig}, []*dns.DNSKEY{key}, now)
	if res != Secure {
		t.Fatalf("VerifyRRSet() = %v (%v), want Secure", res, err)
	}
}

// Validation is read-only. The vendored crypto helper canonicalizes records,
// restores their original TTL, sorts the RRset, and temporarily clears the
// RRSIG in place. Calling it directly would both alter the answer returned to
// a client and race when cached DNSKEY/denial material is shared by requests.
func TestVerifyRRSetDoesNotMutateItsInputs(t *testing.T) {
	z := newZone(t, "example.test.")
	now := time.Now()
	signed := []dns.RR{&dns.CNAME{
		Hdr:   dns.Header{Name: "alias.example.test.", Class: dns.ClassINET, TTL: 300},
		CNAME: rdata.CNAME{Target: "target.example.test."},
	}}
	sig := z.sign(signed, now.Add(-time.Hour), now.Add(time.Hour))

	response := []dns.RR{&dns.CNAME{
		Hdr:   dns.Header{Name: "Alias.Example.Test.", Class: dns.ClassINET, TTL: 42},
		CNAME: rdata.CNAME{Target: "Target.Example.Test."},
	}}
	sig.Hdr.Name = "Alias.Example.Test."
	sig.Hdr.TTL = 42
	key := *z.key
	key.Tag = 0
	beforeRR := response[0].String()
	beforeSig := sig.String()

	res, err := VerifyRRSet(response, []*dns.RRSIG{sig}, []*dns.DNSKEY{&key}, now)
	if res != Secure || err != nil {
		t.Fatalf("VerifyRRSet() = %v (%v), want Secure", res, err)
	}
	if got := response[0].String(); got != beforeRR {
		t.Fatalf("record mutated during verification:\n before %s\n after  %s", beforeRR, got)
	}
	if got := sig.String(); got != beforeSig {
		t.Fatalf("signature mutated during verification:\n before %s\n after  %s", beforeSig, got)
	}
	if key.Tag != 0 {
		t.Fatalf("DNSKEY tag cache mutated during verification: %d", key.Tag)
	}
}

func TestVerifyRRSetSafelySharesCachedInputsAcrossRequests(t *testing.T) {
	z := newZone(t, "example.test.")
	now := time.Now()
	rrset := []dns.RR{aRecord("www.example.test.", "192.0.2.1")}
	sig := z.sign(rrset, now.Add(-time.Hour), now.Add(time.Hour))
	key := *z.key
	key.Tag = 0

	const workers = 16
	const iterations = 20
	errs := make(chan error, workers)
	var wg sync.WaitGroup
	for range workers {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for range iterations {
				res, err := VerifyRRSet(rrset, []*dns.RRSIG{sig}, []*dns.DNSKEY{&key}, now)
				if res != Secure || err != nil {
					errs <- fmt.Errorf("VerifyRRSet() = %v (%v)", res, err)
					return
				}
			}
		}()
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		t.Fatal(err)
	}
	if key.Tag != 0 {
		t.Fatalf("shared key tag cache mutated: %d", key.Tag)
	}
}

// RFC 9905 section 2 requires an operator's validating resolver to treat
// RSASHA1 and RSASHA1-NSEC3-SHA1 signing algorithms as unsupported even while
// the implementation retains the ability to verify them. A cryptographically
// genuine signature made only with either deprecated algorithm therefore
// renders the RRset Insecure, never Secure.
func TestDeprecatedRSASHA1SignaturesAreInsecure(t *testing.T) {
	for _, algorithm := range []uint8{dns.RSASHA1, dns.RSASHA1NSEC3SHA1} {
		t.Run(dns.AlgorithmToString[algorithm], func(t *testing.T) {
			z := newZoneWithAlgorithm(t, "example.test.", algorithm)
			rrset := []dns.RR{aRecord("www.example.test.", "192.0.2.1")}
			now := time.Now()
			sig := z.sign(rrset, now.Add(-time.Hour), now.Add(time.Hour))

			res, err := VerifyRRSet(rrset, []*dns.RRSIG{sig}, []*dns.DNSKEY{z.key}, now)
			if res != Insecure {
				t.Fatalf("VerifyRRSet() = %v (%v), want Insecure", res, err)
			}
		})
	}
}

func TestDeprecatedSignaturePolicyStillAcceptsAnotherValidAlgorithm(t *testing.T) {
	deprecated := newZoneWithAlgorithm(t, "example.test.", dns.RSASHA1)
	accepted := newZone(t, "example.test.")
	rrset := []dns.RR{aRecord("www.example.test.", "192.0.2.1")}
	now := time.Now()

	res, err := VerifyRRSet(rrset, []*dns.RRSIG{
		deprecated.sign(rrset, now.Add(-time.Hour), now.Add(time.Hour)),
		accepted.sign(rrset, now.Add(-time.Hour), now.Add(time.Hour)),
	}, []*dns.DNSKEY{deprecated.key, accepted.key}, now)
	if res != Secure {
		t.Fatalf("VerifyRRSet() = %v (%v), want Secure from the accepted algorithm", res, err)
	}
}

// RFC 6840 section 5.12: an extra RRSIG whose algorithm/key does not exist in
// the authenticated DNSKEY RRset is ignored. It must not let an attacker turn
// a missing accepted signature into an Insecure policy result.
func TestUnknownExtraSignatureDoesNotDowngradeAnRRSet(t *testing.T) {
	z := newZone(t, "example.test.")
	rrset := []dns.RR{aRecord("www.example.test.", "192.0.2.1")}
	sig := &dns.RRSIG{
		Hdr: dns.Header{Name: "www.example.test.", Class: dns.ClassINET, TTL: 300},
		RRSIG: rdata.RRSIG{
			TypeCovered: dns.TypeA,
			Algorithm:   99,
			Labels:      3,
			KeyTag:      12345,
			SignerName:  "example.test.",
		},
	}

	res, err := VerifyRRSet(rrset, []*dns.RRSIG{sig}, []*dns.DNSKEY{z.key}, time.Now())
	if res != Indeterminate || !errors.Is(err, ErrNoSignature) {
		t.Fatalf("VerifyRRSet() = %v (%v), want Indeterminate/ErrNoSignature", res, err)
	}
}

func TestDeprecatedRevokedKeyCannotDowngradeOrdinaryRRSet(t *testing.T) {
	z := newZoneWithAlgorithm(t, "example.test.", dns.RSASHA1)
	z.key.Flags |= dns.FlagREVOKE
	rrset := []dns.RR{aRecord("www.example.test.", "192.0.2.1")}
	now := time.Now()
	sig := z.sign(rrset, now.Add(-time.Hour), now.Add(time.Hour))

	res, err := VerifyRRSet(rrset, []*dns.RRSIG{sig}, []*dns.DNSKEY{z.key}, now)
	if res != Indeterminate || !errors.Is(err, ErrNoSignature) {
		t.Fatalf("VerifyRRSet() = %v (%v), want Indeterminate/ErrNoSignature", res, err)
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

// RFC 6840 section 5.12: a signature from a key absent from the authenticated
// DNSKEY RRset is extra material, not evidence that the covered RRset is bad.
// The containing-zone caller will still reject a signed RRset with no usable
// signature, but the generic verifier must disregard this RRSIG first.
func TestVerifyRRSetIgnoresAForeignKey(t *testing.T) {
	real, attacker := newZone(t, "example.test."), newZone(t, "example.test.")
	rrset := []dns.RR{aRecord("www.example.test.", "192.0.2.1")}
	now := time.Now()
	sig := attacker.sign(rrset, now.Add(-time.Hour), now.Add(time.Hour))

	res, err := VerifyRRSet(rrset, []*dns.RRSIG{sig}, []*dns.DNSKEY{real.key}, now)
	if res != Indeterminate || !errors.Is(err, ErrNoSignature) {
		t.Fatalf("VerifyRRSet() with a foreign key = %v (%v), want Indeterminate/ErrNoSignature", res, err)
	}
}

// The validity window is meaningful only after the validator finds the
// corresponding DNSKEY. Checking it first lets an expired extra signature
// create a false Bogus result, contrary to RFC 6840 sections 5.4 and 5.12.
func TestVerifyRRSetIgnoresExpiredSignatureFromUnknownKey(t *testing.T) {
	real, retired := newZone(t, "example.test."), newZone(t, "example.test.")
	rrset := []dns.RR{aRecord("www.example.test.", "192.0.2.1")}
	now := time.Now()
	sig := retired.sign(rrset, now.Add(-48*time.Hour), now.Add(-24*time.Hour))

	res, err := VerifyRRSet(rrset, []*dns.RRSIG{sig}, []*dns.DNSKEY{real.key}, now)
	if res != Indeterminate || !errors.Is(err, ErrNoSignature) {
		t.Fatalf("VerifyRRSet() with an expired unknown-key signature = %v (%v), want Indeterminate/ErrNoSignature", res, err)
	}
}

func TestVerifyRRSetAcceptsValidSignatureAlongsideExpiredUnknownKey(t *testing.T) {
	current, retired := newZone(t, "example.test."), newZone(t, "example.test.")
	rrset := []dns.RR{aRecord("www.example.test.", "192.0.2.1")}
	now := time.Now()
	sigs := []*dns.RRSIG{
		retired.sign(rrset, now.Add(-48*time.Hour), now.Add(-24*time.Hour)),
		current.sign(rrset, now.Add(-time.Hour), now.Add(time.Hour)),
	}

	res, err := VerifyRRSet(rrset, sigs, []*dns.DNSKEY{current.key}, now)
	if res != Secure || err != nil {
		t.Fatalf("VerifyRRSet() with valid and expired-extra signatures = %v (%v), want Secure", res, err)
	}
}

// RFC 4035 erratum 8037 documents why an implementation may not let one
// RRset force an unbounded key/signature cross-product: doing so enabled the
// KeyTrap CPU-exhaustion attack.  Match Unbound's eight-cryptographic-check
// ceiling and fail closed before a ninth bad signature can consume more work.
func TestVerifyRRSetBoundsCryptographicWorkPerRRSet(t *testing.T) {
	z := newZone(t, "example.test.")
	rrset := []dns.RR{aRecord("www.example.test.", "192.0.2.1")}
	now := time.Now()
	valid := z.sign(rrset, now.Add(-time.Hour), now.Add(time.Hour))
	sigs := make([]*dns.RRSIG, 0, 9)
	for range 8 {
		bad := *valid
		bad.Signature = base64.StdEncoding.EncodeToString([]byte{0})
		sigs = append(sigs, &bad)
	}
	sigs = append(sigs, valid)

	res, err := VerifyRRSet(rrset, sigs, []*dns.DNSKEY{z.key}, now)
	if res != Bogus || err == nil || !strings.Contains(err.Error(), "too many") {
		t.Fatalf("VerifyRRSet() = %v (%v), want Bogus/too-many-validations", res, err)
	}
}

func TestVerifyRRSetAcceptsAValidSignatureWithinTheWorkLimit(t *testing.T) {
	z := newZone(t, "example.test.")
	rrset := []dns.RR{aRecord("www.example.test.", "192.0.2.1")}
	now := time.Now()
	valid := z.sign(rrset, now.Add(-time.Hour), now.Add(time.Hour))
	sigs := make([]*dns.RRSIG, 0, 8)
	for range 7 {
		bad := *valid
		bad.Signature = base64.StdEncoding.EncodeToString([]byte{0})
		sigs = append(sigs, &bad)
	}
	sigs = append(sigs, valid)

	res, err := VerifyRRSet(rrset, sigs, []*dns.DNSKEY{z.key}, now)
	if res != Secure || err != nil {
		t.Fatalf("VerifyRRSet() = %v (%v), want Secure at the work-limit boundary", res, err)
	}
}

// RFC 5702 section 2.2 requires RSA/SHA-512 DNSKEY moduli to be at least
// 1024 bits. The DNS library's generic RSA decoder accepts a 768-bit modulus,
// so the validator must not mistake such a key for a usable corresponding
// DNSKEY under RFC 6840 section 5.12.
func TestVerifyRRSetIgnoresRSASHA512KeyBelowRFCMinimum(t *testing.T) {
	key := dns.NewDNSKEY("example.test.", dns.RSASHA512)
	key.Hdr.TTL = 300
	key.Flags = dns.FlagZONE
	key.Protocol = 3
	// RFC 3110 encoding: one-byte exponent length, 65537, then a 768-bit
	// modulus. It is syntactically well formed but prohibited by RFC 5702.
	public := append([]byte{3, 1, 0, 1}, append([]byte{0x80}, make([]byte, 95)...)...)
	key.PublicKey = base64.StdEncoding.EncodeToString(public)

	rrset := []dns.RR{aRecord("www.example.test.", "192.0.2.1")}
	now := time.Now()
	sig := dns.NewRRSIG(key.Header().Name, key.Algorithm, key.KeyTag(),
		uint32(now.Add(-time.Hour).Unix()), uint32(now.Add(time.Hour).Unix()))
	sig.Hdr = dns.Header{Name: rrset[0].Header().Name, Class: dns.ClassINET, TTL: 300}
	sig.TypeCovered = dns.TypeA
	sig.Labels = 3
	sig.Signature = base64.StdEncoding.EncodeToString([]byte{0})

	res, err := VerifyRRSet(rrset, []*dns.RRSIG{sig}, []*dns.DNSKEY{key}, now)
	if res != Indeterminate || !errors.Is(err, ErrNoSignature) {
		t.Fatalf("VerifyRRSet() with a 768-bit RSA/SHA-512 key = %v (%v), want Indeterminate/ErrNoSignature", res, err)
	}
}

func TestRFC5702RSAKeySizeBoundaries(t *testing.T) {
	makeKey := func(algorithm uint8, modulusBits int) *dns.DNSKEY {
		modulus := make([]byte, (modulusBits+7)/8)
		modulus[0] = 1 << ((modulusBits - 1) % 8)
		modulus[len(modulus)-1] |= 1
		key := dns.NewDNSKEY("example.test.", algorithm)
		key.PublicKey = base64.StdEncoding.EncodeToString(append([]byte{3, 1, 0, 1}, modulus...))
		return key
	}

	for _, tc := range []struct {
		name      string
		algorithm uint8
		bits      int
		want      bool
	}{
		{"RSASHA256-511", dns.RSASHA256, 511, false},
		{"RSASHA256-512", dns.RSASHA256, 512, true},
		{"RSASHA256-4096", dns.RSASHA256, 4096, true},
		{"RSASHA256-4097", dns.RSASHA256, 4097, false},
		{"RSASHA512-1023", dns.RSASHA512, 1023, false},
		{"RSASHA512-1024", dns.RSASHA512, 1024, true},
		{"RSASHA512-4096", dns.RSASHA512, 4096, true},
		{"RSASHA512-4097", dns.RSASHA512, 4097, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := dnskeyMeetsAlgorithmConstraints(makeKey(tc.algorithm, tc.bits)); got != tc.want {
				t.Fatalf("dnskeyMeetsAlgorithmConstraints(%d bits) = %v, want %v", tc.bits, got, tc.want)
			}
		})
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
			res, err := VerifyRRSet(rrset, []*dns.RRSIG{sig}, []*dns.DNSKEY{z.key}, now)
			if res != Bogus {
				t.Fatalf("VerifyRRSet() = %v, want bogus", res)
			}
			if !errors.Is(err, ErrSignatureOutsideValidity) {
				t.Fatalf("VerifyRRSet() error = %v, want ErrSignatureOutsideValidity", err)
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

// RFC 4035 section 5.3.1 requires the signer name to be the zone containing
// the DNSKEY RRset, even if the bytes happen to verify under an anchored key.
func TestVerifyDNSKEYsRejectsASignatureFromAnotherZone(t *testing.T) {
	z := newZone(t, "example.test.")
	keys := []*dns.DNSKEY{z.key}
	rrset := []dns.RR{z.key}
	now := time.Now()
	sig := z.signAs("other.test.", rrset, now.Add(-time.Hour), now.Add(time.Hour))

	res, _ := VerifyDNSKEYs(keys, []*dns.RRSIG{sig}, []*dns.DS{z.key.ToDS(dns.SHA256)}, now)
	if res != Bogus {
		t.Fatalf("VerifyDNSKEYs() with another signer zone = %v, want bogus", res)
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

// Once a supported DS has authenticated a key, the child is known to be a
// signed delegation. RFC 4035 sections 2.2 and 5.5 require its apex DNSKEY
// RRset to have a usable RRSIG and classify the response BAD when none can be
// validated. The generic RRset helper cannot know that, but VerifyDNSKEYs can.
func TestSupportedDelegationWithoutDNSKEYSignatureIsBogus(t *testing.T) {
	z := newZone(t, "example.test.")
	ds := z.key.ToDS(dns.SHA256)

	res, err := VerifyDNSKEYs([]*dns.DNSKEY{z.key}, nil, []*dns.DS{ds}, time.Now())
	if res != Bogus {
		t.Fatalf("result = %v (%v), want Bogus", res, err)
	}
}

// An RRSIG over another RR type does not satisfy the DNSKEY RRset's signature
// requirement. This is the same authenticated failure as omitting the RRSIG,
// not a transport ambiguity.
func TestSupportedDelegationWithoutCoveringDNSKEYSignatureIsBogus(t *testing.T) {
	z := newZone(t, "example.test.")
	ds := z.key.ToDS(dns.SHA256)
	rrset := []dns.RR{aRecord("example.test.", "192.0.2.1")}
	now := time.Now()
	unrelated := z.sign(rrset, now.Add(-time.Hour), now.Add(time.Hour))

	res, err := VerifyDNSKEYs([]*dns.DNSKEY{z.key}, []*dns.RRSIG{unrelated}, []*dns.DS{ds}, now)
	if res != Bogus {
		t.Fatalf("result = %v (%v), want Bogus", res, err)
	}
}

// RFC 4035 section 5.2 and RFC 6840 section 5.2 apply the same rule to the
// public-key algorithm named by a DS as to an unsupported DS digest: the DS is
// disregarded, and a delegation with no supported DS left is treated unsigned.
func TestDelegationWithUnsupportedKeyAlgorithmIsInsecureNotBogus(t *testing.T) {
	z := newZone(t, "example.test.")
	unsupported := *z.key
	unsupported.Algorithm = 99
	unsupported.Tag = 0
	ds := unsupported.ToDS(dns.SHA256)
	if ds == nil {
		t.Fatal("construct DS for unsupported public-key algorithm")
	}

	res, err := VerifyDNSKEYs([]*dns.DNSKEY{&unsupported}, nil, []*dns.DS{ds}, time.Now())
	if res != Insecure {
		t.Fatalf("result = %v (%v), want Insecure", res, err)
	}
}

// RFC 9905 section 2 requires resolver operators to treat algorithm 5
// (RSASHA1) and algorithm 7 (RSASHA1-NSEC3-SHA1) DS records as unsupported.
// The implementation still retains verification support for interoperability;
// this is the delegation policy that prevents those algorithms establishing a
// secure chain on their own.
func TestDeprecatedRSASHA1DelegationsAreInsecure(t *testing.T) {
	for _, algorithm := range []uint8{dns.RSASHA1, dns.RSASHA1NSEC3SHA1} {
		t.Run(dns.AlgorithmToString[algorithm], func(t *testing.T) {
			z := newZone(t, "example.test.")
			key := *z.key
			key.Algorithm = algorithm
			key.Tag = 0
			ds := key.ToDS(dns.SHA256)
			if ds == nil {
				t.Fatal("construct deprecated-algorithm DS fixture")
			}

			res, err := VerifyDNSKEYs([]*dns.DNSKEY{&key}, nil, []*dns.DS{ds}, time.Now())
			if res != Insecure {
				t.Fatalf("result = %v (%v), want Insecure", res, err)
			}
		})
	}
}

// RFC 9904 makes the IANA registry canonical. Digest value 5 is GOST
// R 34.11-2012 there; this pinned DNS library still calls the same numeric
// value experimental SHA-512 and can compute the wrong digest for it. It is
// therefore unsupported until the library implements the registered meaning.
func TestRegisteredDigestFiveIsNotMistakenForLibrarySHA512(t *testing.T) {
	z := newZone(t, "example.test.")
	ds := z.key.ToDS(5)
	if ds == nil {
		t.Fatal("construct dependency's legacy digest-5 DS fixture")
	}

	res, err := VerifyDNSKEYs([]*dns.DNSKEY{z.key}, nil, []*dns.DS{ds}, time.Now())
	if res != Insecure {
		t.Fatalf("result = %v (%v), want Insecure", res, err)
	}
}

// Unsupported DS records are ignored, not allowed to hide a failure through a
// different DS record whose algorithms this validator does support.
func TestUnsupportedDelegationDoesNotMaskSupportedMismatch(t *testing.T) {
	z := newZone(t, "example.test.")
	badSupported := z.key.ToDS(dns.SHA256)
	badSupported.Digest = "0000000000000000000000000000000000000000000000000000000000000000"

	unsupported := *z.key
	unsupported.Algorithm = 99
	unsupported.Tag = 0
	unsupportedDS := unsupported.ToDS(dns.SHA256)
	if unsupportedDS == nil {
		t.Fatal("construct DS for unsupported public-key algorithm")
	}

	res, err := VerifyDNSKEYs(
		[]*dns.DNSKEY{z.key, &unsupported},
		nil,
		[]*dns.DS{unsupportedDS, badSupported},
		time.Now(),
	)
	if res != Bogus {
		t.Fatalf("result = %v (%v), want Bogus", res, err)
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

func cnameRecord(name, target string) dns.RR {
	return &dns.CNAME{
		Hdr:   dns.Header{Name: name, Class: dns.ClassINET, TTL: 300},
		CNAME: rdata.CNAME{Target: target},
	}
}

// The answer to a CNAME is two RRsets: the alias, and what it points at. No
// single signature covers both, so checking the answer as one set finds nothing
// that covers it -- which is indistinguishable from an answer carrying no
// signature at all, and would be refused under enforcement.
func TestGroupRRSetsSeparatesACNAMEChain(t *testing.T) {
	z := newZone(t, "example.test.")
	now := time.Now()

	alias := []dns.RR{cnameRecord("www.example.test.", "host.example.test.")}
	target := []dns.RR{aRecord("host.example.test.", "192.0.2.1")}
	aliasSig := z.sign(alias, now.Add(-time.Hour), now.Add(time.Hour))
	targetSig := z.sign(target, now.Add(-time.Hour), now.Add(time.Hour))

	answer := []dns.RR{alias[0], aliasSig, target[0], targetSig}

	// The whole answer as one set: no signature covers it.
	all, sigs := SplitSignatures(answer)
	if res, err := VerifyRRSet(all, sigs, []*dns.DNSKEY{z.key}, now); res == Secure {
		t.Fatal("a mixed answer verified as one set; this test no longer covers the bug")
	} else if err != ErrNoSignature {
		t.Logf("mixed set failed with %v (still not Secure, which is the point)", err)
	}

	// Taken apart, each set carries its own signature and verifies.
	sets := GroupRRSets(answer)
	if len(sets) != 2 {
		t.Fatalf("groups = %d, want 2 (the alias and its target)", len(sets))
	}
	for _, set := range sets {
		res, err := VerifyRRSet(set.Records, set.Sigs, []*dns.DNSKEY{z.key}, now)
		if res != Secure {
			t.Errorf("%s %s: result = %v (%v), want Secure",
				set.Name, dns.TypeToString[set.Type], res, err)
		}
	}
}

// Grouping must not become a way to smuggle records past verification: a set
// with no signature of its own still has none after the answer is split up.
func TestGroupRRSetsDoesNotInventSignatures(t *testing.T) {
	z := newZone(t, "example.test.")
	now := time.Now()

	signed := []dns.RR{aRecord("host.example.test.", "192.0.2.1")}
	sig := z.sign(signed, now.Add(-time.Hour), now.Add(time.Hour))
	// Injected alongside a legitimately signed set, carrying nothing of its own.
	unsigned := aRecord("evil.example.test.", "203.0.113.1")

	sets := GroupRRSets([]dns.RR{signed[0], sig, unsigned})
	var checked bool
	for _, set := range sets {
		if set.Name != "evil.example.test." {
			continue
		}
		checked = true
		if len(set.Sigs) != 0 {
			t.Errorf("an unsigned set was handed %d signature(s)", len(set.Sigs))
		}
		if res, _ := VerifyRRSet(set.Records, set.Sigs, []*dns.DNSKEY{z.key}, now); res == Secure {
			t.Error("an unsigned set verified as secure")
		}
	}
	if !checked {
		t.Fatal("the injected set was not grouped at all")
	}
}

// RFC 4035 section 5.3.1: a signature claiming more labels than the name it
// covers cannot have been made over that name.
func TestSignatureClaimingMoreLabelsThanTheNameIsNotAccepted(t *testing.T) {
	z := newZone(t, "example.test.")
	now := time.Now()
	rrset := []dns.RR{aRecord("www.example.test.", "192.0.2.1")}
	sig := z.sign(rrset, now.Add(-time.Hour), now.Add(time.Hour))
	sig.Labels = 9 // far more than "www.example.test." has

	if res, _ := VerifyRRSet(rrset, []*dns.RRSIG{sig}, []*dns.DNSKEY{z.key}, now); res == Secure {
		t.Error("a signature claiming more labels than the owner name verified")
	}
}

// RFC 4035 section 5.3.3: a signature over a wildcard verifies for every name
// beneath it. Without noticing the expansion, a validator accepts a wildcard
// signature as the answer for a name that has a record of its own -- which is a
// forged answer that verifies.
func TestWildcardExpansionIsReportedWithTheNameToDisprove(t *testing.T) {
	z := newZone(t, "example.test.")
	now := time.Now()

	// Signed the way a zone signs a wildcard: over "*.example.test.".
	wildcard := []dns.RR{aRecord("*.example.test.", "192.0.2.1")}
	sig := z.sign(wildcard, now.Add(-time.Hour), now.Add(time.Hour))
	t.Logf("signature over the wildcard has Labels=%d", sig.Labels)

	// Served the way a resolver returns it: the records and the signature both
	// under the name that was asked, with only Labels betraying the expansion.
	expanded := []dns.RR{aRecord("anything.example.test.", "192.0.2.1")}
	sig.Hdr.Name = "anything.example.test."

	res, verified, err := VerifyRRSetDetail(expanded, []*dns.RRSIG{sig}, []*dns.DNSKEY{z.key}, now)
	if res != Secure {
		t.Fatalf("a genuine wildcard answer did not verify: %v (%v) -- "+
			"if the library does not reconstruct the wildcard owner, real "+
			"wildcard answers would be refused under enforcement", res, err)
	}
	nextCloser, wasWildcard := WildcardNextCloser(verified, "anything.example.test.")
	if !wasWildcard {
		t.Fatal("a wildcard expansion went unnoticed, so no proof would be demanded for it")
	}
	if nextCloser != "anything.example.test." {
		t.Errorf("next closer = %q, want anything.example.test.", nextCloser)
	}
}

// RFC 6840 section 5.4 says any valid RRSIG is sufficient. If an RRset has
// both a valid exact-owner signature and a valid wildcard signature, return
// the exact signature even when the wildcard is listed first: the exact path
// needs no denial proof and must not be rejected because the other valid path
// would need one.
func TestVerifyRRSetPrefersAValidExactSignatureOverAWildcardSignature(t *testing.T) {
	z := newZone(t, "example.test.")
	now := time.Now()
	expanded := []dns.RR{aRecord("www.example.test.", "192.0.2.1")}
	wildcard := []dns.RR{aRecord("*.example.test.", "192.0.2.1")}
	wildcardSig := z.sign(wildcard, now.Add(-time.Hour), now.Add(time.Hour))
	wildcardSig.Hdr.Name = expanded[0].Header().Name
	exactSig := z.sign(expanded, now.Add(-time.Hour), now.Add(time.Hour))

	res, verified, err := VerifyRRSetDetail(
		expanded,
		[]*dns.RRSIG{wildcardSig, exactSig},
		[]*dns.DNSKEY{z.key},
		now,
	)
	if res != Secure || err != nil {
		t.Fatalf("VerifyRRSetDetail() = %v (%v), want Secure", res, err)
	}
	if verified != exactSig {
		t.Fatal("wildcard signature was preferred over the available exact signature")
	}
}

// A literal query for an existing wildcard owner is an exact-owner answer,
// not wildcard synthesis. Its RRSIG Labels field still omits the leading "*"
// (RFC 4034 section 3.1.3), so label count alone cannot distinguish the two.
// Requiring denial for the exact owner would demand proof that an owner whose
// signed data we just authenticated does not exist.
func TestLiteralWildcardOwnerIsNotReportedAsExpansion(t *testing.T) {
	z := newZone(t, "example.test.")
	now := time.Now()
	wildcard := []dns.RR{aRecord("*.example.test.", "192.0.2.1")}
	sig := z.sign(wildcard, now.Add(-time.Hour), now.Add(time.Hour))

	res, verified, err := VerifyRRSetDetail(wildcard, []*dns.RRSIG{sig}, []*dns.DNSKEY{z.key}, now)
	if res != Secure {
		t.Fatalf("literal wildcard owner did not verify: %v (%v)", res, err)
	}
	if nextCloser, expanded := WildcardNextCloser(verified, "*.example.test."); expanded {
		t.Fatalf("literal wildcard owner was reported as expansion needing denial of %s", nextCloser)
	}

	// A query name may itself start with a literal star and still have been
	// synthesized by a higher wildcard; compare reconstructed owners instead
	// of treating every leading star as exact.
	expandedName := "*.child.example.test."
	expanded := []dns.RR{aRecord(expandedName, "192.0.2.1")}
	sig.Hdr.Name = expandedName
	res, verified, err = VerifyRRSetDetail(expanded, []*dns.RRSIG{sig}, []*dns.DNSKEY{z.key}, now)
	if res != Secure {
		t.Fatalf("star-prefixed wildcard expansion did not verify: %v (%v)", res, err)
	}
	if nextCloser, wasExpanded := WildcardNextCloser(verified, expandedName); !wasExpanded || nextCloser != "child.example.test." {
		t.Fatalf("star-prefixed expansion = (%q, %v), want (child.example.test., true)", nextCloser, wasExpanded)
	}
}

// The ordinary case must not be dragged into the wildcard path: a signature
// made over the name itself demands no extra proof.
func TestAnOrdinarySignatureIsNotTreatedAsAWildcard(t *testing.T) {
	z := newZone(t, "example.test.")
	now := time.Now()
	rrset := []dns.RR{aRecord("www.example.test.", "192.0.2.1")}
	sig := z.sign(rrset, now.Add(-time.Hour), now.Add(time.Hour))

	if _, expanded := WildcardNextCloser(sig, "www.example.test."); expanded {
		t.Error("a signature over the name itself was taken for a wildcard expansion")
	}
}

// RFC 4034 section 2.1.2: protocol values other than 3 mean the key is not for
// DNSSEC, and it must not be used as though it were.
func TestKeyWithAWrongProtocolIsNotUsed(t *testing.T) {
	z := newZone(t, "example.test.")
	now := time.Now()
	rrset := []dns.RR{aRecord("www.example.test.", "192.0.2.1")}
	sig := z.sign(rrset, now.Add(-time.Hour), now.Add(time.Hour))

	z.key.Protocol = 2
	if res, _ := VerifyRRSet(rrset, []*dns.RRSIG{sig}, []*dns.DNSKEY{z.key}, now); res == Secure {
		t.Error("a key with a non-DNSSEC protocol value was used to verify")
	}
}

// RFC 5011 section 2.1: once a DNSKEY carries REVOKE, it is unusable for
// ordinary data.  Its sole exception is authenticating its self-signature on
// the DNSKEY RRset so that the revocation can itself be validated.
func TestRevokedKeyIsUsedOnlyForItsDNSKEYSelfSignature(t *testing.T) {
	z := newZone(t, "example.test.")
	z.key.Flags |= dns.FlagREVOKE
	now := time.Now()

	ordinary := []dns.RR{aRecord("www.example.test.", "192.0.2.1")}
	ordinarySig := z.sign(ordinary, now.Add(-time.Hour), now.Add(time.Hour))
	if res, _ := VerifyRRSet(ordinary, []*dns.RRSIG{ordinarySig}, []*dns.DNSKEY{z.key}, now); res == Secure {
		t.Fatal("a revoked DNSKEY authenticated ordinary zone data")
	}

	keySet := []dns.RR{z.key}
	selfSig := z.sign(keySet, now.Add(-time.Hour), now.Add(time.Hour))
	if res, err := VerifyRRSet(keySet, []*dns.RRSIG{selfSig}, []*dns.DNSKEY{z.key}, now); res != Secure {
		t.Fatalf("revocation self-signature result = %v (%v), want Secure", res, err)
	}
}

// A matching key for an algorithm the validator implements is part of a
// claimed chain. Malformed key material makes that chain Bogus; it must never
// be reclassified as an unsupported-algorithm Insecure delegation.
func TestMalformedSupportedKeyIsBogusNotInsecure(t *testing.T) {
	z := newZone(t, "example.test.")
	now := time.Now()
	rrset := []dns.RR{aRecord("www.example.test.", "192.0.2.1")}
	sig := z.sign(rrset, now.Add(-time.Hour), now.Add(time.Hour))

	malformed := *z.key
	// Keep the DNSKEY wire format and key tag computable while supplying an
	// impossibly short ECDSA public point, so verification reaches the key
	// parser rather than taking the unrelated no-matching-key branch. Tag is a
	// library-side cache and is deliberately not trusted as wire data.
	malformed.PublicKey = base64.StdEncoding.EncodeToString([]byte{1, 2, 3})
	malformed.Tag = 0
	sig.KeyTag = immutableDNSKEYTag(&malformed)

	res, err := VerifyRRSet(rrset, []*dns.RRSIG{sig}, []*dns.DNSKEY{&malformed}, now)
	if res != Bogus {
		t.Fatalf("result = %v (%v), want Bogus", res, err)
	}
}

// RFC 9276 section 3.2 / RFC 5155 section 10.3: the hashing is per query and
// the count is chosen by the zone, so it has to be bounded.
func TestNSEC3IterationsAreBounded(t *testing.T) {
	if h := NSEC3Hash("example.test.", 1, maxNSEC3Iterations+1, ""); h != "" {
		t.Error("a zone asking for more iterations than the limit was hashed anyway")
	}
	if h := NSEC3Hash("example.test.", 1, 0, ""); h == "" {
		t.Error("the ordinary case should still hash")
	}
}

// RFC 4035 section 5.3.3: an answer may not be used beyond the expiration of
// the signature that vouches for it. A cache that carries the verdict with the
// entry would otherwise keep serving a verdict that had stopped being true.
func TestEarliestSignatureExpiryFindsTheFirstOneToGo(t *testing.T) {
	z := newZone(t, "example.test.")
	now := time.Now()

	soon := []dns.RR{aRecord("a.example.test.", "192.0.2.1")}
	later := []dns.RR{aRecord("b.example.test.", "192.0.2.2")}
	soonSig := z.sign(soon, now.Add(-time.Hour), now.Add(10*time.Minute))
	laterSig := z.sign(later, now.Add(-time.Hour), now.Add(10*time.Hour))

	at, ok := EarliestSignatureExpiry(now, []dns.RR{soon[0], laterSig}, []dns.RR{later[0], soonSig})
	if !ok {
		t.Fatal("no signature was found among records that carry two")
	}
	if d := at.Sub(now); d > 11*time.Minute || d < 9*time.Minute {
		t.Errorf("earliest expiry is %v away, want about 10 minutes", d)
	}
}

// Records with nothing signing them place no bound, and must not be reported as
// if they expired at the epoch.
func TestEarliestSignatureExpiryReportsWhenThereIsNone(t *testing.T) {
	rrs := []dns.RR{aRecord("a.example.test.", "192.0.2.1")}
	if _, ok := EarliestSignatureExpiry(time.Now(), rrs); ok {
		t.Error("an unsigned answer was reported as having a signature expiry")
	}
}

// The field wraps, so it is read as a distance from now rather than an absolute
// second count: a signature valid across the 2106 wrap must not read as expired.
func TestSignatureExpiryIsReadAsADistanceNotAnAbsolute(t *testing.T) {
	// A moment shortly before the 32-bit wrap, with a signature expiring after it.
	now := time.Unix(int64(^uint32(0))-60, 0)
	sig := &dns.RRSIG{RRSIG: rdata.RRSIG{Expiration: uint32(60)}} // already wrapped

	at := SignatureExpiry(sig, now)
	if !at.After(now) {
		t.Errorf("a signature expiring after the wrap read as %v, before now %v", at, now)
	}
	if d := at.Sub(now); d > 3*time.Minute {
		t.Errorf("expiry is %v away, want about two minutes", d)
	}
}
