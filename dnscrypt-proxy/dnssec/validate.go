// Package dnssec verifies the signatures on a DNS answer against the chain of
// keys leading back to a trust anchor.
//
// It answers one question -- whether an answer is what the zone's owner
// published -- and answers it in three ways, because "not signed" and "signed
// wrongly" are different situations and only one of them is an attack.
package dnssec

import (
	"encoding/base64"
	"errors"
	"fmt"
	"math/bits"
	"strings"
	"time"

	"codeberg.org/miekg/dns"
)

// Result is what verification concluded about an answer.
type Result int

const (
	// Indeterminate: nothing was concluded, because the inputs did not allow a
	// conclusion. Reporting mode can serve it with no AD claim; enforcing mode
	// must treat it as a validation failure unless the client set CD.
	Indeterminate Result = iota
	// Insecure: the zone is genuinely unsigned, proven or assumed by the caller.
	// The ordinary state of most of the internet, and not a failure.
	Insecure
	// Secure: every record checked carried a signature that verified against a
	// key the chain reaches.
	Secure
	// Bogus: at least one applicable signature exists but none verifies, or an
	// applicable signature is outside its validity. Signatures with no
	// corresponding authenticated DNSKEY are ignored (RFC 6840 section 5.12).
	// This is the case worth refusing: an answer that claims to be signed and
	// is not what the zone published.
	Bogus
)

func (r Result) String() string {
	switch r {
	case Insecure:
		return "insecure"
	case Secure:
		return "secure"
	case Bogus:
		return "bogus"
	default:
		return "indeterminate"
	}
}

// ErrNoSignature reports that an RRset carried no RRSIG at all. Whether that is
// Insecure or Bogus depends on the delegation above it, which this package does
// not know on its own -- the caller decides.
var ErrNoSignature = fmt.Errorf("rrset carries no signature")

// ErrSignatureOutsideValidity reports that an RRSIG was otherwise applicable
// but is not valid at the validator's current time. RFC 4035 section 5.3.3
// makes that response Bogus; callers may nevertheless obtain a fresh answer
// from another recursive upstream, because a relay serving stale cache data is
// not evidence that the zone itself published bad data.
var ErrSignatureOutsideValidity = errors.New("signature is outside its validity")

// ErrUnsupportedSignatureAlgorithm reports that every otherwise relevant
// signature used an algorithm disabled by resolver policy. RFC 9905 section 2
// requires operators to treat RSASHA1 and RSASHA1-NSEC3-SHA1 this way even
// though implementations must retain the code needed to verify them.
var ErrUnsupportedSignatureAlgorithm = errors.New("unsupported DNSSEC signing algorithm")

// VerifyRRSet reports whether rrset is covered by a signature that verifies
// against one of keys and is valid at now.
//
// A signature is accepted on the first key that verifies it. Several keys can
// carry the same tag -- the tag is a checksum, not an identifier -- so a key
// that fails is a reason to try the next one, not to conclude anything.
func VerifyRRSet(rrset []dns.RR, sigs []*dns.RRSIG, keys []*dns.DNSKEY, now time.Time) (Result, error) {
	res, _, err := VerifyRRSetDetail(rrset, sigs, keys, now)
	return res, err
}

// covers reports whether sig is a signature over this rrset -- same owner, same
// class, same type. A signature over something else is not evidence about this.
func covers(sig *dns.RRSIG, rrset []dns.RR) bool {
	h := rrset[0].Header()
	if !dns.EqualName(sig.Header().Name, h.Name) || sig.Header().Class != h.Class {
		return false
	}
	if sig.TypeCovered != dns.RRToType(rrset[0]) {
		return false
	}
	// RFC 4035 section 5.3.1: a signature claiming more labels than the name it
	// covers has cannot have been made over that name.
	if int(sig.Labels) > CountLabels(h.Name) {
		return false
	}
	// Every record of an RRset shares owner, class and type; a caller that
	// mixes them would otherwise have part of the set silently unverified.
	for _, rr := range rrset[1:] {
		hh := rr.Header()
		if dns.RRToType(rr) != sig.TypeCovered || hh.Class != h.Class || !dns.EqualName(hh.Name, h.Name) {
			return false
		}
	}
	return true
}

// ValidAt reports whether now falls within the signature's validity.
//
// The timestamps are serial numbers rather than absolute seconds (RFC 4034
// section 3.1.5), so they are compared modulo 2^32 against the current time.
// Comparing them as plain integers works only until 2106 and breaks early for
// any zone that signs across the wrap.
func ValidAt(sig *dns.RRSIG, now time.Time) bool {
	ts := uint32(now.Unix())
	return serialLE(sig.Inception, ts) && serialLE(ts, sig.Expiration)
}

// serialLE reports a <= b in serial arithmetic (RFC 1982).
func serialLE(a, b uint32) bool {
	return b-a < 1<<31
}

// VerifyDNSKEYs reports whether a zone's DNSKEY set is the one the parent
// delegated to, and returns the keys that may sign the zone's records.
//
// Two things have to hold, and both are load-bearing: some key in the set must
// hash to a DS the parent published, and the set itself must be signed by a key
// in the set. The first ties the zone to its parent; the second stops a key
// that the parent never vouched for from being smuggled into the set.
func VerifyDNSKEYs(keys []*dns.DNSKEY, sigs []*dns.RRSIG, dss []*dns.DS, now time.Time) (Result, error) {
	if len(keys) == 0 {
		return Indeterminate, fmt.Errorf("no keys offered")
	}
	if len(dss) == 0 {
		return Indeterminate, fmt.Errorf("no delegation signer to anchor against")
	}

	// Whether the parent published a delegation signer this build can follow at
	// all. RFC 4035 section 5.2 and RFC 6840 section 5.2 require a validator to
	// disregard DS records whose public-key algorithm or digest algorithm it
	// cannot check. If none remain, the child is treated as unsigned rather than
	// forged: refusing it would take zones off the air as algorithms turn over.
	//
	// Deliberately independent of whether any key matches. A key the parent
	// never delegated is forged, and must stay refused -- that is the case this
	// whole function exists for.
	checkable := false
	for _, ds := range dss {
		if acceptedDNSKEYAlgorithm(ds.Algorithm) && supportedDSDigest(ds.DigestType) {
			checkable = true
			break
		}
	}

	anchored := make([]*dns.DNSKEY, 0, len(keys))
	for _, key := range keys {
		for _, ds := range dss {
			if !acceptedDNSKEYAlgorithm(ds.Algorithm) || !supportedDSDigest(ds.DigestType) {
				continue
			}
			if key.KeyTag() != ds.KeyTag || key.Algorithm != ds.Algorithm {
				continue
			}
			computed := key.ToDS(ds.DigestType)
			if computed == nil {
				// A digest this build cannot compute is not a mismatch; it
				// simply proves nothing.
				continue
			}
			if equalFold(computed.Digest, ds.Digest) {
				anchored = append(anchored, key)
				break
			}
		}
	}
	if len(anchored) == 0 {
		if !checkable {
			return Insecure, fmt.Errorf("no delegation signer this build can check")
		}
		return Bogus, fmt.Errorf("no offered key matches the delegation signer")
	}

	zone := keys[0].Header().Name
	rrset := make([]dns.RR, 0, len(keys))
	for _, key := range keys {
		if !dns.EqualName(key.Header().Name, zone) {
			return Bogus, fmt.Errorf("DNSKEY set mixes zones %s and %s", zone, key.Header().Name)
		}
		rrset = append(rrset, key)
	}
	// RFC 4035 section 5.3.1 requires the RRSIG Signer's Name to name the
	// zone containing the RRset. The cryptographic check alone cannot enforce
	// that: a key can sign an otherwise valid RRSIG carrying another name.
	zoneSigs := signaturesFromZone(sigs, zone)
	// Verified against the anchored keys only: a self-signature by an unanchored
	// key would let the set vouch for itself.
	res, err := VerifyRRSet(rrset, zoneSigs, anchored, now)
	if res != Secure && hasCoveringSignatureFromAnotherZone(rrset, sigs, zone) {
		return Bogus, fmt.Errorf("key set has a signature from another zone")
	}
	if res != Secure {
		// At this point a supported DS has authenticated at least one key in
		// this DNSKEY RRset.  The generic RRset verifier reports a missing or
		// non-covering RRSIG as Indeterminate because it has no delegation
		// context of its own.  We do: RFC 4035 sections 2.2 and 5.5 require the
		// apex DNSKEY RRset to carry a usable signature and classify the answer
		// BAD when none validates.  Preserve that as Bogus instead of inflating
		// the resolver's "unchecked" verdicts for a signed delegation.
		return Bogus, fmt.Errorf("key set is not signed by an anchored key: %w", err)
	}
	return Secure, nil
}

// acceptedDNSKEYAlgorithm is the resolver operator's validation policy, not
// merely a list of code paths implemented by dns.RRSIG.Verify. RFC 9905
// section 2 requires implementations to retain RSASHA1 verification support,
// but requires operators to treat algorithms 5 and 7 as unsupported for both
// DS records and DNSSEC signatures; they are therefore deliberately absent
// here. Merely appearing in the DNS library's name table does not establish
// support either (that table also contains DSA, GOST, and Ed448).
func acceptedDNSKEYAlgorithm(algorithm uint8) bool {
	switch algorithm {
	case dns.RSASHA256,
		dns.RSASHA512,
		dns.ECDSAP256SHA256,
		dns.ECDSAP384SHA384,
		dns.ED25519:
		return true
	default:
		return false
	}
}

// supportedDSDigest lists the IANA-assigned digest algorithms that this build
// implements correctly. Keeping this independent of the offered DNSKEY
// material is important: a malformed key under a supported DS is a validation
// failure, not evidence that the DS algorithm was unsupported. Do not include
// dns.SHA512 here: the pinned library uses that name for numeric value 5, which
// IANA now assigns to GOST R 34.11-2012, not SHA-512.
func supportedDSDigest(digest uint8) bool {
	switch digest {
	case dns.SHA1, dns.SHA256, dns.SHA384:
		return true
	default:
		return false
	}
}

// signaturesFromZone keeps only signatures whose signer is the zone expected
// to own the RRset. Callers know that zone from the chain of trust; the generic
// RRset verifier deliberately does not guess it.
func signaturesFromZone(sigs []*dns.RRSIG, zone string) []*dns.RRSIG {
	matched := make([]*dns.RRSIG, 0, len(sigs))
	for _, sig := range sigs {
		if dns.EqualName(sig.SignerName, zone) {
			matched = append(matched, sig)
		}
	}
	return matched
}

func hasCoveringSignatureFromAnotherZone(rrset []dns.RR, sigs []*dns.RRSIG, zone string) bool {
	for _, sig := range sigs {
		if covers(sig, rrset) && !dns.EqualName(sig.SignerName, zone) {
			return true
		}
	}
	return false
}

// equalFold compares hex digests without caring about case, which zones publish
// inconsistently.
func equalFold(a, b string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := 0; i < len(a); i++ {
		x, y := a[i], b[i]
		if 'A' <= x && x <= 'Z' {
			x += 'a' - 'A'
		}
		if 'A' <= y && y <= 'Z' {
			y += 'a' - 'A'
		}
		if x != y {
			return false
		}
	}
	return true
}

// SplitSignatures separates an answer section into the records and the
// signatures over them, which every caller here needs and none should repeat.
func SplitSignatures(rrs []dns.RR) (records []dns.RR, sigs []*dns.RRSIG) {
	for _, rr := range rrs {
		if sig, ok := rr.(*dns.RRSIG); ok {
			sigs = append(sigs, sig)
			continue
		}
		records = append(records, rr)
	}
	return records, sigs
}

// RRSet is a group of records that share an owner, class and type, together
// with the signatures offered for them. A signature covers exactly one of
// these, which is why an answer has to be taken apart before it can be checked.
type RRSet struct {
	Name    string
	Type    uint16
	Records []dns.RR
	Sigs    []*dns.RRSIG
}

// GroupRRSets splits a message section into the sets a signature can cover.
//
// A section is not one RRset, and treating it as one is not a near-enough
// approximation: a CNAME chain answers with the alias and the records it leads
// to, each owned by a different name and often signed by a different zone. No
// single signature covers all of that, so the whole answer reads as carrying no
// signature at all -- indistinguishable, from the outside, from a zone that
// signs nothing.
func GroupRRSets(rrs []dns.RR) []RRSet {
	var sigs []*dns.RRSIG
	var sets []RRSet
	at := map[string]int{}

	for _, rr := range rrs {
		if sig, ok := rr.(*dns.RRSIG); ok {
			sigs = append(sigs, sig)
			continue
		}
		h := rr.Header()
		rrtype := dns.RRToType(rr)
		// Owner names are compared without case, so a set is not split in two
		// by an upstream that varies the case it answers in.
		key := fmt.Sprintf("%s/%d/%d", strings.ToLower(h.Name), h.Class, rrtype)
		if i, seen := at[key]; seen {
			sets[i].Records = append(sets[i].Records, rr)
			continue
		}
		at[key] = len(sets)
		sets = append(sets, RRSet{Name: h.Name, Type: rrtype, Records: []dns.RR{rr}})
	}

	for i := range sets {
		for _, sig := range sigs {
			if sig.TypeCovered == sets[i].Type &&
				dns.EqualName(sig.Header().Name, sets[i].Name) &&
				sig.Header().Class == sets[i].Records[0].Header().Class {
				sets[i].Sigs = append(sets[i].Sigs, sig)
			}
		}
	}
	return sets
}

// CountLabels returns the number of labels in name, not counting the root.
func CountLabels(name string) int {
	name = strings.ToLower(strings.TrimSuffix(name, "."))
	if name == "" {
		return 0
	}
	return strings.Count(name, ".") + 1
}

// WildcardNextCloser reports whether sig covers an RRset that the zone
// synthesized from a wildcard, and if so the name whose absence has to be
// proved for that synthesis to have been legitimate.
//
// RFC 4035 section 5.3.3: a signature made over "*.example.com" verifies for
// every name under example.com, so on its own it is evidence only that the
// wildcard exists -- not that it was the right answer for this name. The zone
// must also show that nothing closer to the name exists, which is the "next
// closer" name: the queried name cut back to one label more than the wildcard
// covers. Without that check a signature for a wildcard can be replayed as the
// answer for a name that has a record of its own.
func WildcardNextCloser(sig *dns.RRSIG, owner string) (string, bool) {
	ownerLabels := CountLabels(owner)
	if int(sig.Labels) >= ownerLabels {
		return "", false
	}
	name := strings.ToLower(strings.TrimSuffix(owner, "."))
	labels := strings.Split(name, ".")
	// RFC 4034 section 3.1.3 also encodes the leading wildcard label by
	// decrementing Labels when the RRset owner itself is "*.zone". Rebuild
	// the owner that was signed before deciding this was synthesis. If it is
	// identical to the returned owner, the client queried the wildcard name
	// literally and there is no missing closer name to prove.
	wildcardLabels := []string{"*"}
	if sig.Labels > 0 {
		wildcardLabels = append(wildcardLabels, labels[len(labels)-int(sig.Labels):]...)
	}
	signedOwner := strings.Join(wildcardLabels, ".") + "."
	if canonicalName(owner) == signedOwner {
		return "", false
	}
	// One label more than the closest encloser the signature vouches for.
	keep := int(sig.Labels) + 1
	if keep > len(labels) {
		return "", false
	}
	return strings.Join(labels[len(labels)-keep:], ".") + ".", true
}

// VerifyRRSetDetail is VerifyRRSet, additionally reporting which signature
// carried it, so that a caller can tell whether the answer was synthesized from
// a wildcard and demand the proof that goes with it.
func VerifyRRSetDetail(rrset []dns.RR, sigs []*dns.RRSIG, keys []*dns.DNSKEY, now time.Time) (Result, *dns.RRSIG, error) {
	if len(rrset) == 0 {
		return Indeterminate, nil, fmt.Errorf("no records to verify")
	}
	if len(sigs) == 0 {
		return Indeterminate, nil, ErrNoSignature
	}
	if len(keys) == 0 {
		return Indeterminate, nil, fmt.Errorf("no keys to verify against")
	}

	var lastErr error
	unsupportedOnly := false
	for _, sig := range sigs {
		if !covers(sig, rrset) {
			continue
		}
		// RFC 6840 section 5.12: an extra RRSIG is not applicable until its
		// algorithm, key tag, and signer identify a usable DNSKEY in the
		// authenticated zone key set. Disregard it before inspecting its
		// validity window or signature bytes; a stale rollover signature must
		// not turn otherwise missing evidence into a false Bogus result.
		if !hasCorrespondingDNSKEY(sig, keys, rrset) {
			continue
		}
		if !acceptedDNSKEYAlgorithm(sig.Algorithm) {
			// Only a signature with a corresponding usable zone key can
			// establish that this RRset relies on an algorithm the operator has
			// deliberately classified as unsupported.
			unsupportedOnly = true
			continue
		}
		if !ValidAt(sig, now) {
			lastErr = fmt.Errorf("%w: signature by key %d", ErrSignatureOutsideValidity, sig.KeyTag)
			continue
		}
		for _, key := range keys {
			if !usableDNSKEYForSignature(key, sig, rrset) {
				continue
			}
			if err := sig.Verify(key, rrset, &dns.SignOption{}); err != nil {
				lastErr = err
				continue
			}
			return Secure, sig, nil
		}
	}
	if unsupportedOnly {
		// RFC 9905 section 2 explicitly renders the RRset Insecure when no
		// other supported signing algorithm validates it. That result takes
		// precedence over failures from alternative signatures, while a valid
		// accepted signature returned Secure above (RFC 6840 section 5.4).
		return Insecure, nil, ErrUnsupportedSignatureAlgorithm
	}
	if lastErr == nil {
		return Indeterminate, nil, ErrNoSignature
	}
	// Unsupported algorithms were skipped above. ErrKey here therefore means
	// that matching material for an accepted algorithm was malformed or
	// unusable. RFC 4035 sections 4.3 and 5.5 require that failed authentication
	// to remain Bogus; treating it as Insecure would be a downgrade around the
	// chain of trust.
	return Bogus, nil, lastErr
}

func hasCorrespondingDNSKEY(sig *dns.RRSIG, keys []*dns.DNSKEY, rrset []dns.RR) bool {
	for _, key := range keys {
		if usableDNSKEYForSignature(key, sig, rrset) {
			return true
		}
	}
	return false
}

func usableDNSKEYForSignature(key *dns.DNSKEY, sig *dns.RRSIG, rrset []dns.RR) bool {
	if key.Algorithm != sig.Algorithm || key.KeyTag() != sig.KeyTag ||
		key.Flags&dns.FlagZONE == 0 || key.Protocol != 3 ||
		!dns.EqualName(key.Header().Name, sig.SignerName) ||
		!dnskeyMeetsAlgorithmConstraints(key) {
		return false
	}
	// RFC 5011 section 2.1: a revoked key is permanently invalid except for
	// authenticating the RRSIG it made over its own DNSKEY RRset so that the
	// revocation can be established. Retaining it in an authenticated DNSKEY
	// set does not let it continue signing ordinary zone data.
	if key.Flags&dns.FlagREVOKE != 0 &&
		(dns.RRToType(rrset[0]) != dns.TypeDNSKEY ||
			!dns.EqualName(rrset[0].Header().Name, key.Header().Name)) {
		return false
	}
	return true
}

// dnskeyMeetsAlgorithmConstraints applies wire-format constraints that are
// part of an algorithm's DNSSEC definition, rather than leaving them to the
// generic crypto backend. In particular, Go can parse and attempt to verify
// RSA/SHA-512 keys below the minimum that RFC 5702 section 2.2 permits.
func dnskeyMeetsAlgorithmConstraints(key *dns.DNSKEY) bool {
	var minBits int
	switch key.Algorithm {
	case dns.RSASHA256:
		minBits = 512
	case dns.RSASHA512:
		minBits = 1024
	default:
		return true
	}
	bits, ok := rsaDNSKEYModulusBits(key.PublicKey)
	return ok && bits >= minBits && bits <= 4096
}

// rsaDNSKEYModulusBits decodes the exponent-length framing from RFC 3110
// section 2 and returns the actual modulus bit length. A leading zero is not a
// valid DNSKEY integer encoding and must not be used to disguise an oversized
// modulus as an allowed one.
func rsaDNSKEYModulusBits(publicKey string) (int, bool) {
	wire, err := base64.StdEncoding.DecodeString(publicKey)
	if err != nil || len(wire) < 3 {
		return 0, false
	}
	exponentLength := int(wire[0])
	offset := 1
	if exponentLength == 0 {
		if len(wire) < 4 {
			return 0, false
		}
		exponentLength = int(wire[1])<<8 | int(wire[2])
		offset = 3
	}
	modulusOffset := offset + exponentLength
	if exponentLength == 0 || modulusOffset >= len(wire) || wire[offset] == 0 || wire[modulusOffset] == 0 {
		return 0, false
	}
	modulus := wire[modulusOffset:]
	return (len(modulus)-1)*8 + bits.Len8(modulus[0]), true
}

// SignatureExpiry returns the moment a signature stops being valid.
//
// The field is seconds since the epoch modulo 2^32, so it is read the way
// RFC 4034 section 3.1.5 says to read it: as a distance from now in RFC 1982
// serial arithmetic, rather than as an absolute number that will be wrong after
// 2106 and wrong today for a zone signing across the wrap.
func SignatureExpiry(sig *dns.RRSIG, now time.Time) time.Time {
	away := int32(sig.Expiration - uint32(now.Unix())) // #nosec G115 -- serial arithmetic, wrap intended
	return now.Add(time.Duration(away) * time.Second)
}

// EarliestSignatureExpiry returns when the first signature over any of these
// records expires, and whether there was one at all.
func EarliestSignatureExpiry(now time.Time, sections ...[]dns.RR) (time.Time, bool) {
	var earliest time.Time
	found := false
	for _, section := range sections {
		for _, rr := range section {
			sig, ok := rr.(*dns.RRSIG)
			if !ok {
				continue
			}
			at := SignatureExpiry(sig, now)
			if !found || at.Before(earliest) {
				earliest, found = at, true
			}
		}
	}
	return earliest, found
}
