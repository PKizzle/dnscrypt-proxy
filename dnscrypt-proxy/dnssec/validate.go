// Package dnssec verifies the signatures on a DNS answer against the chain of
// keys leading back to a trust anchor.
//
// It answers one question -- whether an answer is what the zone's owner
// published -- and answers it in three ways, because "not signed" and "signed
// wrongly" are different situations and only one of them is an attack.
package dnssec

import (
	"errors"
	"fmt"
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
	// Bogus: signatures exist and do not verify, or verify outside their
	// validity, or no key matches them. This is the case worth refusing: an
	// answer that claims to be signed and is not what the zone published.
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

	// Whether the parent published a delegation signer this build can compute at
	// all. RFC 4035 section 5.2 treats a delegation whose digests are all
	// unknown as unsigned rather than forged: refusing it would take zones off
	// the air as digest types turn over, which is the opposite of what
	// validating is for.
	//
	// Deliberately independent of whether any key matches. A key the parent
	// never delegated is forged, and must stay refused -- that is the case this
	// whole function exists for.
	checkable := false
	for _, ds := range dss {
		for _, key := range keys {
			if key.ToDS(ds.DigestType) != nil {
				checkable = true
				break
			}
		}
		if checkable {
			break
		}
	}

	anchored := make([]*dns.DNSKEY, 0, len(keys))
	for _, key := range keys {
		for _, ds := range dss {
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
		return res, fmt.Errorf("key set is not signed by an anchored key: %w", err)
	}
	return Secure, nil
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
	for _, sig := range sigs {
		if !covers(sig, rrset) {
			continue
		}
		if !ValidAt(sig, now) {
			lastErr = fmt.Errorf("%w: signature by key %d", ErrSignatureOutsideValidity, sig.KeyTag)
			continue
		}
		for _, key := range keys {
			if key.Algorithm != sig.Algorithm || key.KeyTag() != sig.KeyTag {
				continue
			}
			if key.Flags&dns.FlagZONE == 0 {
				continue
			}
			// RFC 4034 section 2.1.2: any other value means the key is not
			// usable for DNSSEC, and must not be treated as though it were.
			if key.Protocol != 3 {
				continue
			}
			if err := sig.Verify(key, rrset, &dns.SignOption{}); err != nil {
				lastErr = err
				continue
			}
			return Secure, sig, nil
		}
		if lastErr == nil {
			lastErr = fmt.Errorf("no key matches signature by key %d", sig.KeyTag)
		}
	}
	if lastErr == nil {
		return Indeterminate, nil, ErrNoSignature
	}
	// RFC 6840 section 5.2: a key this build cannot use proves nothing either
	// way, and a zone must not be refused for being signed in a way this
	// validator cannot follow -- which is what refusing here would come to as
	// algorithms turn over.
	if errors.Is(lastErr, dns.ErrKey) {
		return Insecure, nil, lastErr
	}
	return Bogus, nil, lastErr
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
