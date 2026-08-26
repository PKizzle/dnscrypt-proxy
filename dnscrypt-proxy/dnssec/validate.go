// Package dnssec verifies the signatures on a DNS answer against the chain of
// keys leading back to a trust anchor.
//
// It answers one question -- whether an answer is what the zone's owner
// published -- and answers it in three ways, because "not signed" and "signed
// wrongly" are different situations and only one of them is an attack.
package dnssec

import (
	"fmt"
	"time"

	"codeberg.org/miekg/dns"
)

// Result is what verification concluded about an answer.
type Result int

const (
	// Indeterminate: nothing was concluded, because the inputs did not allow a
	// conclusion. Never a reason to reject.
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

// VerifyRRSet reports whether rrset is covered by a signature that verifies
// against one of keys and is valid at now.
//
// A signature is accepted on the first key that verifies it. Several keys can
// carry the same tag -- the tag is a checksum, not an identifier -- so a key
// that fails is a reason to try the next one, not to conclude anything.
func VerifyRRSet(rrset []dns.RR, sigs []*dns.RRSIG, keys []*dns.DNSKEY, now time.Time) (Result, error) {
	if len(rrset) == 0 {
		return Indeterminate, fmt.Errorf("no records to verify")
	}
	if len(sigs) == 0 {
		return Indeterminate, ErrNoSignature
	}
	if len(keys) == 0 {
		return Indeterminate, fmt.Errorf("no keys to verify against")
	}

	var lastErr error
	for _, sig := range sigs {
		if !covers(sig, rrset) {
			continue
		}
		if !ValidAt(sig, now) {
			lastErr = fmt.Errorf("signature by key %d is outside its validity", sig.KeyTag)
			continue
		}
		for _, key := range keys {
			if key.Algorithm != sig.Algorithm || key.KeyTag() != sig.KeyTag {
				continue
			}
			// A key that is not a zone key must not sign a zone's records.
			if key.Flags&dns.FlagZONE == 0 {
				continue
			}
			// A fresh option set per call, never nil: Verify dereferences it
			// without checking, and it writes a pooler into whatever it is
			// given, so a shared one would be a data race between queries.
			if err := sig.Verify(key, rrset, &dns.SignOption{}); err != nil {
				lastErr = err
				continue
			}
			return Secure, nil
		}
		if lastErr == nil {
			lastErr = fmt.Errorf("no key matches signature by key %d", sig.KeyTag)
		}
	}
	if lastErr == nil {
		return Indeterminate, ErrNoSignature
	}
	// Signatures were present and none of them held up.
	return Bogus, lastErr
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

	anchored := make([]*dns.DNSKEY, 0, len(keys))
	for _, key := range keys {
		for _, ds := range dss {
			if key.KeyTag() != ds.KeyTag || key.Algorithm != ds.Algorithm {
				continue
			}
			computed := key.ToDS(ds.DigestType)
			if computed == nil {
				// A digest algorithm this build cannot compute is not a
				// mismatch; it simply proves nothing.
				continue
			}
			if equalFold(computed.Digest, ds.Digest) {
				anchored = append(anchored, key)
				break
			}
		}
	}
	if len(anchored) == 0 {
		return Bogus, fmt.Errorf("no offered key matches the delegation signer")
	}

	rrset := make([]dns.RR, 0, len(keys))
	for _, key := range keys {
		rrset = append(rrset, key)
	}
	// Verified against the anchored keys only: a self-signature by an unanchored
	// key would let the set vouch for itself.
	res, err := VerifyRRSet(rrset, sigs, anchored, now)
	if res != Secure {
		return res, fmt.Errorf("key set is not signed by an anchored key: %w", err)
	}
	return Secure, nil
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
