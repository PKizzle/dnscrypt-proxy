package dnssec

import (
	"crypto/sha1"
	"encoding/base32"
	"strings"

	"codeberg.org/miekg/dns"
)

// This file proves that something is absent.
//
// A forged "no such name" is as useful to an attacker as a forged address: it
// takes a service off the network, and it is how a signed zone is made to look
// unsigned -- strip the delegation signer, answer "there is none", and every
// name below is beyond DNSSEC's reach. A zone therefore signs statements about
// the gaps between the names it holds, and this checks them.

// wireName encodes a domain name the way it is signed: lower case, each label
// preceded by its length, terminated by a zero byte.
func wireName(name string) []byte {
	name = strings.ToLower(name)
	if name == "." || name == "" {
		return []byte{0}
	}
	name = strings.TrimSuffix(name, ".")
	out := make([]byte, 0, len(name)+2)
	for _, label := range strings.Split(name, ".") {
		out = append(out, byte(len(label)))
		out = append(out, label...)
	}
	return append(out, 0)
}

var base32Hex = base32.HexEncoding.WithPadding(base32.NoPadding)

// NSEC3Hash returns the hashed owner name for name, as RFC 5155 section 5
// defines it: SHA-1 over the wire-format name and the salt, re-applied
// `iterations` more times, rendered in base32hex.
//
// Only SHA-1 is defined for NSEC3; an unknown algorithm returns "" so the
// caller treats the record as proving nothing rather than as a match.
func NSEC3Hash(name string, algorithm uint8, iterations uint16, salt string) string {
	if algorithm != 1 {
		return ""
	}
	saltBytes, err := hexDecode(salt)
	if err != nil {
		return ""
	}
	digest := sha1.Sum(append(wireName(name), saltBytes...)) // #nosec G401 -- RFC 5155 defines SHA-1 here
	buf := digest[:]
	if iterations > maxNSEC3Iterations {
		// Refusing here rather than at each call site keeps the limit in one
		// place: an empty hash is already how this reports "nothing can be
		// concluded", and every caller already handles it.
		return ""
	}
	for i := uint16(0); i < iterations; i++ {
		next := sha1.Sum(append(buf, saltBytes...)) // #nosec G401 -- as above
		buf = next[:]
	}
	return strings.ToUpper(base32Hex.EncodeToString(buf))
}

func hexDecode(s string) ([]byte, error) {
	// A zero-length salt is written as "-".
	if s == "-" || s == "" {
		return nil, nil
	}
	out := make([]byte, len(s)/2)
	for i := 0; i < len(out); i++ {
		hi, err := hexVal(s[2*i])
		if err != nil {
			return nil, err
		}
		lo, err := hexVal(s[2*i+1])
		if err != nil {
			return nil, err
		}
		out[i] = hi<<4 | lo
	}
	return out, nil
}

func hexVal(c byte) (byte, error) {
	switch {
	case '0' <= c && c <= '9':
		return c - '0', nil
	case 'a' <= c && c <= 'f':
		return c - 'a' + 10, nil
	case 'A' <= c && c <= 'F':
		return c - 'A' + 10, nil
	}
	return 0, errBadHex
}

var errBadHex = &hexError{}

type hexError struct{}

func (*hexError) Error() string { return "invalid hex digit" }

// canonicalCompare orders two names the way DNSSEC does (RFC 4034 section 6.1):
// by label, right to left, each label compared as raw lower-cased bytes.
//
// This is not lexical order on the whole string. "z.example." sorts before
// "a.b.example." because the comparison starts at the rightmost label, and an
// implementation that compares the strings directly gets the gaps wrong -- and
// therefore accepts denials that prove nothing.
func canonicalCompare(a, b string) int {
	al := canonicalLabels(a)
	bl := canonicalLabels(b)
	for i, j := len(al)-1, len(bl)-1; i >= 0 && j >= 0; i, j = i-1, j-1 {
		if c := strings.Compare(al[i], bl[j]); c != 0 {
			return c
		}
	}
	switch {
	case len(al) < len(bl):
		return -1
	case len(al) > len(bl):
		return 1
	}
	return 0
}

func canonicalLabels(name string) []string {
	name = strings.ToLower(strings.TrimSuffix(name, "."))
	if name == "" {
		return nil
	}
	return strings.Split(name, ".")
}

// nsecCovers reports whether the gap this NSEC describes contains name, which
// is what proves the name is absent from the zone.
//
// The last NSEC of a zone wraps: its next name is the apex, and it covers
// everything after its owner. Treating that as an ordinary range would leave
// the end of every zone unprovable.
func nsecCovers(rr *dns.NSEC, name string) bool {
	owner, next := rr.Header().Name, rr.NextDomain
	afterOwner := canonicalCompare(name, owner) > 0
	beforeNext := canonicalCompare(name, next) < 0
	if canonicalCompare(owner, next) >= 0 {
		return afterOwner || beforeNext
	}
	return afterOwner && beforeNext
}

// nsec3Covers is nsecCovers for hashed names, which are compared as the base32
// strings they are written in.
func nsec3Covers(rr *dns.NSEC3, hashed string) bool {
	owner := strings.ToUpper(firstLabel(rr.Header().Name))
	next := strings.ToUpper(rr.NextDomain)
	afterOwner := hashed > owner
	beforeNext := hashed < next
	if owner >= next {
		return afterOwner || beforeNext
	}
	return afterOwner && beforeNext
}

func firstLabel(name string) string {
	name = strings.TrimSuffix(name, ".")
	if i := strings.Index(name, "."); i >= 0 {
		return name[:i]
	}
	return name
}

// coversType reports whether a type bitmap lists rrtype.
func coversType(bitmap []uint16, rrtype uint16) bool {
	for _, t := range bitmap {
		if t == rrtype {
			return true
		}
	}
	return false
}

// Denial holds the records a zone offered as proof that something is absent.
type Denial struct {
	NSEC  []*dns.NSEC
	NSEC3 []*dns.NSEC3
}

// CollectDenial picks the denial records out of an authority section.
func CollectDenial(rrs []dns.RR) Denial {
	var d Denial
	for _, rr := range rrs {
		switch v := rr.(type) {
		case *dns.NSEC:
			d.NSEC = append(d.NSEC, v)
		case *dns.NSEC3:
			d.NSEC3 = append(d.NSEC3, v)
		}
	}
	return d
}

// Empty reports whether nothing was offered.
func (d Denial) Empty() bool { return len(d.NSEC) == 0 && len(d.NSEC3) == 0 }

// ProvesNoData reports whether the zone proved that name exists but holds no
// record of rrtype.
//
// The proof is a record matching the name whose bitmap omits the type. The
// bitmap is what carries the meaning, so two entries in it have to be refused
// as well: a CNAME would mean the answer should have followed it, and a DNAME
// likewise -- accepting either lets a zone deny a name it actually redirects.
func (d Denial) ProvesNoData(name string, rrtype uint16) bool {
	for _, rr := range d.NSEC {
		if canonicalCompare(rr.Header().Name, name) != 0 {
			continue
		}
		if coversType(rr.TypeBitMap, rrtype) || coversType(rr.TypeBitMap, dns.TypeCNAME) {
			return false
		}
		return true
	}
	for _, rr := range d.NSEC3 {
		hashed := NSEC3Hash(name, rr.Hash, rr.Iterations, rr.Salt)
		if hashed == "" || hashed != strings.ToUpper(firstLabel(rr.Header().Name)) {
			continue
		}
		if coversType(rr.TypeBitMap, rrtype) || coversType(rr.TypeBitMap, dns.TypeCNAME) {
			return false
		}
		return true
	}
	return false
}

// ProvesNoDS reports whether the zone proved that name is delegated without a
// delegation signer -- the one denial that decides whether everything below it
// is genuinely outside DNSSEC or merely being made to look that way.
//
// A matching record must list NS (this really is a delegation) and omit both DS
// and SOA (it is the child's cut, not the parent's own apex). Under NSEC3 there
// is a second route: a delegation the zone opted out of is covered rather than
// matched, and the opt-out flag has to be set for that to mean anything.
func (d Denial) ProvesNoDS(name string) bool {
	for _, rr := range d.NSEC {
		if canonicalCompare(rr.Header().Name, name) != 0 {
			continue
		}
		if coversType(rr.TypeBitMap, dns.TypeDS) || coversType(rr.TypeBitMap, dns.TypeSOA) {
			return false
		}
		return coversType(rr.TypeBitMap, dns.TypeNS)
	}
	for _, rr := range d.NSEC3 {
		hashed := NSEC3Hash(name, rr.Hash, rr.Iterations, rr.Salt)
		if hashed == "" {
			continue
		}
		if hashed == strings.ToUpper(firstLabel(rr.Header().Name)) {
			if coversType(rr.TypeBitMap, dns.TypeDS) || coversType(rr.TypeBitMap, dns.TypeSOA) {
				return false
			}
			return coversType(rr.TypeBitMap, dns.TypeNS)
		}
	}
	// Opt-out: the delegation was never given a record of its own, and the gap
	// containing it is flagged as one where that is allowed.
	for _, rr := range d.NSEC3 {
		if rr.Flags&1 == 0 {
			continue
		}
		hashed := NSEC3Hash(name, rr.Hash, rr.Iterations, rr.Salt)
		if hashed != "" && nsec3Covers(rr, hashed) {
			return true
		}
	}
	return false
}

// ProvesNameError reports whether the zone proved that name does not exist at
// all.
//
// Two things have to be shown, and showing only the first is a classic hole: no
// record covers the name, AND no wildcard could have synthesized it. A zone
// with *.example. in it can answer for a name that has no record of its own, so
// a denial that ignores the wildcard denies something the zone would actually
// have answered.
func (d Denial) ProvesNameError(name, zone string) bool {
	wildcard := "*." + canonicalName(zone)

	if len(d.NSEC) > 0 {
		covered, wildcardDenied := false, false
		for _, rr := range d.NSEC {
			if nsecCovers(rr, name) {
				covered = true
			}
			if nsecCovers(rr, wildcard) || canonicalCompare(rr.Header().Name, wildcard) == 0 {
				// A matching wildcard record proves the wildcard exists, which
				// is not a name error; only a covering one denies it.
				if nsecCovers(rr, wildcard) {
					wildcardDenied = true
				}
			}
		}
		return covered && wildcardDenied
	}

	// NSEC3 proves it in three parts: the deepest ancestor that does exist, the
	// absence of the next label down from it, and the absence of a wildcard at
	// that ancestor.
	closest, ok := d.closestEncloser(name, zone)
	if !ok {
		return false
	}
	nextCloser := nextCloserName(name, closest)
	if nextCloser == "" || !d.covered(nextCloser) {
		return false
	}
	return d.covered("*." + closest)
}

// closestEncloser finds the deepest ancestor of name that the zone has a
// matching record for.
func (d Denial) closestEncloser(name, zone string) (string, bool) {
	candidate := canonicalName(name)
	zone = canonicalName(zone)
	for {
		for _, rr := range d.NSEC3 {
			hashed := NSEC3Hash(candidate, rr.Hash, rr.Iterations, rr.Salt)
			if hashed != "" && hashed == strings.ToUpper(firstLabel(rr.Header().Name)) {
				return candidate, true
			}
		}
		if canonicalCompare(candidate, zone) == 0 {
			return "", false
		}
		parent := parentName(candidate)
		if parent == "" || parent == candidate {
			return "", false
		}
		candidate = parent
	}
}

// covered reports whether some NSEC3 covers the gap containing name.
func (d Denial) covered(name string) bool {
	for _, rr := range d.NSEC3 {
		hashed := NSEC3Hash(name, rr.Hash, rr.Iterations, rr.Salt)
		if hashed != "" && nsec3Covers(rr, hashed) {
			return true
		}
	}
	return false
}

// nextCloserName is the ancestor of name one label below closest.
func nextCloserName(name, closest string) string {
	nameLabels := canonicalLabels(name)
	closestLabels := canonicalLabels(closest)
	if len(nameLabels) <= len(closestLabels) {
		return ""
	}
	return strings.Join(nameLabels[len(nameLabels)-len(closestLabels)-1:], ".") + "."
}

// canonicalName lower-cases a name and gives it a trailing dot.
func canonicalName(name string) string {
	name = strings.ToLower(name)
	if !strings.HasSuffix(name, ".") {
		name += "."
	}
	return name
}

func parentName(name string) string {
	labels := canonicalLabels(name)
	if len(labels) <= 1 {
		return "."
	}
	return strings.Join(labels[1:], ".") + "."
}

// maxNSEC3Iterations bounds the hashing a zone can ask a validator to do.
//
// RFC 9276 section 3.2 puts the useful number at zero and records that extra
// iterations buy no meaningful protection; RFC 5155 section 10.3 already
// allowed a validator to refuse to follow a zone that asks for too many. The
// work is per query and chosen by whoever writes the zone, so an unbounded
// count is a lever for spending this resolver's CPU rather than the attacker's.
// Answers above the limit are treated as unproven rather than forged.
const maxNSEC3Iterations = 100

// ProvesNoCloserMatch reports whether the zone proved that nextCloser does not
// exist, which is what makes an answer synthesized from a wildcard legitimate.
//
// RFC 4035 section 5.3.3 and RFC 5155 section 8.8: a wildcard signature covers
// every name below the closest encloser, so it says nothing on its own about
// which name should have been answered. Only the absence of anything closer
// does that.
func (d Denial) ProvesNoCloserMatch(nextCloser string) bool {
	for _, rr := range d.NSEC {
		if nsecCovers(rr, nextCloser) {
			return true
		}
	}
	for _, rr := range d.NSEC3 {
		if rr.Iterations > maxNSEC3Iterations {
			continue
		}
		hashed := NSEC3Hash(nextCloser, rr.Hash, rr.Iterations, rr.Salt)
		if hashed != "" && nsec3Covers(rr, hashed) {
			return true
		}
	}
	return false
}
