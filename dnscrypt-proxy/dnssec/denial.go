package dnssec

import (
	"crypto/sha1"
	"encoding/base32"
	"errors"
	"strings"
	"time"

	"codeberg.org/miekg/dns"
)

// ErrUnsupportedNSEC3Iterations says that a signed denial was understood and
// authenticated, but deliberately not processed because its iteration count
// exceeds this validator's resource limit. RFC 9276 section 3.2 assigns EDE
// code 27 to that distinct case; it is not evidence that the zone forged data.
var ErrUnsupportedNSEC3Iterations = errors.New("unsupported NSEC3 iterations")

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
	if len(s)%2 != 0 {
		return nil, errBadHex
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
	sigs  []*dns.RRSIG
	// cnames is positive evidence collected only from a DS lookup. A signed,
	// exact CNAME at the queried name proves that the current zone owns that
	// name, and therefore that it is not a delegation point. Keeping it with
	// the DS-absence evidence lets the chain distinguish that ordinary case
	// from a response whose absence of DS data was merely unexplained.
	cnames    []*dns.CNAME
	cnameSigs []*dns.RRSIG
	zone      string
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
		case *dns.RRSIG:
			if v.TypeCovered == dns.TypeNSEC || v.TypeCovered == dns.TypeNSEC3 {
				d.sigs = append(d.sigs, v)
			}
		}
	}
	return d
}

// CollectDelegationEvidence gathers the proof a DS lookup can return when the
// queried label is an alias rather than a zone cut. RFC 1034 section 3.6.2
// makes a CNAME exclusive of ordinary data, and RFC 4035 sections 2.5 and 2.6
// leave no room for parent-side DS/NS data at that same owner. The CNAME is
// still untrusted here; Verified authenticates it with the current parent key
// before the chain relies on it.
func CollectDelegationEvidence(answer, authority []dns.RR) Denial {
	d := CollectDenial(authority)
	for _, rr := range answer {
		switch v := rr.(type) {
		case *dns.CNAME:
			d.cnames = append(d.cnames, v)
		case *dns.RRSIG:
			if v.TypeCovered == dns.TypeCNAME {
				d.cnameSigs = append(d.cnameSigs, v)
			}
		}
	}
	return d
}

// Verified returns only denial records whose signatures verify with keys from
// zone. An NSEC or NSEC3 is data from the upstream just like an address is;
// using it without its RRSIG turns a forged negative reply into a secure one,
// or lets a forged missing DS downgrade a signed child to unsigned.
//
// The signer name is checked as well as the cryptographic signature. The key
// has already been tied to zone by the chain, and an RRSIG over the zone's own
// denial must name that zone as its signer.
func (d Denial) Verified(keys []*dns.DNSKEY, zone string, now time.Time) Denial {
	all := make([]dns.RR, 0, len(d.NSEC)+len(d.NSEC3)+len(d.sigs))
	for _, rr := range d.NSEC {
		all = append(all, rr)
	}
	for _, rr := range d.NSEC3 {
		all = append(all, rr)
	}
	for _, sig := range d.sigs {
		if dns.EqualName(sig.SignerName, zone) {
			all = append(all, sig)
		}
	}

	verified := Denial{zone: canonicalName(zone)}
	for _, set := range GroupRRSets(all) {
		if set.Type != dns.TypeNSEC && set.Type != dns.TypeNSEC3 {
			continue
		}
		// RFC 4035 section 5.3.1 requires the signer to name the zone
		// containing the RRset. Checking the signer name alone is insufficient:
		// a zone key can cryptographically sign arbitrary wire data.
		if !WithinZone(set.Name, zone) {
			continue
		}
		if res, err := VerifyRRSet(set.Records, set.Sigs, keys, now); res != Secure || err != nil {
			continue
		}
		if set.Type == dns.TypeNSEC && !hasExactNSECSignature(set, keys, now) {
			// RFC 4035 section 5.4: a matching NSEC establishes that wildcard
			// expansion was not used only when the signer recorded the same
			// label count as the NSEC owner. A valid wildcard-expanded NSEC is
			// not a statement about an exact existing owner, so it must not be
			// used as any kind of denial proof.
			continue
		}
		for _, rr := range set.Records {
			switch rr := rr.(type) {
			case *dns.NSEC:
				verified.NSEC = append(verified.NSEC, rr)
			case *dns.NSEC3:
				// RFC 5155 section 8.2: only flag values 0 and 1 are valid
				// NSEC3 denial proofs. Unknown flag bits must not be used to
				// establish absence or a downgrade.
				if rr.Flags != 0 && rr.Flags != 1 {
					continue
				}
				verified.NSEC3 = append(verified.NSEC3, rr)
			}
		}
	}
	for _, cname := range d.cnames {
		owner := cname.Header().Name
		if !WithinZone(owner, zone) {
			continue
		}
		rrset := []dns.RR{cname}
		for _, sig := range signaturesFromZone(d.cnameSigs, zone) {
			// A wildcard-expanded CNAME alone is not enough: without the
			// accompanying denial proof, it does not establish that this exact
			// owner was not a delegation. An exact signature is the positive
			// parent-side fact needed by the chain walk.
			if int(sig.Labels) != CountLabels(owner) {
				continue
			}
			if res, err := VerifyRRSet(rrset, []*dns.RRSIG{sig}, keys, now); res == Secure && err == nil {
				verified.cnames = append(verified.cnames, cname)
				break
			}
		}
	}
	return verified
}

// hasExactNSECSignature checks the label-count part of RFC 4035 section 5.4.
// VerifyRRSet accepts a valid wildcard signature by design; a non-wildcard
// NSEC with fewer labels was expanded and proves no exact owner exists. An
// NSEC whose *actual* owner is a wildcard is different: RFC 4034 encodes its
// label count without the wildcard label, and RFC 4035 appendix B.7 uses that
// record to prove wildcard NODATA. Inspect every usable signature rather than
// relying on whichever valid one VerifyRRSet finds first.
func hasExactNSECSignature(set RRSet, keys []*dns.DNSKEY, now time.Time) bool {
	for _, sig := range set.Sigs {
		labels := CountLabels(set.Name)
		exactWildcardOwner := strings.HasPrefix(canonicalName(set.Name), "*.") && int(sig.Labels) == labels-1
		if int(sig.Labels) != labels && !exactWildcardOwner {
			continue
		}
		if res, _ := VerifyRRSet(set.Records, []*dns.RRSIG{sig}, keys, now); res == Secure {
			return true
		}
	}
	return false
}

// Empty reports whether nothing was offered.
func (d Denial) Empty() bool {
	return len(d.NSEC) == 0 && len(d.NSEC3) == 0 && len(d.cnames) == 0
}

// HasOnlyUnsupportedNSEC3Iterations reports whether every authenticated
// denial proof supplied by the zone is an NSEC3 record over our iteration
// limit. It is deliberately narrower than "contains": a normal NSEC/NSEC3
// proof that fails to establish the queried absence remains Bogus, even if an
// unrelated high-iteration NSEC3 record accompanied it.
func (d Denial) HasOnlyUnsupportedNSEC3Iterations() bool {
	if len(d.NSEC) != 0 || len(d.NSEC3) == 0 {
		return false
	}
	for _, rr := range d.NSEC3 {
		// RFC 5155 section 8.1 requires an unknown hash type to be ignored.
		// EDE 27 is only accurate when iterations, rather than the algorithm,
		// is the reason this validator declined the otherwise authenticated
		// proof.
		if rr.Hash != 1 || rr.Iterations <= maxNSEC3Iterations {
			return false
		}
	}
	return true
}

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
		if coversType(rr.TypeBitMap, rrtype) ||
			coversType(rr.TypeBitMap, dns.TypeCNAME) ||
			coversType(rr.TypeBitMap, dns.TypeDNAME) ||
			(coversType(rr.TypeBitMap, dns.TypeNS) && !coversType(rr.TypeBitMap, dns.TypeSOA)) {
			return false
		}
		return true
	}
	for _, rr := range d.NSEC3 {
		hashed := NSEC3Hash(name, rr.Hash, rr.Iterations, rr.Salt)
		if hashed == "" || hashed != strings.ToUpper(firstLabel(rr.Header().Name)) {
			continue
		}
		if coversType(rr.TypeBitMap, rrtype) ||
			coversType(rr.TypeBitMap, dns.TypeCNAME) ||
			coversType(rr.TypeBitMap, dns.TypeDNAME) ||
			(coversType(rr.TypeBitMap, dns.TypeNS) && !coversType(rr.TypeBitMap, dns.TypeSOA)) {
			return false
		}
		return true
	}
	return false
}

// ProvesWildcardNoData reports whether a wildcard matched name but did not
// hold rrtype. This is not an NXDOMAIN: the closest-encloser proof says the
// queried name is absent, while the matching wildcard NSEC/NSEC3 says the
// wildcard does exist and omits the requested type.
//
// RFC 4035 appendix B.7 and RFC 5155 section 7.2.5 require both parts. In
// particular, accepting only the first would turn a nonexistent name into a
// secure NODATA even when no wildcard exists; accepting only the second would
// let a wildcard be used below a closer existing name.
func (d Denial) ProvesWildcardNoData(name, zone string, rrtype uint16) bool {
	if len(d.NSEC) > 0 {
		for _, rr := range d.NSEC {
			if !d.nsecMayProveAbsence(rr, name) {
				continue
			}
			closest := nsecClosestEncloser(name, rr.Header().Name, zone)
			if closest != "" && d.ProvesNoData("*."+closest, rrtype) {
				return true
			}
		}
		return false
	}

	closest, ok := d.closestEncloser(name, zone)
	if !ok {
		return false
	}
	nextCloser := nextCloserName(name, closest)
	return nextCloser != "" && d.covered(nextCloser) && d.ProvesNoData("*."+closest, rrtype)
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
		if hashed != "" && nsec3Covers(rr, hashed) && d.nsec3MayProveAbsence(rr, name) {
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
	if len(d.NSEC) > 0 {
		for _, rr := range d.NSEC {
			if !d.nsecMayProveAbsence(rr, name) {
				continue
			}
			// RFC 4035 section 5.4 requires that a name error also prove no
			// relevant wildcard could have answered. For NSEC, the record that
			// covers QNAME retains the hierarchy that NSEC3 hashes away: its
			// owner and QNAME share the closest encloser. Checking only
			// "*.zone" would accept a replayed NXDOMAIN for x.b.zone when
			// "*.b.zone" actually exists.
			closest := nsecClosestEncloser(name, rr.Header().Name, zone)
			if closest != "" && d.nsecCovers("*."+closest) {
				return true
			}
		}
		return false
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

// nsecClosestEncloser derives the closest enclosing name retained by an NSEC
// proof. Unlike NSEC3, canonical NSEC ordering includes the hierarchy: the
// immediate predecessor that covers QNAME must lie at or below the same
// closest encloser. RFC 7129 section 5.5 describes this as NSEC implicitly
// containing the closest-encloser information.
func nsecClosestEncloser(name, owner, zone string) string {
	nameLabels := canonicalLabels(name)
	ownerLabels := canonicalLabels(owner)
	common := 0
	for i, j := len(nameLabels)-1, len(ownerLabels)-1; i >= 0 && j >= 0; i, j = i-1, j-1 {
		if nameLabels[i] != ownerLabels[j] {
			break
		}
		common++
	}
	if common == 0 {
		return ""
	}
	closest := strings.Join(nameLabels[len(nameLabels)-common:], ".") + "."
	if !WithinZone(closest, zone) {
		return ""
	}
	return closest
}

func (d Denial) nsecCovers(name string) bool {
	for _, rr := range d.NSEC {
		if d.nsecMayProveAbsence(rr, name) {
			return true
		}
	}
	return false
}

// nsecMayProveAbsence applies RFC 6840 section 4.1's two exclusions. A
// parental NSEC at a delegation, or an NSEC at a DNAME, does not authorize the
// parent to deny records below that point. Without this check, authentic data
// from an ancestor can be replayed as an NXDOMAIN under its child.
func (d Denial) nsecMayProveAbsence(rr *dns.NSEC, name string) bool {
	if !nsecCovers(rr, name) {
		return false
	}
	owner := rr.Header().Name
	// Query plugins retain a client QNAME without its trailing root label,
	// while DNS RRs are fully qualified. dns.EqualName requires both inputs to
	// be FQDNs and panics otherwise. Canonical comparison has the DNSSEC name
	// semantics we need here and accepts either internal representation.
	if canonicalCompare(name, owner) != 0 && WithinZone(name, owner) {
		if coversType(rr.TypeBitMap, dns.TypeDNAME) {
			return false
		}
		if coversType(rr.TypeBitMap, dns.TypeNS) && !coversType(rr.TypeBitMap, dns.TypeSOA) &&
			d.zone != "" && CountLabels(d.zone) < CountLabels(owner) {
			return false
		}
	}
	return true
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
				// RFC 5155 section 8.3 requires the closest-encloser record
				// to be authoritative for this zone: a DNAME cannot be used,
				// and NS is acceptable only together with SOA at the apex.
				if coversType(rr.TypeBitMap, dns.TypeDNAME) ||
					(coversType(rr.TypeBitMap, dns.TypeNS) && !coversType(rr.TypeBitMap, dns.TypeSOA)) {
					return "", false
				}
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
		if hashed != "" && nsec3Covers(rr, hashed) && d.nsec3MayProveAbsence(rr, name) {
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
		if d.nsecMayProveAbsence(rr, nextCloser) {
			return true
		}
	}
	for _, rr := range d.NSEC3 {
		if rr.Iterations > maxNSEC3Iterations {
			continue
		}
		hashed := NSEC3Hash(nextCloser, rr.Hash, rr.Iterations, rr.Salt)
		if hashed != "" && nsec3Covers(rr, hashed) && d.nsec3MayProveAbsence(rr, nextCloser) {
			return true
		}
	}
	return false
}

// ProvesNotADelegation reports whether the zone showed that name is an ordinary
// name inside it rather than a delegation to a child zone.
//
// The distinction decides whether a missing delegation signer means "there is
// nothing delegated here" or "there is a child zone and its parent does not
// sign for it", and only the first allows the walk to carry on using this
// zone's keys. Positive proof is required: an NSEC or NSEC3 matching the name
// itself, without NS in its type bitmap. A covering NSEC also proves this: the
// name does not exist in the parent zone, so cannot be its delegation point.
// A covering NSEC3 has that meaning only without Opt-Out; an Opt-Out span can
// conceal an unsigned delegation. Anything less -- a proof for another name,
// an opt-out span, hashing this build declines to do -- establishes nothing,
// and treating that as "not a delegation" would hand the parent's keys to a
// child zone and refuse its unsigned answers as forged.
func (d Denial) ProvesNotADelegation(name string) bool {
	for _, rr := range d.NSEC {
		if canonicalCompare(rr.Header().Name, name) != 0 {
			if d.nsecMayProveAbsence(rr, name) {
				return true
			}
			continue
		}
		// SOA marks a zone apex, which this name would not be if it were merely
		// a name inside the zone above.
		if coversType(rr.TypeBitMap, dns.TypeNS) || coversType(rr.TypeBitMap, dns.TypeSOA) {
			return false
		}
		return true
	}
	for _, rr := range d.NSEC3 {
		hashed := NSEC3Hash(name, rr.Hash, rr.Iterations, rr.Salt)
		if hashed == "" {
			continue
		}
		if hashed != strings.ToUpper(firstLabel(rr.Header().Name)) {
			// RFC 5155 section 8.9 permits an NSEC3 span to hide an unsigned
			// delegation only with Opt-Out. Without that bit, a covered name is
			// known not to be a zone cut.
			if rr.Flags == 0 && nsec3Covers(rr, hashed) && d.nsec3MayProveAbsence(rr, name) {
				return true
			}
			continue
		}
		if coversType(rr.TypeBitMap, dns.TypeNS) || coversType(rr.TypeBitMap, dns.TypeSOA) {
			return false
		}
		return true
	}
	for _, cname := range d.cnames {
		if canonicalCompare(cname.Header().Name, name) == 0 {
			return true
		}
	}
	return false
}

// nsec3MayProveAbsence is the NSEC3 form of the RFC 6840 section 4.1 guard.
// The original owner is hashed, so test every ancestor of the claimed-absent
// name against this NSEC3 owner. Only an exact hash match establishes that its
// DNAME or delegation bitmap belongs to an ancestor rather than an unrelated
// point in the hash ring.
func (d Denial) nsec3MayProveAbsence(rr *dns.NSEC3, name string) bool {
	if !coversType(rr.TypeBitMap, dns.TypeDNAME) &&
		!(coversType(rr.TypeBitMap, dns.TypeNS) && !coversType(rr.TypeBitMap, dns.TypeSOA)) {
		return true
	}
	zone := d.zone
	if zone == "" {
		zone = "."
	}
	candidate := canonicalName(name)
	owner := strings.ToUpper(firstLabel(rr.Header().Name))
	for {
		if NSEC3Hash(candidate, rr.Hash, rr.Iterations, rr.Salt) == owner {
			return false
		}
		if canonicalCompare(candidate, zone) == 0 {
			return true
		}
		parent := parentName(candidate)
		if parent == candidate {
			return true
		}
		candidate = parent
	}
}
