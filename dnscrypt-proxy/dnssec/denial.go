package dnssec

import (
	"bytes"
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
	if iterations > maxNSEC3Iterations {
		// Check the authenticated cost before doing even the first SHA-1. A
		// response may contain many unusable records, and none of them should
		// consume hashing work merely to be declined.
		return ""
	}
	saltBytes, err := hexDecode(salt)
	if err != nil {
		return ""
	}
	digest := sha1.Sum(append(wireName(name), saltBytes...)) // #nosec G401 -- RFC 5155 defines SHA-1 here
	buf := digest[:]
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
	// policyNSEC and policyNSEC3 contain structurally usable records whose
	// corresponding authenticated DNSKEY exists, but whose only covering
	// RRSIG uses an algorithm disabled by resolver policy. They are never
	// combined into a Secure proof. Status methods try the ordinary records
	// first, then may use the combined set only to return Insecure.
	policyNSEC  []*dns.NSEC
	policyNSEC3 []*dns.NSEC3
	sigs        []*dns.RRSIG
	// cnames is positive evidence collected only from a DS lookup. A signed,
	// exact CNAME at the queried name proves that the current zone owns that
	// name, and therefore that it is not a delegation point. Keeping it with
	// the DS-absence evidence lets the chain distinguish that ordinary case
	// from a response whose absence of DS data was merely unexplained.
	cnames       []*dns.CNAME
	cnameSigs    []*dns.RRSIG
	policyCNAMEs []*dns.CNAME
	zone         string
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
		if set.Type == dns.TypeNSEC3 && canonicalCompare(parentName(set.Name), zone) != 0 {
			// An NSEC3 owner is exactly one hash label below its zone. Merely
			// being somewhere beneath the signer is not enough; otherwise an
			// ordinary signed name with an NSEC3-shaped first label could be
			// repurposed as denial data. This is Unbound's filter_init zone
			// check and follows the owner construction in RFC 5155 section 3.
			continue
		}
		res, _ := VerifyRRSet(set.Records, set.Sigs, keys, now)
		if res != Secure && res != Insecure {
			continue
		}
		if set.Type == dns.TypeNSEC {
			// RFC 4035 section 5.4: a matching NSEC establishes that wildcard
			// expansion was not used only when the signer recorded the same
			// label count as the NSEC owner. A valid wildcard-expanded NSEC is
			// not a statement about an exact existing owner, so it must not be
			// used as any kind of denial proof.
			res = exactNSECSignatureStatus(set, keys, now)
			if res != Secure && res != Insecure {
				continue
			}
		}
		for _, rr := range set.Records {
			switch rr := rr.(type) {
			case *dns.NSEC:
				// RFC 4034 section 4.1.1: Next Domain Name is another
				// authoritative owner in this same zone (or the zone apex when
				// the interval wraps).  A signer cannot use its final interval to
				// deny names beyond the namespace its key authenticates.
				if !WithinZone(rr.NextDomain, zone) {
					continue
				}
				if res == Secure {
					verified.NSEC = append(verified.NSEC, rr)
				} else {
					verified.policyNSEC = append(verified.policyNSEC, rr)
				}
			case *dns.NSEC3:
				// RFC 5155 section 8.2: only flag values 0 and 1 are valid
				// NSEC3 denial proofs. Unknown flag bits must not be used to
				// establish absence or a downgrade.
				if rr.Flags != 0 && rr.Flags != 1 {
					continue
				}
				if res == Secure {
					verified.NSEC3 = append(verified.NSEC3, rr)
				} else {
					verified.policyNSEC3 = append(verified.policyNSEC3, rr)
				}
			}
		}
	}
	for _, cname := range d.cnames {
		owner := cname.Header().Name
		if !WithinZone(owner, zone) {
			continue
		}
		rrset := []dns.RR{cname}
		exactSigs := make([]*dns.RRSIG, 0, len(d.cnameSigs))
		for _, sig := range signaturesFromZone(d.cnameSigs, zone) {
			// A wildcard-expanded CNAME alone is not enough: without the
			// accompanying denial proof, it does not establish that this exact
			// owner was not a delegation. An exact signature is the positive
			// parent-side fact needed by the chain walk.
			if int(sig.Labels) != CountLabels(owner) {
				continue
			}
			exactSigs = append(exactSigs, sig)
		}
		res, _ := VerifyRRSet(rrset, exactSigs, keys, now)
		switch res {
		case Secure:
			verified.cnames = append(verified.cnames, cname)
		case Insecure:
			verified.policyCNAMEs = append(verified.policyCNAMEs, cname)
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
func exactNSECSignatureStatus(set RRSet, keys []*dns.DNSKEY, now time.Time) Result {
	exactSigs := make([]*dns.RRSIG, 0, len(set.Sigs))
	for _, sig := range set.Sigs {
		labels := CountLabels(set.Name)
		exactWildcardOwner := strings.HasPrefix(canonicalName(set.Name), "*.") && int(sig.Labels) == labels-1
		if int(sig.Labels) != labels && !exactWildcardOwner {
			continue
		}
		exactSigs = append(exactSigs, sig)
	}
	res, _ := VerifyRRSet(set.Records, exactSigs, keys, now)
	if res == Secure || res == Insecure {
		return res
	}
	return Indeterminate
}

// Empty reports whether nothing was offered.
func (d Denial) Empty() bool {
	return len(d.NSEC) == 0 && len(d.NSEC3) == 0 && len(d.cnames) == 0 &&
		len(d.policyNSEC) == 0 && len(d.policyNSEC3) == 0 && len(d.policyCNAMEs) == 0
}

// withPolicyRecords returns a copy containing both fully verified records and
// records whose only usable signature has an authenticated but policy-disabled
// algorithm. Callers must use that copy only to decide Insecure, never Secure.
// Trying the original Denial first ensures an unrelated deprecated signature
// cannot downgrade a complete proof made with an accepted algorithm.
func (d Denial) withPolicyRecords() (Denial, bool) {
	if len(d.policyNSEC) == 0 && len(d.policyNSEC3) == 0 && len(d.policyCNAMEs) == 0 {
		return d, false
	}
	combined := d
	combined.NSEC = append(append([]*dns.NSEC(nil), d.NSEC...), d.policyNSEC...)
	combined.NSEC3 = append(append([]*dns.NSEC3(nil), d.NSEC3...), d.policyNSEC3...)
	combined.cnames = append(append([]*dns.CNAME(nil), d.cnames...), d.policyCNAMEs...)
	combined.policyNSEC = nil
	combined.policyNSEC3 = nil
	combined.policyCNAMEs = nil
	return combined, true
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

// HasMixedNSEC3Parameters reports whether authenticated NSEC3 records from
// the same response belong to different hash chains. RFC 5155 section 8.2
// permits treating such a response as bogus. More importantly, the individual
// closest-encloser, next-closer, and wildcard facts must not be assembled from
// different chains. Unbound applies the same check in param_set_same().
func (d Denial) HasMixedNSEC3Parameters() bool {
	var (
		first     *dns.NSEC3
		firstSalt []byte
	)
	for _, rr := range d.NSEC3 {
		// Unknown hash algorithms are ignored by RFC 5155 section 8.1 and
		// therefore do not participate in a known chain's parameters.
		if rr.Hash != 1 {
			continue
		}
		salt, err := hexDecode(rr.Salt)
		if err != nil {
			continue
		}
		if first == nil {
			first = rr
			firstSalt = salt
			continue
		}
		if rr.Hash != first.Hash || rr.Iterations != first.Iterations || !bytes.Equal(salt, firstSalt) {
			return true
		}
	}
	return false
}

// maxNSEC3Calculations is a final bound on distinct names hashed during one
// denial proof. A legal DNS name can contain at most 127 one-octet labels, so
// 256 leaves room for every ancestor plus the next-closer and wildcard names.
// The ordinary bound comes from memoization: authenticated response records
// can multiply cheap comparisons, but can no longer multiply SHA-1 work.
const maxNSEC3Calculations = 256

type nsec3Proof struct {
	algorithm    uint8
	iterations   uint16
	salt         string
	saltBytes    []byte
	usable       bool
	hashes       map[string]string
	calculations int
	exhausted    bool
}

// newNSEC3Proof chooses the one usable parameter chain for a proof. RFC 5155
// section 8.2 permits a mixed-chain response to be treated as bogus; combining
// facts from those chains would be unsound and would also defeat hash caching.
func newNSEC3Proof(d Denial) *nsec3Proof {
	proof := &nsec3Proof{hashes: make(map[string]string)}
	if d.HasMixedNSEC3Parameters() {
		return proof
	}
	for _, rr := range d.NSEC3 {
		if rr.Hash != 1 || rr.Iterations > maxNSEC3Iterations {
			continue
		}
		salt, err := hexDecode(rr.Salt)
		if err != nil {
			continue
		}
		proof.algorithm = rr.Hash
		proof.iterations = rr.Iterations
		proof.salt = rr.Salt
		proof.saltBytes = salt
		proof.usable = true
		break
	}
	return proof
}

func (proof *nsec3Proof) matches(rr *dns.NSEC3) bool {
	if proof == nil || !proof.usable || rr == nil || rr.Hash != proof.algorithm || rr.Iterations != proof.iterations {
		return false
	}
	salt, err := hexDecode(rr.Salt)
	return err == nil && bytes.Equal(salt, proof.saltBytes)
}

func (proof *nsec3Proof) hash(name string) string {
	if proof == nil || !proof.usable {
		return ""
	}
	name = canonicalName(name)
	if hashed, ok := proof.hashes[name]; ok {
		return hashed
	}
	if proof.calculations >= maxNSEC3Calculations {
		proof.exhausted = true
		return ""
	}
	proof.calculations++
	hashed := NSEC3Hash(name, proof.algorithm, proof.iterations, proof.salt)
	proof.hashes[name] = hashed
	return hashed
}

// ProvesNoData reports whether the zone securely proved that name exists but
// holds no record of rrtype.
//
// The proof is a record matching the name whose bitmap omits the type. The
// bitmap is what carries the meaning, so a CNAME entry has to be refused as
// well: the answer should have followed that alias. A DNAME entry is different:
// RFC 6672 section 2.3 says the DNAME owner itself is not redirected and may
// hold other RR types, so an exact-owner proof may legitimately omit rrtype.
// DNAME remains disallowed when an NSEC/NSEC3 is used to deny a descendant.
func (d Denial) ProvesNoData(name string, rrtype uint16) bool {
	return d.NoDataStatus(name, rrtype) == Secure
}

// NoDataStatus preserves an RFC 9905 policy downgrade: records signed only by
// a corresponding but disabled algorithm may establish an Insecure answer,
// but can never contribute to a Secure proof.
func (d Denial) NoDataStatus(name string, rrtype uint16) Result {
	if d.provesNoDataWithProof(name, rrtype, newNSEC3Proof(d)) {
		return Secure
	}
	if combined, ok := d.withPolicyRecords(); ok &&
		combined.provesNoDataWithProof(name, rrtype, newNSEC3Proof(combined)) {
		return Insecure
	}
	return Indeterminate
}

func (d Denial) provesNoData(name string, rrtype uint16) bool {
	return d.provesNoDataWithProof(name, rrtype, newNSEC3Proof(d))
}

func (d Denial) provesNoDataWithProof(name string, rrtype uint16, proof *nsec3Proof) bool {
	for _, rr := range d.NSEC {
		if canonicalCompare(rr.Header().Name, name) != 0 {
			// RFC 4035 section 5.4 also permits an NSEC interval to prove
			// that no RRsets exist at an empty non-terminal.  In canonical
			// order the owner precedes QNAME, QNAME is covered, and the next
			// owner is a strict descendant of QNAME.  That descendant is why
			// the otherwise empty name exists.
			if canonicalCompare(rr.Header().Name, name) < 0 &&
				d.nsecMayProveAbsence(rr, name) &&
				canonicalCompare(rr.NextDomain, name) != 0 &&
				WithinZone(rr.NextDomain, name) {
				return true
			}
			continue
		}
		// RFC 6840 section 4.2: when an ANY response contains no answer
		// RRsets, validation must establish that no RRsets exist at QNAME.
		// An exact NSEC owner establishes the opposite even though the ANY
		// meta-type is (correctly) absent from its bitmap.
		if rrtype == dns.TypeANY {
			return false
		}
		if coversType(rr.TypeBitMap, rrtype) ||
			coversType(rr.TypeBitMap, dns.TypeCNAME) ||
			(coversType(rr.TypeBitMap, dns.TypeNS) && !coversType(rr.TypeBitMap, dns.TypeSOA)) {
			return false
		}
		return true
	}
	hashed := proof.hash(name)
	if hashed == "" {
		return false
	}
	for _, rr := range d.NSEC3 {
		if !proof.matches(rr) || hashed != strings.ToUpper(firstLabel(rr.Header().Name)) {
			continue
		}
		if rrtype == dns.TypeANY {
			// RFC 5155 section 8.5: unlike NSEC, NSEC3 may include an
			// exact hash with an empty type bitmap specifically to represent
			// an empty non-terminal. That is the one exact-owner proof which
			// establishes that an empty ANY answer contains every RRset at
			// QNAME (namely none), as RFC 6840 section 4.2 requires.
			return len(rr.TypeBitMap) == 0
		}
		if coversType(rr.TypeBitMap, rrtype) ||
			coversType(rr.TypeBitMap, dns.TypeCNAME) ||
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
	return d.WildcardNoDataStatus(name, zone, rrtype) == Secure
}

// WildcardNoDataStatus reports how completely an authenticated denial proves
// that a wildcard, rather than the queried name, exists without rrtype.
//
// An NSEC3 Opt-Out span over the next-closer name is a valid response, but it
// can hide an unsigned delegation at that name. RFC 5155 section 9.2 therefore
// forbids AD on the response. Keeping that as Insecure instead of collapsing
// it into either Secure or "no proof" lets callers serve the valid response
// without authenticating what the Opt-Out span deliberately did not prove.
func (d Denial) WildcardNoDataStatus(name, zone string, rrtype uint16) Result {
	status := d.wildcardNoDataStatusWithProof(name, zone, rrtype, newNSEC3Proof(d))
	if status != Indeterminate {
		return status
	}
	if combined, ok := d.withPolicyRecords(); ok &&
		combined.wildcardNoDataStatusWithProof(name, zone, rrtype, newNSEC3Proof(combined)) != Indeterminate {
		return Insecure
	}
	return Indeterminate
}

func (d Denial) wildcardNoDataStatus(name, zone string, rrtype uint16) Result {
	return d.wildcardNoDataStatusWithProof(name, zone, rrtype, newNSEC3Proof(d))
}

func (d Denial) wildcardNoDataStatusWithProof(name, zone string, rrtype uint16, proof *nsec3Proof) Result {
	if len(d.NSEC) > 0 {
		for _, rr := range d.NSEC {
			if !d.nsecMayProveAbsence(rr, name) {
				continue
			}
			closest := nsecClosestEncloser(name, rr, zone)
			if closest != "" && d.provesNoDataWithProof(wildcardName(closest), rrtype, proof) {
				return Secure
			}
		}
		return Indeterminate
	}

	closest, ok := d.closestEncloserWithProof(name, zone, proof)
	if !ok {
		return Indeterminate
	}
	nextCloser := nextCloserName(name, closest)
	if nextCloser == "" || !d.provesNoDataWithProof(wildcardName(closest), rrtype, proof) {
		return Indeterminate
	}
	return d.nsec3CoverageStatusWithProof(nextCloser, proof)
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
	return d.NoDSStatus(name) != Indeterminate
}

// NoDSStatus distinguishes an exact authenticated denial from an NSEC3
// Opt-Out denial. Both establish that the parent supplies no usable DS for a
// child, but only the exact proof itself can carry AD. The Opt-Out form means
// the child is insecure and RFC 5155 section 9.2 forbids authenticating the
// response as a whole.
func (d Denial) NoDSStatus(name string) Result {
	status := d.noDSStatusWithProof(name, newNSEC3Proof(d))
	if status != Indeterminate {
		return status
	}
	if combined, ok := d.withPolicyRecords(); ok &&
		combined.noDSStatusWithProof(name, newNSEC3Proof(combined)) != Indeterminate {
		return Insecure
	}
	return Indeterminate
}

func (d Denial) noDSStatus(name string) Result {
	return d.noDSStatusWithProof(name, newNSEC3Proof(d))
}

func (d Denial) noDSStatusWithProof(name string, proof *nsec3Proof) Result {
	for _, rr := range d.NSEC {
		if canonicalCompare(rr.Header().Name, name) != 0 {
			continue
		}
		if coversType(rr.TypeBitMap, dns.TypeDS) || coversType(rr.TypeBitMap, dns.TypeSOA) {
			return Indeterminate
		}
		if coversType(rr.TypeBitMap, dns.TypeNS) {
			return Secure
		}
		return Indeterminate
	}
	hashed := proof.hash(name)
	for _, rr := range d.NSEC3 {
		if hashed == "" || !proof.matches(rr) {
			continue
		}
		if hashed == strings.ToUpper(firstLabel(rr.Header().Name)) {
			if coversType(rr.TypeBitMap, dns.TypeDS) || coversType(rr.TypeBitMap, dns.TypeSOA) {
				return Indeterminate
			}
			if coversType(rr.TypeBitMap, dns.TypeNS) {
				return Secure
			}
			return Indeterminate
		}
	}
	// Opt-Out is not proved by an arbitrary covering span. RFC 5155 sections
	// 8.6 and 8.9 require a full closest-provable-encloser proof, and require
	// its next-closer span to carry Opt-Out. Without the matching encloser, a
	// signed interval elsewhere in the hash ring says nothing about this cut.
	if d.zone == "" || hashed == "" {
		return Indeterminate
	}
	closest, ok := d.closestEncloserWithProof(name, d.zone, proof)
	if !ok {
		return Indeterminate
	}
	nextCloser := nextCloserName(name, closest)
	if nextCloser != "" && d.nsec3CoverageStatusWithProof(nextCloser, proof) == Insecure {
		return Insecure
	}
	return Indeterminate
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
	return d.NameErrorStatus(name, zone) == Secure
}

// NameErrorStatus reports whether a name error is fully authenticated or
// rests on an NSEC3 Opt-Out closest-encloser proof. The latter is Insecure:
// the next-closer span may hide an unsigned delegation, so RFC 5155 section
// 9.2 explicitly says the response MUST NOT carry AD.
func (d Denial) NameErrorStatus(name, zone string) Result {
	status := d.nameErrorStatusWithProof(name, zone, newNSEC3Proof(d))
	if status != Indeterminate {
		return status
	}
	if combined, ok := d.withPolicyRecords(); ok &&
		combined.nameErrorStatusWithProof(name, zone, newNSEC3Proof(combined)) != Indeterminate {
		return Insecure
	}
	return Indeterminate
}

func (d Denial) nameErrorStatus(name, zone string) Result {
	return d.nameErrorStatusWithProof(name, zone, newNSEC3Proof(d))
}

func (d Denial) nameErrorStatusWithProof(name, zone string, proof *nsec3Proof) Result {
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
			closest := nsecClosestEncloser(name, rr, zone)
			if closest != "" && d.nsecCovers(wildcardName(closest)) {
				return Secure
			}
		}
		return Indeterminate
	}

	// NSEC3 proves it in three parts: the deepest ancestor that does exist, the
	// absence of the next label down from it, and the absence of a wildcard at
	// that ancestor.
	closest, ok := d.closestEncloserWithProof(name, zone, proof)
	if !ok {
		return Indeterminate
	}
	nextCloser := nextCloserName(name, closest)
	if nextCloser == "" {
		return Indeterminate
	}
	status := d.nsec3CoverageStatusWithProof(nextCloser, proof)
	if status == Indeterminate || !d.coveredWithProof(wildcardName(closest), proof) {
		return Indeterminate
	}
	return status
}

// nsecClosestEncloser derives the closest enclosing name retained by an NSEC
// proof. Both endpoints are existing names. RFC 4592 section 3.3.1 defines the
// closest encloser as the deepest existing ancestor of QNAME, so it is the
// longer shared suffix with either the owner or Next Domain Name. Looking only
// at the owner misses empty non-terminals implied by the next name and checks a
// higher wildcard than the one the authoritative lookup would actually use.
func nsecClosestEncloser(name string, rr *dns.NSEC, zone string) string {
	ownerClosest := sharedTopDomain(name, rr.Header().Name)
	nextClosest := sharedTopDomain(name, rr.NextDomain)
	closest := ownerClosest
	if CountLabels(nextClosest) > CountLabels(ownerClosest) {
		closest = nextClosest
	}
	if !WithinZone(closest, zone) {
		return ""
	}
	return closest
}

func sharedTopDomain(a, b string) string {
	nameLabels := canonicalLabels(a)
	otherLabels := canonicalLabels(b)
	common := 0
	for i, j := len(nameLabels)-1, len(otherLabels)-1; i >= 0 && j >= 0; i, j = i-1, j-1 {
		if nameLabels[i] != otherLabels[j] {
			break
		}
		common++
	}
	if common == 0 {
		// canonicalLabels omits the root's empty label, which every pair of
		// absolute DNS names shares.
		return "."
	}
	return strings.Join(nameLabels[len(nameLabels)-common:], ".") + "."
}

// wildcardName returns the wildcard at closest. The root's wildcard is "*.",
// not "*.."; keeping this in one helper prevents root-zone NSEC proofs from
// becoming malformed while ordinary zones retain their familiar form.
func wildcardName(closest string) string {
	if canonicalName(closest) == "." {
		return "*."
	}
	return "*." + canonicalName(closest)
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
	return d.closestEncloserWithProof(name, zone, newNSEC3Proof(d))
}

func (d Denial) closestEncloserWithProof(name, zone string, proof *nsec3Proof) (string, bool) {
	candidate := canonicalName(name)
	zone = canonicalName(zone)
	for {
		hashed := proof.hash(candidate)
		if hashed == "" {
			return "", false
		}
		for _, rr := range d.NSEC3 {
			if proof.matches(rr) && hashed == strings.ToUpper(firstLabel(rr.Header().Name)) {
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
	return d.coveredWithProof(name, newNSEC3Proof(d))
}

func (d Denial) coveredWithProof(name string, proof *nsec3Proof) bool {
	hashed := proof.hash(name)
	if hashed == "" {
		return false
	}
	for _, rr := range d.NSEC3 {
		if proof.matches(rr) && nsec3Covers(rr, hashed) && d.nsec3MayProveAbsenceWithProof(rr, name, proof) {
			return true
		}
	}
	return false
}

// nsec3CoverageStatus returns Secure when an authenticated non-Opt-Out span
// covers name, Insecure when only Opt-Out spans do, and Indeterminate when no
// usable span does. Prefer a non-Opt-Out proof if a response contains both:
// that proof establishes absence without the delegation ambiguity Opt-Out
// intentionally creates.
func (d Denial) nsec3CoverageStatus(name string) Result {
	return d.nsec3CoverageStatusWithProof(name, newNSEC3Proof(d))
}

func (d Denial) nsec3CoverageStatusWithProof(name string, proof *nsec3Proof) Result {
	hashed := proof.hash(name)
	if hashed == "" {
		return Indeterminate
	}
	optOut := false
	for _, rr := range d.NSEC3 {
		if !proof.matches(rr) || !nsec3Covers(rr, hashed) ||
			!d.nsec3MayProveAbsenceWithProof(rr, name, proof) {
			continue
		}
		if rr.Flags&1 == 0 {
			return Secure
		}
		optOut = true
	}
	if optOut {
		return Insecure
	}
	return Indeterminate
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
	return d.NoCloserMatchStatus(nextCloser) == Secure
}

// NoCloserMatchStatus is the wildcard-answer counterpart of
// NameErrorStatus. A signed wildcard RRset plus an Opt-Out span still cannot
// authenticate that no unsigned delegation exists closer to QNAME.
func (d Denial) NoCloserMatchStatus(nextCloser string) Result {
	status := d.noCloserMatchStatus(nextCloser)
	if status != Indeterminate {
		return status
	}
	if combined, ok := d.withPolicyRecords(); ok && combined.noCloserMatchStatus(nextCloser) != Indeterminate {
		return Insecure
	}
	return Indeterminate
}

func (d Denial) noCloserMatchStatus(nextCloser string) Result {
	for _, rr := range d.NSEC {
		if d.nsecMayProveAbsence(rr, nextCloser) {
			return Secure
		}
	}
	if len(d.NSEC) > 0 {
		return Indeterminate
	}
	return d.nsec3CoverageStatus(nextCloser)
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
	return d.NotADelegationStatus(name) == Secure
}

// NotADelegationStatus distinguishes a fully authenticated proof from one
// whose necessary RRsets use only a policy-disabled signing algorithm.
func (d Denial) NotADelegationStatus(name string) Result {
	if d.provesNotADelegationWithProof(name, newNSEC3Proof(d)) {
		return Secure
	}
	if combined, ok := d.withPolicyRecords(); ok &&
		combined.provesNotADelegationWithProof(name, newNSEC3Proof(combined)) {
		return Insecure
	}
	return Indeterminate
}

func (d Denial) provesNotADelegation(name string) bool {
	return d.provesNotADelegationWithProof(name, newNSEC3Proof(d))
}

func (d Denial) provesNotADelegationWithProof(name string, proof *nsec3Proof) bool {
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
	hashed := proof.hash(name)
	for _, rr := range d.NSEC3 {
		if hashed == "" || !proof.matches(rr) {
			continue
		}
		if hashed != strings.ToUpper(firstLabel(rr.Header().Name)) {
			// RFC 5155 section 8.9 permits an NSEC3 span to hide an unsigned
			// delegation only with Opt-Out. Without that bit, a covered name is
			// known not to be a zone cut.
			if rr.Flags == 0 && nsec3Covers(rr, hashed) && d.nsec3MayProveAbsenceWithProof(rr, name, proof) {
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
	// A validated wildcard NODATA response proves that the queried name is
	// absent and that the wildcard was the applicable owner. A delegation at
	// that name would have stopped wildcard synthesis, so this is positive
	// evidence that the name is not a zone cut. RFC 5155 section 8.7 requires
	// the closest-encloser and wildcard proofs used here.
	return d.zone != "" &&
		d.wildcardNoDataStatusWithProof(name, d.zone, dns.TypeDS, proof) == Secure
}

// nsec3MayProveAbsence is the NSEC3 form of the RFC 6840 section 4.1 guard.
// The original owner is hashed, so test every ancestor of the claimed-absent
// name against this NSEC3 owner. Only an exact hash match establishes that its
// DNAME or delegation bitmap belongs to an ancestor rather than an unrelated
// point in the hash ring.
func (d Denial) nsec3MayProveAbsence(rr *dns.NSEC3, name string) bool {
	return d.nsec3MayProveAbsenceWithProof(rr, name, newNSEC3Proof(d))
}

func (d Denial) nsec3MayProveAbsenceWithProof(rr *dns.NSEC3, name string, proof *nsec3Proof) bool {
	if !proof.matches(rr) {
		return false
	}
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
		hashed := proof.hash(candidate)
		if hashed == "" {
			return false
		}
		if hashed == owner {
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
