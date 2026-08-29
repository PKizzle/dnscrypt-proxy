package dnssec

import (
	"fmt"
	"strings"
	"time"

	"codeberg.org/miekg/dns"
)

// RootAnchors are the delegation signers for the root zone, published by IANA
// (RFC 7958). Every chain this package builds ends here; nothing above them is
// verifiable, so they are the one thing taken on trust.
//
// Both current keys are listed. A resolver that knows only the older one stops
// working the day the root retires it, which is exactly the kind of outage that
// gets DNSSEC turned off rather than fixed.
var RootAnchors = []*dns.DS{
	newDS(".", 20326, dns.RSASHA256, 2,
		"E06D44B80B8F1D39A95C0B0D7C65D08458E880409BBC683457104237C7F8EC8D"),
	newDS(".", 38696, dns.RSASHA256, 2,
		"683D2D0ACB8C9B712A1948B27F741219298D0A450D612C483AF444A4C0FB2B16"),
}

func newDS(owner string, keyTag uint16, algorithm uint8, digestType uint8, digest string) *dns.DS {
	ds := &dns.DS{Hdr: dns.Header{Name: owner, Class: dns.ClassINET, TTL: 3600}}
	ds.KeyTag = keyTag
	ds.Algorithm = algorithm
	ds.DigestType = digestType
	ds.Digest = digest
	return ds
}

// Fetcher retrieves the records a chain is built from.
//
// It is an interface because the chain logic is worth testing without a network
// and without the proxy: a fake that serves a hierarchy built in the test says
// far more about whether the walk is right than any live query could.
type Fetcher interface {
	// DNSKEY returns the key set of zone, with the signatures over it.
	DNSKEY(zone string) (keys []*dns.DNSKEY, sigs []*dns.RRSIG, err error)
	// DS returns the delegation signers the PARENT of zone publishes for it,
	// with the signatures over them and whatever the parent offered in place of
	// them. No records and no error does NOT by itself mean an unsigned
	// delegation: most names are not zone cuts at all, and the denial is what
	// tells the two apart.
	DS(zone string) (dss []*dns.DS, sigs []*dns.RRSIG, denial Denial, err error)
}

// ChainResult is what walking the chain established about a zone.
type ChainResult struct {
	// Status is Secure when keys were reached, Insecure when a delegation
	// proved unsigned, Bogus when something along the way did not hold up.
	Status Result
	// Keys may sign records in Zone. Empty unless Status is Secure.
	Keys []*dns.DNSKEY
	// Zone is the deepest zone the walk established keys for.
	Zone string
	// Why explains an Insecure or Bogus outcome.
	Why error
}

// AncestorZones lists the zones enclosing name, root first, ending with name
// itself: "www.example.com." yields ".", "com.", "example.com.",
// "www.example.com.".
//
// Every one of them is a possible zone cut. Which of them actually are cuts is
// what walking the chain discovers.
func AncestorZones(name string) []string {
	// Canonical form is lower case and ends in a dot; the library keeps its own
	// helper unexported, and the rule is short enough to state here.
	name = strings.ToLower(name)
	if !strings.HasSuffix(name, ".") {
		name += "."
	}
	if name == "." {
		return []string{"."}
	}
	name = strings.TrimSuffix(name, ".")
	labels := strings.Split(name, ".")
	zones := make([]string, 0, len(labels)+1)
	zones = append(zones, ".")
	for i := len(labels) - 1; i >= 0; i-- {
		zones = append(zones, strings.Join(labels[i:], ".")+".")
	}
	return zones
}

// BuildChain walks from the root down to zone, returning the keys that may sign
// records there.
//
// The walk stops at the first delegation the parent does not sign for. That is
// the ordinary case -- most zones are unsigned -- and it is reported as
// Insecure rather than as a failure. It is also the downgrade an attacker
// wants: stripping a DS makes a signed zone look unsigned. Proving the absence
// of a DS needs the denial-of-existence records from the parent, so a caller
// that must not be downgraded checks DSProven before believing Insecure.
// forget drops a zone from a fetcher that keeps anything, so a set that did not
// verify is asked for again rather than answered from cache.
func forget(f Fetcher, zone string) {
	if c, ok := f.(interface{ ForgetZone(string) }); ok {
		c.ForgetZone(zone)
	}
}

func BuildChain(f Fetcher, zone string, anchors []*dns.DS, now time.Time) ChainResult {
	zones := AncestorZones(zone)

	// The root's keys are anchored by the trust anchors rather than by a parent.
	keys, sigs, err := f.DNSKEY(".")
	if err != nil {
		return ChainResult{Status: Indeterminate, Zone: ".", Why: fmt.Errorf("fetch root keys: %w", err)}
	}
	if res, err := VerifyDNSKEYs(keys, sigs, anchors, now); res != Secure {
		// Held keys that do not verify are worse than none: kept, they answer
		// every walk from cache and leave everything below unvalidated until
		// they expire. At the root that is every name there is.
		forget(f, ".")
		return ChainResult{Status: res, Zone: ".", Why: fmt.Errorf("root key set: %w", err)}
	}
	current := ChainResult{Status: Secure, Keys: keys, Zone: "."}
	// An authenticated name-error proof establishes that this label is absent
	// from the current zone. DNS names with descendants are existing empty
	// non-terminals, so no label below a proven-absent name can be a zone cut.
	// Remembering that fact avoids asking every descendant for its own DS proof.
	//
	// This is deliberately a complete name-error proof, not merely a covering
	// NSEC/NSEC3: RFC 5155 sections 8.3 and 8.4 require the closest encloser,
	// next-closer, and wildcard evidence before a validator can conclude that a
	// name is absent. An exact NSEC/NSEC3 or a signed CNAME only establishes
	// that one label is not a cut; a delegation may still exist below it.
	var absentAncestor string

	for _, child := range zones[1:] {
		if absentAncestor != "" && WithinZone(child, absentAncestor) {
			continue
		}
		dss, _, denial, err, invalid := verifiedDelegationSigners(f, child, current, now)
		if err != nil {
			if invalid {
				return ChainResult{
					Status: Bogus, Zone: current.Zone,
					Why: fmt.Errorf("delegation signer for %s is not signed by %s: %w", child, current.Zone, err),
				}
			}
			return ChainResult{Status: Indeterminate, Zone: current.Zone, Why: fmt.Errorf("fetch DS for %s: %w", child, err)}
		}
		if len(dss) == 0 {
			denial = denial.Verified(current.Keys, current.Zone, now)
			// No delegation signer has two very different meanings, and reading
			// the wrong one costs either coverage or correctness.
			//
			// Most names are not zone cuts: "www.example.com" is a record
			// inside "example.com", and its parent publishes no DS for it
			// because there is nothing there to delegate. Calling that an
			// unsigned delegation stops the walk one zone too deep and leaves
			// every such name unvalidated -- which is nearly every name that
			// matters.
			//
			// A delegation that genuinely exists and is genuinely unsigned is
			// the other meaning, and the parent says which by whether it proves
			// an NS at that name.
			switch {
			case denial.ProvesNoDS(child):
				current.Status = Insecure
				current.Keys = nil
				current.Why = fmt.Errorf("%s is delegated without a signer", child)
				return current
			case denial.Empty():
				// Nothing was offered to tell the two apart. Descending on the
				// parent's keys would refuse a genuinely unsigned zone for
				// carrying no signature, so this stays where it was and says that
				// nothing could be concluded. It is not an unsigned delegation:
				// no signed proof established one.
				current.Status = Indeterminate
				current.Keys = nil
				current.Why = fmt.Errorf("%s: no proof of what is or is not delegated there", child)
				return current
			case denial.ProvesNameError(child, current.Zone):
				// A complete authenticated name-error proof says this label is
				// absent, not just that it is an ordinary existing name. Any
				// descendant is therefore absent too, so it cannot be a zone
				// cut. Retain the current zone's keys for the original response.
				absentAncestor = canonicalName(child)
				continue
			case denial.ProvesNotADelegation(child):
				// An ordinary name inside the zone reached so far. The walk
				// carries on rather than stopping here: a label further down
				// can still be a zone cut, and stopping at the first one that
				// is not would hand this zone's keys to a child zone below it
				// and refuse that zone's unsigned answers as forged. A CDN
				// name three labels below a signed zone is exactly that shape.
				continue
			default:
				// The parent offered something, but nothing that settles which
				// of the two this is. Carrying on would hand its keys to what
				// may be a child zone and then refuse that zone's unsigned
				// answers as forged -- which is what a reverse-DNS delegation
				// under an opt-out span looks like from here.
				current.Status = Indeterminate
				current.Keys = nil
				current.Why = fmt.Errorf("%s: nothing shown either way about a delegation there", child)
				return current
			}
		}

		childKeys, childSigs, err := f.DNSKEY(child)
		if err != nil {
			return ChainResult{Status: Indeterminate, Zone: current.Zone, Why: fmt.Errorf("fetch keys for %s: %w", child, err)}
		}
		if res, err := VerifyDNSKEYs(childKeys, childSigs, dss, now); res != Secure {
			// A key set that cannot be used stops the walk without condemning
			// the zone: everything at or below is served unvalidated, which is
			// what an unsigned zone gets and what RFC 6840 section 5.2 asks for.
			// It is dropped rather than kept, so the next walk asks again
			// instead of meeting the same answer from cache.
			forget(f, child)
			return ChainResult{Status: res, Zone: child, Why: fmt.Errorf("key set for %s: %w", child, err)}
		}
		current = ChainResult{Status: Secure, Keys: childKeys, Zone: child}
	}
	return current
}

// verifiedDelegationSigners fetches and authenticates the parent-side DS RRset
// before allowing it into the chain cache. A delivered but invalid DS response
// is not a network failure, so CachingFetcher cannot distinguish it from a
// valid response on its own. Retrying after dropping that entry matters with a
// pool of encrypted recursive upstreams: one stale or malformed response must
// not poison every name below a TLD for its TTL. It never trusts the retry
// blindly; after the bounded attempts an invalid signed delegation remains
// Bogus, as RFC 4035 requires.
func verifiedDelegationSigners(f Fetcher, child string, parent ChainResult, now time.Time) ([]*dns.DS, []*dns.RRSIG, Denial, error, bool) {
	var lastErr error
	for attempt := 0; attempt < chainFetchAttempts; attempt++ {
		dss, sigs, denial, err := f.DS(child)
		if err != nil {
			return nil, nil, Denial{}, err, false
		}
		if len(dss) == 0 {
			return dss, sigs, denial, nil, false
		}

		dsSet := make([]dns.RR, 0, len(dss))
		for _, ds := range dss {
			dsSet = append(dsSet, ds)
		}
		if res, err := VerifyRRSet(dsSet, signaturesFromZone(sigs, parent.Zone), parent.Keys, now); res == Secure {
			return dss, sigs, denial, nil, false
		} else {
			lastErr = err
		}

		// Do not let a reply which failed authentication survive in a cache. The
		// next attempt must reach an upstream again rather than re-read it.
		forget(f, child)
	}
	return nil, nil, Denial{}, lastErr, true
}

// WithinZone reports whether name is the zone itself or sits below it.
//
// The comparison is on whole labels. A suffix test alone would place
// "notexample.com" inside "example.com" and hand it that zone's keys, which is
// how a name the zone never delegated gets checked as though it had.
func WithinZone(name, zone string) bool {
	name = strings.ToLower(strings.TrimSuffix(name, "."))
	zone = strings.ToLower(strings.TrimSuffix(zone, "."))
	if zone == "" || name == zone {
		return true
	}
	return strings.HasSuffix(name, "."+zone)
}
