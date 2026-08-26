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
	// with the signatures over them. No records and no error means the parent
	// published none -- a delegation to an unsigned zone.
	DS(zone string) (dss []*dns.DS, sigs []*dns.RRSIG, err error)
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
func BuildChain(f Fetcher, zone string, anchors []*dns.DS, now time.Time) ChainResult {
	zones := AncestorZones(zone)

	// The root's keys are anchored by the trust anchors rather than by a parent.
	keys, sigs, err := f.DNSKEY(".")
	if err != nil {
		return ChainResult{Status: Indeterminate, Zone: ".", Why: fmt.Errorf("fetch root keys: %w", err)}
	}
	if res, err := VerifyDNSKEYs(keys, sigs, anchors, now); res != Secure {
		return ChainResult{Status: res, Zone: ".", Why: fmt.Errorf("root key set: %w", err)}
	}
	current := ChainResult{Status: Secure, Keys: keys, Zone: "."}

	for _, child := range zones[1:] {
		dss, dsSigs, err := f.DS(child)
		if err != nil {
			return ChainResult{Status: Indeterminate, Zone: current.Zone, Why: fmt.Errorf("fetch DS for %s: %w", child, err)}
		}
		if len(dss) == 0 {
			// The parent delegates without signing for the child. Everything at
			// or below here is outside DNSSEC's reach.
			current.Status = Insecure
			current.Keys = nil
			current.Why = fmt.Errorf("%s is delegated without a signer", child)
			return current
		}

		// The DS set is the parent's data, so the parent's keys must sign it.
		dsSet := make([]dns.RR, 0, len(dss))
		for _, ds := range dss {
			dsSet = append(dsSet, ds)
		}
		if res, err := VerifyRRSet(dsSet, dsSigs, current.Keys, now); res != Secure {
			return ChainResult{
				Status: Bogus, Zone: current.Zone,
				Why: fmt.Errorf("delegation signer for %s is not signed by %s: %w", child, current.Zone, err),
			}
		}

		childKeys, childSigs, err := f.DNSKEY(child)
		if err != nil {
			return ChainResult{Status: Indeterminate, Zone: current.Zone, Why: fmt.Errorf("fetch keys for %s: %w", child, err)}
		}
		if res, err := VerifyDNSKEYs(childKeys, childSigs, dss, now); res != Secure {
			return ChainResult{Status: res, Zone: child, Why: fmt.Errorf("key set for %s: %w", child, err)}
		}
		current = ChainResult{Status: Secure, Keys: childKeys, Zone: child}
	}
	return current
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
