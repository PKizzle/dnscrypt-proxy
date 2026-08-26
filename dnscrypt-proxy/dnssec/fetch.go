package dnssec

import (
	"fmt"
	"sync"
	"time"

	"codeberg.org/miekg/dns"
)

// QueryFunc asks an upstream for one record set.
//
// The chain is built from answers fetched the same way every other answer is,
// over whatever transport the proxy already uses, so validation inherits its
// privacy rather than opening a second, plaintext path to the root.
//
// The caller must make these queries skip validation. Validating the key set
// used to validate a key set does not terminate.
type QueryFunc func(qname string, qtype uint16) (*dns.Msg, error)

// CachingFetcher answers DNSKEY and DS lookups for a chain walk, remembering
// what it learns.
//
// Caching is not an optimisation here so much as a requirement: without it,
// every query for a name three labels deep would fetch six records first, and
// the ones near the root would be fetched again for every name on the internet.
// Entries expire on the TTL the zone published, so a rollover is picked up
// when the zone says it will be.
type CachingFetcher struct {
	Query QueryFunc
	// Now allows tests to control expiry; time.Now when nil.
	Now func() time.Time

	mu   sync.Mutex
	keys map[string]*keyEntry
	dss  map[string]*dsEntry
}

type keyEntry struct {
	keys    []*dns.DNSKEY
	sigs    []*dns.RRSIG
	expires time.Time
}

type dsEntry struct {
	dss     []*dns.DS
	sigs    []*dns.RRSIG
	denial  Denial
	expires time.Time
}

// NewCachingFetcher returns a fetcher that asks query and caches the answers.
func NewCachingFetcher(query QueryFunc) *CachingFetcher {
	return &CachingFetcher{
		Query: query,
		keys:  map[string]*keyEntry{},
		dss:   map[string]*dsEntry{},
	}
}

func (f *CachingFetcher) now() time.Time {
	if f.Now != nil {
		return f.Now()
	}
	return time.Now()
}

// DNSKEY returns the key set of zone.
func (f *CachingFetcher) DNSKEY(zone string) ([]*dns.DNSKEY, []*dns.RRSIG, error) {
	zone = canonicalName(zone)

	f.mu.Lock()
	if e, ok := f.keys[zone]; ok && f.now().Before(e.expires) {
		keys, sigs := e.keys, e.sigs
		f.mu.Unlock()
		return keys, sigs, nil
	}
	f.mu.Unlock()

	msg, err := f.Query(zone, dns.TypeDNSKEY)
	if err != nil {
		return nil, nil, err
	}
	if msg == nil {
		return nil, nil, fmt.Errorf("no response for DNSKEY %s", zone)
	}
	if msg.Rcode != dns.RcodeSuccess {
		return nil, nil, fmt.Errorf("DNSKEY %s: rcode %d", zone, msg.Rcode)
	}

	var keys []*dns.DNSKEY
	var sigs []*dns.RRSIG
	for _, rr := range msg.Answer {
		switch v := rr.(type) {
		case *dns.DNSKEY:
			keys = append(keys, v)
		case *dns.RRSIG:
			sigs = append(sigs, v)
		}
	}
	if len(keys) == 0 {
		return nil, nil, fmt.Errorf("no keys in the answer for %s", zone)
	}

	f.mu.Lock()
	f.keys[zone] = &keyEntry{keys: keys, sigs: sigs, expires: f.now().Add(ttlOf(msg.Answer))}
	f.mu.Unlock()
	return keys, sigs, nil
}

// DS returns the delegation signers the parent of zone publishes for it.
//
// An empty result with no error means the parent published none, which the
// chain reads as an unsigned delegation. NXDOMAIN is deliberately not treated
// that way: a name that does not exist is not a zone that is merely unsigned,
// and reporting it as one would turn a typo into a silent downgrade.
func (f *CachingFetcher) DS(zone string) ([]*dns.DS, []*dns.RRSIG, Denial, error) {
	zone = canonicalName(zone)

	f.mu.Lock()
	if e, ok := f.dss[zone]; ok && f.now().Before(e.expires) {
		dss, sigs, denial := e.dss, e.sigs, e.denial
		f.mu.Unlock()
		return dss, sigs, denial, nil
	}
	f.mu.Unlock()

	msg, err := f.Query(zone, dns.TypeDS)
	if err != nil {
		return nil, nil, Denial{}, err
	}
	if msg == nil {
		return nil, nil, Denial{}, fmt.Errorf("no response for DS %s", zone)
	}
	switch msg.Rcode {
	case dns.RcodeSuccess:
	case dns.RcodeNameError:
		return nil, nil, Denial{}, fmt.Errorf("DS %s: the name does not exist", zone)
	default:
		return nil, nil, Denial{}, fmt.Errorf("DS %s: rcode %d", zone, msg.Rcode)
	}

	var dss []*dns.DS
	var sigs []*dns.RRSIG
	for _, rr := range msg.Answer {
		switch v := rr.(type) {
		case *dns.DS:
			dss = append(dss, v)
		case *dns.RRSIG:
			sigs = append(sigs, v)
		}
	}

	// Cache the absence too, on the TTL of whatever denied it: an unsigned
	// delegation is the common case, and re-asking for every name below it
	// would cost more than the signed path does.
	records := msg.Answer
	denial := Denial{}
	if len(dss) == 0 {
		records = msg.Ns
		// Held with the absence it explains: it is what says whether there is a
		// delegation here at all, and re-deriving it per name below this one
		// would cost a query each time.
		denial = CollectDenial(msg.Ns)
		if denial.Empty() {
			// An absence nothing accounts for is not a fact worth keeping. A
			// response that lost its authority section on the way back looks
			// exactly like an unsigned delegation, and caching that reading
			// would hold every name under this zone unvalidated until the entry
			// expired -- long after the answer that caused it was gone.
			return dss, sigs, denial, nil
		}
	}
	f.mu.Lock()
	f.dss[zone] = &dsEntry{dss: dss, sigs: sigs, denial: denial, expires: f.now().Add(ttlOf(records))}
	f.mu.Unlock()
	return dss, sigs, denial, nil
}

// Forget drops everything cached, for a reload.
func (f *CachingFetcher) Forget() {
	f.mu.Lock()
	f.keys = map[string]*keyEntry{}
	f.dss = map[string]*dsEntry{}
	f.mu.Unlock()
}

const (
	minCacheTTL = 60 * time.Second
	maxCacheTTL = time.Hour
)

// ttlOf returns how long a set may be held: the smallest TTL in it, bounded so
// that a zone publishing seconds cannot turn every lookup into a fetch, and one
// publishing weeks cannot pin a superseded key past a rollover.
func ttlOf(rrs []dns.RR) time.Duration {
	smallest := uint32(0)
	for _, rr := range rrs {
		ttl := rr.Header().TTL
		if smallest == 0 || ttl < smallest {
			smallest = ttl
		}
	}
	d := time.Duration(smallest) * time.Second
	if d < minCacheTTL {
		return minCacheTTL
	}
	if d > maxCacheTTL {
		return maxCacheTTL
	}
	return d
}
