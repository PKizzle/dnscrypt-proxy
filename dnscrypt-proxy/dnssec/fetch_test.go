package dnssec

import (
	"fmt"
	"testing"
	"time"

	"codeberg.org/miekg/dns"
	"codeberg.org/miekg/dns/rdata"
)

// recordingQuery counts what it is asked, so the tests can tell a cache hit
// from a fetch.
type recordingQuery struct {
	calls    map[string]int
	respond  func(qname string, qtype uint16) (*dns.Msg, error)
	lastName string
}

func (r *recordingQuery) fn(qname string, qtype uint16) (*dns.Msg, error) {
	if r.calls == nil {
		r.calls = map[string]int{}
	}
	r.calls[fmt.Sprintf("%s/%d", qname, qtype)]++
	r.lastName = qname
	return r.respond(qname, qtype)
}

func msgWith(rcode uint16, answer []dns.RR, ns []dns.RR) *dns.Msg {
	m := &dns.Msg{}
	m.Rcode = rcode
	m.Answer = answer
	m.Ns = ns
	return m
}

func TestFetcherReturnsKeysAndCachesThem(t *testing.T) {
	z := newZone(t, "example.test.")
	sig := z.sign([]dns.RR{z.key}, time.Now().Add(-time.Hour), time.Now().Add(time.Hour))
	rec := &recordingQuery{respond: func(string, uint16) (*dns.Msg, error) {
		return msgWith(dns.RcodeSuccess, []dns.RR{z.key, sig}, nil), nil
	}}
	f := NewCachingFetcher(rec.fn)

	for i := 0; i < 3; i++ {
		keys, sigs, err := f.DNSKEY("example.test.")
		if err != nil || len(keys) != 1 || len(sigs) != 1 {
			t.Fatalf("DNSKEY() = %d keys, %d sigs, err %v", len(keys), len(sigs), err)
		}
	}
	if got := rec.calls["example.test./48"]; got != 1 {
		t.Errorf("upstream asked %d times, want 1: the answer should be cached", got)
	}
}

// DNSKEY and DS are tied to the exact owner and class that was queried. An
// authenticated record for a sibling is not chain material for this name,
// even if a recursive upstream places it in the Answer section.
func TestFetcherKeepsOnlyExactINChainRecords(t *testing.T) {
	for _, qtype := range []uint16{dns.TypeDNSKEY, dns.TypeDS} {
		t.Run(dns.TypeToString[qtype], func(t *testing.T) {
			z := newZone(t, "example.test.")
			other := newZone(t, "other.test.")
			keyWrongClass := *z.key
			keyWrongClass.Hdr.Class = dns.ClassCHAOS
			var wanted, wrongOwner, wrongClass dns.RR = z.key, other.key, &keyWrongClass
			if qtype == dns.TypeDS {
				wantedDS := z.key.ToDS(dns.SHA256)
				wrongClassDS := *wantedDS
				wrongClassDS.Hdr.Class = dns.ClassCHAOS
				wanted, wrongOwner, wrongClass = wantedDS, other.key.ToDS(dns.SHA256), &wrongClassDS
			}
			rec := &recordingQuery{respond: func(string, uint16) (*dns.Msg, error) {
				return msgWith(dns.RcodeSuccess, []dns.RR{wrongOwner, wrongClass, wanted}, nil), nil
			}}
			f := NewCachingFetcher(rec.fn)

			if qtype == dns.TypeDNSKEY {
				keys, _, err := f.DNSKEY("example.test.")
				if err != nil {
					t.Fatalf("DNSKEY(): %v", err)
				}
				if len(keys) != 1 || !dns.EqualName(keys[0].Header().Name, "example.test.") || keys[0].Header().Class != dns.ClassINET {
					t.Fatalf("filtered DNSKEYs = %v, want only exact IN owner", keys)
				}
			} else {
				dss, _, _, err := f.DS("example.test.")
				if err != nil {
					t.Fatalf("DS(): %v", err)
				}
				if len(dss) != 1 || !dns.EqualName(dss[0].Header().Name, "example.test.") || dss[0].Header().Class != dns.ClassINET {
					t.Fatalf("filtered DS records = %v, want only exact IN owner", dss)
				}
			}
		})
	}
}

// A syntactically delivered response can still be unusable chain evidence.
// Keep the endpoint exclusion set across those failures just as for a dropped
// packet, so one empty/truncated resolver cannot cause an unchecked verdict
// while another configured resolver has the complete RRset.
func TestFetcherRetriesUnusableDeliveredResponsesAcrossDistinctEndpoints(t *testing.T) {
	for _, qtype := range []uint16{dns.TypeDNSKEY, dns.TypeDS} {
		t.Run(dns.TypeToString[qtype], func(t *testing.T) {
			z := newZone(t, "example.test.")
			z.key.Hdr.TTL = 300
			calls := 0
			servers := []string{"resolver-a", "resolver-b"}
			f := NewCachingFetcherExcluding(func(_ string, gotType uint16, excluded map[string]struct{}) (*dns.Msg, error) {
				if gotType != qtype {
					t.Fatalf("query type = %d, want %d", gotType, qtype)
				}
				if len(excluded) != calls {
					t.Fatalf("attempt %d exclusions = %v", calls+1, excluded)
				}
				server := servers[calls]
				excluded[server] = struct{}{}
				calls++
				if calls == 1 {
					if qtype == dns.TypeDNSKEY {
						return msgWith(dns.RcodeSuccess, nil, nil), nil
					}
					m := msgWith(dns.RcodeSuccess, nil, nil)
					m.Truncated = true
					return m, nil
				}
				if qtype == dns.TypeDNSKEY {
					return msgWith(dns.RcodeSuccess, []dns.RR{z.key}, nil), nil
				}
				return msgWith(dns.RcodeSuccess, nil, nil), nil
			})

			if qtype == dns.TypeDNSKEY {
				if _, _, err := f.DNSKEY("example.test."); err != nil {
					t.Fatalf("DNSKEY() after alternate endpoint = %v", err)
				}
			} else if _, _, _, err := f.DS("example.test."); err != nil {
				t.Fatalf("DS() after alternate endpoint = %v", err)
			}
			if calls != 2 {
				t.Fatalf("queries = %d, want 2 distinct endpoints", calls)
			}
		})
	}
}

// The zone's own TTL decides how long its keys are held, so a rollover is
// picked up when the zone said it would be.
func TestFetcherHonoursTheTTL(t *testing.T) {
	z := newZone(t, "example.test.")
	z.key.Hdr.TTL = 120
	sig := z.sign([]dns.RR{z.key}, time.Now().Add(-time.Hour), time.Now().Add(time.Hour))
	sig.Hdr.TTL = 120
	rec := &recordingQuery{respond: func(string, uint16) (*dns.Msg, error) {
		return msgWith(dns.RcodeSuccess, []dns.RR{z.key, sig}, nil), nil
	}}
	f := NewCachingFetcher(rec.fn)

	base := time.Now()
	f.Now = func() time.Time { return base }
	if _, _, err := f.DNSKEY("example.test."); err != nil {
		t.Fatalf("first DNSKEY(): %v", err)
	}
	f.Now = func() time.Time { return base.Add(119 * time.Second) }
	if _, _, err := f.DNSKEY("example.test."); err != nil {
		t.Fatalf("cached DNSKEY(): %v", err)
	}
	if got := rec.calls["example.test./48"]; got != 1 {
		t.Fatalf("asked %d times before expiry, want 1", got)
	}
	f.Now = func() time.Time { return base.Add(2 * time.Minute) }
	if _, _, err := f.DNSKEY("example.test."); err != nil {
		t.Fatalf("DNSKEY() after expiry: %v", err)
	}
	if got := rec.calls["example.test./48"]; got != 2 {
		t.Errorf("asked %d times after expiry, want 2", got)
	}
}

// RFC 8767 section 4 keeps the ordinary TTL as the point at which the source
// must be consulted again; stale use is permitted only after that refresh
// attempt fails. In particular, a zero-TTL RR is transaction-only and MUST
// NOT be cached. The validator may cap long cache lifetimes, but it must not
// stretch a publisher's short or zero lifetime to its old 60-second floor.
func TestFetcherDoesNotExtendShortOrZeroTTLs(t *testing.T) {
	z := newZone(t, "example.test.")
	sig := z.sign([]dns.RR{z.key}, time.Now().Add(-time.Hour), time.Now().Add(time.Hour))

	for _, tc := range []struct {
		name string
		ttl  uint32
		want time.Duration
	}{
		{name: "zero", ttl: 0, want: 0},
		{name: "short", ttl: 5, want: 5 * time.Second},
		{name: "long capped", ttl: 7200, want: maxCacheTTL},
	} {
		t.Run(tc.name, func(t *testing.T) {
			keyCopy := *z.key
			sigCopy := *sig
			keyCopy.Hdr.TTL = tc.ttl
			sigCopy.Hdr.TTL = tc.ttl
			if got := ttlOf([]dns.RR{&keyCopy, &sigCopy}); got != tc.want {
				t.Fatalf("ttlOf(%d) = %v, want %v", tc.ttl, got, tc.want)
			}
		})
	}

	// A zero in any member makes the atomic entry transaction-only; do not
	// lose it merely because a later member has a nonzero TTL.
	keyCopy := *z.key
	sigCopy := *sig
	keyCopy.Hdr.TTL = 0
	sigCopy.Hdr.TTL = 300
	if got := ttlOf([]dns.RR{&keyCopy, &sigCopy}); got != 0 {
		t.Fatalf("ttlOf(mixed zero/nonzero) = %v, want 0", got)
	}
}

// RFC 8767 section 7 explicitly excludes zero-TTL data from stale fallback.
// It can be used for the transaction that fetched it, but after that a failed
// refresh must be reported rather than resurrecting the transaction-only key
// or delegation signer from the validator's private cache.
func TestFetcherNeverUsesZeroTTLChainMaterialAsStale(t *testing.T) {
	for _, qtype := range []uint16{dns.TypeDNSKEY, dns.TypeDS} {
		t.Run(dns.TypeToString[qtype], func(t *testing.T) {
			z := newZone(t, "example.test.")
			z.key.Hdr.TTL = 0
			var rr dns.RR = z.key
			if qtype == dns.TypeDS {
				rr = z.key.ToDS(dns.SHA256)
				rr.Header().TTL = 0
			}
			sig := z.sign([]dns.RR{rr}, time.Now().Add(-time.Hour), time.Now().Add(time.Hour))
			sig.Hdr.TTL = 0
			calls := 0
			rec := &recordingQuery{respond: func(string, uint16) (*dns.Msg, error) {
				calls++
				if calls == 1 {
					return msgWith(dns.RcodeSuccess, []dns.RR{rr, sig}, nil), nil
				}
				return nil, fmt.Errorf("upstream unreachable")
			}}
			f := NewCachingFetcher(rec.fn)

			if qtype == dns.TypeDNSKEY {
				if _, _, err := f.DNSKEY("example.test."); err != nil {
					t.Fatalf("first DNSKEY fetch: %v", err)
				}
				if _, _, err := f.DNSKEY("example.test."); err == nil {
					t.Fatal("zero-TTL DNSKEY was reused after refresh failure")
				}
			} else {
				if _, _, _, err := f.DS("example.test."); err != nil {
					t.Fatalf("first DS fetch: %v", err)
				}
				if _, _, _, err := f.DS("example.test."); err == nil {
					t.Fatal("zero-TTL DS was reused after refresh failure")
				}
			}
		})
	}
}

// No delegation signer is an ordinary answer, not an error: it is how an
// unsigned zone looks, and the chain reads it as insecure.
func TestFetcherReportsAnAbsentDelegationSignerAsEmpty(t *testing.T) {
	rec := &recordingQuery{respond: func(string, uint16) (*dns.Msg, error) {
		return msgWith(dns.RcodeSuccess, nil, nil), nil
	}}
	f := NewCachingFetcher(rec.fn)

	dss, _, _, err := f.DS("unsigned.test.")
	if err != nil {
		t.Fatalf("DS() = %v, want no error", err)
	}
	if len(dss) != 0 {
		t.Errorf("DS() returned %d signers, want none", len(dss))
	}
}

// A name error is not an unsigned delegation. Its denial proof is passed to
// the chain, which can establish that the label is not a zone cut only after
// verifying it with the parent key.
func TestFetcherKeepsANameErrorProofForTheChain(t *testing.T) {
	proof := nsec("a.", "z.", dns.TypeNSEC, dns.TypeRRSIG)
	rec := &recordingQuery{respond: func(string, uint16) (*dns.Msg, error) {
		return msgWith(dns.RcodeNameError, nil, []dns.RR{proof}), nil
	}}
	f := NewCachingFetcher(rec.fn)

	dss, _, denial, err := f.DS("nope.")
	if err != nil || len(dss) != 0 || len(denial.NSEC) != 1 {
		t.Fatalf("DS() = %d signers, %d NSEC, err %v; want a usable negative proof", len(dss), len(denial.NSEC), err)
	}
}

// A DS query to an alias returns the signed CNAME in the Answer section, not
// an NSEC in Authority. The chain needs that evidence to continue through the
// parent zone, so the fetcher must preserve and cache it rather than treating
// the empty DS set as unexplained.
func TestFetcherKeepsCNAMEDelegationEvidence(t *testing.T) {
	cname := &dns.CNAME{
		Hdr:   dns.Header{Name: "alias.example.", Class: dns.ClassINET, TTL: 120},
		CNAME: rdata.CNAME{Target: "target.example."},
	}
	sig := &dns.RRSIG{
		Hdr:   dns.Header{Name: "alias.example.", Class: dns.ClassINET, TTL: 120},
		RRSIG: rdata.RRSIG{TypeCovered: dns.TypeCNAME},
	}
	rec := &recordingQuery{respond: func(string, uint16) (*dns.Msg, error) {
		return msgWith(dns.RcodeSuccess, []dns.RR{cname, sig}, nil), nil
	}}
	f := NewCachingFetcher(rec.fn)

	for i := 0; i < 2; i++ {
		dss, _, evidence, err := f.DS("alias.example.")
		if err != nil || len(dss) != 0 || len(evidence.cnames) != 1 || len(evidence.cnameSigs) != 1 {
			t.Fatalf("DS() = %d DS, %d CNAME, %d CNAME signatures, err %v", len(dss), len(evidence.cnames), len(evidence.cnameSigs), err)
		}
	}
	if got := rec.calls["alias.example./43"]; got != 1 {
		t.Errorf("upstream asked %d times, want 1: CNAME evidence should be cached", got)
	}
}

func TestFetcherPropagatesFailure(t *testing.T) {
	rec := &recordingQuery{respond: func(string, uint16) (*dns.Msg, error) {
		return nil, fmt.Errorf("upstream unreachable")
	}}
	f := NewCachingFetcher(rec.fn)

	if _, _, err := f.DNSKEY("example.test."); err == nil {
		t.Error("DNSKEY() should report an upstream failure rather than an empty key set")
	}
	if _, _, _, err := f.DS("example.test."); err == nil {
		t.Error("DS() should report an upstream failure")
	}
}

func TestFetcherRefusesAnEmptyKeySet(t *testing.T) {
	rec := &recordingQuery{respond: func(string, uint16) (*dns.Msg, error) {
		return msgWith(dns.RcodeSuccess, nil, nil), nil
	}}
	f := NewCachingFetcher(rec.fn)

	if _, _, err := f.DNSKEY("example.test."); err == nil {
		t.Error("a zone with no keys in the answer is not a usable key set")
	}
}

func TestFetcherForgetDropsTheCache(t *testing.T) {
	z := newZone(t, "example.test.")
	sig := z.sign([]dns.RR{z.key}, time.Now().Add(-time.Hour), time.Now().Add(time.Hour))
	rec := &recordingQuery{respond: func(string, uint16) (*dns.Msg, error) {
		return msgWith(dns.RcodeSuccess, []dns.RR{z.key, sig}, nil), nil
	}}
	f := NewCachingFetcher(rec.fn)

	if _, _, err := f.DNSKEY("example.test."); err != nil {
		t.Fatalf("DNSKEY(): %v", err)
	}
	f.Forget()
	if _, _, err := f.DNSKEY("example.test."); err != nil {
		t.Fatalf("DNSKEY() after Forget(): %v", err)
	}
	if got := rec.calls["example.test./48"]; got != 2 {
		t.Errorf("asked %d times across a Forget(), want 2", got)
	}
}

// Names differing only in case and trailing dot are the same zone; caching them
// separately would multiply every fetch.
func TestFetcherTreatsNamesCanonically(t *testing.T) {
	z := newZone(t, "example.test.")
	sig := z.sign([]dns.RR{z.key}, time.Now().Add(-time.Hour), time.Now().Add(time.Hour))
	rec := &recordingQuery{respond: func(string, uint16) (*dns.Msg, error) {
		return msgWith(dns.RcodeSuccess, []dns.RR{z.key, sig}, nil), nil
	}}
	f := NewCachingFetcher(rec.fn)

	for _, name := range []string{"example.test.", "Example.Test.", "example.test"} {
		if _, _, err := f.DNSKEY(name); err != nil {
			t.Fatalf("DNSKEY(%q): %v", name, err)
		}
	}
	if got := rec.calls["example.test./48"]; got != 1 {
		t.Errorf("asked %d times for one zone spelled three ways, want 1", got)
	}
}

// The whole point of the fetcher is to feed a chain walk, so it is worth
// checking the two fit together over a hierarchy served through it.
func TestFetcherDrivesAChainWalk(t *testing.T) {
	h := newHierarchy(t, ".", "test.", "example.test.")
	f := NewCachingFetcher(func(qname string, qtype uint16) (*dns.Msg, error) {
		switch qtype {
		case dns.TypeDNSKEY:
			keys, sigs, err := h.DNSKEY(canonicalName(qname))
			if err != nil {
				return msgWith(dns.RcodeNameError, nil, nil), nil
			}
			answer := make([]dns.RR, 0, len(keys)+len(sigs))
			for _, k := range keys {
				answer = append(answer, k)
			}
			for _, s := range sigs {
				answer = append(answer, s)
			}
			return msgWith(dns.RcodeSuccess, answer, nil), nil
		case dns.TypeDS:
			dss, sigs, _, err := h.DS(canonicalName(qname))
			if err != nil {
				return msgWith(dns.RcodeNameError, nil, nil), nil
			}
			answer := make([]dns.RR, 0, len(dss)+len(sigs))
			for _, d := range dss {
				answer = append(answer, d)
			}
			for _, s := range sigs {
				answer = append(answer, s)
			}
			return msgWith(dns.RcodeSuccess, answer, nil), nil
		}
		return msgWith(dns.RcodeNameError, nil, nil), nil
	})

	res := BuildChain(f, "example.test.", h.anchors(), h.now)
	if res.Status != Secure {
		t.Fatalf("BuildChain() through the fetcher = %v (%v), want secure", res.Status, res.Why)
	}
	if res.Zone != "example.test." {
		t.Errorf("zone = %q, want example.test.", res.Zone)
	}
}

// A delegation signer that is absent with nothing to account for the absence is
// not a fact: a response that lost its authority section looks identical to an
// unsigned delegation, and remembering that reading holds every name under the
// zone unvalidated long after the response that caused it is gone.
func TestFetcherDoesNotCacheAnAbsenceNothingAccountsFor(t *testing.T) {
	calls := 0
	rec := &recordingQuery{respond: func(string, uint16) (*dns.Msg, error) {
		calls++
		return msgWith(dns.RcodeSuccess, nil, nil), nil
	}}
	f := NewCachingFetcher(rec.fn)

	for i := 0; i < 3; i++ {
		if _, _, _, err := f.DS("unproven.test."); err != nil {
			t.Fatalf("DS() = %v, want no error", err)
		}
	}
	if calls != 3 {
		t.Errorf("upstream asked %d time(s), want 3 -- an unproven absence was cached", calls)
	}
}

// One lost packet should not cost a zone its validation: a dropped fetch means
// nothing can be concluded, which for a signed zone removes the protection from
// every name beneath it.
func TestFetcherRetriesADroppedFetch(t *testing.T) {
	calls := 0
	rec := &recordingQuery{respond: func(name string, qtype uint16) (*dns.Msg, error) {
		calls++
		if calls == 1 {
			return nil, fmt.Errorf("packet lost")
		}
		return msgWith(dns.RcodeSuccess, nil, nil), nil
	}}
	f := NewCachingFetcher(rec.fn)

	if _, _, _, err := f.DS("example.test."); err != nil {
		t.Fatalf("DS() = %v, want the retry to have succeeded", err)
	}
	if calls != 2 {
		t.Errorf("upstream asked %d time(s), want 2 (one lost, one retried)", calls)
	}
}

// A pool-aware caller must see one exclusion set for the entire RRset fetch.
// Otherwise every retry starts from an empty set and weighted selection can
// repeatedly choose the endpoint that just timed out.
func TestFetcherCarriesEndpointExclusionsAcrossRetries(t *testing.T) {
	calls := 0
	selected := []string{"resolver-a", "resolver-b", "resolver-c"}
	f := NewCachingFetcherExcluding(func(_ string, _ uint16, excluded map[string]struct{}) (*dns.Msg, error) {
		if len(excluded) != calls {
			t.Fatalf("attempt %d received %d exclusions, want %d", calls+1, len(excluded), calls)
		}
		server := selected[calls]
		if _, duplicate := excluded[server]; duplicate {
			t.Fatalf("attempt %d selected excluded endpoint %q", calls+1, server)
		}
		excluded[server] = struct{}{}
		calls++
		if calls < chainFetchAttempts {
			return nil, fmt.Errorf("%s timed out", server)
		}
		return msgWith(dns.RcodeSuccess, nil, nil), nil
	})

	if _, _, _, err := f.DS("example.test."); err != nil {
		t.Fatalf("DS() = %v, want the distinct final endpoint to succeed", err)
	}
	if calls != chainFetchAttempts {
		t.Fatalf("upstream asked %d time(s), want %d distinct attempts", calls, chainFetchAttempts)
	}
}

func TestFetcherCountsPreviouslyExcludedEndpointsAgainstRetryBudget(t *testing.T) {
	calls := 0
	excluded := map[string]struct{}{"resolver-a": {}}
	remaining := []string{"resolver-b", "resolver-c"}
	f := NewCachingFetcherExcluding(func(_ string, _ uint16, got map[string]struct{}) (*dns.Msg, error) {
		if got == nil || len(got) != calls+1 {
			t.Fatalf("attempt %d exclusions = %v, want %d entries", calls+1, got, calls+1)
		}
		server := remaining[calls]
		got[server] = struct{}{}
		calls++
		return nil, fmt.Errorf("%s timed out", server)
	})

	if _, _, _, err := f.DSExcluding("example.test.", excluded); err == nil {
		t.Fatal("DSExcluding() should report exhaustion")
	}
	if calls != chainFetchAttempts-1 {
		t.Fatalf("additional attempts = %d, want %d", calls, chainFetchAttempts-1)
	}
}

// Retrying forever would turn an upstream that is simply down into a hang.
func TestFetcherGivesUpAfterTheRetries(t *testing.T) {
	calls := 0
	rec := &recordingQuery{respond: func(string, uint16) (*dns.Msg, error) {
		calls++
		return nil, fmt.Errorf("upstream unreachable")
	}}
	f := NewCachingFetcher(rec.fn)

	if _, _, _, err := f.DS("example.test."); err == nil {
		t.Error("DS() should report a failure that never resolved")
	}
	if calls != chainFetchAttempts {
		t.Errorf("upstream asked %d time(s), want %d", calls, chainFetchAttempts)
	}
}

// A key set that cannot be refreshed is better used a little stale than not at
// all: giving up serves every name under the zone unvalidated, while a key that
// has genuinely gone simply fails to verify where that is checked.
func TestFetcherFallsBackToKeysItAlreadyHeld(t *testing.T) {
	z := newZone(t, "example.test.")
	now := time.Now()
	fail := false
	rec := &recordingQuery{respond: func(name string, qtype uint16) (*dns.Msg, error) {
		if fail {
			return nil, fmt.Errorf("upstream unreachable")
		}
		return msgWith(dns.RcodeSuccess, []dns.RR{z.key}, nil), nil
	}}
	f := NewCachingFetcher(rec.fn)
	f.Now = func() time.Time { return now }

	if _, _, err := f.DNSKEY("example.test."); err != nil {
		t.Fatalf("first fetch: %v", err)
	}

	// Past the entry's lifetime, with upstream now unreachable.
	now = now.Add(24 * time.Hour)
	fail = true

	keys, _, err := f.DNSKEY("example.test.")
	if err != nil {
		t.Fatalf("DNSKEY() = %v, want the previously held key set", err)
	}
	if len(keys) == 0 {
		t.Error("no keys returned, so every name under the zone goes unvalidated")
	}
}

// With nothing held there is nothing to fall back to, and the failure must be
// reported rather than answered with an empty key set.
func TestFetcherWithNothingHeldStillReportsFailure(t *testing.T) {
	rec := &recordingQuery{respond: func(string, uint16) (*dns.Msg, error) {
		return nil, fmt.Errorf("upstream unreachable")
	}}
	f := NewCachingFetcher(rec.fn)

	if _, _, err := f.DNSKEY("example.test."); err == nil {
		t.Error("a failure with nothing cached was not reported")
	}
}

// RFC 8767 permits stale data only for a bounded period, and asks for a maximum
// stale timer rather than reuse without end.
func TestFetcherStopsUsingKeysThatAreTooOld(t *testing.T) {
	z := newZone(t, "example.test.")
	now := time.Now()
	fail := false
	rec := &recordingQuery{respond: func(string, uint16) (*dns.Msg, error) {
		if fail {
			return nil, fmt.Errorf("upstream unreachable")
		}
		return msgWith(dns.RcodeSuccess, []dns.RR{z.key}, nil), nil
	}}
	f := NewCachingFetcher(rec.fn)
	f.Now = func() time.Time { return now }

	if _, _, err := f.DNSKEY("example.test."); err != nil {
		t.Fatalf("first fetch: %v", err)
	}
	fail = true

	// Inside the window the held set is still used.
	now = now.Add(maxStale / 2)
	if _, _, err := f.DNSKEY("example.test."); err != nil {
		t.Errorf("within the stale window: %v, want the held key set", err)
	}

	// Beyond it, there is nothing left to stand on.
	now = now.Add(maxStale * 2)
	if _, _, err := f.DNSKEY("example.test."); err == nil {
		t.Error("a key set far past its lifetime was still used")
	}
}

// The bound limits reuse, not scrutiny: what is held is checked against the
// current time wherever it is used, so a set whose signatures have expired does
// not validate merely because it was cached.
func TestStaleKeysDoNotEscapeSignatureChecking(t *testing.T) {
	z := newZone(t, "example.test.")
	now := time.Now()
	rrset := []dns.RR{aRecord("www.example.test.", "192.0.2.1")}
	expired := z.sign(rrset, now.Add(-48*time.Hour), now.Add(-24*time.Hour))

	res, _ := VerifyRRSet(rrset, []*dns.RRSIG{expired}, []*dns.DNSKEY{z.key}, now)
	if res == Secure {
		t.Error("an expired signature verified, so staleness would bypass the validity window")
	}
}

// A key set that does not verify must not be kept. Answered from cache it
// leaves every name below that zone unvalidated until it expires, and at the
// root that is every name there is.
func TestForgetZoneMakesTheNextWalkAskAgain(t *testing.T) {
	z := newZone(t, "example.test.")
	calls := 0
	rec := &recordingQuery{respond: func(string, uint16) (*dns.Msg, error) {
		calls++
		return msgWith(dns.RcodeSuccess, []dns.RR{z.key}, nil), nil
	}}
	f := NewCachingFetcher(rec.fn)

	if _, _, err := f.DNSKEY("example.test."); err != nil {
		t.Fatalf("first fetch: %v", err)
	}
	if _, _, err := f.DNSKEY("example.test."); err != nil {
		t.Fatalf("second fetch: %v", err)
	}
	if calls != 1 {
		t.Fatalf("upstream asked %d times, want 1 -- the set should have been cached", calls)
	}

	f.ForgetZone("example.test.")

	if _, _, err := f.DNSKEY("example.test."); err != nil {
		t.Fatalf("after forgetting: %v", err)
	}
	if calls != 2 {
		t.Errorf("upstream asked %d times, want 2 -- the dropped set was answered from cache", calls)
	}
}

// Part of a key set verifies as nothing: the signature covers the whole of it,
// so a set missing a key fails exactly as a forged one does.
func TestFetcherRefusesATruncatedKeySet(t *testing.T) {
	z := newZone(t, "example.test.")
	rec := &recordingQuery{respond: func(string, uint16) (*dns.Msg, error) {
		m := msgWith(dns.RcodeSuccess, []dns.RR{z.key}, nil)
		m.Truncated = true
		return m, nil
	}}
	f := NewCachingFetcher(rec.fn)

	if _, _, err := f.DNSKEY("example.test."); err == nil {
		t.Error("a truncated key set was accepted as the whole of it")
	}
}

// A partial delegation response can omit either a DS or the proof that it is
// absent. It cannot be read as a complete answer to the chain walk.
func TestFetcherRefusesATruncatedDSSet(t *testing.T) {
	rec := &recordingQuery{respond: func(string, uint16) (*dns.Msg, error) {
		m := msgWith(dns.RcodeSuccess, nil, nil)
		m.Truncated = true
		return m, nil
	}}
	f := NewCachingFetcher(rec.fn)

	if _, _, _, err := f.DS("example.test."); err == nil {
		t.Error("a truncated DS response was accepted as complete")
	}
}
