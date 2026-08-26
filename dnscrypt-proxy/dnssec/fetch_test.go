package dnssec

import (
	"fmt"
	"testing"
	"time"

	"codeberg.org/miekg/dns"
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

// A name that does not exist is not an unsigned zone. Reporting it as one would
// let a typo -- or a forged NXDOMAIN -- read as a downgrade.
func TestFetcherDistinguishesNoSuchNameFromNoSigner(t *testing.T) {
	rec := &recordingQuery{respond: func(string, uint16) (*dns.Msg, error) {
		return msgWith(dns.RcodeNameError, nil, nil), nil
	}}
	f := NewCachingFetcher(rec.fn)

	if _, _, _, err := f.DS("nope.test."); err == nil {
		t.Error("DS() for a nonexistent name should be an error, not an unsigned delegation")
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
