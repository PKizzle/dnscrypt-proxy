package main

import (
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func TestInflightCollapsesConcurrentIdenticalCalls(t *testing.T) {
	f := newInflight()
	var calls int32
	release := make(chan struct{})

	const callers = 50
	var wg sync.WaitGroup
	shared := make([]bool, callers)
	for i := 0; i < callers; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			_, wasShared := f.Do("same", func() inflightResult {
				atomic.AddInt32(&calls, 1)
				<-release // hold the exchange open so the others pile up
				return inflightResult{response: []byte("answer"), serverName: "srv"}
			})
			shared[i] = wasShared
		}(i)
	}
	// Give the goroutines time to queue behind the first.
	time.Sleep(100 * time.Millisecond)
	close(release)
	wg.Wait()

	if got := atomic.LoadInt32(&calls); got != 1 {
		t.Errorf("upstream was asked %d times for %d concurrent identical queries, want 1", got, callers)
	}
	leaders := 0
	for _, s := range shared {
		if !s {
			leaders++
		}
	}
	if leaders != 1 {
		t.Errorf("%d callers did the work, want exactly 1", leaders)
	}
}

// Different questions must never be merged, however close together they arrive.
func TestInflightKeepsDifferentCallsApart(t *testing.T) {
	f := newInflight()
	var calls int32
	release := make(chan struct{})

	var wg sync.WaitGroup
	for _, key := range []string{"a", "b", "c"} {
		wg.Add(1)
		go func(k string) {
			defer wg.Done()
			f.Do(k, func() inflightResult {
				atomic.AddInt32(&calls, 1)
				<-release
				return inflightResult{response: []byte(k)}
			})
		}(key)
	}
	time.Sleep(100 * time.Millisecond)
	close(release)
	wg.Wait()

	if got := atomic.LoadInt32(&calls); got != 3 {
		t.Errorf("three distinct questions produced %d exchanges, want 3", got)
	}
}

// A query arriving after the previous one finished must get a fresh exchange,
// not the answer that was just handed out.
func TestInflightDoesNotShareAcrossTime(t *testing.T) {
	f := newInflight()
	var calls int32
	fn := func() inflightResult {
		atomic.AddInt32(&calls, 1)
		return inflightResult{response: []byte("x")}
	}
	for i := 0; i < 3; i++ {
		if _, shared := f.Do("same", fn); shared {
			t.Fatalf("call %d waited on a finished exchange", i)
		}
	}
	if got := atomic.LoadInt32(&calls); got != 3 {
		t.Errorf("sequential calls produced %d exchanges, want 3", got)
	}
}

func TestInflightSharesTheError(t *testing.T) {
	f := newInflight()
	boom := errors.New("upstream unreachable")
	release := make(chan struct{})

	var wg sync.WaitGroup
	errs := make([]error, 5)
	for i := 0; i < 5; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			res, _ := f.Do("same", func() inflightResult {
				<-release
				return inflightResult{err: boom}
			})
			errs[i] = res.err
		}(i)
	}
	time.Sleep(50 * time.Millisecond)
	close(release)
	wg.Wait()

	for i, err := range errs {
		if !errors.Is(err, boom) {
			t.Errorf("caller %d got %v, want the shared failure", i, err)
		}
	}
}

// The key is the query as it goes on the wire, with only the transaction ID
// masked: two callers asking the same thing share, and anything else does not.
func TestInflightKeyIgnoresOnlyTheTransactionID(t *testing.T) {
	// 12-byte header plus a question; MinDNSPacketSize is 17.
	base := []byte{
		0xAA, 0xBB, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x03, 'w', 'w', 'w', 0x07, 'e', 'x', 'a', 'm', 'p', 'l', 'e', 0x00, 0x00, 0x01, 0x00, 0x01,
	}
	other := make([]byte, len(base))
	copy(other, base)
	other[0], other[1] = 0x12, 0x34 // different ID, same question

	k1, ok1 := inflightKey("srv", base)
	k2, ok2 := inflightKey("srv", other)
	if !ok1 || !ok2 {
		t.Fatal("well-formed queries should produce keys")
	}
	if k1 != k2 {
		t.Error("queries differing only in transaction ID should share a key")
	}

	// A different question must not.
	changed := make([]byte, len(base))
	copy(changed, base)
	changed[len(changed)-1] = 'x'
	if k3, _ := inflightKey("srv", changed); k3 == k1 {
		t.Error("a different question must not share a key")
	}

	// Nor must the same question sent to a different upstream.
	if k4, _ := inflightKey("other-srv", base); k4 == k1 {
		t.Error("the same question to a different server must not share a key")
	}

	// A runt packet has no question to key on.
	if _, ok := inflightKey("srv", []byte{0x01}); ok {
		t.Error("a packet too short to hold a question should not produce a key")
	}
}
