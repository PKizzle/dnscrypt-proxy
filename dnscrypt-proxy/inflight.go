package main

import "sync"

// inflight collapses identical queries that are outstanding at the same moment
// into a single exchange with the upstream.
//
// A name expiring from the cache while it is being asked for repeatedly -- the
// popular case, and the one a cache is least able to help with -- otherwise
// sends the same question upstream once per caller. The first caller does the
// work and the rest wait for its answer.
//
// Identity is the query as it will go on the wire, with only the transaction ID
// masked out. That is deliberately strict: two questions that differ in any
// other way, including the client subnet an upstream may answer differently
// for, are different questions and are never merged. Being too eager here would
// hand one client an answer computed for another.
type inflight struct {
	mu    sync.Mutex
	calls map[string]*inflightCall
}

type inflightCall struct {
	done chan struct{}
	res  inflightResult
}

// inflightResult is what the caller that did the work found out, including the
// parts of the exchange its followers would otherwise have no way to report.
type inflightResult struct {
	response   []byte
	err        error
	serverName string
	returnCode PluginsReturnCode
}

func newInflight() *inflight {
	return &inflight{calls: make(map[string]*inflightCall)}
}

// Do runs fn for the first caller of key and shares its outcome with everyone
// who asks for the same key while it is still running. The bool reports whether
// this caller waited for someone else's work rather than doing its own.
func (f *inflight) Do(key string, fn func() inflightResult) (inflightResult, bool) {
	f.mu.Lock()
	if call, ok := f.calls[key]; ok {
		f.mu.Unlock()
		<-call.done
		return call.res, true
	}
	call := &inflightCall{done: make(chan struct{})}
	f.calls[key] = call
	f.mu.Unlock()

	// The entry is removed before the waiters are released, so a query arriving
	// after this one has finished starts a fresh exchange rather than joining a
	// finished one and receiving an answer that is already older than it looks.
	defer func() {
		f.mu.Lock()
		delete(f.calls, key)
		f.mu.Unlock()
		close(call.done)
	}()

	call.res = fn()
	return call.res, false
}

// inflightKey identifies a query by its wire form, with the transaction ID
// masked out because it is the one part that is per-caller by definition.
func inflightKey(serverName string, query []byte) (string, bool) {
	if len(query) < MinDNSPacketSize {
		return "", false
	}
	// The ID occupies the first two bytes; everything after it is the question
	// and whatever options the plugins added.
	key := make([]byte, 0, len(serverName)+1+len(query))
	key = append(key, serverName...)
	key = append(key, 0)
	key = append(key, 0, 0)
	key = append(key, query[2:]...)
	return string(key), true
}
