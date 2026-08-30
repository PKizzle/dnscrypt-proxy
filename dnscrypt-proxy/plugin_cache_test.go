package main

import (
	"testing"
	"time"

	"codeberg.org/miekg/dns"
)

func TestDNSSECInternalQueriesBypassGeneralResponseCache(t *testing.T) {
	if err := initCachedResponses(16); err != nil {
		t.Fatal(err)
	}
	state := PluginsState{clientProto: dnssecInternalProto}
	query := dns.NewMsg("cache-bypass.example.", dns.TypeDS)
	if query == nil {
		t.Fatal("could not build query")
	}
	key := computeCacheKey(&state, query)
	cachedResponses.Insert(key, CachedResponse{
		expiration: time.Now().Add(time.Hour),
		msg:        cloneMsg(query),
	})

	if err := (&PluginCache{}).Eval(&state, query); err != nil {
		t.Fatal(err)
	}
	if state.synthResponse != nil || state.cacheHit {
		t.Fatal("an internal DNSSEC query was served from the general response cache")
	}
}

func TestDNSSECInternalQueriesAreNotWrittenToGeneralResponseCache(t *testing.T) {
	if err := initCachedResponses(16); err != nil {
		t.Fatal(err)
	}
	state := PluginsState{clientProto: dnssecInternalProto}
	response := dns.NewMsg("cache-bypass-write.example.", dns.TypeDS)
	if response == nil {
		t.Fatal("could not build response")
	}
	response.Response = true
	key := computeCacheKey(&state, response)

	if err := (&PluginCacheResponse{}).Eval(&state, response); err != nil {
		t.Fatal(err)
	}
	if _, ok := cachedResponses.Get(key); ok {
		t.Fatal("an internal DNSSEC response was written to the general response cache")
	}
}
