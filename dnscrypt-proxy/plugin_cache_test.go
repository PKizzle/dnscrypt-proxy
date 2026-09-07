package main

import (
	"testing"
	"time"

	"codeberg.org/miekg/dns"
	"github.com/dnscrypt/dnscrypt-proxy/dnscrypt-proxy/dnssec"
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

func TestCachedResponsePreservesDNSSECVerdict(t *testing.T) {
	if err := initCachedResponses(16); err != nil {
		t.Fatal(err)
	}
	question := dns.NewMsg("cached-verdict.example.", dns.TypeA)
	if question == nil {
		t.Fatal("could not build query")
	}
	response := cloneMsg(question)
	response.Response = true
	response.Answer = []dns.RR{&dns.A{
		Hdr: dns.Header{Name: "cached-verdict.example.", Class: dns.ClassINET, TTL: 60},
	}}

	writerState := PluginsState{
		cacheMinTTL: 1,
		cacheMaxTTL: 60,
		sessionData: map[string]any{
			dnssecVerdictKey: dnssec.Secure.String(),
		},
	}
	if err := (&PluginCacheResponse{}).Eval(&writerState, response); err != nil {
		t.Fatal(err)
	}

	readerState := PluginsState{}
	if err := (&PluginCache{}).Eval(&readerState, question); err != nil {
		t.Fatal(err)
	}
	if !readerState.cacheHit {
		t.Fatal("expected response to be served from cache")
	}
	if got, _ := readerState.sessionData[dnssecVerdictKey].(string); got != dnssec.Secure.String() {
		t.Fatalf("cached DNSSEC verdict = %q, want %q", got, dnssec.Secure.String())
	}
}

func TestCachedBogusCDResponseIsNotSharedWithNonCDClient(t *testing.T) {
	if err := initCachedResponses(16); err != nil {
		t.Fatal(err)
	}
	const name = "cached-cd-bogus.example."

	cdQuery := dns.NewMsg(name, dns.TypeA)
	cdQuery.CheckingDisabled = true
	cdWriter := PluginsState{
		cacheMinTTL: 1,
		cacheMaxTTL: 60,
		sessionData: map[string]any{},
	}
	if err := (&PluginDNSSECRequest{}).Eval(&cdWriter, cdQuery); err != nil {
		t.Fatal(err)
	}
	if !cdQuery.CheckingDisabled {
		t.Fatal("upstream query did not retain the forced CD bit")
	}
	cdWriter.sessionData[dnssecVerdictKey] = dnssec.Bogus.String()
	response := cloneMsg(cdQuery)
	response.Response = true
	response.Answer = []dns.RR{&dns.A{
		Hdr: dns.Header{Name: name, Class: dns.ClassINET, TTL: 60},
	}}
	if err := (&PluginCacheResponse{}).Eval(&cdWriter, response); err != nil {
		t.Fatal(err)
	}

	nonCDQuery := dns.NewMsg(name, dns.TypeA)
	nonCDReader := PluginsState{sessionData: map[string]any{}}
	if err := (&PluginDNSSECRequest{}).Eval(&nonCDReader, nonCDQuery); err != nil {
		t.Fatal(err)
	}
	if !nonCDQuery.CheckingDisabled {
		t.Fatal("DNSSEC request plugin did not force CD upstream")
	}
	if err := (&PluginCache{}).Eval(&nonCDReader, nonCDQuery); err != nil {
		t.Fatal(err)
	}
	if nonCDReader.cacheHit || nonCDReader.synthResponse != nil {
		t.Fatal("a non-CD client received the Bogus response cached for a CD client")
	}

	cdQueryAgain := dns.NewMsg(name, dns.TypeA)
	cdQueryAgain.CheckingDisabled = true
	cdReader := PluginsState{sessionData: map[string]any{}}
	if err := (&PluginDNSSECRequest{}).Eval(&cdReader, cdQueryAgain); err != nil {
		t.Fatal(err)
	}
	if err := (&PluginCache{}).Eval(&cdReader, cdQueryAgain); err != nil {
		t.Fatal(err)
	}
	if !cdReader.cacheHit || cdReader.synthResponse == nil {
		t.Fatal("the CD client did not receive its own cached response")
	}
	if got, _ := cdReader.sessionData[dnssecVerdictKey].(string); got != dnssec.Bogus.String() {
		t.Fatalf("cached DNSSEC verdict = %q, want %q", got, dnssec.Bogus.String())
	}
}
