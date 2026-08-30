package main

import (
	"crypto/sha512"
	"encoding/binary"
	"fmt"
	"github.com/dnscrypt/dnscrypt-proxy/dnscrypt-proxy/dnssec"
	"time"

	"codeberg.org/miekg/dns"
	"github.com/jedisct1/go-sieve-cache/pkg/sievecache"
)

const StaleResponseTTL = 30 * time.Second

type CachedResponse struct {
	expiration time.Time
	msg        *dns.Msg
}

// cachedResponses is created once, before any goroutine that reads it exists
var cachedResponses *sievecache.ShardedSieveCache[[32]byte, CachedResponse]

func initCachedResponses(cacheSize int) error {
	if cachedResponses != nil {
		return nil
	}
	cache, err := sievecache.NewSharded[[32]byte, CachedResponse](cacheSize)
	if err != nil {
		return fmt.Errorf("failed to initialize the cache: %w", err)
	}
	cachedResponses = cache
	return nil
}

func computeCacheKey(pluginsState *PluginsState, msg *dns.Msg) [32]byte {
	question := msg.Question[0]
	h := sha512.New512_256()
	var tmp [5]byte
	binary.LittleEndian.PutUint16(tmp[0:2], dns.RRToType(question))
	binary.LittleEndian.PutUint16(tmp[2:4], question.Header().Class)
	if pluginsState.dnssec {
		tmp[4] = 1
	}
	if msg.CheckingDisabled {
		tmp[4] |= 2
	}
	h.Write(tmp[:])
	normalizedRawQName := []byte(question.Header().Name)
	NormalizeRawQName(&normalizedRawQName)
	h.Write(normalizedRawQName)
	var sum [32]byte
	h.Sum(sum[:0])

	return sum
}

// ---

type PluginCache struct{}

func (plugin *PluginCache) Name() string {
	return "cache"
}

func (plugin *PluginCache) Description() string {
	return "DNS cache (reader)."
}

func (plugin *PluginCache) Init(proxy *Proxy) error {
	return initCachedResponses(proxy.cacheSize)
}

func (plugin *PluginCache) Drop() error {
	return nil
}

func (plugin *PluginCache) Reload() error {
	return nil
}

func (plugin *PluginCache) Eval(pluginsState *PluginsState, msg *dns.Msg) error {
	// DNSSEC's internal DNSKEY and DS fetches have their own cache, which only
	// retains the material the chain walk has accepted. Replaying a response
	// from the general cache here would defeat the chain walk's retry path: a
	// malformed or incomplete delegation proof is evicted from that cache, but
	// would still be served again before a different upstream could be tried.
	if pluginsState.clientProto == dnssecInternalProto {
		return nil
	}
	if cachedResponses == nil {
		return nil
	}
	cacheKey := computeCacheKey(pluginsState, msg)
	cached, ok := cachedResponses.Get(cacheKey)
	if !ok {
		return nil
	}
	expiration := cached.expiration
	synth := cloneMsg(cached.msg)

	synth.ID = msg.ID
	synth.Response = true
	synth.Question = msg.Question

	if time.Now().After(expiration) {
		expiration2 := time.Now().Add(StaleResponseTTL)
		updateTTL(synth, expiration2)
		pluginsState.sessionData["stale"] = synth
		return nil
	}

	updateTTL(synth, expiration)

	pluginsState.synthResponse = synth
	pluginsState.action = PluginsActionSynth
	pluginsState.cacheHit = true
	return nil
}

// ---

type PluginCacheResponse struct{}

func (plugin *PluginCacheResponse) Name() string {
	return "cache_response"
}

func (plugin *PluginCacheResponse) Description() string {
	return "DNS cache (writer)."
}

func (plugin *PluginCacheResponse) Init(proxy *Proxy) error {
	return initCachedResponses(proxy.cacheSize)
}

func (plugin *PluginCacheResponse) Drop() error {
	return nil
}

func (plugin *PluginCacheResponse) Reload() error {
	return nil
}

func (plugin *PluginCacheResponse) Eval(pluginsState *PluginsState, msg *dns.Msg) error {
	// See PluginCache.Eval. Internal validation material is cached only after
	// the DNSSEC fetcher has accepted it; the general cache must not preserve a
	// reply which the chain walk later rejects.
	if pluginsState.clientProto == dnssecInternalProto {
		return nil
	}
	if msg.Rcode != dns.RcodeSuccess && msg.Rcode != dns.RcodeNameError && msg.Rcode != dns.RcodeNotAuth {
		return nil
	}
	if msg.Truncated {
		return nil
	}
	if cachedResponses == nil {
		return nil
	}
	cacheKey := computeCacheKey(pluginsState, msg)
	ttl := getMinTTL(
		msg,
		pluginsState.cacheMinTTL,
		pluginsState.cacheMaxTTL,
		pluginsState.cacheNegMinTTL,
		pluginsState.cacheNegMaxTTL,
	)
	expiration := time.Now().Add(ttl)
	// An answer must not outlive the signatures that vouch for it. RFC 4035
	// section 5.3.3 puts the RRSIG expiration as a hard bound on how long the
	// data may be used, and this cache carries the validator's verdict with the
	// entry -- so without the bound it would keep serving a verdict that had
	// stopped being true, and cache_min_ttl could push an entry past the
	// signature on its own.
	if until, ok := dnssec.EarliestSignatureExpiry(time.Now(), msg.Answer, msg.Ns); ok && until.Before(expiration) {
		expiration = until
	}
	cachedMsg := cloneMsg(msg)
	cachedMsg.Question = nil
	cachedResponses.Insert(cacheKey, CachedResponse{expiration: expiration, msg: cachedMsg})
	updateTTL(msg, expiration)

	return nil
}
