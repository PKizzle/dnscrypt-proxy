package main

import (
	"net"
	"testing"
	"time"

	"codeberg.org/miekg/dns"
)

// TestCacheStatisticsAccuracy tests that cache statistics only include
// queries that participate in caching (cache hits + queries that went to a server).
// Blocked queries should be excluded from cache statistics.
func TestCacheStatisticsAccuracy(t *testing.T) {
	// Create a minimal proxy config
	proxy := &Proxy{
		monitoringUI: MonitoringUIConfig{
			Enabled:            true,
			MaxQueryLogEntries: 100,
			MaxMemoryMB:        1,
		},
	}

	// Create monitoring UI and metrics collector
	ui := NewMonitoringUI(proxy)
	if ui == nil {
		t.Fatal("Failed to create monitoring UI")
	}
	mc := ui.metricsCollector

	// Initial state: no cache hits or misses
	if mc.cacheHits != 0 {
		t.Errorf("Initial cacheHits should be 0, got %d", mc.cacheHits)
	}
	if mc.cacheMisses != 0 {
		t.Errorf("Initial cacheMisses should be 0, got %d", mc.cacheMisses)
	}

	// Test case 1: Cache hit - should increment cacheHits
	{
		msg := &dns.Msg{}
		msg.Question = []dns.RR{&dns.A{Hdr: dns.Header{Name: "example.com.", Class: dns.ClassINET}}}

		addr := net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 1234}
		clientAddr := net.Addr(&addr)

		pluginsState := PluginsState{
			requestStart: time.Now(),
			timeout:      5 * time.Second,
			qName:        "example.com.",
			serverName:   "cloudflare",
			clientProto:  "udp",
			clientAddr:   &clientAddr,
			cacheHit:     true, // This is a cache hit
			returnCode:   PluginsReturnCodePass,
		}

		ui.UpdateMetrics(pluginsState, msg)

		if mc.cacheHits != 1 {
			t.Errorf("After cache hit, cacheHits should be 1, got %d", mc.cacheHits)
		}
		if mc.cacheMisses != 0 {
			t.Errorf("After cache hit, cacheMisses should be 0, got %d", mc.cacheMisses)
		}
	}

	// Test case 2: Cache miss with server resolution - should increment cacheMisses
	{
		msg := &dns.Msg{}
		msg.Question = []dns.RR{&dns.A{Hdr: dns.Header{Name: "example2.com.", Class: dns.ClassINET}}}

		addr := net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 1234}
		clientAddr := net.Addr(&addr)

		pluginsState := PluginsState{
			requestStart: time.Now(),
			timeout:      5 * time.Second,
			qName:        "example2.com.",
			serverName:   "cloudflare", // Query went to a server
			clientProto:  "udp",
			clientAddr:   &clientAddr,
			cacheHit:     false, // Cache miss
			returnCode:   PluginsReturnCodePass,
		}

		ui.UpdateMetrics(pluginsState, msg)

		if mc.cacheHits != 1 {
			t.Errorf("After cache miss, cacheHits should still be 1, got %d", mc.cacheHits)
		}
		if mc.cacheMisses != 1 {
			t.Errorf("After cache miss, cacheMisses should be 1, got %d", mc.cacheMisses)
		}
	}

	// Test case 3: Blocked query (REJECT) - should NOT increment either counter
	{
		msg := &dns.Msg{}
		msg.Question = []dns.RR{&dns.A{Hdr: dns.Header{Name: "blocked.com.", Class: dns.ClassINET}}}

		addr := net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 1234}
		clientAddr := net.Addr(&addr)

		pluginsState := PluginsState{
			requestStart: time.Now(),
			timeout:      5 * time.Second,
			qName:        "blocked.com.",
			serverName:   "-", // No server - query was blocked
			clientProto:  "udp",
			clientAddr:   &clientAddr,
			cacheHit:     false,
			returnCode:   PluginsReturnCodeReject, // Blocked query
		}

		ui.UpdateMetrics(pluginsState, msg)

		// Cache stats should NOT change for blocked queries
		if mc.cacheHits != 1 {
			t.Errorf("After blocked query, cacheHits should still be 1, got %d", mc.cacheHits)
		}
		if mc.cacheMisses != 1 {
			t.Errorf("After blocked query, cacheMisses should still be 1, got %d", mc.cacheMisses)
		}
		if mc.blockCount != 1 {
			t.Errorf("After blocked query, blockCount should be 1, got %d", mc.blockCount)
		}
	}

	// Test case 4: Another blocked query (DROP) - should NOT increment cache counters
	{
		msg := &dns.Msg{}
		msg.Question = []dns.RR{&dns.A{Hdr: dns.Header{Name: "dropped.com.", Class: dns.ClassINET}}}

		addr := net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 1234}
		clientAddr := net.Addr(&addr)

		pluginsState := PluginsState{
			requestStart: time.Now(),
			timeout:      5 * time.Second,
			qName:        "dropped.com.",
			serverName:   "-", // No server - query was dropped
			clientProto:  "udp",
			clientAddr:   &clientAddr,
			cacheHit:     false,
			returnCode:   PluginsReturnCodeDrop, // Dropped query
		}

		ui.UpdateMetrics(pluginsState, msg)

		// Cache stats should NOT change for dropped queries
		if mc.cacheHits != 1 {
			t.Errorf("After dropped query, cacheHits should still be 1, got %d", mc.cacheHits)
		}
		if mc.cacheMisses != 1 {
			t.Errorf("After dropped query, cacheMisses should still be 1, got %d", mc.cacheMisses)
		}
		if mc.blockCount != 2 {
			t.Errorf("After dropped query, blockCount should be 2, got %d", mc.blockCount)
		}
	}

	// Verify cache hit ratio calculation
	metrics := mc.GetMetrics()
	cacheHitRatio, ok := metrics["cache_hit_ratio"].(float64)
	if !ok {
		t.Fatal("cache_hit_ratio not found in metrics or wrong type")
	}

	// Expected: 1 hit / (1 hit + 1 miss) = 0.5
	expectedRatio := 0.5
	if cacheHitRatio != expectedRatio {
		t.Errorf("Expected cache hit ratio %.2f, got %.2f", expectedRatio, cacheHitRatio)
	}

	// Verify total queries includes all queries (including blocked ones)
	totalQueries, ok := metrics["total_queries"].(uint64)
	if !ok {
		t.Fatal("total_queries not found in metrics or wrong type")
	}
	// We sent 4 queries total (1 cache hit + 1 cache miss + 2 blocked)
	if totalQueries != 4 {
		t.Errorf("Expected total_queries to be 4, got %d", totalQueries)
	}

	// Verify blocked queries count
	blockedQueries, ok := metrics["blocked_queries"].(uint64)
	if !ok {
		t.Fatal("blocked_queries not found in metrics or wrong type")
	}
	if blockedQueries != 2 {
		t.Errorf("Expected blocked_queries to be 2, got %d", blockedQueries)
	}
}
