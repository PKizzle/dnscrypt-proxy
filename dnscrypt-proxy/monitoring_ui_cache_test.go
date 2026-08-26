package main

import (
	"net"
	"sync/atomic"
	"testing"
	"time"

	"codeberg.org/miekg/dns"
)

// newTestMonitoringUI builds a monitoring UI with its collector running.
func newTestMonitoringUI(t *testing.T) *MonitoringUI {
	t.Helper()
	ui := NewMonitoringUI(&Proxy{
		monitoringUI: MonitoringUIConfig{
			Enabled:            true,
			MaxQueryLogEntries: 100,
			MaxMemoryMB:        1,
		},
	})
	if ui == nil {
		t.Fatal("Failed to create monitoring UI")
	}
	return ui
}

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

		ui.UpdateMetrics(&pluginsState, msg)
		ui.Flush()

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

		ui.UpdateMetrics(&pluginsState, msg)
		ui.Flush()

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

		ui.UpdateMetrics(&pluginsState, msg)
		ui.Flush()

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

		ui.UpdateMetrics(&pluginsState, msg)
		ui.Flush()

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

// The collector runs on its own goroutine, so a caller that has just recorded
// something and needs to read it back has to have a way to wait.
func TestFlushMakesRecordedQueriesVisible(t *testing.T) {
	ui := newTestMonitoringUI(t)
	defer func() { _ = ui.Stop() }()

	msg := &dns.Msg{}
	msg.Question = []dns.RR{&dns.A{Hdr: dns.Header{Name: "flush.example.", Class: dns.ClassINET}}}
	for i := 0; i < 50; i++ {
		pluginsState := PluginsState{
			returnCode:   PluginsReturnCodePass,
			serverName:   "test-server",
			qName:        "flush.example.",
			questionMsg:  msg,
			cacheHit:     true,
			requestStart: time.Now(),
			timeout:      5 * time.Second,
		}
		ui.UpdateMetrics(&pluginsState, msg)
	}
	ui.Flush()

	ui.metricsCollector.countersMutex.RLock()
	total := ui.metricsCollector.totalQueries
	hits := ui.metricsCollector.cacheHits
	ui.metricsCollector.countersMutex.RUnlock()

	if total != 50 {
		t.Errorf("totalQueries = %d after Flush(), want 50", total)
	}
	if hits != 50 {
		t.Errorf("cacheHits = %d after Flush(), want 50", hits)
	}
}

// Recording must never block the goroutine answering a query, even when the
// collector cannot keep up: the events are dropped and counted instead.
func TestUpdateMetricsDoesNotBlockWhenTheQueueIsFull(t *testing.T) {
	ui := newTestMonitoringUI(t)
	defer func() { _ = ui.Stop() }()

	// Stop the collector so nothing drains, then overfill the queue.
	close(ui.metricsCollector.collectorStop)
	time.Sleep(50 * time.Millisecond)

	msg := &dns.Msg{}
	msg.Question = []dns.RR{&dns.A{Hdr: dns.Header{Name: "flood.example.", Class: dns.ClassINET}}}

	done := make(chan struct{})
	go func() {
		defer close(done)
		for i := 0; i < cap(ui.metricsCollector.events)*2; i++ {
			pluginsState := PluginsState{
				returnCode:   PluginsReturnCodePass,
				serverName:   "test-server",
				qName:        "flood.example.",
				questionMsg:  msg,
				requestStart: time.Now(),
				timeout:      5 * time.Second,
			}
			ui.UpdateMetrics(&pluginsState, msg)
		}
	}()

	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("UpdateMetrics blocked when the collector was not draining")
	}
	if atomic.LoadUint64(&ui.metricsCollector.droppedEvents) == 0 {
		t.Error("events beyond the queue should be counted as dropped")
	}
}
