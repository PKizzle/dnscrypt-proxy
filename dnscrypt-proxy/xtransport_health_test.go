package main

import (
	"net/http"
	"testing"
	"time"
)

func TestHTTP2DeadConnectionDetectionFollowsTimeout(t *testing.T) {
	h2 := configureHTTP2Transport(&http.Transport{}, time.Second)
	if h2 == nil {
		t.Fatal("HTTP/2 was not configured")
	}
	if h2.ReadIdleTimeout != time.Second || h2.PingTimeout != time.Second {
		t.Fatalf("ReadIdleTimeout=%v PingTimeout=%v, want both 1s", h2.ReadIdleTimeout, h2.PingTimeout)
	}
}

func TestHTTP3TransportClosesDeadConnectionsQuickly(t *testing.T) {
	xTransport := NewXTransport()
	xTransport.timeout = time.Second
	xTransport.http3 = true
	xTransport.rebuildTransport()

	cfg := xTransport.h3Transport.QUICConfig
	if cfg == nil {
		t.Fatal("HTTP/3 transport uses quic-go defaults (30s idle timeout)")
	}
	if cfg.MaxIdleTimeout != HTTP3MaxIdleTimeout || cfg.KeepAlivePeriod != HTTP3KeepAlivePeriod {
		t.Fatalf("MaxIdleTimeout=%v KeepAlivePeriod=%v", cfg.MaxIdleTimeout, cfg.KeepAlivePeriod)
	}
	if cfg.KeepAlivePeriod >= cfg.MaxIdleTimeout {
		t.Fatal("keepalives must be sent within the idle timeout or quiet connections close")
	}
}
