package main

import (
	"testing"
	"time"

	"github.com/VividCortex/ewma"
)

func retryTestServer(name string) *ServerInfo {
	return &ServerInfo{Name: name, rtt: ewma.NewMovingAverage(RTTEwmaDecay)}
}

func TestGetOneExceptNeverReturnsExcludedServer(t *testing.T) {
	serversInfo := NewServersInfo()
	serversInfo.inner = []*ServerInfo{
		retryTestServer("excluded"),
		retryTestServer("eligible-a"),
		retryTestServer("eligible-b"),
	}

	for range 100 {
		server := serversInfo.getOneExcept("excluded")
		if server == nil {
			t.Fatal("getOneExcept() returned nil with eligible servers")
		}
		if server.Name == "excluded" {
			t.Fatal("getOneExcept() returned the excluded server")
		}
	}
}

func TestGetOneKeepsConfiguredSelectorForOrdinaryQueries(t *testing.T) {
	serversInfo := NewServersInfo()
	serversInfo.lbStrategy = LBStrategyFirst{}
	serversInfo.inner = []*ServerInfo{
		retryTestServer("first"),
		retryTestServer("second"),
	}

	server := serversInfo.getOne()
	if server == nil {
		t.Fatal("getOne() returned nil")
	}
	if server.Name != "first" {
		t.Fatalf("getOne() = %q, want configured first candidate", server.Name)
	}
}

func TestFirstStrategyPromotesAlternativeAfterFailure(t *testing.T) {
	proxy := NewProxy()
	proxy.timeout = time.Second
	proxy.serversInfo.lbStrategy = LBStrategyFirst{}
	proxy.serversInfo.lbEstimator = false
	proxy.serversInfo.inner = []*ServerInfo{
		retryTestServer("first"),
		retryTestServer("second"),
	}
	proxy.serversInfo.inner[0].rtt.Set(10)
	proxy.serversInfo.inner[1].rtt.Set(20)

	failed := proxy.serversInfo.getOne()
	if failed == nil || failed.Name != "first" {
		t.Fatalf("initial getOne() = %v, want first", failed)
	}
	failed.noticeFailure(proxy)

	next := proxy.serversInfo.getOne()
	if next == nil || next.Name != "second" {
		t.Fatalf("getOne() after failure = %v, want second", next)
	}
}

func TestGetOneExceptReturnsNilWhenNoAlternativeExists(t *testing.T) {
	serversInfo := NewServersInfo()
	serversInfo.inner = []*ServerInfo{retryTestServer("only")}
	if server := serversInfo.getOneExcept("only"); server != nil {
		t.Fatalf("getOneExcept() = %q, want nil", server.Name)
	}
}

func TestGetOneExcludingNeverReusesATriedServer(t *testing.T) {
	serversInfo := NewServersInfo()
	serversInfo.inner = []*ServerInfo{
		retryTestServer("original"),
		retryTestServer("alternate-a"),
		retryTestServer("alternate-b"),
	}
	excluded := map[string]struct{}{"original": {}}

	for range 2 {
		server := serversInfo.getOneExcluding(excluded)
		if server == nil {
			t.Fatal("getOneExcluding() exhausted eligible servers too early")
		}
		if _, wasTried := excluded[server.Name]; wasTried {
			t.Fatalf("getOneExcluding() reused tried server %q", server.Name)
		}
		excluded[server.Name] = struct{}{}
	}
	if server := serversInfo.getOneExcluding(excluded); server != nil {
		t.Fatalf("getOneExcluding() = %q after all servers were tried, want nil", server.Name)
	}
}
