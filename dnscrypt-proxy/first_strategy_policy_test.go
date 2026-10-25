package main

import (
	"fmt"
	"strings"
	"testing"
	"time"
)

func TestLoadBalancingDefaultsKeepFirstStrategyPolicy(t *testing.T) {
	want := firstStrategyPolicy{
		failbackDelay:           5 * time.Minute,
		failbackTolerance:       1.1,
		servfailFailover:        3,
		servfailSustainedCount:  16,
		servfailSustainedWindow: 30 * time.Second,
	}
	if got := NewServersInfo().firstPolicy; got != want {
		t.Fatalf("NewServersInfo policy = %+v, want %+v", got, want)
	}
	config := newConfig()
	proxy := NewProxy()
	if err := configureLoadBalancing(proxy, &config); err != nil {
		t.Fatalf("default configuration rejected: %v", err)
	}
	if got := proxy.serversInfo.firstPolicy; got != want {
		t.Fatalf("configured default policy = %+v, want %+v", got, want)
	}
}

func TestLoadBalancingAppliesFirstStrategyPolicy(t *testing.T) {
	config := newConfig()
	config.LBFailbackDelay = 60
	config.LBFailbackTolerance = 0
	config.LBServfailFailover = 1
	config.LBSustainedServfails = 4
	config.LBSustainedWindow = 0
	proxy := NewProxy()
	if err := configureLoadBalancing(proxy, &config); err != nil {
		t.Fatal(err)
	}
	want := firstStrategyPolicy{
		failbackDelay:           time.Minute,
		failbackTolerance:       1,
		servfailFailover:        1,
		servfailSustainedCount:  4,
		servfailSustainedWindow: 0,
	}
	if got := proxy.serversInfo.firstPolicy; got != want {
		t.Fatalf("policy = %+v, want %+v", got, want)
	}
}

func TestLoadBalancingRejectsInvalidFirstStrategyPolicy(t *testing.T) {
	cases := []struct {
		key    string
		mutate func(*Config)
	}{
		{"lb_failback_delay", func(c *Config) { c.LBFailbackDelay = 9 }},
		{"lb_failback_tolerance", func(c *Config) { c.LBFailbackTolerance = -1 }},
		{"lb_failback_tolerance", func(c *Config) { c.LBFailbackTolerance = 101 }},
		{"lb_servfail_failover", func(c *Config) { c.LBServfailFailover = 0 }},
		{"lb_servfail_sustained_count", func(c *Config) { c.LBSustainedServfails = 0 }},
		{"lb_servfail_sustained_window", func(c *Config) { c.LBSustainedWindow = -1 }},
	}
	for _, c := range cases {
		config := newConfig()
		c.mutate(&config)
		err := configureLoadBalancing(NewProxy(), &config)
		if err == nil || !strings.Contains(err.Error(), c.key) {
			t.Errorf("%s: error = %v, want one naming the key", c.key, err)
		}
	}
}

func TestFirstStrategyHonoursFailbackDelay(t *testing.T) {
	proxy := firstStrategyFailbackProxy()
	proxy.serversInfo.firstPolicy.failbackDelay = time.Minute
	probe := installFakeProbe(proxy, map[string]float64{"fast": 14, "slow": 90})
	fast := proxy.serversInfo.inner[0]
	fast.noticeFailure(proxy)
	if got := headName(proxy); got != "slow" {
		t.Fatalf("head after the failure = %q, want slow", got)
	}
	failBackAt(proxy, fast.failover.demotedAt.Add(time.Minute-time.Second))
	if got := probe.callCount("fast"); got != 0 {
		t.Fatalf("fast probed %d times before the delay, want 0", got)
	}
	failBackAt(proxy, fast.failover.demotedAt.Add(time.Minute))
	if got := headName(proxy); got != "fast" {
		t.Fatalf("head after the configured delay = %q, want fast", got)
	}
}

func TestFirstStrategyHonoursFailbackTolerance(t *testing.T) {
	cases := []struct {
		tolerance float64
		demoted   float64
		want      string
	}{
		{1, 101, "slow"},
		{1, 100, "fast"},
		{1.5, 140, "fast"},
		{1.5, 151, "slow"},
	}
	for _, c := range cases {
		proxy := firstStrategyFailbackProxy()
		proxy.serversInfo.firstPolicy.failbackTolerance = c.tolerance
		installFakeProbe(proxy, map[string]float64{"fast": c.demoted, "slow": 100})
		fast := proxy.serversInfo.inner[0]
		fast.noticeFailure(proxy)
		failBackAt(proxy, fast.failover.demotedAt.Add(firstStrategyFailbackDelay))
		if got := headName(proxy); got != c.want {
			t.Errorf("tolerance %v, demoted probe %v against 100: head = %q, want %q",
				c.tolerance, c.demoted, got, c.want)
		}
	}
}

func TestFirstStrategyHonoursServfailFailover(t *testing.T) {
	proxy := firstStrategyFailbackProxy()
	proxy.serversInfo.firstPolicy.servfailFailover = 1
	proxy.serversInfo.inner[0].noticeServfail(proxy, "one.example.test.", false)
	if got := headName(proxy); got != "slow" {
		t.Fatalf("head after one SERVFAIL = %q, want slow", got)
	}
}

func TestFirstStrategyHonoursSustainedServfailRun(t *testing.T) {
	proxy := firstStrategyFailbackProxy()
	proxy.serversInfo.firstPolicy.servfailSustainedCount = 4
	proxy.serversInfo.firstPolicy.servfailSustainedWindow = 10 * time.Second
	fast := proxy.serversInfo.inner[0]
	for i := range 3 {
		fast.noticeServfail(proxy, fmt.Sprintf("bl%d.example.test.", i), true)
	}
	proxy.serversInfo.Lock()
	fast.failover.servfailRunStartedAt = time.Now().Add(-10 * time.Second)
	proxy.serversInfo.Unlock()
	if got := headName(proxy); got != "fast" {
		t.Fatalf("three zone-attributed SERVFAILs moved the head to %q", got)
	}
	fast.noticeServfail(proxy, "bl3.example.test.", true)
	if got := headName(proxy); got != "slow" {
		t.Fatalf("a sustained run of four SERVFAILs over the window kept the head: %q", got)
	}
}
