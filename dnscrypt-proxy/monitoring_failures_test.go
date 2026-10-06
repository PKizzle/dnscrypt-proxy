package main

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"
)

func TestPrometheusReportsFailuresAndPreferredServer(t *testing.T) {
	ui := newTestMonitoringUI(t)
	mc := ui.metricsCollector
	mc.prometheusEnabled = true
	proxy := mc.proxy
	proxy.timeout = time.Second
	proxy.serversInfo = NewServersInfo()
	proxy.serversInfo.lbStrategy = LBStrategyFirst{}
	proxy.serversInfo.inner = []*ServerInfo{
		refreshTestServer("cloudflare", 10),
		refreshTestServer("quad9", 20),
	}

	cloudflare, quad9 := proxy.serversInfo.inner[0], proxy.serversInfo.inner[1]

	// One timeout demotes the preferred server, so quad9 takes the queries.
	cloudflare.noticeFailureReason(proxy, failureReasonTimeout)
	out := mc.generatePrometheusMetrics()
	for _, want := range []string{
		`dnscrypt_proxy_server_failures_total{server="cloudflare",reason="timeout"} 1`,
		`dnscrypt_proxy_preferred_server{server="quad9"} 1`,
		`dnscrypt_proxy_preferred_server{server="cloudflare"} 0`,
	} {
		if !strings.Contains(out, want) {
			t.Errorf("metrics missing %q", want)
		}
	}

	// A failure re-sorts the order, so the servers are held by pointer.
	quad9.noticeFailureReason(proxy, failureReasonServfail)
	quad9.noticeFailureReason(proxy, failureReasonServfail)
	out = mc.generatePrometheusMetrics()
	if want := `dnscrypt_proxy_server_failures_total{server="quad9",reason="servfail"} 2`; !strings.Contains(out, want) {
		t.Errorf("metrics missing %q", want)
	}
	head := proxy.serversInfo.serverOrder()[0]
	if want := `dnscrypt_proxy_preferred_server{server="` + head + `"} 1`; !strings.Contains(out, want) {
		t.Errorf("preferred gauge disagrees with selection order head %q", head)
	}
	ones := 0
	for _, line := range strings.Split(out, "\n") {
		if strings.HasPrefix(line, "dnscrypt_proxy_preferred_server{") && strings.HasSuffix(line, " 1") {
			ones++
		}
	}
	if ones != 1 {
		t.Errorf("preferred_server has %d series set to 1, want exactly 1", ones)
	}
}

func TestFailureCountersSurviveServerReplacement(t *testing.T) {
	proxy := NewProxy()
	proxy.timeout = time.Second
	proxy.serversInfo.inner = []*ServerInfo{refreshTestServer("resolver", 10)}
	proxy.serversInfo.inner[0].noticeFailure(proxy)
	// A certificate refresh swaps in a new ServerInfo for the same name.
	proxy.serversInfo.inner[0] = refreshTestServer("resolver", 10)
	proxy.serversInfo.inner[0].noticeFailure(proxy)

	if got := proxy.serversInfo.failureCounts()[serverFailureKey{"resolver", failureReasonOther}]; got != 2 {
		t.Fatalf("failures after replacement = %d, want 2", got)
	}
}

func TestFailureReasonForError(t *testing.T) {
	if got := failureReasonForError(context.DeadlineExceeded); got != failureReasonTimeout {
		t.Errorf("deadline exceeded classified as %q", got)
	}
	if got := failureReasonForError(errors.New("connection refused")); got != failureReasonNetwork {
		t.Errorf("plain error classified as %q", got)
	}
}
