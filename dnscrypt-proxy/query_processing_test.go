package main

import (
	"errors"
	"testing"

	"codeberg.org/miekg/dns"
)

func packedResponseWithRcode(t *testing.T, rcode uint16) []byte {
	t.Helper()
	msg := dns.NewMsg("example.test.", dns.TypeA)
	msg.Response = true
	msg.Rcode = rcode
	if err := msg.Pack(); err != nil {
		t.Fatal(err)
	}
	return msg.Data
}

func TestUpstreamExchangeSucceededRejectsDNSLevelSERVFAIL(t *testing.T) {
	if upstreamExchangeSucceeded(&PluginsState{}, nil, nil) {
		t.Error("a missing response was counted as success")
	}
	if upstreamExchangeSucceeded(&PluginsState{}, []byte{}, nil) {
		t.Error("an empty response was counted as success")
	}
	if upstreamExchangeSucceeded(&PluginsState{}, packedResponseWithRcode(t, dns.RcodeSuccess), errors.New("transport failed")) {
		t.Error("a transport error was counted as success")
	}
	if upstreamExchangeSucceeded(&PluginsState{}, packedResponseWithRcode(t, dns.RcodeServerFailure), nil) {
		t.Error("an upstream SERVFAIL was counted as success")
	}
	if !upstreamExchangeSucceeded(&PluginsState{}, packedResponseWithRcode(t, dns.RcodeSuccess), nil) {
		t.Error("an upstream NOERROR response was not counted as success")
	}
	if !upstreamExchangeSucceeded(&PluginsState{}, packedResponseWithRcode(t, dns.RcodeNameError), nil) {
		t.Error("an upstream NXDOMAIN response was not counted as success")
	}
}

func TestUpstreamExchangeSucceededRejectsAStaleAnswer(t *testing.T) {
	stale := &PluginsState{servedStale: true}
	if upstreamExchangeSucceeded(stale, packedResponseWithRcode(t, dns.RcodeSuccess), nil) {
		t.Error("an answer from the stale cache after a failed exchange was counted as the server's success")
	}
}
