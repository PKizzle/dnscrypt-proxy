package main

import (
	"bytes"
	"encoding/binary"
	"testing"

	"codeberg.org/miekg/dns"
)

// paddedResponse builds an NXDOMAIN response whose OPT record carries an EDNS
// padding option, the shape a DoH resolver returns for a padded query.
func paddedResponse(t *testing.T, id uint16, padding int) []byte {
	t.Helper()
	var b bytes.Buffer
	header := []uint16{id, 0x8183, 1, 0, 0, 1} // QR RD RA, NXDOMAIN
	for _, v := range header {
		binary.Write(&b, binary.BigEndian, v)
	}
	b.Write([]byte{7, 'e', 'x', 'a', 'm', 'p', 'l', 'e', 4, 't', 'e', 's', 't', 0})
	binary.Write(&b, binary.BigEndian, []uint16{dns.TypeAAAA, dns.ClassINET})
	b.WriteByte(0) // OPT owner: root
	binary.Write(&b, binary.BigEndian, []uint16{dns.TypeOPT, 1232})
	binary.Write(&b, binary.BigEndian, uint32(0x8000)) // DO
	binary.Write(&b, binary.BigEndian, uint16(4+padding))
	binary.Write(&b, binary.BigEndian, []uint16{12, uint16(padding)})
	b.Write(make([]byte, padding))
	return b.Bytes()
}

// repackWithoutOptions does what response processing does to a message:
// unpack it, drop its EDNS options, and pack it into the buffer it came in.
func repackWithoutOptions(t *testing.T, packet []byte) []byte {
	t.Helper()
	msg := dns.Msg{Data: packet}
	if err := msg.Unpack(); err != nil {
		t.Fatalf("unpack before repack: %v", err)
	}
	removeEDNS0Options(&msg)
	if err := msg.Pack(); err != nil {
		t.Fatalf("repack: %v", err)
	}
	return msg.Data
}

func TestRepackWritesIntoTheGivenBuffer(t *testing.T) {
	// This is why a collapsed response must never be handed out shared: if
	// re-packing allocated a new buffer, sharing would be harmless.
	packet := paddedResponse(t, 1, 310)
	repacked := repackWithoutOptions(t, packet)
	if len(repacked) >= len(packet) || &repacked[0] != &packet[0] {
		t.Skip("this DNS library no longer re-packs in place; the copy is still required for safety")
	}
}

func TestCollapsedCallersGetIndependentResponses(t *testing.T) {
	shared := paddedResponse(t, 0x1111, 310)
	original := bytes.Clone(shared)
	leaderQuery := []byte{0x11, 0x11}
	followerQuery := []byte{0x22, 0x22}

	// The caller that did the work processes its answer first, re-packing it.
	leader := inflightResponseForCaller(shared, leaderQuery)
	repackWithoutOptions(t, leader)

	// A caller that waited reads the shared answer afterwards.
	follower := inflightResponseForCaller(shared, followerQuery)
	if !bytes.Equal(shared, original) {
		t.Fatal("processing one caller's response modified the shared response")
	}
	msg := dns.Msg{Data: follower}
	if err := msg.Unpack(); err != nil {
		t.Fatalf("waiting caller received a corrupted response: %v", err)
	}
	if msg.ID != 0x2222 {
		t.Fatalf("waiting caller's response ID = %#x, want its own %#x", msg.ID, 0x2222)
	}
}

func TestCollapsedFailureStaysNil(t *testing.T) {
	if got := inflightResponseForCaller(nil, []byte{1, 2}); got != nil {
		t.Fatalf("response = %v, want nil so the caller sees no answer", got)
	}
}
