package main

import (
	"bytes"
	"net"
	"testing"
)

func TestExtractClientIPStr(t *testing.T) {
	tests := []struct {
		name         string
		pluginsState *PluginsState
		wantIP       string
		wantOK       bool
	}{
		{
			name: "nil clientAddr should return empty",
			pluginsState: &PluginsState{
				clientProto: "tcp",
				clientAddr:  nil,
			},
			wantIP: "",
			wantOK: false,
		},
		{
			name: "valid UDP address",
			pluginsState: &PluginsState{
				clientProto: "udp",
				clientAddr: func() *net.Addr {
					addr := net.Addr(
						&net.UDPAddr{
							IP:   net.ParseIP("192.168.1.1"),
							Port: 53,
						},
					)
					return &addr
				}(),
			},
			wantIP: "192.168.1.1",
			wantOK: true,
		},
		{
			name: "valid TCP address",
			pluginsState: &PluginsState{
				clientProto: "tcp",
				clientAddr: func() *net.Addr {
					addr := net.Addr(
						&net.TCPAddr{
							IP:   net.ParseIP("10.0.0.1"),
							Port: 53,
						},
					)
					return &addr
				}(),
			},
			wantIP: "10.0.0.1",
			wantOK: true,
		},
		{
			name: "unknown protocol",
			pluginsState: &PluginsState{
				clientProto: "unknown",
				clientAddr: func() *net.Addr {
					addr := net.Addr(
						&net.TCPAddr{
							IP:   net.ParseIP("10.0.0.1"),
							Port: 53,
						},
					)
					return &addr
				}(),
			},
			wantIP: "",
			wantOK: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotIP, gotOK := ExtractClientIPStr(tt.pluginsState)
			if gotIP != tt.wantIP {
				t.Errorf("ExtractClientIPStr() IP = %v, want %v", gotIP, tt.wantIP)
			}
			if gotOK != tt.wantOK {
				t.Errorf("ExtractClientIPStr() OK = %v, want %v", gotOK, tt.wantOK)
			}
		})
	}
}

func TestDNSStreamMessageLimitIsIndependentOfUDPWorkingSize(t *testing.T) {
	if MaxDNSPacketSize != 0xffff {
		t.Fatalf("stream DNS limit = %d, want 65535", MaxDNSPacketSize)
	}
	if MaxDNSUDPPacketSize >= MaxDNSPacketSize {
		t.Fatalf("UDP working size %d must remain below stream limit %d", MaxDNSUDPPacketSize, MaxDNSPacketSize)
	}
}

func TestReadPrefixedAcceptsDNSMessageLargerThanEDNSUDPSize(t *testing.T) {
	payload := bytes.Repeat([]byte{0x5a}, MaxDNSUDPPacketSize+236)
	prefixed, err := PrefixWithSize(append([]byte(nil), payload...))
	if err != nil {
		t.Fatal(err)
	}

	reader, writer := net.Pipe()
	writeErr := make(chan error, 1)
	go func() {
		_, err := writer.Write(prefixed)
		writeErr <- err
		_ = writer.Close()
	}()

	got, err := ReadPrefixed(reader)
	_ = reader.Close()
	if err != nil {
		t.Fatal(err)
	}
	if err := <-writeErr; err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, payload) {
		t.Fatalf("read %d bytes, want %d", len(got), len(payload))
	}
}

func TestReadPrefixedAcceptsMaximumDNSMessage(t *testing.T) {
	payload := bytes.Repeat([]byte{0xa5}, MaxDNSPacketSize)
	prefixed, err := PrefixWithSize(append([]byte(nil), payload...))
	if err != nil {
		t.Fatal(err)
	}

	reader, writer := net.Pipe()
	writeErr := make(chan error, 1)
	go func() {
		_, err := writer.Write(prefixed)
		writeErr <- err
		_ = writer.Close()
	}()

	got, err := ReadPrefixed(reader)
	_ = reader.Close()
	if err != nil {
		t.Fatal(err)
	}
	if err := <-writeErr; err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, payload) {
		t.Fatalf("read %d bytes, want %d", len(got), len(payload))
	}
}

func TestLocalDoHPaddingDoesNotExpandLargeAnswersToStreamLimit(t *testing.T) {
	size := MaxDNSUDPPacketSize + 1
	if got := dohPaddedLen(size); got != size {
		t.Fatalf("dohPaddedLen(%d) = %d, want no padding", size, got)
	}
}
