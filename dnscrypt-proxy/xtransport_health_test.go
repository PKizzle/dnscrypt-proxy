package main

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"
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

	cfg := xTransport.http3Pool.newTransport().QUICConfig
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

// localCertificate returns a self-signed certificate for 127.0.0.1 and the
// path of a PEM file that makes a transport trust it.
func localCertificate(t *testing.T) (tls.Certificate, string) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "127.0.0.1"},
		IPAddresses:           []net.IP{net.IPv4(127, 0, 0, 1)},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "ca.pem")
	if err := os.WriteFile(path, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o600); err != nil {
		t.Fatal(err)
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}, path
}

func TestHTTP3ClosesAConnectionThatNoRequestUses(t *testing.T) {
	// Keepalives stop the QUIC idle timeout from closing a quiet connection, so
	// the transport has to close it once no request has used it for the idle
	// limit. Otherwise every server a refresh probes keeps a connection forever.
	cert, caPath := localCertificate(t)
	udpConn, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	connections := make(chan *quic.Conn, 4)
	server := &http3.Server{
		Handler:   http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}),
		TLSConfig: http3.ConfigureTLSConfig(&tls.Config{Certificates: []tls.Certificate{cert}}),
		ConnContext: func(ctx context.Context, conn *quic.Conn) context.Context {
			connections <- conn
			return ctx
		},
	}
	go server.Serve(udpConn)
	t.Cleanup(func() {
		server.Close()
		udpConn.Close()
	})

	xTransport := NewXTransport()
	xTransport.timeout = 2 * time.Second
	xTransport.http3 = true
	xTransport.http3Probe = true
	xTransport.idleConnTimeout = 100 * time.Millisecond
	xTransport.tlsClientCreds = DOHClientCreds{rootCA: caPath}
	xTransport.rebuildTransport()

	u := &url.URL{Scheme: "https", Host: udpConn.LocalAddr().String(), Path: "/dns-query"}
	if _, _, _, _, err := xTransport.Get(u, "", 0); err != nil {
		t.Fatal(err)
	}
	var conn *quic.Conn
	select {
	case conn = <-connections:
	default:
		t.Fatal("the request did not reach the server over HTTP/3")
	}
	select {
	case <-conn.Context().Done():
	case <-time.After(3 * time.Second):
		t.Fatal("the HTTP/3 connection was still open long after its last request")
	}
}

func TestHTTP3PoolKeepsHostsThatRequestsStillUse(t *testing.T) {
	pool := newHTTP3Pool(func() *http3.Transport { return &http3.Transport{} }, time.Minute)
	busy := pool.acquire("busy.example")
	recent := pool.acquire("recent.example")
	pool.release("recent.example")
	quiet := pool.acquire("quiet.example")
	pool.release("quiet.example")

	pool.closeIdleSince(time.Now().Add(-time.Minute))
	if pool.acquire("busy.example") != busy {
		t.Error("closed the connection of a host with a request in flight")
	}
	if pool.acquire("recent.example") != recent {
		t.Error("closed the connection of a host used within the idle limit")
	}

	pool.closeIdleSince(time.Now())
	if pool.acquire("quiet.example") == quiet {
		t.Error("kept the connection of a host that no request uses")
	}
}
