package script

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"
)

// startTLSServer returns (addr, stop) for a TLS-on-TCP listener presenting
// a freshly-minted self-signed certificate for "example.test".
func startTLSServer(t *testing.T, response string) (string, func()) {
	t.Helper()
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "example.test"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		DNSNames:     []string{"example.test", "alt.example.test"},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &priv.PublicKey, priv)
	if err != nil {
		t.Fatal(err)
	}
	cert := tls.Certificate{Certificate: [][]byte{der}, PrivateKey: priv}

	cfg := &tls.Config{Certificates: []tls.Certificate{cert}}
	ln, err := tls.Listen("tcp", "127.0.0.1:0", cfg)
	if err != nil {
		t.Fatal(err)
	}

	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				// Force the server-side TLS handshake. tls.Listen's
				// accept returns a lazy *tls.Conn; if we close before
				// any Read/Write the client sees a bare RST instead of
				// a completed handshake.
				tc := c.(*tls.Conn)
				if err := tc.Handshake(); err != nil {
					_ = c.Close()
					return
				}
				if response != "" {
					_, _ = c.Write([]byte(response))
				}
				time.Sleep(50 * time.Millisecond)
				_ = c.Close()
			}(c)
		}
	}()
	return ln.Addr().String(), func() { _ = ln.Close(); wg.Wait() }
}

func TestAPI_TLSCert(t *testing.T) {
	addr, stop := startTLSServer(t, "")
	defer stop()
	host, portStr, _ := net.SplitHostPort(addr)
	portInt, _ := strconv.Atoi(portStr)

	p := filepath.Join(t.TempDir(), "s.lua")
	if err := os.WriteFile(p, []byte(`
description = "tls.cert"
ports = "any"
function run(h, port)
  local c, err = scry.tls.cert(h, port, {timeout=1500, verify=false})
  if err then return nil, err end
  return "subject=" .. c.subject .. ";sans=" .. table.concat(c.dns_names, ",")
end
`), 0o644); err != nil {
		t.Fatal(err)
	}
	s, err := Load(p)
	if err != nil {
		t.Fatal(err)
	}
	e := NewEngine([]*Script{s}, 3*time.Second)
	f := e.RunAll(context.Background(), host, uint16(portInt))
	if len(f) != 1 {
		t.Fatalf("got %v", f)
	}
	if !strings.Contains(f[0].Output, "CN=example.test") {
		t.Errorf("subject missing: %q", f[0].Output)
	}
	if !strings.Contains(f[0].Output, "alt.example.test") {
		t.Errorf("sans missing: %q", f[0].Output)
	}
}

func TestAPI_TLSRequest(t *testing.T) {
	addr, stop := startTLSServer(t, "HELLO-FROM-TLS\r\n")
	defer stop()
	host, portStr, _ := net.SplitHostPort(addr)
	portInt, _ := strconv.Atoi(portStr)

	p := filepath.Join(t.TempDir(), "s.lua")
	if err := os.WriteFile(p, []byte(`
description = "tls.request"
ports = "any"
function run(h, port)
  local body, err = scry.tls.request(h, port, "", {timeout=1500, verify=false, max_bytes=64})
  if err then return nil, err end
  return body
end
`), 0o644); err != nil {
		t.Fatal(err)
	}
	s, err := Load(p)
	if err != nil {
		t.Fatal(err)
	}
	e := NewEngine([]*Script{s}, 3*time.Second)
	f := e.RunAll(context.Background(), host, uint16(portInt))
	if len(f) != 1 || !strings.Contains(f[0].Output, "HELLO-FROM-TLS") {
		t.Fatalf("unexpected: %v", f)
	}
}

func TestAPI_TLSCert_ConnectError(t *testing.T) {
	// Bind-then-close → guaranteed unreachable.
	ln, _ := net.Listen("tcp", "127.0.0.1:0")
	_, portStr, _ := net.SplitHostPort(ln.Addr().String())
	portInt, _ := strconv.Atoi(portStr)
	ln.Close()

	p := filepath.Join(t.TempDir(), "s.lua")
	if err := os.WriteFile(p, []byte(`
description = "tls.cert err"
ports = "any"
function run(h, port)
  local c, err = scry.tls.cert(h, port, {timeout=200, verify=false})
  if err then return "err:"..err end
  return "cert"
end
`), 0o644); err != nil {
		t.Fatal(err)
	}
	s, _ := Load(p)
	e := NewEngine([]*Script{s}, 3*time.Second)
	f := e.RunAll(context.Background(), "127.0.0.1", uint16(portInt))
	if len(f) != 1 || !strings.HasPrefix(f[0].Output, "err:") {
		t.Fatalf("expected err:… finding, got %v", f)
	}
}
