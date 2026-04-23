package banner

import (
	"context"
	"net"
	"net/netip"
	"strconv"
	"testing"
	"time"
)

func startListener(t *testing.T, greeting string) (uint16, func()) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	_, pStr, _ := net.SplitHostPort(ln.Addr().String())
	p, _ := strconv.Atoi(pStr)

	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				if greeting != "" {
					_, _ = c.Write([]byte(greeting))
				}
				time.Sleep(50 * time.Millisecond)
				_ = c.Close()
			}(c)
		}
	}()
	return uint16(p), func() { _ = ln.Close() }
}

func TestGrab_ReadsBanner(t *testing.T) {
	port, stop := startListener(t, "SSH-2.0-OpenSSH_8.4\r\n")
	defer stop()

	s, err := Grab(context.Background(), netip.MustParseAddr("127.0.0.1"), port, 500*time.Millisecond, 0)
	if err != nil {
		t.Fatalf("Grab: %v", err)
	}
	if s != "SSH-2.0-OpenSSH_8.4" {
		t.Fatalf("got %q, want %q", s, "SSH-2.0-OpenSSH_8.4")
	}
}

func TestGrab_QuietService_ReturnsEmpty(t *testing.T) {
	port, stop := startListener(t, "") // never writes
	defer stop()

	s, err := Grab(context.Background(), netip.MustParseAddr("127.0.0.1"), port, 200*time.Millisecond, 0)
	if err != nil {
		t.Fatalf("Grab: %v", err)
	}
	if s != "" {
		t.Fatalf("expected empty, got %q", s)
	}
}

func TestGrab_StripsControlChars(t *testing.T) {
	port, stop := startListener(t, "hello\x00\x01world\r\n")
	defer stop()

	s, err := Grab(context.Background(), netip.MustParseAddr("127.0.0.1"), port, 500*time.Millisecond, 0)
	if err != nil {
		t.Fatal(err)
	}
	if s != "helloworld" {
		t.Fatalf("got %q, want %q", s, "helloworld")
	}
}

func TestGrab_ConnectError(t *testing.T) {
	// Bind-then-close: guaranteed unavailable port.
	ln, _ := net.Listen("tcp", "127.0.0.1:0")
	_, pStr, _ := net.SplitHostPort(ln.Addr().String())
	p, _ := strconv.Atoi(pStr)
	ln.Close()

	_, err := Grab(context.Background(), netip.MustParseAddr("127.0.0.1"), uint16(p), 200*time.Millisecond, 0)
	if err == nil {
		t.Fatal("expected dial error")
	}
}
