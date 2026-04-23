package discovery

import (
	"context"
	"net"
	"net/netip"
	"strconv"
	"strings"
	"testing"
	"time"
)

func TestPing_Up_Listening(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer ln.Close()
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			_ = c.Close()
		}
	}()

	_, pStr, _ := net.SplitHostPort(ln.Addr().String())
	p, _ := strconv.Atoi(pStr)

	r := Ping(context.Background(), netip.MustParseAddr("127.0.0.1"),
		Config{Ports: []uint16{uint16(p)}, Timeout: 500 * time.Millisecond})
	if !r.Up {
		t.Fatalf("expected up; got %+v", r)
	}
	if r.Via != "tcp:"+pStr {
		t.Errorf("Via = %q, want tcp:%s", r.Via, pStr)
	}
}

func TestPing_Up_Refused(t *testing.T) {
	ln, _ := net.Listen("tcp", "127.0.0.1:0")
	_, pStr, _ := net.SplitHostPort(ln.Addr().String())
	p, _ := strconv.Atoi(pStr)
	ln.Close() // ensures the port is closed → RST / ECONNREFUSED

	r := Ping(context.Background(), netip.MustParseAddr("127.0.0.1"),
		Config{Ports: []uint16{uint16(p)}, Timeout: 500 * time.Millisecond})
	if !r.Up {
		t.Fatalf("refused port should count as up; got %+v", r)
	}
	if !strings.Contains(r.Via, "/refused") {
		t.Errorf("expected refused marker in Via, got %q", r.Via)
	}
}

func TestPing_Down_UnreachableNetwork(t *testing.T) {
	// 10.255.255.1 on this dev box is unreachable (routing error) and
	// responds quickly — a fine stand-in for "down".
	r := Ping(context.Background(), netip.MustParseAddr("10.255.255.1"),
		Config{Ports: []uint16{1}, Timeout: 300 * time.Millisecond})
	if r.Up {
		t.Fatalf("expected down; got %+v", r)
	}
}

func TestPing_ConcurrentProbes_FirstWins(t *testing.T) {
	// One listening port + four likely-filtered ports → first probe
	// (listener) should return up quickly without waiting for timeouts.
	ln, _ := net.Listen("tcp", "127.0.0.1:0")
	defer ln.Close()
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			_ = c.Close()
		}
	}()
	_, pStr, _ := net.SplitHostPort(ln.Addr().String())
	p, _ := strconv.Atoi(pStr)

	start := time.Now()
	r := Ping(context.Background(), netip.MustParseAddr("127.0.0.1"),
		Config{
			Ports:   []uint16{65531, 65532, uint16(p), 65533, 65534},
			Timeout: 5 * time.Second,
		})
	if !r.Up {
		t.Fatalf("expected up; got %+v", r)
	}
	if d := time.Since(start); d > 2*time.Second {
		t.Fatalf("took %s — concurrent probes should return on first hit", d)
	}
}
