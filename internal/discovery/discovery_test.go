package discovery

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"strconv"
	"syscall"
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

// TestClassifyDialErr locks in the refused/unreachable/timeout
// classification without depending on real kernel TCP semantics.
// The previous TestPing_Up_Refused relied on net.Listen("tcp",
// "127.0.0.1:0") + Close producing ECONNREFUSED on dial, which is
// timing-dependent on GitHub Actions runners (TIME_WAIT, port
// reuse, kernel config) and was flaky across linux/windows CI.
func TestClassifyDialErr(t *testing.T) {
	cases := []struct {
		name    string
		err     error
		wantUp  bool
		wantVia string
	}{
		{"nil", nil, false, ""},
		{"timeout", &net.OpError{Op: "dial", Err: &timeoutErr{}}, false, ""},
		{"network unreachable", &net.OpError{Op: "dial", Err: syscall.ENETUNREACH}, false, ""},
		{"host unreachable", &net.OpError{Op: "dial", Err: syscall.EHOSTUNREACH}, false, ""},
		{"refused", &net.OpError{Op: "dial", Err: syscall.ECONNREFUSED}, true, "tcp:22/refused"},
		{"connection reset", &net.OpError{Op: "dial", Err: syscall.ECONNRESET}, true, "tcp:22"},
		{"unclassified — Windows WSA variant", errors.New("connectex: unknown Windows error"), true, "tcp:22"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			up, via := classifyDialErr(tc.err, 22)
			if up != tc.wantUp {
				t.Fatalf("up = %v, want %v", up, tc.wantUp)
			}
			if via != tc.wantVia {
				t.Fatalf("via = %q, want %q", via, tc.wantVia)
			}
		})
	}
}

// timeoutErr is a minimal net.Error-satisfying timeout stub for the
// classifier test.
type timeoutErr struct{}

func (timeoutErr) Error() string   { return "i/o timeout" }
func (timeoutErr) Timeout() bool   { return true }
func (timeoutErr) Temporary() bool { return true }

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
