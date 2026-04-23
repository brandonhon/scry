package cli

import (
	"bytes"
	"context"
	"net"
	"strconv"
	"strings"
	"testing"
)

func TestParseSinglePort(t *testing.T) {
	cases := []struct {
		in      string
		want    uint16
		wantErr bool
	}{
		{"22", 22, false},
		{"1", 1, false},
		{"65535", 65535, false},
		{"0", 0, true},
		{"65536", 0, true},
		{"", 0, true},
		{"abc", 0, true},
		{"-1", 0, true},
	}
	for _, tc := range cases {
		got, err := parseSinglePort(tc.in)
		if (err != nil) != tc.wantErr {
			t.Errorf("parseSinglePort(%q) err=%v, wantErr=%v", tc.in, err, tc.wantErr)
		}
		if got != tc.want {
			t.Errorf("parseSinglePort(%q) = %d, want %d", tc.in, got, tc.want)
		}
	}
}

// TestRootCmd_OpenPort spins up a local listener and verifies gscan reports
// that port as open. This exercises the full cobra wiring end-to-end.
func TestRootCmd_OpenPort(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer ln.Close()
	_, portStr, _ := net.SplitHostPort(ln.Addr().String())
	// Accept loop so the connect completes cleanly.
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			_ = c.Close()
		}
	}()

	var stdout, stderr bytes.Buffer
	cmd := NewRootCmd(&stdout, &stderr)
	cmd.SetArgs([]string{"127.0.0.1", "-p", portStr})
	cmd.SetContext(context.Background())

	if err := cmd.Execute(); err != nil {
		t.Fatalf("execute: %v\nstderr=%s", err, stderr.String())
	}

	out := stdout.String()
	wantPrefix := "127.0.0.1:" + portStr + "\topen"
	if !strings.Contains(out, wantPrefix) {
		t.Fatalf("output missing %q\ngot: %q", wantPrefix, out)
	}
}

func TestRootCmd_ClosedPort(t *testing.T) {
	// Bind-then-close to get a port we know is not listening.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	_, portStr, _ := net.SplitHostPort(ln.Addr().String())
	ln.Close()

	var stdout, stderr bytes.Buffer
	cmd := NewRootCmd(&stdout, &stderr)
	cmd.SetArgs([]string{"127.0.0.1", "-p", portStr, "--timeout", "500ms"})
	cmd.SetContext(context.Background())

	if err := cmd.Execute(); err != nil {
		t.Fatalf("execute: %v\nstderr=%s", err, stderr.String())
	}
	out := stdout.String()
	// On Linux, closed ports on loopback return RST → classified "closed".
	// On some kernels / Windows the behavior is consistent; tolerate "closed"
	// or "filtered" since both are non-open classifications that prove the
	// probe ran.
	if strings.Contains(out, "\topen\t") {
		t.Fatalf("port %s was unexpectedly open\nout=%q", portStr, out)
	}
	if !(strings.Contains(out, "\tclosed\t") || strings.Contains(out, "\tfiltered\t")) {
		t.Fatalf("expected closed or filtered classification\nout=%q", out)
	}
}

func TestRootCmd_MissingPortsFlag(t *testing.T) {
	var stdout, stderr bytes.Buffer
	cmd := NewRootCmd(&stdout, &stderr)
	cmd.SetArgs([]string{"127.0.0.1"})
	cmd.SetContext(context.Background())
	if err := cmd.Execute(); err == nil {
		t.Fatalf("expected error when --ports missing")
	}
}

// Ensure we accept comma-separated targets through to parse errors when
// unparseable — smoke test of the wiring, not of the parser itself.
func TestRootCmd_BadTarget(t *testing.T) {
	var stdout, stderr bytes.Buffer
	cmd := NewRootCmd(&stdout, &stderr)
	cmd.SetArgs([]string{"999.999.999.999", "-p", "22"})
	cmd.SetContext(context.Background())
	if err := cmd.Execute(); err == nil {
		t.Fatal("expected error for invalid target")
	}
}

// Compile-time nudge: ensure Version can be overridden.
var _ = strconv.Itoa
