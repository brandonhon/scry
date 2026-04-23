package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"net"
	"strconv"
	"strings"
	"testing"
)

// listenAndAccept spins up a loopback listener that drains connections
// (used to get a guaranteed-open port in tests).
func listenAndAccept(t *testing.T) (addr string, stop func()) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			_ = c.Close()
		}
	}()
	return ln.Addr().String(), func() { _ = ln.Close() }
}

func TestRootCmd_OpenPortHumanOutput(t *testing.T) {
	a, stop := listenAndAccept(t)
	defer stop()
	_, portStr, _ := net.SplitHostPort(a)

	var stdout, stderr bytes.Buffer
	cmd := NewRootCmd(&stdout, &stderr)
	cmd.SetArgs([]string{"127.0.0.1", "-p", portStr, "--no-color"})
	cmd.SetContext(context.Background())
	if err := cmd.Execute(); err != nil {
		t.Fatalf("execute: %v\nstderr=%s", err, stderr.String())
	}
	out := stdout.String()
	if !strings.Contains(out, "UP") {
		t.Fatalf("missing UP badge in %q", out)
	}
	if !strings.Contains(out, "127.0.0.1") {
		t.Fatalf("missing host in %q", out)
	}
	if !strings.Contains(out, "/tcp") || !strings.Contains(out, "open") {
		t.Fatalf("missing open port line in %q", out)
	}
	if !strings.Contains(out, "scanned 1 host(s), 1 up") {
		t.Fatalf("missing summary in %q", out)
	}
	if strings.Contains(out, "\x1b[") {
		t.Fatalf("--no-color still emitted ANSI: %q", out)
	}
}

func TestRootCmd_JSONOutput(t *testing.T) {
	a, stop := listenAndAccept(t)
	defer stop()
	_, portStr, _ := net.SplitHostPort(a)

	var stdout, stderr bytes.Buffer
	cmd := NewRootCmd(&stdout, &stderr)
	cmd.SetArgs([]string{"127.0.0.1", "-p", portStr, "-o", "json"})
	cmd.SetContext(context.Background())
	if err := cmd.Execute(); err != nil {
		t.Fatalf("execute: %v\nstderr=%s", err, stderr.String())
	}

	// One NDJSON line per host.
	lines := strings.Split(strings.TrimSpace(stdout.String()), "\n")
	if len(lines) != 1 {
		t.Fatalf("got %d lines, want 1; out=%q", len(lines), stdout.String())
	}
	var h struct {
		Addr    string `json:"addr"`
		Up      bool   `json:"up"`
		Results []struct {
			Port  uint16 `json:"port"`
			State string `json:"state"`
		} `json:"results"`
	}
	if err := json.Unmarshal([]byte(lines[0]), &h); err != nil {
		t.Fatalf("unmarshal %q: %v", lines[0], err)
	}
	if h.Addr != "127.0.0.1" || !h.Up || len(h.Results) != 1 || h.Results[0].State != "open" {
		t.Fatalf("unexpected json: %+v", h)
	}
	p, _ := strconv.Atoi(portStr)
	if int(h.Results[0].Port) != p {
		t.Fatalf("port mismatch: got %d want %d", h.Results[0].Port, p)
	}
}

func TestRootCmd_GrepOutput(t *testing.T) {
	a, stop := listenAndAccept(t)
	defer stop()
	_, portStr, _ := net.SplitHostPort(a)

	var stdout, stderr bytes.Buffer
	cmd := NewRootCmd(&stdout, &stderr)
	cmd.SetArgs([]string{"127.0.0.1", "-p", portStr, "-o", "grep", "--no-dns"})
	cmd.SetContext(context.Background())
	if err := cmd.Execute(); err != nil {
		t.Fatalf("execute: %v\nstderr=%s", err, stderr.String())
	}
	line := strings.TrimSpace(stdout.String())
	if !strings.HasPrefix(line, "Host: 127.0.0.1\tStatus: up") {
		t.Fatalf("unexpected grep line: %q", line)
	}
	if !strings.Contains(line, portStr+"/open/") {
		t.Fatalf("missing port/open in %q", line)
	}
}

// Without --no-dns, reverse DNS enrichment is best-effort. Verify the
// grep output tolerates either "127.0.0.1" or "127.0.0.1 (name)".
func TestRootCmd_ReverseDNSRendersInHeader(t *testing.T) {
	a, stop := listenAndAccept(t)
	defer stop()
	_, portStr, _ := net.SplitHostPort(a)

	var stdout, stderr bytes.Buffer
	cmd := NewRootCmd(&stdout, &stderr)
	cmd.SetArgs([]string{"127.0.0.1", "-p", portStr, "-o", "grep"})
	cmd.SetContext(context.Background())
	if err := cmd.Execute(); err != nil {
		t.Fatalf("execute: %v\nstderr=%s", err, stderr.String())
	}
	out := stdout.String()
	if !strings.Contains(out, "127.0.0.1") {
		t.Fatalf("missing addr in %q", out)
	}
}

func TestRootCmd_PingOnlyDiscovery(t *testing.T) {
	// Spin up a listener so 127.0.0.1 has at least one reachable port,
	// though discovery also considers RSTs as up.
	_, stop := listenAndAccept(t)
	defer stop()

	var stdout, stderr bytes.Buffer
	cmd := NewRootCmd(&stdout, &stderr)
	cmd.SetArgs([]string{"127.0.0.1", "--sn", "-o", "grep", "--no-dns", "--timeout", "500ms"})
	cmd.SetContext(context.Background())
	if err := cmd.Execute(); err != nil {
		t.Fatalf("execute: %v\nstderr=%s", err, stderr.String())
	}
	out := stdout.String()
	if !strings.Contains(out, "Host: 127.0.0.1\tStatus: up") {
		t.Fatalf("expected up status from -sn discovery; got %q", out)
	}
}

func TestRootCmd_PingOnly_RejectsPorts(t *testing.T) {
	var stdout, stderr bytes.Buffer
	cmd := NewRootCmd(&stdout, &stderr)
	cmd.SetArgs([]string{"127.0.0.1", "--sn", "-p", "22"})
	cmd.SetContext(context.Background())
	if err := cmd.Execute(); err == nil {
		t.Fatal("expected error for -sn with -p")
	}
}

func TestRootCmd_MissingPortsFlagUnlessPingOnly(t *testing.T) {
	var stdout, stderr bytes.Buffer
	cmd := NewRootCmd(&stdout, &stderr)
	cmd.SetArgs([]string{"127.0.0.1"})
	cmd.SetContext(context.Background())
	if err := cmd.Execute(); err == nil {
		t.Fatal("expected error when --ports missing and not --ping-only")
	}
}

func TestRootCmd_InvalidOutputFormat(t *testing.T) {
	var stdout, stderr bytes.Buffer
	cmd := NewRootCmd(&stdout, &stderr)
	cmd.SetArgs([]string{"127.0.0.1", "-p", "22", "-o", "xml"})
	cmd.SetContext(context.Background())
	if err := cmd.Execute(); err == nil {
		t.Fatal("expected error for unknown output format")
	}
}

func TestRootCmd_UpFlagSuppressesDownHosts(t *testing.T) {
	ln, _ := net.Listen("tcp", "127.0.0.1:0")
	_, portStr, _ := net.SplitHostPort(ln.Addr().String())
	ln.Close()

	var stdout, stderr bytes.Buffer
	cmd := NewRootCmd(&stdout, &stderr)
	cmd.SetArgs([]string{"127.0.0.1", "-p", portStr, "--up", "--timeout", "300ms", "-o", "grep"})
	cmd.SetContext(context.Background())
	if err := cmd.Execute(); err != nil {
		t.Fatalf("execute: %v\nstderr=%s", err, stderr.String())
	}
	if stdout.Len() != 0 {
		t.Fatalf("--up should hide down host, got %q", stdout.String())
	}
}

func TestRootCmd_DownFlagSuppressesUpHosts(t *testing.T) {
	a, stop := listenAndAccept(t)
	defer stop()
	_, portStr, _ := net.SplitHostPort(a)

	var stdout, stderr bytes.Buffer
	cmd := NewRootCmd(&stdout, &stderr)
	cmd.SetArgs([]string{"127.0.0.1", "-p", portStr, "--down", "-o", "grep"})
	cmd.SetContext(context.Background())
	if err := cmd.Execute(); err != nil {
		t.Fatalf("execute: %v", err)
	}
	if stdout.Len() != 0 {
		t.Fatalf("--down should hide up host, got %q", stdout.String())
	}
}

func TestRootCmd_UpDownMutex(t *testing.T) {
	var stdout, stderr bytes.Buffer
	cmd := NewRootCmd(&stdout, &stderr)
	cmd.SetArgs([]string{"127.0.0.1", "-p", "22", "--up", "--down"})
	cmd.SetContext(context.Background())
	if err := cmd.Execute(); err == nil {
		t.Fatal("expected error for --up + --down")
	}
}

func TestRootCmd_BadPortSpec(t *testing.T) {
	var stdout, stderr bytes.Buffer
	cmd := NewRootCmd(&stdout, &stderr)
	cmd.SetArgs([]string{"127.0.0.1", "-p", "not-a-port"})
	cmd.SetContext(context.Background())
	if err := cmd.Execute(); err == nil {
		t.Fatal("expected error for invalid -p")
	}
}

func TestRootCmd_BadTarget(t *testing.T) {
	var stdout, stderr bytes.Buffer
	cmd := NewRootCmd(&stdout, &stderr)
	cmd.SetArgs([]string{"999.999.999.999", "-p", "22"})
	cmd.SetContext(context.Background())
	if err := cmd.Execute(); err == nil {
		t.Fatal("expected error for invalid target")
	}
}

