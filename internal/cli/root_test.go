package cli

import (
	"bytes"
	"context"
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

func TestRootCmd_OpenPortIsReported(t *testing.T) {
	a, stop := listenAndAccept(t)
	defer stop()
	_, portStr, _ := net.SplitHostPort(a)

	var stdout, stderr bytes.Buffer
	cmd := NewRootCmd(&stdout, &stderr)
	cmd.SetArgs([]string{"127.0.0.1", "-p", portStr})
	cmd.SetContext(context.Background())

	if err := cmd.Execute(); err != nil {
		t.Fatalf("execute: %v\nstderr=%s", err, stderr.String())
	}
	out := stdout.String()
	if !strings.Contains(out, "127.0.0.1\tup\t") {
		t.Fatalf("missing up header in %q", out)
	}
	if !strings.Contains(out, "/tcp\topen\t") {
		t.Fatalf("missing open port line in %q", out)
	}
	// Host elapsed should be formatted after the up token.
}

func TestRootCmd_UpFlagSuppressesDownHosts(t *testing.T) {
	// Pick a closed port on loopback.
	ln, _ := net.Listen("tcp", "127.0.0.1:0")
	_, portStr, _ := net.SplitHostPort(ln.Addr().String())
	ln.Close()

	var stdout, stderr bytes.Buffer
	cmd := NewRootCmd(&stdout, &stderr)
	cmd.SetArgs([]string{"127.0.0.1", "-p", portStr, "--up", "--timeout", "300ms"})
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
	cmd.SetArgs([]string{"127.0.0.1", "-p", portStr, "--down"})
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

func TestRootCmd_PortList(t *testing.T) {
	a, stop := listenAndAccept(t)
	defer stop()
	_, openStr, _ := net.SplitHostPort(a)
	openPort, _ := strconv.Atoi(openStr)

	// An almost-certainly-closed port on loopback.
	closedPort := 1
	if closedPort == openPort {
		closedPort = 2
	}

	var stdout, stderr bytes.Buffer
	cmd := NewRootCmd(&stdout, &stderr)
	cmd.SetArgs([]string{
		"127.0.0.1",
		"-p", strconv.Itoa(closedPort) + "," + openStr,
		"--timeout", "400ms",
		"-v",
	})
	cmd.SetContext(context.Background())
	if err := cmd.Execute(); err != nil {
		t.Fatalf("execute: %v\nstderr=%s", err, stderr.String())
	}
	out := stdout.String()
	if !strings.Contains(out, "/tcp\topen\t") {
		t.Fatalf("expected open line; out=%q", out)
	}
	// -v should reveal the closed/filtered line too.
	if !(strings.Contains(out, "\tclosed\t") || strings.Contains(out, "\tfiltered\t")) {
		t.Fatalf("expected closed/filtered line with -v; out=%q", out)
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

func TestRootCmd_MissingPortsFlag(t *testing.T) {
	var stdout, stderr bytes.Buffer
	cmd := NewRootCmd(&stdout, &stderr)
	cmd.SetArgs([]string{"127.0.0.1"})
	cmd.SetContext(context.Background())
	if err := cmd.Execute(); err == nil {
		t.Fatal("expected error when --ports missing")
	}
}
