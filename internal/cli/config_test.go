package cli

import (
	"bytes"
	"context"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func writeCfg(t *testing.T, body string) string {
	t.Helper()
	dir := t.TempDir()
	p := filepath.Join(dir, "c.yaml")
	if err := os.WriteFile(p, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestConfig_FileProvidesDefaults(t *testing.T) {
	a, stop := listenAndAccept(t)
	defer stop()
	_, portStr, _ := net.SplitHostPort(a)

	// Config supplies --ports + --no-dns so we don't have to on the CLI.
	cfg := writeCfg(t, "ports: "+portStr+"\nno-dns: true\n")

	var stdout, stderr bytes.Buffer
	cmd := NewRootCmd(&stdout, &stderr)
	cmd.SetArgs([]string{"127.0.0.1", "--config", cfg, "-o", "grep"})
	cmd.SetContext(context.Background())
	if err := cmd.Execute(); err != nil {
		t.Fatalf("execute: %v\nstderr=%s", err, stderr.String())
	}
	if !strings.Contains(stdout.String(), portStr+"/open/") {
		t.Fatalf("expected open-port grep line from config-supplied ports; out=%q", stdout.String())
	}
}

func TestConfig_FlagOverridesConfig(t *testing.T) {
	a, stop := listenAndAccept(t)
	defer stop()
	_, portStr, _ := net.SplitHostPort(a)

	// Config says ports: 1 (closed), CLI says ports=<listening>.
	cfg := writeCfg(t, "ports: 1\nno-dns: true\n")

	var stdout, stderr bytes.Buffer
	cmd := NewRootCmd(&stdout, &stderr)
	cmd.SetArgs([]string{"127.0.0.1", "--config", cfg, "-p", portStr, "-o", "grep"})
	cmd.SetContext(context.Background())
	if err := cmd.Execute(); err != nil {
		t.Fatalf("execute: %v", err)
	}
	if !strings.Contains(stdout.String(), portStr+"/open/") {
		t.Fatalf("CLI flag should have overridden config; out=%q", stdout.String())
	}
}

func TestConfig_ExplicitPath_NotFound(t *testing.T) {
	var stdout, stderr bytes.Buffer
	cmd := NewRootCmd(&stdout, &stderr)
	cmd.SetArgs([]string{"127.0.0.1", "--config", "/no/such/file.yaml", "-p", "22"})
	cmd.SetContext(context.Background())
	if err := cmd.Execute(); err == nil {
		t.Fatal("expected error when --config file is missing")
	}
}

func TestConfig_StringSlice_ExcludeList(t *testing.T) {
	a, stop := listenAndAccept(t)
	defer stop()
	_, portStr, _ := net.SplitHostPort(a)

	cfg := writeCfg(t, `
ports: `+portStr+`
no-dns: true
exclude:
  - 10.0.0.1
  - 10.0.0.2/32
`)
	var stdout, stderr bytes.Buffer
	cmd := NewRootCmd(&stdout, &stderr)
	cmd.SetArgs([]string{"127.0.0.1", "--config", cfg, "-o", "grep"})
	cmd.SetContext(context.Background())
	if err := cmd.Execute(); err != nil {
		t.Fatalf("execute: %v\nstderr=%s", err, stderr.String())
	}
	if !strings.Contains(stdout.String(), "127.0.0.1") {
		t.Fatalf("expected scan to run; out=%q", stdout.String())
	}
}
