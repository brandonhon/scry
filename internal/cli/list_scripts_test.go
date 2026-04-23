package cli

import (
	"bytes"
	"context"
	"strings"
	"testing"
)

func TestRootCmd_ListScripts_BundledFour(t *testing.T) {
	var stdout, stderr bytes.Buffer
	cmd := NewRootCmd(&stdout, &stderr)
	cmd.SetArgs([]string{
		"--list-scripts",
		"--script", "../../scripts/http-title.lua",
		"--script", "../../scripts/ssh-banner.lua",
		"--script", "../../scripts/tls-cert-info.lua",
		"--script", "../../scripts/redis-ping.lua",
	})
	cmd.SetContext(context.Background())
	if err := cmd.Execute(); err != nil {
		t.Fatalf("execute: %v\nstderr=%s", err, stderr.String())
	}

	out := stdout.String()
	for _, name := range []string{"http-title", "ssh-banner", "tls-cert-info", "redis-ping"} {
		if !strings.Contains(out, name) {
			t.Errorf("missing %s in:\n%s", name, out)
		}
	}
	if !strings.Contains(out, "ports=22,2222") {
		t.Errorf("ssh-banner ports column wrong:\n%s", out)
	}
}

func TestRootCmd_ListScripts_RequiresScriptFile(t *testing.T) {
	var stdout, stderr bytes.Buffer
	cmd := NewRootCmd(&stdout, &stderr)
	cmd.SetArgs([]string{"--list-scripts"})
	cmd.SetContext(context.Background())
	if err := cmd.Execute(); err == nil {
		t.Fatal("expected error when --list-scripts has no --script")
	}
}
