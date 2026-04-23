//go:build !rawsock

package cli

import (
	"bytes"
	"context"
	"strings"
	"testing"
)

// TestRootCmd_SYN_UnavailableOnDefaultBuild ensures --syn produces a
// clean, actionable error on the default (non-rawsock) build instead of
// panicking or silently falling back.
func TestRootCmd_SYN_UnavailableOnDefaultBuild(t *testing.T) {
	var stdout, stderr bytes.Buffer
	cmd := NewRootCmd(&stdout, &stderr)
	cmd.SetArgs([]string{"127.0.0.1", "-p", "22", "--syn"})
	cmd.SetContext(context.Background())

	err := cmd.Execute()
	if err == nil {
		t.Fatal("expected error from --syn on default build")
	}
	if !strings.Contains(err.Error(), "rawsock") {
		t.Fatalf("error should mention `rawsock`; got %q", err)
	}
}
