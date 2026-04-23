//go:build linux || darwin

package cli

import (
	"bytes"
	"strings"
	"testing"

	"golang.org/x/sys/unix"
)

// TestWarnUlimit_AboveLimit triggers the warning by passing a concurrency
// well above the current soft limit.
func TestWarnUlimit_AboveLimit(t *testing.T) {
	var lim unix.Rlimit
	if err := unix.Getrlimit(unix.RLIMIT_NOFILE, &lim); err != nil {
		t.Skipf("getrlimit: %v", err)
	}
	var buf bytes.Buffer
	warnUlimit(&buf, int(lim.Cur)*10)
	if !strings.Contains(buf.String(), "--concurrency") {
		t.Fatalf("expected warning, got %q", buf.String())
	}
}

func TestWarnUlimit_BelowLimit_Silent(t *testing.T) {
	var buf bytes.Buffer
	warnUlimit(&buf, 1)
	if buf.Len() != 0 {
		t.Fatalf("did not expect warning for concurrency=1, got %q", buf.String())
	}
}
