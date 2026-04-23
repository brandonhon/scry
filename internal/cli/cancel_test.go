package cli

import (
	"bytes"
	"context"
	"net"
	"strings"
	"testing"
	"time"
)

// TestRootCmd_SIGINT_FlushesPartialResults verifies that cancelling the
// command context mid-scan still emits output for any host that was
// already probed. The producer must drain its in-flight work into the
// channel, and the consumer must keep draining after ctx is cancelled.
//
// Strategy: point the scan at a mix of one fast, listening loopback port
// and several unreachable hosts on a long timeout, then cancel ctx
// shortly after launch. We expect the listening host to appear even
// though other hosts are still in flight at cancel time.
func TestRootCmd_SIGINT_FlushesPartialResults(t *testing.T) {
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
	_, portStr, _ := net.SplitHostPort(ln.Addr().String())

	var stdout, stderr bytes.Buffer
	cmd := NewRootCmd(&stdout, &stderr)
	cmd.SetArgs([]string{
		// A reachable target followed by several slow ones.
		"127.0.0.1,10.255.255.1,10.255.255.2,10.255.255.3",
		"-p", portStr,
		"-o", "grep",
		"--timeout", "3s",
		"--retries", "0",
		"--no-dns",
		"--max-hosts", "1", // force serial hosts so the cancel lands before the slow ones complete
	})

	ctx, cancel := context.WithCancel(context.Background())
	cmd.SetContext(ctx)

	// Cancel after enough time to finish the loopback but before the slow
	// hosts time out.
	time.AfterFunc(200*time.Millisecond, cancel)

	done := make(chan struct{})
	go func() {
		_ = cmd.Execute()
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("command did not return within 5s of cancel")
	}

	out := stdout.String()
	if !strings.Contains(out, "Host: 127.0.0.1") {
		t.Fatalf("fast host should have been flushed; got %q", out)
	}
}
