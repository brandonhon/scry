package script

import (
	"context"
	"net"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"
)

// startFakeSMB2 accepts a connection, reads the SMB1 Negotiate, and
// responds with an SMB2 header signalling "SMB1 rejected". Good enough
// to exercise the smb-version.lua parser path without a real SMB stack.
func startFakeSMB2(t *testing.T) (uint16, func()) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	_, pStr, _ := net.SplitHostPort(ln.Addr().String())
	p, _ := strconv.Atoi(pStr)

	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				_ = c.SetReadDeadline(time.Now().Add(2 * time.Second))
				buf := make([]byte, 256)
				_, _ = c.Read(buf) // discard the negotiate request
				// NetBIOS length prefix 0x00000040, then SMB2 magic.
				reply := []byte{0x00, 0x00, 0x00, 0x40, 0xfe, 'S', 'M', 'B'}
				for len(reply) < 64 {
					reply = append(reply, 0x00)
				}
				_, _ = c.Write(reply)
			}(c)
		}
	}()
	return uint16(p), func() { _ = ln.Close(); wg.Wait() }
}

func TestBundled_SMBVersion_DetectsSMB2(t *testing.T) {
	port, stop := startFakeSMB2(t)
	defer stop()

	s, err := Load("../../scripts/smb-version.lua")
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	// Script's ports table is {139,445}; override by running RunAll with
	// a port it matches via AnyPort? It doesn't match random ports. For
	// the test, call runOne directly bypassing Matches.
	e := NewEngine([]*Script{s}, 3*time.Second)
	out, err := e.runOne(context.Background(), s, "127.0.0.1", port)
	if err != nil {
		t.Fatalf("runOne: %v", err)
	}
	if !strings.Contains(out, "smb2") {
		t.Fatalf("expected smb2 detection, got %q", out)
	}
}
