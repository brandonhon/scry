package script

import (
	"context"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"
)

// startMultiStepServer prints a greeting, then echoes each line prefixed
// with "ok: ". Closes on blank line. Good exercise of conn:send + conn:read.
func startMultiStepServer(t *testing.T) (uint16, func()) {
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
				_, _ = c.Write([]byte("GREETING\n"))
				buf := make([]byte, 256)
				for {
					_ = c.SetReadDeadline(time.Now().Add(500 * time.Millisecond))
					n, err := c.Read(buf)
					if err != nil || n == 0 {
						return
					}
					line := strings.TrimRight(string(buf[:n]), "\r\n ")
					if line == "" {
						return
					}
					_, _ = c.Write([]byte("ok: " + line + "\n"))
				}
			}(c)
		}
	}()
	return uint16(p), func() { _ = ln.Close(); wg.Wait() }
}

func TestAPI_TCPConnect_MultiStep(t *testing.T) {
	port, stop := startMultiStepServer(t)
	defer stop()

	p := filepath.Join(t.TempDir(), "s.lua")
	if err := os.WriteFile(p, []byte(`
description = "multi-step"
ports = "any"
function run(h, port)
  local c, err = scry.tcp.connect(h, port, {timeout=1000})
  if err then return nil, err end
  local greet, err2 = c:read(64)
  if err2 then c:close(); return nil, err2 end
  local _, err3 = c:send("PING\n")
  if err3 then c:close(); return nil, err3 end
  local reply, err4 = c:read(64)
  if err4 then c:close(); return nil, err4 end
  c:close()
  return greet:gsub("%s+$","") .. "|" .. reply:gsub("%s+$","")
end
`), 0o644); err != nil {
		t.Fatal(err)
	}
	s, err := Load(p)
	if err != nil {
		t.Fatal(err)
	}
	e := NewEngine([]*Script{s}, 3*time.Second)
	f := e.RunAll(context.Background(), "127.0.0.1", port)
	if len(f) != 1 {
		t.Fatalf("got %d findings", len(f))
	}
	if !strings.Contains(f[0].Output, "GREETING") || !strings.Contains(f[0].Output, "ok: PING") {
		t.Fatalf("expected greeting+echo, got %q", f[0].Output)
	}
}

func TestAPI_TCPConnect_ConnectError(t *testing.T) {
	// Bind-then-close → closed port.
	ln, _ := net.Listen("tcp", "127.0.0.1:0")
	_, pStr, _ := net.SplitHostPort(ln.Addr().String())
	p, _ := strconv.Atoi(pStr)
	ln.Close()

	f := runInline(t, `
description = "connect err"
ports = "any"
function run(h, port)
  local c, err = scry.tcp.connect(h, port, {timeout=300})
  if err then return "err:"..err end
  c:close()
  return "ok"
end
`, "127.0.0.1", uint16(p))
	if len(f) != 1 || !strings.HasPrefix(f[0].Output, "err:") {
		t.Fatalf("expected err:…, got %v", f)
	}
}

func TestAPI_TCPConnect_ReadTimeout(t *testing.T) {
	// Silent server: accepts but never writes.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				time.Sleep(5 * time.Second)
				_ = c.Close()
			}(c)
		}
	}()
	_, pStr, _ := net.SplitHostPort(ln.Addr().String())
	p, _ := strconv.Atoi(pStr)

	f := runInline(t, `
description = "read timeout"
ports = "any"
function run(h, port)
  local c, err = scry.tcp.connect(h, port, {timeout=150})
  if err then return nil, err end
  local body, err2 = c:read(64)
  c:close()
  if err2 == "timeout" then return "timed out" end
  return "got:"..(body or "nil")
end
`, "127.0.0.1", uint16(p))
	if len(f) != 1 || f[0].Output != "timed out" {
		t.Fatalf("expected 'timed out', got %v", f)
	}
}
