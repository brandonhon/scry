package script

import (
	"net"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"
)

// startNSETestServer is a tiny TCP server that greets with "HELLO" and
// echoes each subsequent write prefixed with "ok ".
func startNSETestServer(t *testing.T) (uint16, func()) {
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
				_, _ = c.Write([]byte("HELLO"))
				buf := make([]byte, 128)
				_ = c.SetReadDeadline(time.Now().Add(500 * time.Millisecond))
				n, err := c.Read(buf)
				if err == nil && n > 0 {
					_, _ = c.Write(append([]byte("ok "), buf[:n]...))
				}
				time.Sleep(30 * time.Millisecond)
			}(c)
		}
	}()
	return uint16(p), func() { _ = ln.Close(); wg.Wait() }
}

// TestNSEShim_RoundTrip verifies the standard NSE socket idiom works.
func TestNSEShim_RoundTrip(t *testing.T) {
	port, stop := startNSETestServer(t)
	defer stop()

	f := runInline(t, `
description = "nse shim"
ports = "any"
function run(h, p)
  local s = nmap.new_socket()
  s:set_timeout(1000)
  local ok, err = s:connect(h, p)
  if not ok then return nil, err end
  local greet, rerr = s:receive_bytes(64)
  if not greet then s:close(); return nil, rerr end
  local _, serr = s:send("PING")
  if serr then s:close(); return nil, serr end
  local reply, rerr2 = s:receive_bytes(64)
  s:close()
  if not reply then return nil, rerr2 end
  return greet .. "|" .. reply
end
`, "127.0.0.1", port)
	if len(f) != 1 {
		t.Fatalf("got %d findings", len(f))
	}
	if !strings.Contains(f[0].Output, "HELLO") || !strings.Contains(f[0].Output, "ok PING") {
		t.Fatalf("unexpected output: %q", f[0].Output)
	}
}

func TestNSEShim_GetScriptArgsReturnsNil(t *testing.T) {
	f := runInline(t, `
description = "stdnse args"
ports = "any"
function run(h, p)
  local v = stdnse.get_script_args("anything")
  if v == nil then return "nil" end
  return "non-nil:"..tostring(v)
end
`, "x", 1)
	if len(f) != 1 || f[0].Output != "nil" {
		t.Fatalf("expected 'nil', got %v", f)
	}
}

func TestNSEShim_PrintDebugRuns(t *testing.T) {
	f := runInline(t, `
description = "stdnse debug"
ports = "any"
function run(h, p)
  stdnse.print_debug(1, "level-debug message")
  stdnse.debug("alias message")
  return "ok"
end
`, "x", 1)
	if len(f) != 1 || f[0].Output != "ok" {
		t.Fatalf("unexpected: %v", f)
	}
}
