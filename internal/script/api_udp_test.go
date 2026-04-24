package script

import (
	"net"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"
)

// startUDPEcho binds a UDP socket and echoes datagrams with "ok: " prefix.
func startUDPEcho(t *testing.T) (uint16, func()) {
	t.Helper()
	addr, err := net.ResolveUDPAddr("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	conn, err := net.ListenUDP("udp", addr)
	if err != nil {
		t.Fatal(err)
	}
	port := uint16(conn.LocalAddr().(*net.UDPAddr).Port)

	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		buf := make([]byte, 1500)
		for {
			_ = conn.SetReadDeadline(time.Now().Add(5 * time.Second))
			n, peer, err := conn.ReadFromUDP(buf)
			if err != nil {
				return
			}
			_, _ = conn.WriteToUDP([]byte("ok: "+string(buf[:n])), peer)
		}
	}()
	return port, func() { _ = conn.Close(); wg.Wait() }
}

func TestAPI_UDPSend_Echo(t *testing.T) {
	port, stop := startUDPEcho(t)
	defer stop()

	f := runInline(t, `
description = "udp.send"
ports = "any"
function run(h, p)
  local body, err = scry.udp.send(h, p, "HI", {timeout=500})
  if err then return nil, err end
  return body
end
`, "127.0.0.1", port)
	if len(f) != 1 || !strings.Contains(f[0].Output, "ok: HI") {
		t.Fatalf("expected echo, got %v", f)
	}
}

func TestAPI_UDPSend_FireAndForget(t *testing.T) {
	port, stop := startUDPEcho(t)
	defer stop()

	f := runInline(t, `
description = "udp fire-and-forget"
ports = "any"
function run(h, p)
  local body, err = scry.udp.send(h, p, "ignored", {timeout=200, expect_reply=false})
  if err then return "err:"..err end
  return "sent:"..tostring(#body)
end
`, "127.0.0.1", port)
	if len(f) != 1 || f[0].Output != "sent:0" {
		t.Fatalf("expected sent:0, got %v", f)
	}
}

func TestAPI_UDPSend_ReadTimeout(t *testing.T) {
	// Bind a UDP socket that never replies.
	conn, _ := net.ListenUDP("udp", &net.UDPAddr{IP: net.ParseIP("127.0.0.1")})
	defer conn.Close()
	port := uint16(conn.LocalAddr().(*net.UDPAddr).Port)

	f := runInline(t, `
description = "udp timeout"
ports = "any"
function run(h, p)
  local body, err = scry.udp.send(h, p, "no-reply", {timeout=150})
  if err == "timeout" then return "timed out" end
  return "got:"..(body or "nil")
end
`, "127.0.0.1", port)
	if len(f) != 1 || f[0].Output != "timed out" {
		t.Fatalf("expected timed out, got %v", f)
	}
	_ = strconv.Itoa // satisfy import when tests are stripped
}
