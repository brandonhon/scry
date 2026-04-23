package script

import (
	"context"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"
)

func writeScript(t *testing.T, body string) string {
	t.Helper()
	dir := t.TempDir()
	p := filepath.Join(dir, "s.lua")
	if err := os.WriteFile(p, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestLoad_ParsesMetadata(t *testing.T) {
	p := writeScript(t, `
description = "demo"
ports = {22, 80, 443}
function run(h, p) return "hi" end
`)
	s, err := Load(p)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if s.Description != "demo" {
		t.Errorf("desc = %q", s.Description)
	}
	if len(s.Ports) != 3 {
		t.Errorf("ports = %v", s.Ports)
	}
	if !s.Matches(80) || s.Matches(81) {
		t.Errorf("Matches wrong")
	}
}

func TestLoad_AnyPort(t *testing.T) {
	p := writeScript(t, `
description = "any"
ports = "any"
function run(h, p) end
`)
	s, err := Load(p)
	if err != nil {
		t.Fatal(err)
	}
	if !s.AnyPort {
		t.Fatal("AnyPort must be true")
	}
	if !s.Matches(1234) {
		t.Fatal("Matches must be true for any-port script")
	}
}

func TestLoad_MissingRun(t *testing.T) {
	p := writeScript(t, `description = "x"` + "\n" + `ports = {22}`)
	if _, err := Load(p); err == nil {
		t.Fatal("expected error for missing run")
	}
}

func TestLoad_InvalidPorts(t *testing.T) {
	p := writeScript(t, `
description = "x"
ports = "some"
function run(h,p) end
`)
	if _, err := Load(p); err == nil {
		t.Fatal("expected error for invalid ports string")
	}
}

func TestRunAll_ReturnsFinding(t *testing.T) {
	p := writeScript(t, `
description = "returns finding"
ports = {80}
function run(host, port) return "hello from " .. host end
`)
	s, err := Load(p)
	if err != nil {
		t.Fatal(err)
	}
	e := NewEngine([]*Script{s}, 2*time.Second)
	findings := e.RunAll(context.Background(), "127.0.0.1", 80)
	if len(findings) != 1 {
		t.Fatalf("got %d findings, want 1", len(findings))
	}
	if findings[0].Output != "hello from 127.0.0.1" {
		t.Errorf("output = %q", findings[0].Output)
	}
}

func TestRunAll_ScriptError(t *testing.T) {
	p := writeScript(t, `
description = "errors"
ports = {80}
function run(h, p) return nil, "bad payload" end
`)
	s, _ := Load(p)
	e := NewEngine([]*Script{s}, 2*time.Second)
	findings := e.RunAll(context.Background(), "127.0.0.1", 80)
	if len(findings) != 1 || !strings.Contains(findings[0].Output, "bad payload") {
		t.Fatalf("expected error finding, got %v", findings)
	}
}

func TestRunAll_PortMismatch(t *testing.T) {
	p := writeScript(t, `
description = "no match"
ports = {80}
function run(h, p) return "should not run" end
`)
	s, _ := Load(p)
	e := NewEngine([]*Script{s}, 2*time.Second)
	findings := e.RunAll(context.Background(), "127.0.0.1", 22)
	if len(findings) != 0 {
		t.Fatalf("expected no findings for wrong port, got %v", findings)
	}
}

func TestAPI_TCPRequest_ReadsBanner(t *testing.T) {
	ln, _ := net.Listen("tcp", "127.0.0.1:0")
	defer ln.Close()
	_, pStr, _ := net.SplitHostPort(ln.Addr().String())
	port, _ := strconv.Atoi(pStr)
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				_, _ = c.Write([]byte("SSH-2.0-Test\r\n"))
				time.Sleep(50 * time.Millisecond)
				_ = c.Close()
			}(c)
		}
	}()

	p := writeScript(t, `
description = "tcp test"
ports = {`+pStr+`}
function run(host, port)
  local body, err = gscan.tcp.request(host, port, "", {timeout=500, max_bytes=64})
  if err then return nil, err end
  return body
end
`)
	s, err := Load(p)
	if err != nil {
		t.Fatal(err)
	}
	e := NewEngine([]*Script{s}, 2*time.Second)
	findings := e.RunAll(context.Background(), "127.0.0.1", uint16(port))
	if len(findings) != 1 {
		t.Fatalf("got %d findings", len(findings))
	}
	if !strings.Contains(findings[0].Output, "SSH-2.0-Test") {
		t.Errorf("banner missing: %q", findings[0].Output)
	}
}

func TestAPI_UtilHex(t *testing.T) {
	p := writeScript(t, `
description = "hex"
ports = "any"
function run(h, p)
  return gscan.util.hex("abc")
end
`)
	s, _ := Load(p)
	e := NewEngine([]*Script{s}, time.Second)
	f := e.RunAll(context.Background(), "x", 1)
	if len(f) != 1 || f[0].Output != "616263" {
		t.Fatalf("unexpected: %v", f)
	}
}
