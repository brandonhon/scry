package script

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func runInline(t *testing.T, body string, host string, port uint16) []Finding {
	t.Helper()
	p := filepath.Join(t.TempDir(), "s.lua")
	if err := os.WriteFile(p, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	s, err := Load(p)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	e := NewEngine([]*Script{s}, 3*time.Second)
	return e.RunAll(context.Background(), host, port)
}

func TestAPI_UtilUnhex(t *testing.T) {
	f := runInline(t, `
description = "unhex"
ports = "any"
function run(h, p)
  local b, err = scry.util.unhex("48656c6c6f")
  if err then return nil, err end
  return b
end`, "x", 1)
	if len(f) != 1 || f[0].Output != "Hello" {
		t.Fatalf("unhex: %v", f)
	}
}

func TestAPI_UtilUnhex_BadInput(t *testing.T) {
	f := runInline(t, `
description = "unhex err"
ports = "any"
function run(h, p)
  local b, err = scry.util.unhex("zz")
  if err then return "err:"..err end
  return "ok"
end`, "x", 1)
	if len(f) != 1 || !strings.HasPrefix(f[0].Output, "err:") {
		t.Fatalf("expected err:…, got %v", f)
	}
}

func TestAPI_LogCallbacks_DoNotError(t *testing.T) {
	// log.* returns 0 values; scripts can call them unconditionally.
	f := runInline(t, `
description = "log"
ports = "any"
function run(h, p)
  scry.log.info("an info message")
  scry.log.warn("a warn message")
  scry.log.error("an err message")
  return "logged"
end`, "x", 1)
	if len(f) != 1 || f[0].Output != "logged" {
		t.Fatalf("log run wrong: %v", f)
	}
}

// DNS tests hit real resolvers by default. Both calls must at minimum
// return a Lua-level result without panicking. We don't assert specific
// names to avoid flakiness on CI hosts with restricted DNS.
func TestAPI_DNSReverse_Runs(t *testing.T) {
	f := runInline(t, `
description = "dns.reverse"
ports = "any"
function run(h, p)
  local name, err = scry.dns.reverse("127.0.0.1")
  if err then return "err" end
  if name == nil then return "nil" end
  return "ok"
end`, "x", 1)
	if len(f) != 1 {
		t.Fatalf("got %d findings", len(f))
	}
	if f[0].Output != "ok" && f[0].Output != "err" && f[0].Output != "nil" {
		t.Fatalf("unexpected: %v", f)
	}
}

func TestAPI_DNSLookup_Runs(t *testing.T) {
	f := runInline(t, `
description = "dns.lookup"
ports = "any"
function run(h, p)
  local ips, err = scry.dns.lookup("localhost")
  if err then return "err" end
  if ips == nil or #ips == 0 then return "empty" end
  return "ok"
end`, "x", 1)
	if len(f) != 1 {
		t.Fatalf("got %d findings", len(f))
	}
}

// Ensure Load rejects scripts whose `ports` is neither a table nor the
// string "any".
func TestLoad_WrongPortsType(t *testing.T) {
	p := filepath.Join(t.TempDir(), "s.lua")
	if err := os.WriteFile(p, []byte(`
description = "bad ports"
ports = 22
function run(h, p) end
`), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(p); err == nil {
		t.Fatal("expected Load error when ports is a number")
	}
}

// Ensure Load rejects a script that fails to compile.
func TestLoad_SyntaxError(t *testing.T) {
	p := filepath.Join(t.TempDir(), "s.lua")
	if err := os.WriteFile(p, []byte(`
description = "bad"
ports = {22}
function run(h, p)  -- missing end
`), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(p); err == nil {
		t.Fatal("expected compile error")
	}
}

// Ensure Load rejects a missing file.
func TestLoad_MissingFile(t *testing.T) {
	if _, err := Load("/no/such/file.lua"); err == nil {
		t.Fatal("expected error for missing file")
	}
}
