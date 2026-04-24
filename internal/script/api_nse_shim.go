package script

import (
	"errors"
	"io"
	"net"
	"strconv"
	"time"

	lua "github.com/yuin/gopher-lua"
)

// registerNSEShim installs minimal `nmap.*` and `stdnse.*` modules so
// NSE scripts that only touch the most-common helpers can run under
// scry with minimal edits. This is **not** a full NSE runtime — see
// scry-plan.md §10 #3 and the compatibility matrix below. We cover the
// helpers that appear in a majority of the bundled NSE scripts we
// surveyed.
//
// Compatibility matrix:
//
//	Tier-1 (provided):
//	  nmap.new_socket()              socket ~ scry.tcp.connect
//	    sock:connect(host, port)     ~ conn = tcp.connect(...)
//	    sock:send(bytes)
//	    sock:receive_bytes(n)        ~ conn:read(n)
//	    sock:close()
//	    sock:set_timeout(ms)
//	  stdnse.get_script_args(k)      returns nil (no --script-args yet)
//	  stdnse.print_debug / .debug    → scry.log.info
//
//	Tier-2 (not provided; scripts will fail with a clear Lua error):
//	  shortport.* — port/service matching. scry's `ports` metadata
//	    expresses the common case; richer predicates are deferred.
//	  creds.* / brute.* — credentials/brute framework.
//	  Any script that imports `http`, `vulns`, `smb`, etc.
func registerNSEShim(L *lua.LState) {
	registerNSESocketMeta(L)
	L.SetGlobal("nmap", buildNmapTable(L))
	L.SetGlobal("stdnse", buildStdnseTable(L))
}

func buildNmapTable(L *lua.LState) *lua.LTable {
	t := L.NewTable()
	L.SetField(t, "new_socket", L.NewFunction(nmapNewSocket))
	return t
}

const nseSocketMeta = "scry.nse.socket"

// nseSocket wraps net.Conn directly. The NSE methods talk to it via
// Go, not by re-entering Lua, to keep the stack shallow and the error
// model predictable.
type nseSocket struct {
	conn    net.Conn
	timeout time.Duration
}

func registerNSESocketMeta(L *lua.LState) {
	mt := L.NewTypeMetatable(nseSocketMeta)
	L.SetField(mt, "__index", L.SetFuncs(L.NewTable(), map[string]lua.LGFunction{
		"connect":       nseSockConnect,
		"send":          nseSockSend,
		"receive_bytes": nseSockReceiveBytes,
		"receive":       nseSockReceiveBytes, // alias some NSE scripts use
		"close":         nseSockClose,
		"set_timeout":   nseSockSetTimeout,
	}))
	// __gc closes the underlying net.Conn if the NSE script drops the
	// socket without calling close(). Idempotent via nseSockClose's
	// nil-check.
	L.SetField(mt, "__gc", L.NewFunction(nseSockGC))
}

func nseSockGC(L *lua.LState) int {
	ud := L.CheckUserData(1)
	s, ok := ud.Value.(*nseSocket)
	if !ok || s == nil || s.conn == nil {
		return 0
	}
	_ = s.conn.Close()
	s.conn = nil
	return 0
}

func nmapNewSocket(L *lua.LState) int {
	ud := L.NewUserData()
	ud.Value = &nseSocket{timeout: time.Duration(defaultAPITimeoutMS) * time.Millisecond}
	L.SetMetatable(ud, L.GetTypeMetatable(nseSocketMeta))
	L.Push(ud)
	return 1
}

func checkNSESock(L *lua.LState, idx int) *nseSocket {
	ud := L.CheckUserData(idx)
	s, ok := ud.Value.(*nseSocket)
	if !ok {
		L.ArgError(idx, "nse socket expected")
	}
	return s
}

// sock:connect(host, port) -> (true, nil) | (nil, errstr). NSE's
// protocol argument is accepted but ignored (scry only supports TCP
// for scripts today).
func nseSockConnect(L *lua.LState) int {
	s := checkNSESock(L, 1)
	host := L.CheckString(2)
	port := L.CheckInt(3)

	d := net.Dialer{Timeout: s.timeout, KeepAlive: -1}
	c, err := d.DialContext(L.Context(), "tcp", net.JoinHostPort(host, strconv.Itoa(port)))
	if err != nil {
		L.Push(lua.LNil)
		L.Push(lua.LString(err.Error()))
		return 2
	}
	s.conn = c
	L.Push(lua.LTrue)
	L.Push(lua.LNil)
	return 2
}

func nseSockSend(L *lua.LState) int {
	s := checkNSESock(L, 1)
	if s.conn == nil {
		L.Push(lua.LNil)
		L.Push(lua.LString("socket not connected"))
		return 2
	}
	payload := L.CheckString(2)
	_ = s.conn.SetDeadline(time.Now().Add(s.timeout))
	n, err := s.conn.Write([]byte(payload))
	if err != nil {
		L.Push(lua.LNil)
		L.Push(lua.LString(err.Error()))
		return 2
	}
	L.Push(lua.LNumber(n))
	L.Push(lua.LNil)
	return 2
}

func nseSockReceiveBytes(L *lua.LState) int {
	s := checkNSESock(L, 1)
	if s.conn == nil {
		L.Push(lua.LNil)
		L.Push(lua.LString("socket not connected"))
		return 2
	}
	n := L.OptInt(2, 4096)
	if n <= 0 {
		n = 4096
	}
	_ = s.conn.SetDeadline(time.Now().Add(s.timeout))
	buf := make([]byte, n)
	got, err := s.conn.Read(buf)
	if err != nil && !errors.Is(err, io.EOF) {
		var nerr net.Error
		if errors.As(err, &nerr) && nerr.Timeout() && got == 0 {
			L.Push(lua.LString(""))
			L.Push(lua.LString("TIMEOUT")) // NSE convention
			return 2
		}
		if got == 0 {
			L.Push(lua.LNil)
			L.Push(lua.LString(err.Error()))
			return 2
		}
	}
	L.Push(lua.LString(string(buf[:got])))
	L.Push(lua.LNil)
	return 2
}

func nseSockClose(L *lua.LState) int {
	s := checkNSESock(L, 1)
	if s.conn != nil {
		_ = s.conn.Close()
		s.conn = nil
	}
	return 0
}

func nseSockSetTimeout(L *lua.LState) int {
	s := checkNSESock(L, 1)
	ms := L.CheckInt(2)
	s.timeout = time.Duration(ms) * time.Millisecond
	return 0
}

// -- stdnse.* -----------------------------------------------------------------

func buildStdnseTable(L *lua.LState) *lua.LTable {
	t := L.NewTable()
	L.SetField(t, "get_script_args", L.NewFunction(stdnseGetScriptArgs))
	L.SetField(t, "print_debug", L.NewFunction(stdnsePrintDebug))
	L.SetField(t, "debug", L.NewFunction(stdnsePrintDebug))
	return t
}

// stdnse.get_script_args(k) — scry has no --script-args yet, so this
// is a no-op. Scripts that depend on args hit the standard Lua
// nil-check pattern and skip.
func stdnseGetScriptArgs(L *lua.LState) int {
	L.Push(lua.LNil)
	return 1
}

// stdnse.print_debug([level,] msg, args...) — NSE overloads the first
// arg. Route to scry.log.info regardless of level.
func stdnsePrintDebug(L *lua.LState) int {
	var msg string
	start := 1
	if _, ok := L.Get(1).(lua.LNumber); ok {
		start = 2
	}
	for i := start; i <= L.GetTop(); i++ {
		if i > start {
			msg += " "
		}
		msg += L.ToString(i)
	}
	// Route via slog directly so we don't re-enter the scry table.
	logInfoDirect(msg)
	return 0
}
