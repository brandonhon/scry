package script

import (
	"context"
	"errors"
	"io"
	"net"
	"strconv"
	"time"

	lua "github.com/yuin/gopher-lua"
)

const (
	defaultAPITimeoutMS = 3000
	defaultMaxBytes     = 64 * 1024
)

// tcpConnMeta is the Lua metatable name for stateful TCP connection
// userdata returned by tcp.connect.
const tcpConnMeta = "scry.tcp.conn"

func buildTCPTable(L *lua.LState) *lua.LTable {
	t := L.NewTable()
	L.SetField(t, "request", L.NewFunction(tcpRequest))
	L.SetField(t, "connect", L.NewFunction(tcpConnect))
	registerTCPConnMeta(L)
	return t
}

// registerTCPConnMeta installs conn:send / conn:read / conn:close on
// the tcpConnMeta metatable. Called once per LState.
func registerTCPConnMeta(L *lua.LState) {
	mt := L.NewTypeMetatable(tcpConnMeta)
	L.SetField(mt, "__index", L.SetFuncs(L.NewTable(), map[string]lua.LGFunction{
		"send":  tcpConnSend,
		"read":  tcpConnRead,
		"close": tcpConnClose,
	}))
}

// tcpConn wraps a net.Conn so Lua scripts can drive multi-step
// protocols (SMB negotiate, SMTP handshake, binary protocols) that
// the one-shot tcp.request can't express.
type tcpConn struct {
	conn    net.Conn
	timeout time.Duration
}

// tcpConnect: scry.tcp.connect(host, port, opts?) -> conn|nil, err?
// opts supported: timeout (ms, applied to dial + each subsequent op).
func tcpConnect(L *lua.LState) int {
	host := L.CheckString(1)
	port := L.CheckInt(2)
	opts := checkOptsTable(L, 3)
	timeoutMS := optInt(opts, "timeout", defaultAPITimeoutMS)
	timeout := time.Duration(timeoutMS) * time.Millisecond

	d := net.Dialer{Timeout: timeout, KeepAlive: -1}
	conn, err := d.DialContext(L.Context(), "tcp", net.JoinHostPort(host, strconv.Itoa(port)))
	if err != nil {
		L.Push(lua.LNil)
		L.Push(lua.LString(err.Error()))
		return 2
	}
	ud := L.NewUserData()
	ud.Value = &tcpConn{conn: conn, timeout: timeout}
	L.SetMetatable(ud, L.GetTypeMetatable(tcpConnMeta))
	L.Push(ud)
	L.Push(lua.LNil)
	return 2
}

// tcpConnSend: conn:send(bytes) -> n|nil, err?
func tcpConnSend(L *lua.LState) int {
	c := checkTCPConn(L, 1)
	payload := L.CheckString(2)
	_ = c.conn.SetDeadline(time.Now().Add(c.timeout))
	n, err := c.conn.Write([]byte(payload))
	if err != nil {
		L.Push(lua.LNil)
		L.Push(lua.LString(err.Error()))
		return 2
	}
	L.Push(lua.LNumber(n))
	L.Push(lua.LNil)
	return 2
}

// tcpConnRead: conn:read(max_bytes?) -> bytes, err?
// Empty return + "timeout" signals a read timeout (non-fatal).
func tcpConnRead(L *lua.LState) int {
	c := checkTCPConn(L, 1)
	maxBytes := L.OptInt(2, 4096)
	if maxBytes <= 0 {
		maxBytes = 4096
	}
	_ = c.conn.SetDeadline(time.Now().Add(c.timeout))
	buf := make([]byte, maxBytes)
	n, err := c.conn.Read(buf)
	if err != nil && err != io.EOF {
		var nerr net.Error
		if errors.As(err, &nerr) && nerr.Timeout() && n == 0 {
			L.Push(lua.LString(""))
			L.Push(lua.LString("timeout"))
			return 2
		}
		if n == 0 {
			L.Push(lua.LNil)
			L.Push(lua.LString(err.Error()))
			return 2
		}
	}
	L.Push(lua.LString(string(buf[:n])))
	L.Push(lua.LNil)
	return 2
}

// tcpConnClose: conn:close()
func tcpConnClose(L *lua.LState) int {
	c := checkTCPConn(L, 1)
	_ = c.conn.Close()
	return 0
}

func checkTCPConn(L *lua.LState, idx int) *tcpConn {
	ud := L.CheckUserData(idx)
	c, ok := ud.Value.(*tcpConn)
	if !ok {
		L.ArgError(idx, "tcp conn expected")
	}
	return c
}

// tcpRequest implements scry.tcp.request(host, port, payload, opts?).
// Opts supported: timeout (ms), max_bytes.
// Returns (string, nil) on success, (nil, string) on error.
func tcpRequest(L *lua.LState) int {
	host := L.CheckString(1)
	port := L.CheckInt(2)
	payload := L.OptString(3, "")
	opts := checkOptsTable(L, 4)

	timeoutMS := optInt(opts, "timeout", defaultAPITimeoutMS)
	maxBytes := optInt(opts, "max_bytes", defaultMaxBytes)

	body, err := doTCPRequest(L.Context(), host, port, []byte(payload),
		time.Duration(timeoutMS)*time.Millisecond, maxBytes)
	if err != nil {
		L.Push(lua.LNil)
		L.Push(lua.LString(err.Error()))
		return 2
	}
	L.Push(lua.LString(body))
	L.Push(lua.LNil)
	return 2
}

func doTCPRequest(ctx context.Context, host string, port int, payload []byte, timeout time.Duration, maxBytes int) (string, error) {
	if timeout <= 0 {
		timeout = time.Duration(defaultAPITimeoutMS) * time.Millisecond
	}
	if maxBytes <= 0 {
		maxBytes = defaultMaxBytes
	}
	d := net.Dialer{Timeout: timeout, KeepAlive: -1}
	conn, err := d.DialContext(ctx, "tcp", net.JoinHostPort(host, strconv.Itoa(port)))
	if err != nil {
		return "", err
	}
	defer conn.Close()

	deadline := time.Now().Add(timeout)
	_ = conn.SetDeadline(deadline)

	if len(payload) > 0 {
		if _, err := conn.Write(payload); err != nil {
			return "", err
		}
	}
	buf := make([]byte, maxBytes)
	n, err := io.ReadFull(conn, buf)
	if err != nil && !errors.Is(err, io.ErrUnexpectedEOF) && !errors.Is(err, io.EOF) {
		if ne, ok := err.(net.Error); !ok || !ne.Timeout() || n == 0 {
			return "", err
		}
	}
	return string(buf[:n]), nil
}
