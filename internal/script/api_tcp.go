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

func buildTCPTable(L *lua.LState) *lua.LTable {
	t := L.NewTable()
	L.SetField(t, "request", L.NewFunction(tcpRequest))
	return t
}

// tcpRequest implements gscan.tcp.request(host, port, payload, opts?).
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
