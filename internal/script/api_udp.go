package script

import (
	"errors"
	"net"
	"strconv"
	"time"

	lua "github.com/yuin/gopher-lua"
)

func buildUDPTable(L *lua.LState) *lua.LTable {
	t := L.NewTable()
	L.SetField(t, "send", L.NewFunction(udpSend))
	return t
}

// udpSend: scry.udp.send(host, port, payload, opts?) -> bytes, err?
//
// Sends one UDP packet and optionally waits for one response. Opts:
//
//	timeout    (ms, default 1500)
//	max_bytes  (int, default 1500)
//	expect_reply (bool, default true) — when false, returns "" after send
//	  and does not wait for a reply, useful for fire-and-forget probes
//	  (e.g. DHCP discover, syslog).
//
// Timeouts return ("", "timeout") rather than an error so scripts can
// distinguish "no reply" (often informative for UDP services) from a
// hard send failure.
func udpSend(L *lua.LState) int {
	host := L.CheckString(1)
	port := L.CheckInt(2)
	payload := L.OptString(3, "")
	opts := checkOptsTable(L, 4)

	timeout := time.Duration(optInt(opts, "timeout", 1500)) * time.Millisecond
	maxBytes := optInt(opts, "max_bytes", 1500)
	if maxBytes <= 0 {
		maxBytes = 1500
	}
	expectReply := optBool(opts, "expect_reply", true)

	body, err := doUDPSend(host, port, []byte(payload), timeout, maxBytes, expectReply)
	if err != nil {
		if errors.Is(err, errUDPTimeout) {
			L.Push(lua.LString(""))
			L.Push(lua.LString("timeout"))
			return 2
		}
		L.Push(lua.LNil)
		L.Push(lua.LString(err.Error()))
		return 2
	}
	L.Push(lua.LString(body))
	L.Push(lua.LNil)
	return 2
}

var errUDPTimeout = errors.New("udp read timeout")

func doUDPSend(host string, port int, payload []byte, timeout time.Duration, maxBytes int, expectReply bool) (string, error) {
	d := net.Dialer{Timeout: timeout}
	conn, err := d.Dial("udp", net.JoinHostPort(host, strconv.Itoa(port)))
	if err != nil {
		return "", err
	}
	defer conn.Close()

	_ = conn.SetDeadline(time.Now().Add(timeout))
	if _, err := conn.Write(payload); err != nil {
		return "", err
	}
	if !expectReply {
		return "", nil
	}
	buf := make([]byte, maxBytes)
	n, err := conn.Read(buf)
	if err != nil {
		var nerr net.Error
		if errors.As(err, &nerr) && nerr.Timeout() {
			return "", errUDPTimeout
		}
		return "", err
	}
	return string(buf[:n]), nil
}
