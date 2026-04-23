// Package portscan probes TCP ports. Phase 1 ships only the TCP connect
// scanner against a single (addr, port) pair. The SYN scanner and the
// worker-pool wiring land in Phase 2 / Phase 6.
package portscan

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"strconv"
	"syscall"
	"time"
)

// State classifies the outcome of a single TCP probe.
type State int

const (
	StateUnknown State = iota
	StateOpen
	StateClosed
	StateFiltered
	StateError
)

func (s State) String() string {
	switch s {
	case StateOpen:
		return "open"
	case StateClosed:
		return "closed"
	case StateFiltered:
		return "filtered"
	case StateError:
		return "error"
	default:
		return "unknown"
	}
}

// Result is the outcome of a single probe.
type Result struct {
	Addr    netip.Addr
	Port    uint16
	State   State
	RTT     time.Duration
	Err     error // populated for StateError
}

// TCPConnect performs one TCP-connect probe against addr:port using the
// supplied timeout. State classification:
//
//	open      — TCP handshake completed
//	closed    — received RST / ECONNREFUSED
//	filtered  — timeout reached with no response
//	error     — some other error (unreachable host, too many open files, …)
func TCPConnect(ctx context.Context, addr netip.Addr, port uint16, timeout time.Duration) Result {
	res := Result{Addr: addr, Port: port}

	dialer := net.Dialer{Timeout: timeout, KeepAlive: -1}
	target := net.JoinHostPort(addr.String(), strconv.Itoa(int(port)))

	start := time.Now()
	conn, err := dialer.DialContext(ctx, "tcp", target)
	res.RTT = time.Since(start)

	if err == nil {
		_ = conn.Close()
		res.State = StateOpen
		return res
	}

	res.Err = err
	res.State = classifyDialErr(err)
	return res
}

// classifyDialErr maps a dial error to a State.
func classifyDialErr(err error) State {
	if errors.Is(err, context.DeadlineExceeded) {
		return StateFiltered
	}
	var nerr net.Error
	if errors.As(err, &nerr) && nerr.Timeout() {
		return StateFiltered
	}
	if errors.Is(err, syscall.ECONNREFUSED) {
		return StateClosed
	}
	return StateError
}
