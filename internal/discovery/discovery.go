// Package discovery decides whether a host is reachable without running
// the full port scan. Phase 4 implements TCP ping only (probe a short
// list of common ports; any response — SYN/ACK or RST — means up). ICMP
// echo lands in Phase 6 alongside SYN scanning under the `rawsock`
// build tag.
package discovery

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"strconv"
	"sync"
	"syscall"
	"time"
)

// DefaultPingPorts is the shortlist probed by Ping when cfg.Ports is empty.
// These are the ports most likely to give a quick response on a real host:
// at least one of them tends to be either open or actively refused on
// typical Windows, Linux, and macOS boxes.
var DefaultPingPorts = []uint16{80, 443, 22, 445, 3389}

// Config tunes a discovery probe.
type Config struct {
	// Ports override DefaultPingPorts. A non-nil empty slice falls back
	// to the default.
	Ports []uint16
	// Timeout per TCP connection attempt. 0 → 800ms.
	Timeout time.Duration
}

// Result summarises one discovery attempt.
type Result struct {
	Up  bool
	RTT time.Duration
	Via string // "tcp:<port>" on success, "" on timeout-only
}

// Ping probes cfg.Ports in parallel and returns up=true on the first port
// that either completes a handshake or is actively refused (RST). A pure
// timeout means we couldn't tell — reported as down with an empty Via.
//
// This matches nmap's -PE fallback behaviour: closed-but-responsive hosts
// still count as up.
func Ping(ctx context.Context, addr netip.Addr, cfg Config) Result {
	ports := cfg.Ports
	if len(ports) == 0 {
		ports = DefaultPingPorts
	}
	timeout := cfg.Timeout
	if timeout <= 0 {
		timeout = 800 * time.Millisecond
	}

	probeCtx, cancel := context.WithCancel(ctx)
	defer cancel()

	type outcome struct {
		up  bool
		rtt time.Duration
		via string
	}
	results := make(chan outcome, len(ports)+1)

	var wg sync.WaitGroup
	// ICMP Echo races alongside the TCP probes (rawsock builds only).
	if icmpAvailable {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if up, rtt, via := pingICMP(probeCtx, addr, timeout); up {
				select {
				case results <- outcome{up: true, rtt: rtt, via: via}:
				default:
				}
			}
		}()
	}
	for _, p := range ports {
		wg.Add(1)
		go func(port uint16) {
			defer wg.Done()
			d := net.Dialer{Timeout: timeout, KeepAlive: -1}
			start := time.Now()
			conn, err := d.DialContext(probeCtx, "tcp", net.JoinHostPort(addr.String(), strconv.Itoa(int(port))))
			rtt := time.Since(start)
			if err == nil {
				_ = conn.Close()
				select {
				case results <- outcome{up: true, rtt: rtt, via: "tcp:" + strconv.Itoa(int(port))}:
				default:
				}
				return
			}
			if up, via := classifyDialErr(err, port); up {
				select {
				case results <- outcome{up: true, rtt: rtt, via: via}:
				default:
				}
			}
		}(p)
	}

	done := make(chan struct{})
	go func() {
		wg.Wait()
		close(done)
	}()

	select {
	case first := <-results:
		// Got a positive answer; cancel the other goroutines and return
		// immediately without waiting for their cleanup.
		cancel()
		return Result{Up: first.up, RTT: first.rtt, Via: first.via}
	case <-done:
		// All probes finished without a positive result.
		return Result{}
	}
}

// classifyDialErr decides whether a failed TCP dial counts as
// "host up" for ping purposes. The semantics:
//
//   - nil err            — Ping handles the connect-success path itself
//   - timeout            — we don't know (filtered/unknown)   → not up
//   - ENETUNREACH        — no route to host                   → not up
//   - EHOSTUNREACH       — no ARP / host unreachable          → not up
//   - anything else      — peer stack responded (RST, reset,
//                          Windows WSA* refused variants)     → up
//
// Enumerating the "peer responded" signatures across Linux/macOS/
// Windows is a moving target (errors.Is(err, syscall.ECONNREFUSED)
// doesn't catch every closed-port case on Windows CI, for example).
// Enumerating the "can't reach" signatures is stable — there's a
// small fixed set of routing-failure errnos on every POSIX-ish OS.
//
// `via` is the display annotation (e.g. "tcp:22/refused").
func classifyDialErr(err error, port uint16) (up bool, via string) {
	if err == nil {
		return false, ""
	}
	var nerr net.Error
	if errors.As(err, &nerr) && nerr.Timeout() {
		return false, ""
	}
	if errors.Is(err, syscall.ENETUNREACH) || errors.Is(err, syscall.EHOSTUNREACH) {
		return false, ""
	}
	via = "tcp:" + strconv.Itoa(int(port))
	if errors.Is(err, syscall.ECONNREFUSED) {
		via += "/refused"
	}
	return true, via
}
