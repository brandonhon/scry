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
		up   bool
		rtt  time.Duration
		via  string
	}
	results := make(chan outcome, len(ports))

	var wg sync.WaitGroup
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
			// ECONNREFUSED (RST) also means the host is reachable — the
			// stack responded, just nothing listens there.
			if errors.Is(err, syscall.ECONNREFUSED) {
				select {
				case results <- outcome{up: true, rtt: rtt, via: "tcp:" + strconv.Itoa(int(port)) + "/refused"}:
				default:
				}
			}
		}(p)
	}

	go func() {
		wg.Wait()
		close(results)
	}()

	first, ok := <-results
	if !ok {
		return Result{}
	}
	// Cancel remaining probes now that we have a verdict.
	cancel()
	// Drain.
	for range results {
	}
	return Result{Up: first.up, RTT: first.rtt, Via: first.via}
}
