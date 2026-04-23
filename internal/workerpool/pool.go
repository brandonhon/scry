// Package workerpool provides a two-level bounded-concurrency helper for
// the scanner (see §5 of ip-scanner-plan.md).
//
// Two semaphores are exposed:
//
//   - Host   — bounds the number of hosts in flight (default 50).
//   - Socket — bounds the total in-flight TCP sockets across all hosts
//     (default 1000).
//
// Both are acquired as weighted semaphores so the caller can release
// exactly what was acquired. The split keeps per-host latency predictable
// while still letting a single "busy" host use many sockets when others
// are idle.
package workerpool

import (
	"context"

	"golang.org/x/sync/semaphore"
)

// Pool holds the two semaphores. Acquire in Host→Socket order and release
// in reverse to avoid starving other hosts while holding socket budget.
type Pool struct {
	host   *semaphore.Weighted
	socket *semaphore.Weighted

	hostLimit   int64
	socketLimit int64
}

// Config tunes pool capacity. Zero/negative values fall back to defaults.
type Config struct {
	Hosts   int // default 50
	Sockets int // default 1000
}

const (
	defaultHosts   = 50
	defaultSockets = 1000
)

// New constructs a Pool.
func New(cfg Config) *Pool {
	h := int64(cfg.Hosts)
	if h <= 0 {
		h = defaultHosts
	}
	s := int64(cfg.Sockets)
	if s <= 0 {
		s = defaultSockets
	}
	return &Pool{
		host:        semaphore.NewWeighted(h),
		socket:      semaphore.NewWeighted(s),
		hostLimit:   h,
		socketLimit: s,
	}
}

// AcquireHost blocks until there is room for another host, or ctx is done.
func (p *Pool) AcquireHost(ctx context.Context) error {
	return p.host.Acquire(ctx, 1)
}

// ReleaseHost releases a single host slot.
func (p *Pool) ReleaseHost() { p.host.Release(1) }

// AcquireSocket blocks until there is a free socket slot, or ctx is done.
func (p *Pool) AcquireSocket(ctx context.Context) error {
	return p.socket.Acquire(ctx, 1)
}

// ReleaseSocket releases a single socket slot.
func (p *Pool) ReleaseSocket() { p.socket.Release(1) }

// HostLimit returns the configured max in-flight hosts.
func (p *Pool) HostLimit() int64 { return p.hostLimit }

// SocketLimit returns the configured max in-flight sockets.
func (p *Pool) SocketLimit() int64 { return p.socketLimit }
