package portscan

import (
	"context"
	"net/netip"
	"sync"
	"time"

	"github.com/bhoneycutt/gscan/internal/target"
	"github.com/bhoneycutt/gscan/internal/workerpool"
)

// Config tunes a Scan run.
type Config struct {
	Ports       []uint16      // required; from ParsePorts
	Timeout     time.Duration // per-probe dial timeout (default 1500ms)
	Retries     int           // retries on filtered (default 0)
	Concurrency int           // max sockets in flight (default 1000)
	HostParall  int           // max hosts in flight (default 50)
}

// HostResult aggregates all port results for a single host.
type HostResult struct {
	Addr    netip.Addr
	Started time.Time
	Elapsed time.Duration
	Results []Result
}

// Up reports whether any probe returned StateOpen. Callers that want
// discovery via closed/filtered signals can inspect Results directly.
func (h HostResult) Up() bool {
	for _, r := range h.Results {
		if r.State == StateOpen {
			return true
		}
	}
	return false
}

// OpenPorts returns the list of open ports (as found, not sorted).
func (h HostResult) OpenPorts() []uint16 {
	var out []uint16
	for _, r := range h.Results {
		if r.State == StateOpen {
			out = append(out, r.Port)
		}
	}
	return out
}

// Scan iterates addresses from it and probes each Config.Ports. Results are
// emitted on the returned channel as complete HostResult values (one per
// host). The channel is closed when iteration + in-flight work finishes or
// when ctx is cancelled.
func Scan(ctx context.Context, it *target.Iterator, cfg Config) <-chan HostResult {
	cfg = applyDefaults(cfg)
	pool := workerpool.New(workerpool.Config{
		Hosts:   cfg.HostParall,
		Sockets: cfg.Concurrency,
	})

	out := make(chan HostResult, cfg.HostParall)
	var wg sync.WaitGroup

	go func() {
		defer func() {
			wg.Wait()
			close(out)
		}()

		for {
			if err := ctx.Err(); err != nil {
				return
			}
			addr, ok := it.Next()
			if !ok {
				return
			}
			if err := pool.AcquireHost(ctx); err != nil {
				return
			}
			wg.Add(1)
			go func(addr netip.Addr) {
				defer wg.Done()
				defer pool.ReleaseHost()
				hr := scanHost(ctx, pool, addr, cfg)
				select {
				case out <- hr:
				case <-ctx.Done():
				}
			}(addr)
		}
	}()

	return out
}

func applyDefaults(cfg Config) Config {
	if cfg.Timeout <= 0 {
		cfg.Timeout = 1500 * time.Millisecond
	}
	if cfg.Concurrency <= 0 {
		cfg.Concurrency = 1000
	}
	if cfg.HostParall <= 0 {
		cfg.HostParall = 50
	}
	if cfg.Retries < 0 {
		cfg.Retries = 0
	}
	return cfg
}

// scanHost probes every configured port for a single host. Each probe
// acquires one socket slot from the pool, so the cross-host socket budget
// is enforced even when one host has many ports.
func scanHost(ctx context.Context, pool *workerpool.Pool, addr netip.Addr, cfg Config) HostResult {
	start := time.Now()
	hr := HostResult{
		Addr:    addr,
		Started: start,
		Results: make([]Result, 0, len(cfg.Ports)),
	}

	var mu sync.Mutex
	var portWg sync.WaitGroup

	for _, port := range cfg.Ports {
		if err := ctx.Err(); err != nil {
			break
		}
		if err := pool.AcquireSocket(ctx); err != nil {
			break
		}
		portWg.Add(1)
		go func(port uint16) {
			defer portWg.Done()
			defer pool.ReleaseSocket()
			res := probeWithRetry(ctx, addr, port, cfg)
			mu.Lock()
			hr.Results = append(hr.Results, res)
			mu.Unlock()
		}(port)
	}

	portWg.Wait()
	hr.Elapsed = time.Since(start)
	return hr
}

// probeWithRetry performs the initial probe plus up to cfg.Retries retries
// on the StateFiltered outcome. Open/closed/error are returned immediately
// — only timeouts get retried, matching the plan's §5 retransmit note.
func probeWithRetry(ctx context.Context, addr netip.Addr, port uint16, cfg Config) Result {
	res := TCPConnect(ctx, addr, port, cfg.Timeout)
	for i := 0; i < cfg.Retries && res.State == StateFiltered; i++ {
		if err := ctx.Err(); err != nil {
			return res
		}
		res = TCPConnect(ctx, addr, port, cfg.Timeout)
	}
	return res
}
