package portscan

import (
	"context"
	"net/netip"
	"sync"
	"time"

	"github.com/bhoneycutt/scry/internal/banner"
	"github.com/bhoneycutt/scry/internal/discovery"
	"github.com/bhoneycutt/scry/internal/progress"
	"github.com/bhoneycutt/scry/internal/resolver"
	"github.com/bhoneycutt/scry/internal/script"
	"github.com/bhoneycutt/scry/internal/target"
	"github.com/bhoneycutt/scry/internal/workerpool"
)

// Config tunes a Scan run. Defaults are speed-first: short timeout, no
// retries, generous concurrency. Raise Timeout + Retries for accuracy on
// WAN or lossy links.
type Config struct {
	Ports       []uint16      // required unless PingOnly
	Timeout     time.Duration // per-probe dial timeout (default 500ms)
	Retries     int           // retries on filtered (default 0)
	Concurrency int           // max sockets in flight (default 2000)
	HostParall  int           // max hosts in flight (default 100)

	// PingOnly skips the port scan and runs TCP ping discovery only (-sn).
	PingOnly bool

	// Banner enables a passive banner grab on every open port.
	Banner bool

	// Progress receives one Tick per host completed. SetTotal is called
	// once up front using target.Iterator.Total(). nil → progress.NewNoop.
	Progress progress.Reporter

	// Resolver enables reverse DNS enrichment. nil disables it (equivalent
	// to --no-dns at the CLI level).
	Resolver *resolver.Cache

	// ScriptEngine runs Lua scripts against each open port. nil disables.
	ScriptEngine *script.Engine

	// Rate bounds SYN packet emission (packets-per-second). 0 disables
	// rate limiting. TCP-connect mode ignores this; the socket semaphore
	// is the pacer there.
	Rate int
}

// HostResult aggregates all port results for a single host, plus any
// reverse-DNS and discovery metadata collected in parallel with the scan.
type HostResult struct {
	Addr      netip.Addr
	Hostname  string // populated when Config.Resolver was set and PTR succeeded
	Started   time.Time
	Elapsed   time.Duration
	Results   []Result
	Discovery *discovery.Result // populated in PingOnly mode
}

// Up reports whether any probe returned StateOpen, or (in PingOnly mode)
// whether discovery reached the host.
func (h HostResult) Up() bool {
	if h.Discovery != nil {
		return h.Discovery.Up
	}
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

// Scan iterates addresses from it and probes each Config.Ports (or runs
// TCP ping when Config.PingOnly is set). Results stream on the returned
// channel; the channel closes when iteration and in-flight work finish
// or when ctx is cancelled.
func Scan(ctx context.Context, it *target.Iterator, cfg Config) <-chan HostResult {
	cfg = applyDefaults(cfg)
	pool := workerpool.New(workerpool.Config{
		Hosts:   cfg.HostParall,
		Sockets: cfg.Concurrency,
	})
	rep := cfg.Progress
	if rep == nil {
		rep = progress.NewNoop()
	}
	// Progress is measured in probes, not hosts, so long single-host scans
	// (like `-p-` against one hostname) show constant motion. PingOnly
	// runs one discovery per host, so its unit is hosts.
	if total, ok := it.Total(); ok {
		unit := int64(1)
		if !cfg.PingOnly && len(cfg.Ports) > 0 {
			unit = int64(len(cfg.Ports))
		}
		rep.SetTotal(int64(total) * unit)
	}

	out := make(chan HostResult, cfg.HostParall)
	var wg sync.WaitGroup

	go func() {
		defer func() {
			wg.Wait()
			rep.Finish()
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
				hr := processHost(ctx, pool, addr, cfg, rep)
				// Always send so partial results survive SIGINT. The
				// consumer is expected to drain `out` until close; see
				// runScan in the cli package.
				out <- hr
			}(addr)
		}
	}()

	return out
}

func applyDefaults(cfg Config) Config {
	if cfg.Timeout <= 0 {
		cfg.Timeout = 500 * time.Millisecond
	}
	if cfg.Concurrency <= 0 {
		cfg.Concurrency = 2000
	}
	if cfg.HostParall <= 0 {
		cfg.HostParall = 100
	}
	if cfg.Retries < 0 {
		cfg.Retries = 0
	}
	return cfg
}

// processHost runs the configured work for a single address. In PingOnly
// mode it performs TCP discovery; otherwise it probes every port. In
// either case it launches a reverse-DNS lookup in parallel so the PTR
// result is ready by the time the scan finishes.
func processHost(ctx context.Context, pool *workerpool.Pool, addr netip.Addr, cfg Config, rep progress.Reporter) HostResult {
	start := time.Now()
	hr := HostResult{Addr: addr, Started: start}

	// Reverse DNS runs in parallel with whatever the main path does.
	var (
		dnsDone chan struct{}
		dnsName string
	)
	if cfg.Resolver != nil {
		dnsDone = make(chan struct{})
		go func() {
			defer close(dnsDone)
			name, _ := cfg.Resolver.Lookup(ctx, addr)
			dnsName = name
		}()
	}

	if cfg.PingOnly {
		res := discovery.Ping(ctx, addr, discovery.Config{Timeout: cfg.Timeout})
		hr.Discovery = &res
		rep.Tick() // one probe per host in ping-only mode
	} else {
		hr.Results = scanPorts(ctx, pool, addr, cfg, rep)
	}

	if dnsDone != nil {
		<-dnsDone
		hr.Hostname = dnsName
	}
	hr.Elapsed = time.Since(start)
	return hr
}

// scanPorts probes every configured port for a single host. Each probe
// acquires one socket slot from the pool, so the cross-host socket
// budget is enforced even when one host has many ports.
func scanPorts(ctx context.Context, pool *workerpool.Pool, addr netip.Addr, cfg Config, rep progress.Reporter) []Result {
	results := make([]Result, 0, len(cfg.Ports))

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
			defer rep.Tick()
			res := probeWithRetry(ctx, addr, port, cfg)
			if res.State == StateOpen {
				if cfg.Banner {
					if b, err := banner.Grab(ctx, addr, port, 500*time.Millisecond, 0); err == nil {
						res.Banner = b
					}
				}
				if cfg.ScriptEngine != nil {
					findings := cfg.ScriptEngine.RunAll(ctx, addr.String(), port)
					for _, f := range findings {
						res.Findings = append(res.Findings, ScriptFinding{Script: f.Script, Output: f.Output})
					}
				}
			}
			mu.Lock()
			results = append(results, res)
			mu.Unlock()
		}(port)
	}

	portWg.Wait()
	return results
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
