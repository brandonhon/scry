package portscan

import (
	"context"
	"net"
	"net/netip"
	"strconv"
	"sync/atomic"
	"testing"
	"time"

	"github.com/brandonhon/scry/internal/target"
)

// countingReporter is a progress.Reporter that records SetTotal + ticks
// so tests can assert the scan emits one tick per probe, not per host.
type countingReporter struct {
	total  int64
	ticks  int64
	finish int64
}

func (c *countingReporter) SetTotal(n int64) { atomic.StoreInt64(&c.total, n) }
func (c *countingReporter) Tick()            { atomic.AddInt64(&c.ticks, 1) }
func (c *countingReporter) Finish()          { atomic.AddInt64(&c.finish, 1) }

// TestScan_ProgressTicksPerProbe proves that a scan of 1 host × N ports
// ticks N times, so long single-host scans (like `-p-` against a
// hostname) show continuous progress.
func TestScan_ProgressTicksPerProbe(t *testing.T) {
	// Pick two real loopback ports — an open listener and a closed one —
	// so the probes finish quickly and deterministically.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			_ = c.Close()
		}
	}()
	_, openStr, _ := net.SplitHostPort(ln.Addr().String())
	openPort, _ := strconv.Atoi(openStr)

	ln2, _ := net.Listen("tcp", "127.0.0.1:0")
	_, closedStr, _ := net.SplitHostPort(ln2.Addr().String())
	closedPort, _ := strconv.Atoi(closedStr)
	ln2.Close()

	const extraPorts = 3 // a few filtered ports to pad the count
	ports := []uint16{uint16(openPort), uint16(closedPort)}
	for i := 0; i < extraPorts; i++ {
		ports = append(ports, uint16(60000+i))
	}

	it, err := target.Parse([]string{"127.0.0.1"}, target.Options{})
	if err != nil {
		t.Fatal(err)
	}

	rep := &countingReporter{}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	out := Scan(ctx, it, Config{
		Ports:       ports,
		Timeout:     200 * time.Millisecond,
		Concurrency: 10,
		HostParall:  1,
		Progress:    rep,
	})
	for range out {
	}

	if got := atomic.LoadInt64(&rep.total); got != int64(len(ports)) {
		t.Errorf("SetTotal = %d, want %d (1 host × %d ports)", got, len(ports), len(ports))
	}
	if got := atomic.LoadInt64(&rep.ticks); got != int64(len(ports)) {
		t.Errorf("Tick count = %d, want %d", got, len(ports))
	}
	if got := atomic.LoadInt64(&rep.finish); got != 1 {
		t.Errorf("Finish count = %d, want 1", got)
	}
}

// TestScan_Progress_PingOnly_TicksPerHost — in -sn mode each host is one
// probe, so the total equals the host count.
func TestScan_Progress_PingOnly_TicksPerHost(t *testing.T) {
	it, err := target.Parse([]string{"10.255.255.0/30"}, target.Options{})
	if err != nil {
		t.Fatal(err)
	}
	rep := &countingReporter{}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	out := Scan(ctx, it, Config{
		Timeout:    300 * time.Millisecond,
		HostParall: 4,
		PingOnly:   true,
		Progress:   rep,
	})
	for range out {
	}

	if got := atomic.LoadInt64(&rep.total); got != 4 {
		t.Errorf("SetTotal = %d, want 4", got)
	}
	if got := atomic.LoadInt64(&rep.ticks); got != 4 {
		t.Errorf("Tick count = %d, want 4", got)
	}
}

var _ = netip.Addr{}
