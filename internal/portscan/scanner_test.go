package portscan

import (
	"context"
	"net"
	"strconv"
	"sync"
	"testing"
	"time"

	"github.com/brandonhon/scry/internal/target"
)

// startListener returns an accepting TCP listener on 127.0.0.1 and a
// cleanup func. The accept loop drains connections until stopped.
func startListener(t *testing.T) (uint16, func()) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	_, ps, _ := net.SplitHostPort(ln.Addr().String())
	p, _ := strconv.Atoi(ps)

	done := make(chan struct{})
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				select {
				case <-done:
				case <-time.After(50 * time.Millisecond):
				}
				_ = c.Close()
			}(c)
		}
	}()

	return uint16(p), func() {
		close(done)
		_ = ln.Close()
		wg.Wait()
	}
}

func TestScan_OpenAndClosed(t *testing.T) {
	openPort, stop := startListener(t)
	defer stop()

	// Find a closed port: bind-then-close.
	ln2, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	_, ps, _ := net.SplitHostPort(ln2.Addr().String())
	closed, _ := strconv.Atoi(ps)
	ln2.Close()

	it, err := target.Parse([]string{"127.0.0.1"}, target.Options{})
	if err != nil {
		t.Fatal(err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	out := Scan(ctx, it, Config{
		Ports:       []uint16{openPort, uint16(closed)},
		Timeout:     500 * time.Millisecond,
		Concurrency: 10,
		HostParall:  4,
	})

	var hosts []HostResult
	for hr := range out {
		hosts = append(hosts, hr)
	}
	if len(hosts) != 1 {
		t.Fatalf("got %d host results, want 1", len(hosts))
	}
	hr := hosts[0]
	if !hr.Up() {
		t.Fatalf("host should be up (listener running on %d)", openPort)
	}
	gotOpen := hr.OpenPorts()
	if len(gotOpen) != 1 || gotOpen[0] != openPort {
		t.Fatalf("OpenPorts = %v, want [%d]", gotOpen, openPort)
	}
	// All probes must have run.
	if len(hr.Results) != 2 {
		t.Fatalf("Results len = %d, want 2", len(hr.Results))
	}
}

func TestScan_ManyHostsBounded(t *testing.T) {
	// Use /30 on loopback — only 127.0.0.0..3 are valid targets and all
	// should be reachable enough to produce a Result quickly with a tight
	// timeout. We mainly want to exercise the host-parallelism semaphore.
	it, err := target.Parse([]string{"127.0.0.0/30"}, target.Options{})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	out := Scan(ctx, it, Config{
		Ports:       []uint16{1},
		Timeout:     300 * time.Millisecond,
		Concurrency: 16,
		HostParall:  2,
	})

	count := 0
	for range out {
		count++
	}
	if count != 4 {
		t.Fatalf("got %d host results, want 4", count)
	}
}

func TestScan_ContextCancelled(t *testing.T) {
	// Scan a non-routable address with a long timeout so dials will hang,
	// then cancel and confirm the channel closes promptly.
	it, err := target.Parse([]string{"10.255.255.1"}, target.Options{})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())

	out := Scan(ctx, it, Config{
		Ports:       []uint16{1, 2, 3},
		Timeout:     5 * time.Second,
		Concurrency: 4,
		HostParall:  4,
	})

	time.AfterFunc(50*time.Millisecond, cancel)
	// Drain; ensure it closes.
	deadline := time.After(2 * time.Second)
	done := make(chan struct{})
	go func() {
		for range out {
		}
		close(done)
	}()
	select {
	case <-done:
	case <-deadline:
		t.Fatal("channel did not close after cancel")
	}
}

func TestProbeWithRetry_NoRetryOnOpen(t *testing.T) {
	openPort, stop := startListener(t)
	defer stop()

	it, err := target.Parse([]string{"127.0.0.1"}, target.Options{})
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	out := Scan(ctx, it, Config{
		Ports:       []uint16{openPort},
		Timeout:     500 * time.Millisecond,
		Retries:     3,
		Concurrency: 4,
		HostParall:  1,
	})
	hr := <-out
	if hr.Results[0].State != StateOpen {
		t.Fatalf("got state %v, want open", hr.Results[0].State)
	}
}
