package workerpool

import (
	"context"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func TestPool_DefaultsAndLimits(t *testing.T) {
	p := New(Config{})
	if p.HostLimit() != defaultHosts {
		t.Fatalf("HostLimit = %d, want %d", p.HostLimit(), defaultHosts)
	}
	if p.SocketLimit() != defaultSockets {
		t.Fatalf("SocketLimit = %d, want %d", p.SocketLimit(), defaultSockets)
	}

	custom := New(Config{Hosts: 7, Sockets: 13})
	if custom.HostLimit() != 7 || custom.SocketLimit() != 13 {
		t.Fatalf("custom limits wrong: hosts=%d sockets=%d", custom.HostLimit(), custom.SocketLimit())
	}
}

// TestPool_HostSemaphoreBounds verifies that at most N hosts run in parallel.
func TestPool_HostSemaphoreBounds(t *testing.T) {
	const limit = 4
	const jobs = 32
	p := New(Config{Hosts: limit, Sockets: 1000})
	ctx := context.Background()

	var (
		inflight  int64
		maxSeen   int64
		wg        sync.WaitGroup
	)
	for i := 0; i < jobs; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if err := p.AcquireHost(ctx); err != nil {
				t.Error(err)
				return
			}
			defer p.ReleaseHost()

			cur := atomic.AddInt64(&inflight, 1)
			for {
				m := atomic.LoadInt64(&maxSeen)
				if cur <= m || atomic.CompareAndSwapInt64(&maxSeen, m, cur) {
					break
				}
			}
			time.Sleep(5 * time.Millisecond)
			atomic.AddInt64(&inflight, -1)
		}()
	}
	wg.Wait()

	if maxSeen > limit {
		t.Fatalf("observed %d concurrent hosts, limit was %d", maxSeen, limit)
	}
	if maxSeen == 0 {
		t.Fatal("pool never ran any hosts")
	}
}

func TestPool_SocketSemaphoreBounds(t *testing.T) {
	const limit = 3
	const jobs = 20
	p := New(Config{Hosts: 100, Sockets: limit})
	ctx := context.Background()

	var inflight, maxSeen int64
	var wg sync.WaitGroup
	for i := 0; i < jobs; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if err := p.AcquireSocket(ctx); err != nil {
				t.Error(err)
				return
			}
			defer p.ReleaseSocket()

			cur := atomic.AddInt64(&inflight, 1)
			for {
				m := atomic.LoadInt64(&maxSeen)
				if cur <= m || atomic.CompareAndSwapInt64(&maxSeen, m, cur) {
					break
				}
			}
			time.Sleep(5 * time.Millisecond)
			atomic.AddInt64(&inflight, -1)
		}()
	}
	wg.Wait()

	if maxSeen > limit {
		t.Fatalf("observed %d concurrent sockets, limit %d", maxSeen, limit)
	}
}

func TestPool_AcquireCancelled(t *testing.T) {
	p := New(Config{Hosts: 1, Sockets: 1})
	ctx, cancel := context.WithCancel(context.Background())

	// Fill host slot.
	if err := p.AcquireHost(context.Background()); err != nil {
		t.Fatal(err)
	}
	defer p.ReleaseHost()

	cancel()
	if err := p.AcquireHost(ctx); err == nil {
		t.Fatal("expected error on cancelled context")
	}
}
