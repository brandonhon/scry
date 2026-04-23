package resolver

import (
	"context"
	"errors"
	"net/netip"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func TestCache_DedupesLookups(t *testing.T) {
	var calls int64
	c := New(Options{
		Lookup: func(ctx context.Context, addr netip.Addr) (string, error) {
			atomic.AddInt64(&calls, 1)
			return "host.example.", nil
		},
	})

	addr := netip.MustParseAddr("10.0.0.1")

	var wg sync.WaitGroup
	for i := 0; i < 20; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			name, err := c.Lookup(context.Background(), addr)
			if err != nil {
				t.Error(err)
				return
			}
			if name != "host.example" {
				t.Errorf("got %q, want %q (trailing dot should be stripped)", name, "host.example")
			}
		}()
	}
	wg.Wait()

	if got := atomic.LoadInt64(&calls); got != 1 {
		t.Fatalf("lookup was called %d times, want 1", got)
	}
}

func TestCache_Error_RecordedAndReturned(t *testing.T) {
	wantErr := errors.New("nxdomain")
	c := New(Options{
		Lookup: func(ctx context.Context, addr netip.Addr) (string, error) {
			return "", wantErr
		},
	})

	name, err := c.Lookup(context.Background(), netip.MustParseAddr("10.0.0.2"))
	if err == nil || !errors.Is(err, wantErr) {
		t.Fatalf("got err=%v, want %v", err, wantErr)
	}
	if name != "" {
		t.Fatalf("got name=%q on error, want empty", name)
	}
}

func TestCache_Timeout(t *testing.T) {
	c := New(Options{
		Timeout: 50 * time.Millisecond,
		Lookup: func(ctx context.Context, addr netip.Addr) (string, error) {
			select {
			case <-ctx.Done():
				return "", ctx.Err()
			case <-time.After(1 * time.Second):
				return "should-not-happen", nil
			}
		},
	})

	start := time.Now()
	_, err := c.Lookup(context.Background(), netip.MustParseAddr("10.0.0.3"))
	if err == nil {
		t.Fatal("expected timeout error")
	}
	if d := time.Since(start); d > 500*time.Millisecond {
		t.Fatalf("took %s, timeout should have fired ~50ms", d)
	}
}

func TestCache_DifferentAddrs_IndependentEntries(t *testing.T) {
	c := New(Options{
		Lookup: func(ctx context.Context, addr netip.Addr) (string, error) {
			return addr.String() + ".example", nil
		},
	})
	a, _ := c.Lookup(context.Background(), netip.MustParseAddr("10.0.0.1"))
	b, _ := c.Lookup(context.Background(), netip.MustParseAddr("10.0.0.2"))
	if a == b {
		t.Fatalf("distinct addrs resolved to the same name: %q", a)
	}
}
