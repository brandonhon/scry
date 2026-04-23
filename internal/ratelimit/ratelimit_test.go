package ratelimit

import (
	"context"
	"testing"
	"time"
)

func TestNew_ZeroIsUnlimited(t *testing.T) {
	l := New(0, 0)
	if l.Limit() != 0 {
		t.Fatalf("Limit()=%d, want 0", l.Limit())
	}
	start := time.Now()
	for i := 0; i < 10_000; i++ {
		if err := l.Wait(context.Background()); err != nil {
			t.Fatal(err)
		}
	}
	if d := time.Since(start); d > 200*time.Millisecond {
		t.Fatalf("unlimited path took %s for 10k Waits — should be ~instant", d)
	}
}

func TestWait_PaceMatchesRate(t *testing.T) {
	// Request 10 tokens at 100/s; expected ~100ms, allow headroom for CI.
	const rps = 100
	const n = 10
	l := New(rps, 1)
	ctx := context.Background()
	start := time.Now()
	for i := 0; i < n; i++ {
		if err := l.Wait(ctx); err != nil {
			t.Fatal(err)
		}
	}
	d := time.Since(start)
	lower := time.Duration(n-1) * time.Second / rps
	if d < lower {
		t.Fatalf("took %s, want at least %s (rps=%d, n=%d)", d, lower, rps, n)
	}
	upper := lower + 500*time.Millisecond
	if d > upper {
		t.Fatalf("took %s, want at most %s (rps=%d, n=%d)", d, upper, rps, n)
	}
}

func TestWait_RespectsCancel(t *testing.T) {
	l := New(1, 1) // 1 token/sec — next request blocks ~1s
	ctx, cancel := context.WithCancel(context.Background())

	// Drain the first token.
	if err := l.Wait(context.Background()); err != nil {
		t.Fatal(err)
	}

	cancel()
	if err := l.Wait(ctx); err == nil {
		t.Fatal("expected error from cancelled context")
	}
}

func TestNilLimiter_SafeToUse(t *testing.T) {
	var l *Limiter
	if err := l.Wait(context.Background()); err != nil {
		t.Fatal(err)
	}
	if l.Limit() != 0 {
		t.Fatal("nil limiter Limit should be 0")
	}
}
