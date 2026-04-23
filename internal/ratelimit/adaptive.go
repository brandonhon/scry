package ratelimit

import (
	"context"
	"sync"
	"sync/atomic"

	"golang.org/x/time/rate"
)

// Adaptive wraps a token-bucket Limiter with a feedback loop that
// halves the rate when the probe error-rate crosses a threshold, and
// doubles it (up to Max) when the error-rate stays well below.
//
// Thresholds are static for v1 per plan §5 (2% high, 0.1% low). The
// window is fixed at 500 in-flight results.
type Adaptive struct {
	inner *rate.Limiter
	mu    sync.Mutex

	current int64 // current pps (read under mu)
	max     int64

	errs  int64 // counters into the current window
	total int64
}

const (
	adaptiveWindow    = 500
	adaptiveHighErr   = 0.02 // >2% → halve
	adaptiveLowErr    = 0.001
	adaptiveMinRate   = 50
	adaptiveBurstMult = 10 // burst is pps / 10, ≥ 1
)

// NewAdaptive returns an Adaptive limiter starting at startRate pps and
// capping at maxRate. startRate<=0 means unlimited (Adaptive becomes a
// no-op wrapper). maxRate<=0 defaults to startRate.
func NewAdaptive(startRate, maxRate int) *Adaptive {
	if startRate <= 0 {
		return &Adaptive{}
	}
	if maxRate <= 0 {
		maxRate = startRate
	}
	a := &Adaptive{
		max:     int64(maxRate),
		current: int64(startRate),
	}
	a.inner = rate.NewLimiter(rate.Limit(startRate), adaptiveBurst(startRate))
	return a
}

func adaptiveBurst(rps int) int {
	b := rps / adaptiveBurstMult
	if b < 1 {
		b = 1
	}
	return b
}

// Wait blocks for one token or until ctx is cancelled.
func (a *Adaptive) Wait(ctx context.Context) error {
	if a == nil || a.inner == nil {
		return ctx.Err()
	}
	return a.inner.Wait(ctx)
}

// ReportProbe records the outcome of a probe. Pass isErr=true for
// timeout / unreachable / reset-storm; false for clean open/closed.
func (a *Adaptive) ReportProbe(isErr bool) {
	if a == nil || a.inner == nil {
		return
	}
	if isErr {
		atomic.AddInt64(&a.errs, 1)
	}
	if atomic.AddInt64(&a.total, 1) < adaptiveWindow {
		return
	}
	a.evaluate()
}

// evaluate closes the current window and possibly adjusts the rate.
func (a *Adaptive) evaluate() {
	a.mu.Lock()
	defer a.mu.Unlock()
	total := atomic.SwapInt64(&a.total, 0)
	errs := atomic.SwapInt64(&a.errs, 0)
	if total < adaptiveWindow {
		// Another goroutine already processed this window; restore.
		atomic.AddInt64(&a.total, total)
		atomic.AddInt64(&a.errs, errs)
		return
	}
	ratio := float64(errs) / float64(total)
	switch {
	case ratio > adaptiveHighErr && a.current > adaptiveMinRate:
		a.current = max64(a.current/2, adaptiveMinRate)
		a.inner.SetLimit(rate.Limit(a.current))
		a.inner.SetBurst(adaptiveBurst(int(a.current)))
	case ratio < adaptiveLowErr && a.current < a.max:
		a.current = min64(a.current*2, a.max)
		a.inner.SetLimit(rate.Limit(a.current))
		a.inner.SetBurst(adaptiveBurst(int(a.current)))
	}
}

// Current returns the active rate in pps (for tests and telemetry).
func (a *Adaptive) Current() int64 {
	if a == nil {
		return 0
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.current
}

func max64(a, b int64) int64 {
	if a > b {
		return a
	}
	return b
}
func min64(a, b int64) int64 {
	if a < b {
		return a
	}
	return b
}
