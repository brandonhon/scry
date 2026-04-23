// Package ratelimit provides a goroutine-safe token-bucket limiter used
// by the SYN scanner to pace packet emission (--rate flag). TCP-connect
// mode already self-paces via the socket-concurrency semaphore and does
// not use this package.
//
// A zero-rate limiter (New(0)) is a no-op — Wait returns immediately —
// so callers can unconditionally hold a Limiter without conditional
// branches on a "rate limiting on" flag.
package ratelimit

import (
	"context"

	"golang.org/x/time/rate"
)

// Limiter is an opaque handle around x/time/rate.Limiter that understands
// the "zero means unlimited" convention.
type Limiter struct {
	inner *rate.Limiter
}

// New returns a limiter that admits at most rps events per second.
// burst is the maximum short-term burst; if burst <= 0 it defaults to
// rps (i.e. roughly one second of traffic). rps <= 0 disables the
// limiter; Wait is a no-op.
func New(rps, burst int) *Limiter {
	if rps <= 0 {
		return &Limiter{} // nil inner ⇒ unlimited
	}
	if burst <= 0 {
		burst = rps
	}
	return &Limiter{inner: rate.NewLimiter(rate.Limit(rps), burst)}
}

// Wait blocks until one token is available or ctx is cancelled. On the
// unlimited path it returns immediately with ctx.Err().
func (l *Limiter) Wait(ctx context.Context) error {
	if l == nil || l.inner == nil {
		return ctx.Err()
	}
	return l.inner.Wait(ctx)
}

// Limit returns the configured rate in events per second. Zero means
// unlimited.
func (l *Limiter) Limit() int {
	if l == nil || l.inner == nil {
		return 0
	}
	return int(l.inner.Limit())
}
