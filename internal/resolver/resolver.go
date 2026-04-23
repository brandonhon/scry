// Package resolver performs concurrent reverse DNS lookups with a per-run
// cache so the same IP is not resolved twice. Lookups are capped by their
// own timeout so a slow PTR server can't stall the scan pipeline.
package resolver

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"strings"
	"sync"
	"time"
)

// LookupFunc is the injectable resolver. Returning "" means "no name";
// returning an error is distinct and is recorded for observability but
// otherwise treated the same as "no name" (callers render the IP).
type LookupFunc func(ctx context.Context, addr netip.Addr) (string, error)

// Cache resolves IPs to hostnames with dedupe and a single-flight-style
// barrier so concurrent callers for the same IP share one lookup.
type Cache struct {
	lookup  LookupFunc
	timeout time.Duration

	mu      sync.Mutex
	entries map[netip.Addr]*entry
}

type entry struct {
	once sync.Once
	name string
	err  error
}

// Options tunes the cache.
type Options struct {
	// Lookup does the PTR query. If nil, net.DefaultResolver.LookupAddr
	// is used.
	Lookup LookupFunc
	// Timeout per individual lookup. 0 → 2s.
	Timeout time.Duration
}

// New returns an empty cache.
func New(opts Options) *Cache {
	if opts.Lookup == nil {
		opts.Lookup = defaultLookup
	}
	if opts.Timeout <= 0 {
		opts.Timeout = 2 * time.Second
	}
	return &Cache{
		lookup:  opts.Lookup,
		timeout: opts.Timeout,
		entries: make(map[netip.Addr]*entry),
	}
}

// Lookup returns the cached hostname for addr, performing a lookup if
// needed. Returns ("", nil) when the reverse lookup succeeded but returned
// no name, and ("", err) when the lookup itself failed. Callers typically
// just want the string, in which case they can ignore the error.
func (c *Cache) Lookup(ctx context.Context, addr netip.Addr) (string, error) {
	c.mu.Lock()
	e, ok := c.entries[addr]
	if !ok {
		e = &entry{}
		c.entries[addr] = e
	}
	c.mu.Unlock()

	e.once.Do(func() {
		lookupCtx, cancel := context.WithTimeout(ctx, c.timeout)
		defer cancel()
		name, err := c.lookup(lookupCtx, addr)
		e.name = strings.TrimSuffix(name, ".")
		e.err = err
	})
	return e.name, e.err
}

// defaultLookup wraps net.DefaultResolver.LookupAddr. Exposed as a
// function-typed var so tests can stub the concrete PTR call without
// hitting the network.
var defaultLookup = func(ctx context.Context, addr netip.Addr) (string, error) {
	names, err := lookupAddr(ctx, addr.String())
	if err != nil {
		return "", err
	}
	if len(names) == 0 {
		return "", errors.New("no PTR records")
	}
	return names[0], nil
}

// lookupAddr is a package-level seam so unit tests can mock the raw
// network call while still exercising the surrounding error-mapping
// logic in defaultLookup.
var lookupAddr = func(ctx context.Context, addr string) ([]string, error) {
	return net.DefaultResolver.LookupAddr(ctx, addr)
}
