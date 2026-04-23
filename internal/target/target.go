// Package target parses target specifications (IPs, ranges, CIDR, hostnames,
// @file references) into a lazy iterator of addresses.
//
// Supported input forms (see §4.1 of scry-plan.md):
//
//	192.168.1.10                  single IPv4
//	::1                           single IPv6
//	192.168.1.10-50               last-octet IPv4 range
//	192.168.1.10-192.168.2.20     arbitrary IPv4 range
//	2001:db8::1-2001:db8::ff      arbitrary IPv6 range
//	192.168.1.0/24                IPv4 CIDR
//	2001:db8::/120                IPv6 CIDR
//	example.com                   hostname (resolved via Options.Resolver)
//	@targets.txt                  file, one target per line, # comments allowed
//
// Any input may itself be a comma-separated list. Whitespace around tokens is
// stripped.
package target

import (
	"context"
	"net"
	"net/netip"
)

// Resolver resolves a hostname to one or more addresses.
type Resolver func(ctx context.Context, host string) ([]netip.Addr, error)

// FileReader reads the contents of a file referenced via @path.
type FileReader func(path string) ([]byte, error)

// Options tunes parser behavior. All fields are optional; zero values are sane.
type Options struct {
	// Excludes are target specs (single, range, CIDR) whose addresses will be
	// skipped by the iterator.
	Excludes []string

	// Resolver is called for hostname targets. If nil, net.DefaultResolver is
	// used. Set to a function returning an error to forbid DNS.
	Resolver Resolver

	// FileReader is called for @file targets. If nil, os.ReadFile is used.
	FileReader FileReader

	// Context is passed to the Resolver. If nil, context.Background() is used.
	Context context.Context
}

// Iterator yields target addresses lazily. It is not safe for concurrent use.
type Iterator struct {
	sources []source
	idx     int
	skip    excludeSet
	total   uint64
	totalOk bool
}

// Next returns the next address and true, or zero-value and false when done.
func (it *Iterator) Next() (netip.Addr, bool) {
	for it.idx < len(it.sources) {
		addr, ok := it.sources[it.idx].next()
		if !ok {
			it.idx++
			continue
		}
		if it.skip.contains(addr) {
			continue
		}
		return addr, true
	}
	return netip.Addr{}, false
}

// Total returns the total number of addresses this iterator will produce,
// if known statically, and a second value indicating whether the count is
// known. The count is not known when any source is a hostname that has not
// yet been resolved. Excludes are not subtracted from the count.
func (it *Iterator) Total() (uint64, bool) {
	return it.total, it.totalOk
}

// Parse parses one or more target specs and returns an iterator. Each spec
// may itself be a comma-separated list.
func Parse(specs []string, opts Options) (*Iterator, error) {
	if opts.Context == nil {
		opts.Context = context.Background()
	}
	if opts.Resolver == nil {
		opts.Resolver = defaultResolver
	}
	if opts.FileReader == nil {
		opts.FileReader = defaultFileReader
	}

	it := &Iterator{totalOk: true}

	for _, spec := range specs {
		if err := parseSpec(spec, &opts, it); err != nil {
			return nil, err
		}
	}

	skip, err := buildExcludes(opts.Excludes, &opts)
	if err != nil {
		return nil, err
	}
	it.skip = skip

	return it, nil
}

// appendSource adds a source to the iterator and updates the total count.
func (it *Iterator) appendSource(s source) {
	it.sources = append(it.sources, s)
	n, ok := s.count()
	if !ok {
		it.totalOk = false
		return
	}
	it.total += n
}

func defaultResolver(ctx context.Context, host string) ([]netip.Addr, error) {
	ips, err := net.DefaultResolver.LookupNetIP(ctx, "ip", host)
	if err != nil {
		return nil, err
	}
	out := make([]netip.Addr, 0, len(ips))
	for _, ip := range ips {
		out = append(out, ip.Unmap())
	}
	return out, nil
}
