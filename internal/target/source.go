package target

import (
	"net/netip"
)

// source produces a sequence of addresses.
type source interface {
	next() (netip.Addr, bool)
	// count returns the number of addresses this source will produce, if
	// known. ok=false for hostname-style sources that have not been
	// resolved yet.
	count() (uint64, bool)
}

// singleSource yields one address, once.
type singleSource struct {
	addr netip.Addr
	done bool
}

func (s *singleSource) next() (netip.Addr, bool) {
	if s.done {
		return netip.Addr{}, false
	}
	s.done = true
	return s.addr, true
}

func (s *singleSource) count() (uint64, bool) { return 1, true }

// rangeSource yields addresses from start to end inclusive.
// Both addresses must be the same family. Iteration uses netip.Addr.Next.
type rangeSource struct {
	next_ netip.Addr
	end   netip.Addr
	done  bool
}

func newRangeSource(start, end netip.Addr) *rangeSource {
	return &rangeSource{next_: start, end: end}
}

func (s *rangeSource) next() (netip.Addr, bool) {
	if s.done {
		return netip.Addr{}, false
	}
	cur := s.next_
	if cur.Compare(s.end) == 0 {
		s.done = true
		return cur, true
	}
	nxt := cur.Next()
	if !nxt.IsValid() {
		s.done = true
		return cur, true
	}
	s.next_ = nxt
	return cur, true
}

func (s *rangeSource) count() (uint64, bool) {
	return addrDiff(s.next_, s.end)
}

// cidrSource yields all addresses in a prefix.
type cidrSource struct {
	inner *rangeSource
	size  uint64
	ok    bool
}

func newCIDRSource(p netip.Prefix) *cidrSource {
	p = p.Masked()
	start := p.Addr()
	end := lastInPrefix(p)
	size, ok := addrDiff(start, end)
	return &cidrSource{
		inner: newRangeSource(start, end),
		size:  size,
		ok:    ok,
	}
}

func (s *cidrSource) next() (netip.Addr, bool) { return s.inner.next() }

func (s *cidrSource) count() (uint64, bool) { return s.size, s.ok }

// sliceSource yields a pre-resolved slice of addresses (e.g., hostname
// results). The count is known once the source exists.
type sliceSource struct {
	addrs []netip.Addr
	idx   int
}

func newSliceSource(addrs []netip.Addr) *sliceSource {
	return &sliceSource{addrs: addrs}
}

func (s *sliceSource) next() (netip.Addr, bool) {
	if s.idx >= len(s.addrs) {
		return netip.Addr{}, false
	}
	a := s.addrs[s.idx]
	s.idx++
	return a, true
}

func (s *sliceSource) count() (uint64, bool) { return uint64(len(s.addrs)), true }
