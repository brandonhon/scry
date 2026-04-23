package target

import (
	"net/netip"
)

// lastInPrefix returns the highest address contained in p. IPv4 only —
// scry's parser rejects v6 targets, so every prefix reaching this
// helper is guaranteed v4.
func lastInPrefix(p netip.Prefix) netip.Addr {
	p = p.Masked()
	bits := p.Bits()
	b := p.Addr().As4()
	host := 32 - bits
	for i := 3; host > 0; i-- {
		n := host
		if n > 8 {
			n = 8
		}
		b[i] |= byte((1 << n) - 1)
		host -= n
	}
	return netip.AddrFrom4(b)
}

// addrDiff returns (b - a + 1), the inclusive count from a to b, and
// ok=true if the result fits in uint64. Requires both addresses to be
// IPv4 and a <= b; otherwise returns (0, false).
func addrDiff(a, b netip.Addr) (uint64, bool) {
	if !a.IsValid() || !b.IsValid() {
		return 0, false
	}
	if !a.Is4() || !b.Is4() {
		return 0, false
	}
	if a.Compare(b) > 0 {
		return 0, false
	}
	ab := a.As4()
	bb := b.As4()
	ai := uint32(ab[0])<<24 | uint32(ab[1])<<16 | uint32(ab[2])<<8 | uint32(ab[3])
	bi := uint32(bb[0])<<24 | uint32(bb[1])<<16 | uint32(bb[2])<<8 | uint32(bb[3])
	return uint64(bi-ai) + 1, true
}
