package target

import (
	"fmt"
	"net/netip"
	"os"
	"strconv"
	"strings"
)

var defaultFileReader FileReader = os.ReadFile

// parseSpec parses a single user-supplied spec (which may be comma-separated)
// and appends any produced sources to it.
func parseSpec(spec string, opts *Options, it *Iterator) error {
	for _, tok := range splitCSV(spec) {
		if err := parseToken(tok, opts, it); err != nil {
			return err
		}
	}
	return nil
}

// parseToken parses one non-comma-separated token.
func parseToken(tok string, opts *Options, it *Iterator) error {
	tok = strings.TrimSpace(tok)
	if tok == "" {
		return nil
	}

	if strings.HasPrefix(tok, "@") {
		return parseFileToken(tok[1:], opts, it)
	}

	if strings.Contains(tok, "/") {
		p, err := netip.ParsePrefix(tok)
		if err != nil {
			return fmt.Errorf("target %q: %w", tok, err)
		}
		if err := requireIPv4(p.Addr(), tok); err != nil {
			return err
		}
		it.appendSource(newCIDRSource(p))
		return nil
	}

	if addr, err := netip.ParseAddr(tok); err == nil {
		addr = addr.Unmap()
		if err := requireIPv4(addr, tok); err != nil {
			return err
		}
		it.appendSource(&singleSource{addr: addr})
		return nil
	}

	if strings.Contains(tok, "-") {
		if rng, ok := parseRange(tok); ok {
			if err := requireIPv4(rng.start, tok); err != nil {
				return err
			}
			it.appendSource(newRangeSource(rng.start, rng.end))
			return nil
		}
	}

	// Hostname. Resolve eagerly; produce a sliceSource with the results.
	addrs, err := opts.Resolver(opts.Context, tok)
	if err != nil {
		return fmt.Errorf("target %q: resolve: %w", tok, err)
	}
	normalized := make([]netip.Addr, 0, len(addrs))
	for _, a := range addrs {
		a = a.Unmap()
		if !a.Is4() {
			continue // drop v6 resolutions; scry is IPv4-only in scope today
		}
		normalized = append(normalized, a)
	}
	if len(normalized) == 0 {
		return fmt.Errorf("target %q: no IPv4 addresses resolved (scry is IPv4-only; see scry-plan.md §10 #22)", tok)
	}
	it.appendSource(newSliceSource(normalized))
	return nil
}

// requireIPv4 rejects any non-v4 address with a clear, actionable error
// pointing users at the IPv6-support branch. scry is IPv4-only in scope
// until that work returns to main; see plan §10 #22.
func requireIPv4(a netip.Addr, tok string) error {
	if a.Is4() || a.Is4In6() {
		return nil
	}
	return fmt.Errorf("target %q: IPv6 is not supported in this release (scry is IPv4-only; IPv6 work lives on the feat/ipv6-support branch, see scry-plan.md §10 #22)", tok)
}

// parseFileToken reads path and parses each non-blank non-comment line as a
// spec. Inline comments (# ...) are stripped. Nested @file references are
// rejected.
func parseFileToken(path string, opts *Options, it *Iterator) error {
	data, err := opts.FileReader(path)
	if err != nil {
		return fmt.Errorf("read %s: %w", path, err)
	}
	for lineNo, raw := range strings.Split(string(data), "\n") {
		line := stripComment(raw)
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		if strings.HasPrefix(line, "@") {
			return fmt.Errorf("%s:%d: nested @file references are not supported", path, lineNo+1)
		}
		if err := parseSpec(line, opts, it); err != nil {
			return fmt.Errorf("%s:%d: %w", path, lineNo+1, err)
		}
	}
	return nil
}

// stripComment removes everything from the first '#' to end of line.
func stripComment(s string) string {
	if i := strings.IndexByte(s, '#'); i >= 0 {
		return s[:i]
	}
	return s
}

// splitCSV splits on commas, trimming whitespace. Empty fields are dropped.
func splitCSV(s string) []string {
	parts := strings.Split(s, ",")
	out := parts[:0]
	for _, p := range parts {
		if t := strings.TrimSpace(p); t != "" {
			out = append(out, t)
		}
	}
	return out
}

type addrRange struct {
	start, end netip.Addr
}

// parseRange parses a range expression. Returns the range and ok=true if the
// token is a syntactically valid range; ok=false otherwise (caller can fall
// through to other interpretations).
func parseRange(tok string) (addrRange, bool) {
	i := strings.IndexByte(tok, '-')
	if i < 0 {
		return addrRange{}, false
	}
	left, right := tok[:i], tok[i+1:]
	if left == "" || right == "" {
		return addrRange{}, false
	}

	start, err := netip.ParseAddr(left)
	if err != nil {
		return addrRange{}, false
	}
	start = start.Unmap()

	// Arbitrary range: right side is also an address of the same family.
	if end, err := netip.ParseAddr(right); err == nil {
		end = end.Unmap()
		if start.Is4() != end.Is4() {
			return addrRange{}, false
		}
		if start.Compare(end) > 0 {
			return addrRange{}, false
		}
		return addrRange{start: start, end: end}, true
	}

	// Last-octet short form (IPv4 only): right side is an integer 0-255.
	if !start.Is4() {
		return addrRange{}, false
	}
	last, err := strconv.Atoi(right)
	if err != nil || last < 0 || last > 255 {
		return addrRange{}, false
	}
	b := start.As4()
	if int(b[3]) > last {
		return addrRange{}, false
	}
	b[3] = byte(last)
	end := netip.AddrFrom4(b)
	return addrRange{start: start, end: end}, true
}

// buildExcludes parses each exclude spec into an excludeSet.
func buildExcludes(specs []string, opts *Options) (excludeSet, error) {
	var set excludeSet
	for _, spec := range specs {
		for _, tok := range splitCSV(spec) {
			rng, err := parseExclude(tok)
			if err != nil {
				return excludeSet{}, err
			}
			set.ranges = append(set.ranges, rng)
		}
	}
	return set, nil
}

// parseExclude parses one exclude token. Excludes must be concrete: single IP,
// range, or CIDR. Hostnames and @file are not accepted here to keep the
// predicate cheap and deterministic.
func parseExclude(tok string) (addrRange, error) {
	tok = strings.TrimSpace(tok)
	if tok == "" {
		return addrRange{}, fmt.Errorf("empty exclude")
	}
	if strings.HasPrefix(tok, "@") {
		return addrRange{}, fmt.Errorf("exclude %q: @file not supported for --exclude", tok)
	}
	if strings.Contains(tok, "/") {
		p, err := netip.ParsePrefix(tok)
		if err != nil {
			return addrRange{}, fmt.Errorf("exclude %q: %w", tok, err)
		}
		p = p.Masked()
		if err := requireIPv4(p.Addr(), tok); err != nil {
			return addrRange{}, err
		}
		return addrRange{start: p.Addr(), end: lastInPrefix(p)}, nil
	}
	if addr, err := netip.ParseAddr(tok); err == nil {
		addr = addr.Unmap()
		if err := requireIPv4(addr, tok); err != nil {
			return addrRange{}, err
		}
		return addrRange{start: addr, end: addr}, nil
	}
	if r, ok := parseRange(tok); ok {
		if err := requireIPv4(r.start, tok); err != nil {
			return addrRange{}, err
		}
		return r, nil
	}
	return addrRange{}, fmt.Errorf("exclude %q: not a valid single/range/CIDR", tok)
}

// excludeSet is a predicate set of address ranges.
type excludeSet struct {
	ranges []addrRange
}

func (s excludeSet) contains(a netip.Addr) bool {
	for _, r := range s.ranges {
		if r.start.Is4() != a.Is4() {
			continue
		}
		if a.Compare(r.start) >= 0 && a.Compare(r.end) <= 0 {
			return true
		}
	}
	return false
}
