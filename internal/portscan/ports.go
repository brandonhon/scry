package portscan

import (
	"fmt"
	"sort"
	"strconv"
	"strings"
)

// ParsePorts parses the -p flag into a deduplicated, order-preserving slice
// of ports.
//
// Supported forms (comma-separated, mixable):
//
//	22                single port
//	22,80,443         list
//	1-1024            range (inclusive)
//	-                 all ports 1..65535 (-p-)
//	top100 / top1000  bundled shortlists (see top.go)
func ParsePorts(spec string) ([]uint16, error) {
	spec = strings.TrimSpace(spec)
	if spec == "" {
		return nil, fmt.Errorf("empty port spec")
	}

	if spec == "-" {
		out := make([]uint16, 0, 65535)
		for p := 1; p <= 65535; p++ {
			out = append(out, uint16(p))
		}
		return out, nil
	}

	seen := make(map[uint16]struct{}, 32)
	out := make([]uint16, 0, 32)

	add := func(p uint16) {
		if _, ok := seen[p]; ok {
			return
		}
		seen[p] = struct{}{}
		out = append(out, p)
	}

	for _, raw := range strings.Split(spec, ",") {
		tok := strings.TrimSpace(raw)
		if tok == "" {
			continue
		}

		if strings.EqualFold(tok, "top100") {
			for _, p := range Top100() {
				add(p)
			}
			continue
		}
		if strings.EqualFold(tok, "top1000") {
			for _, p := range Top1000() {
				add(p)
			}
			continue
		}

		if strings.Contains(tok, "-") {
			lo, hi, err := parsePortRange(tok)
			if err != nil {
				return nil, err
			}
			for p := lo; p <= hi; p++ {
				add(uint16(p))
				if p == 65535 {
					break
				}
			}
			continue
		}

		n, err := parsePort(tok)
		if err != nil {
			return nil, err
		}
		add(n)
	}

	if len(out) == 0 {
		return nil, fmt.Errorf("port spec %q resolved to zero ports", spec)
	}
	return out, nil
}

func parsePort(s string) (uint16, error) {
	n, err := strconv.Atoi(s)
	if err != nil {
		return 0, fmt.Errorf("invalid port %q: %w", s, err)
	}
	if n < 1 || n > 65535 {
		return 0, fmt.Errorf("port %d out of range (1-65535)", n)
	}
	return uint16(n), nil
}

func parsePortRange(tok string) (int, int, error) {
	i := strings.IndexByte(tok, '-')
	left, right := tok[:i], tok[i+1:]
	if left == "" || right == "" {
		return 0, 0, fmt.Errorf("invalid port range %q", tok)
	}
	lo, err := parsePort(left)
	if err != nil {
		return 0, 0, err
	}
	hi, err := parsePort(right)
	if err != nil {
		return 0, 0, err
	}
	if lo > hi {
		return 0, 0, fmt.Errorf("invalid port range %q: start > end", tok)
	}
	return int(lo), int(hi), nil
}

// SortPorts returns a new slice of ports sorted ascending. Useful when
// presenting results; ParsePorts itself preserves input order.
func SortPorts(ps []uint16) []uint16 {
	out := make([]uint16, len(ps))
	copy(out, ps)
	sort.Slice(out, func(i, j int) bool { return out[i] < out[j] })
	return out
}
