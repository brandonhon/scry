package target

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"reflect"
	"testing"
)

// collect drains an iterator to a slice.
func collect(t *testing.T, it *Iterator, limit int) []netip.Addr {
	t.Helper()
	var out []netip.Addr
	for i := 0; i < limit; i++ {
		a, ok := it.Next()
		if !ok {
			return out
		}
		out = append(out, a)
	}
	// If we hit the limit without exhausting, flag it — something is wrong.
	if _, ok := it.Next(); ok {
		t.Fatalf("iterator produced more than limit=%d addrs", limit)
	}
	return out
}

func mustAddr(t *testing.T, s string) netip.Addr {
	t.Helper()
	a, err := netip.ParseAddr(s)
	if err != nil {
		t.Fatalf("ParseAddr(%q): %v", s, err)
	}
	return a
}

func addrs(t *testing.T, ss ...string) []netip.Addr {
	t.Helper()
	out := make([]netip.Addr, len(ss))
	for i, s := range ss {
		out[i] = mustAddr(t, s)
	}
	return out
}

// -- parser table tests -------------------------------------------------------

func TestParse_Forms(t *testing.T) {
	cases := []struct {
		name  string
		spec  string
		want  []netip.Addr
		total uint64
	}{
		{
			name:  "single IPv4",
			spec:  "192.168.1.10",
			want:  addrs(t, "192.168.1.10"),
			total: 1,
		},
		{
			name:  "single IPv6",
			spec:  "2001:db8::1",
			want:  addrs(t, "2001:db8::1"),
			total: 1,
		},
		{
			name:  "IPv6 loopback",
			spec:  "::1",
			want:  addrs(t, "::1"),
			total: 1,
		},
		{
			name:  "last-octet range",
			spec:  "192.168.1.10-12",
			want:  addrs(t, "192.168.1.10", "192.168.1.11", "192.168.1.12"),
			total: 3,
		},
		{
			name:  "last-octet range equal endpoints",
			spec:  "10.0.0.5-5",
			want:  addrs(t, "10.0.0.5"),
			total: 1,
		},
		{
			name:  "arbitrary IPv4 range crossing octet boundary",
			spec:  "192.168.1.254-192.168.2.1",
			want:  addrs(t, "192.168.1.254", "192.168.1.255", "192.168.2.0", "192.168.2.1"),
			total: 4,
		},
		{
			name:  "arbitrary IPv6 range",
			spec:  "2001:db8::1-2001:db8::3",
			want:  addrs(t, "2001:db8::1", "2001:db8::2", "2001:db8::3"),
			total: 3,
		},
		{
			name:  "IPv4 CIDR /30",
			spec:  "192.168.1.0/30",
			want:  addrs(t, "192.168.1.0", "192.168.1.1", "192.168.1.2", "192.168.1.3"),
			total: 4,
		},
		{
			name:  "IPv4 CIDR unaligned input masked down",
			spec:  "192.168.1.5/30",
			want:  addrs(t, "192.168.1.4", "192.168.1.5", "192.168.1.6", "192.168.1.7"),
			total: 4,
		},
		{
			name:  "IPv6 CIDR /126",
			spec:  "2001:db8::/126",
			want:  addrs(t, "2001:db8::", "2001:db8::1", "2001:db8::2", "2001:db8::3"),
			total: 4,
		},
		{
			name:  "single-host /32",
			spec:  "10.0.0.1/32",
			want:  addrs(t, "10.0.0.1"),
			total: 1,
		},
		{
			name:  "single-host v6 /128",
			spec:  "::1/128",
			want:  addrs(t, "::1"),
			total: 1,
		},
		{
			name:  "comma-separated mix",
			spec:  "10.0.0.1, 10.0.0.5-7 ,192.168.1.0/30",
			want:  addrs(t, "10.0.0.1", "10.0.0.5", "10.0.0.6", "10.0.0.7", "192.168.1.0", "192.168.1.1", "192.168.1.2", "192.168.1.3"),
			total: 8,
		},
	}

	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			it, err := Parse([]string{tc.spec}, Options{})
			if err != nil {
				t.Fatalf("Parse(%q): %v", tc.spec, err)
			}
			got := collect(t, it, 10_000)
			if !reflect.DeepEqual(got, tc.want) {
				t.Fatalf("addresses mismatch\n got: %v\nwant: %v", got, tc.want)
			}
			total, ok := it.Total()
			if !ok {
				t.Fatalf("Total() reported unknown; want known=%d", tc.total)
			}
			if total != tc.total {
				t.Fatalf("Total() = %d, want %d", total, tc.total)
			}
		})
	}
}

// -- parser error cases -------------------------------------------------------

func TestParse_Errors(t *testing.T) {
	cases := []struct {
		name string
		spec string
	}{
		{"bad CIDR bits", "192.168.1.0/33"},
		{"bad IP", "999.1.1.1"},
		{"reverse range", "192.168.1.10-192.168.1.1"},
		{"mixed-family range", "192.168.1.1-2001:db8::1"},
		{"last-octet below start", "192.168.1.10-5"},
		{"last-octet overflow", "192.168.1.10-256"},
	}
	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			_, err := Parse([]string{tc.spec}, Options{
				Resolver: func(context.Context, string) ([]netip.Addr, error) {
					return nil, errors.New("dns disabled in test")
				},
			})
			if err == nil {
				t.Fatalf("expected error for %q", tc.spec)
			}
		})
	}
}

// -- hostname resolution ------------------------------------------------------

func TestParse_Hostname_UsesInjectedResolver(t *testing.T) {
	called := 0
	opts := Options{
		Resolver: func(_ context.Context, host string) ([]netip.Addr, error) {
			called++
			if host != "scan.example.com" {
				t.Fatalf("unexpected host %q", host)
			}
			return []netip.Addr{mustAddr(t, "10.1.1.1"), mustAddr(t, "10.1.1.2")}, nil
		},
	}
	it, err := Parse([]string{"scan.example.com"}, opts)
	if err != nil {
		t.Fatal(err)
	}
	if called != 1 {
		t.Fatalf("resolver called %d times, want 1", called)
	}
	got := collect(t, it, 10)
	want := addrs(t, "10.1.1.1", "10.1.1.2")
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got %v, want %v", got, want)
	}
	total, ok := it.Total()
	if !ok || total != 2 {
		t.Fatalf("Total() = (%d, %v), want (2, true)", total, ok)
	}
}

func TestParse_Hostname_ResolverError(t *testing.T) {
	opts := Options{
		Resolver: func(context.Context, string) ([]netip.Addr, error) {
			return nil, errors.New("nxdomain")
		},
	}
	_, err := Parse([]string{"no-such-host.invalid"}, opts)
	if err == nil {
		t.Fatal("expected error")
	}
}

func TestParse_Hostname_ZeroAddrs(t *testing.T) {
	opts := Options{
		Resolver: func(context.Context, string) ([]netip.Addr, error) {
			return nil, nil
		},
	}
	_, err := Parse([]string{"empty.example"}, opts)
	if err == nil {
		t.Fatal("expected error for zero-addr resolution")
	}
}

// -- @file --------------------------------------------------------------------

func TestParse_File(t *testing.T) {
	content := `# comment line
10.0.0.1
10.0.0.2  # trailing comment
  10.0.0.3 , 10.0.0.4

192.168.1.0/30
`
	opts := Options{
		FileReader: func(path string) ([]byte, error) {
			if path != "targets.txt" {
				return nil, fmt.Errorf("unexpected path %q", path)
			}
			return []byte(content), nil
		},
	}
	it, err := Parse([]string{"@targets.txt"}, opts)
	if err != nil {
		t.Fatal(err)
	}
	got := collect(t, it, 100)
	want := addrs(t,
		"10.0.0.1", "10.0.0.2", "10.0.0.3", "10.0.0.4",
		"192.168.1.0", "192.168.1.1", "192.168.1.2", "192.168.1.3",
	)
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got %v\nwant %v", got, want)
	}
}

func TestParse_File_NestedRejected(t *testing.T) {
	opts := Options{
		FileReader: func(path string) ([]byte, error) {
			return []byte("@other.txt\n"), nil
		},
	}
	_, err := Parse([]string{"@targets.txt"}, opts)
	if err == nil {
		t.Fatal("expected error for nested @file")
	}
}

func TestParse_File_ReadError(t *testing.T) {
	opts := Options{
		FileReader: func(path string) ([]byte, error) {
			return nil, errors.New("boom")
		},
	}
	_, err := Parse([]string{"@targets.txt"}, opts)
	if err == nil {
		t.Fatal("expected error when FileReader fails")
	}
}

// -- excludes -----------------------------------------------------------------

func TestParse_Excludes(t *testing.T) {
	cases := []struct {
		name     string
		spec     string
		excludes []string
		want     []netip.Addr
	}{
		{
			name:     "exclude single",
			spec:     "192.168.1.0/30",
			excludes: []string{"192.168.1.2"},
			want:     addrs(t, "192.168.1.0", "192.168.1.1", "192.168.1.3"),
		},
		{
			name:     "exclude cidr",
			spec:     "10.0.0.0/29",
			excludes: []string{"10.0.0.4/30"},
			want:     addrs(t, "10.0.0.0", "10.0.0.1", "10.0.0.2", "10.0.0.3"),
		},
		{
			name:     "exclude range",
			spec:     "10.0.0.1-10",
			excludes: []string{"10.0.0.3-7"},
			want:     addrs(t, "10.0.0.1", "10.0.0.2", "10.0.0.8", "10.0.0.9", "10.0.0.10"),
		},
		{
			name:     "exclude comma-separated list",
			spec:     "10.0.0.0/30",
			excludes: []string{"10.0.0.1,10.0.0.2"},
			want:     addrs(t, "10.0.0.0", "10.0.0.3"),
		},
	}
	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			it, err := Parse([]string{tc.spec}, Options{Excludes: tc.excludes})
			if err != nil {
				t.Fatal(err)
			}
			got := collect(t, it, 100)
			if !reflect.DeepEqual(got, tc.want) {
				t.Fatalf("got %v\nwant %v", got, tc.want)
			}
		})
	}
}

func TestParse_Exclude_Invalid(t *testing.T) {
	_, err := Parse([]string{"10.0.0.1"}, Options{Excludes: []string{"not-an-ip"}})
	if err == nil {
		t.Fatal("expected error")
	}
}

func TestParse_Exclude_FileRejected(t *testing.T) {
	_, err := Parse([]string{"10.0.0.1"}, Options{Excludes: []string{"@file.txt"}})
	if err == nil {
		t.Fatal("expected error — @file not allowed in excludes")
	}
}

// -- laziness / scale ---------------------------------------------------------

func TestIterator_LargeCIDR_LazyTotal(t *testing.T) {
	// /8 would be 16M addresses — verify Total() reports correctly and we can
	// produce a few without allocating the whole range.
	it, err := Parse([]string{"10.0.0.0/8"}, Options{})
	if err != nil {
		t.Fatal(err)
	}
	total, ok := it.Total()
	if !ok || total != 1<<24 {
		t.Fatalf("Total() = (%d, %v), want (%d, true)", total, ok, 1<<24)
	}
	// Pull first few, verify they start at the network address.
	first := [3]netip.Addr{}
	for i := range first {
		a, ok := it.Next()
		if !ok {
			t.Fatalf("ran out at i=%d", i)
		}
		first[i] = a
	}
	want := [3]netip.Addr{mustAddr(t, "10.0.0.0"), mustAddr(t, "10.0.0.1"), mustAddr(t, "10.0.0.2")}
	if first != want {
		t.Fatalf("got %v, want %v", first, want)
	}
}

func TestIterator_V6LargePrefix_TotalUnknown(t *testing.T) {
	// /0 v6 has 2^128 addresses — can't fit in uint64.
	it, err := Parse([]string{"::/0"}, Options{})
	if err != nil {
		t.Fatal(err)
	}
	_, ok := it.Total()
	if ok {
		t.Fatalf("Total() reported known for /0; expected unknown")
	}
	// First address should still iterate.
	a, ok := it.Next()
	if !ok {
		t.Fatal("Next() returned !ok on fresh /0")
	}
	if a != mustAddr(t, "::") {
		t.Fatalf("first addr = %v, want ::", a)
	}
}

// -- multiple specs -----------------------------------------------------------

func TestParse_MultipleSpecs(t *testing.T) {
	it, err := Parse([]string{"10.0.0.1", "10.0.0.2-3"}, Options{})
	if err != nil {
		t.Fatal(err)
	}
	got := collect(t, it, 10)
	want := addrs(t, "10.0.0.1", "10.0.0.2", "10.0.0.3")
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got %v, want %v", got, want)
	}
}

// -- addr helpers -------------------------------------------------------------

func TestLastInPrefix(t *testing.T) {
	cases := []struct {
		in   string
		want string
	}{
		{"192.168.1.0/24", "192.168.1.255"},
		{"192.168.1.0/30", "192.168.1.3"},
		{"10.0.0.0/8", "10.255.255.255"},
		{"10.0.0.1/32", "10.0.0.1"},
		{"2001:db8::/126", "2001:db8::3"},
		{"2001:db8::/64", "2001:db8::ffff:ffff:ffff:ffff"},
		{"::/0", "ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff"},
	}
	for _, tc := range cases {
		p := netip.MustParsePrefix(tc.in)
		got := lastInPrefix(p)
		if got.String() != tc.want {
			t.Errorf("lastInPrefix(%s) = %s, want %s", tc.in, got, tc.want)
		}
	}
}

func TestAddrDiff(t *testing.T) {
	cases := []struct {
		a, b   string
		n      uint64
		ok     bool
	}{
		{"10.0.0.0", "10.0.0.0", 1, true},
		{"10.0.0.0", "10.0.0.9", 10, true},
		{"0.0.0.0", "255.255.255.255", 1 << 32, true},
		{"2001:db8::", "2001:db8::ff", 256, true},
		{"10.0.0.5", "10.0.0.1", 0, false}, // reversed
	}
	for _, tc := range cases {
		got, ok := addrDiff(mustAddr(t, tc.a), mustAddr(t, tc.b))
		if got != tc.n || ok != tc.ok {
			t.Errorf("addrDiff(%s, %s) = (%d, %v), want (%d, %v)", tc.a, tc.b, got, ok, tc.n, tc.ok)
		}
	}
}
