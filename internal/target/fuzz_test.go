package target

import (
	"context"
	"errors"
	"net/netip"
	"testing"
)

// FuzzParse feeds arbitrary strings into Parse with resolution/file-read
// disabled so the fuzzer can't hang on DNS or try to read files outside
// the sandbox. The contract: Parse either returns an error, or returns
// an Iterator whose Next+Total calls do not panic.
func FuzzParse(f *testing.F) {
	seeds := []string{
		"192.168.1.10",
		"192.168.1.10-50",
		"192.168.1.10-192.168.2.20",
		"192.168.1.0/24",
		"10.0.0.1,10.0.0.2",
		"2001:db8::/120",
		"::1",
		"2001:db8::1-2001:db8::ff",
		"",
		"   ",
		",,,,",
		"-",
		"-5",
		"5-",
		"999.999.999.999",
		"192.168.1.0/33",
		"@nope",
		"a,b,c",
		string([]byte{0, 1, 2, 3}),
	}
	for _, s := range seeds {
		f.Add(s)
	}

	opts := Options{
		Resolver: func(context.Context, string) ([]netip.Addr, error) {
			return nil, errors.New("dns disabled in fuzz")
		},
		FileReader: func(string) ([]byte, error) {
			return nil, errors.New("file IO disabled in fuzz")
		},
	}

	f.Fuzz(func(t *testing.T, spec string) {
		it, err := Parse([]string{spec}, opts)
		if err != nil {
			return
		}
		// Walk a bounded number of addresses; a /0 would be infinite.
		for i := 0; i < 128; i++ {
			if _, ok := it.Next(); !ok {
				break
			}
		}
		_, _ = it.Total()
	})
}

// FuzzParseExclude exercises the exclude parser, which has a tighter
// grammar (no @file, no hostnames).
func FuzzParseExclude(f *testing.F) {
	for _, s := range []string{
		"10.0.0.1", "10.0.0.0/24", "10.0.0.1-5", "10.0.0.1,10.0.0.2",
		"", "-", "not-an-ip", "10.0.0.1/33", "@file", "2001:db8::/120",
	} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, spec string) {
		_, _ = Parse([]string{"10.0.0.1"}, Options{Excludes: []string{spec}})
	})
}

// FuzzParseRange targets the range-detection fallthrough path directly.
func FuzzParseRange(f *testing.F) {
	for _, s := range []string{
		"10.0.0.1-5", "10.0.0.1-10.0.0.5", "2001:db8::1-2001:db8::ff",
		"", "-", "10.0.0.1-", "-10.0.0.5", "10.0.0.5-10.0.0.1",
	} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, tok string) {
		// parseRange must not panic on any input.
		_, _ = parseRange(tok)
	})
}
