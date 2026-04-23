package portscan

import (
	"reflect"
	"testing"
)

func TestParsePorts_Forms(t *testing.T) {
	cases := []struct {
		name string
		in   string
		want []uint16
	}{
		{"single", "22", []uint16{22}},
		{"list", "22,80,443", []uint16{22, 80, 443}},
		{"range", "1-5", []uint16{1, 2, 3, 4, 5}},
		{"list+range mix", "22,80-82,443", []uint16{22, 80, 81, 82, 443}},
		{"dedup preserves first occurrence", "80,22,80,443,22", []uint16{80, 22, 443}},
		{"whitespace tolerated", " 22 , 80 ", []uint16{22, 80}},
		{"single-element range", "22-22", []uint16{22}},
		{"range to 65535 upper", "65534-65535", []uint16{65534, 65535}},
	}
	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			got, err := ParsePorts(tc.in)
			if err != nil {
				t.Fatalf("ParsePorts(%q): %v", tc.in, err)
			}
			if !reflect.DeepEqual(got, tc.want) {
				t.Fatalf("got %v, want %v", got, tc.want)
			}
		})
	}
}

func TestParsePorts_AllPorts(t *testing.T) {
	got, err := ParsePorts("-")
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 65535 {
		t.Fatalf("len(-) = %d, want 65535", len(got))
	}
	if got[0] != 1 || got[len(got)-1] != 65535 {
		t.Fatalf("bounds: first=%d last=%d", got[0], got[len(got)-1])
	}
}

func TestParsePorts_TopShortlists(t *testing.T) {
	got, err := ParsePorts("top100")
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 100 {
		t.Fatalf("top100 len = %d", len(got))
	}
	if got[0] != 80 {
		t.Fatalf("top100[0] = %d, want 80 (most common)", got[0])
	}

	got1k, err := ParsePorts("top1000")
	if err != nil {
		t.Fatal(err)
	}
	if len(got1k) != 1000 {
		t.Fatalf("top1000 len = %d", len(got1k))
	}
	// top1000 must begin with top100 in the same order.
	for i, p := range got {
		if got1k[i] != p {
			t.Fatalf("top1000[%d] = %d, want %d (top100 prefix)", i, got1k[i], p)
		}
	}
}

func TestParsePorts_TopMixedWithList(t *testing.T) {
	// Pick a port guaranteed not to be in top100.
	const extra uint16 = 65530
	got, err := ParsePorts("top100,65530")
	if err != nil {
		t.Fatal(err)
	}
	if got[len(got)-1] != extra {
		t.Fatalf("last port = %d, want %d", got[len(got)-1], extra)
	}
	if len(got) != 101 {
		t.Fatalf("len = %d, want 101", len(got))
	}
}

func TestParsePorts_Errors(t *testing.T) {
	cases := []struct {
		name string
		in   string
	}{
		{"empty", ""},
		{"zero port", "0"},
		{"overflow", "70000"},
		{"negative", "-1-5"},
		{"reverse range", "80-22"},
		{"bad token", "abc"},
		{"dash only token", "-22"},
		{"trailing dash", "22-"},
	}
	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			if _, err := ParsePorts(tc.in); err == nil {
				t.Fatalf("expected error for %q", tc.in)
			}
		})
	}
}

func TestTopLists_ReturnCopies(t *testing.T) {
	a := Top100()
	a[0] = 0
	b := Top100()
	if b[0] == 0 {
		t.Fatal("Top100 must return a copy")
	}
}
