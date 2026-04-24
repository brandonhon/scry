package output

import (
	"bytes"
	"net/netip"
	"strings"
	"testing"
)

func TestLiveWriter_RendersTableAndRedraws(t *testing.T) {
	var buf bytes.Buffer
	w := New(FormatLive, &buf, Options{Color: false})

	if err := w.Begin(); err != nil {
		t.Fatal(err)
	}
	// Three hosts in reverse-sort order to exercise the addr sort.
	addrs := []string{"192.168.1.30", "192.168.1.10", "192.168.1.20"}
	for _, a := range addrs {
		hr := sampleHost(true)
		hr.Addr = netip.MustParseAddr(a)
		if err := w.WriteHost(hr); err != nil {
			t.Fatal(err)
		}
	}
	if err := w.End(); err != nil {
		t.Fatal(err)
	}

	out := buf.String()
	for _, a := range addrs {
		if !strings.Contains(out, a) {
			t.Errorf("missing %s in live output", a)
		}
	}
	if !strings.Contains(out, "scanned 3 host(s), 3 up") {
		t.Fatalf("missing summary: %q", out)
	}
	// With three WriteHost calls the writer must emit cursor-up escapes.
	if !strings.Contains(out, "\x1b[") {
		t.Fatalf("no cursor-move escapes emitted: %q", out)
	}
}

func TestLiveWriter_EmptyRunEndsCleanly(t *testing.T) {
	var buf bytes.Buffer
	w := New(FormatLive, &buf, Options{Color: false})
	_ = w.Begin()
	_ = w.End()
	if !strings.Contains(buf.String(), "scanned 0 host(s)") {
		t.Fatalf("expected empty summary, got %q", buf.String())
	}
}

func TestParseFormat_Live(t *testing.T) {
	f, err := ParseFormat("live")
	if err != nil {
		t.Fatal(err)
	}
	if f != FormatLive {
		t.Fatalf("got %v", f)
	}
}
