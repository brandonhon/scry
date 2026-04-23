package output

import (
	"bytes"
	"encoding/json"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/bhoneycutt/scry/internal/portscan"
)

func sampleHost(up bool) portscan.HostResult {
	results := []portscan.Result{
		{Port: 22, State: portscan.StateOpen, RTT: 180 * time.Microsecond},
		{Port: 80, State: portscan.StateClosed, RTT: 50 * time.Microsecond},
		{Port: 443, State: portscan.StateFiltered, RTT: 1500 * time.Millisecond},
	}
	if !up {
		results[0].State = portscan.StateFiltered
	}
	return portscan.HostResult{
		Addr:    netip.MustParseAddr("192.168.1.10"),
		Started: time.Date(2026, 4, 23, 12, 0, 0, 0, time.UTC),
		Elapsed: 12 * time.Millisecond,
		Results: results,
	}
}

func TestParseFormat(t *testing.T) {
	cases := []struct {
		in   string
		want Format
		err  bool
	}{
		{"", FormatHuman, false},
		{"human", FormatHuman, false},
		{"json", FormatJSON, false},
		{"grep", FormatGrep, false},
		{"xml", "", true},
	}
	for _, c := range cases {
		got, err := ParseFormat(c.in)
		if (err != nil) != c.err {
			t.Errorf("ParseFormat(%q) err=%v wantErr=%v", c.in, err, c.err)
		}
		if err == nil && got != c.want {
			t.Errorf("ParseFormat(%q) = %v, want %v", c.in, got, c.want)
		}
	}
}

func TestServiceLookup(t *testing.T) {
	cases := map[uint16]string{
		22:   "ssh",
		80:   "http",
		443:  "https",
		3389: "rdp",
		8080: "http-proxy",
		4242: "", // unknown
	}
	for p, want := range cases {
		if got := Service(p); got != want {
			t.Errorf("Service(%d) = %q, want %q", p, got, want)
		}
	}
}

func TestHumanWriter_Plain(t *testing.T) {
	var buf bytes.Buffer
	w := New(FormatHuman, &buf, Options{Color: false, Verbose: 0})
	if err := w.Begin(); err != nil {
		t.Fatal(err)
	}
	if err := w.WriteHost(sampleHost(true)); err != nil {
		t.Fatal(err)
	}
	if err := w.WriteHost(sampleHost(false)); err != nil {
		t.Fatal(err)
	}
	if err := w.End(); err != nil {
		t.Fatal(err)
	}

	out := buf.String()
	if !strings.Contains(out, "UP") || !strings.Contains(out, "DOWN") {
		t.Fatalf("missing UP/DOWN badge in %q", out)
	}
	if !strings.Contains(out, "192.168.1.10") {
		t.Fatalf("missing host in %q", out)
	}
	if !strings.Contains(out, "22/tcp") {
		t.Fatalf("missing open port line in %q", out)
	}
	if !strings.Contains(out, "ssh") {
		t.Fatalf("service annotation missing in %q", out)
	}
	// Verbose=0: closed/filtered must be hidden.
	if strings.Contains(out, "closed") || strings.Contains(out, "filtered") {
		t.Fatalf("verbose=0 should hide closed/filtered; got %q", out)
	}
	if !strings.Contains(out, "scanned 2 host(s), 1 up") {
		t.Fatalf("summary missing in %q", out)
	}
}

func TestHumanWriter_Verbose(t *testing.T) {
	var buf bytes.Buffer
	w := New(FormatHuman, &buf, Options{Color: false, Verbose: 1})
	_ = w.Begin()
	_ = w.WriteHost(sampleHost(true))
	_ = w.End()

	out := buf.String()
	if !strings.Contains(out, "closed") || !strings.Contains(out, "filtered") {
		t.Fatalf("verbose=1 should reveal closed/filtered; got %q", out)
	}
}

func TestHumanWriter_NoANSIWhenColorOff(t *testing.T) {
	var buf bytes.Buffer
	w := New(FormatHuman, &buf, Options{Color: false})
	_ = w.Begin()
	_ = w.WriteHost(sampleHost(true))
	_ = w.End()
	if strings.Contains(buf.String(), "\x1b[") {
		t.Fatalf("plain mode leaked ANSI escape: %q", buf.String())
	}
}

func TestJSONWriter_NDJSON(t *testing.T) {
	var buf bytes.Buffer
	w := New(FormatJSON, &buf, Options{Verbose: 0})
	_ = w.Begin()
	_ = w.WriteHost(sampleHost(true))
	_ = w.WriteHost(sampleHost(false))
	_ = w.End()

	lines := strings.Split(strings.TrimRight(buf.String(), "\n"), "\n")
	if len(lines) != 2 {
		t.Fatalf("got %d lines, want 2 — buf=%q", len(lines), buf.String())
	}

	var h jsonHost
	if err := json.Unmarshal([]byte(lines[0]), &h); err != nil {
		t.Fatalf("unmarshal: %v (line=%q)", err, lines[0])
	}
	if h.Addr != "192.168.1.10" || !h.Up {
		t.Fatalf("unexpected host=%+v", h)
	}
	// Verbose=0: only the open port should appear.
	if len(h.Results) != 1 || h.Results[0].Port != 22 || h.Results[0].State != "open" {
		t.Fatalf("unexpected results=%+v", h.Results)
	}
	if h.Results[0].Service != "ssh" || h.Results[0].Proto != "tcp" {
		t.Fatalf("service/proto: %+v", h.Results[0])
	}
}

func TestGrepWriter_SingleLinePerHost(t *testing.T) {
	var buf bytes.Buffer
	w := New(FormatGrep, &buf, Options{Verbose: 0})
	_ = w.Begin()
	_ = w.WriteHost(sampleHost(true))
	_ = w.WriteHost(sampleHost(false))
	_ = w.End()

	lines := strings.Split(strings.TrimRight(buf.String(), "\n"), "\n")
	if len(lines) != 2 {
		t.Fatalf("got %d lines, want 2 — buf=%q", len(lines), buf.String())
	}
	if !strings.Contains(lines[0], "Status: up") || !strings.Contains(lines[0], "22/open/ssh") {
		t.Fatalf("missing status/ports in %q", lines[0])
	}
	if !strings.Contains(lines[1], "Status: down") || !strings.Contains(lines[1], "Ports: -") {
		t.Fatalf("down host should have Ports: - got %q", lines[1])
	}
}

func TestShouldColor_Honors_NoColorEnv(t *testing.T) {
	t.Setenv("NO_COLOR", "1")
	// Even with forceOn=true, the --no-color flag path is handled by the
	// caller; NO_COLOR from env should kill auto-detection.
	// Pass a non-file Writer so the os.File branch doesn't apply.
	got := ShouldColor(&bytes.Buffer{}, false, false)
	if got {
		t.Fatal("NO_COLOR should disable color")
	}
}

func TestShouldColor_ForceOff(t *testing.T) {
	if ShouldColor(&bytes.Buffer{}, true, true) {
		t.Fatal("forceOff should win")
	}
}
