package output

import (
	"fmt"
	"io"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/charmbracelet/lipgloss"

	"github.com/brandonhon/scry/internal/portscan"
)

// liveHumanWriter redraws a single host-summary table in place instead
// of streaming per-host blocks. Use the `--live` flag on an interactive
// terminal. Non-TTY callers should route to humanWriter.
//
// Implementation: buffers every host result, sorts by address, and
// repaints the screen each WriteHost using bare ANSI cursor moves.
// Lipgloss renders the inner styling; we handle the redraw loop so we
// don't drag in bubbletea.
type liveHumanWriter struct {
	w     io.Writer
	opts  Options
	style humanStyle

	mu        sync.Mutex
	hosts     map[string]portscan.HostResult
	order     []string // sorted list of addrs, rebuilt on each draw
	linesDrew int
	start     time.Time
}

func newLiveHumanWriter(w io.Writer, opts Options) *liveHumanWriter {
	return &liveHumanWriter{
		w:     w,
		opts:  opts,
		style: buildStyle(opts.Color),
		hosts: make(map[string]portscan.HostResult, 64),
		// start is set here so the field is only written once, outside
		// any lock; Begin() and End() then read it under the mutex.
		start: time.Now(),
	}
}

func (h *liveHumanWriter) Begin() error {
	// Hide cursor during the scan; restore on End. start is set at
	// construction — Begin intentionally does not touch it so the
	// field has a single writer.
	if h.opts.Color {
		_, _ = fmt.Fprint(h.w, "\x1b[?25l")
	}
	return nil
}

func (h *liveHumanWriter) WriteHost(hr portscan.HostResult) error {
	h.mu.Lock()
	defer h.mu.Unlock()

	addr := hr.Addr.String()
	h.hosts[addr] = hr
	h.redrawLocked()
	return nil
}

func (h *liveHumanWriter) End() error {
	h.mu.Lock()
	defer h.mu.Unlock()

	// One final paint (no cursor-up), plus summary line.
	h.clearLocked()
	h.paintTableLocked()
	upCount := 0
	for _, hr := range h.hosts {
		if hr.Up() {
			upCount++
		}
	}
	summary := fmt.Sprintf("scanned %d host(s), %d up in %s",
		len(h.hosts), upCount, time.Since(h.start).Round(time.Millisecond))
	_, _ = fmt.Fprintln(h.w, h.style.summary.Render(summary))
	if h.opts.Color {
		_, _ = fmt.Fprint(h.w, "\x1b[?25h") // restore cursor
	}
	return nil
}

// redrawLocked repaints the table. Callers hold h.mu.
func (h *liveHumanWriter) redrawLocked() {
	h.clearLocked()
	h.paintTableLocked()
}

// clearLocked moves the cursor up by linesDrew and clears to end-of-screen.
func (h *liveHumanWriter) clearLocked() {
	if h.linesDrew > 0 {
		_, _ = fmt.Fprintf(h.w, "\x1b[%dA\x1b[J", h.linesDrew)
	}
	h.linesDrew = 0
}

func (h *liveHumanWriter) paintTableLocked() {
	h.order = h.order[:0]
	for addr := range h.hosts {
		h.order = append(h.order, addr)
	}
	sort.Strings(h.order)

	// Header row.
	header := h.style.header.Render(
		fmt.Sprintf("%-4s  %-15s  %-28s  %10s  %s",
			"", "ADDR", "HOSTNAME", "ELAPSED", "OPEN PORTS"))
	_, _ = fmt.Fprintln(h.w, header)
	h.linesDrew++

	for _, addr := range h.order {
		hr := h.hosts[addr]
		badge := "DOWN"
		badgeStyle := h.style.downBadge
		if hr.Up() {
			badge = "UP"
			badgeStyle = h.style.upBadge
		}

		ports := openPortList(hr)
		portsCol := "-"
		if len(ports) > 0 {
			portsCol = portsCellString(ports)
		}
		host := hr.Hostname
		if host == "" {
			host = "-"
		}
		line := fmt.Sprintf("%s  %s  %s  %s  %s",
			badgeStyle.Render(fmt.Sprintf("%-4s", badge)),
			h.style.service.Render(fmt.Sprintf("%-15s", addr)),
			h.style.dim.Render(fmt.Sprintf("%-28s", truncate(host, 28))),
			h.style.dim.Render(fmt.Sprintf("%10s", hr.Elapsed.Round(time.Millisecond))),
			portsCol,
		)
		_, _ = fmt.Fprintln(h.w, line)
		h.linesDrew++
	}
}

func openPortList(hr portscan.HostResult) []portscan.Result {
	var out []portscan.Result
	for _, r := range hr.Results {
		if r.State == portscan.StateOpen {
			out = append(out, r)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Port < out[j].Port })
	return out
}

// portsCellString renders the open-port column compactly. Long lists
// wrap with a count suffix so the table stays tabular.
func portsCellString(rs []portscan.Result) string {
	const maxInline = 6
	entries := make([]string, 0, len(rs))
	for _, r := range rs {
		svc := Service(r.Port)
		if svc == "" {
			entries = append(entries, fmt.Sprintf("%d", r.Port))
		} else {
			entries = append(entries, fmt.Sprintf("%d/%s", r.Port, svc))
		}
	}
	if len(entries) <= maxInline {
		return strings.Join(entries, " ")
	}
	return strings.Join(entries[:maxInline], " ") + fmt.Sprintf(" +%d more", len(entries)-maxInline)
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	if n <= 1 {
		return s[:n]
	}
	return s[:n-1] + "…"
}

// Compile-time assertion that liveHumanWriter satisfies Writer.
var _ Writer = (*liveHumanWriter)(nil)

// Lipgloss-friendly styles only resolve at render time; silence unused
// var lints when the color path is off.
var _ = lipgloss.NewStyle
