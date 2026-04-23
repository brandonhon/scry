package output

import (
	"fmt"
	"io"
	"sort"
	"strings"
	"time"

	"github.com/charmbracelet/lipgloss"

	"github.com/bhoneycutt/gscan/internal/portscan"
)

// humanWriter renders a lipgloss-styled block per host.
type humanWriter struct {
	w     io.Writer
	opts  Options
	style humanStyle
	hosts int
	up    int
	start time.Time
}

type humanStyle struct {
	header     lipgloss.Style
	upBadge    lipgloss.Style
	downBadge  lipgloss.Style
	open       lipgloss.Style
	closed     lipgloss.Style
	filtered   lipgloss.Style
	errState   lipgloss.Style
	dim        lipgloss.Style
	service    lipgloss.Style
	summary    lipgloss.Style
}

func newHumanWriter(w io.Writer, opts Options) *humanWriter {
	return &humanWriter{
		w:     w,
		opts:  opts,
		style: buildStyle(opts.Color),
	}
}

func buildStyle(color bool) humanStyle {
	if !color {
		// Neutral (no ANSI) — lipgloss emits plain strings when all styles
		// are empty.
		return humanStyle{}
	}
	return humanStyle{
		header:    lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("99")),
		upBadge:   lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("10")),
		downBadge: lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("8")),
		open:      lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("10")),
		closed:    lipgloss.NewStyle().Foreground(lipgloss.Color("9")),
		filtered:  lipgloss.NewStyle().Foreground(lipgloss.Color("11")),
		errState:  lipgloss.NewStyle().Foreground(lipgloss.Color("13")),
		dim:       lipgloss.NewStyle().Faint(true),
		service:   lipgloss.NewStyle().Foreground(lipgloss.Color("14")),
		summary:   lipgloss.NewStyle().Bold(true),
	}
}

func (h *humanWriter) Begin() error {
	h.start = time.Now()
	return nil
}

func (h *humanWriter) WriteHost(hr portscan.HostResult) error {
	h.hosts++
	if hr.Up() {
		h.up++
	}
	badge := h.style.downBadge.Render("DOWN")
	if hr.Up() {
		badge = h.style.upBadge.Render("UP  ")
	}
	addr := h.style.header.Render(hr.Addr.String())
	elapsed := h.style.dim.Render(hr.Elapsed.Round(time.Microsecond).String())

	header := fmt.Sprintf("%s  %s", badge, addr)
	if hr.Hostname != "" {
		header += "  " + h.style.dim.Render("("+hr.Hostname+")")
	}
	if _, err := fmt.Fprintf(h.w, "%s  %s\n", header, elapsed); err != nil {
		return err
	}

	// Discovery-only (-sn) has no per-port table; show the "via" hint.
	if hr.Discovery != nil {
		if hr.Discovery.Up && hr.Discovery.Via != "" {
			line := fmt.Sprintf("  via %s  %s",
				hr.Discovery.Via,
				h.style.dim.Render(hr.Discovery.RTT.Round(time.Microsecond).String()))
			if _, err := fmt.Fprintln(h.w, line); err != nil {
				return err
			}
			if _, err := fmt.Fprintln(h.w); err != nil {
				return err
			}
		}
		return nil
	}

	// Sort ports for stable display.
	rows := make([]portscan.Result, len(hr.Results))
	copy(rows, hr.Results)
	sort.Slice(rows, func(i, j int) bool { return rows[i].Port < rows[j].Port })

	written := 0
	for _, r := range rows {
		if !h.keepPort(r) {
			continue
		}
		line := h.formatPortLine(r)
		if _, err := fmt.Fprintln(h.w, line); err != nil {
			return err
		}
		written++
	}
	// Blank line between hosts for readability, but only if we emitted ports.
	if written > 0 {
		if _, err := fmt.Fprintln(h.w); err != nil {
			return err
		}
	}
	return nil
}

func (h *humanWriter) keepPort(r portscan.Result) bool {
	if r.State == portscan.StateOpen {
		return true
	}
	if h.opts.Verbose >= 1 && (r.State == portscan.StateClosed || r.State == portscan.StateFiltered) {
		return true
	}
	if h.opts.Verbose >= 2 && r.State == portscan.StateError {
		return true
	}
	return false
}

func (h *humanWriter) formatPortLine(r portscan.Result) string {
	line := h.formatPortMainLine(r)
	for _, f := range r.Findings {
		line += "\n      " + h.style.service.Render("["+f.Script+"] ") + sanitize(f.Output)
	}
	return line
}

func (h *humanWriter) formatPortMainLine(r portscan.Result) string {
	var state string
	switch r.State {
	case portscan.StateOpen:
		state = h.style.open.Render("open    ")
	case portscan.StateClosed:
		state = h.style.closed.Render("closed  ")
	case portscan.StateFiltered:
		state = h.style.filtered.Render("filtered")
	case portscan.StateError:
		state = h.style.errState.Render("error   ")
	default:
		state = "unknown "
	}
	svc := Service(r.Port)
	if svc != "" {
		svc = h.style.service.Render(svc)
	}
	rtt := h.style.dim.Render(r.RTT.Round(time.Microsecond).String())

	line := fmt.Sprintf("  %5d/tcp  %s  %-18s %s", r.Port, state, svc, rtt)
	if r.Banner != "" {
		line += "  " + h.style.dim.Render("→ "+sanitize(r.Banner))
	}
	if r.State == portscan.StateError && r.Err != nil {
		line += "  " + h.style.dim.Render(sanitize(r.Err.Error()))
	}
	return line
}

func (h *humanWriter) End() error {
	elapsed := time.Since(h.start).Round(time.Millisecond)
	line := fmt.Sprintf("scanned %d host(s), %d up in %s", h.hosts, h.up, elapsed)
	_, err := fmt.Fprintln(h.w, h.style.summary.Render(line))
	return err
}

func sanitize(s string) string {
	s = strings.ReplaceAll(s, "\n", " ")
	return strings.ReplaceAll(s, "\t", " ")
}
