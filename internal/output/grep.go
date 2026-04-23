package output

import (
	"fmt"
	"io"
	"sort"
	"strings"
	"time"

	"github.com/bhoneycutt/gscan/internal/portscan"
)

// grepWriter emits one line per host, grep-friendly. Example:
//
//	Host: 192.168.1.10    Status: up    Ports: 22/open/ssh,80/open/http    Elapsed: 12ms
//
// Fields are separated by tabs; the inner ports list uses commas so a
// single grep hit yields the whole host summary.
type grepWriter struct {
	w    io.Writer
	opts Options
}

func (g *grepWriter) Begin() error { return nil }

func (g *grepWriter) WriteHost(hr portscan.HostResult) error {
	rows := make([]portscan.Result, len(hr.Results))
	copy(rows, hr.Results)
	sort.Slice(rows, func(i, j int) bool { return rows[i].Port < rows[j].Port })

	parts := make([]string, 0, len(rows))
	for _, r := range rows {
		if !g.keepPort(r) {
			continue
		}
		svc := Service(r.Port)
		if svc == "" {
			svc = "-"
		}
		parts = append(parts, fmt.Sprintf("%d/%s/%s", r.Port, r.State, svc))
	}
	ports := strings.Join(parts, ",")
	if ports == "" {
		ports = "-"
	}

	status := "down"
	if hr.Up() {
		status = "up"
	}
	addr := hr.Addr.String()
	if hr.Hostname != "" {
		addr += " (" + hr.Hostname + ")"
	}
	_, err := fmt.Fprintf(g.w,
		"Host: %s\tStatus: %s\tPorts: %s\tElapsed: %s\n",
		addr, status, ports, hr.Elapsed.Round(time.Microsecond))
	return err
}

func (g *grepWriter) End() error { return nil }

func (g *grepWriter) keepPort(r portscan.Result) bool {
	if r.State == portscan.StateOpen {
		return true
	}
	if g.opts.Verbose >= 1 && (r.State == portscan.StateClosed || r.State == portscan.StateFiltered) {
		return true
	}
	if g.opts.Verbose >= 2 && r.State == portscan.StateError {
		return true
	}
	return false
}
