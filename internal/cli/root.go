// Package cli wires cobra commands onto the internal packages.
package cli

import (
	"context"
	"fmt"
	"io"
	"sort"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/bhoneycutt/gscan/internal/portscan"
	"github.com/bhoneycutt/gscan/internal/target"
)

// Version is set at build time via -ldflags "-X ...Version=vX.Y.Z".
var Version = "dev"

// NewRootCmd builds the gscan root cobra command.
func NewRootCmd(stdout, stderr io.Writer) *cobra.Command {
	var (
		portsFlag       string
		timeoutFlag     time.Duration
		excludeFlag     []string
		concurrencyFlag int
		hostParallFlag  int
		retriesFlag     int
		upFlag          bool
		downFlag        bool
		verbose         int
	)

	cmd := &cobra.Command{
		Use:     "gscan [TARGETS...]",
		Short:   "Fast IP/port scanner",
		Long:    "gscan is a fast TCP/IP scanner with TCP-connect probes and bounded concurrency.",
		Args:    cobra.MinimumNArgs(1),
		Version: Version,
		Example: `  gscan 127.0.0.1 -p 22
  gscan 192.168.1.0/24 -p top100
  gscan 10.0.0.1-50 -p 22,80,443
  gscan example.com -p- --timeout 300ms`,
		RunE: func(cmd *cobra.Command, args []string) error {
			if upFlag && downFlag {
				return fmt.Errorf("--up and --down are mutually exclusive")
			}
			ports, err := portscan.ParsePorts(portsFlag)
			if err != nil {
				return err
			}
			it, err := target.Parse(args, target.Options{
				Excludes: excludeFlag,
				Context:  cmd.Context(),
			})
			if err != nil {
				return err
			}
			cfg := portscan.Config{
				Ports:       ports,
				Timeout:     timeoutFlag,
				Retries:     retriesFlag,
				Concurrency: concurrencyFlag,
				HostParall:  hostParallFlag,
			}
			return runScan(cmd.Context(), stdout, it, cfg, scanFilter{up: upFlag, down: downFlag, verbose: verbose})
		},
		SilenceUsage: true,
	}

	cmd.SetOut(stdout)
	cmd.SetErr(stderr)

	f := cmd.Flags()
	f.StringVarP(&portsFlag, "ports", "p", "", "Ports: 22 | 22,80 | 1-1024 | - | top100 | top1000")
	f.DurationVar(&timeoutFlag, "timeout", 1500*time.Millisecond, "Per-probe dial timeout")
	f.StringSliceVar(&excludeFlag, "exclude", nil, "Addresses/ranges/CIDRs to skip (comma-separated, repeatable)")
	f.IntVar(&concurrencyFlag, "concurrency", 1000, "Max parallel sockets in flight")
	f.IntVar(&hostParallFlag, "max-hosts", 50, "Max hosts probed in parallel")
	f.IntVar(&retriesFlag, "retries", 1, "Retries on filtered (timeout) probes")
	f.BoolVar(&upFlag, "up", false, "Only show hosts with at least one open port")
	f.BoolVar(&downFlag, "down", false, "Only show hosts with no open ports")
	f.CountVarP(&verbose, "verbose", "v", "Verbose output (-v shows closed/filtered, -vv shows errors too)")

	_ = cmd.MarkFlagRequired("ports")
	return cmd
}

type scanFilter struct {
	up, down bool
	verbose  int
}

func (sf scanFilter) keepHost(hr portscan.HostResult) bool {
	if sf.up && !hr.Up() {
		return false
	}
	if sf.down && hr.Up() {
		return false
	}
	return true
}

func (sf scanFilter) keepPort(r portscan.Result) bool {
	if r.State == portscan.StateOpen {
		return true
	}
	if sf.verbose >= 1 && (r.State == portscan.StateClosed || r.State == portscan.StateFiltered) {
		return true
	}
	if sf.verbose >= 2 && r.State == portscan.StateError {
		return true
	}
	return false
}

func runScan(ctx context.Context, w io.Writer, it *target.Iterator, cfg portscan.Config, sf scanFilter) error {
	out := portscan.Scan(ctx, it, cfg)
	for hr := range out {
		if err := ctx.Err(); err != nil {
			return err
		}
		if !sf.keepHost(hr) {
			continue
		}
		if err := writeHost(w, hr, sf); err != nil {
			return err
		}
	}
	return ctx.Err()
}

func writeHost(w io.Writer, hr portscan.HostResult, sf scanFilter) error {
	header := fmt.Sprintf("%s\t%s\t%s\n",
		hr.Addr.String(),
		upStr(hr.Up()),
		hr.Elapsed.Round(time.Microsecond),
	)
	if _, err := io.WriteString(w, header); err != nil {
		return err
	}
	// Emit per-port results sorted by port for deterministic output.
	sort.Slice(hr.Results, func(i, j int) bool { return hr.Results[i].Port < hr.Results[j].Port })
	for _, r := range hr.Results {
		if !sf.keepPort(r) {
			continue
		}
		line := fmt.Sprintf("  %d/tcp\t%s\t%s", r.Port, r.State, r.RTT.Round(time.Microsecond))
		if r.State == portscan.StateError && r.Err != nil {
			line += "\t" + sanitizeErr(r.Err.Error())
		}
		if _, err := fmt.Fprintln(w, line); err != nil {
			return err
		}
	}
	return nil
}

func upStr(up bool) string {
	if up {
		return "up"
	}
	return "down"
}

// sanitizeErr prevents newlines in error messages from breaking TSV output.
func sanitizeErr(s string) string {
	s = strings.ReplaceAll(s, "\n", " ")
	return strings.ReplaceAll(s, "\t", " ")
}
