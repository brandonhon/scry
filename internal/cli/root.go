// Package cli wires cobra commands onto the internal packages.
package cli

import (
	"context"
	"fmt"
	"io"
	"time"

	"github.com/spf13/cobra"

	"github.com/bhoneycutt/gscan/internal/output"
	"github.com/bhoneycutt/gscan/internal/portscan"
	"github.com/bhoneycutt/gscan/internal/progress"
	"github.com/bhoneycutt/gscan/internal/resolver"
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
		outputFlag      string
		noColorFlag     bool
		pingOnlyFlag    bool
		noDNSFlag       bool
		bannerFlag      bool
		noProgressFlag  bool
	)

	cmd := &cobra.Command{
		Use:     "gscan [TARGETS...]",
		Short:   "Fast IP/port scanner",
		Long:    "gscan is a fast TCP/IP scanner with TCP-connect probes, bounded concurrency, and optional banner grab.",
		Args:    cobra.MinimumNArgs(1),
		Version: Version,
		Example: `  gscan 127.0.0.1 -p 22
  gscan 192.168.1.0/24 -p top100 --up
  gscan 10.0.0.1-50 -p 22,80,443 --banner
  gscan 10.0.0.0/24 --sn               # host discovery only (alias for --ping-only)
  gscan example.com -p- --timeout 300ms`,
		RunE: func(cmd *cobra.Command, args []string) error {
			if upFlag && downFlag {
				return fmt.Errorf("--up and --down are mutually exclusive")
			}
			if pingOnlyFlag && portsFlag != "" {
				return fmt.Errorf("--ping-only does not take -p")
			}
			if !pingOnlyFlag && portsFlag == "" {
				return fmt.Errorf("required flag \"ports\" not set")
			}

			format, err := output.ParseFormat(outputFlag)
			if err != nil {
				return err
			}

			var ports []uint16
			if !pingOnlyFlag {
				ports, err = portscan.ParsePorts(portsFlag)
				if err != nil {
					return err
				}
			}

			it, err := target.Parse(args, target.Options{
				Excludes: excludeFlag,
				Context:  cmd.Context(),
			})
			if err != nil {
				return err
			}

			var dns *resolver.Cache
			if !noDNSFlag {
				dns = resolver.New(resolver.Options{})
			}

			// Progress on stderr only when stderr is a TTY and the user
			// didn't opt out. Piped JSON/grep stays clean.
			var rep progress.Reporter
			if noProgressFlag {
				rep = progress.NewNoop()
			} else {
				rep = progress.New("scanning", false)
			}

			cfg := portscan.Config{
				Ports:       ports,
				Timeout:     timeoutFlag,
				Retries:     retriesFlag,
				Concurrency: concurrencyFlag,
				HostParall:  hostParallFlag,
				PingOnly:    pingOnlyFlag,
				Banner:      bannerFlag,
				Progress:    rep,
				Resolver:    dns,
			}

			writer := output.New(format, stdout, output.Options{
				Color:   format == output.FormatHuman && output.ShouldColor(stdout, false, noColorFlag),
				Verbose: verbose,
			})

			return runScan(cmd.Context(), it, cfg, writer, scanFilter{up: upFlag, down: downFlag})
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
	f.StringVarP(&outputFlag, "output", "o", "human", "Output format: human | json | grep")
	f.BoolVar(&noColorFlag, "no-color", false, "Disable ANSI colour in human output")
	f.BoolVar(&pingOnlyFlag, "ping-only", false, "Host discovery only, no port scan")
	f.BoolVar(&pingOnlyFlag, "sn", false, "Alias for --ping-only (nmap-style)")
	f.BoolVar(&noDNSFlag, "no-dns", false, "Skip reverse DNS lookups")
	f.BoolVar(&bannerFlag, "banner", false, "Grab a short service banner on open ports")
	f.BoolVar(&noProgressFlag, "no-progress", false, "Disable the stderr progress bar")

	return cmd
}

type scanFilter struct {
	up, down bool
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

func runScan(ctx context.Context, it *target.Iterator, cfg portscan.Config, w output.Writer, sf scanFilter) error {
	if err := w.Begin(); err != nil {
		return err
	}

	results := portscan.Scan(ctx, it, cfg)
	for hr := range results {
		if err := ctx.Err(); err != nil {
			return err
		}
		if !sf.keepHost(hr) {
			continue
		}
		if err := w.WriteHost(hr); err != nil {
			return err
		}
	}

	if err := w.End(); err != nil {
		return err
	}
	return ctx.Err()
}
