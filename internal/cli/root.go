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
	)

	cmd := &cobra.Command{
		Use:     "gscan [TARGETS...]",
		Short:   "Fast IP/port scanner",
		Long:    "gscan is a fast TCP/IP scanner with TCP-connect probes and bounded concurrency.",
		Args:    cobra.MinimumNArgs(1),
		Version: Version,
		Example: `  gscan 127.0.0.1 -p 22
  gscan 192.168.1.0/24 -p top100 --up
  gscan 10.0.0.1-50 -p 22,80,443 -o json
  gscan example.com -p- --timeout 300ms`,
		RunE: func(cmd *cobra.Command, args []string) error {
			if upFlag && downFlag {
				return fmt.Errorf("--up and --down are mutually exclusive")
			}
			format, err := output.ParseFormat(outputFlag)
			if err != nil {
				return err
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

	_ = cmd.MarkFlagRequired("ports")
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
