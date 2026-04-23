// Package cli wires cobra commands onto the internal packages.
//
// Phase 1 scope: one command (gscan), TCP connect to a single port per host.
package cli

import (
	"context"
	"errors"
	"fmt"
	"io"
	"strconv"
	"time"

	"github.com/spf13/cobra"

	"github.com/bhoneycutt/gscan/internal/portscan"
	"github.com/bhoneycutt/gscan/internal/target"
)

// Version is set at build time via -ldflags "-X ...Version=vX.Y.Z".
var Version = "dev"

// NewRootCmd builds the gscan root cobra command. stdout/stderr are injected
// for testability; main.go wires them to os.Stdout / os.Stderr.
func NewRootCmd(stdout, stderr io.Writer) *cobra.Command {
	var (
		portsFlag   string
		timeoutFlag time.Duration
		excludeFlag []string
	)

	cmd := &cobra.Command{
		Use:     "gscan [TARGETS...]",
		Short:   "Fast IP/port scanner",
		Long:    "gscan is a fast TCP/IP scanner. Phase 1 performs TCP-connect probes on a single port.",
		Args:    cobra.MinimumNArgs(1),
		Version: Version,
		Example: "  gscan 127.0.0.1 -p 22\n  gscan 192.168.1.0/30 -p 80\n  gscan example.com -p 443",
		RunE: func(cmd *cobra.Command, args []string) error {
			port, err := parseSinglePort(portsFlag)
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

			return runScan(cmd.Context(), stdout, it, port, timeoutFlag)
		},
		SilenceUsage:  true,
		SilenceErrors: false,
	}

	cmd.SetOut(stdout)
	cmd.SetErr(stderr)

	f := cmd.Flags()
	f.StringVarP(&portsFlag, "ports", "p", "", "Port to scan (Phase 1: single port; full syntax lands in Phase 2)")
	f.DurationVar(&timeoutFlag, "timeout", 1500*time.Millisecond, "Per-probe dial timeout")
	f.StringSliceVar(&excludeFlag, "exclude", nil, "Addresses/ranges/CIDRs to skip (comma-separated, repeatable)")

	_ = cmd.MarkFlagRequired("ports")

	return cmd
}

// runScan iterates targets and probes one port on each, writing one line per
// result to w.
func runScan(ctx context.Context, w io.Writer, it *target.Iterator, port uint16, timeout time.Duration) error {
	for {
		if err := ctx.Err(); err != nil {
			return err
		}
		addr, ok := it.Next()
		if !ok {
			return nil
		}
		res := portscan.TCPConnect(ctx, addr, port, timeout)
		if err := writeResult(w, res); err != nil {
			return err
		}
	}
}

func writeResult(w io.Writer, r portscan.Result) error {
	if r.State == portscan.StateError {
		_, err := fmt.Fprintf(w, "%s:%d\t%s\t%s\t%v\n", r.Addr, r.Port, r.State, r.RTT.Round(time.Microsecond), r.Err)
		return err
	}
	_, err := fmt.Fprintf(w, "%s:%d\t%s\t%s\n", r.Addr, r.Port, r.State, r.RTT.Round(time.Microsecond))
	return err
}

// parseSinglePort parses a single TCP port in the range 1..65535.
// Phase 2 replaces this with the full port-spec parser.
func parseSinglePort(s string) (uint16, error) {
	if s == "" {
		return 0, errors.New("--ports is required")
	}
	n, err := strconv.Atoi(s)
	if err != nil {
		return 0, fmt.Errorf("invalid port %q: %w", s, err)
	}
	if n < 1 || n > 65535 {
		return 0, fmt.Errorf("port %d out of range (1-65535)", n)
	}
	return uint16(n), nil
}
