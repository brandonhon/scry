// Package cli wires cobra commands onto the internal packages.
package cli

import (
	"context"
	"fmt"
	"io"
	"time"

	"github.com/spf13/cobra"

	"github.com/bhoneycutt/scry/internal/output"
	"github.com/bhoneycutt/scry/internal/portscan"
	"github.com/bhoneycutt/scry/internal/progress"
	"github.com/bhoneycutt/scry/internal/resolver"
	"github.com/bhoneycutt/scry/internal/script"
	"github.com/bhoneycutt/scry/internal/target"
)

// Version is set at build time via -ldflags "-X ...Version=vX.Y.Z".
var Version = "dev"

// NewRootCmd builds the scry root cobra command.
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
		scriptFiles     []string
		scriptTimeout   time.Duration
		synFlag         bool
		listScriptsFlag bool
		rateFlag        int
		adaptiveFlag    bool
	)

	cmd := &cobra.Command{
		Use:     "scry [TARGETS...]",
		Short:   "Fast IP/port scanner",
		Long:    "scry is a fast TCP/IP scanner with TCP-connect probes, bounded concurrency, and optional banner grab.",
		// Targets required unless --list-scripts is set.
		Args: cobra.ArbitraryArgs,
		Version: Version,
		Example: `  scry 127.0.0.1 -p 22
  scry 192.168.1.0/24 -p top100 --up
  scry 10.0.0.1-50 -p 22,80,443 --banner
  scry 10.0.0.0/24 --sn               # host discovery only (alias for --ping-only)
  scry example.com -p- --timeout 300ms`,
		RunE: func(cmd *cobra.Command, args []string) error {
			if listScriptsFlag {
				return runListScripts(stdout, scriptFiles)
			}
			if len(args) == 0 {
				return fmt.Errorf("requires at least 1 target (or pass --list-scripts)")
			}
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

			var scriptEngine *script.Engine
			if len(scriptFiles) > 0 {
				scripts := make([]*script.Script, 0, len(scriptFiles))
				for _, f := range scriptFiles {
					s, err := script.Load(f)
					if err != nil {
						return err
					}
					scripts = append(scripts, s)
				}
				scriptEngine = script.NewEngine(scripts, scriptTimeout)
			}

			// Progress on stderr only when stderr is a TTY and the user
			// didn't opt out. Piped JSON/grep stays clean.
			var rep progress.Reporter
			if noProgressFlag {
				rep = progress.NewNoop()
			} else {
				rep = progress.New("scanning", false)
			}

			warnUlimit(stderr, concurrencyFlag)

			cfg := portscan.Config{
				Ports:        ports,
				Timeout:      timeoutFlag,
				Retries:      retriesFlag,
				Concurrency:  concurrencyFlag,
				HostParall:   hostParallFlag,
				PingOnly:     pingOnlyFlag,
				Banner:       bannerFlag,
				Progress:     rep,
				Resolver:     dns,
				ScriptEngine: scriptEngine,
				Rate:         rateFlag,
				Adaptive:     adaptiveFlag,
			}

			writer := output.New(format, stdout, output.Options{
				Color:   format == output.FormatHuman && output.ShouldColor(stdout, false, noColorFlag),
				Verbose: verbose,
			})

			return runScan(cmd.Context(), it, cfg, writer, scanFilter{up: upFlag, down: downFlag}, synFlag)
		},
		SilenceUsage: true,
	}

	cmd.SetOut(stdout)
	cmd.SetErr(stderr)

	f := cmd.Flags()
	f.StringVarP(&portsFlag, "ports", "p", "", "Ports: 22 | 22,80 | 1-1024 | - | top100 | top1000")
	f.DurationVar(&timeoutFlag, "timeout", 500*time.Millisecond, "Per-probe dial timeout (bump for WAN or high-latency links)")
	f.StringSliceVar(&excludeFlag, "exclude", nil, "Addresses/ranges/CIDRs to skip (comma-separated, repeatable)")
	f.IntVar(&concurrencyFlag, "concurrency", 2000, "Max parallel sockets in flight (lower if hitting RLIMIT_NOFILE)")
	f.IntVar(&hostParallFlag, "max-hosts", 100, "Max hosts probed in parallel")
	f.IntVar(&retriesFlag, "retries", 0, "Retries on filtered (timeout) probes (set 1+ for accuracy on lossy links)")
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
	f.StringSliceVar(&scriptFiles, "script", nil, "Lua script to run against open ports (repeatable)")
	f.DurationVar(&scriptTimeout, "script-timeout", 5*time.Second, "Per-invocation timeout for --script")
	f.BoolVar(&synFlag, "syn", false, "Use raw SYN scanner (requires -tags rawsock build + CAP_NET_RAW; cannot scan loopback or WSL2)")
	f.BoolVar(&listScriptsFlag, "list-scripts", false, "Print metadata for scripts passed via --script and exit")
	f.IntVar(&rateFlag, "rate", 10000, "Max SYN packets per second (--syn only; 0 = unlimited)")
	f.BoolVar(&adaptiveFlag, "adaptive", false, "Adapt SYN send rate to probe error-rate (start at --rate/4, scale to --rate)")

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

func runScan(ctx context.Context, it *target.Iterator, cfg portscan.Config, w output.Writer, sf scanFilter, syn bool) error {
	if syn {
		if !portscan.SYNAvailable {
			return portscan.ErrSYNUnavailable
		}
		if cfg.PingOnly {
			return fmt.Errorf("--syn cannot be combined with --ping-only")
		}
	}

	if err := w.Begin(); err != nil {
		return err
	}

	// Drain the results channel even after ctx is cancelled so that every
	// host already probed lands in the output. The producer reacts to ctx
	// cancellation by refusing to launch new hosts but still flushes
	// everything in flight before closing the channel.
	var results <-chan portscan.HostResult
	if syn {
		ch, err := portscan.SynScan(ctx, it, cfg)
		if err != nil {
			return err
		}
		results = ch
	} else {
		results = portscan.Scan(ctx, it, cfg)
	}
	var writeErr error
	for hr := range results {
		if writeErr != nil {
			continue // keep draining; skip further writes
		}
		if !sf.keepHost(hr) {
			continue
		}
		if err := w.WriteHost(hr); err != nil {
			writeErr = err
		}
	}

	if err := w.End(); err != nil && writeErr == nil {
		writeErr = err
	}
	if writeErr != nil {
		return writeErr
	}
	return ctx.Err()
}
