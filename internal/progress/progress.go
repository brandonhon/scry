// Package progress provides a minimal reporter interface for the scanner
// to emit host-level progress updates. A TTY-backed implementation renders
// a progress bar on stderr using github.com/schollz/progressbar/v3; the
// Noop implementation is used when stderr is not a TTY so piping JSON/grep
// output stays clean.
//
// Reporters are goroutine-safe (schollz/progressbar is), so the scanner
// can call them from its per-host workers without extra locking.
package progress

import (
	"io"
	"os"
	"time"

	"github.com/mattn/go-isatty"
	"github.com/schollz/progressbar/v3"
)

// Reporter emits progress updates. All methods must be safe for concurrent
// use from scanner workers.
type Reporter interface {
	// SetTotal declares the expected total count when known. Calling with
	// a non-positive value switches the reporter to indeterminate mode.
	SetTotal(n int64)
	// Tick records one unit of progress.
	Tick()
	// Finish flushes any trailing output (newline after the bar).
	Finish()
}

// NewNoop returns a Reporter that discards all updates.
func NewNoop() Reporter { return noop{} }

// isTTY is overridable for tests. Default probes os.Stderr.
var isTTY = func() bool {
	fd := os.Stderr.Fd()
	return isatty.IsTerminal(fd) || isatty.IsCygwinTerminal(fd)
}

// New returns a stderr-backed bar when stderr is a TTY, otherwise Noop.
// Options:
//   - description shown before the bar (e.g., "scanning")
//   - force: when true, emit the bar even if stderr is not a TTY (useful
//     for tests / logs). force=false is the normal runtime path.
func New(description string, force bool) Reporter {
	if !force && !isTTY() {
		return noop{}
	}
	return newBar(os.Stderr, description)
}

// NewFor returns a bar that writes to the given io.Writer, typed for tests.
func NewFor(w io.Writer, description string) Reporter {
	return newBar(w, description)
}

// -- no-op implementation -----------------------------------------------------

type noop struct{}

func (noop) SetTotal(int64) {}
func (noop) Tick()          {}
func (noop) Finish()        {}

// -- TTY bar ------------------------------------------------------------------

type bar struct {
	w    io.Writer
	desc string
	bar  *progressbar.ProgressBar
}

func newBar(w io.Writer, desc string) *bar {
	return &bar{
		w:    w,
		desc: desc,
		bar:  newBarInstance(w, -1, desc),
	}
}

func newBarInstance(w io.Writer, total int64, desc string) *progressbar.ProgressBar {
	opts := []progressbar.Option{
		progressbar.OptionSetWriter(w),
		progressbar.OptionSetDescription(desc),
		progressbar.OptionShowCount(),
		progressbar.OptionShowIts(),
		progressbar.OptionSetItsString("probe"),
		progressbar.OptionSetWidth(30),
		progressbar.OptionThrottle(100 * time.Millisecond),
		progressbar.OptionClearOnFinish(),
		progressbar.OptionSetPredictTime(true),
		progressbar.OptionSpinnerType(14),
		progressbar.OptionFullWidth(),
	}
	if total > 0 {
		return progressbar.NewOptions64(total, opts...)
	}
	// Indeterminate — use -1 so the bar renders as a spinner with a
	// "processed N" counter.
	return progressbar.NewOptions64(-1, opts...)
}

func (b *bar) SetTotal(n int64) {
	// Re-create the underlying bar so width and ETA re-initialise against
	// the new total. Callers typically set the total once, up front.
	b.bar = newBarInstance(b.w, n, b.desc)
}

func (b *bar) Tick() { _ = b.bar.Add(1) }

func (b *bar) Finish() {
	_ = b.bar.Finish()
	// Bar's OptionClearOnFinish wipes its line; add a newline to put any
	// following log text on its own line.
	_, _ = io.WriteString(b.w, "\n")
}
