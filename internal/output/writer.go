// Package output renders per-host scan results in one of several formats.
// Writers are streaming: the scanner calls WriteHost as each host result
// arrives, and End flushes any trailer.
package output

import (
	"fmt"
	"io"

	"github.com/brandonhon/scry/internal/portscan"
)

// Format selects the renderer.
type Format string

const (
	FormatHuman Format = "human"
	FormatJSON  Format = "json"
	FormatGrep  Format = "grep"
	// FormatLive is selected by --live; the CLI downgrades to
	// FormatHuman automatically when stdout isn't a TTY so pipelines
	// stay clean.
	FormatLive Format = "live"
)

// ParseFormat maps a user string to a Format.
func ParseFormat(s string) (Format, error) {
	switch s {
	case "", "human":
		return FormatHuman, nil
	case "json":
		return FormatJSON, nil
	case "grep":
		return FormatGrep, nil
	case "live":
		return FormatLive, nil
	default:
		return "", fmt.Errorf("unknown output format %q (want human|json|grep|live)", s)
	}
}

// Options tunes writer rendering.
type Options struct {
	// Color enables ANSI styling in the human writer. Ignored by json/grep.
	Color bool
	// Verbose is 0 (open only), 1 (+ closed/filtered), 2 (+ errors).
	Verbose int
}

// Writer is the streaming output interface.
type Writer interface {
	// Begin is called once before any WriteHost. Implementations may
	// emit a header or set up state.
	Begin() error
	// WriteHost renders a single host's result.
	WriteHost(hr portscan.HostResult) error
	// End is called once after the last WriteHost. Use it to flush
	// trailers (e.g., a summary line).
	End() error
}

// New returns a Writer for the selected format.
func New(format Format, w io.Writer, opts Options) Writer {
	switch format {
	case FormatJSON:
		return &jsonWriter{w: w, opts: opts}
	case FormatGrep:
		return &grepWriter{w: w, opts: opts}
	case FormatLive:
		return newLiveHumanWriter(w, opts)
	default:
		return newHumanWriter(w, opts)
	}
}
