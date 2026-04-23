//go:build windows

package output

import (
	"os"

	"golang.org/x/sys/windows"
)

// EnableVT turns on ANSI escape processing on the Windows console so that
// lipgloss styles render as colour instead of literal "\x1b[...m". Safe to
// call multiple times; failures (old console, redirected stdout) are
// ignored and color auto-detection will simply report false.
func EnableVT() {
	for _, f := range []*os.File{os.Stdout, os.Stderr} {
		h := windows.Handle(f.Fd())
		var mode uint32
		if err := windows.GetConsoleMode(h, &mode); err != nil {
			continue
		}
		_ = windows.SetConsoleMode(h, mode|windows.ENABLE_VIRTUAL_TERMINAL_PROCESSING)
	}
}
