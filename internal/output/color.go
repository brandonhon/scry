package output

import (
	"io"
	"os"

	"github.com/mattn/go-isatty"
)

// ShouldColor decides whether ANSI styling should be used for w.
//
//   - forced true  → always on.
//   - forced false → always off.
//   - auto         → on when w is an *os.File pointing at a TTY AND
//     NO_COLOR is not set. https://no-color.org/
func ShouldColor(w io.Writer, forceOn, forceOff bool) bool {
	if forceOff {
		return false
	}
	if forceOn {
		return true
	}
	if _, ok := os.LookupEnv("NO_COLOR"); ok {
		return false
	}
	f, ok := w.(*os.File)
	if !ok {
		return false
	}
	return isatty.IsTerminal(f.Fd()) || isatty.IsCygwinTerminal(f.Fd())
}
