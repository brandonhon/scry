//go:build !linux && !darwin

package cli

import "io"

// warnUlimit is a no-op on platforms without RLIMIT_NOFILE (e.g. Windows,
// which uses a different fd accounting model).
func warnUlimit(_ io.Writer, _ int) {}
