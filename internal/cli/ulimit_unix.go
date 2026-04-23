//go:build linux || darwin

package cli

import (
	"fmt"
	"io"

	"golang.org/x/sys/unix"
)

// warnUlimit prints a stderr note when the configured socket concurrency
// is likely to exhaust the process's open-file limit. TCP-connect
// probes each consume one fd, plus a few for stdin/out/err and
// resolvers. We warn when `concurrency` is within 90% of the soft
// RLIMIT_NOFILE so the user can raise `ulimit -n` before hitting
// "too many open files" mid-scan.
func warnUlimit(stderr io.Writer, concurrency int) {
	var lim unix.Rlimit
	if err := unix.Getrlimit(unix.RLIMIT_NOFILE, &lim); err != nil {
		return
	}
	// Reserve a small headroom for the rest of the process.
	const headroom = 64
	safe := int64(lim.Cur) - headroom
	if safe <= 0 || int64(concurrency) <= safe {
		return
	}
	fmt.Fprintf(stderr,
		"warning: --concurrency=%d exceeds safe open-file limit (%d); raise with `ulimit -n` or lower --concurrency\n",
		concurrency, lim.Cur)
}
