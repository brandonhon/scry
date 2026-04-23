//go:build !rawsock

package portscan

import (
	"context"
	"errors"
	"net/netip"

	"github.com/bhoneycutt/scry/internal/target"
)

// SYNAvailable reports whether this build of scry includes the raw-socket
// SYN scanner. Default builds return false; builds with `-tags rawsock`
// return true.
const SYNAvailable = false

// SynScan is a stub on builds without the `rawsock` tag. It always
// returns ErrSYNUnavailable; the CLI checks SYNAvailable first and
// never reaches this call on a default build.
func SynScan(_ context.Context, _ *target.Iterator, _ Config) (<-chan HostResult, error) {
	return nil, ErrSYNUnavailable
}

// ErrSYNUnavailable is returned by the CLI when --syn is requested on a
// default build.
var ErrSYNUnavailable = errors.New(
	"SYN scanning is not compiled into this binary; rebuild with `-tags rawsock` and install libpcap (Linux) or Npcap (Windows)")

// Used only by the rawsock build but referenced by the CLI so the compiler
// is happy regardless of tags.
var _ = netip.Addr{}
