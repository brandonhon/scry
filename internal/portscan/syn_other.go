//go:build rawsock && !linux

// SYN scanning stub for non-Linux rawsock builds. Windows support via
// Npcap is tracked in DEFERRED.md.
package portscan

import (
	"context"
	"errors"

	"github.com/bhoneycutt/scry/internal/target"
)

const SYNAvailable = false

var ErrSYNUnavailable = errors.New(
	"SYN scanning under -tags rawsock is Linux-only in this build; Windows Npcap support is tracked in DEFERRED.md")

func SynScan(_ context.Context, _ *target.Iterator, _ Config) (<-chan HostResult, error) {
	return nil, ErrSYNUnavailable
}
