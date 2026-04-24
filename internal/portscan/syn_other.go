//go:build rawsock && !linux && !windows

// SYN scanning stub for non-Linux rawsock builds.
//
// A full Windows/Npcap implementation needs:
//   - Interface enumeration via pcap.FindAllDevs() returning NPF device
//     names like \Device\NPF_{GUID}; match against the route to the
//     destination (GetBestRoute2).
//   - ARP / neighbour resolution via GetIpNetTable2 (iphlpapi.dll) or
//     SendARP (iphlpapi) to replace the /proc/net/arp path used on
//     Linux.
//   - Same pcap send/receive pipeline as syn_linux.go — refactor the
//     shared machinery into a rawsock-tagged (non-platform) file first
//     so syn_windows.go only supplies the above platform specifics.
//   - Install docs: Npcap must be running in WinPcap-compat mode; the
//     scry binary needs to run elevated.
//
// See DEFERRED.md "SYN scan (Windows)" for the full scope.
package portscan

import (
	"context"
	"errors"

	"github.com/bhoneycutt/scry/internal/target"
)

const SYNAvailable = false

var ErrSYNUnavailable = errors.New(
	"SYN scanning under -tags rawsock is Linux-only in this release. Windows/Npcap support is tracked in DEFERRED.md; contributions welcome via the SynScan contract (synchronous setup returns (<-chan HostResult, error); use scanState from syn_linux.go as the reference implementation)")

func SynScan(_ context.Context, _ *target.Iterator, _ Config) (<-chan HostResult, error) {
	return nil, ErrSYNUnavailable
}
