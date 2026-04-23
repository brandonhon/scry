//go:build !rawsock || !linux

package discovery

import (
	"context"
	"net/netip"
	"time"
)

// icmpAvailable is false on the default build; pingICMP never succeeds.
const icmpAvailable = false

func pingICMP(_ context.Context, _ netip.Addr, _ time.Duration) (bool, time.Duration, string) {
	return false, 0, ""
}
