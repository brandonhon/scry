//go:build rawsock && linux

package discovery

import (
	"context"
	"encoding/binary"
	"net"
	"net/netip"
	"os"
	"time"

	"golang.org/x/net/icmp"
	"golang.org/x/net/ipv4"
)

// icmpAvailable reports that the rawsock-linux build has an ICMP path.
const icmpAvailable = true

// pingICMP sends one ICMP Echo Request and waits for a matching Echo
// Reply within timeout. Returns (up, rtt, via) where via is "icmp" on
// success. Uses unprivileged SOCK_DGRAM when ping_group_range permits
// the process gid; otherwise the caller falls back to TCP ping.
func pingICMP(ctx context.Context, addr netip.Addr, timeout time.Duration) (bool, time.Duration, string) {
	if !addr.Is4() {
		return false, 0, ""
	}
	c, err := icmp.ListenPacket("udp4", "0.0.0.0")
	if err != nil {
		return false, 0, ""
	}
	defer c.Close()
	deadline := time.Now().Add(timeout)
	_ = c.SetDeadline(deadline)

	id := os.Getpid() & 0xffff
	seq := 1
	body := &icmp.Echo{ID: id, Seq: seq, Data: []byte("scry")}
	msg := icmp.Message{Type: ipv4.ICMPTypeEcho, Body: body}
	wire, err := msg.Marshal(nil)
	if err != nil {
		return false, 0, ""
	}

	start := time.Now()
	if _, err := c.WriteTo(wire, &net.UDPAddr{IP: addr.AsSlice()}); err != nil {
		return false, 0, ""
	}

	buf := make([]byte, 512)
	for {
		n, peer, err := c.ReadFrom(buf)
		if err != nil {
			return false, 0, ""
		}
		parsed, err := icmp.ParseMessage(1, buf[:n])
		if err != nil {
			continue
		}
		echo, ok := parsed.Body.(*icmp.Echo)
		if !ok {
			continue
		}
		if echo.ID != id || echo.Seq != seq {
			continue
		}
		_ = peer
		return true, time.Since(start), "icmp"
	}
}

// silence lints when this file is unreferenced by the v6 path.
var _ = binary.BigEndian
