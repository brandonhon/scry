//go:build rawsock && linux

package portscan

import (
	"bufio"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os"
	"strconv"
	"strings"
)

// procNetArp + procNetRoute are indirected so tests can stub them.
var (
	procNetArp   = "/proc/net/arp"
	procNetRoute = "/proc/net/route"
)

// resolveDstMAC picks the correct next-hop MAC for a destination:
//   - On-link (dst is in the source subnet): ARP-resolve dst directly.
//   - Off-link: ARP-resolve the default gateway.
//
// Falls back to broadcast when every path fails; the caller warns once.
// Returns the MAC, a bool indicating whether the result is authoritative
// (false means the broadcast fallback was used), and any diagnostic err.
func resolveDstMAC(iface string, srcNet *net.IPNet, dst netip.Addr) (net.HardwareAddr, bool, error) {
	nextHop := dst
	if srcNet != nil && !srcNet.Contains(dst.AsSlice()) {
		// Off-link: resolve via gateway.
		gw, err := defaultGateway(iface)
		if err != nil {
			return broadcastMAC(), false, fmt.Errorf("default gateway for %s: %w", iface, err)
		}
		nextHop = gw
	}
	mac, err := lookupARP(nextHop, iface)
	if err != nil {
		return broadcastMAC(), false, err
	}
	return mac, true, nil
}

func broadcastMAC() net.HardwareAddr {
	return net.HardwareAddr{0xff, 0xff, 0xff, 0xff, 0xff, 0xff}
}

// lookupARP reads /proc/net/arp and returns the MAC for ip on iface.
// The kernel populates /proc/net/arp lazily; if the entry is missing,
// the caller can trigger population by sending any packet to the IP
// (even ICMP ping) before retrying. scry's pcap send itself acts as
// that trigger for the very first host — subsequent hosts hit cache.
func lookupARP(ip netip.Addr, iface string) (net.HardwareAddr, error) {
	f, err := os.Open(procNetArp)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	target := ip.String()
	scanner := bufio.NewScanner(f)
	scanner.Scan() // discard header
	for scanner.Scan() {
		fields := strings.Fields(scanner.Text())
		// IP address | HW type | Flags | HW address | Mask | Device
		if len(fields) < 6 {
			continue
		}
		if fields[0] != target {
			continue
		}
		if iface != "" && fields[5] != iface {
			continue
		}
		if fields[3] == "00:00:00:00:00:00" {
			continue // incomplete entry
		}
		mac, err := net.ParseMAC(fields[3])
		if err != nil {
			return nil, err
		}
		return mac, nil
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}
	return nil, fmt.Errorf("no ARP entry for %s on %s", target, iface)
}

// defaultGateway returns the default-gateway IP for iface by reading
// /proc/net/route. The route file is little-endian hex; the default
// route has Destination == 00000000 and the Gateway field is the v4
// address we need.
func defaultGateway(iface string) (netip.Addr, error) {
	f, err := os.Open(procNetRoute)
	if err != nil {
		return netip.Addr{}, err
	}
	defer f.Close()

	scanner := bufio.NewScanner(f)
	scanner.Scan() // header
	for scanner.Scan() {
		fields := strings.Fields(scanner.Text())
		// Iface | Destination | Gateway | Flags | RefCnt | Use | Metric | Mask | MTU | Window | IRTT
		if len(fields) < 3 {
			continue
		}
		if iface != "" && fields[0] != iface {
			continue
		}
		if fields[1] != "00000000" {
			continue
		}
		ip, err := parseHexLEIPv4(fields[2])
		if err != nil {
			return netip.Addr{}, err
		}
		if ip.IsUnspecified() {
			continue
		}
		return ip, nil
	}
	if err := scanner.Err(); err != nil {
		return netip.Addr{}, err
	}
	return netip.Addr{}, errors.New("no default route")
}

// parseHexLEIPv4 parses the little-endian hex form that appears in
// /proc/net/route (e.g. 0100A8C0 → 192.168.0.1).
func parseHexLEIPv4(s string) (netip.Addr, error) {
	if len(s) != 8 {
		return netip.Addr{}, fmt.Errorf("bad length for route hex %q", s)
	}
	b, err := hex.DecodeString(s)
	if err != nil {
		return netip.Addr{}, err
	}
	// File stores little-endian; reverse to get network order.
	b[0], b[1], b[2], b[3] = b[3], b[2], b[1], b[0]
	return netip.AddrFrom4([4]byte{b[0], b[1], b[2], b[3]}), nil
}

// srcSubnet returns the *net.IPNet covering srcIP on iface, or nil if
// the interface can't be enumerated.
func srcSubnet(iface string, srcIP net.IP) *net.IPNet {
	ifc, err := net.InterfaceByName(iface)
	if err != nil {
		return nil
	}
	addrs, err := ifc.Addrs()
	if err != nil {
		return nil
	}
	for _, a := range addrs {
		ipn, ok := a.(*net.IPNet)
		if !ok {
			continue
		}
		if ipn.IP.Equal(srcIP) {
			return ipn
		}
	}
	return nil
}

var _ = strconv.Itoa // reserved for future netlink path