//go:build rawsock && linux

package portscan

import (
	"math/rand"
	"net/netip"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

// sendSYNv6 emits an IPv6 SYN. Neighbour discovery (ND) replaces ARP on
// v6 but Linux's neighbour cache is populated the same way — the first
// outbound packet causes the kernel to solicit, and subsequent sends
// hit cache. Here we use the broadcast-equivalent multicast MAC
// (33:33:00:00:00:01, the "all-nodes" L2 address) as a first-shot
// placeholder so the kernel bridges the send onto the wire. Callers
// that need precise ND resolution are tracked in DEFERRED.md.
func (st *scanState) sendSYNv6(dst netip.Addr, dstPort, srcPort uint16) error {
	// Use the destination's resolved MAC if we have one (future ND
	// support). Until then fall back to all-nodes multicast.
	dstMAC := st.dstMACFor(dst)
	if dstMAC == nil || dstMAC[0] == 0xff { // broadcast isn't valid for v6
		dstMAC = []byte{0x33, 0x33, 0x00, 0x00, 0x00, 0x01}
	}
	eth := layers.Ethernet{
		SrcMAC:       st.srcMAC,
		DstMAC:       dstMAC,
		EthernetType: layers.EthernetTypeIPv6,
	}
	ip6 := layers.IPv6{
		Version:    6,
		HopLimit:   64,
		NextHeader: layers.IPProtocolTCP,
		SrcIP:      st.srcIP, // already v6 when the picker finds v6 addrs
		DstIP:      dst.AsSlice(),
	}
	tcp := layers.TCP{
		SrcPort: layers.TCPPort(srcPort),
		DstPort: layers.TCPPort(dstPort),
		Seq:     rand.Uint32(), //nolint:gosec
		SYN:     true,
		Window:  1024,
	}
	_ = tcp.SetNetworkLayerForChecksum(&ip6)

	buf := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true}
	if err := gopacket.SerializeLayers(buf, opts, &eth, &ip6, &tcp); err != nil {
		return err
	}
	return st.handle.WritePacketData(buf.Bytes())
}
