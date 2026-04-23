//go:build rawsock && linux

// Package-level SYN scanner for Linux using libpcap via gopacket.
//
// The scanner opens a single pcap handle on the outbound interface,
// crafts and sends bare SYN packets from a sender goroutine, and reads
// responses in a receiver goroutine. Outstanding probes are tracked in
// a (srcPort, dstAddr, dstPort) → waiter map; a match wakes the waiter
// and classifies the probe (open/closed/filtered).
//
// Build with `-tags rawsock` after installing libpcap-dev. Run with
// CAP_NET_RAW:
//
//	sudo setcap cap_net_raw,cap_net_admin=eip ./scry
//
// Without the capability, pcap.OpenLive will fail with a clear error.
package portscan

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"math/rand"
	"net"
	"net/netip"
	"sync"
	"sync/atomic"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"

	"github.com/bhoneycutt/scry/internal/progress"
	"github.com/bhoneycutt/scry/internal/target"
)

// SYNAvailable is true in rawsock builds.
const SYNAvailable = true

// ErrSYNUnavailable is defined on all builds; in this one it's a nil-like
// sentinel that callers won't hit because the CLI permits --syn.
var ErrSYNUnavailable error

// SynScan opens a pcap handle synchronously, then returns a result
// channel in the same streaming shape as Scan. Setup failures (missing
// capability, no interface, libpcap issues) are returned as an error so
// the CLI can surface them before any output is emitted.
func SynScan(ctx context.Context, it *target.Iterator, cfg Config) (<-chan HostResult, error) {
	cfg = applyDefaults(cfg)

	rep := cfg.Progress
	if rep == nil {
		rep = progress.NewNoop()
	}
	if total, ok := it.Total(); ok {
		rep.SetTotal(int64(total))
	}

	state, cleanup, err := setupSYN(ctx, cfg.Timeout)
	if err != nil {
		return nil, err
	}

	out := make(chan HostResult, cfg.HostParall)
	go func() {
		defer func() {
			cleanup()
			rep.Finish()
			close(out)
		}()
		runSYN(ctx, state, it, cfg, out, rep)
	}()
	return out, nil
}

// ---- internals --------------------------------------------------------------

// scanState tracks in-flight SYN probes for a single scan run.
type scanState struct {
	mu       sync.Mutex
	waiters  map[probeKey]*probeWaiter
	srcIP    net.IP
	srcMAC   net.HardwareAddr
	dstMAC   net.HardwareAddr // gateway MAC for off-link dsts; same-subnet is rare in practice
	iface    string
	handle   *pcap.Handle
	basePort uint16 // ephemeral base; each probe uses basePort + portIdx++
	portIdx  uint32
}

type probeKey struct {
	srcPort uint16
	dstIP   [16]byte
	dstPort uint16
}

type probeWaiter struct {
	done    chan probeOutcome
	started time.Time
}

type probeOutcome struct {
	state State
	rtt   time.Duration
}

func runSYN(ctx context.Context, state *scanState, it *target.Iterator, cfg Config, out chan<- HostResult, rep progress.Reporter) {
	// Receiver goroutine reads responses and wakes waiters.
	recvCtx, recvCancel := context.WithCancel(ctx)
	defer recvCancel()
	go receiveLoop(recvCtx, state)

	// Iterator-driven host worker pool. Each host goroutine sends one
	// SYN per configured port, registers the waiter, waits for either
	// a response or the timeout, then emits a HostResult.
	var wg sync.WaitGroup
	hostSem := make(chan struct{}, cfg.HostParall)

loop:
	for {
		if err := ctx.Err(); err != nil {
			break loop
		}
		addr, ok := it.Next()
		if !ok {
			break loop
		}
		if !addr.Is4() {
			// IPv6 is deferred (DEFERRED.md). Report via an error result.
			res := HostResult{
				Addr:    addr,
				Started: time.Now(),
				Results: []Result{{Addr: addr, State: StateError, Err: errors.New("SYN scan supports IPv4 only in this build")}},
			}
			rep.Tick()
			out <- res
			continue
		}
		hostSem <- struct{}{}
		wg.Add(1)
		go func(addr netip.Addr) {
			defer wg.Done()
			defer func() { <-hostSem }()
			hr := scanHostSYN(ctx, state, addr, cfg)
			rep.Tick()
			out <- hr
		}(addr)
	}

	wg.Wait()
}

// scanHostSYN probes every configured port on one host. Each port gets
// its own ephemeral source port (basePort + atomic index) so responses
// can be demultiplexed in the receiver without a bloom-style filter.
func scanHostSYN(ctx context.Context, st *scanState, dst netip.Addr, cfg Config) HostResult {
	start := time.Now()
	hr := HostResult{Addr: dst, Started: start}

	var mu sync.Mutex
	var wg sync.WaitGroup
	for _, port := range cfg.Ports {
		wg.Add(1)
		go func(port uint16) {
			defer wg.Done()
			res := synProbe(ctx, st, dst, port, cfg.Timeout)
			mu.Lock()
			hr.Results = append(hr.Results, res)
			mu.Unlock()
		}(port)
	}
	wg.Wait()
	hr.Elapsed = time.Since(start)
	return hr
}

// synProbe sends one SYN, registers a waiter, and blocks until a matching
// response or the timeout. Retries once on StateFiltered per §5.
func synProbe(ctx context.Context, st *scanState, dst netip.Addr, port uint16, timeout time.Duration) Result {
	res := Result{Addr: dst, Port: port}

	attempt := func() probeOutcome {
		srcPort := st.allocSrcPort()
		key := makeKey(srcPort, dst, port)

		waiter := &probeWaiter{done: make(chan probeOutcome, 1), started: time.Now()}
		st.mu.Lock()
		st.waiters[key] = waiter
		st.mu.Unlock()
		defer func() {
			st.mu.Lock()
			delete(st.waiters, key)
			st.mu.Unlock()
		}()

		if err := st.sendSYN(dst, port, srcPort); err != nil {
			return probeOutcome{state: StateError}
		}
		select {
		case out := <-waiter.done:
			return out
		case <-time.After(timeout):
			return probeOutcome{state: StateFiltered, rtt: timeout}
		case <-ctx.Done():
			return probeOutcome{state: StateError}
		}
	}

	out := attempt()
	if out.state == StateFiltered {
		out = attempt() // single retransmit, §5 retransmit policy
	}
	res.State = out.state
	res.RTT = out.rtt
	return res
}

// receiveLoop reads packets from the pcap handle and matches them against
// the waiter map.
func receiveLoop(ctx context.Context, st *scanState) {
	src := gopacket.NewPacketSource(st.handle, st.handle.LinkType())
	for {
		select {
		case <-ctx.Done():
			return
		case pkt, ok := <-src.Packets():
			if !ok {
				return
			}
			parseAndDispatch(pkt, st)
		}
	}
}

// parseAndDispatch extracts an IPv4+TCP layer from pkt; if it matches a
// waiter, classifies and notifies.
func parseAndDispatch(pkt gopacket.Packet, st *scanState) {
	ipL := pkt.Layer(layers.LayerTypeIPv4)
	tcpL := pkt.Layer(layers.LayerTypeTCP)
	if ipL == nil || tcpL == nil {
		return
	}
	ip := ipL.(*layers.IPv4)
	tcp := tcpL.(*layers.TCP)

	// The reply's src is the probe's dst.
	srcAddr, ok := netip.AddrFromSlice(ip.SrcIP.To4())
	if !ok {
		return
	}
	key := makeKey(uint16(tcp.DstPort), srcAddr, uint16(tcp.SrcPort))
	st.mu.Lock()
	waiter, found := st.waiters[key]
	st.mu.Unlock()
	if !found {
		return
	}
	var state State
	switch {
	case tcp.SYN && tcp.ACK:
		state = StateOpen
	case tcp.RST:
		state = StateClosed
	default:
		// Anything else is ambiguous; leave as filtered so the timeout or
		// retransmit path handles it.
		return
	}
	select {
	case waiter.done <- probeOutcome{state: state, rtt: time.Since(waiter.started)}:
	default:
	}
}

func makeKey(srcPort uint16, dst netip.Addr, dstPort uint16) probeKey {
	return probeKey{srcPort: srcPort, dstIP: dst.As16(), dstPort: dstPort}
}

// allocSrcPort returns the next ephemeral source port. Wraps the 16-bit
// space so long scans don't overflow and so the 16-bit mod is explicit.
func (st *scanState) allocSrcPort() uint16 {
	n := atomic.AddUint32(&st.portIdx, 1)
	// Offset into the high half of the ephemeral range so we don't step
	// on connections the OS is already using.
	return st.basePort + uint16(n&0x3FFF)
}

// sendSYN crafts and emits a single SYN on the pcap handle.
func (st *scanState) sendSYN(dst netip.Addr, dstPort, srcPort uint16) error {
	eth := layers.Ethernet{
		SrcMAC:       st.srcMAC,
		DstMAC:       st.dstMAC,
		EthernetType: layers.EthernetTypeIPv4,
	}
	ip := layers.IPv4{
		Version:  4,
		IHL:      5,
		TTL:      64,
		Protocol: layers.IPProtocolTCP,
		SrcIP:    st.srcIP.To4(),
		DstIP:    dst.AsSlice(),
	}
	tcp := layers.TCP{
		SrcPort: layers.TCPPort(srcPort),
		DstPort: layers.TCPPort(dstPort),
		Seq:     rand.Uint32(), //nolint:gosec // not security-critical
		SYN:     true,
		Window:  1024,
	}
	_ = tcp.SetNetworkLayerForChecksum(&ip)

	buf := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true}
	if err := gopacket.SerializeLayers(buf, opts, &eth, &ip, &tcp); err != nil {
		return err
	}
	return st.handle.WritePacketData(buf.Bytes())
}

// setupSYN discovers an outbound interface, opens pcap, and prepares the
// rendering state. This is deliberately best-effort for v0.2: it picks the
// first non-loopback interface with an IPv4 address and uses its hardware
// address as the source. Gateway MAC detection is skipped — most practical
// scans are on the same broadcast domain where we can resolve the dst MAC
// via ARP lookups (not yet wired); for off-link we'd need a default-gateway
// lookup. Future work: see DEFERRED.md.
func setupSYN(ctx context.Context, timeout time.Duration) (*scanState, func(), error) {
	iface, srcIP, srcMAC, err := pickInterface()
	if err != nil {
		return nil, nil, err
	}
	h, err := pcap.OpenLive(iface, 65535, true, timeout)
	if err != nil {
		return nil, nil, fmt.Errorf("pcap open %s: %w (need CAP_NET_RAW or root)", iface, err)
	}
	if err := h.SetBPFFilter("tcp"); err != nil {
		h.Close()
		return nil, nil, fmt.Errorf("bpf filter: %w", err)
	}
	st := &scanState{
		waiters:  make(map[probeKey]*probeWaiter, 1024),
		srcIP:    srcIP,
		srcMAC:   srcMAC,
		dstMAC:   net.HardwareAddr{0xff, 0xff, 0xff, 0xff, 0xff, 0xff}, // broadcast placeholder
		iface:    iface,
		handle:   h,
		basePort: 40000 + uint16(rand.Intn(10000)), //nolint:gosec
	}
	return st, func() { h.Close() }, nil
}

func pickInterface() (string, net.IP, net.HardwareAddr, error) {
	ifaces, err := net.Interfaces()
	if err != nil {
		return "", nil, nil, err
	}
	for _, ifc := range ifaces {
		if ifc.Flags&net.FlagLoopback != 0 || ifc.Flags&net.FlagUp == 0 {
			continue
		}
		addrs, _ := ifc.Addrs()
		for _, a := range addrs {
			ipn, ok := a.(*net.IPNet)
			if !ok || ipn.IP.To4() == nil {
				continue
			}
			return ifc.Name, ipn.IP, ifc.HardwareAddr, nil
		}
	}
	return "", nil, nil, errors.New("no non-loopback IPv4 interface found")
}

// Silence unused-import lints when building without the binary package.
var _ = binary.BigEndian
