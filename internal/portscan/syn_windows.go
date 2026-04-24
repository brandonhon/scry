//go:build rawsock && windows

// SYN scanner for Windows using Npcap via gopacket.
//
// Run requirements:
//   - Npcap installed in WinPcap-compatible mode.
//   - The scry binary must run elevated (Administrator).
//
// Known v0 limitations compared to the Linux path:
//   - Destination MAC resolution is a broadcast fallback only. A proper
//     implementation would call GetIpNetTable2 (iphlpapi.dll) for the
//     ARP cache and resolve the default-gateway MAC for off-link
//     targets. DEFERRED.md tracks this follow-up.
//   - This file intentionally duplicates the Linux scanner rather than
//     sharing machinery behind a platform interface. Keeping the known-
//     good Linux path untouched during Windows scaffolding was judged
//     lower risk than a large refactor.
//
// Build with:
//
//	GOOS=windows go build -tags rawsock -o scry.exe ./cmd/scry
package portscan

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"math/rand"
	"net"
	"net/netip"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"

	"github.com/bhoneycutt/scry/internal/progress"
	"github.com/bhoneycutt/scry/internal/ratelimit"
	"github.com/bhoneycutt/scry/internal/target"
)

const SYNAvailable = true

var ErrSYNUnavailable error

// SynScan — Windows entry point. Same streaming contract as Linux.
func SynScan(ctx context.Context, it *target.Iterator, cfg Config) (<-chan HostResult, error) {
	cfg = applyDefaults(cfg)

	rep := cfg.Progress
	if rep == nil {
		rep = progress.NewNoop()
	}
	if total, ok := it.Total(); ok {
		unit := int64(1)
		if len(cfg.Ports) > 0 {
			unit = int64(len(cfg.Ports))
		}
		rep.SetTotal(int64(total) * unit)
	}

	state, cleanup, err := setupSYN(ctx, cfg.Timeout, cfg.Rate, cfg.Adaptive)
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

// ---- shared types (duplicated from syn_linux.go; see file header) ----------

type scanState struct {
	mu       sync.Mutex
	waiters  map[probeKey]*probeWaiter
	srcIP    net.IP
	srcMAC   net.HardwareAddr
	srcNet   *net.IPNet
	iface    string
	handle   *pcap.Handle
	basePort uint16
	portIdx  uint32
	limiter  *ratelimit.Limiter
	adaptive *ratelimit.Adaptive

	macMu     sync.Mutex
	macByDst  map[netip.Addr]net.HardwareAddr
	bcastWarn sync.Once
	warnW     io.Writer
}

func (st *scanState) waitForToken(ctx context.Context) error {
	if st.adaptive != nil {
		return st.adaptive.Wait(ctx)
	}
	return st.limiter.Wait(ctx)
}

func (st *scanState) reportProbe(state State) {
	if st.adaptive == nil {
		return
	}
	isErr := state == StateFiltered || state == StateError
	st.adaptive.ReportProbe(isErr)
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
	recvCtx, recvCancel := context.WithCancel(ctx)
	defer recvCancel()
	go receiveLoop(recvCtx, state)

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
		hostSem <- struct{}{}
		wg.Add(1)
		go func(addr netip.Addr) {
			defer wg.Done()
			defer func() { <-hostSem }()
			hr := scanHostSYN(ctx, state, addr, cfg, rep)
			out <- hr
		}(addr)
	}
	wg.Wait()
}

func scanHostSYN(ctx context.Context, st *scanState, dst netip.Addr, cfg Config, rep progress.Reporter) HostResult {
	start := time.Now()
	hr := HostResult{Addr: dst, Started: start}

	var mu sync.Mutex
	var wg sync.WaitGroup
	for _, port := range cfg.Ports {
		wg.Add(1)
		go func(port uint16) {
			defer wg.Done()
			defer rep.Tick()
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

		if err := st.waitForToken(ctx); err != nil {
			return probeOutcome{state: StateError}
		}
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
		out = attempt()
	}
	res.State = out.state
	res.RTT = out.rtt
	st.reportProbe(out.state)
	return res
}

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

func parseAndDispatch(pkt gopacket.Packet, st *scanState) {
	ipL := pkt.Layer(layers.LayerTypeIPv4)
	tcpL := pkt.Layer(layers.LayerTypeTCP)
	if ipL == nil || tcpL == nil {
		return
	}
	ip := ipL.(*layers.IPv4)
	tcp := tcpL.(*layers.TCP)
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

func (st *scanState) allocSrcPort() uint16 {
	n := atomic.AddUint32(&st.portIdx, 1)
	return st.basePort + uint16(n&0x3FFF)
}

func (st *scanState) sendSYN(dst netip.Addr, dstPort, srcPort uint16) error {
	eth := layers.Ethernet{
		SrcMAC:       st.srcMAC,
		DstMAC:       st.dstMACFor(dst),
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
		Seq:     rand.Uint32(), //nolint:gosec
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

// dstMACFor — Windows v0 uses the broadcast fallback unconditionally and
// prints a single warning. TODO: GetIpNetTable2 path.
func (st *scanState) dstMACFor(dst netip.Addr) net.HardwareAddr {
	st.macMu.Lock()
	if mac, ok := st.macByDst[dst]; ok {
		st.macMu.Unlock()
		return mac
	}
	st.macMu.Unlock()

	st.bcastWarn.Do(func() {
		_, _ = fmt.Fprintln(st.warnW,
			"warning: Windows SYN scanner uses broadcast dst MAC (no ARP resolution yet); results may be unreliable on off-link targets. See DEFERRED.md.")
	})
	mac := net.HardwareAddr{0xff, 0xff, 0xff, 0xff, 0xff, 0xff}

	st.macMu.Lock()
	st.macByDst[dst] = mac
	st.macMu.Unlock()
	return mac
}

// setupSYN opens an Npcap handle on the first non-loopback interface
// with an IPv4 address. Npcap device names are of the form
// \Device\NPF_{GUID}; we match them to Go net.Interface entries by
// comparing assigned addresses.
func setupSYN(ctx context.Context, timeout time.Duration, rps int, adaptive bool) (*scanState, func(), error) {
	dev, srcIP, srcMAC, err := pickInterface()
	if err != nil {
		return nil, nil, fmt.Errorf("pick Npcap device: %w (is Npcap installed in WinPcap-compatible mode?)", err)
	}
	h, err := pcap.OpenLive(dev, 65535, true, timeout)
	if err != nil {
		return nil, nil, fmt.Errorf("pcap open %s: %w (need Administrator)", dev, err)
	}
	if err := h.SetBPFFilter("tcp"); err != nil {
		h.Close()
		return nil, nil, fmt.Errorf("bpf filter: %w", err)
	}
	burst := rps
	if burst > 1000 {
		burst = 1000
	}
	st := &scanState{
		waiters:  make(map[probeKey]*probeWaiter, 1024),
		srcIP:    srcIP,
		srcMAC:   srcMAC,
		srcNet:   srcSubnet(dev, srcIP),
		iface:    dev,
		handle:   h,
		basePort: 40000 + uint16(rand.Intn(10000)), //nolint:gosec
		macByDst: make(map[netip.Addr]net.HardwareAddr, 64),
		warnW:    os.Stderr,
	}
	if adaptive && rps > 0 {
		start := rps / 4
		if start < 100 {
			start = 100
		}
		st.adaptive = ratelimit.NewAdaptive(start, rps)
	} else {
		st.limiter = ratelimit.New(rps, burst)
	}
	return st, func() { h.Close() }, nil
}

// pickInterface matches Npcap devices (from pcap.FindAllDevs) against
// Go's net.Interfaces by IPv4 address. Returns the Npcap device name
// (suitable for pcap.OpenLive), the chosen source IP, and the MAC of
// the matching net.Interface.
func pickInterface() (string, net.IP, net.HardwareAddr, error) {
	devs, err := pcap.FindAllDevs()
	if err != nil {
		return "", nil, nil, err
	}
	ifaces, err := net.Interfaces()
	if err != nil {
		return "", nil, nil, err
	}
	// Index net.Interfaces by their IPv4 address for fast lookup.
	byAddr := make(map[string]*net.Interface, len(ifaces))
	for i := range ifaces {
		ifc := &ifaces[i]
		if ifc.Flags&net.FlagLoopback != 0 || ifc.Flags&net.FlagUp == 0 {
			continue
		}
		addrs, _ := ifc.Addrs()
		for _, a := range addrs {
			ipn, ok := a.(*net.IPNet)
			if !ok || ipn.IP.To4() == nil {
				continue
			}
			byAddr[ipn.IP.String()] = ifc
		}
	}
	for _, dev := range devs {
		// Skip obviously-loopback devices by name (pcap doesn't expose a
		// PCAP_IF_LOOPBACK constant on every build). Npcap typically
		// exposes the loopback adapter as "\Device\NPF_Loopback".
		if strings.Contains(strings.ToLower(dev.Name), "loopback") {
			continue
		}
		for _, a := range dev.Addresses {
			v4 := a.IP.To4()
			if v4 == nil {
				continue
			}
			if ifc, ok := byAddr[v4.String()]; ok {
				return dev.Name, v4, ifc.HardwareAddr, nil
			}
		}
	}
	return "", nil, nil, errors.New("no Npcap device with an IPv4 address found")
}

// srcSubnet finds the *net.IPNet covering srcIP.
func srcSubnet(_ string, srcIP net.IP) *net.IPNet {
	ifaces, err := net.Interfaces()
	if err != nil {
		return nil
	}
	for _, ifc := range ifaces {
		addrs, _ := ifc.Addrs()
		for _, a := range addrs {
			ipn, ok := a.(*net.IPNet)
			if !ok {
				continue
			}
			if ipn.IP.Equal(srcIP) {
				return ipn
			}
		}
	}
	return nil
}

// Silence unused-import lints.
var _ = binary.BigEndian
var _ = strings.Contains
