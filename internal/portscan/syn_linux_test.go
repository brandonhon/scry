//go:build rawsock && linux

package portscan

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"os"
	"strconv"
	"testing"
	"time"

	"github.com/brandonhon/scry/internal/target"
	"github.com/google/gopacket/pcap"
)

// requirePcap skips the test when the process can't open a pcap handle —
// which is the common case outside of CI/root sessions. We deliberately
// avoid `os.Getuid()==0` because CAP_NET_RAW via setcap doesn't change
// the uid. Checking for the actual capability by attempting to open
// any interface is the cleanest proxy.
func requirePcap(t *testing.T) {
	t.Helper()
	ifs, err := pcap.FindAllDevs()
	if err != nil || len(ifs) == 0 {
		t.Skipf("no pcap devices available: %v", err)
	}
	h, err := pcap.OpenLive(ifs[0].Name, 1600, true, 10*time.Millisecond)
	if err != nil {
		t.Skipf("pcap open failed (need CAP_NET_RAW): %v", err)
	}
	h.Close()
}

func TestSynScan_LoopbackListenerReportsOpen(t *testing.T) {
	if os.Getenv("SCRY_RUN_SYN_TESTS") == "" {
		t.Skip("set SCRY_RUN_SYN_TESTS=1 to opt in; requires CAP_NET_RAW")
	}
	requirePcap(t)

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer ln.Close()
	_, pStr, _ := net.SplitHostPort(ln.Addr().String())
	port, _ := strconv.Atoi(pStr)

	it, err := target.Parse([]string{"127.0.0.1"}, target.Options{})
	if err != nil {
		t.Fatal(err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	out, err := SynScan(ctx, it, Config{
		Ports:      []uint16{uint16(port)},
		Timeout:    1 * time.Second,
		HostParall: 1,
	})
	if err != nil {
		t.Fatalf("SynScan setup: %v", err)
	}

	var seenOpen bool
	for hr := range out {
		for _, r := range hr.Results {
			if r.State == StateOpen && int(r.Port) == port {
				seenOpen = true
			}
			if r.State == StateError && r.Err != nil {
				t.Logf("SYN error: %v", r.Err)
			}
		}
	}
	if !seenOpen {
		t.Fatal("SYN scan did not classify the listening port as open")
	}
}

// TestSynScan_RealTarget runs the SYN scanner against an
// operator-supplied host and port. Opt-in via:
//
//	SCRY_RUN_SYN_TESTS=1
//	SCRY_SYN_TARGET=host:port   # real, reachable, non-WSL
//
// The test passes when the target port is classified open OR closed —
// both prove the pcap path sent and matched a response. A filtered
// outcome usually means ARP/routing broke; the test logs a hint.
func TestSynScan_RealTarget(t *testing.T) {
	if os.Getenv("SCRY_RUN_SYN_TESTS") == "" {
		t.Skip("set SCRY_RUN_SYN_TESTS=1 to opt in")
	}
	target := os.Getenv("SCRY_SYN_TARGET")
	if target == "" {
		t.Skip("set SCRY_SYN_TARGET=host:port to exercise the real-network path")
	}
	requirePcap(t)

	host, pStr, err := net.SplitHostPort(target)
	if err != nil {
		t.Fatalf("SCRY_SYN_TARGET=%q is not host:port: %v", target, err)
	}
	port, err := strconv.Atoi(pStr)
	if err != nil || port <= 0 || port > 65535 {
		t.Fatalf("SCRY_SYN_TARGET port %q: %v", pStr, err)
	}

	it, err := targetParse(host)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	out, err := SynScan(ctx, it, Config{
		Ports:      []uint16{uint16(port)},
		Timeout:    3 * time.Second,
		HostParall: 1,
		Retries:    1,
	})
	if err != nil {
		t.Fatalf("SynScan setup: %v", err)
	}

	var seenAnswer bool
	for hr := range out {
		for _, r := range hr.Results {
			t.Logf("%s:%d → %s (rtt=%s)", r.Addr, r.Port, r.State, r.RTT)
			switch r.State {
			case StateOpen, StateClosed:
				seenAnswer = true
			case StateFiltered:
				t.Logf("filtered — if consistent, check CAP_NET_RAW, firewall, and ARP/gateway reachability to %s", host)
			}
		}
	}
	if !seenAnswer {
		t.Fatalf("no open/closed classification from %s — pcap path may be broken", target)
	}
}

// targetParse wraps target.Parse for the single-host shape used above.
func targetParse(host string) (*target.Iterator, error) {
	return target.Parse([]string{host}, target.Options{})
}

var _ = errors.New
var _ = netip.Addr{}
