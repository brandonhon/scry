//go:build rawsock && linux

package portscan

import (
	"net/netip"
	"os"
	"path/filepath"
	"testing"
)

func writeFixture(t *testing.T, body string) string {
	t.Helper()
	dir := t.TempDir()
	p := filepath.Join(dir, "f")
	if err := os.WriteFile(p, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestLookupARP_FindsEntry(t *testing.T) {
	body := `IP address       HW type     Flags       HW address            Mask     Device
192.168.1.1      0x1         0x2         aa:bb:cc:dd:ee:ff     *        eth0
192.168.1.99     0x1         0x0         00:00:00:00:00:00     *        eth0
`
	p := writeFixture(t, body)
	orig := procNetArp
	t.Cleanup(func() { procNetArp = orig })
	procNetArp = p

	mac, err := lookupARP(netip.MustParseAddr("192.168.1.1"), "eth0")
	if err != nil {
		t.Fatal(err)
	}
	if mac.String() != "aa:bb:cc:dd:ee:ff" {
		t.Fatalf("got %s, want aa:bb:cc:dd:ee:ff", mac)
	}
}

func TestLookupARP_IncompleteEntrySkipped(t *testing.T) {
	body := `IP address       HW type     Flags       HW address            Mask     Device
192.168.1.99     0x1         0x0         00:00:00:00:00:00     *        eth0
`
	p := writeFixture(t, body)
	orig := procNetArp
	t.Cleanup(func() { procNetArp = orig })
	procNetArp = p

	if _, err := lookupARP(netip.MustParseAddr("192.168.1.99"), "eth0"); err == nil {
		t.Fatal("expected no-entry error for incomplete record")
	}
}

func TestLookupARP_WrongInterfaceIgnored(t *testing.T) {
	body := `IP address       HW type     Flags       HW address            Mask     Device
192.168.1.1      0x1         0x2         aa:bb:cc:dd:ee:ff     *        wlan0
`
	p := writeFixture(t, body)
	orig := procNetArp
	t.Cleanup(func() { procNetArp = orig })
	procNetArp = p

	if _, err := lookupARP(netip.MustParseAddr("192.168.1.1"), "eth0"); err == nil {
		t.Fatal("expected no-entry error when iface mismatch")
	}
}

func TestDefaultGateway_FindsDefaultRoute(t *testing.T) {
	// Destination 00000000 = default route; Gateway 0100A8C0 = 192.168.0.1
	// (little-endian hex in /proc/net/route).
	body := `Iface	Destination	Gateway 	Flags	RefCnt	Use	Metric	Mask		MTU	Window	IRTT
eth0	0000A8C0	00000000	0001	0	0	0	00FFFFFF	0	0	0
eth0	00000000	0100A8C0	0003	0	0	0	00000000	0	0	0
`
	p := writeFixture(t, body)
	orig := procNetRoute
	t.Cleanup(func() { procNetRoute = orig })
	procNetRoute = p

	gw, err := defaultGateway("eth0")
	if err != nil {
		t.Fatal(err)
	}
	if gw.String() != "192.168.0.1" {
		t.Fatalf("got %s, want 192.168.0.1", gw)
	}
}

func TestDefaultGateway_NoDefaultRoute(t *testing.T) {
	body := `Iface	Destination	Gateway 	Flags	RefCnt	Use	Metric	Mask		MTU	Window	IRTT
eth0	0000A8C0	00000000	0001	0	0	0	00FFFFFF	0	0	0
`
	p := writeFixture(t, body)
	orig := procNetRoute
	t.Cleanup(func() { procNetRoute = orig })
	procNetRoute = p

	if _, err := defaultGateway("eth0"); err == nil {
		t.Fatal("expected no-default-route error")
	}
}

func TestParseHexLEIPv4(t *testing.T) {
	cases := []struct {
		in, want string
	}{
		{"0100A8C0", "192.168.0.1"},
		{"01020304", "4.3.2.1"},
	}
	for _, tc := range cases {
		got, err := parseHexLEIPv4(tc.in)
		if err != nil {
			t.Errorf("%s: %v", tc.in, err)
		}
		if got.String() != tc.want {
			t.Errorf("%s → %s, want %s", tc.in, got, tc.want)
		}
	}
}
