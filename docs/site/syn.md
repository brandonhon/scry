---
title: SYN scanning
---

# SYN scanning

The default scry binary uses TCP connect scans — zero privileges, no
CGO, no libpcap. SYN scanning is opt-in behind the `rawsock` build tag.

## Why it's gated

- Pulls in `github.com/google/gopacket` and links against libpcap.
- Needs `CAP_NET_RAW` (Linux) or Npcap (Windows, not yet shipped).
- Loopback and WSL2 virtual adapters don't route SYN packets through
  pcap — verification requires a real adjacent host.

## Build

```sh
sudo apt install libpcap-dev            # Debian/Ubuntu
sudo dnf install libpcap-devel          # Fedora/RHEL

go build -tags rawsock -o bin/scry ./cmd/scry
sudo setcap cap_net_raw,cap_net_admin=eip bin/scry
```

## Use

```sh
./bin/scry 10.0.0.0/24 -p top100 --syn
./bin/scry 10.0.0.1 -p- --syn --rate 20000
```

## Flags

| Flag | Purpose |
|---|---|
| `--syn` | Use raw SYN scanner (requires `rawsock` + CAP_NET_RAW). |
| `--rate N` | Max SYN packets/sec; 0 = unlimited. Default 10000. |
| `--adaptive` | Start at `--rate/4` and scale up/down based on probe error rate. |

## Known limitations

- **Loopback (`127.0.0.0/8`)**: kernel routes bypass pcap. Use connect
  mode for loopback.
- **WSL2**: virtualised adapter breaks pcap interface routing; use a
  real Linux host.
- **Off-link ARP**: scry reads `/proc/net/arp` and `/proc/net/route`
  for destination MAC resolution. If every path fails it falls back
  to broadcast and prints a one-time stderr warning.
- **Windows (Npcap)**: not yet shipped; see [`DEFERRED.md`]({{ site.github.repository_url }}/blob/main/DEFERRED.md)
  and the plan §10 #21.
- **IPv6**: parked on `feat/ipv6-support`; see §10 #22.
