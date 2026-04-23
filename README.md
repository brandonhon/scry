# scry

Fast IP/port scanner. CLI-first, single static binary, Linux + Windows.

This is the working name. See [`scry-plan.md`](./scry-plan.md) for the full project plan.

## Status

All seven phases merged. Default build is CGO-free and privilege-free; the raw-socket SYN scanner is available under `-tags rawsock` on Linux.

Phases in order:
1. Target parsing (IPv4, ranges, CIDR, hostnames, `@file`; IPv6 is out of scope — see §10 #22 and [`DEFERRED.md`](./DEFERRED.md)).
2. Bounded-concurrency TCP-connect scanner; full `-p` syntax with `top100`/`top1000`/`-p-`.
3. Three output formats: `human` (lipgloss), `json` (NDJSON), `grep`; colour auto-detection.
4. Host discovery (`--ping-only`/`--sn`), reverse DNS, banner grab, stderr progress bar.
5. Lua scripting engine (`--script`) with a curated `scry.*` API and four bundled scripts.
6. Raw-socket SYN scanner under `-tags rawsock` (Linux). See [SYN scanning](#syn-scanning).
7. Hardening: parser fuzz targets, race detector in CI, partial-result flush on SIGINT, man page, goreleaser.

ICMP echo and the Windows Npcap path for SYN are tracked in [`DEFERRED.md`](./DEFERRED.md).

## Build

Linux / macOS:

```sh
make build
```

Windows (PowerShell):

```powershell
.\scripts\build.ps1 build
```

Or directly:

```sh
go build -o bin/scry ./cmd/scry
```

## Usage

```sh
scry 127.0.0.1 -p 22
scry 192.168.1.0/24 -p top100 --up
scry 10.0.0.1-50 -p 22,80,443 --timeout 500ms
scry example.com -p-                    # all 65535 ports
scry 10.0.0.0/24 -p top100 -o json      # NDJSON for pipelines
scry 10.0.0.0/24 -p top100 -o grep      # grepable one-liner per host
scry 10.0.0.0/24 --sn                   # host discovery only
scry 10.0.0.1 -p 22 --banner            # passive banner grab on open ports
scry 10.0.0.0/24 -p 22,80,443,6379 \
  --script scripts/http-title.lua \
  --script scripts/ssh-banner.lua \
  --script scripts/tls-cert-info.lua \
  --script scripts/redis-ping.lua
```

See [`scripts/README.md`](./scripts/README.md) for the `scry.*` API surface and script anatomy.

## Speed vs. accuracy

Defaults are tuned for speed on LAN and low-latency links. If you are scanning WAN targets, over VPN, or across lossy links, raise the timeout and add retries:

| Scenario | Suggested flags |
|---|---|
| LAN / fast link (default) | *(none)* |
| VPN or coffee-shop WiFi | `--timeout 1s --retries 1` |
| Scanning over the public internet | `--timeout 2s --retries 2` |
| Tight socket budget | `--concurrency 500 --max-hosts 20` |

Effective defaults: `--timeout 500ms`, `--retries 0`, `--concurrency 2000`, `--max-hosts 100`. On a lossy link at defaults, filtered ports can be misclassified — bumping `--timeout` and `--retries` trades speed for accuracy.

## SYN scanning

SYN scanning is build-tag gated so the default binary has no libpcap dependency. To enable it:

```sh
# Linux
sudo apt install libpcap-dev                              # or: dnf install libpcap-devel
go build -tags rawsock -o bin/scry ./cmd/scry
sudo setcap cap_net_raw,cap_net_admin=eip bin/scry        # grant privileges without root
./bin/scry 10.0.0.0/24 -p top100 --syn
```

`--syn` on the default binary prints a clean error telling you to rebuild.

### Known pcap limitations

- **Loopback (`127.0.0.0/8`)**: Linux kernel-internal routing bypasses pcap's interface-level capture. A SYN sent from pcap will never appear on `lo`, and an open port on `127.0.0.1` will look filtered. Use TCP-connect mode (default) for loopback scans.
- **WSL2**: the virtualised network adapter breaks the same pcap interface assumptions. Neither loopback nor the WSL2 `eth0` route SYN packets correctly through libpcap. Run SYN scans from a real Linux host (bare-metal, VM with bridged networking, or a cloud instance).
- **Off-link targets**: scry resolves the default gateway's MAC via ARP when sending to hosts outside the local subnet. If that lookup fails the Ethernet frame falls back to broadcast — you'll see a one-time stderr warning. Running with `setcap cap_net_raw,cap_net_admin=eip` is usually what fixes it.

Deferred: Windows Npcap path. IPv6 lives on the `feat/ipv6-support` branch. See [`DEFERRED.md`](./DEFERRED.md).

### Output formats

**human** (default): colour-coded, per-host block with service annotations.
```
UP    192.168.1.10  12ms
     22/tcp  open      ssh                180µs
     80/tcp  open      http               212µs
```

**json**: one host per line.
```
{"addr":"192.168.1.10","up":true,"started":"...","elapsed":"12ms","results":[{"port":22,"proto":"tcp","state":"open","service":"ssh","rtt":"180µs"}]}
```

**grep**: one grepable line per host.
```
Host: 192.168.1.10	Status: up	Ports: 22/open/ssh,80/open/http	Elapsed: 12ms
```

Accepted target forms (parser, `internal/target`):

- Single IPv4: `192.168.1.10` (IPv6 is out of scope; see §10 #22)
- Last-octet range: `192.168.1.10-50`
- Arbitrary range: `192.168.1.10-192.168.2.20`
- CIDR: `192.168.1.0/24`
- Hostname: `example.com`
- File: `@targets.txt` (one entry per line)
- Comma-separated lists of any of the above
- Exclusions via `--exclude`

## License

MIT — see [`LICENSE`](./LICENSE).
