# scry

Fast IP/port scanner. CLI-first, single static binary, Linux + Windows.

This is the working name. See [`scry-plan.md`](./scry-plan.md) for the full project plan.

## Status

All seven phases merged. Default build is CGO-free and privilege-free; the raw-socket SYN scanner is available under `-tags rawsock` on Linux.

Phases in order:
1. Target parsing (IPv4+IPv6, ranges, CIDR, hostnames, `@file`).
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

## SYN scanning

SYN scanning is build-tag gated so the default binary has no libpcap dependency. To enable it:

```sh
# Linux
sudo apt install libpcap-dev                              # or: dnf install libpcap-devel
go build -tags rawsock -o bin/scry ./cmd/scry
sudo setcap cap_net_raw,cap_net_admin=eip bin/scry        # grant privileges without root
./bin/scry 10.0.0.0/24 -p top100 --syn
```

`--syn` on the default binary prints a clean error telling you to rebuild. Loopback and WSL2 virtual adapters are known not to route SYN packets correctly through pcap; use a real adjacent host for verification.

Deferred: Windows Npcap path, IPv6 SYN, ARP/gateway MAC resolution, token-bucket `--rate` pacing. See [`DEFERRED.md`](./DEFERRED.md).

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

- Single IPv4/IPv6: `192.168.1.10`, `::1`
- Last-octet range: `192.168.1.10-50`
- Arbitrary range: `192.168.1.10-192.168.2.20`
- CIDR: `192.168.1.0/24`, `2001:db8::/120`
- Hostname: `example.com`
- File: `@targets.txt` (one entry per line)
- Comma-separated lists of any of the above
- Exclusions via `--exclude`

## License

MIT — see [`LICENSE`](./LICENSE).
