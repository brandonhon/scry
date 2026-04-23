# gscan

Fast IP/port scanner. CLI-first, single static binary, Linux + Windows.

This is the working name. See [`ip-scanner-plan.md`](./ip-scanner-plan.md) for the full project plan.

## Status

Phase 7 (hardening). Parser fuzz targets, race detector in CI, partial-result flush on SIGINT, `make man` (checked-in `docs/man/gscan.1`), goreleaser config, tag-triggered release workflow.

Earlier phases in order:
1. Target parsing (IPv4+IPv6, ranges, CIDR, hostnames, `@file`).
2. Bounded-concurrency TCP-connect scanner; full `-p` syntax with `top100`/`top1000`/`-p-`.
3. Three output formats: `human` (lipgloss), `json` (NDJSON), `grep`; colour auto-detection.
4. Host discovery (`--ping-only`/`--sn`), reverse DNS, banner grab, stderr progress bar.
5. Lua scripting engine (`--script`) with a curated `gscan.*` API and four bundled scripts.

Phase 6 (SYN scan + ICMP, raw sockets under `-tags rawsock`) is queued in [`DEFERRED.md`](./DEFERRED.md) and is intentionally left for after v0.1.0 so the shipping binary stays CGO- and privilege-free.

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
go build -o bin/gscan ./cmd/gscan
```

## Usage

```sh
gscan 127.0.0.1 -p 22
gscan 192.168.1.0/24 -p top100 --up
gscan 10.0.0.1-50 -p 22,80,443 --timeout 500ms
gscan example.com -p-                    # all 65535 ports
gscan 10.0.0.0/24 -p top100 -o json      # NDJSON for pipelines
gscan 10.0.0.0/24 -p top100 -o grep      # grepable one-liner per host
gscan 10.0.0.0/24 --sn                   # host discovery only
gscan 10.0.0.1 -p 22 --banner            # passive banner grab on open ports
gscan 10.0.0.0/24 -p 22,80,443,6379 \
  --script scripts/http-title.lua \
  --script scripts/ssh-banner.lua \
  --script scripts/tls-cert-info.lua \
  --script scripts/redis-ping.lua
```

See [`scripts/README.md`](./scripts/README.md) for the `gscan.*` API surface and script anatomy.

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
