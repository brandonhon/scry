# gscan

Fast IP/port scanner. CLI-first, single static binary, Linux + Windows.

This is the working name. See [`ip-scanner-plan.md`](./ip-scanner-plan.md) for the full project plan.

## Status

Phase 4 (discovery, DNS, banners, progress). Adds:
- `--ping-only` / `--sn` — TCP host discovery without a full port scan.
- Reverse DNS in parallel with port probing, per-run cache, `--no-dns` opt-out.
- `--banner` — passive banner grab on open ports.
- stderr progress bar on TTYs (auto-suppressed for pipes); `--no-progress` opts out.

ICMP echo is deferred to Phase 6 alongside SYN scanning under a build tag so the default binary stays dependency-free. TCP connect is still the only probe type in v1.

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
```

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
