# gscan

Fast IP/port scanner. CLI-first, single static binary, Linux + Windows.

This is the working name. See [`ip-scanner-plan.md`](./ip-scanner-plan.md) for the full project plan.

## Status

Phase 3 (output polish). Three output formats — `human` (lipgloss-styled per-host blocks), `json` (NDJSON for pipelines), `grep` (grepable one-liner per host). Colour auto-detects on TTYs and respects `NO_COLOR`; Windows consoles get VT escapes enabled at startup. TCP-connect only; SYN scan lands in Phase 6.

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
