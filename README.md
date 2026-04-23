# gscan

Fast IP/port scanner. CLI-first, single static binary, Linux + Windows.

This is the working name. See [`ip-scanner-plan.md`](./ip-scanner-plan.md) for the full project plan.

## Status

Phase 2 (core scanner). Bounded concurrency, full `-p` syntax, `--up`/`--down` filtering, retries, per-host latency. TCP-connect only; SYN scan lands in Phase 6.

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
gscan example.com -p-          # all 65535 ports
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
