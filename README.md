# gscan

Fast IP/port scanner. CLI-first, single static binary, Linux + Windows.

This is the working name. See [`ip-scanner-plan.md`](./ip-scanner-plan.md) for the full project plan.

## Status

Phase 1 (MVP skeleton). Only TCP connect scanning against a single host:port works today.

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

## Usage (Phase 1)

```sh
gscan 127.0.0.1 -p 22
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
