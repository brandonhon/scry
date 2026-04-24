---
title: Usage
---

# Usage

## Target syntax

| Form | Example |
|---|---|
| Single IPv4 | `192.168.1.10` |
| Last-octet range | `192.168.1.10-50` |
| Arbitrary range | `192.168.1.10-192.168.2.20` |
| CIDR | `192.168.1.0/24` |
| Hostname | `example.com` |
| Target file | `@hosts.txt` (one entry per line, `#` for comments) |
| Mixed list | `10.0.0.1,10.0.0.5-7,192.168.1.0/30` |
| Exclusions | `--exclude 192.168.1.1,192.168.1.255` |

IPv6 is **not** accepted on main; see the [plan]({{ site.github.repository_url }}/blob/main/scry-plan.md) §10 #22.

## Port syntax (`-p`)

| Form | Meaning |
|---|---|
| `22` | Single port |
| `22,80,443` | List |
| `1-1024` | Range |
| `-` | All 65,535 |
| `top100`, `top1000` | Bundled shortlists |

## Common recipes

```sh
# Scan a /24 for common services
scry 192.168.1.0/24 -p top100 --up

# Full-port scan of one host, bigger timeout for WAN
scry example.com -p- --timeout 2s --retries 1

# Banner grab + human output, no DNS lookups
scry 10.0.0.1-10 -p 21,22,25,80,443,6379 --banner --no-dns

# Host discovery only (no port scan)
scry 10.0.0.0/24 --sn

# Pipelines: NDJSON + jq
scry 10.0.0.0/24 -p top100 -o json | jq 'select(.up) | .addr'

# Run bundled scripts
scry 10.0.0.0/24 -p 22,80,443,6379,445 \
  --script scripts/ssh-banner.lua \
  --script scripts/http-title.lua \
  --script scripts/tls-cert-info.lua \
  --script scripts/redis-ping.lua \
  --script scripts/smb-version.lua
```

## Speed vs. accuracy

Defaults are tuned for LAN:

| Flag | Default | When to raise |
|---|---|---|
| `--timeout` | 500ms | WAN, VPN, lossy links |
| `--retries` | 0 | Same |
| `--concurrency` | 2000 | *Lower* when hitting `RLIMIT_NOFILE` |
| `--max-hosts` | 100 | Rarely |

Presets:

| Scenario | Suggested |
|---|---|
| Fast LAN | (defaults) |
| VPN / coffee-shop WiFi | `--timeout 1s --retries 1` |
| Public internet | `--timeout 2s --retries 2` |
| Tight fd budget | `--concurrency 500 --max-hosts 20` |

On Linux and macOS scry warns to stderr if `--concurrency` is close to
the soft `RLIMIT_NOFILE`.

## Progress

scry shows a live progress bar on stderr when stderr is a TTY. The bar
ticks once per probe completed (not per host), so long single-host scans
like `scry example.com -p-` update smoothly throughout. Pass
`--no-progress` to suppress.

## All flags

Run `scry --help` for the full list, or check the [`scry.1`]({{ site.github.repository_url }}/blob/main/docs/man/scry.1) man page.
