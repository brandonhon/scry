---
title: scry
---

# scry

Fast, MIT-licensed IP/port scanner written in Go. Single static binary for
Linux, Windows, and macOS. TCP connect by default — no privileges, no CGO,
no libpcap. Optional SYN mode on Linux for speed on trusted hardware.

## What it does

- Scans IP addresses, ranges, CIDRs, hostnames, and `@file` target lists.
- Three output formats: `human` (coloured per-host blocks), `json` (NDJSON
  for pipelines), and `grep` (one line per host).
- Runs Lua 5.1 scripts against open ports with a curated `scry.*` API —
  TCP stateless or stateful, UDP, TLS + cert introspection, DNS, hex.
- Bundled scripts: `http-title`, `ssh-banner`, `tls-cert-info`, `redis-ping`,
  `smb-version`.
- Reverse DNS in parallel, optional banner grab, live progress on stderr.

## Pages

- [Install](./install.html)
- [Usage & examples](./usage.html)
- [Output formats](./output.html)
- [Scripting](./scripting.html)
- [SYN scanning](./syn.html)
- [Config file](./config.html)
- [Deferred / roadmap]({{ site.github.repository_url }}/blob/main/DEFERRED.md)
- [Full plan & decision log]({{ site.github.repository_url }}/blob/main/scry-plan.md)

## Quick start

```sh
scry 192.168.1.0/24 -p top100 --up
scry 10.0.0.1-50 -p 22,80,443 --banner
scry 10.0.0.0/24 -p top100 -o json | jq '.results[] | select(.state=="open")'
```

## License

MIT. See [`LICENSE`]({{ site.github.repository_url }}/blob/main/LICENSE).
