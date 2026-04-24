---
title: Scripting
---

# Scripting

scry embeds a Lua 5.1 runtime (gopher-lua). Scripts declare metadata and
a `run(host, port)` function that's called on every matching open port.
A fresh Lua state is created per invocation, so scripts cannot leak
state between calls.

## Shape

```lua
description = "one-line summary"
ports       = {80, 443}   -- or the string "any"
function run(host, port)
  -- return "finding" on success, (nil, "reason") on error, nothing for no-op
end
```

## `scry.*` API

| Function | Purpose |
|---|---|
| `scry.tcp.request(host, port, payload, opts)` | One-shot: connect, write, read up to `max_bytes`. |
| `scry.tcp.connect(host, port, opts)` | Stateful conn userdata: `:send`, `:read(n)`, `:close`. |
| `scry.udp.send(host, port, payload, opts)` | One datagram + optional reply (`expect_reply=false` for fire-and-forget). |
| `scry.tls.request(host, port, payload, opts)` | Same as tcp.request over TLS; `opts.verify` defaults to false. |
| `scry.tls.cert(host, port, opts)` | Leaf cert: `{subject, issuer, not_before, not_after, dns_names}`. |
| `scry.dns.lookup(host)` | Forward A/AAAA lookup → table of strings. |
| `scry.dns.reverse(ip)` | PTR lookup. |
| `scry.log.info` / `.warn` / `.error` | Structured log at `source=script`. |
| `scry.util.hex(bytes)` / `.unhex(hex)` | Hex encode/decode arbitrary bytes. |

Option tables commonly accept `timeout` (milliseconds) and `max_bytes`
(int). All network calls respect a per-script wall-clock timeout from
`--script-timeout` (default 5s).

## Error conventions

- Success: one return value (the finding string) or no returns (no-op).
- Error: `return nil, "reason"`.
- Read timeout on `:read` / `udp.send`: the function returns
  `("", "timeout")`. This is distinct from a hard error so scripts can
  treat "no reply yet" as informative rather than fatal.

## Binary payloads & Lua 5.1

gopher-lua is Lua 5.1, which lacks the `\xNN` string escape added in
5.2. Build binary payloads via `scry.util.unhex("…")` or decimal escapes
(`\255`). `scripts/smb-version.lua` is the reference example.

## Bundled scripts

| File | Ports | What it reports |
|---|---|---|
| `scripts/http-title.lua` | 80, 8080, 8000, 8888 | HTML `<title>` |
| `scripts/ssh-banner.lua` | 22, 2222 | SSH identification string |
| `scripts/tls-cert-info.lua` | 443, 8443, 9443 | Cert subject, issuer, expiry, SANs |
| `scripts/redis-ping.lua` | 6379 | `+PONG` / auth-required marker |
| `scripts/smb-version.lua` | 139, 445 | SMB1 dialect index or SMB2 fallthrough |

## Running scripts

```sh
scry 10.0.0.0/24 -p 22,80,443,6379,445 \
  --script scripts/ssh-banner.lua \
  --script scripts/tls-cert-info.lua \
  --script scripts/redis-ping.lua \
  --script scripts/smb-version.lua
```

Use `--list-scripts` to print metadata (name, ports, description)
without running a scan:

```sh
scry --list-scripts --script scripts/*.lua
```

## Writing a new script

Target: under 20 lines. Example — detect a bare Memcached server:

```lua
description = "memcached stats"
ports = {11211}
function run(host, port)
  local body, err = scry.tcp.request(host, port, "stats\r\n", {timeout=1000, max_bytes=4096})
  if err then return nil, err end
  local version = body:match("STAT version (%S+)")
  if version then return "memcached " .. version end
end
```
