# scry example scripts

Each script is a small Lua 5.1 program (via gopher-lua) that runs against an
open port during a scan. Load them with `--script scripts/<name>.lua`
(repeatable). See `scry-plan.md` §7 for the design rationale.

## Shape

```lua
description = "one-line summary"
ports       = {80, 443}   -- table of TCP ports, or the string "any"
function run(host, port)
  -- return "finding" on success, or nil, "reason" on error, or nothing for no-op
end
```

A fresh Lua state is created for every invocation, so scripts cannot leak
state between calls.

## API surface (`scry.*`)

| Function                                         | Purpose                                         |
|--------------------------------------------------|-------------------------------------------------|
| `scry.tcp.request(host, port, payload, opts)`   | Connect, write payload, read up to `max_bytes`. |
| `scry.tls.request(host, port, payload, opts)`   | Same over TLS; `opts.verify` defaults to false. |
| `scry.tls.cert(host, port, opts)`               | Return leaf cert: subject, issuer, dates, sans. |
| `scry.dns.lookup(host)`                         | Forward A/AAAA lookup.                          |
| `scry.dns.reverse(ip)`                          | PTR lookup.                                     |
| `scry.log.info / warn / error`                  | Structured log at `source=script`.              |
| `scry.util.hex / unhex`                         | Hex encode/decode arbitrary bytes.              |

All network calls respect a per-script timeout (`--script-timeout`, default 5s).
Option tables commonly accept `timeout` (milliseconds) and `max_bytes` (int).

## Shipped scripts

- `http-title.lua` — extracts `<title>` from web servers on 80/8080/8000/8888.
- `ssh-banner.lua` — reports the SSH identification string on 22/2222.
- `tls-cert-info.lua` — leaf certificate subject/issuer/not-after on 443/8443/9443.
- `redis-ping.lua` — `PING` → `+PONG` detection on 6379.

Usage:

```sh
scry 10.0.0.0/24 -p 22,80,443,6379 \
    --script scripts/http-title.lua \
    --script scripts/ssh-banner.lua \
    --script scripts/tls-cert-info.lua \
    --script scripts/redis-ping.lua
```
