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
| `scry.tcp.request(host, port, payload, opts)`   | One-shot: connect, write, read up to `max_bytes`. |
| `scry.tcp.connect(host, port, opts)`            | Stateful conn: `:send(bytes)`, `:read(n)`, `:close()`. |
| `scry.udp.send(host, port, payload, opts)`      | One datagram + optional reply read (`expect_reply=false` for fire-and-forget). |
| `scry.tls.request(host, port, payload, opts)`   | Same shape as tcp.request over TLS; `opts.verify` defaults to false. |
| `scry.tls.cert(host, port, opts)`               | Leaf cert: subject, issuer, dates, dns_names. |
| `scry.dns.lookup(host)`                         | Forward A/AAAA lookup.                          |
| `scry.dns.reverse(ip)`                          | PTR lookup.                                     |
| `scry.log.info / warn / error`                  | Structured log at `source=script`.              |
| `scry.util.hex / unhex`                         | Hex encode/decode arbitrary bytes.              |

All network calls respect a per-script timeout (`--script-timeout`, default 5s).
Option tables commonly accept `timeout` (milliseconds) and `max_bytes` (int).

## NSE compatibility shim

scry also exposes a minimal `nmap.*` / `stdnse.*` surface so simple NSE
scripts can run with minimal edits. The Tier-1 surface:

| Nmap API | scry equivalent |
|---|---|
| `nmap.new_socket()` | returns a socket with `connect / send / receive_bytes / close / set_timeout` — backed by the same net.Conn path as `scry.tcp.connect`. |
| `stdnse.get_script_args(k)` | returns `nil` (scry has no `--script-args` yet). |
| `stdnse.print_debug` / `debug` | route to `scry.log.info` with `source=script.nse`. |

Anything else — `shortport.*`, `creds.*`, `brute.*`, protocol libs
(`http`, `vulns`, `smb`) — is **not** provided. Scripts that hard-depend
on them will fail cleanly with a Lua error. See `scry-plan.md` §10 #28
for the rationale.

## Shipped scripts

- `http-title.lua` — extracts `<title>` from web servers on 80/8080/8000/8888.
- `ssh-banner.lua` — reports the SSH identification string on 22/2222.
- `tls-cert-info.lua` — leaf certificate subject/issuer/not-after on 443/8443/9443.
- `redis-ping.lua` — `PING` → `+PONG` detection on 6379.
- `smb-version.lua` — SMB1 Negotiate on 139/445; reports dialect index or falls through to SMB2 detection.

Usage:

```sh
scry 10.0.0.0/24 -p 22,80,443,6379 \
    --script scripts/http-title.lua \
    --script scripts/ssh-banner.lua \
    --script scripts/tls-cert-info.lua \
    --script scripts/redis-ping.lua
```
