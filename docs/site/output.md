---
title: Output formats
---

# Output formats

Pick with `-o` / `--output`. Default is `human`.

## `human` (default)

Colour-coded per-host block with service annotations. Service names come
from the IANA registry (~6000 TCP assignments embedded at build time).

```
UP    192.168.1.10  (router.local)  12ms
     22/tcp  open      ssh                180µs
     80/tcp  open      http               212µs

scanned 1 host(s), 1 up in 12ms
```

Colour is auto-detected from `isatty(stdout)`; disable with `--no-color`
or the `NO_COLOR` env var. On Windows, VT escape processing is enabled
at startup.

## `json`

One NDJSON record per host. Stable schema (additions only, no renames):

```json
{
  "addr": "192.168.1.10",
  "hostname": "router.local",
  "up": true,
  "started": "2026-04-24T18:30:00Z",
  "elapsed": "12ms",
  "results": [
    {"port": 22, "proto": "tcp", "state": "open", "service": "ssh", "rtt": "180µs"}
  ]
}
```

Fields per port result: `port`, `proto`, `state`, `service`, `rtt`,
optional `banner`, optional `err`, optional `findings[]` (script output).

## `grep`

One host per line, tab-delimited fields, comma-joined port list. Suitable
for `grep -F 'Status: up'`.

```
Host: 192.168.1.10 (router.local)	Status: up	Ports: 22/open/ssh,80/open/http	Elapsed: 12ms
```

Script findings appear as `[script=output]` suffixes on the port entry.

## `--live` (opt-in)

In-place updating table for interactive use; falls back to the streaming
`human` writer when stdout isn't a TTY. See the
[Live mode section of the Usage page](./usage.html).
