# scry data snapshots

Frozen source files used by the code generators under `cmd/gen-*`. Checked
in so `make regen-data` is offline-reproducible across contributors and CI.

## Files

| File | Source | License |
|---|---|---|
| `iana-service-names-port-numbers.csv` | [IANA Service Names and Transport Protocol Port Number Registry](https://www.iana.org/assignments/service-names-port-numbers/service-names-port-numbers.xhtml) | Public domain (factual registry; IANA assignments are not copyrightable) |

## Regeneration

```sh
curl -sL https://www.iana.org/assignments/service-names-port-numbers/service-names-port-numbers.csv \
    -o data/iana-service-names-port-numbers.csv
make regen-data
```

## Why IANA and not nmap-services

`nmap-services` has richer data — frequency-sorted rankings derived from real
scans — but it ships under the Nmap Public Source License, which is
copyleft-style and incompatible with scry's MIT license. We use IANA's
public-domain registry for service names and fall back to `top100` (hand
curated in `internal/portscan/top.go`) plus numeric order of IANA-assigned
TCP ports for `top1000`. See `scry-plan.md` §10 #23 for the rationale.
