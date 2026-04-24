---
title: Config file
---

# Config file

scry reads a YAML config file on startup. Values apply to flags the
user didn't set on the command line — precedence is:

```
CLI flag  >  SCRY_* env var  >  config file  >  flag default
```

## Path

Default location (in order):

1. `--config FILE` — explicit path.
2. `$SCRY_CONFIG` — env override.
3. `$XDG_CONFIG_HOME/scry/config.yaml` (Unix) — typically
   `~/.config/scry/config.yaml`.
4. `%APPDATA%\scry\config.yaml` (Windows).

Explicit paths (flag or env) must exist; implicit defaults silently skip
when missing.

## Keys

One-to-one with flag names. Supported:

```yaml
# Ports & targets
ports: top100
exclude:
  - 10.0.0.1
  - 10.0.0.2/32

# Timing & concurrency
timeout: 500ms
retries: 0
concurrency: 2000
max-hosts: 100

# Filtering
up: true
# down: true        # (mutually exclusive with up)

# Output
output: human
no-color: false
no-progress: false

# Discovery / DNS / banners
ping-only: false
no-dns: false
banner: true

# Scripting
script:
  - scripts/ssh-banner.lua
  - scripts/tls-cert-info.lua
script-timeout: 5s

# SYN (rawsock builds only)
syn: false
rate: 10000
adaptive: false

# Live TUI
live: false
```

## Example

```yaml
# ~/.config/scry/config.yaml
timeout: 1s
retries: 1
banner: true
output: grep
script:
  - scripts/ssh-banner.lua
  - scripts/tls-cert-info.lua
```

After this, a plain `scry 10.0.0.0/24 -p top100` behaves as if you'd
passed `--timeout 1s --retries 1 --banner -o grep --script ...`.

## Env vars

Any flag key can be overridden with `SCRY_<FLAG>`:

```sh
SCRY_TIMEOUT=2s SCRY_RETRIES=2 scry 10.0.0.0/24 -p 22
```

Env takes precedence over config file but loses to explicit flags.
