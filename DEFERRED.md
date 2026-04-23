# Deferred Work

A running list of decisions, gaps, and known compromises taken during Phases 1–5 that still need attention. Organized by area. Update this file whenever a phase defers something; tick items off when they ship.

The `ip-scanner-plan.md` §10 decisions log is the **authoritative** short-form record. This file is the long-form task queue pointing back to code locations.

---

## Scanning / Protocols

- [ ] **ICMP echo discovery** — §10 #7. Currently TCP-only. Plan: ship under `-tags rawsock` alongside Phase 6 SYN. Needs `SOCK_DGRAM` path on Linux (via `golang.org/x/net/icmp`) and Npcap-based path on Windows, with a clear error + fallback when privileges aren't present.
  - Affects: `internal/discovery/discovery.go`, a new `icmp_*.go` file pair.
- [ ] **SYN scan** — Phase 6. gopacket + libpcap/Npcap, sender/receiver goroutines, (srcIP, srcPort, seq) state table, token-bucket pacer (`--rate`), single retransmit on filtered.
  - Affects: `internal/portscan/syn_linux.go`, `syn_windows.go`, build tag `rawsock`.
- [ ] **Adaptive rate limiter** (§5). Start conservative, ramp up under 2% error rate, back off on ICMP unreachables / connection-reset storms. Today `--concurrency` is a fixed cap.
  - Affects: `internal/ratelimit/` (new package, wired into `portscan.Scan`).
- [ ] **`ulimit -n` check on Linux** (§5). Warn or raise early when user asks for high `--concurrency` but the process has a low fd limit.

## Port Lists

- [ ] **Replace `top1000` placeholder**. `internal/portscan/top.go` currently uses `top100 ∪ (numeric-order tail)` as a stand-in. Ship an authoritative list derived from `nmap-services`. API stays the same; only `top1000` body changes.

## Lua Scripting

- [ ] **UDP in scripting API** — §10 #9. Add `gscan.udp.send(host, port, payload, opts)` when a real script needs it (likely candidates: `dns-info.lua`, `snmp-version.lua`).
  - Affects: `internal/script/api_udp.go` (new).
- [ ] **Stateful TCP connection API**. Today scripts only have the one-shot `tcp.request`. For protocols that need multiple round-trips (IMAP, SMTP LOGIN, binary handshakes), expose userdata `conn = gscan.tcp.connect(...)` with `conn:send`, `conn:read(n, opts)`, `conn:close`.
- [ ] **NSE compatibility shim (Option B, §7)**. Expose `nmap.*` module implementing the most-used NSE helpers (`nmap.new_socket`, `stdnse.get_script_args`, `shortport.port_or_service`) so simple NSE scripts run unmodified. v2 material — document a compatibility matrix.
- [ ] **Script tests**. `internal/script` coverage is 47.3%. TLS and DNS API paths are exercised end-to-end by bundled scripts but lack direct unit tests. Stand up a self-signed TLS server in tests and cover `tls.cert` / `tls.request`; mock the resolver for `dns.lookup` / `dns.reverse`.
- [ ] **More bundled scripts**. Plan §9 lists: http-title ✅, ssh-banner ✅, tls-cert-info ✅, smb-version ❌ (needs a binary-protocol probe — defer until stateful TCP API lands), redis-ping ✅.

## Output

- [ ] **Live-updating TUI table** (§4.6). Currently per-host blocks stream as they complete; a bubbletea redraw-in-place table is the stretch goal called out in the plan.
- [ ] **Service-name database**. `internal/output/service.go` is a hand-curated ~80-entry map. Consider embedding a larger `services` file (IANA-derived) keyed by port for richer annotations.

## Hardening (Phase 7)

- [ ] **Fuzz the target parser** — Phase 7 explicit ask. `internal/target` — write Go 1.18+ fuzz targets for `Parse`, exclude parsing, and range math; run as part of CI.
- [ ] **Signal handling semantics**. Ctrl-C cancels the context today (good) but does not explicitly "flush partial results" — the writer's `End()` runs because the result channel closes cleanly. Verify behaviour under mid-scan SIGINT with a large CIDR; confirm we emit everything we've collected rather than drop the in-flight partial batch.
- [ ] **Race detector in CI**. Local `make test-race` is clean; add `-race` to the `.github/workflows/ci.yml` test step.
- [ ] **`goreleaser` config + GitHub Releases workflow**. Cross-compile, checksums, tagged releases. Plan §7 / §9 Phase 7.
- [ ] **Man page + docs site**. Plan §9 Phase 7. Either mdBook or a hand-written `docs/gscan.1` via `go-md2man`.
- [ ] **`setcap cap_net_raw+ep ./gscan`** install docs. Goes with Phase 6 SYN work.

## Config / UX

- [ ] **Config file support** — §10 #6. Flags-only today. Add viper-backed `~/.config/gscan/config.yaml` (`%APPDATA%\gscan\` on Windows) only when the flag surface stabilizes and users ask.
- [ ] **`--list-scripts`** subcommand or flag. Today the only way to see what scripts ship is `ls scripts/`; surface their `description` globals in `gscan --list-scripts`.
- [ ] **Brand / final name** — §10 #1. `gscan` conflicts with an existing Homebrew formula; decide at release time whether to rename (e.g. `ripr`, `swiftscan`, `nibble`, `thump`) or namespace via a custom tap.

## Portability

- [ ] **IPv6 scanning** (§10 #5). Parser accepts v6 from day one, but default TCP-connect behaviour against v6 hasn't been exercised end-to-end. Add an integration test that listens on `[::1]:port` and confirms the scanner reaches it. Verify Windows behaviour too.
- [ ] **macOS build/test in CI**. CI matrix runs `ubuntu-latest` + `windows-latest`. macOS is reportedly fine via `GOOS=darwin` cross-compile but never gets tested. Add `macos-latest` once a contributor has a real machine to confirm.

## Build System

- [x] ~~`GO111MODULE=off` host default~~ — Makefile exports `on`, CI sets it, PowerShell script sets it. Documented.
- [ ] **`go.mod` auto-upgrade on `go get`**. `go get <pkg>@latest` repeatedly bumps the module `go` directive to the installed toolchain (1.25 locally). Today handled by manual `go mod edit -go=1.22` after each add. Consider either pinning `GOTOOLCHAIN=go1.22.x` in the Makefile, or deciding to move the module to a newer minimum version.

## Dependency Notes (for reviewers / future maintainers)

- `github.com/spf13/cobra v1.10.2` — CLI.
- `golang.org/x/sync v0.10.0` — pinned older for Go 1.22 compatibility.
- `github.com/charmbracelet/lipgloss v0.13.0` — pinned for Go 1.22 compatibility.
- `github.com/schollz/progressbar/v3 v3.17.1` — stderr bar.
- `github.com/yuin/gopher-lua v1.1.1` — Lua 5.1 VM. Note split import paths: `lua.*` for VM/compile + AST, `github.com/yuin/gopher-lua/parse` for `parse.Parse`.
- `github.com/mattn/go-isatty` — TTY detection.

---

_Last updated: 2026-04-23 (Phase 5 merge)._
