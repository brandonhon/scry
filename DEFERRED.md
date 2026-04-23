# Deferred Work

A running list of decisions, gaps, and known compromises. Organized by area. Update this file whenever a phase defers something; tick items off when they ship.

The `scry-plan.md` §10 decisions log is the **authoritative** short-form record. This file is the long-form task queue pointing back to code locations.

---

## Scanning / Protocols

- [ ] **ICMP echo discovery** — §10 #7. Currently TCP-only. Plan: ship under `-tags rawsock` alongside the SYN scanner. Needs `SOCK_DGRAM` path on Linux (via `golang.org/x/net/icmp`) and Npcap-based path on Windows, with a clear error + fallback when privileges aren't present.
  - Affects: `internal/discovery/discovery.go`, a new `icmp_*.go` file pair.
- [x] **SYN scan (Linux)** — Shipped 2026-04-23. `internal/portscan/syn_linux.go` via gopacket + libpcap under `-tags rawsock`. §10 #15/#16.
- [ ] **SYN scan (Windows)** — §10 #15. Needs Npcap + the same pipeline under `rawsock && windows`. Installer docs must mention WinPcap-compat mode. `syn_other.go` is the placeholder.
- [ ] **SYN scan (IPv6)** — §10 #15. Today `syn_linux.go` errors on any non-IPv4 target with `SYN scan supports IPv4 only in this build`. Needs `layers.IPv6` serialisation + BPF filter update (`ip or ip6`).
- [ ] **ARP / gateway MAC lookup for SYN** — §10 #16. Today the Ethernet frame uses a broadcast DST MAC (`ff:ff:ff:ff:ff:ff`). Works in some environments but fails in others. Proper fix: resolve dst MAC via ARP for on-link targets, default-gateway MAC for off-link. Affects `setupSYN` in `syn_linux.go`.
- [ ] **Loopback / WSL2 routability for SYN**. Verified during Phase 6 that SYN scans against loopback and against WSL2's virtualised adapter both fail (pcap routing / interface selection limitations), not a scanner bug. Document in README install section so users don't hit it blind. The opt-in end-to-end test behind `SCRY_RUN_SYN_TESTS=1` should be run against a real adjacent host.
- [ ] **Rate limiter for SYN** (§5). Token-bucket pacer on the sender side (`--rate`, default 10000 pps). Today SYN sends as fast as goroutines fire.
- [ ] **Adaptive rate limiter** (§5). Start conservative, ramp up under 2% error rate, back off on ICMP unreachables / connection-reset storms. Today `--concurrency` is a fixed cap.
  - Affects: `internal/ratelimit/` (new package, wired into `portscan.Scan`).
- [x] **`ulimit -n` check on Linux/macOS** (§5). `internal/cli/ulimit_unix.go` warns to stderr when `--concurrency` gets within 64 fds of the soft `RLIMIT_NOFILE`.

## Port Lists

- [ ] **Replace `top1000` placeholder**. `internal/portscan/top.go` currently uses `top100 ∪ (numeric-order tail)` as a stand-in. Ship an authoritative list derived from `nmap-services`. API stays the same; only `top1000` body changes.

## Lua Scripting

- [ ] **UDP in scripting API** — §10 #9. Add `scry.udp.send(host, port, payload, opts)` when a real script needs it (likely candidates: `dns-info.lua`, `snmp-version.lua`).
  - Affects: `internal/script/api_udp.go` (new).
- [ ] **Stateful TCP connection API**. Today scripts only have the one-shot `tcp.request`. For protocols that need multiple round-trips (IMAP, SMTP LOGIN, binary handshakes), expose userdata `conn = scry.tcp.connect(...)` with `conn:send`, `conn:read(n, opts)`, `conn:close`.
- [ ] **NSE compatibility shim (Option B, §7)**. Expose `nmap.*` module implementing the most-used NSE helpers (`nmap.new_socket`, `stdnse.get_script_args`, `shortport.port_or_service`) so simple NSE scripts run unmodified. v2 material — document a compatibility matrix.
- [ ] **Script tests**. `internal/script` coverage is 47.3%. TLS and DNS API paths are exercised end-to-end by bundled scripts but lack direct unit tests. Stand up a self-signed TLS server in tests and cover `tls.cert` / `tls.request`; mock the resolver for `dns.lookup` / `dns.reverse`.
- [ ] **More bundled scripts**. Plan §9 lists: http-title ✅, ssh-banner ✅, tls-cert-info ✅, smb-version ❌ (needs a binary-protocol probe — defer until stateful TCP API lands), redis-ping ✅.

## Output

- [ ] **Live-updating TUI table** (§4.6). Currently per-host blocks stream as they complete; a bubbletea redraw-in-place table is the stretch goal called out in the plan.
- [ ] **Service-name database**. `internal/output/service.go` is a hand-curated ~80-entry map. Consider embedding a larger `services` file (IANA-derived) keyed by port for richer annotations.

## Hardening (Phase 7)

- [x] **Fuzz the target parser**. Shipped 2026-04-23 — `internal/target/fuzz_test.go` covers `FuzzParse`, `FuzzParseExclude`, `FuzzParseRange`. CI runs each for 30s per push.
- [x] **Signal handling semantics**. §10 #11. Scanner unconditionally sends on the results channel; `cli.runScan` drains until close. Regression test in `internal/cli/cancel_test.go`.
- [x] **Race detector in CI**. `.github/workflows/ci.yml` now runs `go test -race ./...`.
- [x] **`goreleaser` config + GitHub Releases workflow**. `.goreleaser.yaml` + `.github/workflows/release.yml` — see §10 #13.
- [x] **Man page**. `cmd/gen-man` + `make man` → `docs/man/scry.1`. §10 #12.
- [ ] **Docs site**. Plan §9 Phase 7 explicitly mentions this. Options: mdBook, MkDocs, or just a `docs/` folder of hand-written Markdown served by GitHub Pages. Not blocking a v0.1.0 release.
- [x] **`setcap cap_net_raw+ep ./scry`** install docs — documented in README "SYN scanning" section alongside Phase 6.
- [x] **`goreleaser check` in CI**. `.github/workflows/ci.yml` now runs `goreleaser check` on every PR.

## Config / UX

- [ ] **Config file support** — §10 #6. Flags-only today. Add viper-backed `~/.config/scry/config.yaml` (`%APPDATA%\scry\` on Windows) only when the flag surface stabilizes and users ask.
- [x] **`--list-scripts`** flag — ships, prints name/ports/description per `--script` file and exits without scanning. See `internal/cli/list_scripts.go`.
- [x] **Brand / final name** — §10 #1. Renamed `gscan` → `scry` on 2026-04-23 to dodge the Homebrew collision.

## Portability

- [ ] **IPv6 scanning** (§10 #5). Parser accepts v6 from day one, but default TCP-connect behaviour against v6 hasn't been exercised end-to-end. Add an integration test that listens on `[::1]:port` and confirms the scanner reaches it. Verify Windows behaviour too.
- [x] **macOS build/test in CI**. `macos-latest` added to the build-test matrix; same vet/race/build pipeline as Linux and Windows.

## Build System

- [x] ~~`GO111MODULE=off` host default~~ — Makefile exports `on`, CI sets it, PowerShell script sets it. Documented.
- [ ] **`go.mod` auto-upgrade on `go get`**. `go get <pkg>@latest` repeatedly bumps the module `go` directive to the installed toolchain (1.25 locally). Today handled by manual `go mod edit -go=1.22` after each add. Consider either pinning `GOTOOLCHAIN=go1.22.x` in the Makefile, or deciding to move the module to a newer minimum version.

## Coverage Targets

- [ ] **Lift `internal/script` coverage** above 70%. Currently 47.3% — see "Script tests" above.
- [x] **Lift `internal/progress` coverage** — 68.8% → 87.5%. `isTTY` injected as a package-level var; tests now hit all three branches of `New()`.
- [x] **Lift `internal/resolver` coverage** — 70.8% → 96.0%. `defaultLookup` + underlying `lookupAddr` both exposed as package-level vars for stubbing; error-mapping paths covered.

## Dependency Notes (for reviewers / future maintainers)

- `github.com/google/gopacket v1.1.19` — SYN packet construction + pcap handle. Linked only under `-tags rawsock`; requires libpcap headers at build time.
- `github.com/spf13/cobra v1.10.2` — CLI.
- `github.com/spf13/cobra/doc` — used only by `cmd/gen-man`, not in the shipped binary.
- `golang.org/x/sync v0.10.0` — pinned older for Go 1.22 compatibility.
- `github.com/charmbracelet/lipgloss v0.13.0` — pinned for Go 1.22 compatibility.
- `github.com/schollz/progressbar/v3 v3.17.1` — stderr bar.
- `github.com/yuin/gopher-lua v1.1.1` — Lua 5.1 VM. Note split import paths: `lua.*` for VM/compile + AST, `github.com/yuin/gopher-lua/parse` for `parse.Parse`.
- `github.com/mattn/go-isatty` — TTY detection.

---

_Last updated: 2026-04-23 (deferred-easy-wins sweep)._
