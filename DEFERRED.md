# Deferred Work

A running list of decisions, gaps, and known compromises. Organized by area. Update this file whenever a phase defers something; tick items off when they ship.

The `scry-plan.md` §10 decisions log is the **authoritative** short-form record. This file is the long-form task queue pointing back to code locations.

---

## Scanning / Protocols

- [x] **ICMP echo discovery** — Shipped 2026-04-23. `internal/discovery/icmp_rawsock_linux.go` races an unprivileged ICMP Echo alongside the TCP ping probes; first responder wins. Default build keeps TCP-only via `icmp_other.go`. §10 #18.
- [x] **SYN scan (Linux)** — Shipped 2026-04-23. `internal/portscan/syn_linux.go` via gopacket + libpcap under `-tags rawsock`. §10 #15/#16.
- [ ] **SYN scan (Windows)** — §10 #15. Needs Npcap plus the same pipeline under `rawsock && windows`. `syn_other.go` now carries a detailed contract note naming `scanState` as the reference implementation and listing the Windows-specific pieces (NPF device names via `pcap.FindAllDevs`, ARP via `GetIpNetTable2`/`SendARP`, Npcap WinPcap-compat mode in install docs). Not shipped because there's no Windows host in this workflow for end-to-end verification.
- [ ] **SYN scan (IPv6)** — Moved to `feat/ipv6-support` branch on 2026-04-23 (§10 #22). Was scaffolded on `main` (syn_v6_linux.go with Ethernet+IPv6+TCP frame and multicast MAC placeholder); lives on the preservation branch now.
- [x] **ARP / gateway MAC lookup for SYN** — Shipped 2026-04-23. `internal/portscan/syn_arp_linux.go` reads `/proc/net/arp` for on-link targets and `/proc/net/route` for default-gateway lookup. Falls back to broadcast with a one-time stderr warning on failure. Cached per scan-run in `scanState.macByDst`.
- [x] **Loopback / WSL2 routability for SYN** — Documented 2026-04-23 in README's new "Known pcap limitations" subsection and in the `--syn` flag help text.
- [x] **Rate limiter for SYN** (§5) — Shipped 2026-04-23. `internal/ratelimit` token-bucket via `golang.org/x/time/rate`; CLI `--rate` defaults to 10000 pps, 0 = unlimited.
- [x] **Adaptive rate limiter** (§5) — Shipped 2026-04-23. `internal/ratelimit/adaptive.go`: halves rate when error-rate exceeds 2%, doubles below 0.1%, 500-probe sliding window, floors at 50 pps. Opt-in via `--adaptive` for v0.1; default-on tracked as follow-up.
- [x] **`ulimit -n` check on Linux/macOS** (§5). `internal/cli/ulimit_unix.go` warns to stderr when `--concurrency` gets within 64 fds of the soft `RLIMIT_NOFILE`.

## Port Lists

- [x] **Replace `top1000` placeholder** — Shipped 2026-04-23. `cmd/gen-top-ports` regenerates `internal/portscan/top.go` from the IANA registry snapshot; the 900-entry tail is now IANA-assigned TCP ports in numeric order. §10 #23. nmap-services was evaluated and rejected on license grounds; see `data/README.md`.
- [ ] **Frequency-sorted top1000** — still a nice-to-have. Today's tail is numeric-order which beats the previous placeholder but is not frequency-ranked past top100. Options: run our own survey against a sample corpus, or license-audit nmap-services again in a future release.

## Lua Scripting

- [x] **UDP in scripting API** — Shipped 2026-04-24. `internal/script/api_udp.go`; `scry.udp.send(host, port, payload, opts)` with optional reply. §10 #24.
- [x] **Stateful TCP connection API** — Shipped 2026-04-24. `scry.tcp.connect(...)` returns a userdata with `:send`, `:read(n)`, `:close`. §10 #24.
- [ ] **NSE compatibility shim (Option B, §7)**. Expose `nmap.*` module implementing the most-used NSE helpers (`nmap.new_socket`, `stdnse.get_script_args`, `shortport.port_or_service`) so simple NSE scripts run unmodified. v2 material — document a compatibility matrix.
- [x] **Script tests** — 47.3% → **83.8%** (2026-04-24). Added TLS cert + TLS request + TLS error tests against an in-process self-signed server; dns.lookup/reverse smoke tests; log.* callbacks; util.unhex happy + error; Load() error paths.
- [x] **More bundled scripts**. Plan §9 list complete: http-title ✅, ssh-banner ✅, tls-cert-info ✅, smb-version ✅ (uses the new stateful tcp.connect), redis-ping ✅.

## Output

- [ ] **Live-updating TUI table** (§4.6). Currently per-host blocks stream as they complete; a bubbletea redraw-in-place table is the stretch goal called out in the plan. Deferred to post-v0.1 by explicit user direction during the ports-and-services sweep.
- [x] **Service-name database** — Shipped 2026-04-23. `cmd/gen-services` regenerates `internal/output/service.go` from IANA (~6000 TCP assignments, ~150 KB binary delta). §10 #23. Names are IANA-canonical (e.g. 3389 → `ms-wbt-server`); a nickname overlay is a follow-up if users ask.

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

- [x] **macOS build/test in CI**. `macos-latest` added to the build-test matrix; same vet/race/build pipeline as Linux and Windows.

## IPv6 (preservation branch)

All IPv6 support lives on the **`feat/ipv6-support`** branch (tip at the scanning-protocols merge, 2026-04-23). `main` is IPv4-only per §10 #22. When bringing v6 back, rebase that branch onto current main and tackle these items together — they were designed as a bundle:

- [ ] **Parser acceptance**: restore v6 literals, v6 CIDR, v6 ranges in `internal/target/parse.go` (revert `requireIPv4`).
- [ ] **Parser helpers**: restore the v6 branches in `internal/target/addr.go` (`lastInPrefix`, `addrDiff` using `math/big`).
- [ ] **SYN frame construction**: re-add `internal/portscan/syn_v6_linux.go` and the v4/v6 dispatch in `sendSYN`; extend BPF to `tcp or ip6 proto 6`; dual-family parse in `parseAndDispatch`.
- [ ] **Interface selection**: restore v6 fallback in `pickInterface`.
- [ ] **Neighbour Discovery**: v6 equivalent of `resolveDstMAC` (ND, not ARP). Today's placeholder uses the all-nodes multicast MAC — good enough for some LAN tests, wrong in most real networks.
- [ ] **Hostname resolution**: restore v6 address acceptance in `parseToken`.
- [ ] **`--exclude`**: restore v6 acceptance in `parseExclude`.
- [ ] **End-to-end verification**: this is the part that kept blocking us — need an IPv6-reachable test host (not WSL2) to sanity-check the full pipeline. The opt-in `SCRY_RUN_SYN_TESTS=1` test should grow a v6 variant.

## Build System

- [x] ~~`GO111MODULE=off` host default~~ — Makefile exports `on`, CI sets it, PowerShell script sets it. Documented.
- [ ] **`go.mod` auto-upgrade on `go get`**. `go get <pkg>@latest` repeatedly bumps the module `go` directive to the installed toolchain (1.25 locally). Today handled by manual `go mod edit -go=1.22` after each add. Consider either pinning `GOTOOLCHAIN=go1.22.x` in the Makefile, or deciding to move the module to a newer minimum version.

## Coverage Targets

- [x] **Lift `internal/script` coverage** — 47.3% → 83.8% (2026-04-24). See "Script tests" above.
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

_Last updated: 2026-04-24 (scripting-polish sweep)._
