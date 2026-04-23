# Fast IP/Port Scanner — Project Plan

A CLI-first network scanner written in Go, targeting Linux and Windows. Goal: rival nmap and Angry IP Scanner on speed and ergonomics, with clean output and a scripting hook.

Working name placeholder: `gscan` (replace as desired).

---

## 1. Goals & non-goals

**Goals**
- Very fast host discovery and port scanning on commodity hardware.
- Single static binary per OS. No runtime dependencies for the default (unprivileged) mode.
- Clear, skimmable terminal output — color, tables, progress.
- Predictable flags; works well in pipelines (JSON/NDJSON output).
- Cross-platform: Linux (primary), Windows 10+ (secondary).

**Non-goals (at least for v1)**
- 100% NSE script compatibility with nmap. We will support a Lua-based scripting model that is NSE-*like* but not a drop-in replacement. See §7.
- GUI. CLI only.
- Active exploitation features.

---

## 2. Tech stack

| Concern | Choice | Why |
|---|---|---|
| Language | Go 1.22+ | Cross-compile, goroutines, static binaries, you know it |
| CLI framework | `github.com/spf13/cobra` + `viper` | Standard, subcommand support, config files |
| Styled output | `github.com/charmbracelet/lipgloss` | Tables, colors, boxes; handles Windows VT |
| Progress / live UI | `github.com/schollz/progressbar/v3` (simple) or `charmbracelet/bubbletea` (full TUI) | Start with progressbar; bubbletea is optional stretch |
| Raw packets (SYN scan, ICMP) | `github.com/google/gopacket` + `pcap` | The de facto choice in Go; requires libpcap/Npcap |
| Lua engine (scripting) | `github.com/yuin/gopher-lua` | Pure Go Lua 5.1; no CGO |
| Concurrency control | `golang.org/x/sync/semaphore` or channel-based pool | Bound in-flight work |
| Structured logging | `log/slog` (stdlib) | No extra dep |
| Testing | stdlib `testing` + `testify` optional | — |

**CGO decision:** avoid CGO in the default build. Gate `gopacket`/`pcap`-dependent features behind a build tag (e.g. `-tags rawsock`) so the unprivileged TCP-connect binary stays dependency-free.

---

## 3. Repository layout

```
gscan/
├── cmd/
│   └── gscan/
│       └── main.go              # cobra root + version
├── internal/
│   ├── cli/                     # cobra commands, flag wiring
│   ├── target/                  # parse IPs, ranges, CIDR; iterator
│   ├── discovery/               # host-up checks (ICMP, TCP ping)
│   ├── portscan/
│   │   ├── connect.go           # TCP connect scanner (default)
│   │   └── syn_linux.go         # SYN scanner, build-tagged
│   │   └── syn_windows.go       # SYN scanner via Npcap, build-tagged
│   ├── resolver/                # forward + reverse DNS, with cache
│   ├── banner/                  # lightweight banner grab on open ports
│   ├── script/                  # Lua engine + API surface
│   ├── output/
│   │   ├── human.go             # lipgloss table / live view
│   │   ├── json.go              # stream NDJSON
│   │   └── grep.go              # grepable one-line-per-host
│   ├── ratelimit/               # adaptive limiter
│   └── workerpool/              # bounded concurrency helper
├── scripts/                     # bundled Lua scripts (examples)
├── docs/
├── Makefile
├── go.mod
└── README.md
```

---

## 4. Feature breakdown

### 4.1 Target parsing (feature 1, 2, 3)
One unified iterator: input string(s) → channel of `net.IP`.

Accept, in any combination, comma-separated:
- `192.168.1.10` — single IP
- `192.168.1.10-50` — last-octet range
- `192.168.1.10-192.168.2.20` — arbitrary range
- `192.168.1.0/24` — CIDR
- `scan.example.com` — resolved to one or more IPs
- `@targets.txt` — one target per line
- Exclusions via `--exclude 192.168.1.1,192.168.1.255`

Implementation: `target.Parse(input string) (Iterator, error)` that yields IPs lazily so `/8` doesn't blow memory.

### 4.2 Hostname resolution (feature 4)
- Forward lookup up front if input is a name.
- Reverse PTR lookup after a host is found up, running in parallel with port scan.
- Per-run cache (map keyed by IP).
- Flag: `--no-dns` to skip entirely.

### 4.3 Port scanning (features 5, 6)
Flag: `-p`
- `-p 22` — single
- `-p 22,80,443` — list
- `-p 1-1024` — range
- `-p-` — all (1-65535)
- `-p top100` / `top1000` — bundled shortlists (mirror nmap's top-ports)

Two backends:
1. **TCP connect** (default, unprivileged, cross-platform).
   - `net.Dialer` with per-connection timeout.
   - Worker pool sized by `--concurrency` (default maybe 500, auto-tune down on errors).
   - State classification: open / closed (RST) / filtered (timeout) / error.
2. **SYN scan** (`--syn`, build tag `rawsock`).
   - `gopacket` to craft SYN, read responses via pcap handle.
   - One sender goroutine + one receiver goroutine; match on (srcIP, srcPort, seq).
   - Linux: needs `CAP_NET_RAW` or root. Windows: needs Npcap installed.
   - If `--syn` requested without privileges → clear error message with remediation.

### 4.4 Host up/down filtering (feature 7)
- `--up` — show only responsive hosts.
- `--down` — show only non-responsive hosts.
- Default: host is "up" if ICMP echo succeeds OR any probed TCP port returns SYN/ACK or RST.
- `--ping-only` / `-sn` — host discovery without port scan.

### 4.5 Scripting (feature 8) — see §7 for depth

### 4.6 Output (feature 9)
- Default: live-updating table grouped by host. Columns: IP, Hostname, Status, Open ports (with service guess), Latency.
- Use lipgloss for borders, status colors (green=open, red=closed, yellow=filtered).
- `-o json` / `--json` → NDJSON, one host per line, for piping.
- `-o grep` → grepable single-line-per-host à la `nmap -oG`.
- `-v` / `-vv` shows closed/filtered ports; default hides them.
- `--no-color` and auto-detect when not a TTY.
- Progress bar shows "hosts scanned / total, ports scanned / total, ETA".

---

## 5. Concurrency & performance model

The speed story is mostly about two things: bounded parallelism and avoiding syscall/allocation overhead per probe.

**TCP connect mode**
- Top-level pipeline: target iterator → host workers → port workers → result collector.
- Two semaphore layers: one on hosts-in-flight (default 50), one on total sockets-in-flight (default 1000; tune via `--max-sockets`).
- Per-dial timeout starts at 1.5s, adaptive: if >X% of attempts time out, back off concurrency; if RTTs are cheap, increase.
- Reuse a single `net.Dialer` with `KeepAlive: -1`.
- On Linux, raise `ulimit -n` early or warn.

**SYN mode**
- Single pcap handle. Sender paces packets via token bucket (`--rate 10000` pps default cap).
- Stateless send, stateful receive: track outstanding (ip, port, seq) → channel back to the collector on match.
- Retransmit once after timeout before classifying filtered.

**Adaptive rate limiter**
- Start conservative, ramp up while error rate < 2%, back off fast on ICMP unreachables or conn reset storms.

**Benchmarks to track early**
- /24 full-port scan wall time.
- /16 top-100 scan wall time.
- Memory peak during /16 scan (watch for iterator/goroutine leaks).

---

## 6. Cross-platform notes

| Concern | Linux | Windows |
|---|---|---|
| TCP connect scan | works out of the box | works out of the box |
| SYN scan | needs `CAP_NET_RAW` or root; `setcap cap_net_raw+ep ./gscan` in install docs | requires Npcap installed in WinPcap-compat mode; document in README |
| ICMP ping | unprivileged ICMP on modern kernels (`/proc/sys/net/ipv4/ping_group_range`) else raw | raw ICMP via Npcap under `--syn`-style path, or fall back to TCP ping |
| ANSI color | native | enable VT processing via `golang.org/x/sys/windows/console` at startup; lipgloss handles most of it |
| File paths | — | use `filepath` everywhere (never `path` for FS) |
| Defaults | `~/.config/gscan/` | `%APPDATA%\gscan\` |

Cross-compile from one host: `GOOS=windows GOARCH=amd64 go build ./cmd/gscan`. Ship both via GitHub Releases with checksums.

---

## 7. Scripting engine — the honest version

**The problem.** Nmap's NSE is Lua 5.3 plus a large set of nmap-specific libraries (`nmap`, `stdnse`, `shortport`, `http`, `creds`, ~600 bundled scripts). Those libraries directly call into nmap internals — the scan engine, service detection DB, output system. Running `.nse` files unmodified would require us to reimplement that entire API surface. That is a project unto itself and is out of scope for v1.

**Three realistic options.** Pick one as the v1 target.

**Option A — Custom Lua API (recommended for v1).**
Ship our own Lua 5.1 runtime via `gopher-lua` with a documented API:
```lua
-- scripts/http-title.lua
description = "Grab HTTP title from open 80/443"
ports = {80, 443, 8080, 8443}
function run(host, port)
  local body, err = gscan.tcp.request(host, port, "GET / HTTP/1.0\r\n\r\n", {timeout=3000})
  if err then return nil end
  local title = body:match("<title>(.-)</title>")
  if title then return "title: " .. title end
end
```
Document the `gscan.*` API surface: `tcp.connect`, `tcp.request`, `udp.send`, `dns.lookup`, `log.info`, `util.hex`, etc. This is achievable in a phase or two of work.

**Option B — NSE compatibility shim (stretch / v2).**
Same engine as A, but also expose an `nmap.*` module that implements the most-used NSE helpers (`nmap.new_socket`, `stdnse.get_script_args`, `shortport.port_or_service`). Many simple NSE scripts would then run unmodified. Complex ones (anything using `brute`, `creds`, or binary protocol libs) won't. Be upfront in docs about the compatibility matrix.

**Option C — Shell out to nmap for scripts.**
If nmap is installed, pass `--script` through to it. This is fast to build and guarantees compat, but it means requiring nmap as a runtime dep and gives up on the "rival nmap" framing.

**Plan:** build A for v1. Revisit B in v2 once the API is stable. Don't pursue C.

---

## 8. CLI design

```
gscan [TARGETS...] [flags]

Examples:
  gscan 192.168.1.0/24
  gscan 10.0.0.1-50 -p 22,80,443
  gscan example.com -p- --syn
  gscan @hosts.txt -p top1000 --up --json > results.ndjson
  gscan 10.0.0.0/16 -p 22 --script scripts/ssh-banner.lua

Flags:
  -p, --ports           Ports: "22", "22,80", "1-1024", "-", "top100"
      --syn             SYN scan (requires privileges / Npcap)
  -sn, --ping-only      Host discovery only
      --up              Only show hosts that are up
      --down            Only show hosts that are down
      --script FILE     Run Lua script against matching hosts/ports (repeatable)
      --concurrency N   Max parallel probes (default 500)
      --rate N          Max packets/sec in SYN mode (default 10000)
      --timeout DUR     Per-probe timeout (default 1.5s)
      --retries N       Retries per probe (default 1)
      --no-dns          Skip reverse DNS
      --exclude LIST    Comma-separated IPs/CIDRs to skip
  -o, --output FORMAT   human|json|grep (default human)
      --no-color
  -v, -vv               Verbosity
      --version
```

---

## 9. Build phases

**Phase 1 — MVP skeleton (1-2 days of focused work)**
- Repo scaffolding, cobra root command, CI (GitHub Actions: build + test on linux/windows).
- `internal/target` with full parser + iterator + tests.
- TCP connect scanner against a single host, single port.
- Plain text output.
- *Exit criteria:* `gscan 127.0.0.1 -p 22` works on Linux and Windows.

**Phase 2 — Core scanner**
- Worker pool, bounded concurrency.
- Full port syntax (`-p`, ranges, top-N lists).
- CIDR + range iteration with proper memory behavior.
- Timeouts, retries, per-host latency tracking.
- `--up` / `--down` filtering.
- *Exit criteria:* `gscan 192.168.1.0/24 -p top100` completes in single-digit seconds on LAN.

**Phase 3 — Output polish**
- lipgloss table renderer with live update.
- Progress bar.
- JSON and grep output formats.
- Color / no-color handling. Windows VT enablement.
- *Exit criteria:* Output looks good enough to screenshot for the README.

**Phase 4 — Discovery & DNS**
- ICMP echo (unprivileged where possible) + TCP ping fallback.
- Reverse DNS with cache, running concurrently with port scan.
- Optional light banner grab on open ports.
- *Exit criteria:* Host-up detection matches nmap `-sn` within a reasonable margin on a test network.

**Phase 5 — Scripting engine**
- Embed gopher-lua, define `gscan.*` API.
- Script loading, `ports` / `description` metadata, `run(host, port)` entry point.
- Ship 3-5 example scripts: http-title, ssh-banner, tls-cert-info, smb-version, redis-ping.
- *Exit criteria:* Writing a new useful script takes <20 lines of Lua.

**Phase 6 — SYN scanning (optional, build-tag gated)**
- gopacket + pcap integration, Linux first.
- Rate limiter, retransmission, state table.
- Npcap path for Windows.
- *Exit criteria:* SYN scan of a /24 full-port on LAN finishes in <10s.

**Phase 7 — Hardening**
- Fuzz the target parser.
- Race detector clean.
- Proper signal handling (Ctrl-C flushes partial results).
- Docs site, man page, release workflow (goreleaser).

---

## 10. Decisions

Decisions made during implementation. Update this list as decisions are revisited.

1. **Final name:** `gscan` — kept as the working name. Homebrew collision to be resolved at release time (rename or namespace decision deferred until we actually ship a tap). _Decided 2026-04-23, Phase 1._
2. **SYN scan scope:** v2. v1 ships with TCP connect only. Raw-socket path will be build-tag gated (`-tags rawsock`) when added, so the default binary stays CGO-free and dependency-free. _Decided 2026-04-23, Phase 1._
3. **Scripting engine:** Option A — custom Lua API via `gopher-lua`. No NSE compatibility shim in v1. _Decided 2026-04-23, Phase 1._
4. **License:** MIT. Permissive, dominant in the Go ecosystem, no copyleft concerns for users embedding or forking. _Decided 2026-04-23, Phase 1._
5. **IPv6:** Parser accepts IPv6 literals and CIDR from day one (v4 + v6 treated as first-class in `internal/target`). Full v6 scanning (discovery + probing) deferred until Phase 4; parser won't have to change when we turn it on. _Decided 2026-04-23, Phase 1._
6. **Config file:** Flags-only for v1. No viper yet. Revisit once the flag surface stabilizes and users ask for it. _Decided 2026-04-23, Phase 1._
7. **ICMP echo in Phase 4:** Deferred to Phase 6. Host-up detection in Phase 4 uses TCP probes only — either the normal port scan, or (in `-sn`/`--ping-only` mode) a short list of common TCP ports (22/80/443/445/3389) where any response (open/closed/RST) counts as up. ICMP will ship alongside SYN scanning under the `rawsock` build tag so the default binary stays CGO- and privilege-free. _Decided 2026-04-23, Phase 4._
8. **Progress indicator:** Added in Phase 4 (originally unscoped). Rendered on stderr via `github.com/schollz/progressbar/v3` only when stderr is a TTY; auto-suppressed for pipes so output formats stay cleanly pipeable. _Decided 2026-04-23, Phase 4, in response to user request: "during the scans it needs to show some type of progress so the user know the tool is working properly."_

