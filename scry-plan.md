# Fast IP/Port Scanner — Project Plan

A CLI-first network scanner written in Go, targeting Linux and Windows. Goal: rival nmap and Angry IP Scanner on speed and ergonomics, with clean output and a scripting hook.

Working name placeholder: `scry` (replace as desired).

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
scry/
├── cmd/
│   └── scry/
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
| SYN scan | needs `CAP_NET_RAW` or root; `setcap cap_net_raw+ep ./scry` in install docs | requires Npcap installed in WinPcap-compat mode; document in README |
| ICMP ping | unprivileged ICMP on modern kernels (`/proc/sys/net/ipv4/ping_group_range`) else raw | raw ICMP via Npcap under `--syn`-style path, or fall back to TCP ping |
| ANSI color | native | enable VT processing via `golang.org/x/sys/windows/console` at startup; lipgloss handles most of it |
| File paths | — | use `filepath` everywhere (never `path` for FS) |
| Defaults | `~/.config/scry/` | `%APPDATA%\scry\` |

Cross-compile from one host: `GOOS=windows GOARCH=amd64 go build ./cmd/scry`. Ship both via GitHub Releases with checksums.

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
  local body, err = scry.tcp.request(host, port, "GET / HTTP/1.0\r\n\r\n", {timeout=3000})
  if err then return nil end
  local title = body:match("<title>(.-)</title>")
  if title then return "title: " .. title end
end
```
Document the `scry.*` API surface: `tcp.connect`, `tcp.request`, `udp.send`, `dns.lookup`, `log.info`, `util.hex`, etc. This is achievable in a phase or two of work.

**Option B — NSE compatibility shim (stretch / v2).**
Same engine as A, but also expose an `nmap.*` module that implements the most-used NSE helpers (`nmap.new_socket`, `stdnse.get_script_args`, `shortport.port_or_service`). Many simple NSE scripts would then run unmodified. Complex ones (anything using `brute`, `creds`, or binary protocol libs) won't. Be upfront in docs about the compatibility matrix.

**Option C — Shell out to nmap for scripts.**
If nmap is installed, pass `--script` through to it. This is fast to build and guarantees compat, but it means requiring nmap as a runtime dep and gives up on the "rival nmap" framing.

**Plan:** build A for v1. Revisit B in v2 once the API is stable. Don't pursue C.

---

## 8. CLI design

```
scry [TARGETS...] [flags]

Examples:
  scry 192.168.1.0/24
  scry 10.0.0.1-50 -p 22,80,443
  scry example.com -p- --syn
  scry @hosts.txt -p top1000 --up --json > results.ndjson
  scry 10.0.0.0/16 -p 22 --script scripts/ssh-banner.lua

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
- *Exit criteria:* `scry 127.0.0.1 -p 22` works on Linux and Windows.

**Phase 2 — Core scanner**
- Worker pool, bounded concurrency.
- Full port syntax (`-p`, ranges, top-N lists).
- CIDR + range iteration with proper memory behavior.
- Timeouts, retries, per-host latency tracking.
- `--up` / `--down` filtering.
- *Exit criteria:* `scry 192.168.1.0/24 -p top100` completes in single-digit seconds on LAN.

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
- Embed gopher-lua, define `scry.*` API.
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

1. **Final name:** `scry` — the verb "to scry" (peer into something to see what's there). Four characters, no existing Homebrew formula, no Go-module collision, distinct from `scan`/`probe`/`sonar`. Earlier working name was `gscan`; dropped because of a Homebrew conflict. Module path is `github.com/bhoneycutt/scry`; binary is `scry`; Lua API surface renamed `scry.*` in scripts. _Finalised 2026-04-23, post-Phase 7._
2. **SYN scan scope:** v2. v1 ships with TCP connect only. Raw-socket path will be build-tag gated (`-tags rawsock`) when added, so the default binary stays CGO-free and dependency-free. _Decided 2026-04-23, Phase 1._
3. **Scripting engine:** Option A — custom Lua API via `gopher-lua`. No NSE compatibility shim in v1. _Decided 2026-04-23, Phase 1._
4. **License:** MIT. Permissive, dominant in the Go ecosystem, no copyleft concerns for users embedding or forking. _Decided 2026-04-23, Phase 1._
5. **IPv6:** ~~Parser accepts IPv6 literals and CIDR from day one~~. **Revised 2026-04-23:** scry is IPv4-only in scope. See §10 #22 for the rationale and #22 points at the preservation branch. _Original decision Phase 1; superseded._
6. **Config file:** Flags-only for v1. No viper yet. Revisit once the flag surface stabilizes and users ask for it. _Decided 2026-04-23, Phase 1._
7. **ICMP echo in Phase 4:** Deferred to Phase 6. Host-up detection in Phase 4 uses TCP probes only — either the normal port scan, or (in `-sn`/`--ping-only` mode) a short list of common TCP ports (22/80/443/445/3389) where any response (open/closed/RST) counts as up. ICMP will ship alongside SYN scanning under the `rawsock` build tag so the default binary stays CGO- and privilege-free. _Decided 2026-04-23, Phase 4._
8. **Progress indicator:** Added in Phase 4 (originally unscoped). Rendered on stderr via `github.com/schollz/progressbar/v3` only when stderr is a TTY; auto-suppressed for pipes so output formats stay cleanly pipeable. _Decided 2026-04-23, Phase 4, in response to user request: "during the scans it needs to show some type of progress so the user know the tool is working properly."_
9. **UDP in Lua API:** Deferred. `scry.udp.send` is not exposed in v1; the Phase 5 scripting surface is TCP-only (`tcp.request`, `tls.request`, `tls.cert`). Add UDP when a concrete script actually needs it (DNS-over-UDP, SNMP). _Decided 2026-04-23, Phase 5._
10. **Script isolation:** One fresh `lua.LState` per script invocation. Slower than pooling but goroutine-safe by construction and prevents scripts leaking state between hosts. Revisit only if scripting becomes a measurable hotspot. _Decided 2026-04-23, Phase 5._
11. **SIGINT semantics:** Ctrl-C cancels the context and refuses new hosts, but every host already in flight completes its probes and its result is flushed to output before the command exits. Implemented via unconditional channel send on the scanner side and a drain-until-close loop on the CLI side. _Decided 2026-04-23, Phase 7._
12. **Man page generator:** Stand-alone `cmd/gen-man` runs from `make man`; produces `docs/man/scry.1`. Not built into the shipped `scry` binary so `cobra/doc` stays out of the release artifact. _Decided 2026-04-23, Phase 7._
13. **Release tooling:** goreleaser for GitHub Releases. Matrix: linux/{amd64,arm64}, windows/amd64, darwin/{amd64,arm64}. windows/arm64 intentionally excluded (not on any demand path today). CGO disabled across the board. _Decided 2026-04-23, Phase 7._
14. **Phase ordering:** Phase 7 hardening shipped before Phase 6 raw sockets so a shippable v1 could exist without the libpcap/Npcap surface. Phase 6 now landed. _Decided 2026-04-23, Phase 7._
15. **SYN scanner build tag:** `-tags rawsock` on Linux only in this cut. Default builds stay CGO-free and surface `--syn` as a clean error pointing at the rebuild instructions. Windows Npcap path and IPv6 SYN are both deferred in `DEFERRED.md`. _Decided 2026-04-23, Phase 6._
16. **SYN dependency layering:** gopacket + libpcap linked only under `rawsock`. The pcap handle is opened synchronously so capability / interface errors surface to the CLI before output begins. Ethernet frame construction uses a broadcast DST MAC as a placeholder; proper ARP lookup / default-gateway MAC resolution is listed in `DEFERRED.md`. _Decided 2026-04-23, Phase 6._
17. **Speed-first defaults.** `--timeout 500ms`, `--retries 0`, `--concurrency 2000`, `--max-hosts 100`. Rationale: LAN scans should feel instant; WAN / lossy-link users raise timeout + retries explicitly. Trade-off: filtered ports are more likely to be misclassified on slow links at default settings; the help text and README call this out. Previous defaults (1500ms / 1 retry / 1000 sockets / 50 hosts) are preserved verbatim in this decision note for anyone diffing behaviour across versions. _Decided 2026-04-23, post-Phase 7, in response to user request: "i think the defaults should be for speed. for more accurate results the user should add flags as necessary."_
18. **ICMP echo races TCP ping, not replaces it.** Under `-tags rawsock` on Linux, `discovery.Ping` launches an ICMP Echo goroutine alongside the TCP probes; first responder wins. Reason: unprivileged ICMP via `SOCK_DGRAM` is gated by `ping_group_range` on some kernels. Racing avoids a long ICMP wait when the socket open silently succeeds but no response comes. Windows ICMP (raw) is deferred with the SYN-Windows work. _Decided 2026-04-23, scanning-protocols sweep._
19. **ARP via `/proc/net/arp` + `/proc/net/route`, not netlink.** `/proc` is rock-solid across all Linux distros, matches our existing `syn_linux` footprint, and avoids pulling in a netlink library or CGO. Netlink is a latent upgrade if caching or staleness becomes a real problem. _Decided 2026-04-23, scanning-protocols sweep._
20. **Adaptive rate limiter is opt-in (`--adaptive`).** First cut defaults to off so a regression in the feedback loop doesn't silently slow real scans. Flip default to on once telemetry from real networks confirms the halve/double thresholds behave. Floor is 50 pps so the limiter can't strangle a scan to a crawl. _Decided 2026-04-23, scanning-protocols sweep._
21. **Windows Npcap SYN path: not shipped.** A scaffolded-but-unverified implementation that rots is worse than a clearly documented gap. `syn_other.go` carries the contract and the Windows-specific pieces any contributor would need (NPF device names via `pcap.FindAllDevs`, ARP via `GetIpNetTable2`/`SendARP`, installer docs for Npcap WinPcap-compat mode). Default Windows build stays TCP-connect only. _Decided 2026-04-23, scanning-protocols sweep._
22. **IPv6 out of scope for v0.1.** All v6 support — parser acceptance, CIDR/range iteration, SYN frame construction, interface selection — moved to the preservation branch `feat/ipv6-support` (tip at the scanning-protocols merge). The parser now rejects v6 literals, prefixes, and ranges with an error that names the branch; hostnames that resolve only to v6 also error; `--exclude` rejects v6. Rationale: keeping v4 and v6 as co-equal first-class in every pipeline doubled the surface area of several code paths and every one of the v6 features we shipped had environment-gated e2e verification. v0.1 ships a narrower, fully-verified product; v6 returns on its own branch when there's an IPv6-reachable test harness. _Decided 2026-04-23, remove-ipv6 sweep, in response to user request: "lets move ALL ipv6 support to it's own branch for now. only ipv4 is in scope at this time."_
23. **IANA, not nmap-services, for bundled port data.** `top1000` and the service-name map are generated from IANA's public-domain Service Names and Port Numbers registry (`data/iana-service-names-port-numbers.csv`), not from `nmap-services`. nmap-services has richer data (frequency-sorted rankings) but ships under the copyleft-style Nmap Public Source License, incompatible with scry's MIT. Generators live under `cmd/gen-top-ports` and `cmd/gen-services`; `make regen-data` rebuilds both files. `top100` stays hand-maintained (nmap frequency order for the top 100 is factual, well-known, and not itself a derivative); the 900-entry tail of `top1000` is now IANA-assigned TCP ports in numeric order (upgrade over the previous "port 1, port 2, …" placeholder). The service map carries every assigned TCP port (~6k entries, ~150 KB binary delta). Trade-off: user-facing annotations match IANA canonical names (e.g. 3389 → `ms-wbt-server`, not `rdp`); a nickname overlay can be added if users ask. _Decided 2026-04-23, ports-and-services sweep._

