# Contributing to scry

Thanks for the interest. scry aims to be a fast, friendly, MIT-licensed
IP/port scanner with a small well-documented surface. These guidelines
exist so contributions land quickly and stay consistent.

## Ground rules

- **Read [`scry-plan.md`](./scry-plan.md)** for the design, phases, and
  decision log (§10). It's authoritative — code disagreements with the
  plan should update §10 first, then the code.
- **Small, reviewable PRs.** One logical change per PR. Reference the
  issue or `DEFERRED.md` line it closes.
- **Conventional commit messages** — `feat(…): …`, `fix(…): …`,
  `docs: …`, `chore: …`, `test(…): …`. The changelog auto-groups them.
- **Run tests before pushing.** `make test-race` must be green on the
  default build; `make test-race-tags rawsock` if you touched the SYN
  path.

## Development setup

```sh
git clone git@github.com:brandonhon/scry.git
cd scry
make build                 # produces bin/scry
make test-race             # full race suite
make man                   # regenerates docs/man/scry.1
```

For SYN-scan work:

```sh
sudo apt install libpcap-dev   # Debian/Ubuntu
go build -tags rawsock ./cmd/scry
sudo setcap cap_net_raw,cap_net_admin=eip bin/scry
SCRY_RUN_SYN_TESTS=1 go test -tags rawsock ./internal/portscan/...
```

The `SCRY_SYN_TARGET=host:port` env var opts a test into hitting a
real adjacent host — required for pcap verification.

## Project layout

See [`scry-plan.md`](./scry-plan.md) §3 for the full map. Quick tour:

| Path | What lives here |
|---|---|
| `cmd/scry` | main entry point |
| `cmd/gen-{man,services,top-ports}` | build-time generators |
| `internal/target` | target-spec parser (IPv4 only; see §10 #22) |
| `internal/portscan` | TCP-connect + raw SYN scanners |
| `internal/discovery` | host-up detection (TCP ping + ICMP under rawsock) |
| `internal/script` | gopher-lua engine + `scry.*` / NSE shim |
| `internal/output` | human / json / grep / live writers |
| `internal/cli` | cobra wiring, config loader, ulimit warnings |
| `internal/ratelimit` | token-bucket + adaptive limiter |
| `internal/progress` | stderr progress bar (TTY-only) |
| `scripts/` | bundled Lua scripts |
| `docs/site/` | Jekyll-rendered documentation site |
| `data/` | IANA registry snapshot + provenance README |

## Adding a feature

1. Check [`DEFERRED.md`](./DEFERRED.md) — it may already be listed.
2. Sketch in an issue first if the change is non-trivial.
3. Follow the existing phase pattern: one feature branch, small
   commits, `merge --no-ff` into `main` when done.
4. Any new CLI flag needs updates in:
   - `internal/cli/root.go` (registration)
   - `internal/cli/config.go` `configFlags` slice (if it should be
     YAML-loadable)
   - `docs/site/usage.md` or `config.md`
   - Man page regeneration: `make man`
5. New `§10` decisions go into `scry-plan.md` when you've resolved a
   trade-off worth documenting.

## Adding a Lua script

1. Put it in `scripts/<name>.lua`.
2. Describe the goal in `scripts/README.md`.
3. Keep it under 20 lines when possible. The `scry.*` API is
   documented at `docs/site/scripting.md`.
4. If the script needs binary payloads, build them via
   `scry.util.unhex(...)` — gopher-lua is Lua 5.1 and lacks `\xNN`
   escapes. `scripts/smb-version.lua` is the reference.

## Code review

- No CRITICAL or HIGH static-analysis findings.
- Tests green: `go vet ./...`, `go test -race ./...`, `golangci-lint
  run` if you have it.
- Behaviour changes need a test that would have caught the regression.

## Code of conduct

By participating you agree to the
[Contributor Covenant](./CODE_OF_CONDUCT.md).

## Licence

By contributing you agree your work will be licensed under the MIT
licence at [`LICENSE`](./LICENSE).
