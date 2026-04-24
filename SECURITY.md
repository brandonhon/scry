# Security policy

## Supported versions

`main` and the latest tagged release receive security fixes.

## Reporting a vulnerability

**Please don't open a public GitHub issue for security reports.**

Instead, open a [private security advisory](https://github.com/brandonhon/scry/security/advisories/new)
so we can triage and patch before details are public.

Include:

- the version / commit you tested
- a minimal reproduction
- the impact (what an attacker can do)
- any suggested remediation

You'll get a first acknowledgement within 72 hours. High-severity
issues will ship a patch release as soon as a fix is verified;
medium/low issues fold into the next scheduled release.

## Scope

scry is an **active-probe network tool**. By design it opens TCP
connections, sends packets, and can run user-supplied Lua scripts. If
an attacker can pass flags to a running `scry` process or feed it a
malicious script, they can already do what they want on the network
scry has access to. The security boundary is the **scry process
itself**, not the network it probes.

In scope:

- Memory-unsafe patterns in the Go source
- Lua sandbox escapes that let a script read/write arbitrary files,
  run processes, or touch sockets outside the scanner's own handles
- Config-file parsing vulnerabilities
- CLI argument parsing vulnerabilities
- Dependency CVEs that affect scry's running binary

Out of scope:

- "scry can scan networks" — that is the feature, not a vulnerability.
- User running scry against a host without authorisation — that's on
  the operator.
- Hardcoded values (like the default progress bar throttle) — they're
  intentional.

## Fixed advisories

None yet. `v0.1.0` is the first tagged release.
