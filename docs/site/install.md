---
title: Install
---

# Install

## Prebuilt binaries

Grab the archive for your platform from the [Releases page]({{ site.github.repository_url }}/releases):

- `scry_<version>_linux_amd64.tar.gz`
- `scry_<version>_linux_arm64.tar.gz`
- `scry_<version>_darwin_amd64.tar.gz`
- `scry_<version>_darwin_arm64.tar.gz`
- `scry_<version>_windows_amd64.zip`

Each archive contains:

- `scry` (or `scry.exe`) — the binary
- `LICENSE`
- `README.md`
- `scripts/*.lua` — bundled scripts
- `docs/man/scry.1` — man page

## Build from source

Requires Go 1.22+.

```sh
git clone {{ site.github.repository_url }} scry
cd scry
make build             # Linux / macOS
.\scripts\build.ps1    # Windows
```

Produces `bin/scry` (or `bin\scry.exe`).

## SYN scan build

SYN scanning is gated behind the `rawsock` build tag because it pulls in
libpcap and needs `CAP_NET_RAW`. See the [SYN page](./syn.html).

```sh
sudo apt install libpcap-dev         # Debian/Ubuntu
sudo dnf install libpcap-devel       # Fedora/RHEL
go build -tags rawsock -o bin/scry ./cmd/scry
sudo setcap cap_net_raw,cap_net_admin=eip bin/scry
```

## Verify

```sh
scry --version
scry 127.0.0.1 -p 22
```

## Compatibility

- Linux kernel 4.x+ (tested on 5.x/6.x).
- macOS 11+.
- Windows 10+; Windows 11 recommended for full VT / colour support.

IPv6 is currently **out of scope** and parked on the `feat/ipv6-support`
branch; see the [plan]({{ site.github.repository_url }}/blob/main/scry-plan.md) §10 #22.
