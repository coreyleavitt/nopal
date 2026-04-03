# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

nopal is a multi-WAN policy routing manager for OpenWrt, replacing mwan3. Written in Nim (requires 2.2+) as a single statically-linked binary with zero runtime dependencies. It uses native nftables JSON API, raw sockets for health probes, and netlink for routing/conntrack operations.

## Build Commands

```bash
nim c src/nopal.nim                    # Debug build
nim c -d:release src/nopal.nim         # Release build (size-optimized, static)
nim c -d:release -d:https src/nopal.nim  # With HTTPS probe support (mbedTLS)

# Cross-compile for OpenWrt targets (requires toolchain image)
nim c -d:release -d:https -d:aarch64 src/nopal.nim
nim c -d:release -d:https -d:armv7hf src/nopal.nim
nim c -d:release -d:https -d:mips src/nopal.nim
nim c -d:release -d:https -d:mipsel src/nopal.nim
```

Cross-compilation uses clang + musl sysroots + compiler-rt. Target profiles are in `config.nims`. Pre-built toolchain image: `ghcr.io/coreyleavitt/nopal-toolchain:latest`.

## Testing

```bash
# Run all module tests (each module has `when isMainModule` test blocks)
nim c -r src/config/parser.nim
nim c -r src/config/diff.nim
nim c -r src/state/machine.nim
nim c -r src/state/tracker.nim
nim c -r src/state/policy.nim
nim c -r src/health/dampening.nim
nim c -r src/health/engine.nim
nim c -r src/health/icmp.nim
nim c -r src/health/dns.nim
nim c -r src/netlink/socket.nim
nim c -r src/nftables/chains.nim
nim c -r src/nftables/marks.nim
nim c -r src/nftables/ruleset.nim
nim c -r src/ipc/protocol.nim
nim c -r src/ipc/methods.nim
nim c -r src/dnsmanager.nim

# HTTPS tests
nim c -r -d:https src/health/https.nim
```

CI runs compile, compile with HTTPS, and all module tests on Nim 2.2.

## Architecture

**Single binary, dual mode**: `nopal.nim` dispatches based on argv[0] (via `paramStr(0)`) — runs as daemon (`nopald`) or CLI tool (`nopal`). CLI communicates with daemon via Unix socket IPC using JSON-RPC (length-prefixed u32 BE).

**Event loop**: `daemon.nim` uses `std/selectors` (epoll) for async I/O. Token allocation: 0-3 reserved for internal fds (signal pipe, IPC listener, link/route monitors), 100+ for probe sockets, 1000+ for IPC clients.

**GC**: `--mm:arc` (deterministic, minimal runtime overhead).

### Key modules

- **`src/config/`** — UCI config parser (`/etc/config/nopal`). `schema.nim` defines types, `parser.nim` parses, `diff.nim` computes minimal changes for hot reload.
- **`src/health/`** — Pluggable health probes via `ProbeTransport` variant type. Implementations: `icmp.nim`, `dns.nim`, `http.nim`, `https.nim` (feature-gated), `arp.nim`. `dampening.nim` implements RFC 2439 exponential penalty/decay. `engine.nim` orchestrates probe cycles.
- **`src/state/`** — Interface state machine (Init → Probing → Online ↔ Degraded ↔ Offline). `machine.nim` is the pure core (`func decide` with `{.raises: [].}`). `tracker.nim` is the mutable shell (snapshot/apply). `policy.nim` resolves active members by metric tiers.
- **`src/netlink/`** — Native netlink via `socket.nim` abstraction. `route.nim` manages routes/rules, `link.nim` monitors link state, `monitor.nim` detects route/address changes, `conntrack.nim` flushes conntrack entries.
- **`src/nftables/`** — Atomic JSON ruleset generation. `chains.nim` builds policy rules with load balancing/sticky routing. `engine.nim` pipes JSON to `nft -j -f -` for atomic application. `marks.nim` does FNV-1a mark hashing.
- **`src/ipc/`** — Unix socket server at `/var/run/nopal.sock`. `methods.nim` dispatches RPC methods (status, interface.status, connected, config.reload). `protocol.nim` defines JSON wire types.

### Design principles

- **No external binaries**: All probes, netlink, nftables use in-process implementations. Probes use `SO_BINDTODEVICE` + `SO_MARK 0xDEAD` to bypass policy rules.
- **Atomic nftables**: Entire ruleset replaced in one JSON transaction, never rule-by-rule.
- **FNV-1a mark hashing**: Stable firewall mark assignment across config reorder, with linear probing for collisions. Slot count from `mark_mask`.
- **Hot reload on SIGHUP**: Config diff preserves interface state; only changed items are updated.
- **Signal safety**: Handlers only write to a self-pipe; event loop reads it.
- **HTTPS**: Optional feature (`-d:https`) using [nim-mbedtls](https://github.com/coreyleavitt/nim-mbedtls). Dynamically links against system mbedTLS on OpenWrt.

## OpenWrt Packaging

`openwrt/` contains packaging files. `openwrt/Makefile` has the package version. CI builds `.ipk` and `.apk` packages for all four target architectures via the Release workflow.

## Hardware Testing

Test device: Cudy R700 (mipsel_24kc, MT7621). See `~/projects/openwrt-builder/profiles/cudy-r700-dev/HARDWARE_TEST_ENV.md` for device details. Test harness: `scripts/hwtest.py` (runs on device with python3 from tmpfs).

**IMPORTANT**: Never install packages to flash on test devices (`apk add` without `--root`). Flash is ~8MB. Python3 and dev tools auto-install to tmpfs via the dev-packages init service.
