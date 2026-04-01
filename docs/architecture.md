# Architecture

## Overview

nopal is a multi-WAN policy routing manager for OpenWrt. Single binary, dual mode: daemon (`nopald`) or CLI tool (`nopal`) selected by argv[0]. The daemon runs a single-threaded epoll event loop that orchestrates health probes, state machines, netlink routing, and nftables firewall rules.

```
                  +-----------+
                  |  Config   |  UCI parser (/etc/config/nopal)
                  +-----+-----+
                        |
                  +-----v-----+
    signals ----->|  Daemon    |<----- IPC (Unix socket)
                  | event loop |
                  +--+--+--+--+
                     |  |  |
           +---------+  |  +----------+
           |            |             |
    +------v----+ +-----v------+ +----v-------+
    |  Health   | |   State    | |  Netlink   |
    |  Probes   | |  Machine   | |  (routes)  |
    +------+----+ +-----+------+ +----+-------+
           |            |             |
           +-----+------+------+-----+
                 |             |
          +------v------+ +---v--------+
          |  nftables   | |  Conntrack |
          | (firewall)  | |  (flush)   |
          +-------------+ +------------+
```

## Event loop: epoll via selectors

### What we chose

A single-threaded, non-blocking event loop using Nim's `selectors` stdlib module (which wraps `epoll` on Linux). All I/O sources -- netlink sockets, probe sockets, IPC clients, the signal self-pipe -- are registered with one selector and dispatched by token.

**Token allocation:**
```
0         = Link monitor (netlink RTNLGRP_LINK)
1         = IPC listener (Unix socket accept)
2         = Signal pipe (self-pipe for SIGTERM/SIGHUP)
3         = Route monitor (netlink route/address changes)
100-199   = Probe sockets (100 + interface_index)
1000+     = IPC client connections (1000 + client_id)
```

**Loop structure:**
1. Compute timeout from timer wheel's next deadline
2. `selector.select(timeout)` -- blocks on epoll
3. Dispatch ready events by token range
4. Process expired timers from min-heap
5. Execute deferred actions (coalesced nftables regeneration, DNS updates)
6. Repeat

### Why not threads

There is no concurrent work to parallelize. The daemon processes events sequentially: a probe reply arrives, the state machine evaluates, routes and rules are updated. Threading would add synchronization overhead, shared-state bugs, and binary size for zero throughput benefit.

On a 580 MHz MIPS router, context switching between threads is expensive. A single epoll loop with non-blocking I/O is the optimal architecture for this workload.

### Why not async/await

Nim's `asyncdispatch` provides coroutine-style async, but it requires ORC (cycle-collecting GC) instead of ARC (simple reference counting). ORC adds ~15 KB to the binary and introduces non-deterministic collection pauses. Since we have no concurrent coroutines -- just multiplexed I/O -- `selectors` gives us the same capability with a smaller, more predictable runtime.

## Signal handling: Self-pipe

### What we chose

POSIX signals (`SIGTERM`, `SIGHUP`, `SIGINT`) are caught by minimal handlers that write a single byte (`'T'` for terminate, `'R'` for reload) to a non-blocking pipe. The read end of the pipe is registered with the selector. The event loop reads the byte and dispatches the action.

`SIGPIPE` is set to `SIG_IGN` to prevent crashes when IPC clients disconnect mid-write.

### Why self-pipe instead of signalfd

`signalfd` is Linux-specific and requires masking signals with `sigprocmask` before creating the fd. The self-pipe trick is POSIX-portable, well-understood, and uses only async-signal-safe operations (`write`). For two signal types, the complexity difference is negligible and the self-pipe is more transparent.

## Configuration: UCI parser

### What we chose

A custom parser for OpenWrt's UCI config format (`/etc/config/nopal`). Tokenizes lines into `config`, `option`, and `list` directives. Collects into typed section objects with validation and cross-reference checking.

**Config hierarchy:**
```
NopalConfig
  globals: GlobalsConfig         (mark_mask, logging, conntrack defaults)
  interfaces: seq[InterfaceConfig] (probe settings, thresholds, device binding)
  members: seq[MemberConfig]     (interface + metric + weight, referenced by policies)
  policies: seq[PolicyConfig]    (member groups, last_resort, sticky mode)
  rules: seq[RuleConfig]         (match criteria -> policy, proto/ports/IPs)
```

**Hot reload:** SIGHUP or `nopal reload` triggers re-parse. `ConfigDiff` computes minimal changes: if only routing changed (members/policies/rules), regenerate nftables without tearing down probes. If interfaces changed structurally, full rebuild with state preservation where possible.

### Why not JSON/TOML/YAML config

OpenWrt's ecosystem is built on UCI. Every OpenWrt tool (`uci`, LuCI web interface, rpcd) speaks UCI natively. Using a different format would make nopal a second-class citizen that can't be configured through the standard OpenWrt UI or automation tools.

### Why a custom parser instead of libuci

`libuci` is a C library with a complex API, internal state management, and file locking semantics designed for the UCI daemon. nopal only needs to read a config file at startup and on reload -- a 200-line tokenizer is simpler, has no FFI surface, and gives complete control over error reporting and validation.

## Health probes: Pluggable transports

### What we chose

Five probe transport types, selected per-interface at config time:

| Transport | Socket type | Protocol |
|---|---|---|
| ICMP | `SOCK_DGRAM + IPPROTO_ICMP/V6` | Echo request/reply |
| DNS | `SOCK_DGRAM` (UDP) | A/AAAA query to port 53 |
| HTTP | `SOCK_STREAM` (TCP) | HEAD request to port 80 |
| HTTPS | `SOCK_STREAM` (TCP) + mbedTLS | HEAD request to port 443 |
| ARP | `AF_PACKET + ETH_P_ARP` | ARP request/reply (IPv4 only) |

**Common patterns:**
- All sockets use `SO_BINDTODEVICE` to bind to the WAN interface
- All sockets use `SO_MARK 0xDEAD` to bypass nopal's own policy routing rules
- All sockets are non-blocking, with fds registered in the selector
- Probe results feed into the state machine as success/failure + RTT

**Probe cycle:** Each interface has N target IPs. One probe per target per cycle. A cycle succeeds if >= `reliability` targets respond within `probe_timeout`. Cycles repeat every `probe_interval` (configurable per-state: faster when degraded, slower when offline).

### Why raw sockets instead of a ping library

ICMP probes require `SO_BINDTODEVICE` and `SO_MARK` to route through the correct WAN and bypass policy rules. No existing library exposes these socket options. Raw socket construction is ~50 lines per transport -- less code than integrating and configuring a library.

### Why not a trait/interface for transports

The set of transports is closed (5 types, known at compile time). A case object (variant type) with a `kind` discriminator is simpler than a vtable and avoids heap allocation for the transport object. The probe engine switches on `kind` at the call site -- there are exactly two call sites (send and recv), so the dispatch is trivial.

## Netlink: Native kernel communication

### What we chose

Direct netlink sockets (`AF_NETLINK`) for all kernel interactions:

- **NETLINK_ROUTE**: Add/delete routes, ip rules, query addresses, monitor link state and route changes
- **NETLINK_NETFILTER**: Selective conntrack flush by firewall mark

Custom `NlMsgBuilder` constructs netlink messages with proper alignment (NLMSG_ALIGN) and attribute nesting. `NlMsgHdr` and protocol-specific headers (`RtMsg`, `IfInfoMsg`, `NfGenMsg`) are `{.packed.}` objects with compile-time size assertions.

**Two socket patterns:**
1. **Request/response** (RouteManager, ConntrackManager): Send a message, wait for ACK with 5-second timeout. Used for route/rule modifications and conntrack flush.
2. **Multicast listener** (LinkMonitor, RouteMonitor): Subscribe to netlink groups, receive asynchronous notifications. Registered with the selector for event-driven dispatch.

### Why not shelling out to `ip route`, `ip rule`, `conntrack`

See design philosophy: process spawning is expensive, output parsing is fragile, and sequential commands create race conditions. Netlink is the kernel's native API -- `ip` and `conntrack` are just netlink clients themselves.

### Why custom netlink implementation instead of a library

Nim has no mature netlink library. The netlink protocol is straightforward: fixed header + variable-length attributes with 4-byte alignment. The full implementation (socket, builder, parser, route/link/conntrack managers) is ~2100 lines. A third-party library would be a larger dependency than the implementation itself.

## State machine: Interface lifecycle

### What we chose

Five states per interface with explicit transition rules:

```
Init ──link up──> Probing ──up_count successes──> Online
                     |                               |
                     | down_count failures           | probe failure
                     v                               v
                  Offline <──down_count failures── Degraded
                     ^                               |
                     |        quality recovered       |
                     └──────── Online <──────────────┘
```

- **Init**: Waiting for netifd to report interface up (link event)
- **Probing**: Link is up, probes running, not yet confirmed reachable
- **Online**: Healthy, participating in policies
- **Degraded**: Started failing probes or quality thresholds exceeded, still in policies
- **Offline**: Down, removed from policies

**Both Online and Degraded participate in routing.** Degraded means "reachable but unreliable" -- traffic still flows, but the interface may be demoted if better alternatives exist.

**Quality tracking:** Sliding window of last N probe results. Computes average RTT and loss percentage. Degraded state triggers when RTT > `latency_threshold` or loss > `loss_threshold`.

**Dampening (RFC 2439):** Exponential penalty on repeated failures prevents flapping interfaces from rapidly toggling Online/Offline. Penalty decays with configurable half-life. Interface is suppressed (cannot transition to Online) while penalty exceeds suppress threshold.

### Why five states instead of two (up/down)

Two states create flapping: an interface that passes one probe goes Online, fails the next probe and goes Offline, toggling every cycle. The Probing and Degraded states provide hysteresis -- you need consecutive successes to come up and consecutive failures to go down. This is critical for mobile/LTE connections with variable latency.

## nftables: Atomic JSON ruleset

### What we chose

A chain builder generates a complete nftables JSON ruleset from the current policy state. The JSON is piped to `nft -j -f -` as a single atomic transaction.

**Chain structure:**
```
inet nopal (table)
  prerouting   -- skip probe packets, restore ct marks, mark inbound WAN traffic
  forward      -- accept local traffic, restore ct marks, jump to policy_rules
  output       -- same as forward for locally-originated traffic
  policy_rules -- match user rules (proto/ports/IPs), jump to policy chains
  policy_{name}  -- per-policy: tier-based weighted load balancing
  mark_{iface}   -- per-interface: set mark + save to conntrack
  postrouting  -- MSS clamping per interface
  sticky_r{N}  -- per-rule sticky session helpers (src_ip or src_dst maps)
```

**Load balancing:** Within a tier, `numgen inc mod N` distributes traffic across members by weight. Weights map to slot counts in a vmap.

**Sticky routing:** Three modes:
- **flow**: Conntrack mark (default, automatic for established connections)
- **src_ip**: nftables map keyed by source IP, with configurable timeout
- **src_dst**: nftables map keyed by (source IP, dest IP) tuple

**Firewall mark assignment:** FNV-1a hash of interface name, mapped to a slot within `mark_mask`. Stable across config reorder (name-based, not position-based). Linear probing for hash collisions.

### Why JSON API instead of native nftables (libnftables)

`libnftables` is a C library with a complex batch/transaction API. The JSON format piped to `nft -j -f -` is:
- Documented and stable (nftables JSON schema)
- Debuggable (pipe to `jq` to inspect)
- Atomic (single stdin read = single transaction)
- Zero FFI surface

The cost is one process spawn per ruleset application (~5ms). This happens on state transitions, not per-packet.

### Why not iptables

nftables is the successor to iptables, available since Linux 3.13 (2014). OpenWrt has used nftables by default since 22.03 (2022). nftables provides native JSON input, atomic ruleset replacement, and maps/sets -- none of which iptables supports.

## IPC: JSON over Unix socket

### What we chose

A Unix domain socket at `/var/run/nopal.sock` with length-prefixed JSON messages (4-byte big-endian length + JSON payload). The CLI tool connects, sends a request, reads the response, and disconnects.

**Methods:** `status`, `interface.status`, `connected`, `config.reload`, `rules`

**Framing:** `[u32 BE length][JSON bytes]`. Max 64 KB per message. Max 8 concurrent clients.

Clients can subscribe to event broadcasts (state changes) by sending a subscribe request.

### Why JSON instead of MessagePack

The IPC is local-only (CLI to daemon on the same device). JSON is:
- Human-debuggable (`socat` + `jq` for manual inspection)
- Zero dependencies (Nim stdlib `json`)
- Negligible overhead for single request/response exchanges

MessagePack saves ~30% wire size, which is irrelevant for local IPC payloads under 4 KB.

### Why length-prefixed framing instead of newline-delimited

JSON can contain newlines in string values. Length-prefixed framing is unambiguous, requires no escaping, and allows the receiver to allocate the exact buffer size before reading.

## Development environment

### What we chose

All development and CI builds run inside openSUSE Tumbleweed Docker containers. Tumbleweed provides rolling-release access to the latest Nim compiler, GCC, and tooling without waiting for distro release cycles.

Cross-compilation toolchains are built with [crosstool-ng](https://crosstool-ng.github.io/) for all four OpenWrt targets:

| Target | ct-ng tuple | Notes |
|---|---|---|
| aarch64 | `aarch64-unknown-linux-musl` | Cortex-A53/A72 routers |
| armv7hf | `armv7-unknown-linux-musleabihf` | Cortex-A7/A9 routers |
| mips | `mips-unknown-linux-musl` | Big-endian MIPS (Atheros, MediaTek) |
| mipsel | `mipsel-unknown-linux-musl` | Little-endian MIPS (Broadcom, Realtek) |

Toolchains are built once and cached as Docker layers. The Nim build pipeline is: `nim c --compileOnly` (generates C on host) then cross-compile the generated C with the ct-ng toolchain.

**HTTPS build variant:** The base binary is fully static. The HTTPS-enabled variant dynamically links against system mbedTLS, which requires mbedTLS development headers at compile time (architecture-independent, pulled from OpenWrt's package feed).

### Why crosstool-ng instead of OpenWrt SDK

The OpenWrt SDK is designed for building full OpenWrt packages with dynamic linking against the system's musl and libraries. For a statically-linked binary:

- The SDK pulls in the entire OpenWrt build system (~500 MB) just to get a cross-compiler
- SDK versions are tied to OpenWrt releases — you can't freely choose GCC or musl versions
- SDK toolchains include OpenWrt-specific patches that are irrelevant for static builds

crosstool-ng builds exactly the toolchain you need: specific GCC version, specific musl version, specific architecture flags. The result is a ~200 MB toolchain per target that produces identical output regardless of the host environment.

### Why Tumbleweed

Rolling release means the Nim compiler, GCC, and all development tools are always current without manual version management. For a language (Nim) that is still evolving, being on the latest stable compiler avoids accumulating workarounds for fixed bugs.

## Source structure

```
src/
  nopal.nim                    -- entry point, argv[0] dispatch, CLI subcommands
  daemon.nim                   -- event loop, component orchestration
  errors.nim                   -- error types
  timer.nim                    -- timer wheel (heapqueue min-heap)
  logging.nim                  -- syslog handler
  dnsmanager.nim               -- resolv.conf writer
  linux_constants.nim          -- importc declarations for Linux-specific constants
  config/
    schema.nim                 -- config types, enums
    parser.nim                 -- UCI tokenizer and validator
    diff.nim                   -- config change detection for hot reload
  netlink/
    socket.nim                 -- NetlinkSocket, NlMsgBuilder, constants
    route.nim                  -- RouteManager: routes, rules, addresses
    link.nim                   -- LinkMonitor: interface up/down events
    monitor.nim                -- RouteMonitor: route/address change events
    conntrack.nim              -- ConntrackManager: selective flush by mark
  health/
    engine.nim                 -- ProbeEngine: cycle orchestration, quality tracking
    icmp.nim                   -- ICMP echo probe (IPv4 + IPv6)
    dns.nim                    -- DNS query probe (UDP)
    http.nim                   -- HTTP HEAD probe (TCP)
    https.nim                  -- HTTPS probe (TCP + mbedTLS, compile-time flag)
    arp.nim                    -- ARP probe (AF_PACKET, IPv4 only)
    dampening.nim              -- RFC 2439 exponential penalty/decay
  state/
    tracker.nim                -- InterfaceTracker, state enum, quality window
    policy.nim                 -- policy resolution (tier grouping, active member selection)
    transition.nim             -- state transition -> action mapping
  nftables/
    chains.nim                 -- chain/rule builder (JSON construction)
    ruleset.nim                -- ruleset types
    engine.nim                 -- nft subprocess driver
  ipc/
    protocol.nim               -- request/response JSON types
    server.nim                 -- Unix socket accept/read/write, framing
    methods.nim                -- RPC method dispatch
docs/
  design-philosophy.md
  architecture.md
  testing.md
tests/
  t_config.nim                -- UCI parser, validation, diff
  t_state.nim                 -- state transitions, dampening, policy resolution
  t_health.nim                -- probe engine cycles, quality window
  t_nftables.nim              -- chain generation, mark assignment
```
