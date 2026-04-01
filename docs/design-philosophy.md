# Design Philosophy

## Zero runtime dependencies

nopal is a single statically-linked binary with no runtime dependencies beyond the kernel. No shell scripts, no interpreted languages, no external binaries for core functionality. The only external process is `nft` for atomic ruleset application -- and that uses a stable JSON API, not fragile CLI parsing.

This is a hard constraint, not a preference. OpenWrt devices have 8-64 MB of flash. Every dependency is storage cost, attack surface, and a versioning liability.

### Why not shell out to `ip`, `conntrack`, etc.

mwan3 (the predecessor) orchestrates `ip rule`, `ip route`, `iptables`, and `conntrack` via shell scripts. This creates:

- Race conditions between sequential shell commands that should be atomic
- Fragile parsing of command output that varies across versions
- Process spawn overhead on every probe cycle (hundreds of fork/exec per minute)
- Difficulty reasoning about system state when multiple scripts modify it concurrently

nopal uses netlink sockets to talk directly to the kernel. One socket, one process, deterministic state.

## Explicit behavior

Nothing happens implicitly. Interfaces don't auto-recover without meeting probe thresholds. Conntrack doesn't flush unless the trigger is configured. DNS servers aren't added unless the interface reaches Online state. Firewall rules don't exist until a policy references the interface.

Every state transition has a defined set of actions. Every action has a defined trigger. If you want behavior, you configure it.

### Why this matters on a router

Routers are infrastructure. Surprising behavior in a desktop application is annoying; surprising behavior in a router causes an outage. Every automatic recovery, implicit fallback, or "smart" default is a potential failure mode that's invisible until it fires in production.

## Separation of concerns

Each subsystem owns exactly one responsibility:

- **Config** parses and validates. It does not act on configuration.
- **State machine** tracks interface health and computes transitions. It does not touch the kernel.
- **Netlink** manages kernel routing state. It does not know about policies.
- **nftables** generates firewall rules. It does not know about interface health.
- **Probe engine** sends and receives health check packets. It does not decide what transitions mean.
- **Daemon** orchestrates. It connects subsystems but contains no domain logic itself.

A change to the nftables rule generation should never require touching the health probe code. A change to the state machine should never require touching netlink. If it does, the boundary is wrong.

## Embedded-first

Design for the smallest target, not the largest. Decisions are evaluated against a 32 MB flash, 128 MB RAM MIPS device:

- **Binary size**: `--gc:arc`, `--opt:size`, `-d:useMalloc`, static musl linking. Every dependency is weighed against its size contribution.
- **Memory**: Reusable buffers, not per-operation allocations. Fixed-size sliding windows, not unbounded collections. Pre-allocated event buffers.
- **CPU**: Single-threaded event loop, not thread pools. Coalesced nftables regeneration, not per-event rebuilds. Timer wheel, not per-interface OS timers.

### Why not async/await

Nim has async/await via `asyncdispatch`. We don't use it because:

- It requires a garbage collector that handles cycles (ORC), not just reference counting (ARC). ORC adds runtime size and unpredictable pause behavior.
- The async transform creates closure environments on the heap for every suspended coroutine.
- nopal is I/O-multiplexed (epoll), not I/O-concurrent. There is one thread doing one thing at a time. `selectors` + non-blocking sockets is the correct abstraction -- async/await would add complexity and overhead for zero functional benefit.

## Atomic operations

System state changes must be atomic or not happen at all.

- **nftables**: The entire ruleset is replaced in one JSON transaction piped to `nft -j -f -`. Either all rules apply or none do. Never rule-by-rule insertion.
- **Config reload**: The full config is parsed and validated before any state changes. If parsing fails, the running config is untouched.
- **Route management**: Routes and rules are added/removed as complete sets per interface, not incrementally.

### Why not incremental nftables updates

Incremental rule insertion creates intermediate states where the ruleset is partially updated. Traffic during that window may be misrouted. With atomic replacement, the kernel switches from the old ruleset to the new one in a single operation. The cost is regenerating the full ruleset (~1ms for typical configs), which is negligible compared to the correctness guarantee.

## Composition over abstraction

Prefer concrete types and direct function calls over abstract interfaces. A health probe is not a generic "plugin" -- it is one of five known transport types (ICMP, DNS, HTTP, HTTPS, ARP) selected at config time. The set of probe types is closed and known at compile time.

Abstract interfaces are justified only when the set of implementations is genuinely open (backends, user-provided strategies) or when testing requires substitution. For internal components with a fixed set of variants, use case objects (variant types) instead.

## Fix the architecture, don't patch symptoms

If a bug reveals a design flaw, fix the design. Don't add a workaround that makes the symptom less visible.

- If the state machine produces incorrect transitions, fix the transition logic -- don't add post-transition fixup code.
- If nftables rules are wrong for a specific config, fix the rule generator -- don't add special-case patches.
- If the event loop has ordering issues, fix the dispatch logic -- don't add retry loops.

Workarounds accumulate. Each one makes the next bug harder to diagnose because the system's actual behavior diverges further from its intended design.

## First principles

Every design decision starts from the problem, not from precedent. mwan3's design is not a starting point to iterate from -- it is a catalog of problems to avoid. Other multi-WAN tools (PBR, load balancers) may have solved similar problems, but their solutions carry their own constraints and assumptions.

Ask "what does this system need to do?" before asking "how did someone else do it?"
