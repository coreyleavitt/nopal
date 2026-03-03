# nopal

Multi-WAN policy routing manager for OpenWrt. Drop-in replacement for
[mwan3](https://openwrt.org/docs/guide-user/network/wan/multiwan/mwan3),
written in Rust as a single statically-linked binary with zero runtime
dependencies.

## Why nopal over mwan3?

| | mwan3 | nopal |
|---|---|---|
| Implementation | Shell scripts + per-interface tracker processes | Single async Rust binary |
| Firewall | iptables (requires `iptables-nft` shim on 22.03+) | Native nftables JSON API |
| Dependencies | arping, httping, nping, ipset, iptables, conntrack-tools | None |
| Config reload | Full stop + start | Hot reload with state preservation |
| IPv6 | Requires separate interface entry per family | `family: both` on a single entry |
| Conntrack flush | Writes `/proc/net/nf_conntrack` (full table wipe) | Native netlink, selective flush by mark |
| Health probes | Forks external binaries (ping, httping, arping, nslookup) | All probes implemented in-process |
| `mwan3 use` | `LD_PRELOAD` sockopt wrapper (fails on static binaries) | UID-range ip rules |
| Status API | Shell reads status files | Unix socket IPC with event subscription |
| Route dampening | None | RFC 2439 exponential penalty + decay |
| Binary size | ~50 KB scripts + many dependency packages | ~800 KB static binary |

## Feature Comparison

nopal implements every mwan3 feature and adds several that mwan3 lacks.

### Health Probes

| Method | mwan3 | nopal | Notes |
|---|---|---|---|
| ICMP ping | `ping` binary | Raw ICMP socket | Configurable TTL, payload size |
| ARP | `arping` binary | Native `AF_PACKET` | Layer-2 probe for same-segment gateways |
| HTTP | `httping` binary | Native TCP + HTTP/1.0 | Detects captive portals (non-2xx = fail) |
| HTTPS | `httping --ssl` | Native rustls TLS | Feature-gated: `--features https` |
| DNS | `nslookup` binary | Raw UDP DNS probe | Configurable query name |
| Composite | N/A | OR-logic across methods | Any method succeeding = up |
| nping-* | nmap `nping` binary | Not supported | Warns with native alternative suggestions |

All probes use `SO_BINDTODEVICE` and `SO_MARK` (0xDEAD) to bypass policy
rules and egress through the correct WAN.

### Quality Monitoring

- Sliding window RTT and packet loss tracking per interface
- Separate failure and recovery thresholds for hysteresis:
  `latency_threshold` / `recovery_latency`, `loss_threshold` / `recovery_loss`
- `check_quality` toggle to disable threshold evaluation without removing config
- `Degraded` state: interface stays in policy while quality recovers

### Route Dampening (nopal only)

RFC 2439-inspired exponential penalty system that prevents interfaces from
flapping between online and offline:

- Configurable halflife, ceiling, suppress, and reuse thresholds
- Penalty decays exponentially: `penalty * 2^(-elapsed / halflife)`
- Suppressed interfaces cannot transition to Online until penalty decays
  below the reuse threshold

### Policy Routing

| Feature | mwan3 | nopal |
|---|---|---|
| Load balancing | `iptables -m statistic` | `nftables numgen inc vmap` |
| Failover (metric tiers) | Yes | Yes |
| Sticky: flow (conntrack) | Yes | Yes |
| Sticky: source IP | ipmark set | nftables map with timeout |
| Sticky: source + dest IP | No | nftables map with concatenated key |
| Last resort | unreachable / blackhole / default | Same |
| Rule matching | proto, src/dest ip, src/dest port, ipset, family | Same + `src_iface` (ingress interface) |
| Named set matching | iptables ipset (broken in OpenWrt 23.05+) | Native nftables named sets |
| Per-rule logging | Yes | Yes (with global toggle) |
| ICMP dual-stack | Single rule | Auto-splits into icmp + icmpv6 |
| MSS clamping | Separate firewall package | Built-in per-interface `clamp_mss` option |

### Networking

| Feature | mwan3 | nopal |
|---|---|---|
| Mark mask | `mmx_mask` (default 0x3F00, 60 interfaces) | `mark_mask` (default 0xFF00, 254 interfaces) |
| Mark assignment | Sequential | FNV-1a hash (stable across config reorder) |
| Connected bypass | ipset scan | nftables anonymous sets + user-editable `bypass_v4`/`bypass_v6` sets |
| DNS management | None | Writes `/tmp/resolv.conf.auto`, HUPs dnsmasq |
| Local source routing | Global option | Per-interface `from <wan_ip>` rules |
| Route table lookup | `rt_table_lookup` list | Same |
| Conntrack flush modes | none / full | none / selective (by mark) / full |
| Conntrack flush triggers | ifup / ifdown / connected / disconnected | Same |

### State Machine

```
Init ──link_up──> Probing ──up_count successes──> Online
                    │                                │
                    │ down_count failures             │ quality degraded
                    v                                v
                 Offline <──down_count failures── Degraded
                    ^                                │
                    │           quality recovered     │
                    └──────────── Online <────────────┘
```

Five states: `Init`, `Probing`, `Online`, `Degraded`, `Offline`.
mwan3 uses four (online/offline/connecting/disconnecting).

### Daemon

| Feature | mwan3 | nopal |
|---|---|---|
| IPC protocol | None (reads status files) | Unix socket, MessagePack-RPC |
| Event subscription | None | Clients receive state change events |
| Hot reload | Full restart | SIGHUP or `nopal reload`, preserves state |
| Hook script | `/etc/mwan3.user` | `/etc/nopal.user` (same env vars + `FIRSTCONNECT`) |
| Status files | Per-target files in `/var/run/mwan3track/` | `/var/run/nopal/<iface>/status` with key=value data |
| rpcd/ubus | Via luci-app-mwan3 | rpcd exec plugin |

## Configuration

nopal reads UCI config from `/etc/config/nopal`. The format is intentionally
close to mwan3 with renamed options for clarity.

### Migration from mwan3

Renamed options (mwan3 -> nopal):

| mwan3 | nopal |
|---|---|
| `interval` | `probe_interval` |
| `timeout` | `probe_timeout` |
| `up` | `up_count` |
| `down` | `down_count` |
| `size` | `probe_size` |
| `failure_latency` | `latency_threshold` |
| `failure_loss` | `loss_threshold` |

Other differences:

- `httping_ssl '1'` is replaced by `track_method 'https'`
- `initial_state` defaults to `offline` (mwan3 defaults to `online`)
- `nping-*` methods are not supported; nopal warns and suggests native
  alternatives (ping, dns, http, https, arping)
- `mark_mask` defaults to `0xFF00` (mwan3 `mmx_mask` defaults to `0x3F00`)

nopal logs warnings when it encounters mwan3 option names in the config.

### Example Config

```
config globals 'globals'
    option enabled '1'
    option log_level 'info'
    option conntrack_flush 'selective'
    option ipv6_enabled '1'

config interface 'wan'
    option enabled '1'
    option device 'eth0.2'
    option family 'both'
    option metric '10'
    option weight '50'
    option track_method 'ping'
    list   track_ip '8.8.8.8'
    list   track_ip '1.1.1.1'
    option reliability '2'
    option probe_interval '5'
    option probe_timeout '2'
    option up_count '3'
    option down_count '5'
    option clamp_mss '1'

config interface 'wanb'
    option enabled '1'
    option device 'eth0.3'
    option family 'both'
    option metric '20'
    option weight '50'
    option track_method 'ping'
    list   track_ip '8.8.4.4'
    list   track_ip '1.0.0.1'
    option reliability '2'
    option probe_interval '5'
    option probe_timeout '2'
    option up_count '3'
    option down_count '5'

config member 'wan_m1_w50'
    option interface 'wan'
    option metric '1'
    option weight '50'

config member 'wanb_m1_w50'
    option interface 'wanb'
    option metric '1'
    option weight '50'

config policy 'balanced'
    list use_member 'wan_m1_w50'
    list use_member 'wanb_m1_w50'
    option last_resort 'default'

config rule 'default_rule'
    option proto 'all'
    option family 'any'
    option sticky '1'
    option sticky_timeout '600'
    option sticky_mode 'flow'
    option use_policy 'balanced'
```

## CLI Usage

```
nopal status              # full daemon status
nopal status wan          # single interface detail
nopal status --json       # machine-readable output
nopal interfaces          # interface summary table
nopal policies            # policy summary table
nopal connected           # bypass CIDRs
nopal rules               # dump nftables policy_rules chain
nopal internal            # full diagnostic dump
nopal use wan curl -s ... # run command via specific WAN
nopal reload              # hot reload config
nopal version             # print version
```

## Building

Requires Rust 1.85+.

```sh
# Standard build
cargo build --release

# With HTTPS probe support
cargo build --release --features https

# Cross-compile for OpenWrt (example: aarch64)
cargo build --release --target aarch64-unknown-linux-musl
```

The release profile is optimized for size (`opt-level = "z"`, LTO, strip).

## Project Structure

```
src/
  main.rs          CLI entry point and daemon mode detection
  daemon.rs        Event loop, state management, action execution
  config/
    mod.rs         UCI config parser
    schema.rs      Config type definitions and defaults
    diff.rs        Config diff for hot reload
  health/
    mod.rs         Probe orchestration, ProbeTransport trait
    icmp.rs        ICMP echo probe
    dns.rs         UDP DNS probe
    http.rs        HTTP probe
    https.rs       HTTPS probe (feature-gated)
    arp.rs         ARP probe
    dampening.rs   RFC 2439 route dampening
  nftables/
    chains.rs      Ruleset generation (chains, rules, maps)
    ruleset.rs     nftables JSON builder
    mod.rs         nft process invocation
  netlink/
    link.rs        Link up/down monitoring
    route_manager.rs  Route and ip rule management
    route_monitor.rs  Route/address change events
    conntrack.rs   Conntrack flush via NETLINK_NETFILTER
  ipc/
    protocol.rs    MessagePack-RPC wire types
    methods.rs     IPC method dispatch
    mod.rs         Unix socket server
  state/
    mod.rs         Interface state machine
    policy.rs      Policy resolution
    transition.rs  State transition -> action mapping
  dns.rs           DNS server file management
  timer.rs         Timer wheel for probe scheduling
  logging.rs       Log initialization
  error.rs         Error types
openwrt/
  files/
    nopal.config   Sample UCI config with migration notes
    nopal.init     procd init script
    rpcd-nopal     rpcd exec plugin for ubus
```

## License

Apache-2.0
