use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ConntrackFlushMode {
    None,
    Selective,
    Full,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum AddressFamily {
    Ipv4,
    Ipv6,
    Both,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum TrackMethod {
    Ping,
    Dns,
    Http,
    Https,
    Arping,
    Composite,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum StickyMode {
    Flow,
    SrcIp,
    SrcDst,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ConntrackFlushTrigger {
    /// Flush when interface link comes up (-> Probing).
    IfUp,
    /// Flush when interface link goes down (-> Offline via link event).
    IfDown,
    /// Flush when interface is confirmed online (-> Online).
    Connected,
    /// Flush when interface goes offline due to probe failures (-> Offline).
    Disconnected,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum LastResort {
    Default,
    Unreachable,
    Blackhole,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum RuleFamily {
    Any,
    Ipv4,
    Ipv6,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct GlobalsConfig {
    pub enabled: bool,
    pub log_level: String,
    pub conntrack_flush: ConntrackFlushMode,
    pub ipv6_enabled: bool,
    pub ipc_socket: String,
    /// Script executed on interface state changes (like mwan3.user).
    /// Set to empty string to disable.
    pub hook_script: String,
    /// Additional routing table IDs to scan for connected networks.
    /// Routes in these tables are added to the nftables bypass set so
    /// traffic to those destinations is not policy-routed.
    pub rt_table_lookup: Vec<u32>,
    /// Global toggle for per-rule logging. When false, per-rule `log`
    /// options are ignored. Allows quick enable/disable of all rule
    /// logging without editing each rule.
    pub logging: bool,
    /// Bitmask controlling which firewall mark bits nopal uses for interface
    /// tagging. Must be a contiguous block of bits (e.g. 0xFF00, 0x3F00).
    /// The number of usable interface slots = (mask / lowest_set_bit) - 1.
    /// Default 0xFF00 supports 254 interfaces.
    pub mark_mask: u32,
}

impl Default for GlobalsConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            log_level: "info".to_string(),
            conntrack_flush: ConntrackFlushMode::Selective,
            ipv6_enabled: false,
            ipc_socket: "/var/run/nopal.sock".to_string(),
            hook_script: "/etc/nopal.user".to_string(),
            rt_table_lookup: Vec::new(),
            logging: false,
            mark_mask: 0xFF00,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum InitialState {
    /// Wait for probes to confirm interface is online (default, safe).
    /// Note: mwan3 defaults to Online; nopal defaults to Offline to avoid
    /// routing traffic through unverified links at startup.
    Offline,
    /// Assume interface is online at startup, begin routing immediately.
    /// Matches mwan3's default behaviour.
    Online,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct InterfaceConfig {
    pub name: String,
    pub enabled: bool,
    pub device: String,
    pub family: AddressFamily,
    pub metric: u32,
    pub weight: u32,
    pub track_method: TrackMethod,
    pub track_ip: Vec<String>,
    /// Override the default port for HTTP (80) / HTTPS (443) probes.
    /// Ignored for non-HTTP probe methods.
    pub track_port: Option<u16>,
    pub reliability: u32,
    pub probe_interval: u32,
    /// Probe interval when the interface is offline. Allows slower polling
    /// of known-down links. Falls back to `probe_interval` if not set.
    pub failure_interval: Option<u32>,
    /// Probe interval when the interface is degraded or recovering. Allows
    /// faster polling to detect recovery sooner. Falls back to
    /// `probe_interval` if not set.
    pub recovery_interval: Option<u32>,
    /// When true, the Probing state (recovering from Offline) uses
    /// `failure_interval` instead of `probe_interval`. This keeps the
    /// slower polling rate until the interface is confirmed online.
    pub keep_failure_interval: bool,
    pub probe_timeout: u32,
    /// Number of packets to send per target per probe cycle.
    pub count: u32,
    /// IP TTL (hop limit) for probe packets.
    pub max_ttl: u32,
    /// ICMP payload size in bytes (standard ping = 56).
    pub probe_size: u32,
    pub up_count: u32,
    pub down_count: u32,
    pub initial_state: InitialState,
    /// Enable quality threshold evaluation. When false, latency and loss
    /// thresholds are ignored even if configured, matching mwan3's
    /// `check_quality` toggle.
    pub check_quality: bool,
    /// RTT threshold in milliseconds. If average RTT over the quality window
    /// exceeds this value, the interface is considered degraded. None disables.
    pub latency_threshold: Option<u32>,
    /// Packet loss threshold as a percentage (0-100). If loss rate over the
    /// quality window exceeds this value, the interface is considered degraded.
    /// None disables.
    pub loss_threshold: Option<u32>,
    /// RTT threshold for recovery from degraded state. If set, average RTT
    /// must drop below this value to recover. Provides hysteresis so the link
    /// must be significantly better to recover than it was when it degraded.
    /// None falls back to `latency_threshold`.
    pub recovery_latency: Option<u32>,
    /// Loss threshold for recovery from degraded state. If set, loss rate
    /// must drop below this value to recover. None falls back to
    /// `loss_threshold`.
    pub recovery_loss: Option<u32>,
    /// Number of recent probes to track for quality evaluation.
    pub quality_window: u32,
    pub dampening: bool,
    pub dampening_halflife: u32,
    pub dampening_ceiling: u32,
    pub dampening_suppress: u32,
    pub dampening_reuse: u32,
    /// Enable source-address-based ip rules for router-originated traffic.
    /// When true, adds `ip rule from <wan_ip> lookup <table>` so traffic
    /// originating from the router with this interface's IP exits through
    /// the correct WAN link.
    pub local_source: bool,
    /// Probe methods used when `track_method` is `composite`. Each target
    /// is probed by all listed methods; a target counts as reachable if any
    /// method succeeds (OR logic). Defaults to `[Ping, Dns]` when empty.
    /// Domain name to resolve when track_method is `dns`. Empty string uses
    /// a minimal root "." query (default). Set to a domain like `example.com`
    /// to verify end-to-end DNS resolution.
    pub dns_query_name: String,
    pub composite_methods: Vec<TrackMethod>,
    pub update_dns: bool,
    pub dns_servers: Vec<String>,
    pub clamp_mss: bool,
    /// Events that trigger a conntrack flush for this interface.
    /// Defaults to `[Disconnected]` matching legacy behavior.
    pub flush_conntrack: Vec<ConntrackFlushTrigger>,
}

impl Default for InterfaceConfig {
    fn default() -> Self {
        Self {
            name: String::new(),
            enabled: true,
            device: String::new(),
            family: AddressFamily::Ipv4,
            metric: 0,
            weight: 1,
            track_method: TrackMethod::Ping,
            track_ip: Vec::new(),
            track_port: None,
            reliability: 1,
            probe_interval: 5,
            failure_interval: None,
            recovery_interval: None,
            keep_failure_interval: false,
            probe_timeout: 2,
            count: 1,
            max_ttl: 128,
            probe_size: 56,
            up_count: 3,
            down_count: 3,
            initial_state: InitialState::Offline,
            check_quality: true,
            latency_threshold: None,
            loss_threshold: None,
            recovery_latency: None,
            recovery_loss: None,
            quality_window: 10,
            dampening: false,
            dampening_halflife: 300,
            dampening_ceiling: 1000,
            dampening_suppress: 500,
            dampening_reuse: 250,
            dns_query_name: String::new(),
            composite_methods: Vec::new(),
            local_source: false,
            update_dns: false,
            dns_servers: Vec::new(),
            clamp_mss: true,
            flush_conntrack: vec![ConntrackFlushTrigger::Disconnected],
        }
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct MemberConfig {
    pub name: String,
    pub interface: String,
    pub metric: u32,
    pub weight: u32,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct PolicyConfig {
    pub name: String,
    pub members: Vec<String>,
    pub last_resort: LastResort,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct RuleConfig {
    pub name: String,
    pub src_ip: Vec<String>,
    pub src_port: Option<String>,
    pub dest_ip: Vec<String>,
    pub dest_port: Option<String>,
    pub proto: String,
    pub family: RuleFamily,
    /// Match traffic arriving on this network interface (e.g. "br-lan").
    pub src_iface: Option<String>,
    /// Match destination against a user-defined nftables named set.
    /// The set must exist in the `inet nopal` table (created externally).
    pub ipset: Option<String>,
    pub sticky: bool,
    pub sticky_timeout: u32,
    pub sticky_mode: StickyMode,
    pub use_policy: String,
    /// Log matching packets via nftables log statement.
    pub log: bool,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct NopalConfig {
    pub globals: GlobalsConfig,
    pub interfaces: Vec<InterfaceConfig>,
    pub members: Vec<MemberConfig>,
    pub policies: Vec<PolicyConfig>,
    pub rules: Vec<RuleConfig>,
}
