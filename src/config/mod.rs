pub mod diff;
pub mod schema;

pub use schema::*;

use crate::error::{Error, Result};
use std::collections::{HashMap, HashSet};
use std::fs;

/// Validate that a UCI section name is safe for use in file paths,
/// nftables chain names, and shell environment variables.
fn validate_name(kind: &str, name: &str) -> Result<()> {
    if name.is_empty() {
        return Err(Error::Config(format!("{kind} has empty name")));
    }
    if name.contains('/') || name.contains('\0') || name.contains("..") {
        return Err(Error::Config(format!(
            "{kind} '{name}': name contains unsafe characters"
        )));
    }
    if !name.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-' || b == b'.') {
        return Err(Error::Config(format!(
            "{kind} '{name}': name must contain only [a-zA-Z0-9_.-]"
        )));
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// UCI parser
// ---------------------------------------------------------------------------

/// A parsed UCI section: its type, optional name, and key-value data.
/// Keys that appear via `list` directives accumulate multiple values;
/// keys that appear via `option` have exactly one.
#[derive(Debug)]
struct UciSection {
    section_type: String,
    name: Option<String>,
    options: HashMap<String, Vec<String>>,
}

impl UciSection {
    fn new(section_type: String, name: Option<String>) -> Self {
        Self {
            section_type,
            name,
            options: HashMap::new(),
        }
    }

    /// Return the first value for a key, or `None` if absent.
    fn get(&self, key: &str) -> Option<&str> {
        self.options.get(key).and_then(|v| v.first()).map(|s| s.as_str())
    }

    /// Return all values for a key (for `list` directives).
    fn get_all(&self, key: &str) -> Vec<&str> {
        self.options
            .get(key)
            .map(|v| v.iter().map(|s| s.as_str()).collect())
            .unwrap_or_default()
    }

    /// Convenience: get a value as a `u32`, falling back to `default`.
    fn get_u32(&self, key: &str, default: u32) -> u32 {
        self.get(key)
            .and_then(|v| v.parse().ok())
            .unwrap_or(default)
    }

    /// Convenience: get a value interpreted as a boolean.
    /// UCI uses "1"/"0" and occasionally "yes"/"no" or "true"/"false".
    fn get_bool(&self, key: &str, default: bool) -> bool {
        match self.get(key) {
            Some("1") | Some("yes") | Some("true") | Some("on") => true,
            Some("0") | Some("no") | Some("false") | Some("off") => false,
            _ => default,
        }
    }
}

/// Strip matching single or double quotes from the start and end of `s`.
fn strip_quotes(s: &str) -> &str {
    let s = s.trim();
    if s.len() >= 2 {
        let bytes = s.as_bytes();
        if (bytes[0] == b'\'' && bytes[bytes.len() - 1] == b'\'')
            || (bytes[0] == b'"' && bytes[bytes.len() - 1] == b'"')
        {
            return &s[1..s.len() - 1];
        }
    }
    s
}

/// Parse a UCI config file into a list of sections.
fn parse_uci(text: &str) -> Result<Vec<UciSection>> {
    let mut sections: Vec<UciSection> = Vec::new();

    for (line_no, raw_line) in text.lines().enumerate() {
        let line = raw_line.trim();

        // Skip blanks and comments.
        if line.is_empty() || line.starts_with('#') {
            continue;
        }

        if line.starts_with("config ") {
            // `config <type> ['<name>']`
            let rest = &line["config ".len()..];
            let mut parts = rest.splitn(2, char::is_whitespace);
            let section_type = parts
                .next()
                .ok_or_else(|| {
                    Error::Config(format!("line {}: missing section type", line_no + 1))
                })?
                .to_string();
            let name = parts.next().map(|s| strip_quotes(s).to_string());
            sections.push(UciSection::new(section_type, name));
        } else if line.starts_with("option ") || line.starts_with("list ") {
            let is_list = line.starts_with("list ");
            let prefix_len = if is_list { "list ".len() } else { "option ".len() };
            let rest = &line[prefix_len..];

            let mut parts = rest.splitn(2, char::is_whitespace);
            let key = parts
                .next()
                .ok_or_else(|| {
                    Error::Config(format!("line {}: missing key", line_no + 1))
                })?
                .to_string();
            let value = parts
                .next()
                .map(|s| strip_quotes(s).to_string())
                .unwrap_or_default();

            let section = sections.last_mut().ok_or_else(|| {
                Error::Config(format!(
                    "line {}: option/list outside of a config section",
                    line_no + 1
                ))
            })?;

            if is_list {
                section.options.entry(key).or_default().push(value);
            } else {
                // `option` replaces any prior value for the same key.
                section.options.insert(key, vec![value]);
            }
        } else {
            // Unknown directive -- warn but do not fail so we stay forward
            // compatible with UCI extensions.
            log::warn!("ignoring unrecognized UCI line {}: {}", line_no + 1, line);
        }
    }

    Ok(sections)
}

// ---------------------------------------------------------------------------
// Section -> typed config converters
// ---------------------------------------------------------------------------

fn parse_globals(sec: &UciSection) -> GlobalsConfig {
    let defaults = GlobalsConfig::default();
    GlobalsConfig {
        enabled: sec.get_bool("enabled", defaults.enabled),
        log_level: sec.get("log_level").unwrap_or(&defaults.log_level).to_string(),
        conntrack_flush: match sec.get("conntrack_flush") {
            Some("none") | Some("0") => ConntrackFlushMode::None,
            Some("selective") => ConntrackFlushMode::Selective,
            Some("full") => ConntrackFlushMode::Full,
            _ => defaults.conntrack_flush,
        },
        ipv6_enabled: sec.get_bool("ipv6_enabled", defaults.ipv6_enabled),
        ipc_socket: sec.get("ipc_socket").unwrap_or(&defaults.ipc_socket).to_string(),
        hook_script: sec.get("hook_script").unwrap_or(&defaults.hook_script).to_string(),
        rt_table_lookup: sec.get_all("rt_table_lookup").iter()
            .filter_map(|v| v.parse::<u32>().ok())
            .collect(),
        logging: sec.get_bool("logging", defaults.logging),
        mark_mask: {
            let raw = sec.get("mark_mask").and_then(|v| {
                if let Some(hex) = v.strip_prefix("0x") {
                    u32::from_str_radix(hex, 16).ok()
                } else {
                    v.parse::<u32>().ok()
                }
            });
            match raw {
                Some(m) if m != 0
                    && (m & (m + (m & m.wrapping_neg()))) == 0
                    && m / (m & m.wrapping_neg()) >= 2 => m,
                Some(m) => {
                    log::warn!(
                        "mark_mask 0x{:X} is not a valid contiguous bit range (need >=2 slots); \
                         using default 0x{:X}",
                        m, defaults.mark_mask,
                    );
                    defaults.mark_mask
                }
                None => defaults.mark_mask,
            }
        },
    }
}

fn parse_interface(sec: &UciSection) -> Result<InterfaceConfig> {
    let name = sec
        .name
        .clone()
        .ok_or_else(|| Error::Config("interface section missing name".into()))?;
    validate_name("interface", &name)?;
    let defaults = InterfaceConfig::default();

    let track_method = match sec.get("track_method") {
        Some("dns") => TrackMethod::Dns,
        Some("http") => TrackMethod::Http,
        Some("https") => TrackMethod::Https,
        Some("arping") => TrackMethod::Arping,
        Some("composite") => TrackMethod::Composite,
        Some("ping") | None => TrackMethod::Ping,
        Some(other) => {
            let suggestion = match other {
                "nping-tcp" => Some("try track_method 'http' or 'https' instead"),
                "nping-udp" => Some("try track_method 'dns' instead"),
                "nping-icmp" => Some("try track_method 'ping' instead"),
                "nping-arp" => Some("try track_method 'arping' instead"),
                _ => None,
            };
            if let Some(hint) = suggestion {
                log::warn!(
                    "interface '{}': track_method '{}' requires nmap and is not supported; {}",
                    name, other, hint,
                );
            } else {
                log::warn!(
                    "interface '{}': unsupported track_method '{}', falling back to ping",
                    name, other,
                );
            }
            TrackMethod::Ping
        }
    };

    // Warn about mwan3 option names that have been renamed in nopal
    let mwan3_renames = [
        ("interval", "probe_interval"),
        ("timeout", "probe_timeout"),
        ("up", "up_count"),
        ("down", "down_count"),
        ("size", "probe_size"),
        ("failure_latency", "latency_threshold"),
        ("failure_loss", "loss_threshold"),
    ];
    for (old, new) in &mwan3_renames {
        if sec.get(old).is_some() {
            log::warn!(
                "interface '{}': option '{}' is a mwan3 name; use '{}' instead",
                name, old, new,
            );
        }
    }
    if sec.get("httping_ssl").is_some() {
        log::warn!(
            "interface '{}': option 'httping_ssl' is not needed; use track_method 'https' instead",
            name,
        );
    }

    let device = sec.get("device").unwrap_or("").to_string();
    if !device.is_empty() {
        validate_name("device", &device)?;
    }

    // Validate dns_server entries are valid IP addresses
    let dns_servers: Vec<String> = sec.get_all("dns_server").iter().filter_map(|s| {
        if s.parse::<std::net::IpAddr>().is_ok() {
            Some(s.to_string())
        } else {
            log::warn!("interface '{}': invalid dns_server '{}', skipping", name, s);
            None
        }
    }).collect();

    // Validate dns_query_name before moving name into the struct
    let dns_query_name = sec.get("dns_query_name").unwrap_or(&defaults.dns_query_name);
    if dns_query_name.len() > 253 {
        return Err(Error::Config(format!(
            "interface '{name}': dns_query_name exceeds 253 characters"
        )));
    }
    for label in dns_query_name.trim_end_matches('.').split('.') {
        if label.len() > 63 {
            return Err(Error::Config(format!(
                "interface '{name}': dns_query_name label exceeds 63 characters"
            )));
        }
    }

    let track_ip: Vec<String> = sec.get_all("track_ip").iter().filter_map(|s| {
        if s.parse::<std::net::IpAddr>().is_ok() {
            Some(s.to_string())
        } else {
            log::warn!("interface '{}': invalid track_ip '{}', ignoring", name, s);
            None
        }
    }).collect();

    Ok(InterfaceConfig {
        name,
        enabled: sec.get_bool("enabled", defaults.enabled),
        device,
        family: match sec.get("family") {
            Some("ipv6") | Some("IPv6") => AddressFamily::Ipv6,
            Some("both") => AddressFamily::Both,
            _ => AddressFamily::Ipv4,
        },
        metric: sec.get_u32("metric", defaults.metric),
        weight: sec.get_u32("weight", defaults.weight).clamp(1, 1000),
        track_method,
        track_ip,
        track_port: sec.get("track_port").and_then(|v| v.parse().ok()),
        reliability: sec.get_u32("reliability", defaults.reliability),
        probe_interval: sec.get_u32("probe_interval", defaults.probe_interval),
        failure_interval: sec.get("failure_interval").and_then(|v| v.parse().ok()),
        recovery_interval: sec.get("recovery_interval").and_then(|v| v.parse().ok()),
        keep_failure_interval: sec.get_bool("keep_failure_interval", defaults.keep_failure_interval),
        probe_timeout: sec.get_u32("probe_timeout", defaults.probe_timeout),
        count: sec.get_u32("count", defaults.count).max(1),
        max_ttl: sec.get_u32("max_ttl", defaults.max_ttl).clamp(1, 255),
        probe_size: sec.get_u32("probe_size", defaults.probe_size).clamp(0, 1400),
        up_count: sec.get_u32("up_count", defaults.up_count).max(1),
        down_count: sec.get_u32("down_count", defaults.down_count).max(1),
        initial_state: match sec.get("initial_state") {
            Some("online") => InitialState::Online,
            _ => InitialState::Offline,
        },
        check_quality: sec.get_bool("check_quality", defaults.check_quality),
        latency_threshold: sec.get("latency_threshold").and_then(|v| v.parse().ok()),
        loss_threshold: sec.get("loss_threshold").and_then(|v| v.parse().ok()),
        recovery_latency: sec.get("recovery_latency").and_then(|v| v.parse().ok()),
        recovery_loss: sec.get("recovery_loss").and_then(|v| v.parse().ok()),
        quality_window: sec.get_u32("quality_window", defaults.quality_window),
        dampening: sec.get_bool("dampening", defaults.dampening),
        dampening_halflife: sec.get_u32("dampening_halflife", defaults.dampening_halflife),
        dampening_ceiling: sec.get_u32("dampening_ceiling", defaults.dampening_ceiling),
        dampening_suppress: sec.get_u32("dampening_suppress", defaults.dampening_suppress),
        dampening_reuse: sec.get_u32("dampening_reuse", defaults.dampening_reuse),
        dns_query_name: dns_query_name.to_string(),
        composite_methods: {
            let vals = sec.get_all("composite_method");
            vals.iter().filter_map(|v| match *v {
                "ping" => Some(TrackMethod::Ping),
                "dns" => Some(TrackMethod::Dns),
                "http" => Some(TrackMethod::Http),
                "https" => Some(TrackMethod::Https),
                "arping" => Some(TrackMethod::Arping),
                other => {
                    log::warn!("unknown composite_method: {other}");
                    None
                }
            }).collect()
        },
        local_source: sec.get_bool("local_source", defaults.local_source),
        update_dns: sec.get_bool("update_dns", defaults.update_dns),
        dns_servers,
        clamp_mss: sec.get_bool("clamp_mss", defaults.clamp_mss),
        flush_conntrack: {
            let vals = sec.get_all("flush_conntrack");
            if vals.is_empty() {
                defaults.flush_conntrack.clone()
            } else {
                vals.iter()
                    .filter_map(|v| match *v {
                        "ifup" => Some(ConntrackFlushTrigger::IfUp),
                        "ifdown" => Some(ConntrackFlushTrigger::IfDown),
                        "connected" => Some(ConntrackFlushTrigger::Connected),
                        "disconnected" => Some(ConntrackFlushTrigger::Disconnected),
                        other => {
                            log::warn!("unknown flush_conntrack trigger: {other}");
                            None
                        }
                    })
                    .collect()
            }
        },
    })
}

fn parse_member(sec: &UciSection) -> Result<MemberConfig> {
    let name = sec
        .name
        .clone()
        .ok_or_else(|| Error::Config("member section missing name".into()))?;
    validate_name("member", &name)?;

    let interface = sec
        .get("interface")
        .ok_or_else(|| Error::Config(format!("member '{name}' missing 'interface'")))?
        .to_string();

    Ok(MemberConfig {
        name,
        interface,
        metric: sec.get_u32("metric", 0),
        weight: sec.get_u32("weight", 1).clamp(1, 1000),
    })
}

fn parse_policy(sec: &UciSection) -> Result<PolicyConfig> {
    let name = sec
        .name
        .clone()
        .ok_or_else(|| Error::Config("policy section missing name".into()))?;
    validate_name("policy", &name)?;

    let members: Vec<String> = sec
        .get_all("use_member")
        .iter()
        .map(|s| s.to_string())
        .collect();

    let last_resort = match sec.get("last_resort") {
        Some("unreachable") => LastResort::Unreachable,
        Some("blackhole") => LastResort::Blackhole,
        _ => LastResort::Default,
    };

    Ok(PolicyConfig {
        name,
        members,
        last_resort,
    })
}

fn parse_rule(sec: &UciSection) -> Result<RuleConfig> {
    let name = sec
        .name
        .clone()
        .ok_or_else(|| Error::Config("rule section missing name".into()))?;
    validate_name("rule", &name)?;

    let use_policy = sec
        .get("use_policy")
        .ok_or_else(|| Error::Config(format!("rule '{name}' missing 'use_policy'")))?
        .to_string();

    // Validate port specs: single port (u16) or range "lo-hi" where lo <= hi
    let src_port = sec.get("src_port").map(|s| s.to_string());
    let dest_port = sec.get("dest_port").map(|s| s.to_string());
    for (label, port) in [("src_port", &src_port), ("dest_port", &dest_port)] {
        if let Some(p) = port {
            let valid = if let Some((lo, hi)) = p.split_once('-') {
                lo.parse::<u16>().is_ok()
                    && hi.parse::<u16>().is_ok()
                    && lo.parse::<u16>().unwrap() <= hi.parse::<u16>().unwrap()
            } else {
                p.parse::<u16>().is_ok()
            };
            if !valid {
                return Err(Error::Config(format!(
                    "rule '{name}': {label} '{p}' must be a port (1-65535) or range (e.g. '1024-65535')"
                )));
            }
        }
    }

    // Validate ipset and src_iface names
    if let Some(ref ipset) = sec.get("ipset") {
        validate_name(&format!("rule '{name}' ipset"), ipset)?;
    }
    if let Some(ref iface) = sec.get("src_iface") {
        validate_name(&format!("rule '{name}' src_iface"), iface)?;
    }

    // Validate proto
    let proto = sec.get("proto").unwrap_or("all");
    match proto {
        "all" | "tcp" | "udp" | "icmp" | "icmpv6" | "sctp" | "gre" | "esp" | "ah" => {}
        _ => {
            return Err(Error::Config(format!(
                "rule '{name}': unsupported proto '{proto}'"
            )));
        }
    }

    // Validate src_ip and dest_ip entries
    let src_ip: Vec<String> = sec.get_all("src_ip").iter().map(|s| s.to_string()).collect();
    let dest_ip: Vec<String> = sec.get_all("dest_ip").iter().map(|s| s.to_string()).collect();
    for (label, addrs) in [("src_ip", &src_ip), ("dest_ip", &dest_ip)] {
        for addr in addrs.iter() {
            if addr.starts_with('@') {
                // Named set reference -- validated by nftables
                continue;
            }
            let base = addr.split('/').next().unwrap_or(addr);
            if base.parse::<std::net::IpAddr>().is_err() {
                return Err(Error::Config(format!(
                    "rule '{name}': invalid {label} '{addr}'"
                )));
            }
            if let Some(prefix_str) = addr.split('/').nth(1) {
                let prefix = prefix_str.parse::<u8>().map_err(|_| {
                    Error::Config(format!(
                        "rule '{name}': invalid {label} prefix in '{addr}'"
                    ))
                })?;
                let max_prefix: u8 = if base.contains(':') { 128 } else { 32 };
                if prefix > max_prefix {
                    return Err(Error::Config(format!(
                        "rule '{name}': {label} prefix /{prefix} exceeds /{max_prefix} for '{addr}'"
                    )));
                }
            }
        }
    }

    Ok(RuleConfig {
        name,
        src_ip,
        src_port,
        dest_ip,
        dest_port,
        proto: proto.to_string(),
        family: match sec.get("family") {
            Some("ipv4") | Some("IPv4") => RuleFamily::Ipv4,
            Some("ipv6") | Some("IPv6") => RuleFamily::Ipv6,
            _ => RuleFamily::Any,
        },
        src_iface: sec.get("src_iface").map(|s| s.to_string()),
        ipset: sec.get("ipset").map(|s| s.to_string()),
        sticky: sec.get_bool("sticky", false),
        sticky_timeout: sec.get_u32("sticky_timeout", 600),
        sticky_mode: match sec.get("sticky_mode") {
            Some("src_ip") => StickyMode::SrcIp,
            Some("src_dst") => StickyMode::SrcDst,
            _ => StickyMode::Flow,
        },
        use_policy,
        log: sec.get_bool("log", false),
    })
}

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/// Load and parse the nopal UCI configuration from the given path.
pub fn load(path: &str) -> Result<NopalConfig> {
    let text = fs::read_to_string(path).map_err(|e| {
        Error::Config(format!("failed to read config file '{path}': {e}"))
    })?;

    load_from_str(&text)
}

/// Parse a nopal UCI configuration from a string. Useful for testing
/// without touching the filesystem.
pub fn load_from_str(text: &str) -> Result<NopalConfig> {
    let sections = parse_uci(text)?;

    let mut globals = GlobalsConfig::default();
    let mut interfaces = Vec::new();
    let mut members = Vec::new();
    let mut policies = Vec::new();
    let mut rules = Vec::new();

    for sec in &sections {
        match sec.section_type.as_str() {
            "globals" => globals = parse_globals(sec),
            "interface" => interfaces.push(parse_interface(sec)?),
            "member" => members.push(parse_member(sec)?),
            "policy" => policies.push(parse_policy(sec)?),
            "rule" => rules.push(parse_rule(sec)?),
            other => {
                log::debug!("skipping unknown UCI section type '{other}'");
            }
        }
    }

    let config = NopalConfig {
        globals,
        interfaces,
        members,
        policies,
        rules,
    };

    validate(&config)?;

    Ok(config)
}

/// Validate cross-section references in the config.
///
/// Checks that members reference existing interfaces, policies reference
/// existing members, rules reference existing policies, and there are no
/// duplicate names within a section type. Returns an error for anything
/// that would cause a runtime failure. Logs warnings for non-fatal issues.
fn validate(config: &NopalConfig) -> Result<()> {
    // Check for duplicate interface names
    let mut seen = HashSet::new();
    for iface in &config.interfaces {
        if !seen.insert(&iface.name) {
            return Err(Error::Config(format!(
                "duplicate interface name '{}'",
                iface.name
            )));
        }
    }

    // Check for duplicate member names
    seen.clear();
    for member in &config.members {
        if !seen.insert(&member.name) {
            return Err(Error::Config(format!(
                "duplicate member name '{}'",
                member.name
            )));
        }
    }

    // Check for duplicate policy names
    seen.clear();
    for policy in &config.policies {
        if !seen.insert(&policy.name) {
            return Err(Error::Config(format!(
                "duplicate policy name '{}'",
                policy.name
            )));
        }
    }

    // Check for duplicate rule names
    seen.clear();
    for rule in &config.rules {
        if !seen.insert(&rule.name) {
            return Err(Error::Config(format!(
                "duplicate rule name '{}'",
                rule.name
            )));
        }
    }

    // Build lookup sets for cross-reference validation
    let interface_names: HashSet<&str> = config
        .interfaces
        .iter()
        .map(|i| i.name.as_str())
        .collect();
    let member_names: HashSet<&str> = config
        .members
        .iter()
        .map(|m| m.name.as_str())
        .collect();
    let policy_names: HashSet<&str> = config
        .policies
        .iter()
        .map(|p| p.name.as_str())
        .collect();

    // Members must reference existing interfaces
    for member in &config.members {
        if !interface_names.contains(member.interface.as_str()) {
            return Err(Error::Config(format!(
                "member '{}' references nonexistent interface '{}'",
                member.name, member.interface
            )));
        }
    }

    // Policies must reference existing members
    for policy in &config.policies {
        for member_name in &policy.members {
            if !member_names.contains(member_name.as_str()) {
                return Err(Error::Config(format!(
                    "policy '{}' references nonexistent member '{}'",
                    policy.name, member_name
                )));
            }
        }
    }

    // Rules must reference existing policies (or "default" which is implicit)
    for rule in &config.rules {
        if rule.use_policy != "default" && !policy_names.contains(rule.use_policy.as_str()) {
            return Err(Error::Config(format!(
                "rule '{}' references nonexistent policy '{}'",
                rule.name, rule.use_policy
            )));
        }
    }

    // Warnings for non-fatal issues

    // Enabled interfaces with no track_ip targets
    for iface in &config.interfaces {
        if iface.enabled && iface.track_ip.is_empty() {
            log::warn!(
                "interface '{}' has no track_ip targets; probing will not work",
                iface.name
            );
        }
    }

    // Members not referenced by any policy
    let referenced_members: HashSet<&str> = config
        .policies
        .iter()
        .flat_map(|p| p.members.iter().map(|m| m.as_str()))
        .collect();
    for member in &config.members {
        if !referenced_members.contains(member.name.as_str()) {
            log::warn!(
                "member '{}' is not referenced by any policy",
                member.name
            );
        }
    }

    Ok(())
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    const SAMPLE_CONFIG: &str = r#"
# /etc/config/nopal - sample configuration

config globals 'globals'
    option enabled '1'
    option log_level 'debug'
    option conntrack_flush 'selective'
    option ipv6_enabled '0'

config interface 'wan'
    option enabled '1'
    option device 'eth0'
    option family 'ipv4'
    option metric '10'
    option weight '3'
    option track_method 'ping'
    list track_ip '1.1.1.1'
    list track_ip '8.8.8.8'
    option reliability '2'
    option probe_interval '5'
    option probe_timeout '2'
    option up_count '3'
    option down_count '3'
    option clamp_mss '1'

config interface 'wanb'
    option enabled '1'
    option device 'eth1'
    option family 'ipv4'
    option metric '20'
    option weight '1'
    option track_method 'ping'
    list track_ip '9.9.9.9'
    option reliability '1'
    option probe_interval '5'
    option probe_timeout '2'
    option up_count '3'
    option down_count '3'

config member 'wan_m1'
    option interface 'wan'
    option metric '10'
    option weight '3'

config member 'wanb_m1'
    option interface 'wanb'
    option metric '20'
    option weight '1'

config policy 'balanced'
    list use_member 'wan_m1'
    list use_member 'wanb_m1'
    option last_resort 'default'

config rule 'default_rule'
    option use_policy 'balanced'
    option proto 'all'
    option sticky '0'
"#;

    #[test]
    fn parse_sample_config() {
        let cfg = load_from_str(SAMPLE_CONFIG).expect("failed to parse sample config");

        // Globals
        assert!(cfg.globals.enabled);
        assert_eq!(cfg.globals.log_level, "debug");
        assert_eq!(cfg.globals.conntrack_flush, ConntrackFlushMode::Selective);
        assert!(!cfg.globals.ipv6_enabled);

        // Interfaces
        assert_eq!(cfg.interfaces.len(), 2);
        let wan = &cfg.interfaces[0];
        assert_eq!(wan.name, "wan");
        assert_eq!(wan.device, "eth0");
        assert_eq!(wan.metric, 10);
        assert_eq!(wan.weight, 3);
        assert_eq!(wan.track_ip, vec!["1.1.1.1", "8.8.8.8"]);
        assert_eq!(wan.reliability, 2);
        assert!(wan.clamp_mss);

        let wanb = &cfg.interfaces[1];
        assert_eq!(wanb.name, "wanb");
        assert_eq!(wanb.metric, 20);
        assert_eq!(wanb.track_ip, vec!["9.9.9.9"]);

        // Members
        assert_eq!(cfg.members.len(), 2);
        assert_eq!(cfg.members[0].name, "wan_m1");
        assert_eq!(cfg.members[0].interface, "wan");
        assert_eq!(cfg.members[1].name, "wanb_m1");

        // Policy
        assert_eq!(cfg.policies.len(), 1);
        assert_eq!(cfg.policies[0].name, "balanced");
        assert_eq!(cfg.policies[0].members, vec!["wan_m1", "wanb_m1"]);
        assert_eq!(cfg.policies[0].last_resort, LastResort::Default);

        // Rules
        assert_eq!(cfg.rules.len(), 1);
        assert_eq!(cfg.rules[0].name, "default_rule");
        assert_eq!(cfg.rules[0].use_policy, "balanced");
        assert_eq!(cfg.rules[0].proto, "all");
        assert!(!cfg.rules[0].sticky);
    }

    #[test]
    fn parse_empty_config() {
        let cfg = load_from_str("").expect("empty config should parse");
        assert!(cfg.interfaces.is_empty());
        assert!(cfg.globals.enabled); // default
    }

    #[test]
    fn parse_comments_and_blanks() {
        let text = "# just a comment\n\n# another\n";
        let cfg = load_from_str(text).expect("comments-only config should parse");
        assert!(cfg.interfaces.is_empty());
    }

    #[test]
    fn option_outside_section_is_error() {
        let text = "option orphan 'value'\n";
        assert!(load_from_str(text).is_err());
    }

    #[test]
    fn unquoted_values() {
        let text = r#"
config globals globals
    option enabled 1
    option log_level info

config interface wan
    option device eth0
    option metric 10
"#;
        let cfg = load_from_str(text).expect("unquoted values should parse");
        assert!(cfg.globals.enabled);
        assert_eq!(cfg.globals.log_level, "info");
        assert_eq!(cfg.interfaces[0].device, "eth0");
        assert_eq!(cfg.interfaces[0].metric, 10);
    }

    #[test]
    fn double_quoted_values() {
        let text = r#"
config interface "wan"
    option device "eth0"
    option metric "10"
"#;
        let cfg = load_from_str(text).expect("double-quoted values should parse");
        assert_eq!(cfg.interfaces[0].name, "wan");
        assert_eq!(cfg.interfaces[0].device, "eth0");
    }

    #[test]
    fn strip_quotes_helper() {
        assert_eq!(strip_quotes("'hello'"), "hello");
        assert_eq!(strip_quotes("\"hello\""), "hello");
        assert_eq!(strip_quotes("hello"), "hello");
        assert_eq!(strip_quotes("'mismatched\""), "'mismatched\"");
        assert_eq!(strip_quotes("''"), "");
        assert_eq!(strip_quotes("a"), "a");
    }

    #[test]
    fn conntrack_flush_modes() {
        for (val, expected) in [
            ("none", ConntrackFlushMode::None),
            ("selective", ConntrackFlushMode::Selective),
            ("full", ConntrackFlushMode::Full),
        ] {
            let text = format!(
                "config globals 'globals'\n    option conntrack_flush '{val}'\n"
            );
            let cfg = load_from_str(&text).unwrap();
            assert_eq!(cfg.globals.conntrack_flush, expected, "failed for {val}");
        }
    }

    #[test]
    fn rule_with_all_fields() {
        let text = r#"
config policy 'balanced'
    option last_resort 'default'

config rule 'custom'
    option src_ip '10.0.0.0/8'
    option src_port '1024-65535'
    option dest_ip '192.168.1.0/24'
    option dest_port '80'
    option proto 'tcp'
    option family 'ipv4'
    option sticky '1'
    option sticky_timeout '300'
    option sticky_mode 'src_ip'
    option use_policy 'balanced'
"#;
        let cfg = load_from_str(text).unwrap();
        let rule = &cfg.rules[0];
        assert_eq!(rule.src_ip, vec!["10.0.0.0/8"]);
        assert_eq!(rule.src_port.as_deref(), Some("1024-65535"));
        assert_eq!(rule.dest_ip, vec!["192.168.1.0/24"]);
        assert_eq!(rule.dest_port.as_deref(), Some("80"));
        assert_eq!(rule.proto, "tcp");
        assert_eq!(rule.family, RuleFamily::Ipv4);
        assert!(rule.sticky);
        assert_eq!(rule.sticky_timeout, 300);
        assert_eq!(rule.sticky_mode, StickyMode::SrcIp);
    }

    #[test]
    fn member_missing_interface_is_error() {
        let text = "config member 'bad'\n    option metric '10'\n";
        assert!(load_from_str(text).is_err());
    }

    #[test]
    fn rule_missing_policy_is_error() {
        let text = "config rule 'bad'\n    option proto 'tcp'\n";
        assert!(load_from_str(text).is_err());
    }

    #[test]
    fn ipv6_enabled_and_family_parsing() {
        let text = r#"
config globals 'globals'
    option ipv6_enabled '1'

config interface 'wan6'
    option device 'eth0'
    option family 'ipv6'
    list track_ip '2001:4860:4860::8888'

config interface 'wan_dual'
    option device 'eth1'
    option family 'both'
    list track_ip '1.1.1.1'
    list track_ip '2606:4700::1111'

config policy 'balanced'
    option last_resort 'default'

config rule 'v6_only'
    option family 'ipv6'
    option use_policy 'balanced'

config rule 'dual'
    option family 'any'
    option use_policy 'balanced'
"#;
        let cfg = load_from_str(text).unwrap();
        assert!(cfg.globals.ipv6_enabled);
        assert_eq!(cfg.interfaces[0].family, AddressFamily::Ipv6);
        assert_eq!(cfg.interfaces[1].family, AddressFamily::Both);
        assert_eq!(cfg.rules[0].family, RuleFamily::Ipv6);
        assert_eq!(cfg.rules[1].family, RuleFamily::Any);
    }

    #[test]
    fn interface_missing_name_is_error() {
        let text = "config interface\n    option device 'eth0'\n";
        // The parser splits on whitespace after "config interface" -- with
        // nothing there, name is None, which triggers an error.
        //
        // Note: "config interface" with nothing after produces section_type
        // = "interface" and name = None, so parse_interface returns Err.
        assert!(load_from_str(text).is_err());
    }

    // -- Cross-section validation tests --

    #[test]
    fn duplicate_interface_name_is_error() {
        let text = r#"
config interface 'wan'
    option device 'eth0'
config interface 'wan'
    option device 'eth1'
"#;
        let err = load_from_str(text).unwrap_err();
        assert!(err.to_string().contains("duplicate interface name 'wan'"));
    }

    #[test]
    fn duplicate_member_name_is_error() {
        let text = r#"
config interface 'wan'
    option device 'eth0'
config member 'wan_m1'
    option interface 'wan'
config member 'wan_m1'
    option interface 'wan'
"#;
        let err = load_from_str(text).unwrap_err();
        assert!(err.to_string().contains("duplicate member name 'wan_m1'"));
    }

    #[test]
    fn duplicate_policy_name_is_error() {
        let text = r#"
config policy 'balanced'
    option last_resort 'default'
config policy 'balanced'
    option last_resort 'unreachable'
"#;
        let err = load_from_str(text).unwrap_err();
        assert!(err.to_string().contains("duplicate policy name 'balanced'"));
    }

    #[test]
    fn duplicate_rule_name_is_error() {
        let text = r#"
config policy 'balanced'
    option last_resort 'default'
config rule 'r1'
    option use_policy 'balanced'
config rule 'r1'
    option use_policy 'balanced'
"#;
        let err = load_from_str(text).unwrap_err();
        assert!(err.to_string().contains("duplicate rule name 'r1'"));
    }

    #[test]
    fn member_references_nonexistent_interface() {
        let text = r#"
config member 'bad_m1'
    option interface 'nonexistent'
"#;
        let err = load_from_str(text).unwrap_err();
        assert!(err
            .to_string()
            .contains("references nonexistent interface 'nonexistent'"));
    }

    #[test]
    fn policy_references_nonexistent_member() {
        let text = r#"
config policy 'balanced'
    list use_member 'nonexistent'
    option last_resort 'default'
"#;
        let err = load_from_str(text).unwrap_err();
        assert!(err
            .to_string()
            .contains("references nonexistent member 'nonexistent'"));
    }

    #[test]
    fn rule_references_nonexistent_policy() {
        let text = r#"
config rule 'r1'
    option use_policy 'nonexistent'
"#;
        let err = load_from_str(text).unwrap_err();
        assert!(err
            .to_string()
            .contains("references nonexistent policy 'nonexistent'"));
    }

    #[test]
    fn rule_with_use_policy_default_is_valid() {
        let text = r#"
config rule 'r1'
    option use_policy 'default'
"#;
        let cfg = load_from_str(text).unwrap();
        assert_eq!(cfg.rules[0].use_policy, "default");
    }

    #[test]
    fn valid_cross_references_pass() {
        let text = r#"
config interface 'wan'
    option device 'eth0'
    list track_ip '1.1.1.1'
config interface 'wanb'
    option device 'eth1'
    list track_ip '8.8.8.8'
config member 'wan_m1'
    option interface 'wan'
config member 'wanb_m1'
    option interface 'wanb'
config policy 'balanced'
    list use_member 'wan_m1'
    list use_member 'wanb_m1'
config rule 'r1'
    option use_policy 'balanced'
"#;
        assert!(load_from_str(text).is_ok());
    }
}
