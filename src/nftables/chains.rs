use serde_json::{json, Value};

use crate::config::schema::LastResort;
use crate::nftables::ruleset::{
    Ruleset, PROBE_MARK, TABLE_FAMILY, TABLE_NAME,
};

/// Describes a WAN interface for ruleset generation.
#[derive(Debug, Clone)]
pub struct InterfaceInfo {
    pub name: String,
    pub mark: u32,
    #[allow(dead_code)]
    pub table_id: u32,
    pub device: String,
    pub clamp_mss: bool,
}

/// Describes a load-balancing or failover policy.
#[derive(Debug, Clone)]
pub struct PolicyInfo {
    pub name: String,
    pub members: Vec<PolicyMember>,
    pub last_resort: LastResort,
}

/// A single member within a policy, already resolved to its mark value.
#[derive(Debug, Clone)]
pub struct PolicyMember {
    pub interface: String,
    pub mark: u32,
    pub weight: u32,
    pub metric: u32,
}

/// Sticky session configuration for a rule.
#[derive(Debug, Clone)]
pub struct StickyInfo {
    /// Sticky mode: `"flow"`, `"src_ip"`, or `"src_dst"`.
    pub mode: String,
    /// Timeout in seconds for sticky map entries.
    pub timeout: u32,
}

/// A traffic-matching rule that directs packets to a policy chain.
#[derive(Debug, Clone)]
pub struct RuleInfo {
    pub src_ip: Vec<String>,
    pub src_port: Option<String>,
    pub dest_ip: Vec<String>,
    pub dest_port: Option<String>,
    pub proto: String,
    pub family: String,
    /// Match traffic arriving on this network interface (e.g. "br-lan").
    pub src_iface: Option<String>,
    /// Match destination against a user-defined nftables named set.
    pub ipset: Option<String>,
    pub policy: String,
    /// Sticky session config. `None` or `Some` with mode `"flow"` means
    /// per-connection stickiness via ct mark (already handled by base rules).
    /// `"src_ip"` or `"src_dst"` creates nftables maps for cross-connection
    /// stickiness.
    pub sticky: Option<StickyInfo>,
    /// Log matching packets via nftables log statement.
    pub log: bool,
}

/// Builds a complete nftables ruleset from interface, policy, and rule data.
pub struct ChainBuilder;

impl ChainBuilder {
    /// Generate the full `inet nopal` ruleset.
    ///
    /// The returned `Ruleset` is ready to be passed to `NftEngine::apply`.
    /// It flushes the existing table (if any), re-creates it, and populates
    /// every chain needed for policy routing.
    ///
    /// `connected` is a list of CIDR prefixes (e.g. `"192.168.1.0/24"`) for
    /// directly-connected networks. Traffic to these destinations is accepted
    /// early in the forward/output chains to prevent policy routing of LAN
    /// and other local traffic.
    pub fn build_ruleset(
        interfaces: &[InterfaceInfo],
        policies: &[PolicyInfo],
        rules: &[RuleInfo],
        connected: &[String],
        mark_mask: u32,
    ) -> Ruleset {
        let mut rs = Ruleset::new();

        // -- table setup --------------------------------------------------
        // Create the table first (idempotent), then flush all its contents
        // so the subsequent commands start from a clean slate.
        rs.add_table(TABLE_FAMILY, TABLE_NAME);
        rs.flush_table(TABLE_FAMILY, TABLE_NAME);

        // -- dynamic bypass sets ------------------------------------------
        // Empty named sets that users can populate at runtime to exclude
        // traffic from policy routing, e.g.:
        //   nft add element inet nopal bypass_v4 { 10.0.0.0/8 }
        rs.add_set("bypass_v4", "ipv4_addr", vec!["interval".to_string()]);
        rs.add_set("bypass_v6", "ipv6_addr", vec!["interval".to_string()]);

        // -- base chains --------------------------------------------------
        rs.add_base_chain("prerouting", "filter", "prerouting", -150, "accept");
        rs.add_base_chain("forward", "filter", "forward", -150, "accept");
        rs.add_base_chain("output", "filter", "output", -150, "accept");
        rs.add_base_chain("postrouting", "filter", "postrouting", 150, "accept");

        // -- regular chains -----------------------------------------------
        rs.add_regular_chain("policy_rules");

        for iface in interfaces {
            rs.add_regular_chain(&format!("mark_{}", iface.name));
        }

        for policy in policies {
            rs.add_regular_chain(&format!("policy_{}", policy.name));
        }

        // -- prerouting rules ---------------------------------------------
        Self::build_prerouting(&mut rs, interfaces, mark_mask);

        // -- forward rules ------------------------------------------------
        Self::build_forward(&mut rs, connected, mark_mask);

        // -- output rules -------------------------------------------------
        Self::build_output(&mut rs, connected, mark_mask);

        // -- postrouting rules --------------------------------------------
        Self::build_postrouting(&mut rs, interfaces);

        // -- sticky maps and chains ---------------------------------------
        for (i, rule) in rules.iter().enumerate() {
            if let Some(ref sticky) = rule.sticky {
                if sticky.mode != "flow" {
                    if let Some(policy) = policies.iter().find(|p| p.name == rule.policy) {
                        Self::build_sticky_map_and_chain(
                            &mut rs, i, rule, sticky, mark_mask, policy,
                        );
                    }
                }
            }
        }

        // -- policy_rules chain -------------------------------------------
        Self::build_policy_rules(&mut rs, rules);

        // -- per-policy chains --------------------------------------------
        for policy in policies {
            Self::build_policy_chain(&mut rs, policy);
        }

        // -- per-interface mark chains ------------------------------------
        for iface in interfaces {
            Self::build_mark_chain(&mut rs, iface);
        }

        rs
    }

    /// Prerouting chain:
    /// 1. Skip probe packets (mark == PROBE_MARK) with an early return.
    /// 2. Accept IPv6 NDP/RA packets (ICMPv6 types 133-137) to prevent
    ///    policy routing from breaking neighbor discovery.
    /// 3. Restore conntrack mark to packet mark when ct mark has WAN bits.
    /// 4. Mark inbound new connections on each WAN device for
    ///    anti-asymmetric routing.
    fn build_prerouting(rs: &mut Ruleset, interfaces: &[InterfaceInfo], mark_mask: u32) {
        // Exception: skip probe packets
        rs.add_rule("prerouting", vec![
            match_meta_mark_eq(PROBE_MARK),
            accept(),
        ]);

        // Exception: accept IPv6 NDP/RA (ICMPv6 types 133-137) before any
        // marking. Without this, Router Solicitation/Advertisement and
        // Neighbor Solicitation/Advertisement packets could be policy-routed,
        // breaking IPv6 neighbor discovery on multi-WAN setups.
        rs.add_rule("prerouting", vec![
            match_nfproto_ipv6(),
            match_protocol("icmpv6"),
            match_icmpv6_type_range(133, 137),
            accept(),
        ]);

        // Restore conntrack mark -> packet mark when ct mark has WAN bits set
        rs.add_rule("prerouting", vec![
            match_ct_mark_masked_neq(mark_mask, 0),
            set_mark_from_ct(mark_mask),
        ]);

        // Mark inbound new connections per interface
        for iface in interfaces {
            rs.add_rule("prerouting", vec![
                match_iifname(&iface.device),
                match_ct_state_new(),
                set_ct_mark(iface.mark),
            ]);
        }
    }

    /// Forward chain:
    /// 1. Accept traffic to directly-connected networks (bypass policy routing).
    /// 2. Restore conntrack mark to packet mark.
    /// 3. If no mark set, jump to policy_rules.
    fn build_forward(rs: &mut Ruleset, connected: &[String], mark_mask: u32) {
        // Skip traffic to connected networks -- LAN and local subnets should
        // never be policy-routed.
        Self::add_connected_bypass(rs, "forward", connected);

        rs.add_rule("forward", vec![
            match_ct_mark_masked_neq(mark_mask, 0),
            set_mark_from_ct(mark_mask),
        ]);

        rs.add_rule("forward", vec![
            match_meta_mark_masked_eq(mark_mask, 0),
            jump("policy_rules"),
        ]);
    }

    /// Output chain:
    /// 1. Accept traffic to directly-connected networks.
    /// 2. Restore conntrack mark to packet mark (for reply traffic).
    /// 3. Skip if mark already set; otherwise jump to policy_rules.
    fn build_output(rs: &mut Ruleset, connected: &[String], mark_mask: u32) {
        Self::add_connected_bypass(rs, "output", connected);

        // Restore conntrack mark -> packet mark for router-originated traffic
        // belonging to an existing connection (e.g., DNS replies, TCP RSTs).
        rs.add_rule("output", vec![
            match_ct_mark_masked_neq(mark_mask, 0),
            set_mark_from_ct(mark_mask),
        ]);

        rs.add_rule("output", vec![
            match_meta_mark_masked_neq(mark_mask, 0),
            accept(),
        ]);

        rs.add_rule("output", vec![
            jump("policy_rules"),
        ]);
    }

    /// Add accept rules for directly-connected network prefixes and
    /// dynamic bypass sets.
    ///
    /// Splits prefixes into IPv4 and IPv6 groups and emits one rule per
    /// address family using an anonymous set of prefixes. Also adds rules
    /// to check the user-populated `bypass_v4` / `bypass_v6` named sets.
    fn add_connected_bypass(rs: &mut Ruleset, chain: &str, connected: &[String]) {
        let (v4, v6): (Vec<_>, Vec<_>) = connected
            .iter()
            .partition(|cidr| !cidr.contains(':'));

        if !v4.is_empty() {
            let set: Vec<Value> = v4.iter().map(|cidr| prefix_value(cidr)).collect();
            rs.add_rule(chain, vec![
                match_daddr_set("ip", set),
                accept(),
            ]);
        }

        if !v6.is_empty() {
            let set: Vec<Value> = v6.iter().map(|cidr| prefix_value(cidr)).collect();
            rs.add_rule(chain, vec![
                match_daddr_set("ip6", set),
                accept(),
            ]);
        }

        // Dynamic bypass: accept traffic matching user-populated named sets.
        // Users can add entries at runtime:
        //   nft add element inet nopal bypass_v4 { 10.0.0.0/8 }
        rs.add_rule(chain, vec![
            match_daddr_named_set("bypass_v4", "ipv4"),
            accept(),
        ]);
        rs.add_rule(chain, vec![
            match_daddr_named_set("bypass_v6", "ipv6"),
            accept(),
        ]);
    }

    /// Postrouting chain:
    /// For each interface with MSS clamping enabled, clamp TCP SYN MSS to
    /// path MTU on the outbound device.
    fn build_postrouting(rs: &mut Ruleset, interfaces: &[InterfaceInfo]) {
        for iface in interfaces {
            if iface.clamp_mss {
                rs.add_rule("postrouting", vec![
                    match_oifname(&iface.device),
                    match_tcp_syn(),
                    clamp_mss_to_pmtu(),
                ]);
            }
        }
    }

    /// policy_rules chain: match user-defined rules and jump to the
    /// corresponding policy chain (or sticky helper chain).
    ///
    /// When `proto` is `"all"` but ports are specified, two rules are emitted
    /// (one for TCP, one for UDP) since port matching requires a concrete L4
    /// protocol. This mirrors mwan3 behaviour.
    fn build_policy_rules(rs: &mut Ruleset, rules: &[RuleInfo]) {
        for (i, rule) in rules.iter().enumerate() {
            let has_ports = rule.src_port.is_some() || rule.dest_port.is_some();
            let is_icmp = rule.proto == "icmp";

            // Build the list of (proto, family_override) pairs to emit.
            // ICMP needs family-specific L4 protocol names: "icmp" for IPv4,
            // "icmpv6" for IPv6. When the rule family is "any", emit both.
            // The family_override forces an nfproto match for the ICMP pair.
            let proto_family_pairs: Vec<(&str, Option<&str>)> = if is_icmp {
                match rule.family.as_str() {
                    "ipv4" => vec![("icmp", None)],
                    "ipv6" => vec![("icmpv6", None)],
                    _ => vec![("icmp", Some("ipv4")), ("icmpv6", Some("ipv6"))],
                }
            } else if rule.proto == "all" && has_ports {
                vec![("tcp", None), ("udp", None)]
            } else {
                vec![(rule.proto.as_str(), None)]
            };

            for (proto, family_override) in &proto_family_pairs {
                let mut expr: Vec<Value> = Vec::new();

                // Address family filter -- family_override is used for ICMP
                // split rules that need an explicit nfproto match.
                let family = family_override.unwrap_or(rule.family.as_str());
                match family {
                    "ipv4" => expr.push(match_nfproto_ipv4()),
                    "ipv6" => expr.push(match_nfproto_ipv6()),
                    _ => {} // "any" -- no family filter
                }

                // Inbound interface match
                if let Some(ref iface) = rule.src_iface {
                    expr.push(match_iifname(iface));
                }

                // Protocol match
                if *proto != "all" {
                    expr.push(match_protocol(proto));
                }

                // Source IP(s) / named set
                if !rule.src_ip.is_empty() {
                    expr.push(match_ip_list(&rule.src_ip, "saddr", &rule.family));
                }

                // Destination IP(s) / named set
                if !rule.dest_ip.is_empty() {
                    expr.push(match_ip_list(&rule.dest_ip, "daddr", &rule.family));
                }

                // User-defined named set match (destination)
                if let Some(ref set_name) = rule.ipset {
                    expr.push(match_daddr_named_set(set_name, &rule.family));
                }

                // Source port (only valid for tcp/udp -- skip for ICMP)
                if !is_icmp {
                    if let Some(ref port) = rule.src_port {
                        expr.push(match_src_port(port, proto));
                    }
                }

                // Destination port (skip for ICMP)
                if !is_icmp {
                    if let Some(ref port) = rule.dest_port {
                        expr.push(match_dst_port(port, proto));
                    }
                }

                // Log matching packets if enabled for this rule
                if rule.log {
                    expr.push(log_prefix(&format!("nopal:{} ", rule.policy)));
                }

                // "default" policy means use the main routing table -- accept
                // immediately so the packet bypasses all nopal policy routing.
                if rule.policy == "default" {
                    expr.push(accept());
                } else {
                    // For sticky rules with src_ip/src_dst mode, jump to the
                    // per-rule sticky helper chain instead of directly to the policy.
                    let needs_sticky_chain = rule
                        .sticky
                        .as_ref()
                        .is_some_and(|s| s.mode != "flow");

                    if needs_sticky_chain {
                        expr.push(jump(&format!("sticky_r{i}")));
                    } else {
                        expr.push(jump(&format!("policy_{}", rule.policy)));
                    }
                }

                rs.add_rule("policy_rules", expr);
            }
        }
    }

    /// Build nftables map(s) and a helper chain for a sticky rule.
    ///
    /// The sticky chain flow:
    /// 1. Look up the sticky key (src IP or src+dst) in the map.
    ///    If found, set the mark from the map, save to ct, accept.
    /// 2. Assign a mark by inlining the policy's member selection logic
    ///    directly (single member: set mark; multi member: numgen data map).
    ///    This avoids jumping to the shared policy chain whose terminal
    ///    `accept` in the mark chain would prevent the map update below.
    /// 3. Update the sticky map with the assigned mark, accept.
    fn build_sticky_map_and_chain(
        rs: &mut Ruleset,
        rule_index: usize,
        rule: &RuleInfo,
        sticky: &StickyInfo,
        mark_mask: u32,
        policy: &PolicyInfo,
    ) {
        let families = match rule.family.as_str() {
            "ipv4" => vec!["ipv4"],
            "ipv6" => vec!["ipv6"],
            _ => vec!["ipv4", "ipv6"],
        };

        // Create map(s) for this rule
        for fam in &families {
            let suffix = if families.len() > 1 {
                format!("_{}", if *fam == "ipv4" { "v4" } else { "v6" })
            } else {
                String::new()
            };
            let map_name = format!("sticky_r{rule_index}{suffix}");

            let addr_type = if *fam == "ipv4" {
                "ipv4_addr"
            } else {
                "ipv6_addr"
            };

            let key_type = match sticky.mode.as_str() {
                "src_dst" => json!([addr_type, addr_type]),
                _ => json!(addr_type), // src_ip
            };

            rs.add_map(&map_name, key_type, "mark", sticky.timeout);
        }

        // Create the sticky helper chain
        let chain_name = format!("sticky_r{rule_index}");
        rs.add_regular_chain(&chain_name);

        // Phase 1: Map lookup -- if the key is already in the map, use it.
        for fam in &families {
            let suffix = if families.len() > 1 {
                format!("_{}", if *fam == "ipv4" { "v4" } else { "v6" })
            } else {
                String::new()
            };
            let map_name = format!("sticky_r{rule_index}{suffix}");
            let proto = if *fam == "ipv4" { "ip" } else { "ip6" };

            let lookup_key = sticky_key_expr(proto, &sticky.mode);

            let mut lookup_expr: Vec<Value> = Vec::new();
            if families.len() > 1 {
                if *fam == "ipv4" {
                    lookup_expr.push(match_nfproto_ipv4());
                } else {
                    lookup_expr.push(match_nfproto_ipv6());
                }
            }
            lookup_expr.push(set_mark_from_map(&lookup_key, &map_name));
            lookup_expr.push(save_mark_to_ct());
            lookup_expr.push(accept());
            rs.add_rule(&chain_name, lookup_expr);
        }

        // Phase 2: Inline policy dispatch -- select interface mark directly.
        // We can't jump to the shared policy chain because its mark chain
        // terminates with `accept`, preventing the map update in phase 3.
        if policy.members.is_empty() {
            match policy.last_resort {
                LastResort::Unreachable => {
                    rs.add_rule(&chain_name, vec![reject_unreachable()]);
                }
                LastResort::Blackhole => {
                    rs.add_rule(&chain_name, vec![drop_packet()]);
                }
                LastResort::Default => {} // fall through, no mark
            }
            return;
        }

        // Group by metric (tier), sorted lowest first. Only the first tier
        // executes -- lower-priority tiers become first after regeneration
        // when higher-priority interfaces go offline.
        let mut tiers: Vec<(u32, Vec<&PolicyMember>)> = Vec::new();
        for member in &policy.members {
            if let Some(tier) = tiers.iter_mut().find(|(m, _)| *m == member.metric) {
                tier.1.push(member);
            } else {
                tiers.push((member.metric, vec![member]));
            }
        }
        tiers.sort_by_key(|(metric, _)| *metric);

        let first_tier = &tiers[0].1;

        if first_tier.len() == 1 {
            // Single member: set mark directly
            rs.add_rule(&chain_name, vec![
                set_meta_mark(first_tier[0].mark),
                save_mark_to_ct(),
            ]);
        } else {
            // Multiple members: weighted round-robin via numgen data map
            let total: u32 = first_tier.iter().map(|m| m.weight).fold(0u32, u32::saturating_add);
            let mut map_entries: Vec<Value> = Vec::new();
            let mut slot = 0u32;
            for member in first_tier {
                for _ in 0..member.weight {
                    map_entries.push(json!([slot, member.mark]));
                    slot += 1;
                }
            }

            rs.add_rule(&chain_name, vec![
                json!({
                    "mangle": {
                        "key": {"meta": {"key": "mark"}},
                        "value": {
                            "map": {
                                "key": {
                                    "numgen": {
                                        "mode": "inc",
                                        "mod": total,
                                        "offset": 0
                                    }
                                },
                                "data": map_entries
                            }
                        }
                    }
                }),
                save_mark_to_ct(),
            ]);
        }

        // Phase 3: Update sticky map with the assigned mark, then accept.
        // Only update if a mark was actually set (non-zero WAN bits).
        for fam in &families {
            let suffix = if families.len() > 1 {
                format!("_{}", if *fam == "ipv4" { "v4" } else { "v6" })
            } else {
                String::new()
            };
            let map_name = format!("sticky_r{rule_index}{suffix}");
            let proto = if *fam == "ipv4" { "ip" } else { "ip6" };

            let update_key = sticky_key_expr(proto, &sticky.mode);

            let mut update_expr: Vec<Value> = Vec::new();
            if families.len() > 1 {
                if *fam == "ipv4" {
                    update_expr.push(match_nfproto_ipv4());
                } else {
                    update_expr.push(match_nfproto_ipv6());
                }
            }
            update_expr.push(match_meta_mark_masked_neq(mark_mask, 0));
            update_expr.push(update_map(&update_key, &map_name));
            update_expr.push(accept());
            rs.add_rule(&chain_name, update_expr);
        }
    }

    /// Per-policy chain. Groups members by metric (tier) for failover
    /// semantics: the lowest metric tier is tried first. Within a tier,
    /// members are load-balanced via `numgen inc mod N`.
    fn build_policy_chain(rs: &mut Ruleset, policy: &PolicyInfo) {
        let chain_name = format!("policy_{}", policy.name);

        if policy.members.is_empty() {
            match policy.last_resort {
                LastResort::Unreachable => {
                    rs.add_rule(&chain_name, vec![reject_unreachable()]);
                }
                LastResort::Blackhole => {
                    rs.add_rule(&chain_name, vec![drop_packet()]);
                }
                LastResort::Default => {
                    // No rule -- packets fall through to default route
                }
            }
            return;
        }

        // Group members by metric (lower = higher priority).
        let mut tiers: Vec<(u32, Vec<&PolicyMember>)> = Vec::new();
        for member in &policy.members {
            if let Some(tier) = tiers.iter_mut().find(|(m, _)| *m == member.metric) {
                tier.1.push(member);
            } else {
                tiers.push((member.metric, vec![member]));
            }
        }
        tiers.sort_by_key(|(metric, _)| *metric);

        for (_metric, members) in &tiers {
            if members.len() == 1 {
                // Single member at this tier -- direct goto
                rs.add_rule(&chain_name, vec![
                    goto(&format!("mark_{}", members[0].interface)),
                ]);
            } else {
                // Multiple members -- weighted round-robin via numgen vmap.
                // Expand weights: each member gets `weight` slots.
                let total: u32 = members.iter().map(|m| m.weight).fold(0u32, u32::saturating_add);
                let mut vmap_entries: Vec<Value> = Vec::new();
                let mut slot = 0u32;
                for member in members {
                    for _ in 0..member.weight {
                        vmap_entries.push(json!([
                            slot,
                            {"goto": {"target": format!("mark_{}", member.interface)}}
                        ]));
                        slot += 1;
                    }
                }

                rs.add_rule(&chain_name, vec![
                    json!({
                        "vmap": {
                            "key": {
                                "numgen": {
                                    "mode": "inc",
                                    "mod": total,
                                    "offset": 0
                                }
                            },
                            "data": vmap_entries
                        }
                    }),
                ]);
            }
        }
    }

    /// Per-interface mark chain: set packet mark, save to conntrack.
    fn build_mark_chain(rs: &mut Ruleset, iface: &InterfaceInfo) {
        let chain_name = format!("mark_{}", iface.name);
        rs.add_rule(&chain_name, vec![
            set_meta_mark(iface.mark),
            save_mark_to_ct(),
            accept(),
        ]);
    }
}

// ---------------------------------------------------------------------------
// nftables JSON expression helpers
//
// Each helper returns a `serde_json::Value` representing one nftables
// expression element. Using `json!()` keeps these compact and readable.
// ---------------------------------------------------------------------------

fn match_meta_mark_eq(value: u32) -> Value {
    json!({
        "match": {
            "op": "==",
            "left": {"meta": {"key": "mark"}},
            "right": value
        }
    })
}

fn match_meta_mark_masked_eq(mask: u32, value: u32) -> Value {
    json!({
        "match": {
            "op": "==",
            "left": {"&": [{"meta": {"key": "mark"}}, mask]},
            "right": value
        }
    })
}

fn match_meta_mark_masked_neq(mask: u32, value: u32) -> Value {
    json!({
        "match": {
            "op": "!=",
            "left": {"&": [{"meta": {"key": "mark"}}, mask]},
            "right": value
        }
    })
}

fn match_ct_mark_masked_neq(mask: u32, value: u32) -> Value {
    json!({
        "match": {
            "op": "!=",
            "left": {"&": [{"ct": {"key": "mark"}}, mask]},
            "right": value
        }
    })
}

fn match_ct_state_new() -> Value {
    json!({
        "match": {
            "op": "==",
            "left": {"ct": {"key": "state"}},
            "right": "new"
        }
    })
}

fn match_iifname(device: &str) -> Value {
    json!({
        "match": {
            "op": "==",
            "left": {"meta": {"key": "iifname"}},
            "right": device
        }
    })
}

fn match_oifname(device: &str) -> Value {
    json!({
        "match": {
            "op": "==",
            "left": {"meta": {"key": "oifname"}},
            "right": device
        }
    })
}

fn match_nfproto_ipv4() -> Value {
    json!({
        "match": {
            "op": "==",
            "left": {"meta": {"key": "nfproto"}},
            "right": "ipv4"
        }
    })
}

fn match_nfproto_ipv6() -> Value {
    json!({
        "match": {
            "op": "==",
            "left": {"meta": {"key": "nfproto"}},
            "right": "ipv6"
        }
    })
}

fn match_icmpv6_type_range(low: u8, high: u8) -> Value {
    json!({
        "match": {
            "op": "==",
            "left": {"payload": {"protocol": "icmpv6", "field": "type"}},
            "right": {"range": [low, high]}
        }
    })
}

fn match_protocol(proto: &str) -> Value {
    json!({
        "match": {
            "op": "==",
            "left": {"meta": {"key": "l4proto"}},
            "right": proto
        }
    })
}

/// Detect whether an address string is IPv6 (contains ':') or IPv4.
fn ip_protocol(addr: &str) -> &'static str {
    if addr.contains(':') { "ip6" } else { "ip" }
}

/// Determine the nftables protocol for an address or set reference.
///
/// For literal addresses, the protocol is inferred from the format (`:` = IPv6).
/// For named set references (`@set_name`), the rule's `family` field is used.
fn ip_protocol_for(addr: &str, rule_family: &str) -> &'static str {
    if addr.starts_with('@') {
        match rule_family {
            "ipv6" => "ip6",
            _ => "ip",
        }
    } else {
        ip_protocol(addr)
    }
}

/// Build the right-hand operand for an IP match.
///
/// For named set references (`@set_name`), emits `{"@": "set_name"}`.
/// For literal addresses/CIDRs, emits the string directly.
fn ip_right_value(addr: &str) -> Value {
    if let Some(set_name) = addr.strip_prefix('@') {
        json!({"@": set_name})
    } else {
        json!(addr)
    }
}

/// Match one or more source/destination IPs.
///
/// For a single value, emits a simple match. For multiple values, emits an
/// anonymous set: `{"set": [addr1, addr2, ...]}`.
fn match_ip_list(addrs: &[String], field: &str, rule_family: &str) -> Value {
    let proto = ip_protocol_for(&addrs[0], rule_family);
    let right = if addrs.len() == 1 {
        ip_right_value(&addrs[0])
    } else {
        json!({"set": addrs.iter().map(|a| ip_right_value(a)).collect::<Vec<_>>()})
    };
    json!({
        "match": {
            "op": "==",
            "left": {"payload": {"protocol": proto, "field": field}},
            "right": right
        }
    })
}

/// Convert a CIDR string like `"192.168.1.0/24"` to an nftables prefix value.
fn prefix_value(cidr: &str) -> Value {
    if let Some((addr, len_s)) = cidr.split_once('/') {
        if let Ok(len) = len_s.parse::<u32>() {
            return json!({"prefix": {"addr": addr, "len": len}});
        }
    }
    // Fallback: treat as a host address
    json!(cidr)
}

/// Match destination address against an anonymous set of prefixes.
fn match_daddr_set(protocol: &str, set: Vec<Value>) -> Value {
    json!({
        "match": {
            "op": "==",
            "left": {"payload": {"protocol": protocol, "field": "daddr"}},
            "right": {"set": set}
        }
    })
}

/// Match destination address against a user-defined named set.
///
/// Emits both `ip daddr @<name>` and `ip6 daddr @<name>` for family "any",
/// or the appropriate one for "ipv4"/"ipv6". For "any" family, we use the
/// `ip daddr` form (callers typically create separate ipv4/ipv6 named sets).
fn match_daddr_named_set(set_name: &str, family: &str) -> Value {
    let protocol = match family {
        "ipv6" => "ip6",
        _ => "ip",
    };
    json!({
        "match": {
            "op": "==",
            "left": {"payload": {"protocol": protocol, "field": "daddr"}},
            "right": format!("@{set_name}")
        }
    })
}

/// Parse a port string into an nftables JSON value.
///
/// Single ports like `"443"` become integer `443`.
/// Ranges like `"1024-65535"` become `{"range": [1024, 65535]}`.
fn parse_port(port: &str) -> Value {
    if let Some((lo, hi)) = port.split_once('-') {
        if let (Ok(lo), Ok(hi)) = (lo.parse::<u16>(), hi.parse::<u16>()) {
            return json!({"range": [lo, hi]});
        }
    }
    if let Ok(n) = port.parse::<u16>() {
        return json!(n);
    }
    // Fallback: pass as-is (will likely fail at nft apply time)
    json!(port)
}

fn match_src_port(port: &str, proto: &str) -> Value {
    json!({
        "match": {
            "op": "==",
            "left": {"payload": {"protocol": proto, "field": "sport"}},
            "right": parse_port(port)
        }
    })
}

fn match_dst_port(port: &str, proto: &str) -> Value {
    json!({
        "match": {
            "op": "==",
            "left": {"payload": {"protocol": proto, "field": "dport"}},
            "right": parse_port(port)
        }
    })
}

fn match_tcp_syn() -> Value {
    // Build manually to avoid tokenization issues with "|" as a JSON key
    // inside the json!() macro.
    let flags_match = Value::Object(serde_json::Map::from_iter([
        ("|".to_string(), json!(["syn", "rst"])),
    ]));
    json!({
        "match": {
            "op": "==",
            "left": {"payload": {"protocol": "tcp", "field": "flags"}},
            "right": {"&": ["syn", flags_match]}
        }
    })
}

fn clamp_mss_to_pmtu() -> Value {
    // Build the "tcp option" key manually -- `option` is a reserved keyword
    // that causes tokenization issues inside the json!() macro in edition 2024.
    let tcp_opt_key = "tcp option".to_string();
    let tcp_opt_val = json!({"name": "maxseg", "field": "size"});
    let key = Value::Object(serde_json::Map::from_iter([
        (tcp_opt_key, tcp_opt_val),
    ]));
    json!({
        "mangle": {
            "key": key,
            "value": {"rt": {"key": "mtu"}}
        }
    })
}

fn set_mark_from_ct(mask: u32) -> Value {
    json!({
        "mangle": {
            "key": {"meta": {"key": "mark"}},
            "value": {"&": [{"ct": {"key": "mark"}}, mask]}
        }
    })
}

fn set_ct_mark(value: u32) -> Value {
    json!({
        "mangle": {
            "key": {"ct": {"key": "mark"}},
            "value": value
        }
    })
}

fn set_meta_mark(value: u32) -> Value {
    json!({
        "mangle": {
            "key": {"meta": {"key": "mark"}},
            "value": value
        }
    })
}

fn save_mark_to_ct() -> Value {
    json!({
        "mangle": {
            "key": {"ct": {"key": "mark"}},
            "value": {"meta": {"key": "mark"}}
        }
    })
}

/// Build the key expression for a sticky map lookup/update.
fn sticky_key_expr(proto: &str, mode: &str) -> Value {
    let saddr = json!({"payload": {"protocol": proto, "field": "saddr"}});
    match mode {
        "src_dst" => {
            let daddr = json!({"payload": {"protocol": proto, "field": "daddr"}});
            json!({"concat": [saddr, daddr]})
        }
        _ => saddr, // src_ip
    }
}

/// Look up a key in a named map and set the packet mark to the result.
/// If the key is not in the map, the rule expression fails (no match).
fn set_mark_from_map(key: &Value, map_name: &str) -> Value {
    json!({
        "mangle": {
            "key": {"meta": {"key": "mark"}},
            "value": {
                "map": {
                    "key": key,
                    "data": {"@": map_name}
                }
            }
        }
    })
}

/// Update a named map entry: key -> current packet mark.
fn update_map(key: &Value, map_name: &str) -> Value {
    json!({
        "map": {
            "op": "update",
            "elem": key,
            "data": {"meta": {"key": "mark"}},
            "map": {"@": map_name}
        }
    })
}

fn drop_packet() -> Value {
    json!({"drop": null})
}

fn reject_unreachable() -> Value {
    json!({
        "reject": {
            "type": "icmpx",
            "expr": "host-unreachable"
        }
    })
}

fn log_prefix(prefix: &str) -> Value {
    json!({"log": {"prefix": prefix}})
}

fn accept() -> Value {
    json!({"accept": null})
}

fn jump(target: &str) -> Value {
    json!({"jump": {"target": target}})
}

fn goto(target: &str) -> Value {
    json!({"goto": {"target": target}})
}

#[cfg(test)]
mod tests {
    use super::*;

    fn two_interface_setup() -> (Vec<InterfaceInfo>, Vec<PolicyInfo>, Vec<RuleInfo>) {
        let interfaces = vec![
            InterfaceInfo {
                name: "wan".to_string(),
                mark: 0x0100,
                table_id: 100,
                device: "eth0".to_string(),
                clamp_mss: true,
            },
            InterfaceInfo {
                name: "wanb".to_string(),
                mark: 0x0200,
                table_id: 200,
                device: "eth1".to_string(),
                clamp_mss: false,
            },
        ];

        let policies = vec![PolicyInfo {
            name: "balanced".to_string(),
            members: vec![
                PolicyMember {
                    interface: "wan".to_string(),
                    mark: 0x0100,
                    weight: 1,
                    metric: 0,
                },
                PolicyMember {
                    interface: "wanb".to_string(),
                    mark: 0x0200,
                    weight: 1,
                    metric: 0,
                },
            ],
            last_resort: LastResort::Default,
        }];

        let rules = vec![RuleInfo {
            src_ip: vec![],
            src_port: None,
            dest_ip: vec![],
            dest_port: None,
            proto: "all".to_string(),
            family: "any".to_string(),
            src_iface: None,
            ipset: None,
            policy: "balanced".to_string(),
            sticky: None,
            log: false,
        }];

        (interfaces, policies, rules)
    }

    #[test]
    fn ruleset_serializes_to_valid_json() {
        let (interfaces, policies, rules) = two_interface_setup();
        let rs = ChainBuilder::build_ruleset(&interfaces, &policies, &rules, &[], 0xFF00);
        let json_str = serde_json::to_string_pretty(&rs).expect("serialization failed");

        // Must parse back as valid JSON
        let parsed: Value = serde_json::from_str(&json_str).expect("invalid JSON");
        let commands = parsed["nftables"]
            .as_array()
            .expect("nftables key must be an array");

        // Verify the overall structure: table, flush, chains, rules
        assert!(
            !commands.is_empty(),
            "ruleset must contain at least one command"
        );

        // First command should be the table definition
        assert!(
            commands[0].get("table").is_some(),
            "first command should be a table definition"
        );

        // Second command should be flush
        assert!(
            commands[1].get("flush").is_some(),
            "second command should be a flush"
        );

        // Collect all command types for structural checks
        let chain_names: Vec<&str> = commands
            .iter()
            .filter_map(|c| c.get("chain"))
            .filter_map(|c| c["name"].as_str())
            .collect();

        assert!(
            chain_names.contains(&"prerouting"),
            "must have prerouting chain"
        );
        assert!(chain_names.contains(&"forward"), "must have forward chain");
        assert!(chain_names.contains(&"output"), "must have output chain");
        assert!(
            chain_names.contains(&"postrouting"),
            "must have postrouting chain"
        );
        assert!(
            chain_names.contains(&"policy_rules"),
            "must have policy_rules chain"
        );
        assert!(
            chain_names.contains(&"policy_balanced"),
            "must have policy_balanced chain"
        );
        assert!(
            chain_names.contains(&"mark_wan"),
            "must have mark_wan chain"
        );
        assert!(
            chain_names.contains(&"mark_wanb"),
            "must have mark_wanb chain"
        );
    }

    #[test]
    fn prerouting_has_probe_exception() {
        let (interfaces, policies, rules) = two_interface_setup();
        let rs = ChainBuilder::build_ruleset(&interfaces, &policies, &rules, &[], 0xFF00);
        let json_str = serde_json::to_string(&rs).expect("serialization failed");
        let parsed: Value = serde_json::from_str(&json_str).expect("invalid JSON");

        let prerouting_rules: Vec<&Value> = parsed["nftables"]
            .as_array()
            .unwrap()
            .iter()
            .filter_map(|c| c.get("rule"))
            .filter(|r| r["chain"] == "prerouting")
            .collect();

        // First rule in prerouting should match PROBE_MARK and accept
        assert!(
            !prerouting_rules.is_empty(),
            "prerouting must have rules"
        );

        let first_expr = &prerouting_rules[0]["expr"];
        let first_str = serde_json::to_string(first_expr).unwrap();
        assert!(
            first_str.contains(&format!("{}", PROBE_MARK)),
            "first prerouting rule must reference probe mark 0x{:X}: {}",
            PROBE_MARK,
            first_str,
        );
    }

    #[test]
    fn connected_networks_bypass_policy_routing() {
        let (interfaces, policies, rules) = two_interface_setup();
        let connected = vec![
            "192.168.1.0/24".to_string(),
            "10.0.0.0/8".to_string(),
            "fd00::/64".to_string(),
        ];
        let rs = ChainBuilder::build_ruleset(&interfaces, &policies, &rules, &connected, 0xFF00);
        let json_str = serde_json::to_string(&rs).expect("serialization failed");
        let parsed: Value = serde_json::from_str(&json_str).expect("invalid JSON");

        // Check forward chain has connected bypass rules before policy_rules jump
        let forward_rules: Vec<&Value> = parsed["nftables"]
            .as_array()
            .unwrap()
            .iter()
            .filter_map(|c| c.get("rule"))
            .filter(|r| r["chain"] == "forward")
            .collect();

        // First rule should be IPv4 connected bypass, second IPv6, then ct restore, then jump
        assert!(forward_rules.len() >= 4, "forward must have bypass + normal rules");
        let first_str = serde_json::to_string(&forward_rules[0]["expr"]).unwrap();
        assert!(first_str.contains("192.168.1.0"), "must contain IPv4 connected prefix");
        assert!(first_str.contains("10.0.0.0"), "must contain second IPv4 prefix");
        assert!(first_str.contains("accept"), "must accept connected traffic");

        let second_str = serde_json::to_string(&forward_rules[1]["expr"]).unwrap();
        assert!(second_str.contains("fd00::"), "must contain IPv6 connected prefix");

        // Output chain should also have bypass rules
        let output_rules: Vec<&Value> = parsed["nftables"]
            .as_array()
            .unwrap()
            .iter()
            .filter_map(|c| c.get("rule"))
            .filter(|r| r["chain"] == "output")
            .collect();

        let out_first_str = serde_json::to_string(&output_rules[0]["expr"]).unwrap();
        assert!(out_first_str.contains("192.168.1.0"), "output must bypass connected IPv4");
    }

    #[test]
    fn no_connected_networks_means_no_bypass_rules() {
        let (interfaces, policies, rules) = two_interface_setup();
        let rs = ChainBuilder::build_ruleset(&interfaces, &policies, &rules, &[], 0xFF00);
        let json_str = serde_json::to_string(&rs).expect("serialization failed");
        let parsed: Value = serde_json::from_str(&json_str).expect("invalid JSON");

        let forward_rules: Vec<&Value> = parsed["nftables"]
            .as_array()
            .unwrap()
            .iter()
            .filter_map(|c| c.get("rule"))
            .filter(|r| r["chain"] == "forward")
            .collect();

        // Without connected networks, forward chain should have 4 rules:
        // ct restore + bypass_v4 set + bypass_v6 set + jump policy_rules
        assert_eq!(forward_rules.len(), 4, "only dynamic bypass set rules when no connected networks");
    }

    #[test]
    fn use_policy_default_emits_accept() {
        let interfaces = vec![InterfaceInfo {
            name: "wan".to_string(),
            mark: 0x0100,
            table_id: 100,
            device: "eth0".to_string(),
            clamp_mss: false,
        }];

        let policies = vec![PolicyInfo {
            name: "balanced".to_string(),
            members: vec![PolicyMember {
                interface: "wan".to_string(),
                mark: 0x0100,
                weight: 1,
                metric: 0,
            }],
            last_resort: LastResort::Default,
        }];

        let rules = vec![
            // Rule using "default" policy -- should accept, not jump
            RuleInfo {
                src_ip: vec!["10.0.0.0/8".to_string()],
                src_port: None,
                dest_ip: vec![],
                dest_port: None,
                proto: "all".to_string(),
                family: "ipv4".to_string(),
                src_iface: None,
                ipset: None,
                policy: "default".to_string(),
                sticky: None,
                log: false,
            },
            // Normal rule -- should jump to policy chain
            RuleInfo {
                src_ip: vec![],
                src_port: None,
                dest_ip: vec![],
                dest_port: None,
                proto: "all".to_string(),
                family: "any".to_string(),
                src_iface: None,
                ipset: None,
                policy: "balanced".to_string(),
                sticky: None,
                log: false,
            },
        ];

        let rs = ChainBuilder::build_ruleset(&interfaces, &policies, &rules, &[], 0xFF00);
        let json_str = serde_json::to_string(&rs).expect("serialization failed");
        let parsed: Value = serde_json::from_str(&json_str).expect("invalid JSON");

        let policy_rules: Vec<&Value> = parsed["nftables"]
            .as_array()
            .unwrap()
            .iter()
            .filter_map(|c| c.get("rule"))
            .filter(|r| r["chain"] == "policy_rules")
            .collect();

        assert_eq!(policy_rules.len(), 2);

        // First rule (use_policy default) should accept, not jump
        let r0_str = serde_json::to_string(&policy_rules[0]["expr"]).unwrap();
        assert!(r0_str.contains("accept"), "default policy must accept");
        assert!(!r0_str.contains("jump"), "default policy must not jump");

        // Second rule should jump to policy chain
        let r1_str = serde_json::to_string(&policy_rules[1]["expr"]).unwrap();
        assert!(r1_str.contains("policy_balanced"), "normal rule must jump to policy");
    }

    #[test]
    fn balanced_policy_uses_numgen_vmap() {
        let (interfaces, policies, rules) = two_interface_setup();
        let rs = ChainBuilder::build_ruleset(&interfaces, &policies, &rules, &[], 0xFF00);
        let json_str = serde_json::to_string(&rs).expect("serialization failed");
        let parsed: Value = serde_json::from_str(&json_str).expect("invalid JSON");

        let balanced_rules: Vec<&Value> = parsed["nftables"]
            .as_array()
            .unwrap()
            .iter()
            .filter_map(|c| c.get("rule"))
            .filter(|r| r["chain"] == "policy_balanced")
            .collect();

        assert_eq!(
            balanced_rules.len(),
            1,
            "balanced policy should have exactly one rule"
        );

        let rule_str = serde_json::to_string(&balanced_rules[0]["expr"]).unwrap();
        assert!(
            rule_str.contains("numgen"),
            "balanced policy must use numgen for load balancing"
        );
        assert!(
            rule_str.contains("vmap"),
            "balanced policy must use vmap"
        );
        assert!(
            rule_str.contains("mark_wan"),
            "vmap must reference mark_wan"
        );
        assert!(
            rule_str.contains("mark_wanb"),
            "vmap must reference mark_wanb"
        );
    }

    #[test]
    fn single_member_policy_uses_goto() {
        let interfaces = vec![InterfaceInfo {
            name: "wan".to_string(),
            mark: 0x0100,
            table_id: 100,
            device: "eth0".to_string(),
            clamp_mss: false,
        }];

        let policies = vec![PolicyInfo {
            name: "failover".to_string(),
            members: vec![PolicyMember {
                interface: "wan".to_string(),
                mark: 0x0100,
                weight: 1,
                metric: 0,
            }],
            last_resort: LastResort::Default,
        }];

        let rules = vec![RuleInfo {
            src_ip: vec![],
            src_port: None,
            dest_ip: vec![],
            dest_port: None,
            proto: "all".to_string(),
            family: "any".to_string(),
            src_iface: None,
            ipset: None,
            policy: "failover".to_string(),
            sticky: None,
            log: false,
        }];

        let rs = ChainBuilder::build_ruleset(&interfaces, &policies, &rules, &[], 0xFF00);
        let json_str = serde_json::to_string(&rs).expect("serialization failed");
        let parsed: Value = serde_json::from_str(&json_str).expect("invalid JSON");

        let failover_rules: Vec<&Value> = parsed["nftables"]
            .as_array()
            .unwrap()
            .iter()
            .filter_map(|c| c.get("rule"))
            .filter(|r| r["chain"] == "policy_failover")
            .collect();

        assert_eq!(failover_rules.len(), 1);
        let rule_str = serde_json::to_string(&failover_rules[0]["expr"]).unwrap();
        assert!(
            rule_str.contains("goto"),
            "single-member policy should use goto"
        );
        assert!(
            !rule_str.contains("numgen"),
            "single-member policy should not use numgen"
        );
    }

    #[test]
    fn mss_clamping_only_for_enabled_interfaces() {
        let (interfaces, policies, rules) = two_interface_setup();
        let rs = ChainBuilder::build_ruleset(&interfaces, &policies, &rules, &[], 0xFF00);
        let json_str = serde_json::to_string(&rs).expect("serialization failed");
        let parsed: Value = serde_json::from_str(&json_str).expect("invalid JSON");

        let postrouting_rules: Vec<&Value> = parsed["nftables"]
            .as_array()
            .unwrap()
            .iter()
            .filter_map(|c| c.get("rule"))
            .filter(|r| r["chain"] == "postrouting")
            .collect();

        // Only eth0 (wan) has clamp_mss=true; eth1 (wanb) does not
        assert_eq!(
            postrouting_rules.len(),
            1,
            "only one interface has clamp_mss enabled"
        );

        let rule_str = serde_json::to_string(&postrouting_rules[0]["expr"]).unwrap();
        assert!(
            rule_str.contains("eth0"),
            "MSS clamp rule must reference eth0"
        );
        assert!(
            !rule_str.contains("eth1"),
            "MSS clamp rule must not reference eth1"
        );
    }

    #[test]
    fn policy_rules_with_filters() {
        let interfaces = vec![InterfaceInfo {
            name: "wan".to_string(),
            mark: 0x0100,
            table_id: 100,
            device: "eth0".to_string(),
            clamp_mss: false,
        }];

        let policies = vec![PolicyInfo {
            name: "direct".to_string(),
            members: vec![PolicyMember {
                interface: "wan".to_string(),
                mark: 0x0100,
                weight: 1,
                metric: 0,
            }],
            last_resort: LastResort::Default,
        }];

        let rules = vec![RuleInfo {
            src_ip: vec!["192.168.1.0/24".to_string()],
            src_port: Some("1024-65535".to_string()),
            dest_ip: vec!["10.0.0.0/8".to_string()],
            dest_port: Some("443".to_string()),
            proto: "tcp".to_string(),
            family: "ipv4".to_string(),
            src_iface: None,
            ipset: None,
            policy: "direct".to_string(),
            sticky: None,
            log: false,
        }];

        let rs = ChainBuilder::build_ruleset(&interfaces, &policies, &rules, &[], 0xFF00);
        let json_str = serde_json::to_string(&rs).expect("serialization failed");
        let parsed: Value = serde_json::from_str(&json_str).expect("invalid JSON");

        let policy_rules: Vec<&Value> = parsed["nftables"]
            .as_array()
            .unwrap()
            .iter()
            .filter_map(|c| c.get("rule"))
            .filter(|r| r["chain"] == "policy_rules")
            .collect();

        assert_eq!(policy_rules.len(), 1);
        let rule_str = serde_json::to_string(&policy_rules[0]["expr"]).unwrap();
        assert!(rule_str.contains("nfproto"), "must filter on address family");
        assert!(rule_str.contains("l4proto"), "must filter on protocol");
        assert!(rule_str.contains("192.168.1.0/24"), "must match src IP");
        assert!(rule_str.contains("10.0.0.0/8"), "must match dst IP");
        assert!(rule_str.contains("sport"), "must match src port");
        assert!(rule_str.contains("dport"), "must match dst port");
        assert!(rule_str.contains("policy_direct"), "must jump to policy chain");

        // Verify ports are integers/ranges, not strings
        let expr = &policy_rules[0]["expr"];
        let sport_match = expr.as_array().unwrap().iter().find(|e| {
            e["match"]["left"]["payload"]["field"] == "sport"
        }).unwrap();
        // "1024-65535" should be a range object
        assert_eq!(sport_match["match"]["right"]["range"][0], 1024);
        assert_eq!(sport_match["match"]["right"]["range"][1], 65535);

        let dport_match = expr.as_array().unwrap().iter().find(|e| {
            e["match"]["left"]["payload"]["field"] == "dport"
        }).unwrap();
        // "443" should be an integer, not a string
        assert_eq!(dport_match["match"]["right"], 443);
        assert!(dport_match["match"]["right"].is_number(), "port must be an integer");
    }

    #[test]
    fn proto_all_with_ports_splits_tcp_udp() {
        let interfaces = vec![InterfaceInfo {
            name: "wan".to_string(),
            mark: 0x0100,
            table_id: 100,
            device: "eth0".to_string(),
            clamp_mss: false,
        }];

        let policies = vec![PolicyInfo {
            name: "balanced".to_string(),
            members: vec![PolicyMember {
                interface: "wan".to_string(),
                mark: 0x0100,
                weight: 1,
                metric: 0,
            }],
            last_resort: LastResort::Default,
        }];

        let rules = vec![RuleInfo {
            src_ip: vec![],
            src_port: None,
            dest_ip: vec![],
            dest_port: Some("80".to_string()),
            proto: "all".to_string(),
            family: "any".to_string(),
            src_iface: None,
            ipset: None,
            policy: "balanced".to_string(),
            sticky: None,
            log: false,
        }];

        let rs = ChainBuilder::build_ruleset(&interfaces, &policies, &rules, &[], 0xFF00);
        let json_str = serde_json::to_string(&rs).expect("serialization failed");
        let parsed: Value = serde_json::from_str(&json_str).expect("invalid JSON");

        let policy_rules: Vec<&Value> = parsed["nftables"]
            .as_array()
            .unwrap()
            .iter()
            .filter_map(|c| c.get("rule"))
            .filter(|r| r["chain"] == "policy_rules")
            .collect();

        // proto:all + dest_port should produce two rules: one TCP, one UDP
        assert_eq!(policy_rules.len(), 2, "must split into TCP and UDP rules");

        let rule0_str = serde_json::to_string(&policy_rules[0]["expr"]).unwrap();
        let rule1_str = serde_json::to_string(&policy_rules[1]["expr"]).unwrap();

        assert!(rule0_str.contains("\"tcp\""), "first rule must match TCP");
        assert!(rule1_str.contains("\"udp\""), "second rule must match UDP");

        // Both should have dport match
        assert!(rule0_str.contains("dport"), "TCP rule must match dport");
        assert!(rule1_str.contains("dport"), "UDP rule must match dport");
    }

    #[test]
    fn proto_all_without_ports_stays_single_rule() {
        let interfaces = vec![InterfaceInfo {
            name: "wan".to_string(),
            mark: 0x0100,
            table_id: 100,
            device: "eth0".to_string(),
            clamp_mss: false,
        }];

        let policies = vec![PolicyInfo {
            name: "balanced".to_string(),
            members: vec![PolicyMember {
                interface: "wan".to_string(),
                mark: 0x0100,
                weight: 1,
                metric: 0,
            }],
            last_resort: LastResort::Default,
        }];

        let rules = vec![RuleInfo {
            src_ip: vec!["10.0.0.0/8".to_string()],
            src_port: None,
            dest_ip: vec![],
            dest_port: None,
            proto: "all".to_string(),
            family: "ipv4".to_string(),
            src_iface: None,
            ipset: None,
            policy: "balanced".to_string(),
            sticky: None,
            log: false,
        }];

        let rs = ChainBuilder::build_ruleset(&interfaces, &policies, &rules, &[], 0xFF00);
        let json_str = serde_json::to_string(&rs).expect("serialization failed");
        let parsed: Value = serde_json::from_str(&json_str).expect("invalid JSON");

        let policy_rules: Vec<&Value> = parsed["nftables"]
            .as_array()
            .unwrap()
            .iter()
            .filter_map(|c| c.get("rule"))
            .filter(|r| r["chain"] == "policy_rules")
            .collect();

        // proto:all without ports should stay as a single rule with no l4proto match
        assert_eq!(policy_rules.len(), 1, "must remain a single rule");
        let rule_str = serde_json::to_string(&policy_rules[0]["expr"]).unwrap();
        assert!(!rule_str.contains("l4proto"), "must not filter on protocol");
    }

    #[test]
    fn failover_policy_tiered_members() {
        let interfaces = vec![
            InterfaceInfo {
                name: "wan".to_string(),
                mark: 0x0100,
                table_id: 100,
                device: "eth0".to_string(),
                clamp_mss: false,
            },
            InterfaceInfo {
                name: "wanb".to_string(),
                mark: 0x0200,
                table_id: 200,
                device: "eth1".to_string(),
                clamp_mss: false,
            },
        ];

        // wan is metric 0 (primary), wanb is metric 10 (backup)
        let policies = vec![PolicyInfo {
            name: "failover".to_string(),
            members: vec![
                PolicyMember {
                    interface: "wan".to_string(),
                    mark: 0x0100,
                    weight: 1,
                    metric: 0,
                },
                PolicyMember {
                    interface: "wanb".to_string(),
                    mark: 0x0200,
                    weight: 1,
                    metric: 10,
                },
            ],
            last_resort: LastResort::Default,
        }];

        let rules = vec![RuleInfo {
            src_ip: vec![],
            src_port: None,
            dest_ip: vec![],
            dest_port: None,
            proto: "all".to_string(),
            family: "any".to_string(),
            src_iface: None,
            ipset: None,
            policy: "failover".to_string(),
            sticky: None,
            log: false,
        }];

        let rs = ChainBuilder::build_ruleset(&interfaces, &policies, &rules, &[], 0xFF00);
        let json_str = serde_json::to_string(&rs).expect("serialization failed");
        let parsed: Value = serde_json::from_str(&json_str).expect("invalid JSON");

        let failover_rules: Vec<&Value> = parsed["nftables"]
            .as_array()
            .unwrap()
            .iter()
            .filter_map(|c| c.get("rule"))
            .filter(|r| r["chain"] == "policy_failover")
            .collect();

        // Two tiers -> two rules, each a single goto
        assert_eq!(
            failover_rules.len(),
            2,
            "failover policy with two tiers should have two rules"
        );

        let first_str = serde_json::to_string(&failover_rules[0]["expr"]).unwrap();
        let second_str = serde_json::to_string(&failover_rules[1]["expr"]).unwrap();

        // Primary (metric 0) should come first
        assert!(
            first_str.contains("mark_wan"),
            "first tier should goto mark_wan"
        );
        assert!(
            second_str.contains("mark_wanb"),
            "second tier should goto mark_wanb"
        );
    }

    #[test]
    fn ipv6_addresses_use_ip6_protocol() {
        let interfaces = vec![InterfaceInfo {
            name: "wan".to_string(),
            mark: 0x0100,
            table_id: 100,
            device: "eth0".to_string(),
            clamp_mss: false,
        }];

        let policies = vec![PolicyInfo {
            name: "direct".to_string(),
            members: vec![PolicyMember {
                interface: "wan".to_string(),
                mark: 0x0100,
                weight: 1,
                metric: 0,
            }],
            last_resort: LastResort::Default,
        }];

        let rules = vec![RuleInfo {
            src_ip: vec!["2001:db8::/32".to_string()],
            src_port: None,
            dest_ip: vec!["10.0.0.0/8".to_string()],
            dest_port: None,
            proto: "all".to_string(),
            family: "any".to_string(),
            src_iface: None,
            ipset: None,
            policy: "direct".to_string(),
            sticky: None,
            log: false,
        }];

        let rs = ChainBuilder::build_ruleset(&interfaces, &policies, &rules, &[], 0xFF00);
        let json_str = serde_json::to_string(&rs).expect("serialization failed");

        let parsed: Value = serde_json::from_str(&json_str).expect("invalid JSON");
        let policy_rules: Vec<&Value> = parsed["nftables"]
            .as_array()
            .unwrap()
            .iter()
            .filter_map(|c| c.get("rule"))
            .filter(|r| r["chain"] == "policy_rules")
            .collect();
        let rule_str = serde_json::to_string(&policy_rules[0]["expr"]).unwrap();

        // IPv6 src address should use "ip6" protocol
        assert!(
            rule_str.contains(r#""protocol":"ip6"#) && rule_str.contains("saddr"),
            "IPv6 src address must use ip6 protocol, got: {rule_str}"
        );
        // IPv4 dst address should use "ip" protocol
        assert!(
            rule_str.contains(r#""protocol":"ip"#) && rule_str.contains("daddr"),
            "IPv4 dst address must use ip protocol, got: {rule_str}"
        );
    }

    #[test]
    fn empty_policy_with_last_resort_unreachable() {
        let interfaces = vec![];
        let policies = vec![PolicyInfo {
            name: "blocked".to_string(),
            members: vec![],
            last_resort: LastResort::Unreachable,
        }];
        let rules = vec![RuleInfo {
            src_ip: vec![],
            src_port: None,
            dest_ip: vec![],
            dest_port: None,
            proto: "all".to_string(),
            family: "any".to_string(),
            src_iface: None,
            ipset: None,
            policy: "blocked".to_string(),
            sticky: None,
            log: false,
        }];

        let rs = ChainBuilder::build_ruleset(&interfaces, &policies, &rules, &[], 0xFF00);
        let json_str = serde_json::to_string(&rs).expect("serialization failed");
        let parsed: Value = serde_json::from_str(&json_str).expect("invalid JSON");

        let policy_chain_rules: Vec<&Value> = parsed["nftables"]
            .as_array()
            .unwrap()
            .iter()
            .filter_map(|c| c.get("rule"))
            .filter(|r| r["chain"] == "policy_blocked")
            .collect();

        assert_eq!(policy_chain_rules.len(), 1, "unreachable policy must have one rule");
        let rule_str = serde_json::to_string(&policy_chain_rules[0]["expr"]).unwrap();
        assert!(rule_str.contains("reject"), "unreachable last_resort must reject, got: {rule_str}");
    }

    #[test]
    fn empty_policy_with_last_resort_blackhole() {
        let interfaces = vec![];
        let policies = vec![PolicyInfo {
            name: "dropped".to_string(),
            members: vec![],
            last_resort: LastResort::Blackhole,
        }];
        let rules = vec![];

        let rs = ChainBuilder::build_ruleset(&interfaces, &policies, &rules, &[], 0xFF00);
        let json_str = serde_json::to_string(&rs).expect("serialization failed");
        let parsed: Value = serde_json::from_str(&json_str).expect("invalid JSON");

        let policy_chain_rules: Vec<&Value> = parsed["nftables"]
            .as_array()
            .unwrap()
            .iter()
            .filter_map(|c| c.get("rule"))
            .filter(|r| r["chain"] == "policy_dropped")
            .collect();

        assert_eq!(policy_chain_rules.len(), 1, "blackhole policy must have one rule");
        let rule_str = serde_json::to_string(&policy_chain_rules[0]["expr"]).unwrap();
        assert!(rule_str.contains("drop"), "blackhole last_resort must drop, got: {rule_str}");
    }

    #[test]
    fn empty_policy_with_last_resort_default() {
        let interfaces = vec![];
        let policies = vec![PolicyInfo {
            name: "fallback".to_string(),
            members: vec![],
            last_resort: LastResort::Default,
        }];
        let rules = vec![];

        let rs = ChainBuilder::build_ruleset(&interfaces, &policies, &rules, &[], 0xFF00);
        let json_str = serde_json::to_string(&rs).expect("serialization failed");
        let parsed: Value = serde_json::from_str(&json_str).expect("invalid JSON");

        let policy_chain_rules: Vec<&Value> = parsed["nftables"]
            .as_array()
            .unwrap()
            .iter()
            .filter_map(|c| c.get("rule"))
            .filter(|r| r["chain"] == "policy_fallback")
            .collect();

        assert_eq!(policy_chain_rules.len(), 0, "default last_resort must have no rules (fall through)");
    }

    #[test]
    fn sticky_src_ip_creates_map_and_chain() {
        let interfaces = vec![InterfaceInfo {
            name: "wan".to_string(),
            mark: 0x0100,
            table_id: 100,
            device: "eth0".to_string(),
            clamp_mss: false,
        }];

        let policies = vec![PolicyInfo {
            name: "balanced".to_string(),
            members: vec![PolicyMember {
                interface: "wan".to_string(),
                mark: 0x0100,
                weight: 1,
                metric: 0,
            }],
            last_resort: LastResort::Default,
        }];

        let rules = vec![RuleInfo {
            src_ip: vec![],
            src_port: None,
            dest_ip: vec![],
            dest_port: None,
            proto: "all".to_string(),
            family: "ipv4".to_string(),
            src_iface: None,
            ipset: None,
            policy: "balanced".to_string(),
            sticky: Some(StickyInfo {
                mode: "src_ip".to_string(),
                timeout: 600,
            }),
            log: false,
        }];

        let rs = ChainBuilder::build_ruleset(&interfaces, &policies, &rules, &[], 0xFF00);
        let json_str = serde_json::to_string(&rs).expect("serialization failed");
        let parsed: Value = serde_json::from_str(&json_str).expect("invalid JSON");
        let commands = parsed["nftables"].as_array().unwrap();

        // Must have a map definition
        let maps: Vec<&Value> = commands.iter().filter_map(|c| c.get("map")).collect();
        assert_eq!(maps.len(), 1, "must have one sticky map");
        assert_eq!(maps[0]["name"], "sticky_r0");
        assert_eq!(maps[0]["type"], "ipv4_addr");
        assert_eq!(maps[0]["map"], "mark");
        assert_eq!(maps[0]["timeout"], 600);

        // Must have a sticky helper chain
        let chain_names: Vec<&str> = commands
            .iter()
            .filter_map(|c| c.get("chain"))
            .filter_map(|c| c["name"].as_str())
            .collect();
        assert!(chain_names.contains(&"sticky_r0"), "must have sticky_r0 chain");

        // policy_rules should jump to sticky_r0, not directly to policy
        let policy_rules: Vec<&Value> = commands
            .iter()
            .filter_map(|c| c.get("rule"))
            .filter(|r| r["chain"] == "policy_rules")
            .collect();
        let rule_str = serde_json::to_string(&policy_rules[0]["expr"]).unwrap();
        assert!(
            rule_str.contains("sticky_r0"),
            "policy_rules must jump to sticky chain, got: {rule_str}"
        );

        // sticky chain should have: lookup rule, mark assignment, update rule
        let sticky_rules: Vec<&Value> = commands
            .iter()
            .filter_map(|c| c.get("rule"))
            .filter(|r| r["chain"] == "sticky_r0")
            .collect();
        assert!(sticky_rules.len() >= 3, "sticky chain needs lookup + mark + update rules");

        // First rule should contain map lookup
        let first = serde_json::to_string(&sticky_rules[0]["expr"]).unwrap();
        assert!(first.contains("sticky_r0"), "first rule must look up sticky map");

        // Second rule should set the mark directly (inlined policy dispatch)
        let second = serde_json::to_string(&sticky_rules[1]["expr"]).unwrap();
        assert!(second.contains("mangle"), "second rule must set mark directly");
        assert!(second.contains(&format!("{}", 0x0100)), "second rule must use interface mark");

        // Third rule should update the map
        let third = serde_json::to_string(&sticky_rules[2]["expr"]).unwrap();
        assert!(third.contains("update"), "third rule must update sticky map");
    }

    #[test]
    fn sticky_flow_mode_no_map() {
        let interfaces = vec![InterfaceInfo {
            name: "wan".to_string(),
            mark: 0x0100,
            table_id: 100,
            device: "eth0".to_string(),
            clamp_mss: false,
        }];

        let policies = vec![PolicyInfo {
            name: "balanced".to_string(),
            members: vec![PolicyMember {
                interface: "wan".to_string(),
                mark: 0x0100,
                weight: 1,
                metric: 0,
            }],
            last_resort: LastResort::Default,
        }];

        let rules = vec![RuleInfo {
            src_ip: vec![],
            src_port: None,
            dest_ip: vec![],
            dest_port: None,
            proto: "all".to_string(),
            family: "any".to_string(),
            src_iface: None,
            ipset: None,
            policy: "balanced".to_string(),
            sticky: Some(StickyInfo {
                mode: "flow".to_string(),
                timeout: 600,
            }),
            log: false,
        }];

        let rs = ChainBuilder::build_ruleset(&interfaces, &policies, &rules, &[], 0xFF00);
        let json_str = serde_json::to_string(&rs).expect("serialization failed");
        let parsed: Value = serde_json::from_str(&json_str).expect("invalid JSON");
        let commands = parsed["nftables"].as_array().unwrap();

        // Flow mode should NOT create maps (ct mark handles it)
        let maps: Vec<&Value> = commands.iter().filter_map(|c| c.get("map")).collect();
        assert!(maps.is_empty(), "flow mode should not create maps");

        // Should jump directly to policy, not to a sticky chain
        let policy_rules: Vec<&Value> = commands
            .iter()
            .filter_map(|c| c.get("rule"))
            .filter(|r| r["chain"] == "policy_rules")
            .collect();
        let rule_str = serde_json::to_string(&policy_rules[0]["expr"]).unwrap();
        assert!(
            rule_str.contains("policy_balanced"),
            "flow mode should jump directly to policy, got: {rule_str}"
        );
    }

    #[test]
    fn sticky_any_family_creates_dual_maps() {
        let interfaces = vec![InterfaceInfo {
            name: "wan".to_string(),
            mark: 0x0100,
            table_id: 100,
            device: "eth0".to_string(),
            clamp_mss: false,
        }];

        let policies = vec![PolicyInfo {
            name: "balanced".to_string(),
            members: vec![PolicyMember {
                interface: "wan".to_string(),
                mark: 0x0100,
                weight: 1,
                metric: 0,
            }],
            last_resort: LastResort::Default,
        }];

        let rules = vec![RuleInfo {
            src_ip: vec![],
            src_port: None,
            dest_ip: vec![],
            dest_port: None,
            proto: "all".to_string(),
            family: "any".to_string(),
            src_iface: None,
            ipset: None,
            policy: "balanced".to_string(),
            sticky: Some(StickyInfo {
                mode: "src_ip".to_string(),
                timeout: 300,
            }),
            log: false,
        }];

        let rs = ChainBuilder::build_ruleset(&interfaces, &policies, &rules, &[], 0xFF00);
        let json_str = serde_json::to_string(&rs).expect("serialization failed");
        let parsed: Value = serde_json::from_str(&json_str).expect("invalid JSON");
        let commands = parsed["nftables"].as_array().unwrap();

        // "any" family should create both v4 and v6 maps
        let maps: Vec<&Value> = commands.iter().filter_map(|c| c.get("map")).collect();
        assert_eq!(maps.len(), 2, "any family must create both v4 and v6 maps");

        let map_names: Vec<&str> = maps.iter().filter_map(|m| m["name"].as_str()).collect();
        assert!(map_names.contains(&"sticky_r0_v4"), "must have v4 map");
        assert!(map_names.contains(&"sticky_r0_v6"), "must have v6 map");
    }

    #[test]
    fn named_set_matching_in_rules() {
        let interfaces = vec![InterfaceInfo {
            name: "wan".to_string(),
            mark: 0x0100,
            table_id: 100,
            device: "eth0".to_string(),
            clamp_mss: false,
        }];

        let policies = vec![PolicyInfo {
            name: "direct".to_string(),
            members: vec![PolicyMember {
                interface: "wan".to_string(),
                mark: 0x0100,
                weight: 1,
                metric: 0,
            }],
            last_resort: LastResort::Default,
        }];

        let rules = vec![
            // IPv4 named set on src_ip
            RuleInfo {
                src_ip: vec!["@vpn_clients".to_string()],
                src_port: None,
                dest_ip: vec![],
                dest_port: None,
                proto: "all".to_string(),
                family: "ipv4".to_string(),
                src_iface: None,
                ipset: None,
                policy: "direct".to_string(),
                sticky: None,
                log: false,
            },
            // IPv6 named set on dest_ip
            RuleInfo {
                src_ip: vec![],
                src_port: None,
                dest_ip: vec!["@blocked_v6".to_string()],
                dest_port: None,
                proto: "all".to_string(),
                family: "ipv6".to_string(),
                src_iface: None,
                ipset: None,
                policy: "direct".to_string(),
                sticky: None,
                log: false,
            },
        ];

        let rs = ChainBuilder::build_ruleset(&interfaces, &policies, &rules, &[], 0xFF00);
        let json_str = serde_json::to_string(&rs).expect("serialization failed");
        let parsed: Value = serde_json::from_str(&json_str).expect("invalid JSON");

        let policy_rules: Vec<&Value> = parsed["nftables"]
            .as_array()
            .unwrap()
            .iter()
            .filter_map(|c| c.get("rule"))
            .filter(|r| r["chain"] == "policy_rules")
            .collect();

        assert_eq!(policy_rules.len(), 2);

        // First rule: src_ip = @vpn_clients with IPv4
        let expr0 = &policy_rules[0]["expr"];
        let src_match = expr0.as_array().unwrap().iter().find(|e| {
            e["match"]["left"]["payload"]["field"] == "saddr"
        }).expect("must have saddr match");
        assert_eq!(
            src_match["match"]["left"]["payload"]["protocol"], "ip",
            "IPv4 set must use 'ip' protocol"
        );
        assert_eq!(
            src_match["match"]["right"]["@"], "vpn_clients",
            "must reference named set"
        );

        // Second rule: dest_ip = @blocked_v6 with IPv6
        let expr1 = &policy_rules[1]["expr"];
        let dst_match = expr1.as_array().unwrap().iter().find(|e| {
            e["match"]["left"]["payload"]["field"] == "daddr"
        }).expect("must have daddr match");
        assert_eq!(
            dst_match["match"]["left"]["payload"]["protocol"], "ip6",
            "IPv6 set must use 'ip6' protocol"
        );
        assert_eq!(
            dst_match["match"]["right"]["@"], "blocked_v6",
            "must reference named set"
        );
    }

    #[test]
    fn per_rule_logging() {
        let (interfaces, policies, _) = two_interface_setup();

        let rules = vec![
            // Rule with logging enabled
            RuleInfo {
                src_ip: vec![],
                src_port: None,
                dest_ip: vec![],
                dest_port: None,
                proto: "all".to_string(),
                family: "any".to_string(),
                src_iface: None,
                ipset: None,
                policy: "balanced".to_string(),
                sticky: None,
                log: true,
            },
            // Rule without logging
            RuleInfo {
                src_ip: vec![],
                src_port: None,
                dest_ip: vec![],
                dest_port: None,
                proto: "tcp".to_string(),
                family: "any".to_string(),
                src_iface: None,
                ipset: None,
                policy: "balanced".to_string(),
                sticky: None,
                log: false,
            },
        ];

        let rs = ChainBuilder::build_ruleset(&interfaces, &policies, &rules, &[], 0xFF00);
        let json_str = serde_json::to_string(&rs).expect("serialization failed");
        let parsed: Value = serde_json::from_str(&json_str).expect("invalid JSON");

        let policy_rules: Vec<&Value> = parsed["nftables"]
            .as_array()
            .unwrap()
            .iter()
            .filter_map(|c| c.get("rule"))
            .filter(|r| r["chain"] == "policy_rules")
            .collect();

        assert_eq!(policy_rules.len(), 2);

        // First rule should have a log statement
        let expr0 = policy_rules[0]["expr"].as_array().unwrap();
        let has_log = expr0.iter().any(|e| e.get("log").is_some());
        assert!(has_log, "logged rule must have log expression");
        let log_entry = expr0.iter().find(|e| e.get("log").is_some()).unwrap();
        assert_eq!(log_entry["log"]["prefix"], "nopal:balanced ");

        // Second rule should NOT have a log statement
        let expr1 = policy_rules[1]["expr"].as_array().unwrap();
        let has_log = expr1.iter().any(|e| e.get("log").is_some());
        assert!(!has_log, "non-logged rule must not have log expression");
    }
}
