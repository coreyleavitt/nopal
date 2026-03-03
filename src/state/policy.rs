use crate::config::schema::{LastResort, MemberConfig, PolicyConfig};
use crate::state::InterfaceTracker;

/// A resolved policy with only active (online) members, organized by tier.
#[derive(Debug)]
pub struct ResolvedPolicy {
    pub name: String,
    /// Tiers sorted by metric (lowest first). Each tier has members at the same metric level.
    pub tiers: Vec<Tier>,
    pub last_resort: LastResort,
}

/// A group of members at the same metric (priority) level.
#[derive(Debug)]
pub struct Tier {
    pub metric: u32,
    pub members: Vec<ActiveMember>,
}

/// A member whose interface is currently online.
#[derive(Debug, Clone)]
pub struct ActiveMember {
    pub interface: String,
    pub mark: u32,
    pub weight: u32,
}

/// Resolve a policy config against current interface states.
///
/// Filters to only online interfaces, groups by metric into tiers, sorts
/// tiers by metric (lowest = highest priority). The active tier is the first
/// one with at least one online member.
pub fn resolve_policy(
    policy: &PolicyConfig,
    members: &[MemberConfig],
    trackers: &[InterfaceTracker],
) -> ResolvedPolicy {
    // Collect all members that are online
    let mut active: Vec<(u32, ActiveMember)> = Vec::new();

    for member_name in &policy.members {
        let Some(member) = members.iter().find(|m| &m.name == member_name) else {
            continue;
        };
        let Some(tracker) = trackers.iter().find(|t| t.name == member.interface) else {
            continue;
        };
        if !tracker.is_active() {
            continue;
        }
        active.push((
            member.metric,
            ActiveMember {
                interface: member.interface.clone(),
                mark: tracker.mark,
                weight: member.weight,
            },
        ));
    }

    // Group by metric into tiers
    active.sort_by_key(|(metric, _)| *metric);

    let mut tiers: Vec<Tier> = Vec::new();
    for (metric, member) in active {
        if let Some(tier) = tiers.last_mut() {
            if tier.metric == metric {
                tier.members.push(member);
                continue;
            }
        }
        tiers.push(Tier {
            metric,
            members: vec![member],
        });
    }

    ResolvedPolicy {
        name: policy.name.clone(),
        tiers,
        last_resort: policy.last_resort,
    }
}

impl ResolvedPolicy {
    /// Get the active tier (first tier with members, i.e. lowest metric).
    pub fn active_tier(&self) -> Option<&Tier> {
        self.tiers.first()
    }

    /// Returns true if no interfaces are available for this policy.
    #[allow(dead_code)]
    pub fn is_empty(&self) -> bool {
        self.tiers.is_empty()
    }

    /// Total weight across the active tier (for nftables numgen).
    #[allow(dead_code)]
    pub fn active_total_weight(&self) -> u32 {
        self.active_tier()
            .map(|t| t.members.iter().map(|m| m.weight).sum())
            .unwrap_or(0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::schema::LastResort;
    use crate::state::{InterfaceState, InterfaceTracker};

    fn make_tracker(name: &str, index: usize, mark: u32, online: bool) -> InterfaceTracker {
        let mut t = InterfaceTracker::new(
            name.into(),
            index,
            mark,
            100 + index as u32,
            format!("eth0.{}", index + 2),
            3,
            5,
        );
        if online {
            t.state = InterfaceState::Online;
        }
        t
    }

    #[test]
    fn resolve_balanced_both_online() {
        let policy = PolicyConfig {
            name: "balanced".into(),
            members: vec!["wan_m1_w50".into(), "wanb_m1_w50".into()],
            last_resort: LastResort::Default,
        };
        let members = vec![
            MemberConfig { name: "wan_m1_w50".into(), interface: "wan".into(), metric: 1, weight: 50 },
            MemberConfig { name: "wanb_m1_w50".into(), interface: "wanb".into(), metric: 1, weight: 50 },
        ];
        let trackers = vec![
            make_tracker("wan", 0, 0x0100, true),
            make_tracker("wanb", 1, 0x0200, true),
        ];

        let resolved = resolve_policy(&policy, &members, &trackers);
        assert_eq!(resolved.tiers.len(), 1);
        assert_eq!(resolved.active_tier().unwrap().members.len(), 2);
        assert_eq!(resolved.active_total_weight(), 100);
    }

    #[test]
    fn resolve_failover_primary_down() {
        let policy = PolicyConfig {
            name: "failover".into(),
            members: vec!["wan_m1_w100".into(), "wanb_m2_w100".into()],
            last_resort: LastResort::Default,
        };
        let members = vec![
            MemberConfig { name: "wan_m1_w100".into(), interface: "wan".into(), metric: 1, weight: 100 },
            MemberConfig { name: "wanb_m2_w100".into(), interface: "wanb".into(), metric: 2, weight: 100 },
        ];
        let trackers = vec![
            make_tracker("wan", 0, 0x0100, false),  // offline
            make_tracker("wanb", 1, 0x0200, true),  // online
        ];

        let resolved = resolve_policy(&policy, &members, &trackers);
        assert_eq!(resolved.tiers.len(), 1);
        let tier = resolved.active_tier().unwrap();
        assert_eq!(tier.metric, 2);
        assert_eq!(tier.members[0].interface, "wanb");
    }

    #[test]
    fn resolve_all_down() {
        let policy = PolicyConfig {
            name: "balanced".into(),
            members: vec!["wan_m1_w50".into()],
            last_resort: LastResort::Unreachable,
        };
        let members = vec![
            MemberConfig { name: "wan_m1_w50".into(), interface: "wan".into(), metric: 1, weight: 50 },
        ];
        let trackers = vec![
            make_tracker("wan", 0, 0x0100, false),
        ];

        let resolved = resolve_policy(&policy, &members, &trackers);
        assert!(resolved.is_empty());
        assert_eq!(resolved.last_resort, LastResort::Unreachable);
    }
}
