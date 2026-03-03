use super::schema::NopalConfig;

/// Result of comparing two configurations.
///
/// Tracks which sections changed so the daemon can apply targeted updates
/// instead of a full teardown/rebuild on every reload.
pub struct ConfigDiff {
    /// Whether any change was detected at all.
    pub changed: bool,
    /// Global settings changed (ipv6_enabled, conntrack_flush, etc.).
    /// Requires a full rebuild.
    pub globals_changed: bool,
    /// Interface names that were added in the new config.
    pub added_interfaces: Vec<String>,
    /// Interface names that were removed from the old config.
    pub removed_interfaces: Vec<String>,
    /// Interface names that exist in both configs but have different settings.
    pub changed_interfaces: Vec<String>,
    /// Members, policies, or rules changed. Requires nftables regeneration.
    pub routing_changed: bool,
    /// Interface order changed. Requires full rebuild because tracker.index
    /// values correspond to positions in config.interfaces.
    pub interface_order_changed: bool,
}

impl ConfigDiff {
    /// Whether a full rebuild is required (globals, interface set changes).
    pub fn needs_full_rebuild(&self) -> bool {
        self.globals_changed
            || !self.added_interfaces.is_empty()
            || !self.removed_interfaces.is_empty()
            || self.interface_order_changed
    }

    /// Whether nftables regeneration is needed (routing policy changes or
    /// interface changes that affect nftables).
    #[allow(dead_code)]
    pub fn needs_nftables(&self) -> bool {
        self.routing_changed || !self.changed_interfaces.is_empty()
    }
}

/// Compare two configurations and return a detailed diff summary.
pub fn diff(old: &NopalConfig, new: &NopalConfig) -> ConfigDiff {
    if old == new {
        return ConfigDiff {
            changed: false,
            globals_changed: false,
            added_interfaces: Vec::new(),
            removed_interfaces: Vec::new(),
            changed_interfaces: Vec::new(),
            routing_changed: false,
            interface_order_changed: false,
        };
    }

    let globals_changed = old.globals != new.globals;

    // Interface diffs: match by name
    let mut added_interfaces = Vec::new();
    let mut removed_interfaces = Vec::new();
    let mut changed_interfaces = Vec::new();

    for new_iface in &new.interfaces {
        match old.interfaces.iter().find(|o| o.name == new_iface.name) {
            Some(old_iface) => {
                if old_iface != new_iface {
                    changed_interfaces.push(new_iface.name.clone());
                }
            }
            None => added_interfaces.push(new_iface.name.clone()),
        }
    }
    for old_iface in &old.interfaces {
        if !new.interfaces.iter().any(|n| n.name == old_iface.name) {
            removed_interfaces.push(old_iface.name.clone());
        }
    }

    // Detect interface reorder: same set of names but different positions.
    // tracker.index relies on position matching, so reorder requires rebuild.
    let interface_order_changed = added_interfaces.is_empty()
        && removed_interfaces.is_empty()
        && old.interfaces.iter().map(|i| &i.name).collect::<Vec<_>>()
            != new.interfaces.iter().map(|i| &i.name).collect::<Vec<_>>();

    // Members/policies/rules affect nftables routing
    let routing_changed = old.members != new.members
        || old.policies != new.policies
        || old.rules != new.rules;

    ConfigDiff {
        changed: true,
        globals_changed,
        added_interfaces,
        removed_interfaces,
        changed_interfaces,
        routing_changed,
        interface_order_changed,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::schema::*;

    fn minimal_config() -> NopalConfig {
        NopalConfig {
            globals: GlobalsConfig::default(),
            interfaces: Vec::new(),
            members: Vec::new(),
            policies: Vec::new(),
            rules: Vec::new(),
        }
    }

    fn test_interface(name: &str) -> InterfaceConfig {
        InterfaceConfig {
            name: name.to_string(),
            device: format!("eth-{name}"),
            ..InterfaceConfig::default()
        }
    }

    #[test]
    fn identical_configs_not_changed() {
        let a = minimal_config();
        let b = minimal_config();
        let d = diff(&a, &b);
        assert!(!d.changed);
        assert!(!d.globals_changed);
        assert!(d.added_interfaces.is_empty());
        assert!(d.removed_interfaces.is_empty());
        assert!(d.changed_interfaces.is_empty());
        assert!(!d.routing_changed);
    }

    #[test]
    fn different_configs_are_changed() {
        let a = minimal_config();
        let mut b = minimal_config();
        b.globals.enabled = false;
        let d = diff(&a, &b);
        assert!(d.changed);
        assert!(d.globals_changed);
    }

    #[test]
    fn interface_added() {
        let a = minimal_config();
        let mut b = minimal_config();
        b.interfaces.push(test_interface("wan"));
        let d = diff(&a, &b);
        assert!(d.changed);
        assert!(!d.globals_changed);
        assert_eq!(d.added_interfaces, vec!["wan"]);
        assert!(d.removed_interfaces.is_empty());
        assert!(d.needs_full_rebuild());
    }

    #[test]
    fn interface_removed() {
        let mut a = minimal_config();
        a.interfaces.push(test_interface("wan"));
        let b = minimal_config();
        let d = diff(&a, &b);
        assert!(d.changed);
        assert_eq!(d.removed_interfaces, vec!["wan"]);
        assert!(d.added_interfaces.is_empty());
        assert!(d.needs_full_rebuild());
    }

    #[test]
    fn interface_changed() {
        let mut a = minimal_config();
        a.interfaces.push(test_interface("wan"));
        let mut b = minimal_config();
        let mut wan = test_interface("wan");
        wan.probe_interval = 10;
        b.interfaces.push(wan);
        let d = diff(&a, &b);
        assert!(d.changed);
        assert!(d.added_interfaces.is_empty());
        assert!(d.removed_interfaces.is_empty());
        assert_eq!(d.changed_interfaces, vec!["wan"]);
        assert!(!d.needs_full_rebuild());
    }

    #[test]
    fn policy_change_only() {
        let mut a = minimal_config();
        a.policies.push(PolicyConfig {
            name: "balanced".into(),
            members: vec!["wan_m".into()],
            last_resort: LastResort::Default,
        });
        let mut b = minimal_config();
        b.policies.push(PolicyConfig {
            name: "balanced".into(),
            members: vec!["wan_m".into(), "lte_m".into()],
            last_resort: LastResort::Default,
        });
        let d = diff(&a, &b);
        assert!(d.changed);
        assert!(!d.globals_changed);
        assert!(d.added_interfaces.is_empty());
        assert!(d.changed_interfaces.is_empty());
        assert!(d.routing_changed);
        assert!(!d.needs_full_rebuild());
        assert!(d.needs_nftables());
    }
}
