use crate::state::InterfaceState;

/// Actions to take when an interface transitions state.
/// The daemon processes these after the state machine updates.
#[derive(Debug)]
pub enum TransitionAction {
    /// Regenerate and apply nftables ruleset.
    RegenerateNftables,
    /// Add routes and ip rules for this interface.
    AddRoutes { index: usize },
    /// Remove routes and ip rules for this interface.
    RemoveRoutes { index: usize },
    /// Update DNS (add servers for interface).
    UpdateDns { index: usize },
    /// Remove DNS servers for interface.
    RemoveDns { index: usize },
    /// Broadcast state change event via IPC.
    BroadcastEvent { index: usize, new_state: InterfaceState },
    /// Write interface state to /var/run/nopal/<interface>/status.
    WriteStatus { index: usize, new_state: InterfaceState },
}

/// Determine what actions to take for a state transition.
pub fn actions_for_transition(
    _interface: &str,
    index: usize,
    _mark: u32,
    old_state: InterfaceState,
    new_state: InterfaceState,
) -> Vec<TransitionAction> {
    let mut actions = Vec::new();

    match (old_state, new_state) {
        // Degraded recovering to Online: routes and DNS already present,
        // no routing changes needed (interface remained in policy while degraded).
        (InterfaceState::Degraded, InterfaceState::Online) => {}

        // Going online: add to routing, regenerate rules, update DNS
        (_, InterfaceState::Online) => {
            actions.push(TransitionAction::AddRoutes { index });
            actions.push(TransitionAction::RegenerateNftables);
            actions.push(TransitionAction::UpdateDns { index });
        }

        // Going offline: remove from routing, regenerate rules, remove DNS
        // (conntrack flush is handled by per-interface flush_conntrack triggers in the daemon)
        (InterfaceState::Online | InterfaceState::Degraded, InterfaceState::Offline) => {
            actions.push(TransitionAction::RemoveRoutes { index });
            actions.push(TransitionAction::RegenerateNftables);
            actions.push(TransitionAction::RemoveDns { index });
        }

        // Going to probing from offline: start probes (handled by timer scheduling)
        (InterfaceState::Offline | InterfaceState::Init, InterfaceState::Probing) => {
            // No immediate routing changes; probes will determine next state.
        }

        // Probing to Degraded: interface reached up_count successes but with
        // poor quality. Still reachable, so add routes and include in policy.
        (InterfaceState::Probing, InterfaceState::Degraded) => {
            actions.push(TransitionAction::AddRoutes { index });
            actions.push(TransitionAction::RegenerateNftables);
            actions.push(TransitionAction::UpdateDns { index });
        }

        // Online to Degraded: routes and DNS already present, no routing
        // changes needed (interface remains in policy while degraded).
        (InterfaceState::Online, InterfaceState::Degraded) => {}

        _ => {}
    }

    // Always broadcast state changes via IPC and write status file
    actions.push(TransitionAction::BroadcastEvent {
        index,
        new_state,
    });
    actions.push(TransitionAction::WriteStatus {
        index,
        new_state,
    });

    actions
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn online_transition_adds_routes_and_nftables() {
        let actions = actions_for_transition("wan", 0, 0x0100, InterfaceState::Probing, InterfaceState::Online);
        assert!(actions.iter().any(|a| matches!(a, TransitionAction::AddRoutes { index: 0 })));
        assert!(actions.iter().any(|a| matches!(a, TransitionAction::RegenerateNftables)));
        assert!(actions.iter().any(|a| matches!(a, TransitionAction::UpdateDns { index: 0 })));
    }

    #[test]
    fn offline_transition_removes_routes_and_dns() {
        let actions = actions_for_transition("wan", 0, 0x0100, InterfaceState::Degraded, InterfaceState::Offline);
        assert!(actions.iter().any(|a| matches!(a, TransitionAction::RemoveRoutes { index: 0 })));
        assert!(actions.iter().any(|a| matches!(a, TransitionAction::RegenerateNftables)));
        assert!(actions.iter().any(|a| matches!(a, TransitionAction::RemoveDns { index: 0 })));
    }

    #[test]
    fn degraded_to_online_no_route_changes() {
        let actions = actions_for_transition("wan", 0, 0x0100, InterfaceState::Degraded, InterfaceState::Online);
        assert!(!actions.iter().any(|a| matches!(a, TransitionAction::AddRoutes { .. })));
        assert!(!actions.iter().any(|a| matches!(a, TransitionAction::RegenerateNftables)));
        assert!(actions.iter().any(|a| matches!(a, TransitionAction::WriteStatus { .. })));
    }

    #[test]
    fn probing_to_degraded_adds_routes() {
        let actions = actions_for_transition("wan", 0, 0x0100, InterfaceState::Probing, InterfaceState::Degraded);
        assert!(actions.iter().any(|a| matches!(a, TransitionAction::AddRoutes { index: 0 })));
        assert!(actions.iter().any(|a| matches!(a, TransitionAction::RegenerateNftables)));
        assert!(actions.iter().any(|a| matches!(a, TransitionAction::UpdateDns { index: 0 })));
    }

    #[test]
    fn all_transitions_write_status_file() {
        let transitions = [
            (InterfaceState::Init, InterfaceState::Probing),
            (InterfaceState::Probing, InterfaceState::Online),
            (InterfaceState::Probing, InterfaceState::Degraded),
            (InterfaceState::Online, InterfaceState::Degraded),
            (InterfaceState::Degraded, InterfaceState::Offline),
            (InterfaceState::Degraded, InterfaceState::Online),
        ];

        for (old, new) in transitions {
            let actions = actions_for_transition("wan", 0, 0x0100, old, new);
            assert!(
                actions.iter().any(|a| matches!(a, TransitionAction::WriteStatus { new_state, .. } if *new_state == new)),
                "missing WriteStatus for {old:?} -> {new:?}",
            );
        }
    }
}
