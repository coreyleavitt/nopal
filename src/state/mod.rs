pub mod policy;
pub mod transition;

use serde::Serialize;
use std::fmt;
use std::net::IpAddr;
use std::time::Instant;

use crate::health::dampening::DampeningState;

/// Interface states in the nopal state machine.
///
/// Transitions:
///   Init -> Probing       (netifd reports interface up)
///   Probing -> Online     (up_count consecutive successes)
///   Online -> Degraded    (probe failures begin accumulating)
///   Degraded -> Online    (probes recover)
///   Degraded -> Offline   (down_count consecutive failures + dampening)
///   Offline -> Probing    (netifd reports interface up again)
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub enum InterfaceState {
    /// Waiting for netifd to report the interface as up.
    Init,
    /// Interface is up, probes running, not yet confirmed online.
    Probing,
    /// Interface is healthy and participating in policies.
    Online,
    /// Interface has started failing probes but hasn't crossed the down threshold.
    Degraded,
    /// Interface is down and removed from policies.
    Offline,
}

impl fmt::Display for InterfaceState {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            InterfaceState::Init => write!(f, "init"),
            InterfaceState::Probing => write!(f, "probing"),
            InterfaceState::Online => write!(f, "online"),
            InterfaceState::Degraded => write!(f, "degraded"),
            InterfaceState::Offline => write!(f, "offline"),
        }
    }
}

/// Per-interface tracking within the state machine.
#[derive(Debug)]
pub struct InterfaceTracker {
    pub name: String,
    pub index: usize,
    pub state: InterfaceState,
    pub mark: u32,
    pub table_id: u32,
    pub device: String,
    /// Cached kernel interface index for the device (0 if not yet resolved).
    pub ifindex: u32,
    /// Consecutive successful probes.
    pub success_count: u32,
    /// Consecutive failed probes.
    pub fail_count: u32,
    /// Required consecutive successes to transition to Online.
    pub up_count: u32,
    /// Required consecutive failures to transition to Offline.
    pub down_count: u32,
    /// Whether this interface is enabled in config.
    pub enabled: bool,
    /// Route dampening state (None if dampening is disabled for this interface).
    pub dampening: Option<DampeningState>,
    /// Average RTT in milliseconds from the quality window (None if no data).
    pub avg_rtt_ms: Option<u32>,
    /// Packet loss percentage (0-100) from the quality window.
    pub loss_percent: u32,
    /// Monotonic instant of the last transition to Online (for uptime tracking).
    pub online_since: Option<Instant>,
    /// Monotonic instant of the last transition to Offline.
    pub offline_since: Option<Instant>,
    /// Source ip rules currently installed for this interface.
    /// Stored as (addr, prefix_len, table_id, priority, family) so they
    /// can be reliably removed even if the device address changes.
    pub source_rules: Vec<(IpAddr, u8, u32, u32, u8)>,
}

impl InterfaceTracker {
    pub fn new(
        name: String,
        index: usize,
        mark: u32,
        table_id: u32,
        device: String,
        up_count: u32,
        down_count: u32,
    ) -> Self {
        let ifindex = {
            let c_name = std::ffi::CString::new(device.as_str()).unwrap_or_default();
            unsafe { libc::if_nametoindex(c_name.as_ptr()) }
        };
        Self {
            name,
            index,
            state: InterfaceState::Init,
            mark,
            table_id,
            device,
            ifindex,
            success_count: 0,
            fail_count: 0,
            up_count,
            down_count,
            enabled: true,
            dampening: None,
            avg_rtt_ms: None,
            loss_percent: 0,
            online_since: None,
            offline_since: None,
            source_rules: Vec::new(),
        }
    }

    /// Enable route dampening with the given parameters.
    pub fn set_dampening(&mut self, halflife: u32, ceiling: u32, suppress: u32, reuse: u32) {
        self.dampening = Some(DampeningState::new(halflife, ceiling, suppress, reuse));
    }

    /// Record a successful probe. Returns new state if a transition occurred.
    ///
    /// When `quality_ok` is false (latency/loss thresholds exceeded), the
    /// interface transitions to Degraded from Online, or stays Degraded if
    /// already there. This does not affect consecutive success/failure
    /// counters used for up/down threshold evaluation.
    ///
    /// If dampening is active and the interface is suppressed, transitions to
    /// Online are blocked until the penalty decays below the reuse threshold.
    pub fn probe_success(&mut self, quality_ok: bool) -> Option<InterfaceState> {
        self.fail_count = 0;
        self.success_count += 1;

        match self.state {
            InterfaceState::Probing => {
                if self.success_count >= self.up_count {
                    if let Some(ref mut damp) = self.dampening {
                        damp.decay();
                        if damp.is_suppressed() {
                            log::info!(
                                "{}: probing -> online blocked by dampening (penalty: {:.0})",
                                self.name, damp.penalty,
                            );
                            return None;
                        }
                    }
                    if quality_ok {
                        self.state = InterfaceState::Online;
                        self.online_since = Some(Instant::now());
                        self.offline_since = None;
                        log::info!("{}: probing -> online ({} successes)", self.name, self.success_count);
                        Some(InterfaceState::Online)
                    } else {
                        self.state = InterfaceState::Degraded;
                        log::warn!("{}: probing -> degraded (quality threshold)", self.name);
                        Some(InterfaceState::Degraded)
                    }
                } else {
                    None
                }
            }
            InterfaceState::Degraded => {
                if !quality_ok {
                    // Quality still degraded, stay in Degraded state
                    return None;
                }
                if let Some(ref mut damp) = self.dampening {
                    damp.decay();
                    if damp.is_suppressed() {
                        log::info!(
                            "{}: degraded -> online blocked by dampening (penalty: {:.0})",
                            self.name, damp.penalty,
                        );
                        return None;
                    }
                }
                self.state = InterfaceState::Online;
                // online_since stays set from the original Online transition
                log::info!("{}: degraded -> online (recovered)", self.name);
                Some(InterfaceState::Online)
            }
            InterfaceState::Online => {
                if !quality_ok {
                    self.state = InterfaceState::Degraded;
                    log::warn!("{}: online -> degraded (quality threshold)", self.name);
                    Some(InterfaceState::Degraded)
                } else {
                    None
                }
            }
            _ => None,
        }
    }

    /// Record a failed probe. Returns new state if a transition occurred.
    ///
    /// When dampening is enabled, a penalty is applied on each transition to
    /// Offline. If the penalty exceeds the suppress threshold, the interface
    /// will be blocked from returning to Online until the penalty decays.
    pub fn probe_failure(&mut self) -> Option<InterfaceState> {
        self.success_count = 0;
        self.fail_count += 1;

        match self.state {
            InterfaceState::Online => {
                self.state = InterfaceState::Degraded;
                log::warn!("{}: online -> degraded (probe failure)", self.name);
                Some(InterfaceState::Degraded)
            }
            InterfaceState::Degraded => {
                if self.fail_count >= self.down_count {
                    self.apply_dampening_failure();
                    self.state = InterfaceState::Offline;
                    self.offline_since = Some(Instant::now());
                    self.online_since = None;
                    log::warn!("{}: degraded -> offline ({} failures)", self.name, self.fail_count);
                    Some(InterfaceState::Offline)
                } else {
                    None
                }
            }
            InterfaceState::Probing => {
                if self.fail_count >= self.down_count {
                    self.apply_dampening_failure();
                    self.state = InterfaceState::Offline;
                    self.offline_since = Some(Instant::now());
                    self.online_since = None;
                    log::warn!("{}: probing -> offline ({} failures)", self.name, self.fail_count);
                    Some(InterfaceState::Offline)
                } else {
                    None
                }
            }
            _ => None,
        }
    }

    /// Apply a dampening failure penalty if dampening is enabled.
    fn apply_dampening_failure(&mut self) {
        if let Some(ref mut damp) = self.dampening {
            let suppressed = damp.apply_failure();
            if suppressed {
                log::warn!(
                    "{}: dampening suppressed (penalty: {:.0}, suppress: {})",
                    self.name, damp.penalty, damp.suppress,
                );
            }
        }
    }

    /// Interface came up via netifd. Returns new state if a transition occurred.
    pub fn link_up(&mut self) -> Option<InterfaceState> {
        match self.state {
            prev @ (InterfaceState::Init | InterfaceState::Offline) => {
                self.success_count = 0;
                self.fail_count = 0;
                self.state = InterfaceState::Probing;
                self.offline_since = None;
                log::info!("{}: {prev} -> probing (link up)", self.name);
                Some(InterfaceState::Probing)
            }
            _ => None,
        }
    }

    /// Interface went down via netifd. Returns new state if a transition occurred.
    pub fn link_down(&mut self) -> Option<InterfaceState> {
        match self.state {
            InterfaceState::Offline | InterfaceState::Init => None,
            prev => {
                self.success_count = 0;
                self.fail_count = 0;
                self.state = InterfaceState::Offline;
                self.offline_since = Some(Instant::now());
                self.online_since = None;
                log::warn!("{}: {prev} -> offline (link down)", self.name);
                Some(InterfaceState::Offline)
            }
        }
    }

    /// Returns true if this interface should be included in policies.
    ///
    /// Both Online and Degraded interfaces participate in routing --
    /// Degraded means reachable but with poor quality, not unreachable.
    pub fn is_active(&self) -> bool {
        self.enabled
            && (self.state == InterfaceState::Online
                || self.state == InterfaceState::Degraded)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_tracker() -> InterfaceTracker {
        InterfaceTracker::new(
            "wan".into(),
            0,
            0x0100,
            100,
            "eth0.2".into(),
            3,  // up_count
            5,  // down_count
        )
    }

    #[test]
    fn init_to_probing_on_link_up() {
        let mut t = make_tracker();
        assert_eq!(t.state, InterfaceState::Init);
        let s = t.link_up();
        assert_eq!(s, Some(InterfaceState::Probing));
        assert_eq!(t.state, InterfaceState::Probing);
    }

    #[test]
    fn probing_to_online_after_up_count() {
        let mut t = make_tracker();
        t.link_up();

        // First two successes: stay probing
        assert_eq!(t.probe_success(true), None);
        assert_eq!(t.probe_success(true), None);
        // Third success: go online
        assert_eq!(t.probe_success(true), Some(InterfaceState::Online));
        assert_eq!(t.state, InterfaceState::Online);
    }

    #[test]
    fn online_to_degraded_to_offline() {
        let mut t = make_tracker();
        t.link_up();
        for _ in 0..3 { t.probe_success(true); }
        assert_eq!(t.state, InterfaceState::Online);

        // First failure: degrade
        assert_eq!(t.probe_failure(), Some(InterfaceState::Degraded));

        // Next 4 failures: stay degraded (need 5 total for offline)
        for _ in 0..3 {
            assert_eq!(t.probe_failure(), None);
        }
        // 5th failure: offline
        assert_eq!(t.probe_failure(), Some(InterfaceState::Offline));
    }

    #[test]
    fn degraded_recovers_on_success() {
        let mut t = make_tracker();
        t.link_up();
        for _ in 0..3 { t.probe_success(true); }
        t.probe_failure(); // -> degraded

        assert_eq!(t.probe_success(true), Some(InterfaceState::Online));
    }

    #[test]
    fn offline_to_probing_on_link_up() {
        let mut t = make_tracker();
        t.link_up();
        for _ in 0..3 { t.probe_success(true); }
        t.probe_failure();
        for _ in 0..4 { t.probe_failure(); } // -> offline

        let s = t.link_up();
        assert_eq!(s, Some(InterfaceState::Probing));
    }

    #[test]
    fn link_down_from_online() {
        let mut t = make_tracker();
        t.link_up();
        for _ in 0..3 { t.probe_success(true); }

        assert_eq!(t.link_down(), Some(InterfaceState::Offline));
        assert_eq!(t.success_count, 0);
        assert_eq!(t.fail_count, 0);
    }

    fn make_dampened_tracker() -> InterfaceTracker {
        let mut t = InterfaceTracker::new(
            "wan".into(),
            0,
            0x0100,
            100,
            "eth0.2".into(),
            3,  // up_count
            3,  // down_count (lower for quicker test cycles)
        );
        // suppress=500, reuse=250, penalty_per_failure=1000 -> one failure suppresses
        t.set_dampening(300, 1000, 500, 250);
        t
    }

    #[test]
    fn dampening_blocks_online_after_flap() {
        let mut t = make_dampened_tracker();
        t.link_up();
        // Go online
        for _ in 0..3 { t.probe_success(true); }
        assert_eq!(t.state, InterfaceState::Online);

        // Go offline (3 failures triggers offline + dampening penalty)
        t.probe_failure(); // -> degraded
        t.probe_failure();
        assert_eq!(t.probe_failure(), Some(InterfaceState::Offline));

        // Dampening should be suppressed now (penalty=1000, suppress=500)
        assert!(t.dampening.as_ref().unwrap().is_suppressed());

        // Link comes back up, start probing
        t.link_up();
        assert_eq!(t.state, InterfaceState::Probing);

        // Probes succeed, but dampening blocks Online transition
        for _ in 0..10 {
            assert_eq!(t.probe_success(true), None);
        }
        assert_eq!(t.state, InterfaceState::Probing);
    }

    #[test]
    fn dampening_allows_online_after_decay() {
        let mut t = make_dampened_tracker();
        t.link_up();
        for _ in 0..3 { t.probe_success(true); }

        // Go offline -> dampening suppressed
        t.probe_failure();
        t.probe_failure();
        t.probe_failure();
        assert_eq!(t.state, InterfaceState::Offline);
        assert!(t.dampening.as_ref().unwrap().is_suppressed());

        // Simulate time passing: manually reset the penalty below reuse threshold
        t.dampening.as_mut().unwrap().penalty = 100.0; // below reuse=250
        t.dampening.as_mut().unwrap().suppressed = false;

        // Link up, start probing
        t.link_up();

        // Now probes should allow Online transition
        for _ in 0..3 { t.probe_success(true); }
        assert_eq!(t.state, InterfaceState::Online);
    }

    #[test]
    fn no_dampening_does_not_block() {
        // Default tracker without dampening
        let mut t = make_tracker();
        t.link_up();
        for _ in 0..3 { t.probe_success(true); }

        // Go offline
        t.probe_failure();
        for _ in 0..4 { t.probe_failure(); }
        assert_eq!(t.state, InterfaceState::Offline);

        // Come back: no dampening, should go online immediately after up_count
        t.link_up();
        for _ in 0..3 { t.probe_success(true); }
        assert_eq!(t.state, InterfaceState::Online);
    }

    // --- Quality-based state transition tests ---

    #[test]
    fn quality_degrades_online_to_degraded() {
        let mut t = make_tracker();
        t.link_up();
        for _ in 0..3 { t.probe_success(true); }
        assert_eq!(t.state, InterfaceState::Online);

        // Probe succeeds but quality is bad
        assert_eq!(t.probe_success(false), Some(InterfaceState::Degraded));
        assert_eq!(t.state, InterfaceState::Degraded);
    }

    #[test]
    fn quality_recovery_degraded_to_online() {
        let mut t = make_tracker();
        t.link_up();
        for _ in 0..3 { t.probe_success(true); }
        t.probe_success(false); // -> degraded
        assert_eq!(t.state, InterfaceState::Degraded);

        // Quality recovers
        assert_eq!(t.probe_success(true), Some(InterfaceState::Online));
        assert_eq!(t.state, InterfaceState::Online);
    }

    #[test]
    fn quality_stays_degraded_while_bad() {
        let mut t = make_tracker();
        t.link_up();
        for _ in 0..3 { t.probe_success(true); }
        t.probe_success(false); // -> degraded
        assert_eq!(t.state, InterfaceState::Degraded);

        // More probes succeed but quality still bad
        assert_eq!(t.probe_success(false), None);
        assert_eq!(t.state, InterfaceState::Degraded);
    }

    #[test]
    fn probing_to_degraded_on_bad_quality() {
        let mut t = make_tracker();
        t.link_up();
        // Reach up_count but quality is bad
        t.probe_success(true);
        t.probe_success(true);
        assert_eq!(t.probe_success(false), Some(InterfaceState::Degraded));
        assert_eq!(t.state, InterfaceState::Degraded);
    }

    #[test]
    fn quality_degraded_then_probe_failure_goes_offline() {
        let mut t = make_tracker();
        t.link_up();
        for _ in 0..3 { t.probe_success(true); }
        t.probe_success(false); // -> degraded via quality

        // Now actual probe failures accumulate
        for i in 0..4 {
            assert_eq!(t.probe_failure(), None, "failure {i} shouldn't go offline yet");
        }
        // 5th failure: offline (down_count=5)
        assert_eq!(t.probe_failure(), Some(InterfaceState::Offline));
    }
}
