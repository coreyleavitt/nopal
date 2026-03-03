//! Route dampening algorithm (RFC 2439 inspired).
//!
//! Prevents rapid interface flapping from causing constant routing churn.
//! When an interface fails, a penalty is added. If the penalty exceeds the
//! suppress threshold, the interface is suppressed (kept offline even if
//! probes start succeeding). The penalty decays exponentially with a
//! configurable half-life. Once the penalty drops below the reuse threshold,
//! the interface is eligible to come back online.
//!
//! Default values (from mwan3 compatibility):
//! - Half-life: 300 seconds
//! - Ceiling: 1000 (max penalty)
//! - Suppress: 500
//! - Reuse: 250
//! - Penalty per failure: 1000

use std::time::Instant;

/// Penalty added for each observed failure.
const PENALTY_PER_FAILURE: f64 = 1000.0;

/// Tracks dampening state for a single interface.
#[derive(Debug)]
pub struct DampeningState {
    /// Accumulated penalty value. Increases on failure, decays over time.
    pub penalty: f64,
    /// Whether the interface is currently suppressed due to dampening.
    pub suppressed: bool,
    /// Half-life in seconds: time for the penalty to decay by half.
    pub halflife: u32,
    /// Maximum penalty value (clamped to this ceiling).
    pub ceiling: u32,
    /// Penalty threshold above which the interface is suppressed.
    pub suppress: u32,
    /// Penalty threshold below which a suppressed interface can be reused.
    pub reuse: u32,
    /// Timestamp of the last penalty update (for decay calculation).
    pub last_update: Instant,
}

impl DampeningState {
    /// Create a new dampening state with the given parameters.
    ///
    /// All thresholds are specified as integer values for configuration
    /// compatibility but stored alongside the `f64` penalty for precise
    /// exponential decay.
    pub fn new(halflife: u32, ceiling: u32, suppress: u32, reuse: u32) -> Self {
        Self {
            penalty: 0.0,
            suppressed: false,
            halflife,
            ceiling,
            suppress,
            reuse,
            last_update: Instant::now(),
        }
    }

    /// Record a probe failure: decay the existing penalty, then add the
    /// failure penalty. Returns `true` if the interface is now suppressed.
    pub fn apply_failure(&mut self) -> bool {
        self.decay();

        self.penalty += PENALTY_PER_FAILURE;
        if self.penalty > self.ceiling as f64 {
            self.penalty = self.ceiling as f64;
        }

        if self.penalty >= self.suppress as f64 {
            self.suppressed = true;
        }

        self.suppressed
    }

    /// Apply exponential decay based on elapsed time since the last update.
    ///
    /// Uses the formula: `penalty * 2^(-elapsed / halflife)`
    pub fn decay(&mut self) {
        let now = Instant::now();
        let elapsed = now.duration_since(self.last_update).as_secs_f64();
        self.last_update = now;

        if elapsed <= 0.0 || self.halflife == 0 {
            return;
        }

        // Exponential decay: penalty * 2^(-t/halflife)
        let decay_factor = (-elapsed / self.halflife as f64).exp2();
        self.penalty *= decay_factor;

        // Snap to zero if negligibly small
        if self.penalty < 0.1 {
            self.penalty = 0.0;
        }

        // Check if we've dropped below the reuse threshold
        if self.suppressed && self.penalty < self.reuse as f64 {
            self.suppressed = false;
        }
    }

    /// Whether the interface is currently suppressed (penalty above suppress
    /// threshold).
    pub fn is_suppressed(&self) -> bool {
        self.suppressed
    }

    /// Whether the penalty has decayed below the reuse threshold, meaning a
    /// suppressed interface can come back online.
    #[allow(dead_code)]
    pub fn should_reuse(&self) -> bool {
        self.penalty < self.reuse as f64
    }

    /// Reset dampening state, clearing all accumulated penalty.
    #[allow(dead_code)]
    pub fn reset(&mut self) {
        self.penalty = 0.0;
        self.suppressed = false;
        self.last_update = Instant::now();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    #[test]
    fn new_state_is_not_suppressed() {
        let state = DampeningState::new(300, 1000, 500, 250);
        assert!(!state.is_suppressed());
        assert!(state.should_reuse());
        assert_eq!(state.penalty, 0.0);
    }

    #[test]
    fn single_failure_suppresses() {
        // With penalty=1000 per failure and suppress=500, one failure suppresses
        let mut state = DampeningState::new(300, 1000, 500, 250);
        let suppressed = state.apply_failure();
        assert!(suppressed);
        assert!(state.is_suppressed());
        assert!(!state.should_reuse());
    }

    #[test]
    fn penalty_capped_at_ceiling() {
        let mut state = DampeningState::new(300, 1000, 500, 250);
        state.apply_failure();
        state.apply_failure();
        state.apply_failure();
        assert_eq!(state.penalty, 1000.0); // ceiling
    }

    #[test]
    fn reset_clears_state() {
        let mut state = DampeningState::new(300, 1000, 500, 250);
        state.apply_failure();
        assert!(state.is_suppressed());

        state.reset();
        assert!(!state.is_suppressed());
        assert_eq!(state.penalty, 0.0);
    }

    #[test]
    fn decay_with_zero_halflife_is_noop() {
        let mut state = DampeningState::new(0, 1000, 500, 250);
        state.penalty = 800.0;
        state.last_update = Instant::now() - Duration::from_secs(100);
        state.decay();
        // Penalty should remain unchanged
        assert_eq!(state.penalty, 800.0);
    }
}
