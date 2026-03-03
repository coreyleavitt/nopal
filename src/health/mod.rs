//! Health probe orchestration for multi-WAN interfaces.
//!
//! The [`ProbeEngine`] manages health probes for each configured interface,
//! tracking consecutive successes and failures to determine when an interface
//! should transition online or offline. Each interface probes its configured
//! targets in round-robin cycles: one probe per target per cycle, with the
//! cycle evaluated after all targets have been probed. A cycle succeeds when
//! at least `reliability` targets respond.
//!
//! Supported probe types:
//! - **ICMP** (`track_method ping`): ICMP echo request/reply
//! - **DNS** (`track_method dns`): UDP DNS query for root "." A record
//! - **HTTP** (`track_method http`): HTTP HEAD request, expects 2xx
//! - **HTTPS** (`track_method https`): HTTPS HEAD request with TLS (feature-gated)
//! - **ARP** (`track_method arping`): ARP request/reply (IPv4 only, layer 2)
//!
//! All probe packets are marked with `SO_MARK = 0xDEAD` and bound to the
//! interface device via `SO_BINDTODEVICE`, ensuring they egress through the
//! correct link and are not caught by nopal's own nftables policy rules.

pub mod arp;
pub mod dampening;
pub mod dns;
pub mod http;
#[cfg(feature = "https")]
pub mod https;
pub mod icmp;

use std::collections::VecDeque;
use std::net::IpAddr;
use std::os::unix::io::RawFd;
use std::time::Instant;

use log::{debug, trace, warn};

use crate::config::schema::TrackMethod;
use crate::error::{Error, Result};
use arp::ArpSocket;
use dns::DnsSocket;
use http::HttpSocket;
use icmp::IcmpSocket;

/// Per-target probe status, updated after each probe cycle.
#[derive(Debug, Clone)]
pub struct TargetStatus {
    /// Target IP address.
    pub ip: IpAddr,
    /// Whether the last probe to this target succeeded.
    pub up: bool,
    /// RTT of the last successful probe in milliseconds.
    pub last_rtt_ms: Option<u32>,
}

/// Trait for health probe transport implementations.
pub(crate) trait ProbeTransport {
    fn send(&mut self, target: IpAddr, seq: u16, id: u16, payload_size: usize) -> Result<()>;
    fn recv(&mut self) -> Result<Option<(u16, u16)>>;
    fn fds(&self) -> Vec<RawFd>;
}

/// Multiple probe transports for the same target (OR logic).
///
/// A composite probe sends via all sub-transports and considers the
/// target reachable if any sub-transport receives a response.
struct CompositeSocket {
    transports: Vec<Box<dyn ProbeTransport>>,
}

impl ProbeTransport for CompositeSocket {
    fn send(&mut self, target: IpAddr, seq: u16, id: u16, payload_size: usize) -> Result<()> {
        let mut any_ok = false;
        let mut last_err = None;
        for t in &mut self.transports {
            match t.send(target, seq, id, payload_size) {
                Ok(()) => any_ok = true,
                Err(e) => last_err = Some(e),
            }
        }
        if any_ok {
            Ok(())
        } else {
            Err(last_err.unwrap_or_else(|| Error::Config("composite probe has no transports".into())))
        }
    }

    fn recv(&mut self) -> Result<Option<(u16, u16)>> {
        for t in &mut self.transports {
            match t.recv()? {
                Some(pair) => return Ok(Some(pair)),
                None => continue,
            }
        }
        Ok(None)
    }

    fn fds(&self) -> Vec<RawFd> {
        self.transports.iter().flat_map(|t| t.fds()).collect()
    }
}

/// Create a single probe transport for the given method.
fn create_transport(
    method: TrackMethod,
    device: &str,
    probe_id: u16,
    first_target: IpAddr,
    max_ttl: u32,
    dns_query_name: &str,
    track_port: Option<u16>,
    name: &str,
) -> Result<Box<dyn ProbeTransport>> {
    match method {
        TrackMethod::Ping => {
            let sock = match first_target {
                IpAddr::V4(_) => IcmpSocket::new_v4(device)?,
                IpAddr::V6(_) => IcmpSocket::new_v6(device)?,
            };
            sock.set_ttl(max_ttl)?;
            Ok(Box::new(sock))
        }
        TrackMethod::Dns => match first_target {
            IpAddr::V4(_) => Ok(Box::new(DnsSocket::new_v4(device, probe_id, dns_query_name)?)),
            IpAddr::V6(_) => Ok(Box::new(DnsSocket::new_v6(device, probe_id, dns_query_name)?)),
        },
        TrackMethod::Http => Ok(Box::new(HttpSocket::new(device, probe_id, track_port))),
        TrackMethod::Arping => {
            if first_target.is_ipv6() {
                return Err(Error::Config(format!(
                    "interface {name}: ARP probes only support IPv4 targets"
                )));
            }
            Ok(Box::new(ArpSocket::new(device, probe_id)?))
        }
        #[cfg(feature = "https")]
        TrackMethod::Https => Ok(Box::new(https::HttpsSocket::new(device, probe_id, track_port))),
        #[cfg(not(feature = "https"))]
        TrackMethod::Https => Err(Error::Config(format!(
            "interface {name}: HTTPS probes require the 'https' feature"
        ))),
        TrackMethod::Composite => Err(Error::Config("cannot nest composite".into())),
    }
}

/// Result of processing probe responses for a single interface.
///
/// Reports cycle outcome and quality metrics. Threshold-based state
/// transitions (up/down counts) are handled by `InterfaceTracker`.
pub struct ProbeResult {
    /// Interface index (matches config order).
    pub interface_index: usize,
    /// Whether the most recent probe cycle succeeded.
    pub success: bool,
    /// Whether quality thresholds are met (true = good, false = degraded).
    /// Always true when no quality thresholds are configured or the
    /// quality window hasn't filled yet.
    pub quality_ok: bool,
    /// Average RTT in milliseconds over the quality window, if available.
    pub avg_rtt_ms: Option<u32>,
    /// Packet loss percentage (0-100) over the quality window.
    pub loss_percent: u32,
}

/// Manages health probes across all configured interfaces.
pub struct ProbeEngine {
    probes: Vec<InterfaceProbe>,
}

/// Per-interface probe state.
struct InterfaceProbe {
    /// Interface index (matches config order).
    index: usize,
    /// Human-readable interface name (for logging).
    name: String,
    /// Network device to bind the ICMP socket to.
    #[allow(dead_code)]
    device: String,
    /// Target IP addresses to probe.
    targets: Vec<IpAddr>,
    /// Probe transport (ICMP, DNS, HTTP, ARP, HTTPS, or composite).
    socket: Option<Box<dyn ProbeTransport>>,
    /// Minimum number of targets that must respond for a cycle to succeed.
    reliability: u32,
    /// Whether a probe is outstanding (sent but not yet received/timed out).
    pending: bool,
    /// ICMP sequence number, incremented per probe.
    seq: u16,
    /// Results for the current probe cycle (true=success per target).
    cycle_results: Vec<bool>,
    /// RTT in ms for each position in the current cycle (set on success).
    cycle_rtts: Vec<Option<u32>>,
    /// Per-target status from the most recent completed cycle.
    target_status: Vec<TargetStatus>,
    /// Position within the current cycle (0..targets.len()).
    cycle_pos: usize,
    /// Timestamp when the current probe was sent, for RTT calculation.
    send_time: Option<Instant>,
    /// RTT of the most recent successful probe (set in check_responses,
    /// consumed in record_timeout to push to the quality window).
    last_rtt: Option<u32>,
    /// Sliding window of recent probe outcomes: Some(rtt_ms) for success,
    /// None for timeout/loss.
    quality_window: VecDeque<Option<u32>>,
    /// Maximum size of the quality window.
    quality_window_size: usize,
    /// RTT threshold in ms (None = disabled).
    latency_threshold: Option<u32>,
    /// Loss percentage threshold (None = disabled).
    loss_threshold: Option<u32>,
    /// RTT threshold for recovery (None = falls back to latency_threshold).
    recovery_latency: Option<u32>,
    /// Loss threshold for recovery (None = falls back to loss_threshold).
    recovery_loss: Option<u32>,
    /// Whether quality is currently degraded. Used to select between
    /// failure thresholds and recovery thresholds (hysteresis).
    quality_degraded: bool,
    /// ICMP payload size in bytes.
    probe_size: usize,
}

impl InterfaceProbe {
    /// Push a probe outcome into the quality sliding window.
    fn push_quality(&mut self, rtt: Option<u32>) {
        if self.quality_window_size == 0 {
            return;
        }
        self.quality_window.push_back(rtt);
        while self.quality_window.len() > self.quality_window_size {
            self.quality_window.pop_front();
        }
    }

    /// Compute avg RTT and loss percentage from the sliding window (read-only).
    fn compute_metrics(&self) -> (Option<u32>, u32) {
        if self.quality_window.is_empty() {
            return (None, 0);
        }
        let total = self.quality_window.len() as u32;
        let losses = self.quality_window.iter().filter(|r| r.is_none()).count() as u32;
        let loss_percent = (losses * 100) / total;
        let (rtt_sum, rtt_count) = self.quality_window.iter()
            .filter_map(|r| *r)
            .fold((0u64, 0u32), |(s, c), rtt| (s + rtt as u64, c + 1));
        let avg_rtt = if rtt_count == 0 {
            None
        } else {
            Some((rtt_sum / rtt_count as u64) as u32)
        };
        (avg_rtt, loss_percent)
    }

    /// Evaluate quality metrics from the sliding window.
    ///
    /// Returns `(avg_rtt_ms, loss_percent, quality_ok)`. Quality is only
    /// evaluated once the window has reached its configured size; until then,
    /// `quality_ok` is always true.
    ///
    /// When recovery thresholds are configured, uses hysteresis: the failure
    /// thresholds detect degradation and the (stricter) recovery thresholds
    /// detect recovery. This prevents flapping when metrics hover near the
    /// threshold boundary.
    fn evaluate_quality(&mut self) -> (Option<u32>, u32, bool) {
        let (avg_rtt, loss_percent) = self.compute_metrics();
        if self.quality_window.is_empty() {
            return (None, 0, true);
        }

        // Only evaluate thresholds once the window is full
        if self.quality_window.len() < self.quality_window_size {
            return (avg_rtt, loss_percent, true);
        }

        let quality_ok = if self.quality_degraded {
            // Currently degraded: use recovery thresholds to recover.
            // Recovery requires metrics to be below the recovery threshold
            // (or below the failure threshold if no recovery threshold is set).
            let lat_ok = match self.recovery_latency.or(self.latency_threshold) {
                Some(threshold) => match avg_rtt {
                    Some(avg) => avg < threshold,
                    None => true,
                },
                None => true,
            };
            let loss_ok = match self.recovery_loss.or(self.loss_threshold) {
                Some(threshold) => loss_percent < threshold,
                None => true,
            };
            let recovered = lat_ok && loss_ok;
            if recovered {
                self.quality_degraded = false;
            }
            recovered
        } else {
            // Currently healthy: use failure thresholds to detect degradation.
            let mut ok = true;
            if let Some(threshold) = self.latency_threshold {
                if let Some(avg) = avg_rtt {
                    if avg > threshold {
                        ok = false;
                    }
                }
            }
            if let Some(threshold) = self.loss_threshold {
                if loss_percent > threshold {
                    ok = false;
                }
            }
            if !ok {
                self.quality_degraded = true;
            }
            ok
        };

        (avg_rtt, loss_percent, quality_ok)
    }
}

impl ProbeEngine {
    /// Create an empty probe engine with no interfaces.
    pub fn new() -> Self {
        Self { probes: Vec::new() }
    }

    /// Add an interface to be probed.
    ///
    /// Creates a probe socket bound to `device` and prepares the interface
    /// for health probing. The socket type (ICMP or DNS) is determined by
    /// `track_method`, and the address family (v4/v6) by the first target.
    ///
    /// # Errors
    ///
    /// Returns an error if the probe socket cannot be created (e.g. missing
    /// capabilities, invalid device name).
    pub fn add_interface(
        &mut self,
        index: usize,
        name: &str,
        device: &str,
        targets: Vec<IpAddr>,
        track_method: TrackMethod,
        composite_methods: &[TrackMethod],
        reliability: u32,
        latency_threshold: Option<u32>,
        loss_threshold: Option<u32>,
        recovery_latency: Option<u32>,
        recovery_loss: Option<u32>,
        quality_window: u32,
        count: u32,
        max_ttl: u32,
        probe_size: u32,
        dns_query_name: &str,
        track_port: Option<u16>,
    ) -> Result<()> {
        if targets.is_empty() {
            return Err(Error::Config(format!(
                "interface {name}: no probe targets configured"
            )));
        }

        let first_target = targets[0];
        let probe_id = index as u16;

        let socket: Box<dyn ProbeTransport> = if track_method == TrackMethod::Composite {
            let methods = if composite_methods.is_empty() {
                &[TrackMethod::Ping, TrackMethod::Dns][..]
            } else {
                composite_methods
            };
            let mut transports = Vec::new();
            for method in methods {
                if *method == TrackMethod::Composite {
                    continue; // no nesting
                }
                transports.push(create_transport(
                    *method, device, probe_id, first_target, max_ttl, dns_query_name,
                    track_port, name,
                )?);
            }
            if transports.is_empty() {
                return Err(Error::Config(format!(
                    "interface {name}: composite probe has no valid methods"
                )));
            }
            Box::new(CompositeSocket { transports })
        } else {
            create_transport(
                track_method, device, probe_id, first_target, max_ttl, dns_query_name,
                track_port, name,
            )?
        };

        // Validate that all targets share the same address family
        let is_v6 = first_target.is_ipv6();
        for target in &targets {
            if target.is_ipv6() != is_v6 {
                return Err(Error::Config(format!(
                    "interface {name}: mixed IPv4/IPv6 targets are not supported; \
                     configure separate interfaces for each address family"
                )));
            }
        }

        // Expand targets by count: each target appears `count` times per cycle
        let count = count.max(1) as usize;
        let expanded_targets: Vec<IpAddr> = targets
            .iter()
            .flat_map(|t| std::iter::repeat(*t).take(count))
            .collect();

        debug!(
            "health: added interface {name} (index={index}, device={device}, \
             method={track_method:?}, targets={}, count={count}, ttl={max_ttl}, \
             size={probe_size})",
            targets.len()
        );

        let num_cycle_targets = expanded_targets.len();
        // Reliability capped to number of targets (original, not expanded)
        let effective_reliability = reliability.min(targets.len() as u32).max(1);

        let target_status = targets
            .iter()
            .map(|ip| TargetStatus {
                ip: *ip,
                up: false,
                last_rtt_ms: None,
            })
            .collect();

        self.probes.push(InterfaceProbe {
            index,
            name: name.to_string(),
            device: device.to_string(),
            targets: expanded_targets,
            socket: Some(socket),
            reliability: effective_reliability,
            pending: false,
            seq: 0,
            cycle_results: vec![false; num_cycle_targets],
            cycle_rtts: vec![None; num_cycle_targets],
            target_status,
            cycle_pos: 0,
            send_time: None,
            last_rtt: None,
            quality_window: VecDeque::new(),
            quality_window_size: quality_window as usize,
            latency_threshold,
            loss_threshold,
            recovery_latency,
            recovery_loss,
            quality_degraded: false,
            probe_size: probe_size as usize,
        });

        Ok(())
    }

    /// Remove an interface from the probe engine.
    ///
    /// The ICMP socket is closed when the `InterfaceProbe` is dropped.
    pub fn remove_interface(&mut self, index: usize) {
        if let Some(pos) = self.probes.iter().position(|p| p.index == index) {
            let probe = self.probes.remove(pos);
            debug!("health: removed interface {} (index={index})", probe.name);
        }
    }

    /// Send a health probe for the interface at `index`.
    ///
    /// Uses the current target in the cycle and the configured probe type
    /// (ICMP or DNS).
    ///
    /// # Errors
    ///
    /// Returns an error if the socket is not available or the send fails.
    pub fn send_probe(&mut self, index: usize) -> Result<()> {
        let probe = self
            .probes
            .iter_mut()
            .find(|p| p.index == index)
            .ok_or_else(|| {
                Error::State(format!("no probe state for interface index {index}"))
            })?;

        let target = probe.targets[probe.cycle_pos];
        probe.seq = probe.seq.wrapping_add(1);
        let id = probe.index as u16;

        trace!(
            "health: sending probe to {target} via {} (seq={}, id={id}, cycle={}/{})",
            probe.name,
            probe.seq,
            probe.cycle_pos + 1,
            probe.targets.len()
        );

        let payload_size = probe.probe_size;
        let socket = probe.socket.as_mut().ok_or_else(|| {
            Error::State(format!(
                "interface {}: probe socket not available",
                probe.name
            ))
        })?;
        socket.send(target, probe.seq, id, payload_size)?;
        probe.pending = true;
        probe.send_time = Some(Instant::now());
        probe.last_rtt = None;

        Ok(())
    }

    /// Non-blocking check for probe responses on all interfaces.
    ///
    /// Reads from each interface's ICMP socket and records successful
    /// responses in the current probe cycle. Results are buffered until
    /// the full cycle completes in [`record_timeout`].
    pub fn check_responses(&mut self) {
        for probe in &mut self.probes {
            if !probe.pending {
                continue;
            }

            let socket = match probe.socket.as_mut() {
                Some(s) => s,
                None => continue,
            };

            match socket.recv() {
                Ok(Some((seq, id))) => {
                    if seq == probe.seq && id == probe.index as u16 {
                        let rtt = probe.send_time.take().map(|t| t.elapsed().as_millis() as u32);
                        trace!(
                            "health: reply from {} (seq={seq}, id={id}, cycle={}/{}, rtt={:?}ms)",
                            probe.name,
                            probe.cycle_pos + 1,
                            probe.targets.len(),
                            rtt,
                        );
                        probe.pending = false;
                        probe.cycle_results[probe.cycle_pos] = true;
                        probe.cycle_rtts[probe.cycle_pos] = rtt;
                        probe.last_rtt = rtt;
                    }
                    // Ignore replies with non-matching seq/id (stale packets)
                }
                Ok(None) => {
                    // No data available yet -- still waiting
                }
                Err(e) => {
                    warn!(
                        "health: recv error on interface {}: {e}",
                        probe.name
                    );
                }
            }
        }
    }

    /// Advance the probe cycle for the interface at `index`.
    ///
    /// Called by the event loop when the probe timeout timer fires. If the
    /// probe is still pending (no response received), the target is counted
    /// as a failure for this cycle. Advances to the next target in the cycle.
    ///
    /// Returns `Some(ProbeResult)` when the full cycle completes (all targets
    /// probed), or `None` if more targets remain in the current cycle.
    pub fn record_timeout(&mut self, index: usize) -> Option<ProbeResult> {
        let probe = self.probes.iter_mut().find(|p| p.index == index)?;

        // If still pending, this target did not respond (cycle_results stays false).
        // If not pending, check_responses already recorded success.
        if probe.pending {
            trace!(
                "health: probe timeout on {} (cycle={}/{})",
                probe.name,
                probe.cycle_pos + 1,
                probe.targets.len()
            );
            // Timeout: push None to quality window (loss)
            probe.push_quality(None);
        } else if probe.cycle_results[probe.cycle_pos] {
            // Success: push RTT to quality window
            probe.push_quality(probe.last_rtt);
        } else {
            // Send failed (never became pending): record as loss
            probe.push_quality(None);
        }
        probe.pending = false;

        // Advance to next position in cycle
        probe.cycle_pos += 1;

        if probe.cycle_pos < probe.targets.len() {
            // Mid-cycle: more targets to probe
            return None;
        }

        // Cycle complete: evaluate
        let successes = probe.cycle_results.iter().filter(|&&r| r).count() as u32;
        let cycle_ok = successes >= probe.reliability;

        debug!(
            "health: cycle complete on {} ({successes}/{} targets, \
             reliability={}, {})",
            probe.name,
            probe.targets.len(),
            probe.reliability,
            if cycle_ok { "success" } else { "failure" }
        );

        // Update per-target status from cycle results. Expanded targets
        // may repeat each IP `count` times; a target is "up" if any of its
        // expanded probes succeeded, and the RTT is from the last success.
        for ts in &mut probe.target_status {
            let mut up = false;
            let mut rtt = None;
            for (i, ip) in probe.targets.iter().enumerate() {
                if *ip == ts.ip && probe.cycle_results[i] {
                    up = true;
                    rtt = probe.cycle_rtts[i];
                }
            }
            ts.up = up;
            if up {
                ts.last_rtt_ms = rtt;
            }
        }

        // Reset cycle for next round
        probe.cycle_pos = 0;
        for r in &mut probe.cycle_results {
            *r = false;
        }
        for r in &mut probe.cycle_rtts {
            *r = None;
        }

        // Evaluate quality metrics
        let (avg_rtt_ms, loss_percent, quality_ok) = probe.evaluate_quality();

        Some(ProbeResult {
            interface_index: index,
            success: cycle_ok,
            quality_ok,
            avg_rtt_ms,
            loss_percent,
        })
    }

    /// Return file descriptors for all active ICMP sockets, keyed by
    /// interface index.
    ///
    /// Used by the event loop to register these fds with mio for readability
    /// notifications. The returned slot is a sequential counter (not the
    /// interface config index) to guarantee unique mio tokens. The daemon
    /// uses `check_responses()` globally on any probe fd wake-up, so the
    /// slot value is only used for token uniqueness.
    pub fn get_fds(&self) -> Vec<(usize, RawFd)> {
        let mut result = Vec::new();
        let mut slot = 0;
        for p in &self.probes {
            if let Some(s) = &p.socket {
                for fd in s.fds() {
                    result.push((slot, fd));
                    slot += 1;
                }
            }
        }
        result
    }

    /// Reset cycle state for the interface at `index`.
    ///
    /// Called when a configuration change affects the interface and the
    /// probe cycle should be restarted.
    pub fn reset_counters(&mut self, index: usize) {
        if let Some(probe) = self.probes.iter_mut().find(|p| p.index == index) {
            probe.pending = false;
            probe.cycle_pos = 0;
            for r in &mut probe.cycle_results {
                *r = false;
            }
            for r in &mut probe.cycle_rtts {
                *r = None;
            }
            probe.send_time = None;
            probe.last_rtt = None;
            probe.quality_window.clear();
            probe.quality_degraded = false;
            debug!("health: reset counters for interface {}", probe.name);
        }
    }

    /// Return per-target probe status for the interface at `index`.
    pub fn target_status(&self, index: usize) -> Vec<TargetStatus> {
        self.probes
            .iter()
            .find(|p| p.index == index)
            .map(|p| p.target_status.clone())
            .unwrap_or_default()
    }

    /// Return the quality metrics for the interface at `index`.
    ///
    /// Returns `(avg_rtt_ms, loss_percent)`. Useful for status reporting.
    #[allow(dead_code)]
    pub fn quality_metrics(&self, index: usize) -> (Option<u32>, u32) {
        self.probes
            .iter()
            .find(|p| p.index == index)
            .map(|p| p.compute_metrics())
            .unwrap_or((None, 0))
    }

    /// Check whether a probe is currently pending for the interface at
    /// `index`.
    #[allow(dead_code)]
    pub fn is_pending(&self, index: usize) -> bool {
        self.probes
            .iter()
            .find(|p| p.index == index)
            .map_or(false, |p| p.pending)
    }

    /// Add a test-only interface without creating a real ICMP socket.
    #[cfg(test)]
    fn add_test_interface(
        &mut self,
        index: usize,
        name: &str,
        num_targets: usize,
        reliability: u32,
    ) {
        Self::add_test_interface_with_quality(
            &mut self.probes,
            index,
            name,
            num_targets,
            reliability,
            None,
            None,
            0,
        );
    }

    /// Add a test-only interface with quality thresholds.
    #[cfg(test)]
    fn add_test_interface_quality(
        &mut self,
        index: usize,
        name: &str,
        num_targets: usize,
        reliability: u32,
        latency_threshold: Option<u32>,
        loss_threshold: Option<u32>,
        quality_window: usize,
    ) {
        Self::add_test_interface_with_quality(
            &mut self.probes,
            index,
            name,
            num_targets,
            reliability,
            latency_threshold,
            loss_threshold,
            quality_window,
        );
    }

    #[cfg(test)]
    fn add_test_interface_with_quality(
        probes: &mut Vec<InterfaceProbe>,
        index: usize,
        name: &str,
        num_targets: usize,
        reliability: u32,
        latency_threshold: Option<u32>,
        loss_threshold: Option<u32>,
        quality_window: usize,
    ) {
        Self::add_test_interface_with_recovery(
            probes,
            index,
            name,
            num_targets,
            reliability,
            latency_threshold,
            loss_threshold,
            None,
            None,
            quality_window,
        );
    }

    #[cfg(test)]
    fn add_test_interface_with_recovery(
        probes: &mut Vec<InterfaceProbe>,
        index: usize,
        name: &str,
        num_targets: usize,
        reliability: u32,
        latency_threshold: Option<u32>,
        loss_threshold: Option<u32>,
        recovery_latency: Option<u32>,
        recovery_loss: Option<u32>,
        quality_window: usize,
    ) {
        let targets: Vec<IpAddr> = (0..num_targets)
            .map(|i| IpAddr::V4(std::net::Ipv4Addr::new(8, 8, 8, i as u8 + 1)))
            .collect();
        let target_status = targets
            .iter()
            .map(|ip| TargetStatus { ip: *ip, up: false, last_rtt_ms: None })
            .collect();
        let effective_reliability = reliability.min(num_targets as u32).max(1);
        probes.push(InterfaceProbe {
            index,
            name: name.to_string(),
            device: "test0".to_string(),
            targets,
            socket: None,
            reliability: effective_reliability,
            pending: false,
            seq: 0,
            cycle_results: vec![false; num_targets],
            cycle_rtts: vec![None; num_targets],
            target_status,
            cycle_pos: 0,
            send_time: None,
            last_rtt: None,
            quality_window: VecDeque::new(),
            quality_window_size: quality_window,
            latency_threshold,
            loss_threshold,
            recovery_latency,
            recovery_loss,
            quality_degraded: false,
            probe_size: 56,
        });
    }

    /// Simulate a response for the current probe (test only).
    #[cfg(test)]
    fn simulate_response(&mut self, index: usize) {
        if let Some(probe) = self.probes.iter_mut().find(|p| p.index == index) {
            probe.pending = false;
            probe.cycle_results[probe.cycle_pos] = true;
            // Default RTT of 10ms for tests that don't care about quality
            probe.last_rtt = Some(10);
        }
    }

    /// Simulate a response with a specific RTT in milliseconds (test only).
    #[cfg(test)]
    fn simulate_response_with_rtt(&mut self, index: usize, rtt_ms: u32) {
        if let Some(probe) = self.probes.iter_mut().find(|p| p.index == index) {
            probe.pending = false;
            probe.cycle_results[probe.cycle_pos] = true;
            probe.last_rtt = Some(rtt_ms);
        }
    }

    /// Simulate sending a probe (sets pending without using socket).
    #[cfg(test)]
    fn simulate_send(&mut self, index: usize) {
        if let Some(probe) = self.probes.iter_mut().find(|p| p.index == index) {
            probe.pending = true;
            probe.seq = probe.seq.wrapping_add(1);
            probe.send_time = Some(Instant::now());
            probe.last_rtt = None;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn single_target_cycle_success() {
        let mut engine = ProbeEngine::new();
        engine.add_test_interface(0, "wan", 1, 1);

        engine.simulate_send(0);
        engine.simulate_response(0);
        let result = engine.record_timeout(0).expect("cycle should complete");
        assert!(result.success);
    }

    #[test]
    fn single_target_cycle_failure() {
        let mut engine = ProbeEngine::new();
        engine.add_test_interface(0, "wan", 1, 1);

        engine.simulate_send(0);
        // No response -- timeout fires with pending still true
        let result = engine.record_timeout(0).expect("cycle should complete");
        assert!(!result.success);
    }

    #[test]
    fn multi_target_reliability_met() {
        // 3 targets, reliability=2: cycle succeeds if >= 2 targets respond
        let mut engine = ProbeEngine::new();
        engine.add_test_interface(0, "wan", 3, 2);

        // Target 0: success
        engine.simulate_send(0);
        engine.simulate_response(0);
        assert!(engine.record_timeout(0).is_none()); // mid-cycle

        // Target 1: success
        engine.simulate_send(0);
        engine.simulate_response(0);
        assert!(engine.record_timeout(0).is_none()); // mid-cycle

        // Target 2: timeout (fail)
        engine.simulate_send(0);
        // No response
        let result = engine.record_timeout(0).expect("cycle should complete");
        assert!(result.success); // 2/3 >= reliability(2)
    }

    #[test]
    fn multi_target_reliability_not_met() {
        // 3 targets, reliability=2: cycle fails if < 2 targets respond
        let mut engine = ProbeEngine::new();
        engine.add_test_interface(0, "wan", 3, 2);

        // Target 0: success
        engine.simulate_send(0);
        engine.simulate_response(0);
        assert!(engine.record_timeout(0).is_none());

        // Target 1: timeout
        engine.simulate_send(0);
        assert!(engine.record_timeout(0).is_none());

        // Target 2: timeout
        engine.simulate_send(0);
        let result = engine.record_timeout(0).expect("cycle should complete");
        assert!(!result.success); // 1/3 < reliability(2)
    }

    #[test]
    fn multi_cycle_success_detection() {
        // Verify cycle success/failure across multiple consecutive cycles
        let mut engine = ProbeEngine::new();
        engine.add_test_interface(0, "wan", 2, 1);

        // Helper to run a full cycle
        let run_cycle = |engine: &mut ProbeEngine, respond: &[bool]| -> ProbeResult {
            for &r in respond {
                engine.simulate_send(0);
                if r {
                    engine.simulate_response(0);
                }
                if let Some(result) = engine.record_timeout(0) {
                    return result;
                }
            }
            panic!("cycle did not complete");
        };

        // Both targets respond -> success (reliability=1, 2 >= 1)
        assert!(run_cycle(&mut engine, &[true, true]).success);

        // Neither target responds -> failure (0 < 1)
        assert!(!run_cycle(&mut engine, &[false, false]).success);

        // One responds -> success (1 >= reliability=1)
        assert!(run_cycle(&mut engine, &[true, false]).success);
    }

    #[test]
    fn reliability_capped_to_target_count() {
        // reliability=5 with only 2 targets → capped to 2
        let mut engine = ProbeEngine::new();
        engine.add_test_interface(0, "wan", 2, 5);

        // Both targets succeed → cycle succeeds (2/2 >= capped reliability 2)
        engine.simulate_send(0);
        engine.simulate_response(0);
        assert!(engine.record_timeout(0).is_none());

        engine.simulate_send(0);
        engine.simulate_response(0);
        let result = engine.record_timeout(0).expect("cycle should complete");
        assert!(result.success);
    }

    #[test]
    fn reset_counters_clears_cycle_state() {
        let mut engine = ProbeEngine::new();
        engine.add_test_interface(0, "wan", 3, 2);

        // Start a cycle (probe target 0)
        engine.simulate_send(0);
        engine.simulate_response(0);
        engine.record_timeout(0); // advances to pos 1

        // Reset mid-cycle
        engine.reset_counters(0);

        // Should start a fresh cycle from position 0
        engine.simulate_send(0);
        engine.simulate_response(0);
        assert!(engine.record_timeout(0).is_none()); // mid-cycle at pos 1

        engine.simulate_send(0);
        engine.simulate_response(0);
        assert!(engine.record_timeout(0).is_none()); // mid-cycle at pos 2

        engine.simulate_send(0);
        engine.simulate_response(0);
        let result = engine.record_timeout(0).expect("cycle should complete");
        assert!(result.success); // 3/3 >= 2
    }

    // --- Quality-based probing tests ---

    #[test]
    fn quality_ok_without_thresholds() {
        // No quality thresholds configured -> quality_ok always true
        let mut engine = ProbeEngine::new();
        engine.add_test_interface(0, "wan", 1, 1);

        engine.simulate_send(0);
        engine.simulate_response(0);
        let result = engine.record_timeout(0).unwrap();
        assert!(result.quality_ok);
        assert!(result.success);
    }

    #[test]
    fn latency_threshold_not_evaluated_until_window_full() {
        // latency_threshold=50ms, window=3: quality not checked until 3 probes
        let mut engine = ProbeEngine::new();
        engine.add_test_interface_quality(0, "wan", 1, 1, Some(50), None, 3);

        // Probe 1: 200ms RTT (way over threshold)
        engine.simulate_send(0);
        engine.simulate_response_with_rtt(0, 200);
        let r = engine.record_timeout(0).unwrap();
        assert!(r.quality_ok); // window not full yet (1/3)

        // Probe 2: 200ms RTT
        engine.simulate_send(0);
        engine.simulate_response_with_rtt(0, 200);
        let r = engine.record_timeout(0).unwrap();
        assert!(r.quality_ok); // window not full yet (2/3)

        // Probe 3: 200ms RTT -> window full, threshold breached
        engine.simulate_send(0);
        engine.simulate_response_with_rtt(0, 200);
        let r = engine.record_timeout(0).unwrap();
        assert!(!r.quality_ok); // avg 200ms > 50ms threshold
        assert_eq!(r.avg_rtt_ms, Some(200));
    }

    #[test]
    fn latency_threshold_triggers_degradation() {
        // latency_threshold=100ms, window=2
        let mut engine = ProbeEngine::new();
        engine.add_test_interface_quality(0, "wan", 1, 1, Some(100), None, 2);

        // 2 probes with 150ms RTT -> avg=150 > threshold=100
        engine.simulate_send(0);
        engine.simulate_response_with_rtt(0, 150);
        engine.record_timeout(0);

        engine.simulate_send(0);
        engine.simulate_response_with_rtt(0, 150);
        let r = engine.record_timeout(0).unwrap();
        assert!(!r.quality_ok);
        assert_eq!(r.avg_rtt_ms, Some(150));
    }

    #[test]
    fn latency_threshold_recovers() {
        // latency_threshold=100ms, window=2
        let mut engine = ProbeEngine::new();
        engine.add_test_interface_quality(0, "wan", 1, 1, Some(100), None, 2);

        // Fill window with high latency
        engine.simulate_send(0);
        engine.simulate_response_with_rtt(0, 150);
        engine.record_timeout(0);

        engine.simulate_send(0);
        engine.simulate_response_with_rtt(0, 150);
        let r = engine.record_timeout(0).unwrap();
        assert!(!r.quality_ok);

        // Now send low latency probes to recover
        engine.simulate_send(0);
        engine.simulate_response_with_rtt(0, 20);
        engine.record_timeout(0);

        engine.simulate_send(0);
        engine.simulate_response_with_rtt(0, 30);
        let r = engine.record_timeout(0).unwrap();
        assert!(r.quality_ok); // avg 25ms < 100ms
        assert_eq!(r.avg_rtt_ms, Some(25));
    }

    #[test]
    fn loss_threshold_triggers_degradation() {
        // loss_threshold=30%, window=4: > 30% loss triggers degradation
        let mut engine = ProbeEngine::new();
        engine.add_test_interface_quality(0, "wan", 1, 1, None, Some(30), 4);

        // Cycle 1: success
        engine.simulate_send(0);
        engine.simulate_response(0);
        let r = engine.record_timeout(0).unwrap();
        assert!(r.quality_ok); // 1/4 window not full

        // Cycle 2: timeout
        engine.simulate_send(0);
        let r = engine.record_timeout(0).unwrap();
        assert!(r.quality_ok); // 2/4 window not full

        // Cycle 3: success
        engine.simulate_send(0);
        engine.simulate_response(0);
        let r = engine.record_timeout(0).unwrap();
        assert!(r.quality_ok); // 3/4 window not full

        // Cycle 4: timeout -> 50% loss > 30% threshold
        engine.simulate_send(0);
        let r = engine.record_timeout(0).unwrap();
        assert!(!r.quality_ok);
        assert_eq!(r.loss_percent, 50);
    }

    #[test]
    fn loss_threshold_below_is_ok() {
        // loss_threshold=50%, window=4: <= 50% loss is ok
        let mut engine = ProbeEngine::new();
        engine.add_test_interface_quality(0, "wan", 1, 1, None, Some(50), 4);

        // 3 successes, 1 loss -> 25% loss <= 50%
        for _ in 0..3 {
            engine.simulate_send(0);
            engine.simulate_response(0);
            engine.record_timeout(0);
        }

        engine.simulate_send(0);
        let r = engine.record_timeout(0).unwrap();
        assert!(r.quality_ok);
        assert_eq!(r.loss_percent, 25);
    }

    #[test]
    fn quality_window_slides() {
        // Verify old entries drop off as new ones enter
        let mut engine = ProbeEngine::new();
        engine.add_test_interface_quality(0, "wan", 1, 1, Some(100), None, 3);

        // Fill with high latency: 200, 200, 200 -> avg=200 > 100
        for _ in 0..3 {
            engine.simulate_send(0);
            engine.simulate_response_with_rtt(0, 200);
            engine.record_timeout(0);
        }

        // Now send low latency: window becomes [200, 200, 50] -> avg=150 > 100 still bad
        engine.simulate_send(0);
        engine.simulate_response_with_rtt(0, 50);
        let r = engine.record_timeout(0).unwrap();
        assert!(!r.quality_ok);

        // [200, 50, 50] -> avg=100, still degraded (recovery requires avg < threshold)
        engine.simulate_send(0);
        engine.simulate_response_with_rtt(0, 50);
        let r = engine.record_timeout(0).unwrap();
        assert!(!r.quality_ok); // avg=100, not < 100

        // [50, 50, 50] -> avg=50 < 100, recovers
        engine.simulate_send(0);
        engine.simulate_response_with_rtt(0, 50);
        let r = engine.record_timeout(0).unwrap();
        assert!(r.quality_ok);
        assert_eq!(r.avg_rtt_ms, Some(50));
    }

    #[test]
    fn combined_latency_and_loss_thresholds() {
        // Both thresholds: latency_threshold=100, loss_threshold=40%, window=5
        let mut engine = ProbeEngine::new();
        engine.add_test_interface_quality(0, "wan", 1, 1, Some(100), Some(40), 5);

        // 5 probes: all succeed with low latency -> quality ok
        for _ in 0..5 {
            engine.simulate_send(0);
            engine.simulate_response_with_rtt(0, 20);
            engine.record_timeout(0);
        }
        // Window: [20, 20, 20, 20, 20], loss=0%, avg=20

        // Add high latency probe (slides window): [20, 20, 20, 20, 200] avg=56
        engine.simulate_send(0);
        engine.simulate_response_with_rtt(0, 200);
        let r = engine.record_timeout(0).unwrap();
        assert!(r.quality_ok); // avg 56 < 100, loss 0%

        // More high latency: [20, 20, 20, 200, 200] avg=92
        engine.simulate_send(0);
        engine.simulate_response_with_rtt(0, 200);
        let r = engine.record_timeout(0).unwrap();
        assert!(r.quality_ok); // avg 92 < 100

        // [20, 20, 200, 200, 200] avg=128 > 100
        engine.simulate_send(0);
        engine.simulate_response_with_rtt(0, 200);
        let r = engine.record_timeout(0).unwrap();
        assert!(!r.quality_ok); // latency threshold breached
    }

    #[test]
    fn reset_counters_clears_quality_window() {
        let mut engine = ProbeEngine::new();
        engine.add_test_interface_quality(0, "wan", 1, 1, Some(50), None, 2);

        // Fill window with high latency
        for _ in 0..2 {
            engine.simulate_send(0);
            engine.simulate_response_with_rtt(0, 200);
            engine.record_timeout(0);
        }

        // Reset should clear quality window
        engine.reset_counters(0);

        // Window is empty, quality_ok should be true even with high latency
        engine.simulate_send(0);
        engine.simulate_response_with_rtt(0, 200);
        let r = engine.record_timeout(0).unwrap();
        assert!(r.quality_ok); // window not full (1/2)
    }

    #[test]
    fn quality_metrics_api() {
        let mut engine = ProbeEngine::new();
        engine.add_test_interface_quality(0, "wan", 1, 1, None, None, 3);

        // No data yet
        let (avg, loss) = engine.quality_metrics(0);
        assert_eq!(avg, None);
        assert_eq!(loss, 0);

        // Add some probes
        engine.simulate_send(0);
        engine.simulate_response_with_rtt(0, 50);
        engine.record_timeout(0);

        engine.simulate_send(0);
        engine.record_timeout(0); // timeout

        let (avg, loss) = engine.quality_metrics(0);
        assert_eq!(avg, Some(50)); // only 1 successful probe
        assert_eq!(loss, 50); // 1 loss out of 2
    }

    #[test]
    fn recovery_latency_hysteresis() {
        // latency_threshold=100ms, recovery_latency=50ms, window=2
        // Degrades at avg > 100, recovers only when avg < 50
        let mut engine = ProbeEngine::new();
        ProbeEngine::add_test_interface_with_recovery(
            &mut engine.probes,
            0, "wan", 1, 1,
            Some(100), None, Some(50), None, 2,
        );

        // Fill window: 150, 150 -> avg=150 > 100 -> degraded
        engine.simulate_send(0);
        engine.simulate_response_with_rtt(0, 150);
        engine.record_timeout(0);
        engine.simulate_send(0);
        engine.simulate_response_with_rtt(0, 150);
        let r = engine.record_timeout(0).unwrap();
        assert!(!r.quality_ok);

        // Improve to avg=75: below failure threshold (100) but above recovery (50)
        engine.simulate_send(0);
        engine.simulate_response_with_rtt(0, 75);
        engine.record_timeout(0);
        engine.simulate_send(0);
        engine.simulate_response_with_rtt(0, 75);
        let r = engine.record_timeout(0).unwrap();
        assert!(!r.quality_ok); // 75 not < 50, still degraded

        // Improve to avg=40: below recovery threshold (50)
        engine.simulate_send(0);
        engine.simulate_response_with_rtt(0, 40);
        engine.record_timeout(0);
        engine.simulate_send(0);
        engine.simulate_response_with_rtt(0, 40);
        let r = engine.record_timeout(0).unwrap();
        assert!(r.quality_ok); // 40 < 50, recovered
    }

    #[test]
    fn recovery_loss_hysteresis() {
        // loss_threshold=30%, recovery_loss=10%, window=5
        let mut engine = ProbeEngine::new();
        ProbeEngine::add_test_interface_with_recovery(
            &mut engine.probes,
            0, "wan", 1, 1,
            None, Some(30), None, Some(10), 5,
        );

        // 3 timeouts, 2 successes -> 60% loss > 30% -> degraded
        engine.simulate_send(0);
        engine.simulate_response(0);
        engine.record_timeout(0);

        engine.simulate_send(0);
        engine.record_timeout(0); // timeout

        engine.simulate_send(0);
        engine.record_timeout(0); // timeout

        engine.simulate_send(0);
        engine.record_timeout(0); // timeout

        engine.simulate_send(0);
        engine.simulate_response(0);
        let r = engine.record_timeout(0).unwrap();
        assert!(!r.quality_ok); // 60% > 30%

        // Add 3 successes and 2 timeouts -> window becomes
        // [timeout, timeout, success, success, timeout] from prior
        // but slides to: [success, success, success, timeout, timeout]
        // Actually let's just alternate: timeout, success, success, success, timeout
        // = 2/5 = 40% -> still above recovery threshold (10%)
        engine.simulate_send(0);
        engine.record_timeout(0); // timeout

        engine.simulate_send(0);
        engine.simulate_response(0);
        engine.record_timeout(0);

        engine.simulate_send(0);
        engine.simulate_response(0);
        engine.record_timeout(0);

        engine.simulate_send(0);
        engine.simulate_response(0);
        engine.record_timeout(0);

        engine.simulate_send(0);
        engine.record_timeout(0); // timeout
        // Window: [timeout, success, success, success, timeout] = 40% loss
        // 40% not < 10% recovery threshold -> still degraded
        // But also: previous cycles evaluated quality and may have set quality_degraded
        // The window at each step never goes below 10%, so stays degraded
        assert!(engine.probes[0].quality_degraded);

        // Now fill with all successes -> 0% loss < 10% recovery threshold
        for _ in 0..5 {
            engine.simulate_send(0);
            engine.simulate_response(0);
            engine.record_timeout(0);
        }
        // Window: [success, success, success, success, success] = 0% loss
        assert!(!engine.probes[0].quality_degraded); // recovered
    }

    #[test]
    fn no_recovery_thresholds_uses_failure_thresholds() {
        // Without recovery thresholds, recovery uses failure threshold with < comparison
        let mut engine = ProbeEngine::new();
        ProbeEngine::add_test_interface_with_recovery(
            &mut engine.probes,
            0, "wan", 1, 1,
            Some(100), None, None, None, 2,
        );

        // Degrade: avg=150 > 100
        engine.simulate_send(0);
        engine.simulate_response_with_rtt(0, 150);
        engine.record_timeout(0);
        engine.simulate_send(0);
        engine.simulate_response_with_rtt(0, 150);
        let r = engine.record_timeout(0).unwrap();
        assert!(!r.quality_ok);

        // avg=100: not < 100, stays degraded
        engine.simulate_send(0);
        engine.simulate_response_with_rtt(0, 100);
        engine.record_timeout(0);
        engine.simulate_send(0);
        engine.simulate_response_with_rtt(0, 100);
        let r = engine.record_timeout(0).unwrap();
        assert!(!r.quality_ok);

        // avg=99: < 100, recovers
        engine.simulate_send(0);
        engine.simulate_response_with_rtt(0, 99);
        engine.record_timeout(0);
        engine.simulate_send(0);
        engine.simulate_response_with_rtt(0, 99);
        let r = engine.record_timeout(0).unwrap();
        assert!(r.quality_ok);
    }
}
