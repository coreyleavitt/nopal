use std::net::IpAddr;
use std::os::fd::RawFd;
use std::process::Command;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::{Duration, Instant};

use mio::unix::SourceFd;
use mio::{Events, Interest, Poll, Token};

use crate::config;
use crate::config::schema::*;
use crate::dns::DnsManager;
use crate::error::{Error, Result};
use crate::health::ProbeEngine;
use crate::ipc::IpcServer;
use crate::ipc::methods::{self, DispatchAction};
use crate::ipc::protocol::Response;
use crate::netlink::conntrack::ConntrackManager;
use crate::netlink::link::{LinkEvent, LinkMonitor};
use crate::netlink::route::RouteManager;
use crate::netlink::route_monitor::{MonitorEvent, RouteMonitor};
use crate::nftables::{ChainBuilder, InterfaceInfo, NftEngine, PolicyInfo, PolicyMember, RuleInfo, StickyInfo};
use crate::state::{InterfaceState, InterfaceTracker};
use crate::state::policy::{self, ResolvedPolicy};
use crate::state::transition::{self, TransitionAction};
use crate::timer::{TimerId, TimerKind, TimerWheel};

// mio Token layout:
//   0          = link monitor
//   1          = IPC listener
//   2          = signal pipe
//   3          = route monitor
//   100..199   = ICMP probe sockets (token = 100 + interface_index)
//   1000+      = IPC client connections (token = 1000 + client_id)
const TOKEN_LINK_MONITOR: Token = Token(0);
const TOKEN_IPC_LISTENER: Token = Token(1);
const TOKEN_SIGNAL: Token = Token(2);
const TOKEN_ROUTE_MONITOR: Token = Token(3);

const TABLE_BASE: u32 = 100;

/// Assign stable (mark, table_id) pairs for a set of interface names.
///
/// Marks are derived from a hash of the interface name so they don't depend on
/// config ordering. Each name hashes to a slot in `1..=max_slots`, with linear
/// probing to resolve the rare collision. The returned vec is parallel to `names`.
///
/// `mark_mask` controls which firewall mark bits are used and how many slots
/// are available: `mark_step = lowest_set_bit(mask)`, `max_slots = mask / step - 1`.
fn assign_marks(names: &[&str], mark_mask: u32) -> Vec<(u32, u32)> {
    if mark_mask == 0 {
        log::error!("mark_mask is 0; no marks can be assigned");
        return names.iter().map(|_| (0, TABLE_BASE)).collect();
    }
    let mark_step = mark_mask & mark_mask.wrapping_neg();
    let max_slots = (mark_mask / mark_step - 1) as usize;

    if names.len() > max_slots {
        log::error!(
            "too many interfaces ({}, max {}); excess will be skipped",
            names.len(),
            max_slots,
        );
    }

    let mut used: Vec<bool> = vec![false; max_slots + 2]; // slots 1..=max_slots
    let mut result = Vec::with_capacity(names.len());

    for name in names {
        if result.len() >= max_slots {
            break;
        }
        let start = name_hash(name, max_slots);
        let mut slot = start;
        let mut probes = 0;
        while used[slot] {
            slot = if slot >= max_slots { 1 } else { slot + 1 };
            probes += 1;
            if probes >= max_slots {
                log::error!("mark slot exhausted for interface {name}");
                break;
            }
        }
        if probes >= max_slots {
            continue;
        }
        used[slot] = true;
        let mark = slot as u32 * mark_step;
        let table_id = TABLE_BASE + slot as u32;
        result.push((mark, table_id));
    }

    result
}

/// Hash an interface name to a value in 1..=max_slots (FNV-1a based).
fn name_hash(name: &str, max_slots: usize) -> usize {
    let mut h: u32 = 2166136261;
    for b in name.bytes() {
        h ^= b as u32;
        h = h.wrapping_mul(16777619);
    }
    (h as usize % max_slots) + 1
}

/// Build the `RuleInfo` vec from config. Called at init and reload.
fn build_rules(config: &NopalConfig) -> Vec<RuleInfo> {
    let ipv6_enabled = config.globals.ipv6_enabled;
    config
        .rules
        .iter()
        .filter_map(|r| {
            let family = match r.family {
                RuleFamily::Ipv4 => "ipv4",
                RuleFamily::Ipv6 => {
                    if !ipv6_enabled {
                        return None;
                    }
                    "ipv6"
                }
                RuleFamily::Any => {
                    if ipv6_enabled { "any" } else { "ipv4" }
                }
            };
            Some(RuleInfo {
                src_ip: r.src_ip.clone(),
                src_port: r.src_port.clone(),
                dest_ip: r.dest_ip.clone(),
                dest_port: r.dest_port.clone(),
                proto: r.proto.clone(),
                family: family.to_string(),
                src_iface: r.src_iface.clone(),
                ipset: r.ipset.clone(),
                policy: r.use_policy.clone(),
                sticky: if r.sticky {
                    Some(StickyInfo {
                        mode: match r.sticky_mode {
                            StickyMode::Flow => "flow".to_string(),
                            StickyMode::SrcIp => "src_ip".to_string(),
                            StickyMode::SrcDst => "src_dst".to_string(),
                        },
                        timeout: r.sticky_timeout,
                    })
                } else {
                    None
                },
                log: r.log && config.globals.logging,
            })
        })
        .collect()
}

/// The nopal daemon. Owns all components and drives the mio event loop.
pub struct Daemon {
    config: NopalConfig,
    config_path: String,
    poll: Poll,
    events: Events,
    timers: TimerWheel,

    // Components
    link_monitor: LinkMonitor,
    route_monitor: RouteMonitor,
    route_manager: RouteManager,
    nft_engine: NftEngine,
    probe_engine: ProbeEngine,
    dns_manager: DnsManager,
    ipc_server: IpcServer,
    conntrack: ConntrackManager,

    // Signal delivery
    signal_fd: RawFd,

    // State
    trackers: Vec<InterfaceTracker>,
    start_time: Instant,
    running: bool,
    reload_requested: bool,
    /// True after the first `connected` hook has fired (for FIRSTCONNECT env var).
    first_connect_fired: bool,
    /// Cached connected networks for IPC queries.
    connected_networks: Vec<String>,
    /// Whether the hook script exists (cached at init/reload to avoid stat per transition).
    hook_script_exists: bool,
    /// True when route/addr events have occurred since the last connected_networks refresh.
    connected_networks_dirty: bool,
    /// Deferred nftables regeneration flag. Set during `execute_actions` so that
    /// multiple transitions in the same event-loop iteration produce only one
    /// `nft` subprocess invocation.
    nftables_dirty: bool,
    /// Deferred DNS update flag: coalesces multiple DNS changes (e.g., at
    /// startup when several interfaces come online) into a single write +
    /// dnsmasq signal.
    dns_dirty: bool,
    /// Cached RuleInfo vec, rebuilt only at init and reload (rules don't change
    /// between config loads).
    cached_rules: Vec<RuleInfo>,
    /// Counter of in-flight hook script reaper threads (shared with spawned threads).
    in_flight_hooks: Arc<AtomicUsize>,

    // Reusable buffers to avoid per-iteration allocations in the event loop
    timer_buf: Vec<(TimerId, TimerKind)>,
    event_buf: Vec<(Token, bool)>,
}

impl Daemon {
    pub fn new(config_path: &str, signal_fd: RawFd) -> Result<Self> {
        let config = config::load(config_path)?;

        log::info!(
            "loaded config: {} interfaces, {} policies, {} rules",
            config.interfaces.len(),
            config.policies.len(),
            config.rules.len()
        );

        let poll = Poll::new()?;
        let events = Events::with_capacity(64);
        let timers = TimerWheel::new();

        // Initialize components
        let mut link_monitor = LinkMonitor::new()?;
        let mut route_monitor = RouteMonitor::new()?;
        let route_manager = RouteManager::new()?;
        let nft_engine = NftEngine::new();
        let probe_engine = ProbeEngine::new();
        let dns_manager = DnsManager::new();
        let mut ipc_server = IpcServer::new(&config.globals.ipc_socket)?;

        // Register signal pipe with mio
        poll.registry().register(
            &mut SourceFd(&signal_fd),
            TOKEN_SIGNAL,
            Interest::READABLE,
        )?;

        // Register link monitor with mio
        poll.registry().register(
            link_monitor.source(),
            TOKEN_LINK_MONITOR,
            Interest::READABLE,
        )?;

        // Register route monitor with mio
        poll.registry().register(
            route_monitor.source(),
            TOKEN_ROUTE_MONITOR,
            Interest::READABLE,
        )?;

        // Register IPC listener with mio
        poll.registry().register(
            ipc_server.listener_mut(),
            TOKEN_IPC_LISTENER,
            Interest::READABLE,
        )?;

        // Build interface trackers from config
        let ipv6_enabled = config.globals.ipv6_enabled;
        let enabled_names: Vec<&str> = config
            .interfaces
            .iter()
            .filter(|iface| iface.enabled)
            .filter(|iface| ipv6_enabled || iface.family != AddressFamily::Ipv6)
            .map(|iface| iface.name.as_str())
            .collect();
        let marks = assign_marks(&enabled_names, config.globals.mark_mask);

        let mut trackers = Vec::new();
        let mut mark_idx = 0;
        for (i, iface) in config.interfaces.iter().enumerate() {
            if !iface.enabled {
                continue;
            }
            if !ipv6_enabled && iface.family == AddressFamily::Ipv6 {
                log::warn!(
                    "{}: skipping IPv6-only interface (ipv6_enabled=false)",
                    iface.name
                );
                continue;
            }
            let Some(&(mark, table_id)) = marks.get(mark_idx) else {
                log::error!("{}: no mark slot available, skipping", iface.name);
                continue;
            };
            mark_idx += 1;
            let mut tracker = InterfaceTracker::new(
                iface.name.clone(),
                i,
                mark,
                table_id,
                iface.device.clone(),
                iface.up_count,
                iface.down_count,
            );
            if iface.dampening {
                tracker.set_dampening(
                    iface.dampening_halflife,
                    iface.dampening_ceiling,
                    iface.dampening_suppress,
                    iface.dampening_reuse,
                );
                log::info!(
                    "{}: dampening enabled (halflife={}, ceiling={}, suppress={}, reuse={})",
                    iface.name, iface.dampening_halflife, iface.dampening_ceiling,
                    iface.dampening_suppress, iface.dampening_reuse,
                );
            }
            trackers.push(tracker);
        }

        let hook_script_exists = {
            let s = &config.globals.hook_script;
            !s.is_empty() && std::path::Path::new(s).exists()
        };

        let cached_rules = build_rules(&config);

        Ok(Self {
            config,
            config_path: config_path.to_string(),
            poll,
            events,
            timers,
            link_monitor,
            route_monitor,
            route_manager,
            nft_engine,
            probe_engine,
            dns_manager,
            ipc_server,
            conntrack: ConntrackManager::new(),
            signal_fd,
            trackers,
            start_time: Instant::now(),
            running: true,
            reload_requested: false,
            first_connect_fired: false,
            connected_networks: Vec::new(),
            hook_script_exists,
            connected_networks_dirty: true,
            nftables_dirty: false,
            dns_dirty: false,
            cached_rules,
            in_flight_hooks: Arc::new(AtomicUsize::new(0)),
            timer_buf: Vec::new(),
            event_buf: Vec::new(),
        })
    }

    /// Run the main event loop.
    pub fn run(&mut self) -> Result<()> {
        log::info!("nopal daemon starting");

        // Initial setup: assume all interfaces are up and start probing.
        // On real hardware, we'd query netifd via ubus first.
        self.initialize_interfaces()?;

        while self.running {
            if self.reload_requested {
                self.handle_reload()?;
                self.reload_requested = false;
            }

            // Calculate poll timeout from next timer deadline
            let timeout = self
                .timers
                .next_deadline()
                .map(|d| d.max(Duration::from_millis(1)))
                .unwrap_or(Duration::from_secs(1));

            self.poll.poll(&mut self.events, Some(timeout))?;

            // Collect events into reusable buffer, then take it to avoid
            // borrow conflict between &self.event_buf and &mut self methods.
            self.event_buf.clear();
            self.event_buf.extend(
                self.events
                    .iter()
                    .map(|e| (e.token(), e.is_readable())),
            );
            let events = std::mem::take(&mut self.event_buf);

            for &(token, readable) in &events {
                if !readable {
                    continue;
                }
                match token {
                    TOKEN_SIGNAL => self.handle_signals(),
                    TOKEN_LINK_MONITOR => self.handle_link_events()?,
                    TOKEN_ROUTE_MONITOR => self.handle_route_events()?,
                    TOKEN_IPC_LISTENER => self.handle_ipc_accept()?,
                    t if t.0 >= 100 && t.0 < 1000 => {
                        self.handle_probe_response(t.0 - 100)?;
                    }
                    t if t.0 >= 1000 => {
                        self.handle_ipc_client(t.0 - 1000)?;
                    }
                    _ => {}
                }
            }
            self.event_buf = events;

            // Process expired timers
            self.timers.poll_into(&mut self.timer_buf);
            let fired = std::mem::take(&mut self.timer_buf);
            for &(_id, kind) in &fired {
                match kind {
                    TimerKind::Probe(idx) => self.handle_probe_timer(idx)?,
                    TimerKind::ProbeTimeout(idx) => self.handle_probe_timeout(idx)?,
                    TimerKind::DampenDecay(idx) => self.handle_dampen_decay(idx),
                    TimerKind::IpcTimeout(client_id) => {
                        self.ipc_server.remove_client(client_id, self.poll.registry());
                    }
                }
            }
            self.timer_buf = fired;

            // Deferred nftables regeneration: coalesce multiple transitions
            // from this iteration into a single nft subprocess invocation.
            if self.nftables_dirty {
                self.nftables_dirty = false;
                if let Err(e) = self.regenerate_nftables() {
                    log::error!("failed to regenerate nftables: {e}");
                }
            }

            // Deferred DNS update: coalesce multiple DNS changes into a
            // single resolv.conf write + dnsmasq signal.
            if self.dns_dirty {
                self.dns_dirty = false;
                if let Err(e) = self.dns_manager.apply() {
                    log::error!("failed to apply DNS update: {e}");
                }
            }
        }

        self.shutdown()?;
        Ok(())
    }

    // -- Signal handling --------------------------------------------------

    /// Drain the signal pipe and process each signal byte.
    fn handle_signals(&mut self) {
        let mut buf = [0u8; 32];
        loop {
            let ret = unsafe {
                libc::read(
                    self.signal_fd,
                    buf.as_mut_ptr() as *mut libc::c_void,
                    buf.len(),
                )
            };
            if ret <= 0 {
                break;
            }
            for &byte in &buf[..ret as usize] {
                match byte {
                    b'T' => {
                        log::info!("received shutdown signal");
                        self.running = false;
                    }
                    b'R' => {
                        log::info!("received reload signal");
                        self.reload_requested = true;
                    }
                    _ => {}
                }
            }
        }
    }

    // -- Initialization ---------------------------------------------------

    fn initialize_interfaces(&mut self) -> Result<()> {
        let mut online_indices = Vec::new();

        for tracker in &mut self.trackers {
            let iface_cfg = self
                .config
                .interfaces
                .iter()
                .find(|c| c.name == tracker.name);

            let initial_online = iface_cfg
                .map(|c| c.initial_state == InitialState::Online)
                .unwrap_or(false);

            if initial_online {
                // Start as Online immediately -- traffic flows before probes converge
                tracker.state = InterfaceState::Online;
                tracker.online_since = Some(Instant::now());
                tracker.success_count = tracker.up_count;
                online_indices.push(tracker.index);
                log::info!("{}: initial_state=online, active immediately", tracker.name);
            } else {
                // Normal path: assume link up, start probing
                tracker.link_up();
            }

            if let Some(cfg) = iface_cfg {
                let ipv6_ok = self.config.globals.ipv6_enabled;
                let targets: Vec<IpAddr> = cfg
                    .track_ip
                    .iter()
                    .filter_map(|ip| ip.parse().ok())
                    .filter(|ip: &IpAddr| ipv6_ok || !ip.is_ipv6())
                    .collect();

                if !targets.is_empty() {
                    if let Err(e) = self.probe_engine.add_interface(
                        tracker.index,
                        &tracker.name,
                        &tracker.device,
                        targets,
                        cfg.track_method,
                        &cfg.composite_methods,
                        cfg.reliability,
                        if cfg.check_quality { cfg.latency_threshold } else { None },
                        if cfg.check_quality { cfg.loss_threshold } else { None },
                        if cfg.check_quality { cfg.recovery_latency } else { None },
                        if cfg.check_quality { cfg.recovery_loss } else { None },
                        cfg.quality_window,
                        cfg.count,
                        cfg.max_ttl,
                        cfg.probe_size,
                        &cfg.dns_query_name,
                        cfg.track_port,
                    ) {
                        log::error!("failed to set up probes for {}: {e}", tracker.name);
                    }
                }

                // Schedule first probe after a short delay (even for initial_state=online,
                // probes run to detect if the interface is actually down)
                self.timers
                    .schedule(Duration::from_secs(1), TimerKind::Probe(tracker.index));
            }
        }

        // Register ICMP sockets with mio
        for (index, fd) in self.probe_engine.get_fds() {
            self.poll.registry().register(
                &mut SourceFd(&fd),
                Token(100 + index),
                Interest::READABLE,
            )?;
        }

        // Set up routes and DNS for initial_state=online interfaces
        for index in &online_indices {
            if let Err(e) = self.add_routes(*index) {
                log::error!("failed to add routes for initial online interface: {e}");
            }
            self.update_dns(*index);
        }

        // Generate initial nftables (includes all online interfaces)
        if let Err(e) = self.regenerate_nftables() {
            log::error!("failed initial nftables generation: {e}");
        }

        // Create status directories and write initial status files
        self.create_status_dirs();
        self.write_initial_status_files();

        Ok(())
    }

    // -- Event handlers ---------------------------------------------------

    fn handle_link_events(&mut self) -> Result<()> {
        let events = self.link_monitor.read_events()?;
        for event in events {
            match &event {
                LinkEvent::Up { ifname, ifindex } => {
                    let transition = self
                        .trackers
                        .iter_mut()
                        .find(|t| t.device == *ifname)
                        .and_then(|tracker| {
                            // Refresh cached ifindex on link up (interface may have been recreated)
                            tracker.ifindex = *ifindex;
                            let old_state = tracker.state;
                            tracker.link_up().map(|new_state| {
                                (tracker.name.clone(), tracker.index, tracker.mark, old_state, new_state, tracker.state)
                            })
                        });

                    if let Some((name, index, mark, old_state, new_state, current_state)) = transition {
                        // Cancel any stale probe timers from a previous
                        // link cycle before scheduling new ones.
                        self.timers.cancel_by_kind(|k| matches!(
                            k,
                            TimerKind::Probe(i) | TimerKind::ProbeTimeout(i) if *i == index
                        ));
                        // Reset quality window and hysteresis so stale data
                        // from the previous link session doesn't influence
                        // the fresh probe cycle.
                        self.probe_engine.reset_counters(index);
                        let actions = transition::actions_for_transition(
                            &name, index, mark, old_state, new_state,
                        );
                        self.execute_actions(actions)?;
                        self.maybe_flush_conntrack(index, mark, old_state, new_state, true);
                        if current_state == InterfaceState::Probing {
                            self.timers
                                .schedule(Duration::from_secs(1), TimerKind::Probe(index));
                        }
                    }
                }
                LinkEvent::Down { ifname, .. } => {
                    if let Some(tracker) = self
                        .trackers
                        .iter_mut()
                        .find(|t| t.device == *ifname)
                    {
                        let old_state = tracker.state;
                        if let Some(new_state) = tracker.link_down() {
                            let name = tracker.name.clone();
                            let index = tracker.index;
                            let mark = tracker.mark;
                            // Cancel outstanding probe timers to prevent stale
                            // timers from firing after the interface goes offline.
                            self.timers.cancel_by_kind(|k| matches!(
                                k,
                                TimerKind::Probe(i) | TimerKind::ProbeTimeout(i) if *i == index
                            ));
                            let actions = transition::actions_for_transition(
                                &name, index, mark, old_state, new_state,
                            );
                            self.execute_actions(actions)?;
                            self.maybe_flush_conntrack(index, mark, old_state, new_state, true);
                        }
                    }
                }
            }
        }
        Ok(())
    }

    /// Handle route and address change events from the netlink monitor.
    ///
    /// Route events: when a default route changes for a tracked device
    /// (e.g. DHCP renewal, PPPoE reconnect), re-sync the per-interface
    /// routing table.
    ///
    /// Address events: when an IP address changes on a tracked device,
    /// update the local_source ip rules so router-originated traffic
    /// continues to exit through the correct WAN link.
    fn handle_route_events(&mut self) -> Result<()> {
        let events = self.route_monitor.read_events()?;
        if events.is_empty() {
            return Ok(());
        }

        for event in events {
            match event {
                MonitorEvent::Route(re) => self.handle_route_change(&re),
                MonitorEvent::Address(ae) => self.handle_addr_change(&ae),
            }
        }

        Ok(())
    }

    /// Sync a per-interface routing table after a main table default route
    /// changed.
    fn handle_route_change(&mut self, event: &crate::netlink::route_monitor::RouteEvent) {
        let ipv6_enabled = self.config.globals.ipv6_enabled;

        // Skip IPv6 events if disabled
        if event.family == libc::AF_INET6 as u8 && !ipv6_enabled {
            return;
        }

        // Find tracker whose device matches this ifindex
        let tracker_info = self.trackers.iter().find_map(|t| {
            if t.ifindex != 0 && t.ifindex == event.ifindex {
                Some((t.name.clone(), t.device.clone(), t.table_id, t.index, t.state))
            } else {
                None
            }
        });

        let Some((name, device, table_id, index, state)) = tracker_info else {
            return;
        };

        // Only sync if the interface has routes installed (Online or Degraded)
        if state != InterfaceState::Online && state != InterfaceState::Degraded {
            return;
        }

        // Check if this address family is relevant for the interface
        if !self.family_relevant_for(index, event.family) {
            return;
        }

        let family_str = if event.family == libc::AF_INET as u8 {
            "ipv4"
        } else {
            "ipv6"
        };

        if event.is_delete {
            log::info!(
                "{name}: main table default route removed ({family_str})"
            );
            if let Err(e) = self.route_manager.del_route(table_id, event.family) {
                log::debug!(
                    "{name}: no route to remove from table {table_id}: {e}"
                );
            }
        } else {
            let gw_str = event
                .gateway
                .map(|g| g.to_string())
                .unwrap_or_else(|| "unknown".to_string());
            log::info!(
                "{name}: main table default route changed to {gw_str} ({family_str}), \
                 syncing table {table_id}"
            );
            // Delete old route (ignore errors -- may not exist)
            let _ = self.route_manager.del_route(table_id, event.family);
            // Copy new default route from main table
            if let Err(e) =
                self.route_manager
                    .copy_default_route(&device, table_id, event.family)
            {
                log::warn!(
                    "{name}: failed to sync default route to table {table_id}: {e}"
                );
            }
        }

        self.connected_networks_dirty = true;
    }

    /// Update local_source ip rules after an address change on a tracked
    /// device.
    fn handle_addr_change(&mut self, event: &crate::netlink::route_monitor::AddrEvent) {
        let ipv6_enabled = self.config.globals.ipv6_enabled;

        // Skip IPv6 events if disabled
        if event.family == libc::AF_INET6 as u8 && !ipv6_enabled {
            return;
        }

        // Find tracker whose device matches this ifindex
        let tracker_info = self.trackers.iter().find_map(|t| {
            if t.ifindex != 0 && t.ifindex == event.ifindex {
                Some((t.name.clone(), t.table_id, t.index, t.state))
            } else {
                None
            }
        });

        let Some((name, table_id, index, state)) = tracker_info else {
            return;
        };

        // Only act if the interface has routes installed
        if state != InterfaceState::Online && state != InterfaceState::Degraded {
            return;
        }

        // Only act if local_source is enabled for this interface
        let local_source = self
            .config
            .interfaces
            .get(index)
            .map(|c| c.local_source)
            .unwrap_or(false);

        if !local_source {
            return;
        }

        if !self.family_relevant_for(index, event.family) {
            return;
        }

        let host_prefix = if event.family == libc::AF_INET as u8 { 32 } else { 128 };
        let priority = 90 + index as u32;

        if event.is_delete {
            log::info!(
                "{name}: address {} removed, deleting source rule",
                event.address
            );
            if let Err(e) = self.route_manager.del_source_rule(
                event.address, host_prefix, table_id, priority, event.family,
            ) {
                log::debug!(
                    "{name}: no source rule to remove for {}: {e}",
                    event.address
                );
            }
            if let Some(tracker) = self.trackers.iter_mut().find(|t| t.index == index) {
                tracker.source_rules.retain(|r| r.0 != event.address || r.4 != event.family);
            }
        } else {
            log::info!(
                "{name}: address {} added, adding source rule (table {table_id})",
                event.address
            );
            if let Err(e) = self.route_manager.add_source_rule(
                event.address, host_prefix, table_id, priority, event.family,
            ) {
                log::debug!(
                    "{name}: source rule for {} already exists or failed: {e}",
                    event.address
                );
            } else if let Some(tracker) = self.trackers.iter_mut().find(|t| t.index == index) {
                tracker.source_rules.push((event.address, host_prefix, table_id, priority, event.family));
            }
        }

        self.connected_networks_dirty = true;
    }

    /// Check if an address family is relevant for a named interface.
    fn family_relevant_for(&self, index: usize, family: u8) -> bool {
        let iface_family = self
            .config
            .interfaces
            .get(index)
            .map(|c| c.family)
            .unwrap_or(AddressFamily::Ipv4);

        match family {
            f if f == libc::AF_INET as u8 => {
                iface_family == AddressFamily::Ipv4
                    || iface_family == AddressFamily::Both
            }
            f if f == libc::AF_INET6 as u8 => {
                iface_family == AddressFamily::Ipv6
                    || iface_family == AddressFamily::Both
            }
            _ => false,
        }
    }

    fn handle_probe_timer(&mut self, index: usize) -> Result<()> {
        if let Err(e) = self.probe_engine.send_probe(index) {
            log::warn!("failed to send probe for interface {index}: {e}");
            // Cancel any pending ProbeTimeout from a previous successful send
            // to prevent a stale timeout from double-recording.
            self.timers
                .cancel_by_kind(|k| matches!(k, TimerKind::ProbeTimeout(i) if *i == index));
            // Treat send failure as an immediate timeout -- record it so the
            // state machine sees the failure instead of silently skipping.
            if let Some(result) = self.probe_engine.record_timeout(index) {
                self.process_probe_result(result)?;
            }
            // Schedule next probe at the normal interval (not a timeout).
            let interval = self.probe_interval_for(index);
            self.timers.schedule(
                Duration::from_secs(interval as u64),
                TimerKind::Probe(index),
            );
            return Ok(());
        }

        // Schedule probe timeout
        let timeout_secs = self.probe_timeout_for(index);
        self.timers.schedule(
            Duration::from_secs(timeout_secs as u64),
            TimerKind::ProbeTimeout(index),
        );

        Ok(())
    }

    /// Handle a readability event on a probe socket.
    ///
    /// The `_index` parameter is the sequential slot from `get_fds()`, NOT
    /// the interface config index (which may have gaps due to disabled
    /// interfaces). We intentionally call `check_responses()` globally
    /// because it tries a non-blocking recv on every probe socket -- this
    /// is correct and simpler than per-socket dispatch.
    fn handle_probe_response(&mut self, _index: usize) -> Result<()> {
        self.probe_engine.check_responses();
        Ok(())
    }

    fn handle_probe_timeout(&mut self, index: usize) -> Result<()> {
        // Final check for responses before recording timeout. This is
        // essential for HTTP probes which don't register with mio and
        // rely on this call to check TCP connection state.
        self.probe_engine.check_responses();

        if let Some(result) = self.probe_engine.record_timeout(index) {
            self.process_probe_result(result)?;
        }

        // Schedule next probe
        let interval = self.probe_interval_for(index);
        self.timers.schedule(
            Duration::from_secs(interval as u64),
            TimerKind::Probe(index),
        );

        Ok(())
    }

    fn process_probe_result(&mut self, result: crate::health::ProbeResult) -> Result<()> {
        let tracker = match self
            .trackers
            .iter_mut()
            .find(|t| t.index == result.interface_index)
        {
            Some(t) => t,
            None => return Ok(()),
        };

        // Update quality metrics for status reporting
        tracker.avg_rtt_ms = result.avg_rtt_ms;
        tracker.loss_percent = result.loss_percent;

        let old_state = tracker.state;
        let new_state = if result.success {
            tracker.probe_success(result.quality_ok)
        } else {
            tracker.probe_failure()
        };

        if let Some(new_state) = new_state {
            let name = tracker.name.clone();
            let index = tracker.index;
            let mark = tracker.mark;

            // Schedule dampening decay timer when transitioning to Offline while suppressed
            if new_state == InterfaceState::Offline {
                if let Some(ref damp) = tracker.dampening {
                    if damp.is_suppressed() {
                        self.schedule_dampen_decay(index);
                    }
                }
            }

            let actions =
                transition::actions_for_transition(&name, index, mark, old_state, new_state);
            self.execute_actions(actions)?;
            self.maybe_flush_conntrack(index, mark, old_state, new_state, false);
        }

        Ok(())
    }

    fn handle_ipc_accept(&mut self) -> Result<()> {
        while let Some((client_id, _stream)) = self.ipc_server.accept()? {
            let token = Token(1000 + client_id);
            if let Some(s) = self.ipc_server.client_stream(client_id) {
                let _ = self.poll.registry().register(s, token, Interest::READABLE);
            }
            // Reap idle clients that never send a request.
            self.timers.schedule(
                Duration::from_secs(30),
                TimerKind::IpcTimeout(client_id),
            );
        }
        Ok(())
    }

    fn handle_ipc_client(&mut self, client_id: usize) -> Result<()> {
        let requests = self.ipc_server.read_client(client_id, self.poll.registry())?;
        if requests.is_empty() {
            return Ok(());
        }

        // Client is active -- cancel the idle timeout.
        self.timers
            .cancel_by_kind(|k| matches!(k, TimerKind::IpcTimeout(id) if *id == client_id));

        // Resolve policies lazily -- only if a request actually needs them.
        let needs_policies = requests.iter().any(|r| r.method == "status");
        let resolved = if needs_policies {
            self.resolve_all_policies()
        } else {
            Vec::new()
        };

        for request in requests {
            let (response, action) = methods::dispatch(
                &request,
                self.start_time,
                &self.trackers,
                &resolved,
                &self.connected_networks,
                &self.probe_engine,
            );
            self.ipc_server.send_response(client_id, &response, self.poll.registry())?;

            if let Some(DispatchAction::Reload) = action {
                self.reload_requested = true;
            }
        }
        Ok(())
    }

    // -- Action execution -------------------------------------------------

    fn execute_actions(&mut self, actions: Vec<TransitionAction>) -> Result<()> {
        for action in actions {
            match action {
                TransitionAction::RegenerateNftables => {
                    self.nftables_dirty = true;
                }
                TransitionAction::AddRoutes { index } => {
                    if let Err(e) = self.add_routes(index) {
                        log::error!("failed to add routes for interface {index}: {e}");
                    }
                }
                TransitionAction::RemoveRoutes { index } => {
                    if let Err(e) = self.remove_routes(index) {
                        log::error!("failed to remove routes for interface {index}: {e}");
                    }
                }
                TransitionAction::UpdateDns { index } => {
                    self.update_dns(index);
                }
                TransitionAction::RemoveDns { index } => {
                    self.remove_dns(index);
                }
                TransitionAction::BroadcastEvent {
                    index,
                    new_state,
                } => {
                    if let Some(name) = self.trackers.get(index).map(|t| t.name.clone()) {
                        let event = Response::event(
                            "interface.state_change",
                            Some(&name),
                            Some(&new_state.to_string()),
                        );
                        self.ipc_server.broadcast_event(&event, self.poll.registry());
                        self.run_hook(&name, new_state);
                    }
                }
                TransitionAction::WriteStatus {
                    index,
                    new_state,
                } => {
                    self.write_status_file(index, new_state);
                }
            }
        }
        Ok(())
    }

    /// Execute the user hook script on state changes.
    ///
    /// The script receives environment variables compatible with mwan3.user:
    /// - `ACTION`: connected, disconnected, ifup, degraded
    /// - `INTERFACE`: logical interface name
    /// - `DEVICE`: physical device name
    /// - `FIRSTCONNECT`: set to `"1"` only on the very first `connected`
    ///   event after daemon startup (not set on subsequent events)
    ///
    /// The process is fire-and-forget -- errors are logged but not propagated.
    fn run_hook(&mut self, interface: &str, new_state: InterfaceState) {
        if !self.hook_script_exists {
            return;
        }
        let script = &self.config.globals.hook_script;

        let action = match new_state {
            InterfaceState::Online => "connected",
            InterfaceState::Offline => "disconnected",
            InterfaceState::Probing => "ifup",
            InterfaceState::Degraded => "degraded",
            InterfaceState::Init => return, // no hook for init
        };

        let device = self
            .trackers
            .iter()
            .find(|t| t.name == interface)
            .map(|t| t.device.as_str())
            .unwrap_or("");

        let first_connect = action == "connected" && !self.first_connect_fired;
        if first_connect {
            self.first_connect_fired = true;
        }

        log::info!("running hook: {script} ACTION={action} INTERFACE={interface} DEVICE={device}");

        let mut cmd = Command::new(script);
        cmd.env("ACTION", action)
            .env("INTERFACE", interface)
            .env("DEVICE", device);
        if first_connect {
            cmd.env("FIRSTCONNECT", "1");
        }

        const MAX_IN_FLIGHT_HOOKS: usize = 4;
        let current = self.in_flight_hooks.load(Ordering::Relaxed);
        if current >= MAX_IN_FLIGHT_HOOKS {
            log::warn!("hook script skipped ({current} already in flight)");
            return;
        }

        match cmd.spawn()
        {
            Ok(mut child) => {
                self.in_flight_hooks.fetch_add(1, Ordering::Relaxed);
                let counter = Arc::clone(&self.in_flight_hooks);
                // Reap in background to avoid zombies
                std::thread::spawn(move || {
                    match child.wait() {
                        Ok(status) if !status.success() => {
                            log::warn!("hook script exited with {status}");
                        }
                        Err(e) => {
                            log::warn!("failed to wait on hook script: {e}");
                        }
                        _ => {}
                    }
                    counter.fetch_sub(1, Ordering::Relaxed);
                });
            }
            Err(e) => {
                log::warn!("failed to execute hook script {script}: {e}");
            }
        }
    }

    /// Write interface state to /var/run/nopal/<interface>/status.
    ///
    /// Format: first line is the state name (for backward-compatible parsing),
    /// followed by key=value lines with counters and timing data.
    /// Create status directories for all tracked interfaces (called once at init/reload).
    fn create_status_dirs(&self) {
        for tracker in &self.trackers {
            let dir = format!("/var/run/nopal/{}", tracker.name);
            if let Err(e) = std::fs::create_dir_all(&dir) {
                log::warn!("failed to create status dir {dir}: {e}");
            }
        }
    }

    fn write_status_file(&self, index: usize, state: InterfaceState) {
        let Some(tracker) = self.trackers.get(index) else { return };
        let interface = &tracker.name;
        let dir = format!("/var/run/nopal/{interface}");
        let mut content = format!("{state}\n");

        if let Some(since) = tracker.online_since {
            content.push_str(&format!("uptime={}\n", since.elapsed().as_secs()));
        }
        if let Some(since) = tracker.offline_since {
            content.push_str(&format!("downtime={}\n", since.elapsed().as_secs()));
        }
        content.push_str(&format!("success_count={}\n", tracker.success_count));
        content.push_str(&format!("fail_count={}\n", tracker.fail_count));
        if let Some(rtt) = tracker.avg_rtt_ms {
            content.push_str(&format!("avg_rtt_ms={rtt}\n"));
        }
        content.push_str(&format!("loss_percent={}\n", tracker.loss_percent));

        // Atomic write via temp + rename with O_EXCL to prevent symlink attacks.
        let tmp = format!("{dir}/status.tmp.{}", std::process::id());
        let _ = std::fs::remove_file(&tmp);
        let path = format!("{dir}/status");
        match std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&tmp)
        {
            Ok(mut f) => {
                use std::io::Write;
                let _ = f.write_all(content.as_bytes());
                if let Err(e) = std::fs::rename(&tmp, &path) {
                    log::warn!("failed to rename status file {tmp} -> {path}: {e}");
                    let _ = std::fs::remove_file(&tmp);
                }
            }
            Err(e) => {
                log::warn!("failed to create status file {tmp}: {e}");
            }
        }
    }

    /// Write initial status files for all configured interfaces.
    fn write_initial_status_files(&self) {
        for (i, tracker) in self.trackers.iter().enumerate() {
            self.write_status_file(i, tracker.state);
        }
    }

    /// Remove /var/run/nopal/ directory on shutdown.
    fn cleanup_status_files(&self) {
        if let Err(e) = std::fs::remove_dir_all("/var/run/nopal") {
            log::debug!("failed to clean up status files: {e}");
        }
    }

    fn regenerate_nftables(&mut self) -> Result<()> {
        let interfaces: Vec<InterfaceInfo> = self
            .trackers
            .iter()
            .filter(|t| t.is_active())
            .map(|t| {
                let clamp_mss = self
                    .config
                    .interfaces
                    .get(t.index)
                    .map(|c| c.clamp_mss)
                    .unwrap_or(false);
                InterfaceInfo {
                    name: t.name.clone(),
                    mark: t.mark,
                    table_id: t.table_id,
                    device: t.device.clone(),
                    clamp_mss,
                }
            })
            .collect();

        let resolved = self.resolve_all_policies();
        let policies: Vec<PolicyInfo> = resolved
            .iter()
            .map(|rp| {
                let members = rp
                    .active_tier()
                    .map(|t| {
                        t.members
                            .iter()
                            .map(|m| PolicyMember {
                                interface: m.interface.clone(),
                                mark: m.mark,
                                weight: m.weight,
                                metric: 0,
                            })
                            .collect()
                    })
                    .unwrap_or_default();
                PolicyInfo {
                    name: rp.name.clone(),
                    members,
                    last_resort: rp.last_resort,
                }
            })
            .collect();

        let ipv6_enabled = self.config.globals.ipv6_enabled;

        if self.connected_networks_dirty {
            self.connected_networks = self.route_manager
                .get_connected_networks(&self.config.globals.rt_table_lookup)
                .unwrap_or_default()
                .into_iter()
                .filter(|cidr| ipv6_enabled || !cidr.contains(':'))
                .collect();
            self.connected_networks_dirty = false;
        }
        let ruleset = ChainBuilder::build_ruleset(&interfaces, &policies, &self.cached_rules, &self.connected_networks, self.config.globals.mark_mask);
        self.nft_engine.apply(&ruleset)
    }

    fn add_routes(&mut self, index: usize) -> Result<()> {
        let tracker = self
            .trackers
            .iter()
            .find(|t| t.index == index)
            .ok_or_else(|| Error::State(format!("no tracker for index {index}")))?;

        let mark = tracker.mark;
        let table_id = tracker.table_id;
        let name = tracker.name.clone();
        let device = tracker.device.clone();

        let cfg = self.config.interfaces.get(index);
        let family = cfg.map(|c| c.family).unwrap_or(AddressFamily::Ipv4);
        let local_source = cfg.map(|c| c.local_source).unwrap_or(false);

        if family == AddressFamily::Ipv4 || family == AddressFamily::Both {
            let af = libc::AF_INET as u8;
            self.route_manager
                .add_rule(mark, self.config.globals.mark_mask, table_id, 100 + index as u32, af)?;
            if let Err(e) = self.route_manager.copy_default_route(
                &device, table_id, af,
            ) {
                log::warn!("failed to copy IPv4 default route for {name}: {e}");
            }
            if local_source {
                self.add_source_rules(&device, &name, table_id, index, af);
            }
        }

        if self.config.globals.ipv6_enabled
            && (family == AddressFamily::Ipv6 || family == AddressFamily::Both)
        {
            let af = libc::AF_INET6 as u8;
            self.route_manager
                .add_rule(mark, self.config.globals.mark_mask, table_id, 100 + index as u32, af)?;
            if let Err(e) = self.route_manager.copy_default_route(
                &device, table_id, af,
            ) {
                log::warn!("failed to copy IPv6 default route for {name}: {e}");
            }
            if local_source {
                self.add_source_rules(&device, &name, table_id, index, af);
            }
        }

        log::info!(
            "added routes for {name} (mark=0x{mark:04X}, table={table_id}, \
             local_source={local_source})"
        );
        Ok(())
    }

    fn remove_routes(&mut self, index: usize) -> Result<()> {
        let tracker = self
            .trackers
            .iter()
            .find(|t| t.index == index)
            .ok_or_else(|| Error::State(format!("no tracker for index {index}")))?;

        let mark = tracker.mark;
        let table_id = tracker.table_id;
        let name = tracker.name.clone();

        let cfg = self.config.interfaces.get(index);
        let family = cfg.map(|c| c.family).unwrap_or(AddressFamily::Ipv4);
        let local_source = cfg.map(|c| c.local_source).unwrap_or(false);

        if family == AddressFamily::Ipv4 || family == AddressFamily::Both {
            let af = libc::AF_INET as u8;
            if let Err(e) = self.route_manager.del_rule(
                mark, self.config.globals.mark_mask, table_id, 100 + index as u32, af,
            ) {
                log::warn!("failed to delete IPv4 ip rule for {name}: {e}");
            }
        }

        if self.config.globals.ipv6_enabled
            && (family == AddressFamily::Ipv6 || family == AddressFamily::Both)
        {
            let af = libc::AF_INET6 as u8;
            if let Err(e) = self.route_manager.del_rule(
                mark, self.config.globals.mark_mask, table_id, 100 + index as u32, af,
            ) {
                log::warn!("failed to delete IPv6 ip rule for {name}: {e}");
            }
        }

        if local_source {
            self.del_source_rules(&name, index);
        }

        if let Err(e) = self.route_manager.flush_table(table_id) {
            log::warn!("failed to flush table {table_id} for {name}: {e}");
        }

        log::info!("removed routes for {name}");
        Ok(())
    }

    /// Add source-address-based ip rules for all IPs on a device.
    ///
    /// Source rules use priority 90 + index (higher precedence than the
    /// fwmark rules at 100 + index) so traffic bound to a specific WAN IP
    /// is routed before the nftables-based policy routing.
    fn add_source_rules(
        &mut self,
        device: &str,
        name: &str,
        table_id: u32,
        index: usize,
        family: u8,
    ) {
        let addrs = match self.route_manager.get_device_addresses(device, family) {
            Ok(a) => a,
            Err(e) => {
                log::warn!("failed to get addresses for {name} ({device}): {e}");
                return;
            }
        };

        let priority = 90 + index as u32;
        for (addr, prefix_len) in &addrs {
            // Use host prefix (/32 or /128) for source matching
            let host_prefix = if family == libc::AF_INET as u8 { 32 } else { 128 };
            if let Err(e) = self.route_manager.add_source_rule(
                *addr, host_prefix, table_id, priority, family,
            ) {
                log::warn!(
                    "failed to add source rule for {addr}/{prefix_len} on {name}: {e}"
                );
            } else {
                log::info!(
                    "added source rule: from {addr} lookup {table_id} (prio {priority})"
                );
                // Track for reliable cleanup even if device address changes
                if let Some(tracker) = self.trackers.iter_mut().find(|t| t.index == index) {
                    tracker.source_rules.push((*addr, host_prefix, table_id, priority, family));
                }
            }
        }
    }

    /// Remove all stored source-address-based ip rules for an interface.
    ///
    /// Uses the tracked rules rather than re-querying device addresses,
    /// so cleanup works correctly even if the device address has changed
    /// (e.g. DHCP renewal, PPPoE reconnect). Drains all stored rules
    /// regardless of address family.
    fn del_source_rules(&mut self, name: &str, index: usize) {
        let rules: Vec<_> = self
            .trackers
            .iter_mut()
            .find(|t| t.index == index)
            .map(|t| std::mem::take(&mut t.source_rules))
            .unwrap_or_default();

        for (addr, prefix_len, table_id, priority, family) in &rules {
            if let Err(e) = self.route_manager.del_source_rule(
                *addr, *prefix_len, *table_id, *priority, *family,
            ) {
                log::warn!("failed to delete source rule for {addr} on {name}: {e}");
            }
        }
    }

    fn flush_conntrack(&mut self, mark: u32, mask: u32) {
        match self.config.globals.conntrack_flush {
            ConntrackFlushMode::Selective => {
                if let Err(e) = self.conntrack.flush_by_mark(mark, mask) {
                    log::error!("conntrack flush failed: {e}");
                }
            }
            ConntrackFlushMode::Full => {
                if let Err(e) = self.conntrack.flush_all() {
                    log::error!("conntrack flush all failed: {e}");
                }
            }
            ConntrackFlushMode::None => {}
        }
    }

    /// Check per-interface flush triggers and flush conntrack if the transition
    /// matches a configured trigger.
    fn maybe_flush_conntrack(
        &mut self,
        index: usize,
        mark: u32,
        old_state: InterfaceState,
        new_state: InterfaceState,
        link_event: bool,
    ) {
        let Some(cfg) = self.config.interfaces.get(index) else {
            return;
        };

        let trigger = match (old_state, new_state, link_event) {
            (_, InterfaceState::Probing, true) => ConntrackFlushTrigger::IfUp,
            (_, InterfaceState::Offline, true) => ConntrackFlushTrigger::IfDown,
            // Degraded->Online is quality recovery, not a new connection;
            // the interface never left routing so flushing would disrupt
            // existing connections unnecessarily.
            (InterfaceState::Degraded, InterfaceState::Online, _) => return,
            (_, InterfaceState::Online, _) => ConntrackFlushTrigger::Connected,
            (_, InterfaceState::Offline, false) => ConntrackFlushTrigger::Disconnected,
            _ => return,
        };

        if cfg.flush_conntrack.contains(&trigger) {
            log::debug!("{}: conntrack flush triggered by {new_state}", cfg.name);
            self.flush_conntrack(mark, self.config.globals.mark_mask);
        }
    }

    fn update_dns(&mut self, index: usize) {
        let Some(cfg) = self.config.interfaces.get(index) else { return };

        if cfg.update_dns && !cfg.dns_servers.is_empty() {
            self.dns_manager.set_servers(&cfg.name, &cfg.dns_servers);
            self.dns_dirty = true;
        }
    }

    fn remove_dns(&mut self, index: usize) {
        let Some(cfg) = self.config.interfaces.get(index) else { return };

        self.dns_manager.remove_interface(&cfg.name);
        self.dns_dirty = true;
    }

    // -- Helpers ----------------------------------------------------------

    fn resolve_all_policies(&self) -> Vec<ResolvedPolicy> {
        self.config
            .policies
            .iter()
            .map(|p| policy::resolve_policy(p, &self.config.members, &self.trackers))
            .collect()
    }

    fn probe_interval_for(&self, index: usize) -> u32 {
        let cfg = match self.config_for_index(index) {
            Some(c) => c,
            None => return 5,
        };

        let state = self
            .trackers
            .iter()
            .find(|t| t.index == index)
            .map(|t| t.state);

        match state {
            Some(InterfaceState::Offline) => {
                cfg.failure_interval.unwrap_or(cfg.probe_interval)
            }
            Some(InterfaceState::Probing) if cfg.keep_failure_interval => {
                cfg.failure_interval.unwrap_or(cfg.probe_interval)
            }
            Some(InterfaceState::Degraded) => {
                cfg.recovery_interval.unwrap_or(cfg.probe_interval)
            }
            _ => cfg.probe_interval,
        }
    }

    fn probe_timeout_for(&self, index: usize) -> u32 {
        self.config_for_index(index)
            .map(|c| c.probe_timeout)
            .unwrap_or(2)
    }

    fn config_for_index(&self, index: usize) -> Option<&InterfaceConfig> {
        self.config.interfaces.get(index)
    }

    fn handle_dampen_decay(&mut self, index: usize) {
        let tracker = match self.trackers.iter_mut().find(|t| t.index == index) {
            Some(t) => t,
            None => return,
        };

        let damp = match tracker.dampening {
            Some(ref mut d) => d,
            None => return,
        };

        damp.decay();

        if damp.is_suppressed() {
            log::debug!(
                "{}: dampening penalty decayed to {:.0} (reuse: {})",
                tracker.name, damp.penalty, damp.reuse,
            );
            // Still suppressed, schedule next decay check
            self.schedule_dampen_decay(index);
        } else {
            log::info!(
                "{}: dampening reuse threshold reached (penalty: {:.0}), unsuppressed",
                tracker.name, damp.penalty,
            );
            // If the interface is Offline with link still up, restart probing.
            // Without this, the interface stays stuck in Offline forever since
            // the state machine only exits Offline via link_up().
            if tracker.state == InterfaceState::Offline {
                let name = tracker.name.clone();
                let mark = tracker.mark;
                if let Some(new_state) = tracker.link_up() {
                    log::info!("{name}: restarting probing after dampening decay");
                    self.probe_engine.reset_counters(index);
                    let actions = transition::actions_for_transition(
                        &name, index, mark, InterfaceState::Offline, new_state,
                    );
                    if let Err(e) = self.execute_actions(actions) {
                        log::error!("failed to restart probing after dampening decay: {e}");
                    }
                    self.timers
                        .schedule(Duration::from_secs(1), TimerKind::Probe(index));
                }
            }
        }
    }

    fn schedule_dampen_decay(&mut self, index: usize) {
        // Cancel any existing decay timer for this interface
        self.timers
            .cancel_by_kind(|k| matches!(k, TimerKind::DampenDecay(i) if *i == index));

        // Schedule decay check at halflife/10 intervals for smooth decay
        let interval = self
            .config_for_index(index)
            .map(|c| c.dampening_halflife / 10)
            .unwrap_or(30)
            .max(1);

        self.timers.schedule(
            Duration::from_secs(interval as u64),
            TimerKind::DampenDecay(index),
        );
    }

    // -- Reload -----------------------------------------------------------

    fn handle_reload(&mut self) -> Result<()> {
        log::info!("reloading configuration from {}", self.config_path);

        let new_config = match config::load(&self.config_path) {
            Ok(c) => c,
            Err(e) => {
                log::error!("failed to reload config: {e}");
                return Ok(());
            }
        };

        let diff = config::diff::diff(&self.config, &new_config);
        if !diff.changed {
            log::info!("config unchanged, skipping reload");
            return Ok(());
        }

        // Fast path: only routing policies/rules changed -- regenerate nftables
        if !diff.needs_full_rebuild()
            && diff.changed_interfaces.is_empty()
            && diff.routing_changed
        {
            log::info!("only routing policies/rules changed, regenerating nftables");
            self.config = new_config;
            self.cached_rules = build_rules(&self.config);
            self.hook_script_exists = {
                let s = &self.config.globals.hook_script;
                !s.is_empty() && std::path::Path::new(s).exists()
            };
            if let Err(e) = self.regenerate_nftables() {
                log::error!("failed to regenerate nftables after reload: {e}");
            }
            return Ok(());
        }

        // Save current interface states by name for restoration
        let prev_states: Vec<(String, InterfaceState, Option<Instant>)> = self
            .trackers
            .iter()
            .map(|t| (t.name.clone(), t.state, t.online_since))
            .collect();

        // -- Teardown existing state --

        // Remove routes for active interfaces
        let active_indices: Vec<usize> = self
            .trackers
            .iter()
            .filter(|t| t.state == InterfaceState::Online || t.state == InterfaceState::Degraded)
            .map(|t| t.index)
            .collect();
        for index in active_indices {
            let _ = self.remove_routes(index);
        }

        // Deregister ICMP sockets from mio
        for (_index, fd) in self.probe_engine.get_fds() {
            let _ = self
                .poll
                .registry()
                .deregister(&mut SourceFd(&fd));
        }

        // Remove all interfaces from probe engine
        let probe_indices: Vec<usize> = self.trackers.iter().map(|t| t.index).collect();
        for idx in probe_indices {
            self.probe_engine.remove_interface(idx);
        }

        // Cancel all interface timers (preserve IPC timeouts)
        self.timers
            .cancel_by_kind(|k| !matches!(k, TimerKind::IpcTimeout(_)));

        // Remove all DNS entries
        let dns_names: Vec<String> = self.trackers.iter().map(|t| t.name.clone()).collect();
        for name in &dns_names {
            self.dns_manager.remove_interface(name);
        }
        let _ = self.dns_manager.apply();

        // -- Replace config and rebuild trackers --

        self.config = new_config;
        self.cached_rules = build_rules(&self.config);
        self.hook_script_exists = {
            let s = &self.config.globals.hook_script;
            !s.is_empty() && std::path::Path::new(s).exists()
        };

        let ipv6_enabled = self.config.globals.ipv6_enabled;
        let enabled_names: Vec<&str> = self
            .config
            .interfaces
            .iter()
            .filter(|iface| iface.enabled)
            .filter(|iface| ipv6_enabled || iface.family != AddressFamily::Ipv6)
            .map(|iface| iface.name.as_str())
            .collect();
        let marks = assign_marks(&enabled_names, self.config.globals.mark_mask);

        let mut new_trackers = Vec::new();
        let mut mark_idx = 0;
        for (i, iface) in self.config.interfaces.iter().enumerate() {
            if !iface.enabled {
                continue;
            }
            if !ipv6_enabled && iface.family == AddressFamily::Ipv6 {
                log::warn!(
                    "{}: skipping IPv6-only interface (ipv6_enabled=false)",
                    iface.name
                );
                continue;
            }
            let Some(&(mark, table_id)) = marks.get(mark_idx) else {
                log::error!("{}: no mark slot available, skipping", iface.name);
                continue;
            };
            mark_idx += 1;
            let mut tracker = InterfaceTracker::new(
                iface.name.clone(),
                i,
                mark,
                table_id,
                iface.device.clone(),
                iface.up_count,
                iface.down_count,
            );
            if iface.dampening {
                tracker.set_dampening(
                    iface.dampening_halflife,
                    iface.dampening_ceiling,
                    iface.dampening_suppress,
                    iface.dampening_reuse,
                );
            }

            // Restore state for previously-known interfaces
            if let Some((_, prev_state, prev_since)) =
                prev_states.iter().find(|(n, _, _)| *n == iface.name)
            {
                match prev_state {
                    InterfaceState::Online => {
                        tracker.state = InterfaceState::Online;
                        tracker.success_count = tracker.up_count;
                        tracker.online_since = *prev_since;
                    }
                    InterfaceState::Degraded => {
                        tracker.state = InterfaceState::Degraded;
                        tracker.success_count = tracker.up_count;
                        tracker.online_since = *prev_since;
                    }
                    InterfaceState::Probing => {
                        tracker.state = InterfaceState::Probing;
                    }
                    InterfaceState::Offline => {
                        tracker.state = InterfaceState::Offline;
                    }
                    InterfaceState::Init => {
                        tracker.link_up();
                    }
                }
            } else {
                // New interface: assume link is up, start probing
                tracker.link_up();
            }

            new_trackers.push(tracker);
        }
        self.trackers = new_trackers;
        self.create_status_dirs();

        // -- Reinitialize probes, routes, and DNS --

        // Set up probe engine for all interfaces (probes run regardless of state
        // so that link_up transitions have working probes immediately)
        for tracker in &self.trackers {
            let iface_cfg = self
                .config
                .interfaces
                .iter()
                .find(|c| c.name == tracker.name);

            if let Some(cfg) = iface_cfg {
                let ipv6_ok = self.config.globals.ipv6_enabled;
                let targets: Vec<IpAddr> = cfg
                    .track_ip
                    .iter()
                    .filter_map(|ip| ip.parse().ok())
                    .filter(|ip: &IpAddr| ipv6_ok || !ip.is_ipv6())
                    .collect();

                if !targets.is_empty() {
                    if let Err(e) = self.probe_engine.add_interface(
                        tracker.index,
                        &tracker.name,
                        &tracker.device,
                        targets,
                        cfg.track_method,
                        &cfg.composite_methods,
                        cfg.reliability,
                        if cfg.check_quality { cfg.latency_threshold } else { None },
                        if cfg.check_quality { cfg.loss_threshold } else { None },
                        if cfg.check_quality { cfg.recovery_latency } else { None },
                        if cfg.check_quality { cfg.recovery_loss } else { None },
                        cfg.quality_window,
                        cfg.count,
                        cfg.max_ttl,
                        cfg.probe_size,
                        &cfg.dns_query_name,
                        cfg.track_port,
                    ) {
                        log::error!("failed to set up probes for {}: {e}", tracker.name);
                    }
                }

                self.timers
                    .schedule(Duration::from_secs(1), TimerKind::Probe(tracker.index));
            }
        }

        // Register new ICMP sockets with mio
        for (index, fd) in self.probe_engine.get_fds() {
            self.poll.registry().register(
                &mut SourceFd(&fd),
                Token(100 + index),
                Interest::READABLE,
            )?;
        }

        // Restore routes and DNS for Online and Degraded interfaces
        let active_indices: Vec<usize> = self
            .trackers
            .iter()
            .filter(|t| t.state == InterfaceState::Online || t.state == InterfaceState::Degraded)
            .map(|t| t.index)
            .collect();
        for index in active_indices {
            if let Err(e) = self.add_routes(index) {
                log::error!("failed to restore routes after reload: {e}");
            }
            self.update_dns(index);
        }

        // Regenerate nftables
        if let Err(e) = self.regenerate_nftables() {
            log::error!("failed to regenerate nftables after reload: {e}");
        }

        log::info!(
            "configuration reloaded: {} interfaces, {} policies, {} rules",
            self.config.interfaces.len(),
            self.config.policies.len(),
            self.config.rules.len(),
        );
        Ok(())
    }

    // -- Shutdown ---------------------------------------------------------

    fn shutdown(&mut self) -> Result<()> {
        log::info!("nopal daemon shutting down");

        if let Err(e) = self.nft_engine.cleanup() {
            log::error!("failed to clean up nftables on shutdown: {e}");
        }

        for tracker in &self.trackers {
            let family = self
                .config
                .interfaces
                .iter()
                .find(|c| c.name == tracker.name)
                .map(|c| c.family)
                .unwrap_or(AddressFamily::Ipv4);

            let priority = 100 + tracker.index as u32;
            if family == AddressFamily::Ipv4 || family == AddressFamily::Both {
                let _ = self.route_manager.del_rule(
                    tracker.mark, self.config.globals.mark_mask, tracker.table_id, priority,
                    libc::AF_INET as u8,
                );
            }
            if self.config.globals.ipv6_enabled
                && (family == AddressFamily::Ipv6 || family == AddressFamily::Both)
            {
                let _ = self.route_manager.del_rule(
                    tracker.mark, self.config.globals.mark_mask, tracker.table_id, priority,
                    libc::AF_INET6 as u8,
                );
            }
            let _ = self.route_manager.flush_table(tracker.table_id);

            // Clean up source rules
            for (addr, prefix_len, table_id, priority, family) in &tracker.source_rules {
                let _ = self.route_manager.del_source_rule(
                    *addr, *prefix_len, *table_id, *priority, *family,
                );
            }
        }

        // Clean up status files
        self.cleanup_status_files();

        // Close the signal pipe read end
        if self.signal_fd >= 0 {
            unsafe { libc::close(self.signal_fd) };
            self.signal_fd = -1;
        }

        log::info!("nopal daemon stopped");
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const TEST_MASK: u32 = 0xFF00;

    #[test]
    fn marks_are_stable_across_reorder() {
        let marks_a = assign_marks(&["wan", "wanb"], TEST_MASK);
        let marks_b = assign_marks(&["wanb", "wan"], TEST_MASK);

        // "wan" should get the same mark regardless of position
        assert_eq!(marks_a[0], marks_b[1], "wan mark must be stable");
        assert_eq!(marks_a[1], marks_b[0], "wanb mark must be stable");
    }

    #[test]
    fn marks_are_unique() {
        let names: Vec<&str> = vec!["wan", "wanb", "wan3", "lte"];
        let marks = assign_marks(&names, TEST_MASK);

        for i in 0..marks.len() {
            for j in (i + 1)..marks.len() {
                assert_ne!(marks[i].0, marks[j].0, "marks must be unique");
                assert_ne!(marks[i].1, marks[j].1, "table_ids must be unique");
            }
        }
    }

    #[test]
    fn marks_are_nonzero_and_in_range() {
        let mark_step = TEST_MASK & TEST_MASK.wrapping_neg();
        let marks = assign_marks(&["wan", "wanb", "wan3"], TEST_MASK);
        for (mark, table_id) in &marks {
            assert!(*mark > 0 && *mark <= 254 * mark_step, "mark in range");
            assert!(*table_id > TABLE_BASE && *table_id <= TABLE_BASE + 254, "table_id in range");
        }
    }

    #[test]
    fn full_254_slots() {
        let names: Vec<String> = (0..254).map(|i| format!("iface{i}")).collect();
        let refs: Vec<&str> = names.iter().map(|s| s.as_str()).collect();
        let marks = assign_marks(&refs, TEST_MASK);
        assert_eq!(marks.len(), 254);

        // All unique
        for i in 0..marks.len() {
            for j in (i + 1)..marks.len() {
                assert_ne!(marks[i].0, marks[j].0);
            }
        }
    }

    #[test]
    fn overflow_truncates() {
        let names: Vec<String> = (0..300).map(|i| format!("iface{i}")).collect();
        let refs: Vec<&str> = names.iter().map(|s| s.as_str()).collect();
        let marks = assign_marks(&refs, TEST_MASK);
        assert_eq!(marks.len(), 254, "excess interfaces must be skipped");
    }

    #[test]
    fn custom_mask_limits_slots() {
        // 0x3F00 gives max_slots = (0x3F00/0x100) - 1 = 62
        let mask: u32 = 0x3F00;
        let names: Vec<String> = (0..100).map(|i| format!("iface{i}")).collect();
        let refs: Vec<&str> = names.iter().map(|s| s.as_str()).collect();
        let marks = assign_marks(&refs, mask);
        assert_eq!(marks.len(), 62, "0x3F00 mask supports 62 interfaces");
    }
}
