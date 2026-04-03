## Daemon event loop and component orchestration.
##
## Central orchestrator: owns all subsystem components, drives the
## selector-based event loop, dispatches probe/link/route/IPC events,
## and coalesces deferred nftables/DNS updates.

import std/[selectors, posix, monotimes, times, options, logging, os, strutils, strformat]

import ./errors
import ./config/schema
import ./config/parser
import ./config/diff
import ./config/discover
import ./state/machine
import ./state/tracker
import ./state/policy
import ./health/engine
import ./health/icmp
import ./health/dns
import ./health/http
import ./health/arp
import ./nftables/marks
import ./nftables/chains
import ./nftables/engine as nftEngine
import ./netlink/route
import ./netlink/link
import ./netlink/monitor
import ./netlink/conntrack
import ./dnsmanager
import ./timer
import ./hooks
import ./statusfiles
import ./ipc/server
import ./ipc/methods
import ./ipc/protocol

# =========================================================================
# Token constants for selector dispatch
# =========================================================================

const
  TokenLink* = 0
  TokenIpc* = 1
  TokenSignal* = 2
  TokenRoute* = 3
  ProbeTokenBase* = 100

# =========================================================================
# Daemon type
# =========================================================================

type
  Daemon* = object
    config: NopalConfig
    configPath: string
    selector: Selector[int]
    timers: TimerWheel

    # Subsystem components
    linkMonitor: LinkMonitor
    routeMonitor: RouteMonitor
    routeManager: RouteManager
    probeEngine: ProbeEngine
    dnsManager: DnsManager
    conntrackMgr: ConntrackManager
    ipcServer: IpcServer

    # Signal delivery
    signalFd: cint

    # Extracted subsystems
    hookRunner: HookRunner
    statusFiles: StatusFileManager

    # State
    trackers*: seq[InterfaceTracker]
    startTime: MonoTime
    running: bool
    connectedNetworks: seq[string]
    connectedNetworksDirty: bool
    nftablesDirty: bool
    dnsDirty: bool
    cachedRules: seq[RuleInfo]

    # Reusable buffers to avoid per-iteration allocations
    timerBuf: seq[TimerEntry]
    linkEventBuf: seq[LinkEvent]
    routeChangeBuf: seq[RouteChange]

# =========================================================================
# RuleInfo construction from config
# =========================================================================

proc buildRulesFromConfig(config: NopalConfig): seq[RuleInfo] =
  ## Build the RuleInfo vec from config. Called at init and reload.
  let ipv6Enabled = config.globals.ipv6Enabled
  for r in config.rules:
    let family = case r.family
      of rfIpv4: "ipv4"
      of rfIpv6:
        if not ipv6Enabled: continue
        "ipv6"
      of rfAny:
        if ipv6Enabled: "any" else: "ipv4"

    let sticky = if r.sticky:
      some(StickyInfo(
        mode: case r.stickyMode
          of smFlow: "flow"
          of smSrcIp: "src_ip"
          of smSrcDst: "src_dst",
        timeout: r.stickyTimeout,
      ))
    else:
      none(StickyInfo)

    result.add(RuleInfo(
      srcIp: r.srcIp,
      srcPort: r.srcPort,
      destIp: r.destIp,
      destPort: r.destPort,
      proto: r.proto,
      family: family,
      srcIface: r.srcIface,
      ipset: r.ipset,
      policy: r.usePolicy,
      sticky: sticky,
      log: r.log and config.globals.logging,
    ))

# =========================================================================
# Initialization
# =========================================================================


proc enrichConfigWithDiscovery(config: var NopalConfig) =
  ## Discover WANs from OpenWrt firewall/network config and enrich
  ## the parsed config with discovered interfaces, members, policies.
  let discovered = discoverWanInterfaces()
  if discovered.len > 0:
    let enriched = buildDiscoveredConfig(
      discovered, config.globals, config.interfaces,
      config.members, config.policies, config.rules)
    if config.interfaces.len == 0:
      config.interfaces = enriched.interfaces
      info fmt"auto-discovered {enriched.interfaces.len} WAN interface(s)"
    else:
      # Fill device for any interface missing it
      for iface in config.interfaces.mitems:
        if iface.device == "":
          for d in discovered:
            if d.name == iface.name:
              iface.device = d.device
              info fmt"resolved device for '{iface.name}' -> '{d.device}'"
        applyGlobalsDefaults(iface, config.globals)
    if config.members.len == 0:
      config.members = enriched.members
    if config.policies.len == 0:
      config.policies = enriched.policies
    if config.rules.len == 0:
      config.rules = enriched.rules
  elif config.interfaces.len == 0:
    warn "no WAN interfaces discovered and none configured — daemon will have nothing to manage"

proc initDaemon*(configPath: string, signalFd: cint): Daemon =
  ## Load config, discover WANs, create all subsystem components,
  ## register fds with selector, assign marks, build trackers.
  var config = loadConfig(configPath)
  enrichConfigWithDiscovery(config)

  info fmt"loaded config: {config.interfaces.len} interfaces, {config.policies.len} policies, {config.rules.len} rules"

  var selector = newSelector[int]()
  var timers = newTimerWheel()

  # Initialize subsystem components
  var linkMon = newLinkMonitor()
  var routeMon = newRouteMonitor()
  var routeMgr = newRouteManager()
  var probeEng = initProbeEngine()
  var dnsMgr = initDnsManager()
  var ctMgr = newConntrackManager()

  # Register signal pipe with selector
  selector.registerHandle(signalFd.int, {Read}, TokenSignal)

  # Register link monitor
  selector.registerHandle(linkMon.fd.int, {Read}, TokenLink)

  # Register route monitor
  selector.registerHandle(routeMon.fd.int, {Read}, TokenRoute)

  # Initialize IPC server (registers listener fd with selector)
  let ipcServer = initIpcServer(config.globals.ipcSocket, selector)

  # Build interface trackers from config
  let ipv6Enabled = config.globals.ipv6Enabled
  var enabledNames: seq[string]
  for iface in config.interfaces:
    if not iface.enabled: continue
    if not ipv6Enabled and iface.family == afIpv6: continue
    enabledNames.add(iface.name)

  let marks = assignMarks(enabledNames, config.globals.markMask)

  var trackers: seq[InterfaceTracker]
  var markIdx = 0
  for i, iface in config.interfaces:
    if not iface.enabled: continue
    if not ipv6Enabled and iface.family == afIpv6:
      warn fmt"{iface.name}: skipping IPv6-only interface (ipv6_enabled=false)"
      continue

    if markIdx >= marks.len:
      error fmt"{iface.name}: no mark slot available, skipping"
      continue

    let (mark, tableId) = marks[markIdx]
    inc markIdx

    var t = newTracker(
      iface.name, i, mark, tableId, iface.device,
      iface.upCount, iface.downCount,
    )

    if iface.dampening:
      t.setDampening(
        iface.dampeningHalflife,
        iface.dampeningCeiling,
        iface.dampeningSuppress,
        iface.dampeningReuse,
      )
      info fmt"{iface.name}: dampening enabled (halflife={iface.dampeningHalflife}, ceiling={iface.dampeningCeiling}, suppress={iface.dampeningSuppress}, reuse={iface.dampeningReuse})"

    trackers.add(t)

  let cachedRules = buildRulesFromConfig(config)

  result = Daemon(
    config: config,
    configPath: configPath,
    selector: selector,
    timers: timers,
    linkMonitor: linkMon,
    routeMonitor: routeMon,
    routeManager: routeMgr,
    probeEngine: probeEng,
    dnsManager: dnsMgr,
    conntrackMgr: ctMgr,
    ipcServer: ipcServer,
    hookRunner: initHookRunner(config.globals.hookScript),
    statusFiles: initStatusFileManager(),
    signalFd: signalFd,
    trackers: trackers,
    startTime: getMonoTime(),
    running: true,
    connectedNetworks: @[],
    connectedNetworksDirty: true,
    nftablesDirty: false,
    dnsDirty: false,
    cachedRules: cachedRules,
    timerBuf: @[],
    linkEventBuf: @[],
    routeChangeBuf: @[],
  )

# =========================================================================
# Helper methods
# =========================================================================

proc configForIndex(d: Daemon, index: int): Option[InterfaceConfig] =
  if index >= 0 and index < d.config.interfaces.len:
    some(d.config.interfaces[index])
  else:
    none(InterfaceConfig)

proc probeIntervalFor(d: Daemon, index: int): uint32 =
  let cfg = d.configForIndex(index)
  if cfg.isNone: return 5

  let c = cfg.get
  var state = isInit
  for t in d.trackers:
    if t.index == index:
      state = t.state
      break

  case state
  of isOffline:
    if c.failureInterval > 0: uint32(c.failureInterval)
    else: c.probeInterval
  of isProbing:
    if c.keepFailureInterval and c.failureInterval > 0: uint32(c.failureInterval)
    else: c.probeInterval
  of isDegraded:
    if c.recoveryInterval > 0: uint32(c.recoveryInterval)
    else: c.probeInterval
  else:
    c.probeInterval

proc probeTimeoutFor(d: Daemon, index: int): uint32 =
  let cfg = d.configForIndex(index)
  if cfg.isSome: cfg.get.probeTimeout
  else: 2

proc resolveAllPolicies(d: Daemon): seq[ResolvedPolicy] =
  for p in d.config.policies:
    result.add(resolvePolicy(p, d.config.members, d.trackers))

proc makeProbeTransport(cfg: InterfaceConfig): ProbeTransport =
  ## Create a probe transport with a live socket for the configured method.
  case cfg.trackMethod
  of tmPing:
    let family = case cfg.family
      of afIpv4: uint8(2)    # AF_INET
      of afIpv6: uint8(10)   # AF_INET6
      of afBoth: uint8(2)    # Default to IPv4
    let fd = createIcmpSocket(cfg.device, family, cfg.maxTtl.int)
    ProbeTransport(kind: tkIcmp, icmpFd: fd, icmpFamily: family)
  of tmDns:
    let family = case cfg.family
      of afIpv4: uint8(2)
      of afIpv6: uint8(10)
      of afBoth: uint8(2)
    let fd = createDnsSocket(cfg.device, family)
    var queryBuf: array[512, byte]
    let queryName = if cfg.dnsQueryName.len > 0: cfg.dnsQueryName else: "example.com"
    let queryLen = encodeDnsQuery(queryName, queryBuf)
    ProbeTransport(kind: tkDns, dnsFd: fd, dnsFamily: family,
                   dnsQueryBuf: queryBuf, dnsQueryLen: queryLen)
  of tmHttp, tmHttps:
    let family = case cfg.family
      of afIpv4: uint8(2)
      of afIpv6: uint8(10)
      of afBoth: uint8(2)
    let port = if cfg.trackPort > 0: uint16(cfg.trackPort)
               elif cfg.trackMethod == tmHttp: 80'u16
               else: 443'u16
    let fd = createHttpSocket(cfg.device, family)
    ProbeTransport(kind: tkHttp, httpFd: fd, httpFamily: family,
                   httpDevice: cfg.device, httpPort: port,
                   httpState: hsIdle)
  of tmArping:
    let (fd, state) = createArpSocket(cfg.device)
    ProbeTransport(kind: tkArp, arpFd: fd, arpIfindex: state.ifindex)
  of tmComposite:
    ProbeTransport(kind: tkComposite, subs: @[])

# =========================================================================
# nftables regeneration
# =========================================================================

proc regenerateNftables(d: var Daemon) =
  ## Resolve policies, build the complete ruleset, apply atomically.
  var interfaces: seq[InterfaceInfo]
  for t in d.trackers:
    if not t.isActive: continue
    let clampMss = d.configForIndex(t.index).map(
      proc(c: InterfaceConfig): bool = c.clampMss
    ).get(false)
    interfaces.add(InterfaceInfo(
      name: t.name,
      mark: t.mark,
      tableId: t.tableId,
      device: t.device,
      clampMss: clampMss,
    ))

  let resolved = d.resolveAllPolicies()
  var policies: seq[PolicyInfo]
  for rp in resolved:
    var members: seq[PolicyMember]
    if rp.hasActiveTier:
      let tier = rp.activeTier
      for m in tier.members:
        members.add(PolicyMember(
          interfaceName: m.interfaceName,
          mark: m.mark,
          weight: m.weight,
          metric: 0,
        ))

    let lr = case rp.lastResort
      of lrDefault: chains.Default
      of lrUnreachable: chains.Unreachable
      of lrBlackhole: chains.Blackhole

    policies.add(PolicyInfo(
      name: rp.name,
      members: members,
      lastResort: lr,
    ))

  if d.connectedNetworksDirty:
    d.connectedNetworksDirty = false
    # Connected networks will be populated by route table dumps when available
    # For now, use basic loopback and link-local prefixes
    d.connectedNetworks = @["127.0.0.0/8", "::1/128"]

  let rs = buildRuleset(
    interfaces, policies, d.cachedRules, d.connectedNetworks,
    d.config.globals.markMask, d.config.globals.ipv6Enabled,
    d.config.globals.logging,
  )

  if not applyRuleset(rs):
    error "failed to regenerate nftables"

# =========================================================================
# Route management
# =========================================================================

proc addRoutes(d: var Daemon, index: int) =
  ## Add ip rules and copy default routes for an interface.
  var t: InterfaceTracker
  var found = false
  for tr in d.trackers:
    if tr.index == index:
      t = tr
      found = true
      break
  if not found:
    error fmt"addRoutes: no tracker for index {index}"
    return

  let cfg = d.configForIndex(index)
  let family = if cfg.isSome: cfg.get.family else: afIpv4

  const AF_INET = uint8(2)
  const AF_INET6 = uint8(10)

  if family == afIpv4 or family == afBoth:
    let r = d.routeManager.addRule(t.mark, d.config.globals.markMask,
                                   t.tableId, 100 + index.uint32, AF_INET)
    if not r.ok:
      warn fmt"failed to add IPv4 ip rule for {t.name}: {r.error}"

  if d.config.globals.ipv6Enabled and (family == afIpv6 or family == afBoth):
    let r = d.routeManager.addRule(t.mark, d.config.globals.markMask,
                                   t.tableId, 100 + index.uint32, AF_INET6)
    if not r.ok:
      warn fmt"failed to add IPv6 ip rule for {t.name}: {r.error}"

  info fmt"added routes for {t.name} (mark=0x{t.mark.toHex(4)}, table={t.tableId})"

proc removeRoutes(d: var Daemon, index: int) =
  ## Delete ip rules and flush routing table for an interface.
  var t: InterfaceTracker
  var found = false
  for tr in d.trackers:
    if tr.index == index:
      t = tr
      found = true
      break
  if not found:
    error fmt"removeRoutes: no tracker for index {index}"
    return

  let cfg = d.configForIndex(index)
  let family = if cfg.isSome: cfg.get.family else: afIpv4

  const AF_INET = uint8(2)
  const AF_INET6 = uint8(10)

  if family == afIpv4 or family == afBoth:
    let r = d.routeManager.delRule(t.mark, d.config.globals.markMask,
                                   t.tableId, 100 + index.uint32, AF_INET)
    if not r.ok:
      warn fmt"failed to delete IPv4 ip rule for {t.name}: {r.error}"

  if d.config.globals.ipv6Enabled and (family == afIpv6 or family == afBoth):
    let r = d.routeManager.delRule(t.mark, d.config.globals.markMask,
                                   t.tableId, 100 + index.uint32, AF_INET6)
    if not r.ok:
      warn fmt"failed to delete IPv6 ip rule for {t.name}: {r.error}"

  let r = d.routeManager.flushTableBoth(t.tableId)
  if not r.ok:
    warn fmt"failed to flush table {t.tableId} for {t.name}: {r.error}"

  info fmt"removed routes for {t.name}"

# =========================================================================
# DNS management
# =========================================================================

proc updateDns(d: var Daemon, index: int) =
  let cfg = d.configForIndex(index)
  if cfg.isNone: return
  let c = cfg.get
  if c.updateDns and c.dnsServers.len > 0:
    d.dnsManager.setServers(c.name, c.dnsServers)
    d.dnsDirty = true

proc removeDns(d: var Daemon, index: int) =
  let cfg = d.configForIndex(index)
  if cfg.isNone: return
  d.dnsManager.removeInterface(cfg.get.name)
  d.dnsDirty = true

# =========================================================================
# Conntrack flush
# =========================================================================

proc flushConntrack(d: var Daemon, mark, mask: uint32) =
  case d.config.globals.conntrackFlush
  of cfmSelective:
    let r = d.conntrackMgr.flushByMark(mark, mask)
    if not r.ok:
      error fmt"conntrack flush failed: {r.error}"
  of cfmFull:
    let r = d.conntrackMgr.flushByMark(0, 0)  # mask=0 means match all entries
    if not r.ok:
      error fmt"conntrack flush all failed: {r.error}"
  of cfmNone:
    discard

proc maybeFlushConntrack(d: var Daemon, index: int, mark: uint32,
                         oldState, newState: InterfaceState,
                         linkEvent: bool) =
  ## Check per-interface flush triggers and flush conntrack if appropriate.
  let cfg = d.configForIndex(index)
  if cfg.isNone: return
  let c = cfg.get

  # Quality recovery (Degraded->Online) is not a new connection;
  # the interface never left routing so flushing would disrupt existing connections.
  if oldState == isDegraded and newState == isOnline:
    return

  var trigger: ConntrackFlushTrigger
  if linkEvent and newState == isProbing:
    trigger = cftIfUp
  elif linkEvent and newState == isOffline:
    trigger = cftIfDown
  elif not linkEvent and newState == isOnline:
    trigger = cftConnected
  elif not linkEvent and newState == isOffline:
    trigger = cftDisconnected
  else:
    return

  if trigger in c.flushConntrack:
    debug fmt"{c.name}: conntrack flush triggered by {newState}"
    d.flushConntrack(mark, d.config.globals.markMask)

# =========================================================================
# Status file helpers
# =========================================================================

proc buildStatusMetrics(t: InterfaceTracker): StatusMetrics =
  ## Build a StatusMetrics from a tracker for the status file manager.
  let avgRtt = if t.avgRttMs.isSome: int(t.avgRttMs.get) else: -1
  let uptime = if t.onlineSince.isSome:
    (getMonoTime() - t.onlineSince.get).inSeconds
  else:
    -1'i64
  let downtime = if t.offlineSince.isSome:
    (getMonoTime() - t.offlineSince.get).inSeconds
  else:
    -1'i64
  StatusMetrics(
    successCount: t.successCount,
    failCount: t.failCount,
    avgRttMs: avgRtt,
    lossPercent: t.lossPercent,
    uptimeSecs: uptime,
    downtimeSecs: downtime,
  )

# =========================================================================
# Action execution
# =========================================================================

proc scheduleDampenDecay(d: var Daemon, index: int) # forward declaration

proc executeEffects(d: var Daemon, trackerIdx: int, decision: StateDecision,
                    oldState: InterfaceState, linkEvent: bool = false) =
  ## Execute the effects determined by the pure state machine decision.
  if not decision.transitioned: return
  let index = d.trackers[trackerIdx].index
  let newState = decision.newState
  for effect in decision.effects:
    case effect
    of efRegenerateNftables:
      d.nftablesDirty = true
    of efAddRoutes:
      d.addRoutes(index)
    of efRemoveRoutes:
      d.removeRoutes(index)
    of efUpdateDns:
      d.updateDns(index)
    of efRemoveDns:
      d.removeDns(index)
    of efBroadcastEvent:
      let name = d.trackers[trackerIdx].name
      if name.len > 0:
        let eventData = EventData(
          event: "interface.state_change",
          interfaceName: name,
          state: $newState,
        )
        let eventResp = successResponse(0, eventData.toJson())
        d.ipcServer.broadcastEvent(eventResp, d.selector)
        let device = d.trackers[trackerIdx].device
        d.hookRunner.runHook(name, device, newState)
    of efWriteStatus:
      let t = d.trackers[trackerIdx]
      d.statusFiles.writeStatus(t.name, newState, buildStatusMetrics(t))
    of efCancelProbeTimers:
      d.timers.cancelByIndex(index, {tkProbe, tkProbeTimeout})
    of efResetProbeCounters:
      d.probeEngine.resetCounters(index)
    of efScheduleFirstProbe:
      d.timers.push(TimerEntry(
        deadline: getMonoTime() + initDuration(seconds = 1),
        kind: tkProbe,
        index: index,
      ))
    of efFlushConntrack:
      d.maybeFlushConntrack(index, d.trackers[trackerIdx].mark,
                            oldState, newState, linkEvent)
    of efScheduleDampenDecay:
      d.scheduleDampenDecay(index)

# =========================================================================
# Dampening decay
# =========================================================================

proc scheduleDampenDecay(d: var Daemon, index: int) =
  ## Schedule a dampening decay timer check.
  let interval = d.configForIndex(index).map(
    proc(c: InterfaceConfig): uint32 = max(c.dampeningHalflife div 10, 1)
  ).get(30'u32)

  d.timers.cancelByIndex(index, {tkDampenDecay})
  d.timers.push(TimerEntry(
    deadline: getMonoTime() + initDuration(seconds = int(interval)),
    kind: tkDampenDecay,
    index: index,
  ))

proc handleStateEvent(d: var Daemon, trackerIdx: int, event: StateEvent,
                      linkEvent: bool = false) =
  ## Unified state machine pipeline:
  ## snapshot → decide → apply → log → execute effects
  let now = getMonoTime()
  let snap = d.trackers[trackerIdx].snapshot(now)
  let oldState = snap.state
  let decision = decide(snap, event)

  # Apply state changes
  d.trackers[trackerIdx].apply(decision, now)

  # Log transition
  if decision.transitioned:
    let name = d.trackers[trackerIdx].name
    info fmt"{name}: {oldState} -> {decision.newState}"

    # Log dampening state changes
    if decision.newDampening.isSome:
      let damp = decision.newDampening.get
      if damp.suppressed:
        debug fmt"{name}: dampening suppressed (penalty={damp.penalty:.1f})"
      elif snap.dampening.isSome and snap.dampening.get.suppressed:
        info fmt"{name}: dampening reuse threshold reached, unsuppressed"
  elif decision.newDampening.isSome and snap.dampening.isSome:
    # No transition but dampening decayed — still suppressed
    let damp = decision.newDampening.get
    if damp.suppressed:
      debug fmt"{d.trackers[trackerIdx].name}: dampening penalty decayed to {damp.penalty:.1f}"
      # Reschedule decay timer for still-suppressed interfaces
      d.scheduleDampenDecay(d.trackers[trackerIdx].index)

  # Execute effects
  d.executeEffects(trackerIdx, decision, oldState, linkEvent)

proc handleDampenDecay(d: var Daemon, index: int) =
  var trackerIdx = -1
  for i in 0 ..< d.trackers.len:
    if d.trackers[i].index == index:
      trackerIdx = i
      break
  if trackerIdx < 0: return
  d.handleStateEvent(trackerIdx, StateEvent(kind: sekDampenDecay))

proc processProbeResult(d: var Daemon, probeResult: ProbeResult) =
  ## Update tracker state from a probe result via the pure state machine.
  var trackerIdx = -1
  for i in 0 ..< d.trackers.len:
    if d.trackers[i].index == probeResult.interfaceIndex:
      trackerIdx = i
      break
  if trackerIdx < 0: return

  # Update quality metrics for status reporting
  d.trackers[trackerIdx].avgRttMs = probeResult.avgRttMs
  d.trackers[trackerIdx].lossPercent = probeResult.lossPercent

  let event = StateEvent(
    kind: sekProbeResult,
    success: probeResult.success,
    qualityOk: probeResult.qualityOk,
  )
  d.handleStateEvent(trackerIdx, event)

# =========================================================================
# Event handlers
# =========================================================================

proc handleReload(d: var Daemon) # forward declaration

proc handleSignals(d: var Daemon) =
  ## Drain the signal pipe and process each signal byte.
  var buf: array[32, byte]
  while true:
    let n = posix.read(d.signalFd, addr buf[0], buf.len)
    if n <= 0: break
    for i in 0 ..< n:
      case chr(buf[i])
      of 'T':
        info "received shutdown signal"
        d.running = false
      of 'R':
        info "received reload signal"
        d.handleReload()
      else:
        discard

proc handleLinkEvents(d: var Daemon) =
  ## Read link events and drive the state machine for each affected interface.
  d.linkEventBuf.setLen(0)
  d.linkMonitor.processEvents(d.linkEventBuf)

  for event in d.linkEventBuf:
    var trackerIdx = -1
    for i in 0 ..< d.trackers.len:
      if d.trackers[i].device == event.ifname:
        trackerIdx = i
        break
    if trackerIdx < 0: continue

    # Update cached ifindex on link up
    if event.up:
      d.trackers[trackerIdx].ifindex = event.ifindex

    let stateEvent = if event.up:
      StateEvent(kind: sekLinkUp)
    else:
      StateEvent(kind: sekLinkDown)

    d.handleStateEvent(trackerIdx, stateEvent, linkEvent = true)

proc handleRouteEvents(d: var Daemon) =
  ## Process route and address change events from netlink monitor.
  d.routeChangeBuf.setLen(0)
  d.routeMonitor.processEvents(d.routeChangeBuf)

  if d.routeChangeBuf.len == 0: return

  for change in d.routeChangeBuf:
    case change.kind
    of rckRouteAdd, rckRouteDel:
      # Find tracker whose ifindex matches
      var found = false
      for t in d.trackers:
        if t.ifindex != 0 and t.ifindex == change.ifindex:
          if t.state == isOnline or t.state == isDegraded:
            debug fmt"{t.name}: route change detected (family={change.family})"
            d.connectedNetworksDirty = true
          found = true
          break
    of rckAddrAdd, rckAddrDel:
      # Address changes may require source rule updates
      d.connectedNetworksDirty = true

proc handleProbeTimer(d: var Daemon, index: int) =
  ## Send a probe for the given interface, schedule timeout.
  let ok = d.probeEngine.sendProbe(index)
  if not ok:
    warn fmt"failed to send probe for interface {index}"
    d.timers.cancelByIndex(index, {tkProbeTimeout})
    # Treat send failure as immediate timeout
    let resultOpt = d.probeEngine.recordTimeout(index)
    if resultOpt.isSome:
      d.processProbeResult(resultOpt.get)
    # Schedule next probe at normal interval
    let interval = d.probeIntervalFor(index)
    d.timers.push(TimerEntry(
      deadline: getMonoTime() + initDuration(seconds = int(interval)),
      kind: tkProbe,
      index: index,
    ))
    return

  # Schedule probe timeout
  let timeout = d.probeTimeoutFor(index)
  d.timers.push(TimerEntry(
    deadline: getMonoTime() + initDuration(seconds = int(timeout)),
    kind: tkProbeTimeout,
    index: index,
  ))

proc handleProbeTimeout(d: var Daemon, index: int) =
  ## Record timeout, advance cycle, schedule next probe.
  # Final check for responses before recording timeout
  d.probeEngine.checkResponses()

  let resultOpt = d.probeEngine.recordTimeout(index)
  if resultOpt.isSome:
    d.processProbeResult(resultOpt.get)

  # Schedule next probe
  let interval = d.probeIntervalFor(index)
  d.timers.push(TimerEntry(
    deadline: getMonoTime() + initDuration(seconds = int(interval)),
    kind: tkProbe,
    index: index,
  ))

proc handleProbeResponse(d: var Daemon, slotIndex: int) =
  ## Handle readability on a probe socket. Calls check_responses globally.
  d.probeEngine.checkResponses()

# =========================================================================
# Interface initialization
# =========================================================================

proc initializeInterfaces(d: var Daemon) =
  ## Set up initial interface states, probes, routes, and nftables.
  var onlineIndices: seq[int]

  for ti in 0 ..< d.trackers.len:
    let index = d.trackers[ti].index
    let cfg = d.configForIndex(index)
    if cfg.isNone: continue
    let c = cfg.get

    let initialOnline = c.initialState == initOnline

    if initialOnline:
      d.trackers[ti].state = isOnline
      d.trackers[ti].onlineSince = some(getMonoTime())
      d.trackers[ti].successCount = d.trackers[ti].upCount
      onlineIndices.add(index)
      info fmt"{d.trackers[ti].name}: initial_state=online, active immediately"
    else:
      # Assume link is up, start probing
      d.trackers[ti].state = isProbing
      d.trackers[ti].successCount = 0
      d.trackers[ti].failCount = 0

    # Set up probe targets
    let ipv6Ok = d.config.globals.ipv6Enabled
    let isV6 = c.family == afIpv6 or (c.family == afBoth and ipv6Ok)
    var targets: seq[string]
    for ip in c.trackIp:
      # Filter IPv6 targets if ipv6 disabled
      if not ipv6Ok and ':' in ip: continue
      targets.add(ip)

    if targets.len > 0:
      let transport = makeProbeTransport(c)
      d.probeEngine.addInterface(
        index, d.trackers[ti].name, d.trackers[ti].device,
        targets, isV6, transport,
        c.reliability, int(c.count),
        latencyThreshold = if c.checkQuality and c.latencyThreshold > 0:
                             some(uint32(c.latencyThreshold)) else: none(uint32),
        lossThreshold = if c.checkQuality and c.lossThreshold > 0:
                          some(uint32(c.lossThreshold)) else: none(uint32),
        recoveryLatency = if c.checkQuality and c.recoveryLatency > 0:
                            some(uint32(c.recoveryLatency)) else: none(uint32),
        recoveryLoss = if c.checkQuality and c.recoveryLoss > 0:
                         some(uint32(c.recoveryLoss)) else: none(uint32),
        qualityWindowSize = int(c.qualityWindow),
        probeSize = int(c.probeSize),
      )

    # Schedule first probe
    d.timers.push(TimerEntry(
      deadline: getMonoTime() + initDuration(seconds = 1),
      kind: tkProbe,
      index: index,
    ))

  # Register probe socket fds with selector
  for (slot, fd) in d.probeEngine.getFds():
    d.selector.registerHandle(fd.int, {Read}, ProbeTokenBase + slot)
  for name in d.probeEngine.invalidFdInterfaces:
    error fmt"probe socket creation failed for interface '{name}' — probes will not work"

  # Set up routes and DNS for initial_state=online interfaces
  for index in onlineIndices:
    d.addRoutes(index)
    d.updateDns(index)

  # Generate initial nftables
  d.regenerateNftables()

  # Create status directories and write initial status files
  var names: seq[string]
  for t in d.trackers: names.add(t.name)
  d.statusFiles.createDirs(names)
  for t in d.trackers:
    d.statusFiles.writeStatus(t.name, t.state, buildStatusMetrics(t))

# =========================================================================
# Reload
# =========================================================================

type
  ReloadContext = object
    newConfig: NopalConfig
    cfgDiff: ConfigDiff
    prevStates: seq[tuple[name: string, state: InterfaceState,
                           onlineSince: Option[MonoTime]]]
    newTrackers: seq[InterfaceTracker]

proc reloadParseAndDiff(configPath: string,
                        currentConfig: NopalConfig): Option[ReloadContext] =
  ## Phase 1: Load new config, compute diff. No daemon access.
  ## Returns none on error or if config is unchanged.
  info fmt"reloading configuration from {configPath}"

  var newConfig: NopalConfig
  try:
    newConfig = loadConfig(configPath)
  except CatchableError as e:
    error fmt"failed to reload config: {e.msg}"
    return none[ReloadContext]()

  enrichConfigWithDiscovery(newConfig)

  let cfgDiff = diff(currentConfig, newConfig)
  if not cfgDiff.changed:
    info "config unchanged, skipping reload"
    return none[ReloadContext]()

  some(ReloadContext(newConfig: newConfig, cfgDiff: cfgDiff))

proc reloadFastPath(ctx: ReloadContext, d: var Daemon): bool =
  ## Phase 2: Handle routing-only changes without full rebuild.
  ## Returns true if handled (no further phases needed).
  if not ctx.cfgDiff.needsFullRebuild and
     ctx.cfgDiff.changedInterfaces.len == 0 and
     ctx.cfgDiff.routingChanged:
    info "only routing policies/rules changed, regenerating nftables"
    d.config = ctx.newConfig
    d.cachedRules = buildRulesFromConfig(d.config)
    d.hookRunner.updateScript(d.config.globals.hookScript)
    d.regenerateNftables()
    return true
  false

proc reloadTeardown(ctx: var ReloadContext,
                    probeEngine: var ProbeEngine,
                    selector: var Selector[int],
                    dnsManager: var DnsManager,
                    trackers: seq[InterfaceTracker],
                    timers: var TimerWheel) =
  ## Phase 3: Save previous states, tear down probes/DNS.
  ## Route removal is done by the caller (needs var Daemon for addRoutes/removeRoutes).
  ## Takes only the specific subsystems it mutates.

  # Save current states for restoration
  for t in trackers:
    ctx.prevStates.add((name: t.name, state: t.state, onlineSince: t.onlineSince))

  # Cancel non-IPC timers
  timers.cancelAll({tkIpcTimeout})

  # Deregister probe sockets from selector
  for (slot, fd) in probeEngine.getFds():
    try:
      selector.unregister(fd.int)
    except CatchableError:
      discard

  # Remove all interfaces from probe engine
  var probeIndices: seq[int]
  for t in trackers: probeIndices.add(t.index)
  for idx in probeIndices:
    probeEngine.removeInterface(idx)

  # Remove all DNS entries
  for t in trackers:
    dnsManager.removeInterface(t.name)
  dnsManager.apply()

proc reloadBuildTrackers(ctx: var ReloadContext, config: NopalConfig) =
  ## Phase 4: Create new trackers with mark assignment and state restoration.
  let ipv6Enabled = config.globals.ipv6Enabled
  var enabledNames: seq[string]
  for iface in config.interfaces:
    if not iface.enabled: continue
    if not ipv6Enabled and iface.family == afIpv6: continue
    enabledNames.add(iface.name)

  let marks = assignMarks(enabledNames, config.globals.markMask)

  var markIdx = 0
  for i, iface in config.interfaces:
    if not iface.enabled: continue
    if not ipv6Enabled and iface.family == afIpv6:
      warn fmt"{iface.name}: skipping IPv6-only interface (ipv6_enabled=false)"
      continue

    if markIdx >= marks.len:
      error fmt"{iface.name}: no mark slot available, skipping"
      continue

    let (mark, tableId) = marks[markIdx]
    inc markIdx

    var t = newTracker(
      iface.name, i, mark, tableId, iface.device,
      iface.upCount, iface.downCount,
    )

    if iface.dampening:
      t.setDampening(
        iface.dampeningHalflife,
        iface.dampeningCeiling,
        iface.dampeningSuppress,
        iface.dampeningReuse,
      )

    # Restore state for previously-known interfaces
    var restoredState = false
    for prev in ctx.prevStates:
      if prev.name == iface.name:
        case prev.state
        of isOnline:
          t.state = isOnline
          t.successCount = t.upCount
          t.onlineSince = prev.onlineSince
        of isDegraded:
          t.state = isDegraded
          t.successCount = t.upCount
          t.onlineSince = prev.onlineSince
        of isProbing:
          t.state = isProbing
        of isOffline:
          t.state = isOffline
        of isInit:
          t.state = isProbing
          t.successCount = 0
          t.failCount = 0
        restoredState = true
        break

    if not restoredState:
      t.state = isProbing
      t.successCount = 0
      t.failCount = 0

    ctx.newTrackers.add(t)

proc reloadReinitSubsystems(ctx: ReloadContext, d: var Daemon) =
  ## Phase 5: Re-register probes, restore routes/DNS, regenerate nftables.
  ## Legitimately needs var Daemon — touches most subsystems.
  d.config = ctx.newConfig
  d.cachedRules = buildRulesFromConfig(d.config)
  d.hookRunner.updateScript(d.config.globals.hookScript)
  d.trackers = ctx.newTrackers

  var names: seq[string]
  for t in d.trackers: names.add(t.name)
  d.statusFiles.createDirs(names)

  # Re-register probes
  for t in d.trackers:
    let cfg = d.configForIndex(t.index)
    if cfg.isNone: continue
    let c = cfg.get

    let ipv6Ok = d.config.globals.ipv6Enabled
    let isV6 = c.family == afIpv6 or (c.family == afBoth and ipv6Ok)
    var targets: seq[string]
    for ip in c.trackIp:
      if not ipv6Ok and ':' in ip: continue
      targets.add(ip)

    if targets.len > 0:
      let transport = makeProbeTransport(c)
      d.probeEngine.addInterface(
        t.index, t.name, t.device, targets, isV6, transport,
        c.reliability, int(c.count),
        latencyThreshold = if c.checkQuality and c.latencyThreshold > 0:
                             some(uint32(c.latencyThreshold)) else: none(uint32),
        lossThreshold = if c.checkQuality and c.lossThreshold > 0:
                          some(uint32(c.lossThreshold)) else: none(uint32),
        recoveryLatency = if c.checkQuality and c.recoveryLatency > 0:
                            some(uint32(c.recoveryLatency)) else: none(uint32),
        recoveryLoss = if c.checkQuality and c.recoveryLoss > 0:
                         some(uint32(c.recoveryLoss)) else: none(uint32),
        qualityWindowSize = int(c.qualityWindow),
        probeSize = int(c.probeSize),
      )

    d.timers.push(TimerEntry(
      deadline: getMonoTime() + initDuration(seconds = 1),
      kind: tkProbe,
      index: t.index,
    ))

  # Register probe sockets with selector
  for (slot, fd) in d.probeEngine.getFds():
    d.selector.registerHandle(fd.int, {Read}, ProbeTokenBase + slot)
  for name in d.probeEngine.invalidFdInterfaces:
    error fmt"probe socket creation failed for interface '{name}' — probes will not work"

  # Restore routes and DNS for active interfaces
  for t in d.trackers:
    if t.state == isOnline or t.state == isDegraded:
      d.addRoutes(t.index)
      d.updateDns(t.index)

  d.regenerateNftables()

proc handleReload(d: var Daemon) =
  ## Reload configuration using Phase Object pattern.
  ## Each phase has minimum access: phases 1,4 are pure config operations,
  ## phase 3 takes specific subsystems, phase 5 takes var Daemon.
  let ctxOpt = reloadParseAndDiff(d.configPath, d.config)
  if ctxOpt.isNone: return
  var ctx = ctxOpt.get

  if reloadFastPath(ctx, d): return

  # Remove routes for active interfaces (needs var Daemon)
  for t in d.trackers:
    if t.state == isOnline or t.state == isDegraded:
      d.removeRoutes(t.index)

  reloadTeardown(ctx, d.probeEngine, d.selector, d.dnsManager,
                 d.trackers, d.timers)
  reloadBuildTrackers(ctx, d.config)
  reloadReinitSubsystems(ctx, d)

  info fmt"configuration reloaded: {d.config.interfaces.len} interfaces, {d.config.policies.len} policies, {d.config.rules.len} rules"

proc handleReloadCommand(d: var Daemon, req: IpcRequest): IpcResponse =
  ## IPC command: reload configuration synchronously, return real result.
  try:
    d.handleReload()
    successResponse(req.id)
  except CatchableError as e:
    errorResponse(req.id, "reload failed: " & e.msg)

# =========================================================================
# Shutdown
# =========================================================================

proc shutdown(d: var Daemon) =
  ## Clean up nftables, routes, and status files.
  info "nopal daemon shutting down"

  discard nftEngine.cleanup()

  const AF_INET = uint8(2)
  const AF_INET6 = uint8(10)

  for t in d.trackers:
    let cfg = d.configForIndex(t.index)
    let family = if cfg.isSome: cfg.get.family else: afIpv4
    let priority = 100 + t.index.uint32

    if family == afIpv4 or family == afBoth:
      let r = d.routeManager.delRule(t.mark, d.config.globals.markMask,
                                     t.tableId, priority, AF_INET)
      if not r.ok and r.error.osError != int32(ENOENT) and r.error.osError != int32(ESRCH):
        warn fmt"shutdown: failed to delete IPv4 ip rule for {t.name}: {r.error}"

    if d.config.globals.ipv6Enabled and (family == afIpv6 or family == afBoth):
      let r = d.routeManager.delRule(t.mark, d.config.globals.markMask,
                                     t.tableId, priority, AF_INET6)
      if not r.ok and r.error.osError != int32(ENOENT) and r.error.osError != int32(ESRCH):
        warn fmt"shutdown: failed to delete IPv6 ip rule for {t.name}: {r.error}"

    let r = d.routeManager.flushTableBoth(t.tableId)
    if not r.ok and r.error.osError != int32(ENOENT) and r.error.osError != int32(ESRCH):
      warn fmt"shutdown: failed to flush table {t.tableId} for {t.name}: {r.error}"

  d.statusFiles.cleanup()

  # Close the signal pipe read end
  if d.signalFd >= 0:
    discard posix.close(d.signalFd)
    d.signalFd = -1

  # Close selector
  try:
    d.selector.close()
  except CatchableError: discard

  info "nopal daemon stopped"

# =========================================================================
# Main event loop
# =========================================================================

proc run*(d: var Daemon) =
  ## Run the main event loop: select, dispatch events, process timers,
  ## coalesce deferred nftables/DNS updates.
  info "nopal daemon starting"

  # Initial setup: assume all interfaces are up and start probing
  d.initializeInterfaces()

  while d.running:

    # Reap any finished hook child processes
    d.hookRunner.reapChildren()

    # Calculate poll timeout from next timer deadline
    let nextDeadline = d.timers.nextDeadline()
    let now = getMonoTime()
    var timeoutMs: int
    if nextDeadline > now:
      timeoutMs = max(int((nextDeadline - now).inMilliseconds), 1)
    else:
      timeoutMs = 1  # Timers already expired, process immediately

    # Clamp to reasonable maximum
    timeoutMs = min(timeoutMs, 1000)

    let readyKeys = d.selector.select(timeoutMs)

    for key in readyKeys:
      if Read notin key.events: continue

      let token = d.selector.getData(key.fd)

      if token == TokenSignal:
        d.handleSignals()
      elif token == TokenLink:
        d.handleLinkEvents()
      elif token == TokenRoute:
        d.handleRouteEvents()
      elif token == TokenIpc:
        let clientId = d.ipcServer.acceptClient(d.selector)
        if clientId >= 0:
          debug fmt"IPC client connected: {clientId}"
      elif token >= ProbeTokenBase and token < IpcClientBase:
        d.handleProbeResponse(token - ProbeTokenBase)
      elif token >= IpcClientBase:
        let clientId = token - IpcClientBase
        let requests = d.ipcServer.readClient(clientId, d.selector)
        for req in requests:
          let ipcMethod = parseIpcMethod(req.rpcMethod)
          let resp = if ipcMethod.isNone:
            errorResponse(req.id, "unknown method '" & req.rpcMethod & "'")
          else:
            let view = DaemonView(
              trackers: addr d.trackers,
              config: unsafeAddr d.config,
              startTime: d.startTime,
              connectedNetworks: addr d.connectedNetworks,
            )
            case ipcMethod.get
            of imStatus:
              handleStatusQuery(view, req)
            of imInterfaceStatus:
              handleInterfaceStatusQuery(view, req)
            of imConnected:
              handleConnectedQuery(view, req)
            of imConfigReload:
              d.handleReloadCommand(req)
            of imSubscribe:
              successResponse(req.id)
          d.ipcServer.sendResponse(clientId, resp, d.selector)

    # Process expired timers
    let timerNow = getMonoTime()
    d.timers.popExpired(timerNow, d.timerBuf)
    for entry in d.timerBuf:
      case entry.kind
      of tkProbe:
        d.handleProbeTimer(entry.index)
      of tkProbeTimeout:
        d.handleProbeTimeout(entry.index)
      of tkDampenDecay:
        d.handleDampenDecay(entry.index)
      of tkIpcTimeout:
        d.ipcServer.removeClient(entry.index, d.selector)

    # Deferred nftables regeneration: coalesce multiple transitions
    if d.nftablesDirty:
      d.nftablesDirty = false
      d.regenerateNftables()

    # Deferred DNS update: coalesce multiple DNS changes
    if d.dnsDirty:
      d.dnsDirty = false
      d.dnsManager.apply()

  d.shutdown()

# =========================================================================
# Public entry point
# =========================================================================

proc runEventLoop*(configPath: string, signalFd: cint) =
  ## Create the daemon and run the event loop until shutdown.
  var daemon = initDaemon(configPath, signalFd)
  daemon.run()
