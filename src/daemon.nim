## Daemon event loop and component orchestration.
##
## Central orchestrator: owns all subsystem components, drives the
## selector-based event loop, dispatches probe/link/route/IPC events,
## and coalesces deferred nftables/DNS updates.

import std/[selectors, posix, monotimes, times, options, logging, os, strutils, strformat, json]

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
import ./linux_constants as lc
import ./netlink/route
import ./netlink/link
import ./netlink/monitor
import ./netlink/conntrack
import ./dnsmanager
import ./timer
import ./hooks
import ./statusfiles
import ./snapshot
import ./version
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
  MaxInterfaces* = 256

type
  TrackerIndex* = array[MaxInterfaces, int16]  ## config index → seq position, -1 = absent

func initTrackerIndex*(): TrackerIndex {.raises: [].} =
  for i in 0 ..< MaxInterfaces:
    result[i] = -1

func buildTrackerIndex*(trackers: openArray[InterfaceTracker]): TrackerIndex {.raises: [].} =
  result = initTrackerIndex()
  for i, t in trackers:
    if t.index >= 0 and t.index < MaxInterfaces:
      result[t.index] = int16(i)

# =========================================================================
# Reload confirmation state
# =========================================================================

type
  PendingReload = object
    oldConfig: NopalConfig
    oldTrackers: seq[InterfaceTracker]
    oldTrackerIndex: TrackerIndex
    oldCachedRules: seq[RuleInfo]
    deadline: MonoTime

  ReloadState = object
    case pending*: bool
    of true: context*: PendingReload
    of false: discard

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
    trackerIndex: TrackerIndex  ## config index → trackers seq position
    reloadState: ReloadState     ## confirmation protocol state
    startTime: MonoTime
    running: bool
    connectedNetworks: seq[string]
    connectedNetworksDirty: bool
    dynamicBypassV4: seq[string]
    dynamicBypassV6: seq[string]
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
    # Compute effective family (may differ from configured when ipv6 disabled)
    let family = case r.family
      of rfIpv4: rfIpv4
      of rfIpv6:
        if not ipv6Enabled: continue
        rfIpv6
      of rfAny:
        if ipv6Enabled: rfAny else: rfIpv4

    let sticky = if r.sticky:
      some(StickyInfo(
        mode: r.stickyMode,
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
    trackerIndex: buildTrackerIndex(trackers),
    reloadState: ReloadState(pending: false),
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
  if index >= 0 and index < MaxInterfaces:
    let ti = int(d.trackerIndex[index])
    if ti >= 0:
      state = d.trackers[ti].state

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
    # Collect WAN ifindexes for bypass filtering
    var wanIfindexes: seq[uint32]
    for t in d.trackers:
      if t.ifindex != 0:
        wanIfindexes.add(t.ifindex)
    let r = d.routeManager.getBypassNetworks(wanIfindexes)
    if r.ok:
      d.connectedNetworks = r.value
    else:
      warn "failed to dump bypass networks: " & $r.error
      d.connectedNetworks = @["127.0.0.0/8", "::1/128"]

  let rs = buildRuleset(
    interfaces, policies, d.cachedRules, d.connectedNetworks,
    d.config.globals.markMask, d.config.globals.ipv6Enabled,
    d.config.globals.logging,
    d.dynamicBypassV4, d.dynamicBypassV6,
  )

  if not applyRuleset(rs):
    error "failed to regenerate nftables"

# =========================================================================
# Route management
#
# Design: per-interface routing tables contain ONLY the default route.
# Non-default routes (VPN, static, connected subnets) are handled by
# ip rule fallthrough to the main table (priority 32766). This is
# functionally equivalent to mwan3rtmon's full-mirror approach for all
# standard multi-WAN scenarios, with less kernel memory and no sync bugs.
#
# To prevent unnecessary nftables marking for locally-routable traffic
# (which would pollute conntrack marks), the bypass network list includes
# both connected subnets and routes through non-WAN interfaces.
# =========================================================================

proc installInfraRules(d: var Daemon, index: int) =
  ## Install all ip rules for one interface: fwmark→table (policy routing)
  ## and lc.PROBE_MARK→table (probe routing). Called once at init.
  ## Rules are never removed during normal operation — dead rules are harmless
  ## because nftables controls which marks are applied.
  if index < 0 or index >= MaxInterfaces: return
  let ti = int(d.trackerIndex[index])
  if ti < 0:
    error fmt"installInfraRules: no tracker for index {index}"
    return
  let t = d.trackers[ti]

  let cfg = d.configForIndex(index)
  let family = if cfg.isSome: cfg.get.family else: afIpv4

  const AF_INET = uint8(2)
  const AF_INET6 = uint8(10)

  # Policy routing rules (fwmark→table, priority 100+)
  if family == afIpv4 or family == afBoth:
    let r = d.routeManager.addRule(t.mark, d.config.globals.markMask,
                                   t.tableId, 100 + index.uint32, AF_INET)
    if not r.ok:
      warn fmt"failed to add IPv4 fwmark rule for {t.name}: {r.error}"

  if d.config.globals.ipv6Enabled and (family == afIpv6 or family == afBoth):
    let r = d.routeManager.addRule(t.mark, d.config.globals.markMask,
                                   t.tableId, 100 + index.uint32, AF_INET6)
    if not r.ok:
      warn fmt"failed to add IPv6 fwmark rule for {t.name}: {r.error}"

  # Probe routing rules (lc.PROBE_MARK→table, priority 50+)
  # SO_BINDTODEVICE + ip rule fallthrough ensures each probe finds its own table.
  if family == afIpv4 or family == afBoth:
    let r = d.routeManager.addRule(lc.PROBE_MARK, 0xFFFFFFFF'u32,
                                   t.tableId, 50 + index.uint32, AF_INET)
    if not r.ok:
      warn fmt"failed to add IPv4 probe rule for {t.name}: {r.error}"

  if d.config.globals.ipv6Enabled and (family == afIpv6 or family == afBoth):
    let r = d.routeManager.addRule(lc.PROBE_MARK, 0xFFFFFFFF'u32,
                                   t.tableId, 50 + index.uint32, AF_INET6)
    if not r.ok:
      warn fmt"failed to add IPv6 probe rule for {t.name}: {r.error}"

  debug fmt"installed ip rules for {t.name} (mark=0x{t.mark.toHex(4)}, table={t.tableId})"

proc installInterfaceRoute(d: var Daemon, trackerIdx: int,
                           gateway: openArray[byte], family: uint8) =
  ## Install a default route in the per-interface routing table.
  ## Called when a gateway becomes known (init dump or route monitor event).
  let t = d.trackers[trackerIdx]
  let r = d.routeManager.addRoute(t.tableId, gateway, t.ifindex, 0, family)
  if not r.ok:
    let familyStr = if family == uint8(2): "IPv4" else: "IPv6"
    warn fmt"failed to add {familyStr} default route for {t.name}: {r.error}"
  else:
    let familyStr = if family == uint8(2): "IPv4" else: "IPv6"
    info fmt"installed {familyStr} default route for {t.name} (table={t.tableId})"

proc removeInterfaceRoute(d: var Daemon, trackerIdx: int, family: uint8) =
  ## Remove a default route from the per-interface routing table.
  ## Called when a gateway disappears (route monitor event).
  let t = d.trackers[trackerIdx]
  let r = d.routeManager.delRoute(t.tableId, family)
  if not r.ok:
    let familyStr = if family == uint8(2): "IPv4" else: "IPv6"
    debug fmt"failed to remove {familyStr} default route for {t.name}: {r.error}"

proc cleanupInfraRoutes(d: var Daemon, index: int) =
  ## Remove all ip rules and flush routing table for an interface.
  ## Called on shutdown and hot-reload interface removal.
  if index < 0 or index >= MaxInterfaces: return
  let ti = int(d.trackerIndex[index])
  if ti < 0: return
  let t = d.trackers[ti]

  let cfg = d.configForIndex(index)
  let family = if cfg.isSome: cfg.get.family else: afIpv4

  const AF_INET = uint8(2)
  const AF_INET6 = uint8(10)

  # Remove fwmark rules
  if family == afIpv4 or family == afBoth:
    discard d.routeManager.delRule(t.mark, d.config.globals.markMask,
                                   t.tableId, 100 + index.uint32, AF_INET)

  if d.config.globals.ipv6Enabled and (family == afIpv6 or family == afBoth):
    discard d.routeManager.delRule(t.mark, d.config.globals.markMask,
                                   t.tableId, 100 + index.uint32, AF_INET6)

  # Remove probe routing rules
  if family == afIpv4 or family == afBoth:
    discard d.routeManager.delRule(lc.PROBE_MARK, 0xFFFFFFFF'u32,
                                   t.tableId, 50 + index.uint32, AF_INET)

  if d.config.globals.ipv6Enabled and (family == afIpv6 or family == afBoth):
    discard d.routeManager.delRule(lc.PROBE_MARK, 0xFFFFFFFF'u32,
                                   t.tableId, 50 + index.uint32, AF_INET6)

  # Flush routing table
  discard d.routeManager.flushTableBoth(t.tableId)

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
  if index < 0 or index >= MaxInterfaces: return
  let trackerIdx = int(d.trackerIndex[index])
  if trackerIdx < 0: return
  d.handleStateEvent(trackerIdx, StateEvent(kind: sekDampenDecay))

proc processProbeResult(d: var Daemon, probeResult: ProbeResult) =
  ## Update tracker state from a probe result via the pure state machine.
  let index = probeResult.interfaceIndex
  if index < 0 or index >= MaxInterfaces: return
  let trackerIdx = int(d.trackerIndex[index])
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
        if d.reloadState.pending:
          warn "SIGHUP ignored: reload pending — accept or cancel first"
        else:
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
  ## Default route changes update per-interface routing tables reactively.
  d.routeChangeBuf.setLen(0)
  d.routeMonitor.processEvents(d.routeChangeBuf)

  if d.routeChangeBuf.len == 0: return

  for change in d.routeChangeBuf:
    case change.kind
    of rckRouteAdd, rckRouteDel:
      if change.dstLen == 0:
        # Default route change — update per-interface routing table
        if change.kind == rckRouteAdd:
          for ti in 0 ..< d.trackers.len:
            if d.trackers[ti].ifindex != 0 and d.trackers[ti].ifindex == change.ifindex:
              if change.hasGateway:
                if change.family == uint8(2):  # AF_INET
                  d.trackers[ti].gateway4[0 ..< 4] = change.gateway[0 ..< 4]
                  d.trackers[ti].hasGateway4 = true
                else:
                  d.trackers[ti].gateway6 = change.gateway
                  d.trackers[ti].hasGateway6 = true
                let gwLen = if change.family == uint8(2): 4 else: 16
                d.installInterfaceRoute(ti, change.gateway[0 ..< gwLen], change.family)
              break
        else:  # rckRouteDel
          for ti in 0 ..< d.trackers.len:
            if d.trackers[ti].ifindex != 0 and d.trackers[ti].ifindex == change.ifindex:
              if change.family == uint8(2):
                d.trackers[ti].hasGateway4 = false
              else:
                d.trackers[ti].hasGateway6 = false
              d.removeInterfaceRoute(ti, change.family)
              break
      # All route changes (default and non-default) may affect bypass networks.
      # Set both dirty flags: connectedNetworksDirty triggers a fresh dump,
      # nftablesDirty ensures the bypass rules are regenerated.
      d.connectedNetworksDirty = true
      d.nftablesDirty = true
    of rckAddrAdd, rckAddrDel:
      d.connectedNetworksDirty = true
      d.nftablesDirty = true

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

# =========================================================================
# Shared probe setup helpers (used by init and reload)
# =========================================================================

proc setupProbeForInterface(d: var Daemon, t: InterfaceTracker,
                            c: InterfaceConfig) =
  ## Configure probes for a single interface: filter targets, create transport,
  ## register with probe engine, schedule first probe timer.
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

proc registerProbeSockets(d: var Daemon) =
  ## Register all probe engine FDs with the selector. Log invalid sockets.
  for (slot, fd) in d.probeEngine.getFds():
    d.selector.registerHandle(fd.int, {Read}, ProbeTokenBase + slot)
  for name in d.probeEngine.invalidFdInterfaces:
    error fmt"probe socket creation failed for interface '{name}' — probes will not work"

proc deregisterProbeSockets(probeEngine: var ProbeEngine, selector: var Selector[int]) =
  ## Unregister all probe engine FDs from the selector.
  for (slot, fd) in probeEngine.getFds():
    try: selector.unregister(fd.int)
    except CatchableError: discard

# =========================================================================

proc initializeInterfaces(d: var Daemon) =
  ## Set up initial interface states, probes, routes, and nftables.

  # Clean up stale ip rules/routes from a previous run (e.g., after SIGKILL).
  # Delete-before-add prevents EEXIST warnings on rule installation.
  for ti in 0 ..< d.trackers.len:
    d.cleanupInfraRoutes(d.trackers[ti].index)

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
      d.trackers[ti].state = isProbing
      d.trackers[ti].successCount = 0
      d.trackers[ti].failCount = 0

    d.setupProbeForInterface(d.trackers[ti], c)

  # Install ip rules for ALL interfaces (infrastructure — never removed)
  for ti in 0 ..< d.trackers.len:
    d.installInfraRules(d.trackers[ti].index)

  # Query ubus for interface gateways and install per-interface table routes.
  # netifd only installs the winning default route in the kernel, so we can't
  # rely on netlink route dumps to find gateways for non-primary interfaces.
  var ifaceNames: seq[string]
  for t in d.trackers: ifaceNames.add(t.name)
  let gateways = getInterfaceGateways(ifaceNames)
  for gw in gateways:
    for ti in 0 ..< d.trackers.len:
      if d.trackers[ti].name == gw.name:
        if gw.gateway4.len > 0:
          var gwBytes: array[16, byte]
          if parseIpToBytes(gw.gateway4, gwBytes):
            d.trackers[ti].gateway4[0 ..< 4] = gwBytes[0 ..< 4]
            d.trackers[ti].hasGateway4 = true
            d.installInterfaceRoute(ti, gwBytes[0 ..< 4], uint8(2))
        if gw.gateway6.len > 0:
          var gwBytes: array[16, byte]
          if parseIpToBytes(gw.gateway6, gwBytes):
            d.trackers[ti].gateway6 = gwBytes
            d.trackers[ti].hasGateway6 = true
            d.installInterfaceRoute(ti, gwBytes, uint8(10))
        break

  # Warn if multiple WANs share the same route metric.
  # Without distinct metrics, the kernel keeps only one default route in the
  # main table. nopal handles routing via per-interface tables, but the router's
  # own traffic during early boot or daemon downtime uses the main table.
  if d.trackers.len >= 2:
    let routeResult = d.routeManager.getDefaultRoutes()
    if routeResult.ok and routeResult.value.len < d.trackers.len:
      warn "only " & $routeResult.value.len & " of " & $d.trackers.len &
           " WAN interfaces have a default route in the main table — " &
           "set different metrics in /etc/config/network for " &
           "resilient failover when nopal is not running"

  d.registerProbeSockets()

  for index in onlineIndices:
    d.updateDns(index)

  d.regenerateNftables()

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
  deregisterProbeSockets(probeEngine, selector)

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
  d.trackerIndex = buildTrackerIndex(d.trackers)

  var names: seq[string]
  for t in d.trackers: names.add(t.name)
  d.statusFiles.createDirs(names)

  # Re-register probes using shared helper
  for t in d.trackers:
    let cfg = d.configForIndex(t.index)
    if cfg.isNone: continue
    d.setupProbeForInterface(t, cfg.get)

  d.registerProbeSockets()

  # Install infrastructure ip rules for all interfaces
  for ti in 0 ..< d.trackers.len:
    d.installInfraRules(d.trackers[ti].index)

  # Query ubus for interface gateways and install per-interface table routes
  var ifaceNames: seq[string]
  for t in d.trackers: ifaceNames.add(t.name)
  let gateways = getInterfaceGateways(ifaceNames)
  for gw in gateways:
    for ti in 0 ..< d.trackers.len:
      if d.trackers[ti].name == gw.name:
        if gw.gateway4.len > 0:
          var gwBytes: array[16, byte]
          if parseIpToBytes(gw.gateway4, gwBytes):
            d.trackers[ti].gateway4[0 ..< 4] = gwBytes[0 ..< 4]
            d.trackers[ti].hasGateway4 = true
            d.installInterfaceRoute(ti, gwBytes[0 ..< 4], uint8(2))
        if gw.gateway6.len > 0:
          var gwBytes: array[16, byte]
          if parseIpToBytes(gw.gateway6, gwBytes):
            d.trackers[ti].gateway6 = gwBytes
            d.trackers[ti].hasGateway6 = true
            d.installInterfaceRoute(ti, gwBytes, uint8(10))
        break

  # Restore DNS for active interfaces
  for t in d.trackers:
    if t.state == isOnline or t.state == isDegraded:
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

  # Clean up infrastructure routes for all interfaces
  for t in d.trackers:
    d.cleanupInfraRoutes(t.index)

  reloadTeardown(ctx, d.probeEngine, d.selector, d.dnsManager,
                 d.trackers, d.timers)
  reloadBuildTrackers(ctx, d.config)
  reloadReinitSubsystems(ctx, d)

  info fmt"configuration reloaded: {d.config.interfaces.len} interfaces, {d.config.policies.len} policies, {d.config.rules.len} rules"

proc performRollback(d: var Daemon) =
  ## Restore the saved config snapshot from a pending reload confirmation.
  ## Uses the same phase object reload pattern but with saved old config.
  if not d.reloadState.pending: return

  let saved = d.reloadState.context
  info "rolling back configuration to pre-reload state"

  # Cancel the confirmation timer
  d.timers.cancelByIndex(0, {tkReloadConfirm})

  # Clean up infrastructure routes for all interfaces
  for t in d.trackers:
    d.cleanupInfraRoutes(t.index)

  var ctx = ReloadContext(newConfig: saved.oldConfig)
  reloadTeardown(ctx, d.probeEngine, d.selector, d.dnsManager,
                 d.trackers, d.timers)
  reloadBuildTrackers(ctx, saved.oldConfig)
  d.cachedRules = saved.oldCachedRules
  reloadReinitSubsystems(ctx, d)

  d.reloadState = ReloadState(pending: false)
  info "configuration rollback complete"

proc handleReloadTimeout(d: var Daemon) =
  ## Timer callback: rollback timeout expired, auto-rollback.
  if not d.reloadState.pending: return
  warn "reload rollback timeout — reverting configuration"
  d.performRollback()

proc handleReloadCommand(d: var Daemon, req: IpcRequest): IpcResponse =
  ## IPC command: reload configuration. Supports optional confirm_timeout param.
  if d.reloadState.pending:
    return errorResponse(req.id, "reload pending — run 'nopal accept' or 'nopal cancel' first")

  # Check for confirm_timeout param
  let confirmTimeout = if req.params != nil and req.params.hasKey("confirm_timeout"):
    let t = req.params{"confirm_timeout"}.getInt(0)
    if t > 0: t else: 0
  else:
    0

  if confirmTimeout > 0:
    # Confirmed reload: save snapshot, apply, start timer
    let snapshot = PendingReload(
      oldConfig: d.config,
      oldTrackers: d.trackers,
      oldTrackerIndex: d.trackerIndex,
      oldCachedRules: d.cachedRules,
      deadline: getMonoTime() + initDuration(seconds = confirmTimeout),
    )

    try:
      d.handleReload()
    except CatchableError as e:
      return errorResponse(req.id, "reload failed: " & e.msg)

    d.reloadState = ReloadState(pending: true, context: snapshot)
    d.timers.push(TimerEntry(
      deadline: snapshot.deadline,
      kind: tkReloadConfirm,
      index: 0,
    ))

    let rollbackMins = confirmTimeout div 60
    info fmt"configuration reloaded with {rollbackMins} minute(s) rollback timeout"
    let data = %*{"status": "pending_rollback", "rollback_secs": confirmTimeout}
    return successResponse(req.id, data)
  else:
    # Immediate reload (existing behavior)
    try:
      d.handleReload()
      successResponse(req.id)
    except CatchableError as e:
      errorResponse(req.id, "reload failed: " & e.msg)

proc handleAcceptCommand(d: var Daemon, req: IpcRequest): IpcResponse =
  ## IPC command: confirm a pending reload — discard snapshot, cancel timer.
  if not d.reloadState.pending:
    return errorResponse(req.id, "no pending reload to accept")

  d.timers.cancelByIndex(0, {tkReloadConfirm})
  d.reloadState = ReloadState(pending: false)
  info "reload confirmed — new configuration accepted"
  successResponse(req.id)

proc handleCancelCommand(d: var Daemon, req: IpcRequest): IpcResponse =
  ## IPC command: cancel a pending reload — rollback to saved config.
  if not d.reloadState.pending:
    return errorResponse(req.id, "no pending reload to cancel")

  d.performRollback()
  successResponse(req.id)

# =========================================================================
# Dynamic bypass commands
# =========================================================================

proc handleBypassAdd(d: var Daemon, req: IpcRequest): IpcResponse =
  ## IPC command: add a CIDR to the dynamic bypass set.
  let network = if req.params != nil and req.params.hasKey("network"):
    req.params{"network"}.getStr()
  else:
    ""
  if network.len == 0:
    return errorResponse(req.id, "missing 'network' parameter")

  # Validate CIDR format (addr/prefix)
  let slashIdx = network.find('/')
  if slashIdx < 0:
    return errorResponse(req.id, "invalid CIDR: missing prefix length (e.g., 10.0.0.0/8)")

  let isV6 = ':' in network
  let setName = if isV6: "bypass_v6" else: "bypass_v4"

  # Check for duplicate
  if isV6:
    if network in d.dynamicBypassV6:
      return errorResponse(req.id, "network already in bypass set: " & network)
    d.dynamicBypassV6.add(network)
  else:
    if network in d.dynamicBypassV4:
      return errorResponse(req.id, "network already in bypass set: " & network)
    d.dynamicBypassV4.add(network)

  # Immediate nft element injection (no full regen needed)
  if not nftEngine.addSetElement(setName, network):
    warn fmt"failed to add bypass element {network} to {setName}"

  info fmt"dynamic bypass added: {network}"
  successResponse(req.id)

proc handleBypassRemove(d: var Daemon, req: IpcRequest): IpcResponse =
  ## IPC command: remove a CIDR from the dynamic bypass set.
  let network = if req.params != nil and req.params.hasKey("network"):
    req.params{"network"}.getStr()
  else:
    ""
  if network.len == 0:
    return errorResponse(req.id, "missing 'network' parameter")

  let isV6 = ':' in network
  let setName = if isV6: "bypass_v6" else: "bypass_v4"

  # Find and remove
  var found = false
  if isV6:
    let idx = d.dynamicBypassV6.find(network)
    if idx >= 0:
      d.dynamicBypassV6.delete(idx)
      found = true
  else:
    let idx = d.dynamicBypassV4.find(network)
    if idx >= 0:
      d.dynamicBypassV4.delete(idx)
      found = true

  if not found:
    return errorResponse(req.id, "network not in bypass set: " & network)

  # Immediate nft element removal
  if not nftEngine.delSetElement(setName, network):
    warn fmt"failed to remove bypass element {network} from {setName}"

  info fmt"dynamic bypass removed: {network}"
  successResponse(req.id)

# =========================================================================
# Shutdown
# =========================================================================

proc shutdown(d: var Daemon) =
  ## Clean shutdown: close all resources in reverse-initialization order.
  info "nopal daemon shutting down"

  # 1. Clean up nftables ruleset
  discard nftEngine.cleanup()

  # 2. Stop IPC server (stop accepting new requests/clients)
  d.ipcServer.close()

  # 3. Deregister probe FDs from selector, then close all probe sockets
  deregisterProbeSockets(d.probeEngine, d.selector)
  d.probeEngine.closeAll()

  # 4. Close conntrack netlink socket (if opened)
  d.conntrackMgr.close()

  # 5. Clean up DNS
  for t in d.trackers:
    d.dnsManager.removeInterface(t.name)
  d.dnsManager.apply()

  # 6. Remove routes/rules (uses routeManager — must be before routeManager.close)
  for t in d.trackers:
    d.cleanupInfraRoutes(t.index)

  # 6. Close route manager netlink socket
  d.routeManager.close()

  # 7. Close link and route monitors
  d.linkMonitor.close()
  d.routeMonitor.close()

  # 8. Clean up status files
  d.statusFiles.cleanup()

  # 9. Close signal pipe read end
  if d.signalFd >= 0:
    discard posix.close(d.signalFd)
    d.signalFd = -1

  # 10. Close selector (must be last — owns FD registrations)
  try:
    d.selector.close()
  except CatchableError: discard

  info "nopal daemon stopped"

# =========================================================================
# Snapshot builder
# =========================================================================

proc buildDaemonSnapshot(d: Daemon, now: MonoTime): DaemonSnapshot =
  ## Build a pure value snapshot of all daemon state for IPC queries.
  let uptime = inSeconds(now - d.startTime)

  # Build interface snapshots
  var ifaces: seq[InterfaceSnapshot]
  for t in d.trackers:
    let targets = d.probeEngine.getTargetStatuses(t.index)
    var targetSnaps: seq[TargetSnapshot]
    for ts in targets:
      targetSnaps.add(TargetSnapshot(
        ip: formatIpBytes(ts.ip, ts.isV6),
        up: ts.up,
        rttMs: if ts.lastRttMs.isSome: int(ts.lastRttMs.get) else: -1,
      ))
    let ifUptime = if t.onlineSince.isSome: inSeconds(now - t.onlineSince.get) else: -1'i64
    let avgRtt = if t.avgRttMs.isSome: int(t.avgRttMs.get) else: -1
    ifaces.add(InterfaceSnapshot(
      name: t.name, device: t.device, state: $t.state,
      enabled: t.enabled, mark: t.mark, tableId: t.tableId,
      successCount: t.successCount, failCount: t.failCount,
      avgRttMs: avgRtt, lossPercent: t.lossPercent,
      uptimeSecs: ifUptime, targets: targetSnaps,
    ))

  # Build policy snapshots
  var pols: seq[PolicySnapshot]
  for pc in d.config.policies:
    let resolved = resolvePolicy(pc, d.config.members, d.trackers)
    var activeMembers: seq[string]
    var activeTier = -1
    if resolved.tiers.len > 0:
      activeTier = int(resolved.tiers[0].metric)
      for m in resolved.tiers[0].members:
        activeMembers.add(m.interfaceName)
    pols.add(PolicySnapshot(name: pc.name, activeMembers: activeMembers, activeTier: activeTier))

  # Reload pending
  let pending = if d.reloadState.pending:
    let remaining = int((d.reloadState.context.deadline - now).inSeconds)
    some(ReloadPendingInfo(remainingSecs: max(0, remaining)))
  else:
    none[ReloadPendingInfo]()

  DaemonSnapshot(
    apiVersion: 1,
    version: NimblePkgVersion,
    uptimeSecs: uptime,
    interfaces: ifaces,
    policies: pols,
    connectedNetworks: d.connectedNetworks,
    dynamicBypass: BypassSnapshot(v4: d.dynamicBypassV4, v6: d.dynamicBypassV6),
    reloadPending: pending,
  )

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
            let snap = buildDaemonSnapshot(d, getMonoTime())
            case ipcMethod.get
            of imStatus:
              handleStatusQuery(snap, req)
            of imInterfaceStatus:
              handleInterfaceStatusQuery(snap, req)
            of imConnected:
              handleConnectedQuery(snap, req)
            of imConfigReload:
              d.handleReloadCommand(req)
            of imConfigAccept:
              d.handleAcceptCommand(req)
            of imConfigCancel:
              d.handleCancelCommand(req)
            of imBypassAdd:
              d.handleBypassAdd(req)
            of imBypassRemove:
              d.handleBypassRemove(req)
            of imBypassList:
              handleBypassListQuery(snap, req)
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
      of tkReloadConfirm:
        d.handleReloadTimeout()

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
