## Daemon event loop and component orchestration.
##
## Central orchestrator: owns all subsystem components, drives the
## selector-based event loop, dispatches probe/link/route/IPC events,
## and coalesces deferred nftables/DNS updates.

import std/[selectors, posix, monotimes, times, options, logging, os, strutils]

import ./config/schema
import ./config/parser
import ./config/diff
import ./state/tracker
import ./state/policy
import ./state/transition
import ./health/engine
import ./health/dampening
import ./nftables/marks
import ./nftables/chains
import ./nftables/engine as nftEngine
import ./netlink/route
import ./netlink/link
import ./netlink/monitor
import ./netlink/conntrack
import ./dnsmanager
import ./timer
# IPC server/methods stubs -- will be imported when complete
# import ./ipc/server
# import ./ipc/methods
# import ./ipc/protocol

# =========================================================================
# Token constants for selector dispatch
# =========================================================================

const
  TokenLink* = 0
  TokenIpc* = 1
  TokenSignal* = 2
  TokenRoute* = 3
  ProbeTokenBase* = 100
  IpcClientBase* = 1000

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

    # Signal delivery
    signalFd: cint

    # State
    trackers*: seq[InterfaceTracker]
    startTime: MonoTime
    running: bool
    reloadRequested: bool
    firstConnectFired: bool
    connectedNetworks: seq[string]
    hookScriptExists: bool
    connectedNetworksDirty: bool
    nftablesDirty: bool
    dnsDirty: bool
    cachedRules: seq[RuleInfo]
    inFlightHooks: int

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

proc checkHookScript(path: string): bool =
  path.len > 0 and fileExists(path)

proc initDaemon*(configPath: string, signalFd: cint): Daemon =
  ## Load config, create all subsystem components, register fds with
  ## selector, assign marks, build trackers.
  let config = loadConfig(configPath)

  info "loaded config: " & $config.interfaces.len & " interfaces, " &
       $config.policies.len & " policies, " & $config.rules.len & " rules"

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
  selector.registerHandle(signalFd, {Read}, TokenSignal)

  # Register link monitor
  selector.registerHandle(linkMon.fd, {Read}, TokenLink)

  # Register route monitor
  selector.registerHandle(routeMon.fd, {Read}, TokenRoute)

  # IPC listener registration is stubbed -- will be added when IPC server is complete
  # selector.registerHandle(ipcServer.fd, {Read}, TokenIpc)

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
      warn iface.name & ": skipping IPv6-only interface (ipv6_enabled=false)"
      continue

    if markIdx >= marks.len:
      error iface.name & ": no mark slot available, skipping"
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
      info iface.name & ": dampening enabled (halflife=" &
           $iface.dampeningHalflife & ", ceiling=" & $iface.dampeningCeiling &
           ", suppress=" & $iface.dampeningSuppress & ", reuse=" &
           $iface.dampeningReuse & ")"

    trackers.add(t)

  let hookExists = checkHookScript(config.globals.hookScript)
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
    signalFd: signalFd,
    trackers: trackers,
    startTime: getMonoTime(),
    running: true,
    reloadRequested: false,
    firstConnectFired: false,
    connectedNetworks: @[],
    hookScriptExists: hookExists,
    connectedNetworksDirty: true,
    nftablesDirty: false,
    dnsDirty: false,
    cachedRules: cachedRules,
    inFlightHooks: 0,
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
  ## Create a probe transport based on the configured track method.
  ## Returns the appropriate transport variant for the engine.
  case cfg.trackMethod
  of tmPing:
    let family = case cfg.family
      of afIpv4: uint8(2)    # AF_INET
      of afIpv6: uint8(10)   # AF_INET6
      of afBoth: uint8(2)    # Default to IPv4
    ProbeTransport(kind: tkIcmp, icmpFd: -1, icmpFamily: family)
  of tmDns:
    let family = case cfg.family
      of afIpv4: uint8(2)
      of afIpv6: uint8(10)
      of afBoth: uint8(2)
    ProbeTransport(kind: tkDns, dnsFd: -1, dnsFamily: family,
                   dnsQueryLen: 0)
  of tmHttp, tmHttps:
    let family = case cfg.family
      of afIpv4: uint8(2)
      of afIpv6: uint8(10)
      of afBoth: uint8(2)
    let port = if cfg.trackPort > 0: uint16(cfg.trackPort)
               elif cfg.trackMethod == tmHttp: 80'u16
               else: 443'u16
    ProbeTransport(kind: tkHttp, httpFd: -1, httpFamily: family,
                   httpDevice: cfg.device, httpPort: port,
                   httpState: hsIdle)
  of tmArping:
    ProbeTransport(kind: tkArp, arpFd: -1, arpIfindex: 0)
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

  # TODO: refresh connected networks from route manager when available
  # For now use cached list
  d.connectedNetworksDirty = false

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
    error "addRoutes: no tracker for index " & $index
    return

  let cfg = d.configForIndex(index)
  let family = if cfg.isSome: cfg.get.family else: afIpv4

  const AF_INET = uint8(2)
  const AF_INET6 = uint8(10)

  if family == afIpv4 or family == afBoth:
    try:
      d.routeManager.addRule(t.mark, d.config.globals.markMask,
                             t.tableId, 100 + index.uint32, AF_INET)
    except CatchableError as e:
      warn "failed to add IPv4 ip rule for " & t.name & ": " & e.msg

  if d.config.globals.ipv6Enabled and (family == afIpv6 or family == afBoth):
    try:
      d.routeManager.addRule(t.mark, d.config.globals.markMask,
                             t.tableId, 100 + index.uint32, AF_INET6)
    except CatchableError as e:
      warn "failed to add IPv6 ip rule for " & t.name & ": " & e.msg

  info "added routes for " & t.name & " (mark=0x" & t.mark.toHex(4) &
       ", table=" & $t.tableId & ")"

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
    error "removeRoutes: no tracker for index " & $index
    return

  let cfg = d.configForIndex(index)
  let family = if cfg.isSome: cfg.get.family else: afIpv4

  const AF_INET = uint8(2)
  const AF_INET6 = uint8(10)

  if family == afIpv4 or family == afBoth:
    try:
      d.routeManager.delRule(t.mark, d.config.globals.markMask,
                             t.tableId, 100 + index.uint32, AF_INET)
    except CatchableError as e:
      warn "failed to delete IPv4 ip rule for " & t.name & ": " & e.msg

  if d.config.globals.ipv6Enabled and (family == afIpv6 or family == afBoth):
    try:
      d.routeManager.delRule(t.mark, d.config.globals.markMask,
                             t.tableId, 100 + index.uint32, AF_INET6)
    except CatchableError as e:
      warn "failed to delete IPv6 ip rule for " & t.name & ": " & e.msg

  try:
    d.routeManager.flushTableBoth(t.tableId)
  except CatchableError as e:
    warn "failed to flush table " & $t.tableId & " for " & t.name & ": " & e.msg

  info "removed routes for " & t.name

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
    try:
      d.conntrackMgr.flushByMark(mark, mask)
    except CatchableError as e:
      error "conntrack flush failed: " & e.msg
  of cfmFull:
    # Full flush not yet implemented in conntrack manager; use selective
    try:
      d.conntrackMgr.flushByMark(mark, mask)
    except CatchableError as e:
      error "conntrack flush all failed: " & e.msg
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
    debug c.name & ": conntrack flush triggered by " & $newState
    d.flushConntrack(mark, d.config.globals.markMask)

# =========================================================================
# Hook script execution
# =========================================================================

const MaxInFlightHooks = 4

proc runHook(d: var Daemon, interfaceName: string, newState: InterfaceState) =
  ## Execute the user hook script on state changes.
  ## Fire-and-forget, errors are logged but not propagated.
  if not d.hookScriptExists: return

  let script = d.config.globals.hookScript

  let action = case newState
    of isOnline: "connected"
    of isOffline: "disconnected"
    of isProbing: "ifup"
    of isDegraded: "degraded"
    of isInit: return

  var device = ""
  for t in d.trackers:
    if t.name == interfaceName:
      device = t.device
      break

  let firstConnect = action == "connected" and not d.firstConnectFired
  if firstConnect:
    d.firstConnectFired = true

  if d.inFlightHooks >= MaxInFlightHooks:
    warn "hook script skipped (" & $d.inFlightHooks & " already in flight)"
    return

  info "running hook: " & script & " ACTION=" & action &
       " INTERFACE=" & interfaceName & " DEVICE=" & device

  # Fork and exec the hook script
  let pid = posix.fork()
  if pid < 0:
    warn "failed to fork for hook script: " & $strerror(errno)
  elif pid == 0:
    # Child process
    # Set environment variables
    putEnv("ACTION", action)
    putEnv("INTERFACE", interfaceName)
    putEnv("DEVICE", device)
    if firstConnect:
      putEnv("FIRSTCONNECT", "1")

    discard posix.execl(cstring(script), cstring(script), nil)
    # If exec fails, exit immediately
    posix.exitnow(127)
  else:
    # Parent process -- reap asynchronously via SIGCHLD or periodic waitpid
    inc d.inFlightHooks
    # Non-blocking waitpid to reap immediately if already finished
    var status: cint
    let res = posix.waitpid(pid, status, WNOHANG)
    if res > 0:
      dec d.inFlightHooks
      if WEXITSTATUS(status) != 0:
        warn "hook script exited with " & $WEXITSTATUS(status)

proc reapHookChildren(d: var Daemon) =
  ## Non-blocking reap of any finished hook child processes.
  while d.inFlightHooks > 0:
    var status: cint
    let res = posix.waitpid(-1, status, WNOHANG)
    if res <= 0: break
    dec d.inFlightHooks
    if WIFEXITED(status) and WEXITSTATUS(status) != 0:
      warn "hook script exited with " & $WEXITSTATUS(status)

# =========================================================================
# Status file management
# =========================================================================

proc createStatusDirs(d: Daemon) =
  for t in d.trackers:
    let dir = "/var/run/nopal/" & t.name
    try:
      createDir(dir)
    except OSError as e:
      warn "failed to create status dir " & dir & ": " & e.msg

proc writeStatusFile(d: Daemon, index: int, state: InterfaceState) =
  var t: InterfaceTracker
  var found = false
  for tr in d.trackers:
    if tr.index == index:
      t = tr
      found = true
      break
  if not found: return

  let dir = "/var/run/nopal/" & t.name
  var content = $state & "\n"

  if t.onlineSince.isSome:
    let elapsed = (getMonoTime() - t.onlineSince.get).inSeconds
    content.add("uptime=" & $elapsed & "\n")
  if t.offlineSince.isSome:
    let elapsed = (getMonoTime() - t.offlineSince.get).inSeconds
    content.add("downtime=" & $elapsed & "\n")
  content.add("success_count=" & $t.successCount & "\n")
  content.add("fail_count=" & $t.failCount & "\n")
  if t.avgRttMs.isSome:
    content.add("avg_rtt_ms=" & $t.avgRttMs.get & "\n")
  content.add("loss_percent=" & $t.lossPercent & "\n")

  # Atomic write via temp + rename
  let tmpPath = dir & "/status.tmp." & $posix.getpid()
  let finalPath = dir & "/status"

  try: removeFile(tmpPath)
  except OSError: discard

  let fd = posix.open(cstring(tmpPath),
                      O_WRONLY or O_CREAT or O_EXCL, 0o644)
  if fd < 0:
    warn "failed to create status file " & tmpPath
    return

  let written = posix.write(fd, cstring(content), content.len)
  if written < 0 or written != content.len:
    warn "failed to write status file"
    discard posix.close(fd)
    try: removeFile(tmpPath)
    except OSError: discard
    return

  discard posix.fsync(fd)
  discard posix.close(fd)

  try:
    moveFile(tmpPath, finalPath)
  except OSError as e:
    warn "failed to rename status file: " & e.msg
    try: removeFile(tmpPath)
    except OSError: discard

proc writeInitialStatusFiles(d: Daemon) =
  for t in d.trackers:
    d.writeStatusFile(t.index, t.state)

proc cleanupStatusFiles(d: Daemon) =
  try:
    removeDir("/var/run/nopal")
  except OSError:
    debug "failed to clean up status files"

# =========================================================================
# Action execution
# =========================================================================

proc executeActions(d: var Daemon, result: TransitionResult) =
  ## Execute the actions determined by a state transition.
  for action in result.actions:
    case action
    of taRegenerateNftables:
      d.nftablesDirty = true
    of taAddRoutes:
      d.addRoutes(result.index)
    of taRemoveRoutes:
      d.removeRoutes(result.index)
    of taUpdateDns:
      d.updateDns(result.index)
    of taRemoveDns:
      d.removeDns(result.index)
    of taBroadcastEvent:
      var name = ""
      for t in d.trackers:
        if t.index == result.index:
          name = t.name
          break
      if name.len > 0:
        # IPC broadcast is stubbed until server.nim is complete
        debug "broadcast: interface.state_change " & name & " -> " & $result.newState
        d.runHook(name, result.newState)
    of taWriteStatus:
      d.writeStatusFile(result.index, result.newState)

# =========================================================================
# Dampening decay
# =========================================================================

proc scheduleDampenDecay(d: var Daemon, index: int) =
  ## Schedule a dampening decay timer check.
  let interval = d.configForIndex(index).map(
    proc(c: InterfaceConfig): uint32 = max(c.dampeningHalflife div 10, 1)
  ).get(30'u32)

  d.timers.push(TimerEntry(
    deadline: getMonoTime() + initDuration(seconds = int(interval)),
    kind: tkDampenDecay,
    index: index,
  ))

proc handleDampenDecay(d: var Daemon, index: int) =
  var trackerIdx = -1
  for i in 0 ..< d.trackers.len:
    if d.trackers[i].index == index:
      trackerIdx = i
      break
  if trackerIdx < 0: return

  if d.trackers[trackerIdx].dampening.isNone: return

  var damp = d.trackers[trackerIdx].dampening.get
  damp.decay()
  d.trackers[trackerIdx].dampening = some(damp)

  if damp.isSuppressed:
    debug d.trackers[trackerIdx].name & ": dampening penalty decayed to " &
          $damp.penalty & " (reuse: " & $damp.reuse & ")"
    d.scheduleDampenDecay(index)
  else:
    info d.trackers[trackerIdx].name &
         ": dampening reuse threshold reached, unsuppressed"

    # If interface is Offline with link still up, restart probing
    if d.trackers[trackerIdx].state == isOffline:
      let name = d.trackers[trackerIdx].name
      let mark = d.trackers[trackerIdx].mark
      let newStateOpt = d.trackers[trackerIdx].linkUp()
      if newStateOpt.isSome:
        info name & ": restarting probing after dampening decay"
        d.probeEngine.resetCounters(index)
        let tr = actionsForTransition(name, index, mark, isOffline, newStateOpt.get)
        d.executeActions(tr)
        d.timers.push(TimerEntry(
          deadline: getMonoTime() + initDuration(seconds = 1),
          kind: tkProbe,
          index: index,
        ))

# =========================================================================
# Process probe result
# =========================================================================

proc processProbeResult(d: var Daemon, probeResult: ProbeResult) =
  ## Update tracker state from a probe result, execute transition actions.
  var trackerIdx = -1
  for i in 0 ..< d.trackers.len:
    if d.trackers[i].index == probeResult.interfaceIndex:
      trackerIdx = i
      break
  if trackerIdx < 0: return

  # Update quality metrics for status reporting
  d.trackers[trackerIdx].avgRttMs = probeResult.avgRttMs
  d.trackers[trackerIdx].lossPercent = probeResult.lossPercent

  let oldState = d.trackers[trackerIdx].state
  let newStateOpt = if probeResult.success:
    d.trackers[trackerIdx].probeSuccess(probeResult.qualityOk)
  else:
    d.trackers[trackerIdx].probeFailure()

  if newStateOpt.isSome:
    let newState = newStateOpt.get
    let name = d.trackers[trackerIdx].name
    let index = d.trackers[trackerIdx].index
    let mark = d.trackers[trackerIdx].mark

    # Schedule dampening decay timer when transitioning to Offline while suppressed
    if newState == isOffline:
      if d.trackers[trackerIdx].dampening.isSome:
        let damp = d.trackers[trackerIdx].dampening.get
        if damp.isSuppressed:
          d.scheduleDampenDecay(index)

    let tr = actionsForTransition(name, index, mark, oldState, newState)
    d.executeActions(tr)
    d.maybeFlushConntrack(index, mark, oldState, newState, false)

# =========================================================================
# Event handlers
# =========================================================================

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
        d.reloadRequested = true
      else:
        discard

proc handleLinkEvents(d: var Daemon) =
  ## Read link events and drive the state machine for each affected interface.
  d.linkEventBuf.setLen(0)
  d.linkMonitor.processEvents(d.linkEventBuf)

  for event in d.linkEventBuf:
    if event.up:
      # Link up
      var trackerIdx = -1
      for i in 0 ..< d.trackers.len:
        if d.trackers[i].device == event.ifname:
          trackerIdx = i
          break
      if trackerIdx < 0: continue

      # Update cached ifindex
      d.trackers[trackerIdx].ifindex = event.ifindex

      let oldState = d.trackers[trackerIdx].state
      let newStateOpt = d.trackers[trackerIdx].linkUp()
      if newStateOpt.isSome:
        let name = d.trackers[trackerIdx].name
        let index = d.trackers[trackerIdx].index
        let mark = d.trackers[trackerIdx].mark
        let currentState = d.trackers[trackerIdx].state

        # Reset quality window and hysteresis
        d.probeEngine.resetCounters(index)

        let tr = actionsForTransition(name, index, mark, oldState, newStateOpt.get)
        d.executeActions(tr)
        d.maybeFlushConntrack(index, mark, oldState, newStateOpt.get, true)

        # Schedule first probe if entering Probing state
        if currentState == isProbing:
          d.timers.push(TimerEntry(
            deadline: getMonoTime() + initDuration(seconds = 1),
            kind: tkProbe,
            index: index,
          ))
    else:
      # Link down
      var trackerIdx = -1
      for i in 0 ..< d.trackers.len:
        if d.trackers[i].device == event.ifname:
          trackerIdx = i
          break
      if trackerIdx < 0: continue

      let oldState = d.trackers[trackerIdx].state
      let newStateOpt = d.trackers[trackerIdx].linkDown()
      if newStateOpt.isSome:
        let name = d.trackers[trackerIdx].name
        let index = d.trackers[trackerIdx].index
        let mark = d.trackers[trackerIdx].mark

        let tr = actionsForTransition(name, index, mark, oldState, newStateOpt.get)
        d.executeActions(tr)
        d.maybeFlushConntrack(index, mark, oldState, newStateOpt.get, true)

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
            debug t.name & ": route change detected (family=" & $change.family & ")"
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
    warn "failed to send probe for interface " & $index
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
      info d.trackers[ti].name & ": initial_state=online, active immediately"
    else:
      discard d.trackers[ti].linkUp()

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
    d.selector.registerHandle(fd, {Read}, ProbeTokenBase + slot)

  # Set up routes and DNS for initial_state=online interfaces
  for index in onlineIndices:
    d.addRoutes(index)
    d.updateDns(index)

  # Generate initial nftables
  d.regenerateNftables()

  # Create status directories and write initial status files
  d.createStatusDirs()
  d.writeInitialStatusFiles()

# =========================================================================
# Reload
# =========================================================================

proc handleReload(d: var Daemon) =
  ## Reload configuration, applying targeted or full rebuild as needed.
  info "reloading configuration from " & d.configPath

  var newConfig: NopalConfig
  try:
    newConfig = loadConfig(d.configPath)
  except CatchableError as e:
    error "failed to reload config: " & e.msg
    return

  let cfgDiff = diff(d.config, newConfig)
  if not cfgDiff.changed:
    info "config unchanged, skipping reload"
    return

  # Fast path: only routing policies/rules changed
  if not cfgDiff.needsFullRebuild and
     cfgDiff.changedInterfaces.len == 0 and
     cfgDiff.routingChanged:
    info "only routing policies/rules changed, regenerating nftables"
    d.config = newConfig
    d.cachedRules = buildRulesFromConfig(d.config)
    d.hookScriptExists = checkHookScript(d.config.globals.hookScript)
    d.regenerateNftables()
    return

  # Save current interface states by name for restoration
  var prevStates: seq[tuple[name: string, state: InterfaceState,
                             onlineSince: Option[MonoTime]]]
  for t in d.trackers:
    prevStates.add((name: t.name, state: t.state, onlineSince: t.onlineSince))

  # -- Teardown existing state --

  # Remove routes for active interfaces
  var activeIndices: seq[int]
  for t in d.trackers:
    if t.state == isOnline or t.state == isDegraded:
      activeIndices.add(t.index)
  for index in activeIndices:
    d.removeRoutes(index)

  # Deregister probe sockets from selector
  for (slot, fd) in d.probeEngine.getFds():
    try:
      d.selector.unregister(fd)
    except CatchableError:
      discard

  # Remove all interfaces from probe engine
  var probeIndices: seq[int]
  for t in d.trackers: probeIndices.add(t.index)
  for idx in probeIndices:
    d.probeEngine.removeInterface(idx)

  # Remove all DNS entries
  for t in d.trackers:
    d.dnsManager.removeInterface(t.name)
  d.dnsManager.apply()

  # -- Replace config and rebuild trackers --

  d.config = newConfig
  d.cachedRules = buildRulesFromConfig(d.config)
  d.hookScriptExists = checkHookScript(d.config.globals.hookScript)

  let ipv6Enabled = d.config.globals.ipv6Enabled
  var enabledNames: seq[string]
  for iface in d.config.interfaces:
    if not iface.enabled: continue
    if not ipv6Enabled and iface.family == afIpv6: continue
    enabledNames.add(iface.name)

  let marks = assignMarks(enabledNames, d.config.globals.markMask)

  var newTrackers: seq[InterfaceTracker]
  var markIdx = 0
  for i, iface in d.config.interfaces:
    if not iface.enabled: continue
    if not ipv6Enabled and iface.family == afIpv6:
      warn iface.name & ": skipping IPv6-only interface (ipv6_enabled=false)"
      continue

    if markIdx >= marks.len:
      error iface.name & ": no mark slot available, skipping"
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
    for prev in prevStates:
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
          discard t.linkUp()
        restoredState = true
        break

    if not restoredState:
      # New interface: assume link is up, start probing
      discard t.linkUp()

    newTrackers.add(t)

  d.trackers = newTrackers
  d.createStatusDirs()

  # -- Reinitialize probes, routes, and DNS --

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

  # Register new probe sockets with selector
  for (slot, fd) in d.probeEngine.getFds():
    d.selector.registerHandle(fd, {Read}, ProbeTokenBase + slot)

  # Restore routes and DNS for Online and Degraded interfaces
  var restoreIndices: seq[int]
  for t in d.trackers:
    if t.state == isOnline or t.state == isDegraded:
      restoreIndices.add(t.index)
  for index in restoreIndices:
    d.addRoutes(index)
    d.updateDns(index)

  # Regenerate nftables
  d.regenerateNftables()

  info "configuration reloaded: " & $d.config.interfaces.len & " interfaces, " &
       $d.config.policies.len & " policies, " & $d.config.rules.len & " rules"

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
      try:
        d.routeManager.delRule(t.mark, d.config.globals.markMask,
                               t.tableId, priority, AF_INET)
      except CatchableError: discard

    if d.config.globals.ipv6Enabled and (family == afIpv6 or family == afBoth):
      try:
        d.routeManager.delRule(t.mark, d.config.globals.markMask,
                               t.tableId, priority, AF_INET6)
      except CatchableError: discard

    try:
      d.routeManager.flushTableBoth(t.tableId)
    except CatchableError: discard

  d.cleanupStatusFiles()

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
    if d.reloadRequested:
      d.handleReload()
      d.reloadRequested = false

    # Reap any finished hook child processes
    d.reapHookChildren()

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
        # IPC listener accept -- stubbed until server.nim is complete
        debug "IPC accept event (stubbed)"
      elif token >= ProbeTokenBase and token < IpcClientBase:
        d.handleProbeResponse(token - ProbeTokenBase)
      elif token >= IpcClientBase:
        # IPC client read -- stubbed until server.nim is complete
        debug "IPC client event (stubbed), client_id=" & $(token - IpcClientBase)

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
        # IPC client timeout -- stubbed until server.nim is complete
        debug "IPC timeout for client " & $entry.index

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
