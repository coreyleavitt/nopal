## IPC query handlers: read-only projections of daemon state.
##
## CQS architecture: this module contains query handlers only.
## Command handlers (config.reload) live in daemon.nim where they
## have mutable access to the Daemon.
##
## Dispatch routing also lives in daemon.nim (case on IpcMethod enum).

import std/[json, options, monotimes, times]
import ./protocol
import ../state/tracker
import ../state/policy
import ../config/schema

type
  IpcMethod* = enum
    imStatus
    imInterfaceStatus
    imConnected
    imConfigReload
    imConfigAccept
    imConfigCancel
    imBypassAdd
    imBypassRemove
    imBypassList
    imSubscribe

  ## Read-only view of daemon state for query handlers.
  DaemonView* = object
    trackers*: ptr seq[InterfaceTracker]
    config*: ptr NopalConfig
    startTime*: MonoTime
    connectedNetworks*: ptr seq[string]
    dynamicBypassV4*: ptr seq[string]
    dynamicBypassV6*: ptr seq[string]
    reloadPending*: Option[ReloadPendingInfo]

func parseIpcMethod*(s: string): Option[IpcMethod] {.raises: [].} =
  ## Parse an RPC method name to the IpcMethod enum.
  ## Returns none for unknown methods.
  case s
  of "status": some(imStatus)
  of "interface.status": some(imInterfaceStatus)
  of "connected": some(imConnected)
  of "config.reload": some(imConfigReload)
  of "config.accept": some(imConfigAccept)
  of "config.cancel": some(imConfigCancel)
  of "bypass.add": some(imBypassAdd)
  of "bypass.remove": some(imBypassRemove)
  of "bypass.list": some(imBypassList)
  of "subscribe": some(imSubscribe)
  else: none[IpcMethod]()

proc buildInterfaceStatus*(t: InterfaceTracker): InterfaceStatusData {.raises: [].} =
  let uptimeSecs = if t.onlineSince.isSome:
    inSeconds(getMonoTime() - t.onlineSince.get)
  else:
    -1'i64
  let avgRtt = if t.avgRttMs.isSome: int(t.avgRttMs.get) else: -1

  InterfaceStatusData(
    name: t.name,
    device: t.device,
    state: $t.state,
    enabled: t.enabled,
    mark: t.mark,
    tableId: t.tableId,
    successCount: t.successCount,
    failCount: t.failCount,
    avgRttMs: avgRtt,
    lossPercent: t.lossPercent,
    uptimeSecs: uptimeSecs,
    targets: nil,
  )

proc handleStatusQuery*(view: DaemonView, req: IpcRequest): IpcResponse {.raises: [].} =
  ## Query: return full daemon status.
  let uptime = inSeconds(getMonoTime() - view.startTime)

  var ifaces: seq[InterfaceStatusData]
  for t in view.trackers[]:
    ifaces.add(buildInterfaceStatus(t))

  var pols: seq[PolicyStatusData]
  for pc in view.config.policies:
    let resolved = resolvePolicy(pc, view.config.members, view.trackers[])
    var activeMembers: seq[string]
    var activeTier = -1
    if resolved.tiers.len > 0:
      activeTier = int(resolved.tiers[0].metric)
      for m in resolved.tiers[0].members:
        activeMembers.add(m.interfaceName)
    pols.add(PolicyStatusData(
      name: pc.name,
      activeMembers: activeMembers,
      activeTier: activeTier,
    ))

  let status = DaemonStatus(
    version: "0.1.0-alpha.5",
    uptimeSecs: uptime,
    interfaces: ifaces,
    policies: pols,
    reloadPending: view.reloadPending,
  )
  successResponse(req.id, status.toJson())

proc handleInterfaceStatusQuery*(view: DaemonView, req: IpcRequest): IpcResponse {.raises: [].} =
  ## Query: return status for a single interface.
  let ifaceName = if req.params != nil and req.params.hasKey("interface"):
    req.params{"interface"}.getStr()
  else:
    ""
  if ifaceName == "" or ifaceName.len > 64:
    return errorResponse(req.id, "missing or invalid 'interface' parameter")

  for t in view.trackers[]:
    if t.name == ifaceName:
      let data = buildInterfaceStatus(t)
      return successResponse(req.id, data.toJson())
  errorResponse(req.id, "interface '" & ifaceName & "' not found")

proc handleConnectedQuery*(view: DaemonView, req: IpcRequest): IpcResponse {.raises: [].} =
  ## Query: return connected networks.
  let data = ConnectedData(networks: view.connectedNetworks[])
  successResponse(req.id, data.toJson())

proc handleBypassListQuery*(view: DaemonView, req: IpcRequest): IpcResponse {.raises: [].} =
  ## Query: return dynamic bypass entries.
  let data = %*{"v4": view.dynamicBypassV4[], "v6": view.dynamicBypassV6[]}
  successResponse(req.id, data)

when isMainModule:
  import std/[unittest, strutils]

  suite "parseIpcMethod":
    test "known methods parse correctly":
      check parseIpcMethod("status") == some(imStatus)
      check parseIpcMethod("interface.status") == some(imInterfaceStatus)
      check parseIpcMethod("connected") == some(imConnected)
      check parseIpcMethod("config.reload") == some(imConfigReload)
      check parseIpcMethod("subscribe") == some(imSubscribe)

    test "unknown methods return none":
      check parseIpcMethod("nonexistent").isNone
      check parseIpcMethod("").isNone
      check parseIpcMethod("STATUS").isNone  # case sensitive

  suite "query handlers":
    test "handleStatusQuery returns DaemonStatus":
      var trackers = @[newTracker("wan", 0, 0x100, 101, "eth0", 3, 5)]
      trackers[0].state = isOnline
      let config = NopalConfig(globals: defaultGlobals())
      var connected: seq[string] = @[]
      let view = DaemonView(
        trackers: addr trackers,
        config: unsafeAddr config,
        startTime: getMonoTime(),
        connectedNetworks: addr connected,
      )
      let req = IpcRequest(id: 1, rpcMethod: "status")
      let resp = handleStatusQuery(view, req)
      check resp.success
      check resp.data["interfaces"].len == 1
      check resp.data["interfaces"][0]["name"].getStr == "wan"

    test "handleInterfaceStatusQuery returns single interface":
      var trackers = @[newTracker("wan", 0, 0x100, 101, "eth0", 3, 5)]
      trackers[0].state = isOnline
      let config = NopalConfig(globals: defaultGlobals())
      var connected: seq[string] = @[]
      let view = DaemonView(
        trackers: addr trackers,
        config: unsafeAddr config,
        startTime: getMonoTime(),
        connectedNetworks: addr connected,
      )
      let req = IpcRequest(id: 1, rpcMethod: "interface.status",
                           params: %*{"interface": "wan"})
      let resp = handleInterfaceStatusQuery(view, req)
      check resp.success
      check resp.data["name"].getStr == "wan"

    test "handleInterfaceStatusQuery unknown interface":
      var trackers: seq[InterfaceTracker] = @[]
      let config = NopalConfig(globals: defaultGlobals())
      var connected: seq[string] = @[]
      let view = DaemonView(
        trackers: addr trackers,
        config: unsafeAddr config,
        startTime: getMonoTime(),
        connectedNetworks: addr connected,
      )
      let req = IpcRequest(id: 1, rpcMethod: "interface.status",
                           params: %*{"interface": "nonexistent"})
      let resp = handleInterfaceStatusQuery(view, req)
      check not resp.success
      check "not found" in resp.error

    test "status reports degraded state with quality metrics":
      var trackers = @[newTracker("wan", 0, 0x100, 101, "eth0", 3, 5)]
      trackers[0].state = isDegraded
      trackers[0].avgRttMs = some(150'u32)
      trackers[0].lossPercent = 30
      trackers[0].successCount = 7
      trackers[0].failCount = 3
      let config = NopalConfig(
        globals: defaultGlobals(),
        policies: @[PolicyConfig(name: "balanced",
                                  members: @["wan_m"],
                                  lastResort: lrDefault)],
        members: @[MemberConfig(name: "wan_m", interfaceName: "wan",
                                 metric: 1, weight: 50)],
      )
      var connected: seq[string] = @[]
      let view = DaemonView(
        trackers: addr trackers,
        config: unsafeAddr config,
        startTime: getMonoTime(),
        connectedNetworks: addr connected,
      )
      let req = IpcRequest(id: 1, rpcMethod: "status")
      let resp = handleStatusQuery(view, req)
      check resp.success
      let iface = resp.data["interfaces"][0]
      check iface["state"].getStr == "degraded"
      check iface["avg_rtt_ms"].getInt == 150
      check iface["loss_percent"].getInt == 30
      check iface["success_count"].getInt == 7
      check iface["fail_count"].getInt == 3
      let pol = resp.data["policies"][0]
      check pol["active_members"].len == 1
      check pol["active_members"][0].getStr == "wan"

    test "handleConnectedQuery returns networks":
      var trackers: seq[InterfaceTracker] = @[]
      let config = NopalConfig(globals: defaultGlobals())
      var connected = @["127.0.0.0/8", "::1/128"]
      let view = DaemonView(
        trackers: addr trackers,
        config: unsafeAddr config,
        startTime: getMonoTime(),
        connectedNetworks: addr connected,
      )
      let req = IpcRequest(id: 1, rpcMethod: "connected")
      let resp = handleConnectedQuery(view, req)
      check resp.success
      check resp.data["networks"].len == 2
