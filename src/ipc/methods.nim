## IPC method dispatch: routes RPC requests to handlers.

import std/[json, options, monotimes, times, strformat]
import ./protocol
import ../state/tracker
import ../state/policy
import ../config/schema

type
  DispatchAction* = enum
    daNone, daReload

  ## Read-only view of daemon state for dispatch.
  DaemonView* = object
    trackers*: ptr seq[InterfaceTracker]
    config*: ptr NopalConfig
    startTime*: MonoTime
    connectedNetworks*: ptr seq[string]

proc buildInterfaceStatus(t: InterfaceTracker): InterfaceStatusData =
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

proc buildStatus(view: DaemonView): DaemonStatus =
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

  DaemonStatus(
    version: "0.1.0-alpha.3",
    uptimeSecs: uptime,
    interfaces: ifaces,
    policies: pols,
  )

proc dispatch*(req: IpcRequest, view: DaemonView): (IpcResponse, DispatchAction) =
  ## Route an IPC request to the appropriate handler.
  ## Returns (response, action) where action tells the daemon what to do.
  case req.rpcMethod
  of "status":
    let status = buildStatus(view)
    (successResponse(req.id, status.toJson()), daNone)

  of "interface.status":
    let ifaceName = if req.params != nil and req.params.hasKey("interface"):
      req.params["interface"].getStr()
    else:
      ""
    if ifaceName == "" or ifaceName.len > 64:
      return (errorResponse(req.id, "missing or invalid 'interface' parameter"), daNone)

    for t in view.trackers[]:
      if t.name == ifaceName:
        let data = buildInterfaceStatus(t)
        return (successResponse(req.id, data.toJson()), daNone)
    (errorResponse(req.id, fmt"interface '{ifaceName}' not found"), daNone)

  of "connected":
    let data = ConnectedData(networks: view.connectedNetworks[])
    (successResponse(req.id, data.toJson()), daNone)

  of "config.reload":
    (successResponse(req.id), daReload)

  of "subscribe":
    # Subscription is handled by the server (marks client.subscribed = true).
    # Just acknowledge.
    (successResponse(req.id), daNone)

  else:
    (errorResponse(req.id, fmt"unknown method '{req.rpcMethod}'"), daNone)

when isMainModule:
  import std/[unittest, strutils]

  suite "IPC methods":
    test "dispatch status returns DaemonStatus":
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
      let (resp, action) = dispatch(req, view)
      check resp.success
      check action == daNone
      check resp.data["interfaces"].len == 1
      check resp.data["interfaces"][0]["name"].getStr == "wan"

    test "dispatch unknown method returns error":
      var trackers: seq[InterfaceTracker] = @[]
      let config = NopalConfig(globals: defaultGlobals())
      var connected: seq[string] = @[]
      let view = DaemonView(
        trackers: addr trackers,
        config: unsafeAddr config,
        startTime: getMonoTime(),
        connectedNetworks: addr connected,
      )
      let req = IpcRequest(id: 2, rpcMethod: "nonexistent")
      let (resp, action) = dispatch(req, view)
      check not resp.success
      check "unknown method" in resp.error

    test "dispatch config.reload sets action":
      var trackers: seq[InterfaceTracker] = @[]
      let config = NopalConfig(globals: defaultGlobals())
      var connected: seq[string] = @[]
      let view = DaemonView(
        trackers: addr trackers,
        config: unsafeAddr config,
        startTime: getMonoTime(),
        connectedNetworks: addr connected,
      )
      let req = IpcRequest(id: 3, rpcMethod: "config.reload")
      let (resp, action) = dispatch(req, view)
      check resp.success
      check action == daReload
