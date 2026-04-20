## IPC query handlers: read-only projections of daemon state.
##
## CQS architecture: this module contains query handlers only.
## Command handlers (config.reload) live in daemon.nim where they
## have mutable access to the Daemon.
##
## Dispatch routing also lives in daemon.nim (case on IpcMethod enum).

import std/[json, options]
import ./protocol
import ../snapshot

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

proc handleStatusQuery*(snap: DaemonSnapshot, req: IpcRequest): IpcResponse {.raises: [].} =
  ## Query: return full daemon status.
  successResponse(req.id, snap.toJson())

proc handleInterfaceStatusQuery*(snap: DaemonSnapshot, req: IpcRequest): IpcResponse {.raises: [].} =
  ## Query: return status for a single interface.
  let ifaceName = if req.params != nil and req.params.hasKey("interface"):
    req.params{"interface"}.getStr()
  else:
    ""
  if ifaceName == "" or ifaceName.len > 64:
    return errorResponse(req.id, "missing or invalid 'interface' parameter")

  for iface in snap.interfaces:
    if iface.name == ifaceName:
      return successResponse(req.id, iface.toJson())
  errorResponse(req.id, "interface '" & ifaceName & "' not found")

proc handleConnectedQuery*(snap: DaemonSnapshot, req: IpcRequest): IpcResponse {.raises: [].} =
  ## Query: return connected networks.
  successResponse(req.id, %*{"networks": snap.connectedNetworks})

proc handleBypassListQuery*(snap: DaemonSnapshot, req: IpcRequest): IpcResponse {.raises: [].} =
  ## Query: return dynamic bypass entries.
  successResponse(req.id, snap.dynamicBypass.toJson())

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

  proc makeTestSnap(ifaces: seq[InterfaceSnapshot] = @[],
                    policies: seq[PolicySnapshot] = @[],
                    connected: seq[string] = @[],
                    bypassV4: seq[string] = @[],
                    bypassV6: seq[string] = @[],
                    reloadPending: Option[ReloadPendingInfo] = none[ReloadPendingInfo]()): DaemonSnapshot =
    DaemonSnapshot(
      apiVersion: 1,
      version: "0.1.3-alpha.4",
      uptimeSecs: 100,
      interfaces: ifaces,
      policies: policies,
      connectedNetworks: connected,
      dynamicBypass: BypassSnapshot(v4: bypassV4, v6: bypassV6),
      reloadPending: reloadPending,
    )

  suite "query handlers":
    test "handleStatusQuery returns DaemonSnapshot":
      let snap = makeTestSnap(
        ifaces = @[InterfaceSnapshot(
          name: "wan", device: "eth0", state: "online",
          enabled: true, mark: 0x100, tableId: 101,
        )],
      )
      let req = IpcRequest(id: 1, rpcMethod: "status")
      let resp = handleStatusQuery(snap, req)
      check resp.success
      check resp.data["interfaces"].len == 1
      check resp.data["interfaces"][0]["name"].getStr == "wan"

    test "handleInterfaceStatusQuery returns single interface":
      let snap = makeTestSnap(
        ifaces = @[InterfaceSnapshot(
          name: "wan", device: "eth0", state: "online",
          enabled: true, mark: 0x100, tableId: 101,
        )],
      )
      let req = IpcRequest(id: 1, rpcMethod: "interface.status",
                           params: %*{"interface": "wan"})
      let resp = handleInterfaceStatusQuery(snap, req)
      check resp.success
      check resp.data["name"].getStr == "wan"

    test "handleInterfaceStatusQuery unknown interface":
      let snap = makeTestSnap()
      let req = IpcRequest(id: 1, rpcMethod: "interface.status",
                           params: %*{"interface": "nonexistent"})
      let resp = handleInterfaceStatusQuery(snap, req)
      check not resp.success
      check "not found" in resp.error

    test "status reports degraded state with quality metrics":
      let snap = makeTestSnap(
        ifaces = @[InterfaceSnapshot(
          name: "wan", device: "eth0", state: "degraded",
          enabled: true, mark: 0x100, tableId: 101,
          successCount: 7, failCount: 3,
          avgRttMs: 150, lossPercent: 30,
          uptimeSecs: -1,
        )],
        policies = @[PolicySnapshot(
          name: "balanced",
          activeMembers: @["wan"],
          activeTier: 1,
        )],
      )
      let req = IpcRequest(id: 1, rpcMethod: "status")
      let resp = handleStatusQuery(snap, req)
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
      let snap = makeTestSnap(connected = @["127.0.0.0/8", "::1/128"])
      let req = IpcRequest(id: 1, rpcMethod: "connected")
      let resp = handleConnectedQuery(snap, req)
      check resp.success
      check resp.data["networks"].len == 2

    test "handleBypassListQuery returns bypass entries":
      let snap = makeTestSnap(bypassV4 = @["10.0.0.0/8"], bypassV6 = @["fc00::/7"])
      let req = IpcRequest(id: 1, rpcMethod: "bypass.list")
      let resp = handleBypassListQuery(snap, req)
      check resp.success
      check resp.data["v4"].len == 1
      check resp.data["v6"].len == 1
