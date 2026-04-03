## IPC request/response types (JSON over Unix socket).
##
## Wire format: u32 BE length prefix + UTF-8 JSON payload.
## Max message size: 64 KB.

import std/[json, options]

const
  MaxMsgSize* = 65536

type
  IpcRequest* = object
    id*: uint64
    rpcMethod*: string
    params*: JsonNode  ## nullable, may contain "interface" key

  IpcResponse* = object
    id*: uint64
    success*: bool
    error*: string     ## empty on success
    data*: JsonNode    ## method-specific payload, nil if none

  InterfaceStatusData* = object
    name*: string
    device*: string
    state*: string
    enabled*: bool
    mark*: uint32
    tableId*: uint32
    successCount*: uint32
    failCount*: uint32
    avgRttMs*: int       ## -1 if unavailable
    lossPercent*: uint32
    uptimeSecs*: int64   ## -1 if not online
    targets*: JsonNode   ## array of {ip, up, rttMs}

  PolicyStatusData* = object
    name*: string
    activeMembers*: seq[string]
    activeTier*: int     ## -1 if empty

  ReloadPendingInfo* = object
    remainingSecs*: int

  DaemonStatus* = object
    version*: string
    uptimeSecs*: int64
    interfaces*: seq[InterfaceStatusData]
    policies*: seq[PolicyStatusData]
    reloadPending*: Option[ReloadPendingInfo]

  EventData* = object
    event*: string       ## "interface.state_change"
    interfaceName*: string
    state*: string

  ConnectedData* = object
    networks*: seq[string]

proc parseResponse*(j: JsonNode): IpcResponse =
  ## Parse a JSON object into an IpcResponse.
  result.id = j.getOrDefault("id").getBiggestInt().uint64
  result.success = j.getOrDefault("success").getBool()
  result.error = j.getOrDefault("error").getStr()
  result.data = j.getOrDefault("data")

proc parseDaemonStatus*(j: JsonNode): DaemonStatus =
  ## Parse a JSON object into a DaemonStatus.
  result.version = j.getOrDefault("version").getStr()
  result.uptimeSecs = j.getOrDefault("uptime_secs").getBiggestInt()
  for iface in j.getOrDefault("interfaces"):
    result.interfaces.add(InterfaceStatusData(
      name: iface.getOrDefault("name").getStr(),
      device: iface.getOrDefault("device").getStr(),
      state: iface.getOrDefault("state").getStr(),
      enabled: iface.getOrDefault("enabled").getBool(),
      mark: iface.getOrDefault("mark").getInt().uint32,
      tableId: iface.getOrDefault("table_id").getInt().uint32,
      avgRttMs: iface.getOrDefault("avg_rtt_ms").getInt(-1),
      lossPercent: iface.getOrDefault("loss_percent").getInt().uint32,
      uptimeSecs: iface.getOrDefault("uptime_secs").getBiggestInt(),
    ))
  for pol in j.getOrDefault("policies"):
    var members: seq[string]
    for m in pol.getOrDefault("active_members"):
      members.add(m.getStr())
    result.policies.add(PolicyStatusData(
      name: pol.getOrDefault("name").getStr(),
      activeMembers: members,
      activeTier: pol.getOrDefault("active_tier").getInt(-1),
    ))

proc parseRequest*(j: JsonNode): IpcRequest =
  ## Parse a JSON object into an IpcRequest.
  result.id = j.getOrDefault("id").getBiggestInt().uint64
  result.rpcMethod = j.getOrDefault("method").getStr()
  result.params = j.getOrDefault("params")

proc successResponse*(id: uint64, data: JsonNode = nil): IpcResponse =
  IpcResponse(id: id, success: true, data: data)

proc errorResponse*(id: uint64, msg: string): IpcResponse =
  IpcResponse(id: id, success: false, error: msg)

proc toJson*(r: IpcResponse): JsonNode =
  result = %*{"id": r.id, "success": r.success}
  if r.error.len > 0:
    result["error"] = %r.error
  if r.data != nil:
    result["data"] = r.data

proc toJson*(s: InterfaceStatusData): JsonNode =
  result = %*{
    "name": s.name, "device": s.device, "state": s.state,
    "enabled": s.enabled, "mark": s.mark, "table_id": s.tableId,
    "success_count": s.successCount, "fail_count": s.failCount,
    "loss_percent": s.lossPercent,
  }
  if s.avgRttMs >= 0: result["avg_rtt_ms"] = %s.avgRttMs
  if s.uptimeSecs >= 0: result["uptime_secs"] = %s.uptimeSecs
  if s.targets != nil: result["targets"] = s.targets

proc toJson*(p: PolicyStatusData): JsonNode =
  result = %*{"name": p.name, "active_members": p.activeMembers}
  if p.activeTier >= 0: result["active_tier"] = %p.activeTier

proc toJson*(d: DaemonStatus): JsonNode =
  var ifaces = newJArray()
  for i in d.interfaces: ifaces.add(i.toJson())
  var pols = newJArray()
  for p in d.policies: pols.add(p.toJson())
  var j = %*{"version": d.version, "uptime_secs": d.uptimeSecs,
              "interfaces": ifaces, "policies": pols}
  if d.reloadPending.isSome:
    j["reload_pending"] = %*{"remaining_secs": d.reloadPending.get.remainingSecs}
  j

proc toJson*(e: EventData): JsonNode =
  %*{"event": e.event, "interface": e.interfaceName, "state": e.state}

proc toJson*(c: ConnectedData): JsonNode =
  %*{"networks": c.networks}

when isMainModule:
  import std/unittest

  suite "IPC protocol":
    test "parseRequest round-trip":
      let j = %*{"id": 1, "method": "status", "params": nil}
      let req = parseRequest(j)
      check req.id == 1
      check req.rpcMethod == "status"

    test "successResponse serialization":
      let resp = successResponse(42, %*{"foo": "bar"})
      let j = resp.toJson()
      check j["id"].getBiggestInt() == 42
      check j["success"].getBool() == true
      check j["data"]["foo"].getStr() == "bar"
      check not j.hasKey("error")

    test "errorResponse serialization":
      let resp = errorResponse(1, "not found")
      let j = resp.toJson()
      check j["success"].getBool() == false
      check j["error"].getStr() == "not found"

    test "DaemonStatus serialization":
      let status = DaemonStatus(
        version: "0.1.0",
        uptimeSecs: 3600,
        interfaces: @[InterfaceStatusData(
          name: "wan", device: "eth0", state: "online",
          enabled: true, mark: 0x100, tableId: 101,
          successCount: 10, failCount: 0,
          avgRttMs: 25, lossPercent: 0, uptimeSecs: 1800,
          targets: %*[{"ip": "8.8.8.8", "up": true, "rtt_ms": 25}],
        )],
        policies: @[PolicyStatusData(
          name: "balanced", activeMembers: @["wan", "lte"], activeTier: 1,
        )],
      )
      let j = status.toJson()
      check j["version"].getStr() == "0.1.0"
      check j["interfaces"].len == 1
      check j["interfaces"][0]["name"].getStr() == "wan"
      check j["policies"][0]["active_members"].len == 2
