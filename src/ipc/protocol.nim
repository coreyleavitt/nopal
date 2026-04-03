## IPC request/response types (JSON over Unix socket).
##
## Wire format: u32 BE length prefix + UTF-8 JSON payload.
## Max message size: 64 KB.

import std/[json, options]
import ../snapshot
export snapshot

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

  EventData* = object
    event*: string       ## "interface.state_change"
    interfaceName*: string
    state*: string

proc parseResponse*(j: JsonNode): IpcResponse =
  ## Parse a JSON object into an IpcResponse.
  result.id = j.getOrDefault("id").getBiggestInt().uint64
  result.success = j.getOrDefault("success").getBool()
  result.error = j.getOrDefault("error").getStr()
  result.data = j.getOrDefault("data")

proc parseDaemonStatus*(j: JsonNode): DaemonSnapshot =
  ## Parse a JSON object into a DaemonSnapshot.
  result.apiVersion = j.getOrDefault("api_version").getInt(0)
  result.version = j.getOrDefault("version").getStr()
  result.uptimeSecs = j.getOrDefault("uptime_secs").getBiggestInt()
  for iface in j.getOrDefault("interfaces"):
    var targets: seq[TargetSnapshot]
    let targetsNode = iface.getOrDefault("targets")
    if targetsNode != nil and targetsNode.kind == JArray:
      for t in targetsNode:
        targets.add(TargetSnapshot(
          ip: t.getOrDefault("ip").getStr(),
          up: t.getOrDefault("up").getBool(),
          rttMs: t.getOrDefault("rtt_ms").getInt(-1),
        ))
    result.interfaces.add(InterfaceSnapshot(
      name: iface.getOrDefault("name").getStr(),
      device: iface.getOrDefault("device").getStr(),
      state: iface.getOrDefault("state").getStr(),
      enabled: iface.getOrDefault("enabled").getBool(),
      mark: iface.getOrDefault("mark").getInt().uint32,
      tableId: iface.getOrDefault("table_id").getInt().uint32,
      successCount: iface.getOrDefault("success_count").getInt().uint32,
      failCount: iface.getOrDefault("fail_count").getInt().uint32,
      avgRttMs: iface.getOrDefault("avg_rtt_ms").getInt(-1),
      lossPercent: iface.getOrDefault("loss_percent").getInt().uint32,
      uptimeSecs: iface.getOrDefault("uptime_secs").getBiggestInt(),
      targets: targets,
    ))
  for pol in j.getOrDefault("policies"):
    var members: seq[string]
    for m in pol.getOrDefault("active_members"):
      members.add(m.getStr())
    result.policies.add(PolicySnapshot(
      name: pol.getOrDefault("name").getStr(),
      activeMembers: members,
      activeTier: pol.getOrDefault("active_tier").getInt(-1),
    ))
  let reloadNode = j.getOrDefault("reload_pending")
  if reloadNode != nil and reloadNode.kind == JObject:
    result.reloadPending = some(ReloadPendingInfo(
      remainingSecs: reloadNode.getOrDefault("remaining_secs").getInt(0),
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

proc toJson*(t: TargetSnapshot): JsonNode =
  result = %*{"ip": t.ip, "up": t.up}
  if t.rttMs >= 0: result["rtt_ms"] = %t.rttMs

proc toJson*(s: InterfaceSnapshot): JsonNode =
  result = %*{
    "name": s.name, "device": s.device, "state": s.state,
    "enabled": s.enabled, "mark": s.mark, "table_id": s.tableId,
    "success_count": s.successCount, "fail_count": s.failCount,
    "loss_percent": s.lossPercent,
  }
  if s.avgRttMs >= 0: result["avg_rtt_ms"] = %s.avgRttMs
  if s.uptimeSecs >= 0: result["uptime_secs"] = %s.uptimeSecs
  if s.targets.len > 0:
    var arr = newJArray()
    for t in s.targets: arr.add(t.toJson())
    result["targets"] = arr

proc toJson*(p: PolicySnapshot): JsonNode =
  result = %*{"name": p.name, "active_members": p.activeMembers}
  if p.activeTier >= 0: result["active_tier"] = %p.activeTier

proc toJson*(b: BypassSnapshot): JsonNode =
  %*{"v4": b.v4, "v6": b.v6}

proc toJson*(d: DaemonSnapshot): JsonNode =
  var ifaces = newJArray()
  for i in d.interfaces: ifaces.add(i.toJson())
  var pols = newJArray()
  for p in d.policies: pols.add(p.toJson())
  var j = %*{"api_version": d.apiVersion, "version": d.version,
              "uptime_secs": d.uptimeSecs,
              "interfaces": ifaces, "policies": pols,
              "connected_networks": d.connectedNetworks,
              "dynamic_bypass": d.dynamicBypass.toJson()}
  if d.reloadPending.isSome:
    j["reload_pending"] = %*{"remaining_secs": d.reloadPending.get.remainingSecs}
  j

proc toJson*(e: EventData): JsonNode =
  %*{"event": e.event, "interface": e.interfaceName, "state": e.state}

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

    test "DaemonSnapshot serialization":
      let snap = DaemonSnapshot(
        apiVersion: 1,
        version: "0.1.0",
        uptimeSecs: 3600,
        interfaces: @[InterfaceSnapshot(
          name: "wan", device: "eth0", state: "online",
          enabled: true, mark: 0x100, tableId: 101,
          successCount: 10, failCount: 0,
          avgRttMs: 25, lossPercent: 0, uptimeSecs: 1800,
          targets: @[TargetSnapshot(ip: "8.8.8.8", up: true, rttMs: 25)],
        )],
        policies: @[PolicySnapshot(
          name: "balanced", activeMembers: @["wan", "lte"], activeTier: 1,
        )],
        connectedNetworks: @["192.168.1.0/24"],
        dynamicBypass: BypassSnapshot(v4: @[], v6: @[]),
      )
      let j = snap.toJson()
      check j["api_version"].getInt() == 1
      check j["version"].getStr() == "0.1.0"
      check j["interfaces"].len == 1
      check j["interfaces"][0]["name"].getStr() == "wan"
      check j["interfaces"][0]["targets"].len == 1
      check j["interfaces"][0]["targets"][0]["ip"].getStr() == "8.8.8.8"
      check j["interfaces"][0]["targets"][0]["rtt_ms"].getInt() == 25
      check j["policies"][0]["active_members"].len == 2
      check j["connected_networks"].len == 1

    test "DaemonSnapshot parseDaemonStatus round-trip":
      let snap = DaemonSnapshot(
        apiVersion: 1,
        version: "0.2.0",
        uptimeSecs: 120,
        interfaces: @[InterfaceSnapshot(
          name: "lte", device: "wwan0", state: "degraded",
          enabled: true, mark: 0x200, tableId: 102,
          successCount: 5, failCount: 2,
          avgRttMs: 80, lossPercent: 20, uptimeSecs: 60,
          targets: @[TargetSnapshot(ip: "1.1.1.1", up: true, rttMs: 80)],
        )],
        policies: @[PolicySnapshot(name: "main", activeMembers: @["lte"], activeTier: 2)],
        reloadPending: some(ReloadPendingInfo(remainingSecs: 30)),
      )
      let j = snap.toJson()
      let parsed = parseDaemonStatus(j)
      check parsed.version == "0.2.0"
      check parsed.interfaces.len == 1
      check parsed.interfaces[0].name == "lte"
      check parsed.interfaces[0].targets.len == 1
      check parsed.reloadPending.isSome
      check parsed.reloadPending.get.remainingSecs == 30
