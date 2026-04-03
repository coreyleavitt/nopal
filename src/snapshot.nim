## Unified daemon state snapshot (pure value types, no pointers).
##
## Replaces the old DaemonView (bag of ptr fields) with a single
## DaemonSnapshot value type for IPC query handlers.
##
## Types only — the builder proc lives in daemon.nim to avoid
## circular imports (daemon imports snapshot, not vice versa).

import std/options

type
  TargetSnapshot* = object
    ip*: string
    up*: bool
    rttMs*: int  ## -1 if unavailable

  InterfaceSnapshot* = object
    name*, device*, state*: string
    enabled*: bool
    mark*, tableId*: uint32
    successCount*, failCount*: uint32
    avgRttMs*: int  ## -1 if unavailable
    lossPercent*: uint32
    uptimeSecs*: int64  ## -1 if not online
    targets*: seq[TargetSnapshot]

  PolicySnapshot* = object
    name*: string
    activeMembers*: seq[string]
    activeTier*: int  ## -1 if empty

  ReloadPendingInfo* = object
    remainingSecs*: int

  BypassSnapshot* = object
    v4*: seq[string]
    v6*: seq[string]

  DaemonSnapshot* = object
    apiVersion*: int
    version*: string
    uptimeSecs*: int64
    interfaces*: seq[InterfaceSnapshot]
    policies*: seq[PolicySnapshot]
    connectedNetworks*: seq[string]
    dynamicBypass*: BypassSnapshot
    reloadPending*: Option[ReloadPendingInfo]

when isMainModule:
  import std/unittest

  suite "snapshot types":
    test "TargetSnapshot construction":
      let t = TargetSnapshot(ip: "8.8.8.8", up: true, rttMs: 25)
      check t.ip == "8.8.8.8"
      check t.up == true
      check t.rttMs == 25

    test "TargetSnapshot unavailable rtt":
      let t = TargetSnapshot(ip: "1.1.1.1", up: false, rttMs: -1)
      check t.rttMs == -1

    test "InterfaceSnapshot construction":
      let iface = InterfaceSnapshot(
        name: "wan", device: "eth0", state: "online",
        enabled: true, mark: 0x100, tableId: 101,
        successCount: 10, failCount: 0,
        avgRttMs: 25, lossPercent: 0, uptimeSecs: 3600,
        targets: @[TargetSnapshot(ip: "8.8.8.8", up: true, rttMs: 25)],
      )
      check iface.name == "wan"
      check iface.targets.len == 1

    test "PolicySnapshot construction":
      let pol = PolicySnapshot(
        name: "balanced",
        activeMembers: @["wan", "lte"],
        activeTier: 1,
      )
      check pol.activeMembers.len == 2
      check pol.activeTier == 1

    test "PolicySnapshot empty":
      let pol = PolicySnapshot(name: "empty", activeTier: -1)
      check pol.activeMembers.len == 0
      check pol.activeTier == -1

    test "DaemonSnapshot construction":
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
          name: "balanced", activeMembers: @["wan"], activeTier: 1,
        )],
        connectedNetworks: @["192.168.1.0/24"],
        dynamicBypass: BypassSnapshot(v4: @["10.0.0.0/8"], v6: @[]),
        reloadPending: none[ReloadPendingInfo](),
      )
      check snap.apiVersion == 1
      check snap.interfaces.len == 1
      check snap.policies.len == 1
      check snap.connectedNetworks.len == 1

    test "DaemonSnapshot with reload pending":
      let snap = DaemonSnapshot(
        apiVersion: 1, version: "0.1.0", uptimeSecs: 60,
        reloadPending: some(ReloadPendingInfo(remainingSecs: 45)),
      )
      check snap.reloadPending.isSome
      check snap.reloadPending.get.remainingSecs == 45
