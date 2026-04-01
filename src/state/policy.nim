## Policy resolution: group members by metric tier, select active members.
##
## Filters to only online/degraded interfaces, groups by metric into tiers,
## sorts tiers by metric (lowest = highest priority). The active tier is
## the first one with at least one online member.

import std/algorithm
import tracker
import ../config/schema

type
  ActiveMember* = object
    `interface`*: string
    mark*: uint32
    weight*: uint32

  Tier* = object
    metric*: uint32
    members*: seq[ActiveMember]

  ResolvedPolicy* = object
    name*: string
    tiers*: seq[Tier]
    lastResort*: LastResort

proc resolvePolicy*(policy: PolicyConfig, members: seq[MemberConfig],
                    trackers: seq[InterfaceTracker]): ResolvedPolicy =
  ## Resolve a policy config against current interface states.
  var active: seq[tuple[metric: uint32, member: ActiveMember]]

  for memberName in policy.members:
    # Find the member config
    var memberCfg: MemberConfig
    var foundMember = false
    for m in members:
      if m.name == memberName:
        memberCfg = m
        foundMember = true
        break
    if not foundMember:
      continue

    # Find the tracker
    var foundTracker = false
    for t in trackers:
      if t.name == memberCfg.`interface`:
        foundTracker = true
        if not t.isActive:
          break
        var am = ActiveMember(mark: t.mark, weight: memberCfg.weight)
        am.`interface` = memberCfg.`interface`
        active.add((memberCfg.metric, am))
        break

  # Sort by metric (lowest first)
  active.sort(proc(a, b: auto): int = cmp(a.metric, b.metric))

  # Group into tiers
  var tiers: seq[Tier]
  for item in active:
    if tiers.len > 0 and tiers[^1].metric == item.metric:
      tiers[^1].members.add(item.member)
    else:
      tiers.add(Tier(metric: item.metric, members: @[item.member]))

  ResolvedPolicy(
    name: policy.name,
    tiers: tiers,
    lastResort: policy.lastResort,
  )

proc activeTier*(rp: ResolvedPolicy): ptr Tier =
  ## Get the active tier (first tier with members, i.e. lowest metric).
  ## Returns nil if no tiers.
  if rp.tiers.len > 0:
    result = unsafeAddr rp.tiers[0]
  else:
    result = nil

proc isEmpty*(rp: ResolvedPolicy): bool =
  rp.tiers.len == 0

proc activeTotalWeight*(rp: ResolvedPolicy): uint32 =
  ## Total weight across the active tier (for nftables numgen).
  if rp.tiers.len > 0:
    for m in rp.tiers[0].members:
      result += m.weight

when isMainModule:
  import std/unittest

  proc makeMember(name, iface: string, metric, weight: uint32): MemberConfig =
    result = MemberConfig(name: name, metric: metric, weight: weight)
    result.`interface` = iface

  proc makeTracker(name: string, index: int, mark: uint32, online: bool): InterfaceTracker =
    var t = newTracker(name, index, mark, 100 + index.uint32,
                       "eth0." & $(index + 2), 3, 5)
    if online:
      t.state = isOnline
    t

  suite "policy resolution":
    test "balanced both online":
      let policy = PolicyConfig(
        name: "balanced",
        members: @["wan_m1_w50", "wanb_m1_w50"],
        lastResort: lrDefault,
      )
      let members = @[
        makeMember("wan_m1_w50", "wan", 1, 50),
        makeMember("wanb_m1_w50", "wanb", 1, 50),
      ]
      let trackers = @[
        makeTracker("wan", 0, 0x0100, true),
        makeTracker("wanb", 1, 0x0200, true),
      ]

      let resolved = resolvePolicy(policy, members, trackers)
      check resolved.tiers.len == 1
      check resolved.tiers[0].members.len == 2
      check resolved.activeTotalWeight == 100

    test "failover primary down":
      let policy = PolicyConfig(
        name: "failover",
        members: @["wan_m1", "wanb_m2"],
        lastResort: lrDefault,
      )
      let members = @[
        makeMember("wan_m1", "wan", 1, 100),
        makeMember("wanb_m2", "wanb", 2, 100),
      ]
      let trackers = @[
        makeTracker("wan", 0, 0x0100, false),   # offline
        makeTracker("wanb", 1, 0x0200, true),   # online
      ]

      let resolved = resolvePolicy(policy, members, trackers)
      check resolved.tiers.len == 1
      let tier = resolved.activeTier
      check tier != nil
      check tier.metric == 2
      check tier.members[0].`interface` == "wanb"

    test "all down":
      let policy = PolicyConfig(
        name: "balanced",
        members: @["wan_m"],
        lastResort: lrUnreachable,
      )
      let members = @[
        makeMember("wan_m", "wan", 1, 50),
      ]
      let trackers = @[
        makeTracker("wan", 0, 0x0100, false),
      ]

      let resolved = resolvePolicy(policy, members, trackers)
      check resolved.isEmpty
      check resolved.lastResort == lrUnreachable
