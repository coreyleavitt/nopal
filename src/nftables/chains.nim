## nftables chain builder -- generates the complete inet nopal ruleset.
##
## Ported from the Rust implementation in chains.rs. Builds all base chains,
## regular chains, expression helpers, and rule generation for policy routing.

import std/[json, strutils, strformat, options, sequtils]
import ./ruleset
import ../config/schema

# ---------------------------------------------------------------------------
# Local input types (decoupled from config schema)
# ---------------------------------------------------------------------------

type
  LastResort* = enum
    Default
    Unreachable
    Blackhole

  InterfaceInfo* = object
    name*, device*: string
    mark*, tableId*: uint32
    clampMss*: bool

  PolicyMember* = object
    interfaceName*: string
    mark*, weight*, metric*: uint32

  PolicyInfo* = object
    name*: string
    members*: seq[PolicyMember]
    lastResort*: LastResort

  StickyInfo* = object
    mode*: StickyMode
    timeout*: uint32

  RuleInfo* = object
    srcIp*, destIp*: seq[string]
    srcPort*, destPort*: string
    proto*: Protocol
    family*: RuleFamily
    srcIface*, ipset*: string
    policy*: string
    sticky*: Option[StickyInfo]
    log*: bool

# ---------------------------------------------------------------------------
# Pure decision types (no JSON dependency)
# ---------------------------------------------------------------------------

type
  PortValue* {.requiresInit.} = object
    ## Pure port representation for decision logic.
    ## JSON translation handled separately.
    case isRange*: bool
    of true:
      rangeStart*, rangeEnd*: uint16
    of false:
      port*: uint16

  ProtoFamilyPair* = tuple[proto: Protocol, familyOverride: Option[RuleFamily]]
  WeightSlot* = tuple[slot: uint32, interfaceName: string]
  StickyKeySpec* = tuple[suffix, keyType: string]
  Tier* = tuple[metric: uint32, members: seq[PolicyMember]]

# ---------------------------------------------------------------------------
# Pure decision functions (func + {.raises: [].})
# ---------------------------------------------------------------------------

func ipProtocol*(address: string): string {.raises: [].} =
  ## Determine nftables protocol from address format.
  if ':' in address: "ip6" else: "ip"

func ipProtocolFor*(address: string, ruleFamily: RuleFamily): string {.raises: [].} =
  ## Determine protocol considering named sets and rule family.
  if address.len > 0 and address[0] == '@':
    if ruleFamily == rfIpv6: "ip6" else: "ip"
  else:
    ipProtocol(address)

func parsePortValue*(port: string): PortValue {.raises: [].} =
  ## Parse a port string into a pure PortValue. Handles single ports and ranges.
  let dashIdx = port.find('-')
  if dashIdx >= 0:
    let loPart = port[0 ..< dashIdx]
    let hiPart = port[dashIdx + 1 .. ^1]
    try:
      let lo = parseInt(loPart)
      let hi = parseInt(hiPart)
      return PortValue(isRange: true, rangeStart: uint16(lo), rangeEnd: uint16(hi))
    except ValueError:
      discard
  try:
    let n = parseInt(port)
    return PortValue(isRange: false, port: uint16(n))
  except ValueError:
    discard
  # Fallback: treat as port 0
  PortValue(isRange: false, port: 0)

func expandProtoFamily*(proto: Protocol, family: RuleFamily, hasPorts: bool): seq[ProtoFamilyPair] {.raises: [].} =
  ## Expand proto+family into concrete (proto, familyOverride) pairs.
  ## E.g., icmp+any → [(icmp, ipv4), (icmpv6, ipv6)]
  if proto.isIcmp:
    case family
    of rfIpv4: @[(namedProto(npIcmp), none[RuleFamily]())]
    of rfIpv6: @[(namedProto(npIcmpv6), none[RuleFamily]())]
    of rfAny: @[(namedProto(npIcmp), some(rfIpv4)), (namedProto(npIcmpv6), some(rfIpv6))]
  elif proto.isAll and hasPorts:
    @[(namedProto(npTcp), none[RuleFamily]()), (namedProto(npUdp), none[RuleFamily]())]
  else:
    @[(proto, none[RuleFamily]())]

func computeWeightSlots*(members: openArray[PolicyMember]): seq[WeightSlot] {.raises: [].} =
  ## Map member weights to numbered slots for numgen vmap.
  ## E.g., weights [30, 50, 20] → 100 slots: 0-29→wan, 30-79→lte, 80-99→wifi
  var slot: uint32 = 0
  for member in members:
    for _ in 0 ..< member.weight:
      result.add((slot: slot, interfaceName: member.interfaceName))
      slot += 1

func determineStickyKeys*(mode: StickyMode, family: RuleFamily): seq[StickyKeySpec] {.raises: [].} =
  ## Determine map suffixes and key types for sticky sessions.
  ## Returns one entry per address family to create maps for.
  let isSrcDst = mode == smSrcDst
  case family
  of rfIpv4:
    if isSrcDst: @[("_v4", "ipv4_addr . ipv4_addr")]
    else: @[("_v4", "ipv4_addr")]
  of rfIpv6:
    if isSrcDst: @[("_v6", "ipv6_addr . ipv6_addr")]
    else: @[("_v6", "ipv6_addr")]
  of rfAny:
    if isSrcDst: @[("_v4", "ipv4_addr . ipv4_addr"), ("_v6", "ipv6_addr . ipv6_addr")]
    else: @[("_v4", "ipv4_addr"), ("_v6", "ipv6_addr")]

func groupByMetric*(members: openArray[PolicyMember]): seq[Tier] {.raises: [].} =
  ## Group policy members by metric value, sorted ascending.
  ## Lower metric = higher priority. Members at the same metric are load-balanced.
  for member in members:
    var found = false
    for i in 0 ..< result.len:
      if result[i].metric == member.metric:
        result[i].members.add(member)
        found = true
        break
    if not found:
      result.add((metric: member.metric, members: @[member]))
  # Manual insertion sort (small N, avoids sort's potential raises)
  for i in 1 ..< result.len:
    var j = i
    while j > 0 and result[j].metric < result[j - 1].metric:
      swap(result[j], result[j - 1])
      dec j

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

const
  ProbeMark = 0xDEAD'u32

# ---------------------------------------------------------------------------
# nftables JSON expression helpers
# ---------------------------------------------------------------------------

proc matchMetaMarkEq(value: uint32): JsonNode =
  %*{"match": {"op": "==", "left": {"meta": {"key": "mark"}}, "right": value}}

proc matchMetaMarkMaskedEq(mask, value: uint32): JsonNode =
  %*{"match": {"op": "==", "left": {"&": [{"meta": {"key": "mark"}}, mask]}, "right": value}}

proc matchMetaMarkMaskedNeq(mask, value: uint32): JsonNode =
  %*{"match": {"op": "!=", "left": {"&": [{"meta": {"key": "mark"}}, mask]}, "right": value}}

proc matchCtMarkMaskedNeq(mask, value: uint32): JsonNode =
  %*{"match": {"op": "!=", "left": {"&": [{"ct": {"key": "mark"}}, mask]}, "right": value}}

proc matchCtStateNew(): JsonNode =
  %*{"match": {"op": "==", "left": {"ct": {"key": "state"}}, "right": "new"}}

proc matchIifname(device: string): JsonNode =
  %*{"match": {"op": "==", "left": {"meta": {"key": "iifname"}}, "right": device}}

proc matchOifname(device: string): JsonNode =
  %*{"match": {"op": "==", "left": {"meta": {"key": "oifname"}}, "right": device}}

proc matchNfprotoIpv4(): JsonNode =
  %*{"match": {"op": "==", "left": {"meta": {"key": "nfproto"}}, "right": "ipv4"}}

proc matchNfprotoIpv6(): JsonNode =
  %*{"match": {"op": "==", "left": {"meta": {"key": "nfproto"}}, "right": "ipv6"}}

proc matchIcmpv6TypeRange(lo, hi: int): JsonNode =
  %*{"match": {"op": "==", "left": {"payload": {"protocol": "icmpv6", "field": "type"}}, "right": {"range": [lo, hi]}}}

proc matchProtocol(proto: string): JsonNode =
  %*{"match": {"op": "==", "left": {"meta": {"key": "l4proto"}}, "right": proto}}

proc matchTcpSyn(): JsonNode =
  %*{"match": {"op": "==", "left": {"payload": {"protocol": "tcp", "field": "flags"}}, "right": {"&": ["syn", {"|": ["syn", "rst"]}]}}}

proc clampMssTopmtu(): JsonNode =
  %*{"mangle": {"key": {"tcp option": {"name": "maxseg", "field": "size"}}, "value": {"rt": {"key": "mtu"}}}}

proc setMetaMark(value: uint32): JsonNode =
  %*{"mangle": {"key": {"meta": {"key": "mark"}}, "value": value}}

proc setCtMark(value: uint32): JsonNode =
  %*{"mangle": {"key": {"ct": {"key": "mark"}}, "value": value}}

proc saveMarkToCt(): JsonNode =
  %*{"mangle": {"key": {"ct": {"key": "mark"}}, "value": {"meta": {"key": "mark"}}}}

proc setMarkFromCt(mask: uint32): JsonNode =
  %*{"mangle": {"key": {"meta": {"key": "mark"}}, "value": {"&": [{"ct": {"key": "mark"}}, mask]}}}

proc dropPacket(): JsonNode =
  %*{"drop": nil}

proc rejectUnreachable(): JsonNode =
  %*{"reject": {"type": "icmpx", "expr": "host-unreachable"}}

proc logPrefix(prefix: string): JsonNode =
  %*{"log": {"prefix": prefix}}

proc nftAccept(): JsonNode =
  %*{"accept": nil}

proc jump(target: string): JsonNode =
  %*{"jump": {"target": target}}

proc goto(target: string): JsonNode =
  %*{"goto": {"target": target}}

# ---------------------------------------------------------------------------
# IP/port helpers
# ---------------------------------------------------------------------------

## ipProtocol and ipProtocolFor are now pure funcs defined above.

proc ipRightValue(address: string): JsonNode =
  if address.startsWith('@'):
    %*{"@": address[1 .. ^1]}
  else:
    %*address

proc prefixValue(cidr: string): JsonNode =
  let slashIdx = cidr.find('/')
  if slashIdx >= 0:
    let addrPart = cidr[0 ..< slashIdx]
    let lenPart = cidr[slashIdx + 1 .. ^1]
    try:
      let prefLen = parseInt(lenPart)
      return %*{"prefix": {"addr": addrPart, "len": prefLen}}
    except ValueError:
      discard
  return %*cidr

proc matchIpList(addrs: seq[string], field: string, ruleFamily: RuleFamily): JsonNode =
  assert addrs.len > 0, "matchIpList called with empty address list"
  let proto = ipProtocolFor(addrs[0], ruleFamily)
  let right =
    if addrs.len == 1:
      ipRightValue(addrs[0])
    else:
      %*{"set": addrs.mapIt(ipRightValue(it))}
  %*{"match": {"op": "==", "left": {"payload": {"protocol": proto, "field": field}}, "right": right}}

proc matchDaddrSet(protocol: string, s: seq[JsonNode]): JsonNode =
  %*{"match": {"op": "==", "left": {"payload": {"protocol": protocol, "field": "daddr"}}, "right": {"set": s}}}

proc matchDaddrNamedSet(setName: string, family: RuleFamily): JsonNode =
  let protocol = if family == rfIpv6: "ip6" else: "ip"
  %*{"match": {"op": "==", "left": {"payload": {"protocol": protocol, "field": "daddr"}}, "right": "@" & setName}}

proc portToJson(pv: PortValue): JsonNode =
  if pv.isRange:
    %*{"range": [int(pv.rangeStart), int(pv.rangeEnd)]}
  else:
    %*int(pv.port)

proc parsePort(port: string): JsonNode =
  portToJson(parsePortValue(port))

proc matchSrcPort(port, proto: string): JsonNode =
  %*{"match": {"op": "==", "left": {"payload": {"protocol": proto, "field": "sport"}}, "right": parsePort(port)}}

proc matchDstPort(port, proto: string): JsonNode =
  %*{"match": {"op": "==", "left": {"payload": {"protocol": proto, "field": "dport"}}, "right": parsePort(port)}}

# ---------------------------------------------------------------------------
# Sticky map helpers
# ---------------------------------------------------------------------------

proc stickyKeyExpr(proto: string, mode: StickyMode): JsonNode =
  let saddr = %*{"payload": {"protocol": proto, "field": "saddr"}}
  if mode == smSrcDst:
    let daddr = %*{"payload": {"protocol": proto, "field": "daddr"}}
    %*{"concat": [saddr, daddr]}
  else:
    saddr

proc setMarkFromMap(key: JsonNode, mapName: string): JsonNode =
  %*{"mangle": {"key": {"meta": {"key": "mark"}}, "value": {"map": {"key": key, "data": {"@": mapName}}}}}

proc updateMap(key: JsonNode, mapName: string): JsonNode =
  %*{"map": {"op": "update", "elem": key, "data": {"meta": {"key": "mark"}}, "map": {"@": mapName}}}

## groupByMetric is now a pure func defined above.

# ---------------------------------------------------------------------------
# Chain builders
# ---------------------------------------------------------------------------

proc addConnectedBypass(rs: var Ruleset, chain: string, connected: openArray[string]) =
  var v4, v6: seq[string]
  for cidr in connected:
    if ':' in cidr:
      v6.add(cidr)
    else:
      v4.add(cidr)

  if v4.len > 0:
    let s = v4.mapIt(prefixValue(it))
    rs.addRule(chain, @[matchDaddrSet("ip", s), nftAccept()])

  if v6.len > 0:
    let s = v6.mapIt(prefixValue(it))
    rs.addRule(chain, @[matchDaddrSet("ip6", s), nftAccept()])

  # Dynamic bypass: user-populated named sets
  rs.addRule(chain, @[matchDaddrNamedSet("bypass_v4", rfIpv4), nftAccept()])
  rs.addRule(chain, @[matchDaddrNamedSet("bypass_v6", rfIpv6), nftAccept()])

proc buildPrerouting(rs: var Ruleset, interfaces: openArray[InterfaceInfo],
                     connected: openArray[string], markMask: uint32) =
  ## Prerouting is where ALL policy decisions happen for forwarded traffic.
  ## Marks must be set BEFORE the routing decision — the kernel reads the
  ## packet mark to select the routing table via fwmark ip rules. If marks
  ## are set after routing (e.g., in the forward chain), the first packet
  ## of every connection uses the main table regardless of policy.

  # 1. Probe bypass: nopal's own health probes must not be policy-routed
  rs.addRule("prerouting", @[matchMetaMarkEq(ProbeMark), nftAccept()])

  # 2. ICMPv6 NDP/RA bypass (types 133-137): essential for IPv6 operation
  rs.addRule("prerouting", @[matchNfprotoIpv6(), matchProtocol("icmpv6"),
    matchIcmpv6TypeRange(133, 137), nftAccept()])

  # 3. Connected/local network bypass: MUST come before ct mark restore.
  #    Return traffic (internet → LAN client) has a ct mark from the
  #    outbound connection. If we restore that mark first, the packet gets
  #    routed through the per-interface table (which only has a default route)
  #    and goes back out the WAN instead of to the LAN client. Bypassing
  #    local destinations first ensures they route via the main table's
  #    connected routes.
  addConnectedBypass(rs, "prerouting", connected)

  # 4. Restore conntrack mark → packet mark for existing connections.
  #    At this point we know the destination is NOT local, so restoring
  #    the WAN mark is safe — the packet should go out the assigned WAN.
  rs.addRule("prerouting", @[matchCtMarkMaskedNeq(markMask, 0), setMarkFromCt(markMask)])
  rs.addRule("prerouting", @[matchMetaMarkMaskedNeq(markMask, 0), nftAccept()])

  # 5. Policy dispatch: new connections to non-local destinations
  rs.addRule("prerouting", @[jump("policy_rules")])

  # 6. Mark inbound new connections per interface (for return-path routing)
  for iface in interfaces:
    rs.addRule("prerouting", @[matchIifname(iface.device), matchCtStateNew(), setCtMark(iface.mark)])

proc buildOutput(rs: var Ruleset, connected: openArray[string], markMask: uint32) =
  ## Output chain handles locally-generated traffic (DNS, NTP, SSH, etc.).
  ## Unlike forwarded traffic, the output hook triggers re-routing when
  ## the packet mark changes, so setting marks here works correctly.
  addConnectedBypass(rs, "output", connected)
  rs.addRule("output", @[matchCtMarkMaskedNeq(markMask, 0), setMarkFromCt(markMask)])
  rs.addRule("output", @[matchMetaMarkMaskedNeq(markMask, 0), nftAccept()])
  rs.addRule("output", @[jump("policy_rules")])

proc buildPostrouting(rs: var Ruleset, interfaces: openArray[InterfaceInfo]) =
  for iface in interfaces:
    if iface.clampMss:
      rs.addRule("postrouting", @[matchOifname(iface.device), matchTcpSyn(), clampMssTopmtu()])

proc buildPolicyRules(rs: var Ruleset, rules: openArray[RuleInfo]) =
  for i, rule in rules:
    let hasPorts = rule.srcPort.len > 0 or rule.destPort.len > 0
    let isIcmp = rule.proto.isIcmp
    let pairs = expandProtoFamily(rule.proto, rule.family, hasPorts)

    for pair in pairs:
      let (proto, familyOverride) = pair
      var expr: seq[JsonNode] = @[]

      # Address family filter
      let family = if familyOverride.isSome: familyOverride.get else: rule.family
      case family
      of rfIpv4: expr.add(matchNfprotoIpv4())
      of rfIpv6: expr.add(matchNfprotoIpv6())
      of rfAny: discard  # no family filter

      # Inbound interface match
      if rule.srcIface.len > 0:
        expr.add(matchIifname(rule.srcIface))

      # Protocol match
      if not proto.isAll:
        expr.add(matchProtocol($proto))

      # Source IP(s)
      if rule.srcIp.len > 0:
        expr.add(matchIpList(rule.srcIp, "saddr", rule.family))

      # Destination IP(s)
      if rule.destIp.len > 0:
        expr.add(matchIpList(rule.destIp, "daddr", rule.family))

      # User-defined named set match (destination)
      if rule.ipset.len > 0:
        expr.add(matchDaddrNamedSet(rule.ipset, rule.family))

      # Source port (skip for ICMP)
      if not isIcmp and rule.srcPort.len > 0:
        expr.add(matchSrcPort(rule.srcPort, $proto))

      # Destination port (skip for ICMP)
      if not isIcmp and rule.destPort.len > 0:
        expr.add(matchDstPort(rule.destPort, $proto))

      # Log matching packets if enabled
      if rule.log:
        expr.add(logPrefix(fmt"nopal:{rule.policy} "))

      # "default" policy = accept (bypass policy routing)
      if rule.policy == "default":
        expr.add(nftAccept())
      else:
        let needsStickyChain = rule.sticky.isSome and rule.sticky.get.mode != smFlow
        if needsStickyChain:
          expr.add(jump(fmt"sticky_r{i}"))
        else:
          expr.add(jump(fmt"policy_{rule.policy}"))

      rs.addRule("policy_rules", expr)

proc buildPolicyChain(rs: var Ruleset, policy: PolicyInfo) =
  let chainName = fmt"policy_{policy.name}"

  if policy.members.len == 0:
    case policy.lastResort
    of Unreachable:
      rs.addRule(chainName, @[rejectUnreachable()])
    of Blackhole:
      rs.addRule(chainName, @[dropPacket()])
    of Default:
      discard  # fall through
    return

  let tiers = groupByMetric(policy.members)

  for tier in tiers:
    let members = tier.members
    if members.len == 1:
      rs.addRule(chainName, @[goto(fmt"mark_{members[0].interfaceName}")])
    else:
      # Weighted round-robin via numgen vmap
      let slots = computeWeightSlots(members)
      let total = uint32(slots.len)
      var vmapEntries = newJArray()
      for ws in slots:
        vmapEntries.add(%*[ws.slot, {"goto": {"target": "mark_" & ws.interfaceName}}])
      rs.addRule(chainName, @[
        %*{"vmap": {"key": {"numgen": {"mode": "inc", "mod": total, "offset": 0}}, "data": {"set": vmapEntries}}}
      ])

proc buildMarkChain(rs: var Ruleset, iface: InterfaceInfo) =
  let chainName = fmt"mark_{iface.name}"
  rs.addRule(chainName, @[setMetaMark(iface.mark), saveMarkToCt(), nftAccept()])

proc buildStickyMapAndChain(rs: var Ruleset, ruleIndex: int, rule: RuleInfo,
                             sticky: StickyInfo, markMask: uint32, policy: PolicyInfo) =
  let families =
    case rule.family
    of rfIpv4: @[rfIpv4]
    of rfIpv6: @[rfIpv6]
    of rfAny: @[rfIpv4, rfIpv6]

  # Create map(s) for this rule
  for fam in families:
    let suffix =
      if families.len > 1:
        if fam == rfIpv4: "_v4" else: "_v6"
      else:
        ""
    let mapName = fmt"sticky_r{ruleIndex}{suffix}"
    let addrType = if fam == rfIpv4: "ipv4_addr" else: "ipv6_addr"
    let keyType =
      if sticky.mode == smSrcDst:
        %*[addrType, addrType]
      else:
        %*addrType
    rs.addMap(mapName, keyType, "mark", sticky.timeout)

  # Create the sticky helper chain
  let chainName = fmt"sticky_r{ruleIndex}"
  rs.addRegularChain(chainName)

  # Phase 1: Map lookup
  for fam in families:
    let suffix =
      if families.len > 1:
        if fam == rfIpv4: "_v4" else: "_v6"
      else:
        ""
    let mapName = fmt"sticky_r{ruleIndex}{suffix}"
    let proto = if fam == rfIpv4: "ip" else: "ip6"
    let lookupKey = stickyKeyExpr(proto, sticky.mode)

    var lookupExpr: seq[JsonNode] = @[]
    if families.len > 1:
      if fam == rfIpv4:
        lookupExpr.add(matchNfprotoIpv4())
      else:
        lookupExpr.add(matchNfprotoIpv6())
    lookupExpr.add(setMarkFromMap(lookupKey, mapName))
    lookupExpr.add(saveMarkToCt())
    lookupExpr.add(nftAccept())
    rs.addRule(chainName, lookupExpr)

  # Phase 2: Inline policy dispatch
  if policy.members.len == 0:
    case policy.lastResort
    of Unreachable:
      rs.addRule(chainName, @[rejectUnreachable()])
    of Blackhole:
      rs.addRule(chainName, @[dropPacket()])
    of Default:
      discard
    return

  let tiers = groupByMetric(policy.members)
  let firstTier = tiers[0].members

  if firstTier.len == 1:
    rs.addRule(chainName, @[setMetaMark(firstTier[0].mark), saveMarkToCt()])
  else:
    var total: uint32 = 0
    for m in firstTier:
      total += m.weight
    var mapEntries = newJArray()
    var slot: uint32 = 0
    for member in firstTier:
      for _ in 0 ..< member.weight:
        mapEntries.add(%*[slot, member.mark])
        slot += 1
    rs.addRule(chainName, @[
      %*{"mangle": {"key": {"meta": {"key": "mark"}}, "value": {"map": {"key": {"numgen": {"mode": "inc", "mod": total, "offset": 0}}, "data": {"set": mapEntries}}}}},
      saveMarkToCt()
    ])

  # Phase 3: Update sticky map with assigned mark
  for fam in families:
    let suffix =
      if families.len > 1:
        if fam == rfIpv4: "_v4" else: "_v6"
      else:
        ""
    let mapName = fmt"sticky_r{ruleIndex}{suffix}"
    let proto = if fam == rfIpv4: "ip" else: "ip6"
    let updateKey = stickyKeyExpr(proto, sticky.mode)

    var updateExpr: seq[JsonNode] = @[]
    if families.len > 1:
      if fam == rfIpv4:
        updateExpr.add(matchNfprotoIpv4())
      else:
        updateExpr.add(matchNfprotoIpv6())
    updateExpr.add(matchMetaMarkMaskedNeq(markMask, 0))
    updateExpr.add(updateMap(updateKey, mapName))
    updateExpr.add(nftAccept())
    rs.addRule(chainName, updateExpr)

# ---------------------------------------------------------------------------
# Public entry point
# ---------------------------------------------------------------------------

proc buildRuleset*(interfaces: openArray[InterfaceInfo], policies: openArray[PolicyInfo],
                   rules: openArray[RuleInfo], connected: openArray[string],
                   markMask: uint32, ipv6Enabled, logging: bool,
                   dynamicBypassV4: openArray[string] = [],
                   dynamicBypassV6: openArray[string] = []): Ruleset =
  # TODO: ipv6Enabled gates IPv6 chain generation; logging gates per-rule log stmts
  var rs = initRuleset()

  # Table setup: add (idempotent create) then flush (clear old rules)
  rs.addTable()
  rs.addFlushTable()

  # Dynamic bypass sets (created empty, populated below if entries exist)
  rs.addSet("bypass_v4", "ipv4_addr", @["interval"])
  rs.addSet("bypass_v6", "ipv6_addr", @["interval"])

  # Populate dynamic bypass sets with runtime entries (survive regen)
  if dynamicBypassV4.len > 0:
    rs.addSetElements("bypass_v4", dynamicBypassV4)
  if dynamicBypassV6.len > 0:
    rs.addSetElements("bypass_v6", dynamicBypassV6)

  # Base chains (no forward — policy decisions are in prerouting)
  rs.addBaseChain("prerouting", "filter", "prerouting", -150, "accept")
  rs.addBaseChain("output", "filter", "output", -150, "accept")
  rs.addBaseChain("postrouting", "filter", "postrouting", 150, "accept")

  # Regular chains
  rs.addRegularChain("policy_rules")
  for iface in interfaces:
    rs.addRegularChain(fmt"mark_{iface.name}")
  for policy in policies:
    rs.addRegularChain(fmt"policy_{policy.name}")

  # Prerouting rules (all policy decisions for forwarded traffic)
  buildPrerouting(rs, interfaces, connected, markMask)

  # Output rules (locally-generated traffic)
  buildOutput(rs, connected, markMask)

  # Postrouting rules
  buildPostrouting(rs, interfaces)

  # Sticky maps and chains
  for i, rule in rules:
    if rule.sticky.isSome:
      let sticky = rule.sticky.get
      if sticky.mode != smFlow:
        for policy in policies:
          if policy.name == rule.policy:
            buildStickyMapAndChain(rs, i, rule, sticky, markMask, policy)
            break

  # Policy rules chain
  buildPolicyRules(rs, rules)

  # Per-policy chains
  for policy in policies:
    buildPolicyChain(rs, policy)

  # Per-interface mark chains
  for iface in interfaces:
    buildMarkChain(rs, iface)

  rs

# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------

when isMainModule:
  import std/unittest

  # Helper to construct seq[RuleInfo] without triggering {.requiresInit.} errors
  # from Protocol. Nim's @[...] uses setLen which needs a default value.
  proc ruleSeq(rules: varargs[RuleInfo]): seq[RuleInfo] =
    {.cast(uncheckedAssign).}:
      result = newSeqOfCap[RuleInfo](rules.len)
      for r in rules: result.add(r)

  suite "pure decision functions":
    test "computeWeightSlots equal weights":
      let members = @[
        PolicyMember(interfaceName: "wan", mark: 0, weight: 1, metric: 0),
        PolicyMember(interfaceName: "lte", mark: 0, weight: 1, metric: 0),
      ]
      let slots = computeWeightSlots(members)
      check slots.len == 2
      check slots[0] == (slot: 0'u32, interfaceName: "wan")
      check slots[1] == (slot: 1'u32, interfaceName: "lte")

    test "computeWeightSlots unequal weights":
      let members = @[
        PolicyMember(interfaceName: "wan", mark: 0, weight: 3, metric: 0),
        PolicyMember(interfaceName: "lte", mark: 0, weight: 2, metric: 0),
      ]
      let slots = computeWeightSlots(members)
      check slots.len == 5
      check slots[0].interfaceName == "wan"
      check slots[2].interfaceName == "wan"
      check slots[3].interfaceName == "lte"
      check slots[4].interfaceName == "lte"

    test "computeWeightSlots single member":
      let members = @[PolicyMember(interfaceName: "wan", mark: 0, weight: 50, metric: 0)]
      let slots = computeWeightSlots(members)
      check slots.len == 50
      for s in slots:
        check s.interfaceName == "wan"

    test "expandProtoFamily icmp any":
      let pairs = expandProtoFamily(namedProto(npIcmp), rfAny, false)
      check pairs.len == 2
      check $pairs[0].proto == "icmp"
      check pairs[0].familyOverride == some(rfIpv4)
      check $pairs[1].proto == "icmpv6"
      check pairs[1].familyOverride == some(rfIpv6)

    test "expandProtoFamily icmp ipv4":
      let pairs = expandProtoFamily(namedProto(npIcmp), rfIpv4, false)
      check pairs.len == 1
      check $pairs[0].proto == "icmp"

    test "expandProtoFamily all with ports":
      let pairs = expandProtoFamily(namedProto(npAll), rfAny, true)
      check pairs.len == 2
      check $pairs[0].proto == "tcp"
      check $pairs[1].proto == "udp"

    test "expandProtoFamily all without ports":
      let pairs = expandProtoFamily(namedProto(npAll), rfAny, false)
      check pairs.len == 1
      check $pairs[0].proto == "all"

    test "expandProtoFamily tcp":
      let pairs = expandProtoFamily(namedProto(npTcp), rfIpv4, true)
      check pairs.len == 1
      check $pairs[0].proto == "tcp"
      check pairs[0].familyOverride == none(RuleFamily)

    test "parsePortValue single port":
      let pv = parsePortValue("80")
      check not pv.isRange
      check pv.port == 80

    test "parsePortValue range":
      let pv = parsePortValue("1024-65535")
      check pv.isRange
      check pv.rangeStart == 1024
      check pv.rangeEnd == 65535

    test "groupByMetric single tier":
      let members = @[
        PolicyMember(interfaceName: "wan", mark: 0, weight: 1, metric: 10),
        PolicyMember(interfaceName: "lte", mark: 0, weight: 1, metric: 10),
      ]
      let tiers = groupByMetric(members)
      check tiers.len == 1
      check tiers[0].metric == 10
      check tiers[0].members.len == 2

    test "groupByMetric multi tier sorted":
      let members = @[
        PolicyMember(interfaceName: "lte", mark: 0, weight: 1, metric: 20),
        PolicyMember(interfaceName: "wan", mark: 0, weight: 1, metric: 10),
      ]
      let tiers = groupByMetric(members)
      check tiers.len == 2
      check tiers[0].metric == 10
      check tiers[0].members[0].interfaceName == "wan"
      check tiers[1].metric == 20

    test "determineStickyKeys src_ip ipv4":
      let keys = determineStickyKeys(smSrcIp, rfIpv4)
      check keys.len == 1
      check keys[0].suffix == "_v4"
      check keys[0].keyType == "ipv4_addr"

    test "determineStickyKeys src_dst any":
      let keys = determineStickyKeys(smSrcDst, rfAny)
      check keys.len == 2
      check keys[0].suffix == "_v4"
      check "ipv4_addr" in keys[0].keyType
      check keys[1].suffix == "_v6"
      check "ipv6_addr" in keys[1].keyType

    test "ipProtocol detects family":
      check ipProtocol("192.168.1.1") == "ip"
      check ipProtocol("::1") == "ip6"
      check ipProtocol("10.0.0.0/8") == "ip"
      check ipProtocol("fd00::/64") == "ip6"

  # Minimal Ruleset stub for testing (mirrors ruleset.nim interface)
  # If ruleset.nim is available, this block can be removed and the import used.

  proc twoInterfaceSetup(): (seq[InterfaceInfo], seq[PolicyInfo], seq[RuleInfo]) =
    let interfaces = @[
      InterfaceInfo(name: "wan", device: "eth0", mark: 0x0100'u32, tableId: 100, clampMss: true),
      InterfaceInfo(name: "wanb", device: "eth1", mark: 0x0200'u32, tableId: 200, clampMss: false),
    ]
    let policies = @[PolicyInfo(
      name: "balanced",
      members: @[
        PolicyMember(interfaceName: "wan", mark: 0x0100'u32, weight: 1, metric: 0),
        PolicyMember(interfaceName: "wanb", mark: 0x0200'u32, weight: 1, metric: 0),
      ],
      lastResort: Default,
    )]
    let rules = ruleSeq(RuleInfo(
      srcIp: @[], destIp: @[], srcPort: "", destPort: "",
      proto: namedProto(npAll), family: rfAny, srcIface: "", ipset: "",
      policy: "balanced", sticky: none(StickyInfo), log: false,
    ))
    (interfaces, policies, rules)

  proc getRulesForChain(parsed: JsonNode, chain: string): seq[JsonNode] =
    result = @[]
    for cmd in parsed["nftables"]:
      if cmd.hasKey("add") and cmd["add"].hasKey("rule"):
        let rule = cmd["add"]["rule"]
        if rule["chain"].getStr() == chain:
          result.add(rule)

  proc getChainNames(parsed: JsonNode): seq[string] =
    result = @[]
    for cmd in parsed["nftables"]:
      if cmd.hasKey("add") and cmd["add"].hasKey("chain"):
        result.add(cmd["add"]["chain"]["name"].getStr())

  proc getMaps(parsed: JsonNode): seq[JsonNode] =
    result = @[]
    for cmd in parsed["nftables"]:
      if cmd.hasKey("add") and cmd["add"].hasKey("map"):
        result.add(cmd["add"]["map"])

  suite "chains":
    test "ruleset serializes to valid JSON with expected structure":
      let (interfaces, policies, rules) = twoInterfaceSetup()
      let rs = buildRuleset(interfaces, policies, rules, @[], 0xFF00'u32, true, false)
      let j = rs.toJson()
      let parsed = parseJson($j)
      let commands = parsed["nftables"]

      check commands.len > 0
      # [0] = metainfo, [1] = add table, [2] = flush table
      check commands[0].hasKey("metainfo")
      check commands[1].hasKey("add")
      check commands[2].hasKey("flush")

      let chainNames = getChainNames(parsed)
      check "prerouting" in chainNames
      check "forward" notin chainNames  # no forward chain — policy in prerouting
      check "output" in chainNames
      check "postrouting" in chainNames
      check "policy_rules" in chainNames
      check "policy_balanced" in chainNames
      check "mark_wan" in chainNames
      check "mark_wanb" in chainNames

    test "prerouting has probe exception":
      let (interfaces, policies, rules) = twoInterfaceSetup()
      let rs = buildRuleset(interfaces, policies, rules, @[], 0xFF00'u32, true, false)
      let parsed = parseJson($rs.toJson())
      let preroutingRules = getRulesForChain(parsed, "prerouting")

      check preroutingRules.len > 0
      let firstStr = $preroutingRules[0]["expr"]
      check $ProbeMark in firstStr

    test "balanced policy uses numgen vmap":
      let (interfaces, policies, rules) = twoInterfaceSetup()
      let rs = buildRuleset(interfaces, policies, rules, @[], 0xFF00'u32, true, false)
      let parsed = parseJson($rs.toJson())
      let balancedRules = getRulesForChain(parsed, "policy_balanced")

      check balancedRules.len == 1
      let ruleStr = $balancedRules[0]["expr"]
      check "numgen" in ruleStr
      check "vmap" in ruleStr
      check "mark_wan" in ruleStr
      check "mark_wanb" in ruleStr

    test "single member policy uses goto":
      let interfaces = @[InterfaceInfo(name: "wan", device: "eth0", mark: 0x0100'u32, tableId: 100, clampMss: false)]
      let policies = @[PolicyInfo(
        name: "failover",
        members: @[PolicyMember(interfaceName: "wan", mark: 0x0100'u32, weight: 1, metric: 0)],
        lastResort: Default,
      )]
      let rules = ruleSeq(RuleInfo(
        srcIp: @[], destIp: @[], srcPort: "", destPort: "",
        proto: namedProto(npAll), family: rfAny, srcIface: "", ipset: "",
        policy: "failover", sticky: none(StickyInfo), log: false,
      ))
      let rs = buildRuleset(interfaces, policies, rules, @[], 0xFF00'u32, true, false)
      let parsed = parseJson($rs.toJson())
      let failoverRules = getRulesForChain(parsed, "policy_failover")

      check failoverRules.len == 1
      let ruleStr = $failoverRules[0]["expr"]
      check "goto" in ruleStr
      check "numgen" notin ruleStr

    test "MSS clamping only for enabled interfaces":
      let (interfaces, policies, rules) = twoInterfaceSetup()
      let rs = buildRuleset(interfaces, policies, rules, @[], 0xFF00'u32, true, false)
      let parsed = parseJson($rs.toJson())
      let postroutingRules = getRulesForChain(parsed, "postrouting")

      # Only eth0 (wan) has clampMss=true
      check postroutingRules.len == 1
      let ruleStr = $postroutingRules[0]["expr"]
      check "eth0" in ruleStr
      check "eth1" notin ruleStr

    test "proto all with ports splits TCP and UDP":
      let interfaces = @[InterfaceInfo(name: "wan", device: "eth0", mark: 0x0100'u32, tableId: 100, clampMss: false)]
      let policies = @[PolicyInfo(
        name: "balanced",
        members: @[PolicyMember(interfaceName: "wan", mark: 0x0100'u32, weight: 1, metric: 0)],
        lastResort: Default,
      )]
      let rules = ruleSeq(RuleInfo(
        srcIp: @[], destIp: @[], srcPort: "", destPort: "80",
        proto: namedProto(npAll), family: rfAny, srcIface: "", ipset: "",
        policy: "balanced", sticky: none(StickyInfo), log: false,
      ))
      let rs = buildRuleset(interfaces, policies, rules, @[], 0xFF00'u32, true, false)
      let parsed = parseJson($rs.toJson())
      let policyRules = getRulesForChain(parsed, "policy_rules")

      check policyRules.len == 2
      let r0 = $policyRules[0]["expr"]
      let r1 = $policyRules[1]["expr"]
      check "\"tcp\"" in r0
      check "\"udp\"" in r1
      check "dport" in r0
      check "dport" in r1

    test "failover tiered members":
      let interfaces = @[
        InterfaceInfo(name: "wan", device: "eth0", mark: 0x0100'u32, tableId: 100, clampMss: false),
        InterfaceInfo(name: "wanb", device: "eth1", mark: 0x0200'u32, tableId: 200, clampMss: false),
      ]
      let policies = @[PolicyInfo(
        name: "failover",
        members: @[
          PolicyMember(interfaceName: "wan", mark: 0x0100'u32, weight: 1, metric: 0),
          PolicyMember(interfaceName: "wanb", mark: 0x0200'u32, weight: 1, metric: 10),
        ],
        lastResort: Default,
      )]
      let rules = ruleSeq(RuleInfo(
        srcIp: @[], destIp: @[], srcPort: "", destPort: "",
        proto: namedProto(npAll), family: rfAny, srcIface: "", ipset: "",
        policy: "failover", sticky: none(StickyInfo), log: false,
      ))
      let rs = buildRuleset(interfaces, policies, rules, @[], 0xFF00'u32, true, false)
      let parsed = parseJson($rs.toJson())
      let failoverRules = getRulesForChain(parsed, "policy_failover")

      check failoverRules.len == 2
      let first = $failoverRules[0]["expr"]
      let second = $failoverRules[1]["expr"]
      check "mark_wan" in first
      check "mark_wanb" in second

    test "empty policy with last_resort unreachable":
      let policies = @[PolicyInfo(name: "blocked", members: @[], lastResort: Unreachable)]
      let rules = ruleSeq(RuleInfo(
        srcIp: @[], destIp: @[], srcPort: "", destPort: "",
        proto: namedProto(npAll), family: rfAny, srcIface: "", ipset: "",
        policy: "blocked", sticky: none(StickyInfo), log: false,
      ))
      let rs = buildRuleset(@[], policies, rules, @[], 0xFF00'u32, true, false)
      let parsed = parseJson($rs.toJson())
      let chainRules = getRulesForChain(parsed, "policy_blocked")

      check chainRules.len == 1
      let ruleStr = $chainRules[0]["expr"]
      check "reject" in ruleStr

    test "empty policy with last_resort blackhole":
      let policies = @[PolicyInfo(name: "dropped", members: @[], lastResort: Blackhole)]
      let rs = buildRuleset(@[], policies, @[], @[], 0xFF00'u32, true, false)
      let parsed = parseJson($rs.toJson())
      let chainRules = getRulesForChain(parsed, "policy_dropped")

      check chainRules.len == 1
      let ruleStr = $chainRules[0]["expr"]
      check "drop" in ruleStr

    test "empty policy with last_resort default":
      let policies = @[PolicyInfo(name: "fallback", members: @[], lastResort: Default)]
      let rs = buildRuleset(@[], policies, @[], @[], 0xFF00'u32, true, false)
      let parsed = parseJson($rs.toJson())
      let chainRules = getRulesForChain(parsed, "policy_fallback")

      check chainRules.len == 0

    test "sticky src_ip creates map and chain":
      let interfaces = @[InterfaceInfo(name: "wan", device: "eth0", mark: 0x0100'u32, tableId: 100, clampMss: false)]
      let policies = @[PolicyInfo(
        name: "balanced",
        members: @[PolicyMember(interfaceName: "wan", mark: 0x0100'u32, weight: 1, metric: 0)],
        lastResort: Default,
      )]
      let rules = ruleSeq(RuleInfo(
        srcIp: @[], destIp: @[], srcPort: "", destPort: "",
        proto: namedProto(npAll), family: rfIpv4, srcIface: "", ipset: "",
        policy: "balanced",
        sticky: some(StickyInfo(mode: smSrcIp, timeout: 600)),
        log: false,
      ))
      let rs = buildRuleset(interfaces, policies, rules, @[], 0xFF00'u32, true, false)
      let parsed = parseJson($rs.toJson())

      let maps = getMaps(parsed)
      check maps.len == 1
      check maps[0]["name"].getStr() == "sticky_r0"
      check maps[0]["type"].getStr() == "ipv4_addr"
      check maps[0]["map"].getStr() == "mark"
      check maps[0]["timeout"].getInt() == 600

      let chainNames = getChainNames(parsed)
      check "sticky_r0" in chainNames

      let policyRules = getRulesForChain(parsed, "policy_rules")
      let ruleStr = $policyRules[0]["expr"]
      check "sticky_r0" in ruleStr

      let stickyRules = getRulesForChain(parsed, "sticky_r0")
      check stickyRules.len >= 3
      let firstRule = $stickyRules[0]["expr"]
      check "sticky_r0" in firstRule
      let secondRule = $stickyRules[1]["expr"]
      check "mangle" in secondRule
      check $0x0100 in secondRule
      let thirdRule = $stickyRules[2]["expr"]
      check "update" in thirdRule

    test "sticky flow mode no map":
      let interfaces = @[InterfaceInfo(name: "wan", device: "eth0", mark: 0x0100'u32, tableId: 100, clampMss: false)]
      let policies = @[PolicyInfo(
        name: "balanced",
        members: @[PolicyMember(interfaceName: "wan", mark: 0x0100'u32, weight: 1, metric: 0)],
        lastResort: Default,
      )]
      let rules = ruleSeq(RuleInfo(
        srcIp: @[], destIp: @[], srcPort: "", destPort: "",
        proto: namedProto(npAll), family: rfAny, srcIface: "", ipset: "",
        policy: "balanced",
        sticky: some(StickyInfo(mode: smFlow, timeout: 600)),
        log: false,
      ))
      let rs = buildRuleset(interfaces, policies, rules, @[], 0xFF00'u32, true, false)
      let parsed = parseJson($rs.toJson())

      let maps = getMaps(parsed)
      check maps.len == 0

      let policyRules = getRulesForChain(parsed, "policy_rules")
      let ruleStr = $policyRules[0]["expr"]
      check "policy_balanced" in ruleStr

    test "connected networks bypass in prerouting":
      let (interfaces, policies, rules) = twoInterfaceSetup()
      let connected = @["192.168.1.0/24", "10.0.0.0/8", "fd00::/64"]
      let rs = buildRuleset(interfaces, policies, rules, connected, 0xFF00'u32, true, false)
      let parsed = parseJson($rs.toJson())

      # Bypass rules are in prerouting (before routing decision), not forward
      let preroutingRules = getRulesForChain(parsed, "prerouting")
      var foundV4Bypass = false
      var foundV6Bypass = false
      for rule in preroutingRules:
        let s = $rule["expr"]
        if "192.168.1.0" in s and "accept" in s:
          foundV4Bypass = true
        if "fd00::" in s and "accept" in s:
          foundV6Bypass = true
      check foundV4Bypass
      check foundV6Bypass

      # No forward chain exists
      let chainNames = getChainNames(parsed)
      check "forward" notin chainNames

    # ------------------------------------------------------------------
    # HIGH priority tests
    # ------------------------------------------------------------------

    test "use_policy_default_emits_accept":
      let interfaces = @[InterfaceInfo(name: "wan", device: "eth0", mark: 0x0100'u32, tableId: 100, clampMss: false)]
      let policies = @[PolicyInfo(
        name: "balanced",
        members: @[PolicyMember(interfaceName: "wan", mark: 0x0100'u32, weight: 1, metric: 0)],
        lastResort: Default,
      )]
      let rules = ruleSeq(
        # Rule using "default" policy -- should accept, not jump
        RuleInfo(
          srcIp: @["10.0.0.0/8"], destIp: @[], srcPort: "", destPort: "",
          proto: namedProto(npAll), family: rfIpv4, srcIface: "", ipset: "",
          policy: "default", sticky: none(StickyInfo), log: false,
        ),
        # Normal rule -- should jump to policy chain
        RuleInfo(
          srcIp: @[], destIp: @[], srcPort: "", destPort: "",
          proto: namedProto(npAll), family: rfAny, srcIface: "", ipset: "",
          policy: "balanced", sticky: none(StickyInfo), log: false,
        ),
      )
      let rs = buildRuleset(interfaces, policies, rules, @[], 0xFF00'u32, true, false)
      let parsed = parseJson($rs.toJson())
      let policyRules = getRulesForChain(parsed, "policy_rules")

      check policyRules.len == 2

      # First rule (use_policy default) should accept, not jump
      let r0Str = $policyRules[0]["expr"]
      check "accept" in r0Str
      check "jump" notin r0Str

      # Second rule should jump to policy chain
      let r1Str = $policyRules[1]["expr"]
      check "policy_balanced" in r1Str

    test "policy_rules_with_filters":
      let interfaces = @[InterfaceInfo(name: "wan", device: "eth0", mark: 0x0100'u32, tableId: 100, clampMss: false)]
      let policies = @[PolicyInfo(
        name: "direct",
        members: @[PolicyMember(interfaceName: "wan", mark: 0x0100'u32, weight: 1, metric: 0)],
        lastResort: Default,
      )]
      let rules = ruleSeq(RuleInfo(
        srcIp: @["192.168.1.0/24"], destIp: @["10.0.0.0/8"],
        srcPort: "1024-65535", destPort: "443",
        proto: namedProto(npTcp), family: rfIpv4, srcIface: "", ipset: "",
        policy: "direct", sticky: none(StickyInfo), log: false,
      ))
      let rs = buildRuleset(interfaces, policies, rules, @[], 0xFF00'u32, true, false)
      let parsed = parseJson($rs.toJson())
      let policyRules = getRulesForChain(parsed, "policy_rules")

      check policyRules.len == 1
      let ruleStr = $policyRules[0]["expr"]
      check "nfproto" in ruleStr
      check "l4proto" in ruleStr
      check "192.168.1.0" in ruleStr  # src IP CIDR
      check "10.0.0.0" in ruleStr     # dst IP CIDR
      check "sport" in ruleStr
      check "dport" in ruleStr
      check "policy_direct" in ruleStr

      # Verify port range and CIDR serialization via string search
      check "1024" in ruleStr
      check "65535" in ruleStr
      check "443" in ruleStr
      check "192.168.1.0" in ruleStr
      check "10.0.0.0" in ruleStr

    test "sticky_any_family_creates_dual_maps":
      let interfaces = @[InterfaceInfo(name: "wan", device: "eth0", mark: 0x0100'u32, tableId: 100, clampMss: false)]
      let policies = @[PolicyInfo(
        name: "balanced",
        members: @[PolicyMember(interfaceName: "wan", mark: 0x0100'u32, weight: 1, metric: 0)],
        lastResort: Default,
      )]
      let rules = ruleSeq(RuleInfo(
        srcIp: @[], destIp: @[], srcPort: "", destPort: "",
        proto: namedProto(npAll), family: rfAny, srcIface: "", ipset: "",
        policy: "balanced",
        sticky: some(StickyInfo(mode: smSrcIp, timeout: 300)),
        log: false,
      ))
      let rs = buildRuleset(interfaces, policies, rules, @[], 0xFF00'u32, true, false)
      let parsed = parseJson($rs.toJson())

      # "any" family should create both v4 and v6 maps
      let maps = getMaps(parsed)
      check maps.len == 2
      var mapNames: seq[string] = @[]
      for m in maps:
        mapNames.add(m["name"].getStr())
      check "sticky_r0_v4" in mapNames
      check "sticky_r0_v6" in mapNames

    test "no_connected_networks_still_has_bypass_sets_in_prerouting":
      let (interfaces, policies, rules) = twoInterfaceSetup()
      let rs = buildRuleset(interfaces, policies, rules, @[], 0xFF00'u32, true, false)
      let parsed = parseJson($rs.toJson())

      # No forward chain exists (policy decisions in prerouting)
      let chainNames2 = getChainNames(parsed)
      check "forward" notin chainNames2

      # Prerouting should still have dynamic bypass set rules
      let preroutingRules = getRulesForChain(parsed, "prerouting")
      var foundBypassV4 = false
      for rule in preroutingRules:
        let s = $rule["expr"]
        if "bypass_v4" in s: foundBypassV4 = true
      check foundBypassV4

    # ------------------------------------------------------------------
    # MEDIUM priority tests
    # ------------------------------------------------------------------

    test "named_set_matching_in_rules":
      let interfaces = @[InterfaceInfo(name: "wan", device: "eth0", mark: 0x0100'u32, tableId: 100, clampMss: false)]
      let policies = @[PolicyInfo(
        name: "direct",
        members: @[PolicyMember(interfaceName: "wan", mark: 0x0100'u32, weight: 1, metric: 0)],
        lastResort: Default,
      )]
      let rules = ruleSeq(
        # IPv4 named set on src_ip
        RuleInfo(
          srcIp: @["@vpn_clients"], destIp: @[], srcPort: "", destPort: "",
          proto: namedProto(npAll), family: rfIpv4, srcIface: "", ipset: "",
          policy: "direct", sticky: none(StickyInfo), log: false,
        ),
        # IPv6 named set on dest_ip
        RuleInfo(
          srcIp: @[], destIp: @["@blocked_v6"], srcPort: "", destPort: "",
          proto: namedProto(npAll), family: rfIpv6, srcIface: "", ipset: "",
          policy: "direct", sticky: none(StickyInfo), log: false,
        ),
      )
      let rs = buildRuleset(interfaces, policies, rules, @[], 0xFF00'u32, true, false)
      let parsed = parseJson($rs.toJson())
      let policyRules = getRulesForChain(parsed, "policy_rules")

      check policyRules.len == 2

      # First rule: src_ip = @vpn_clients with IPv4
      let expr0 = policyRules[0]["expr"]
      var srcMatch: JsonNode
      for e in expr0:
        if e.hasKey("match") and e["match"]["left"].hasKey("payload"):
          if e["match"]["left"]["payload"]["field"].getStr() == "saddr":
            srcMatch = e
            break
      check srcMatch["match"]["left"]["payload"]["protocol"].getStr() == "ip"
      check srcMatch["match"]["right"]["@"].getStr() == "vpn_clients"

      # Second rule: dest_ip = @blocked_v6 with IPv6
      let expr1 = policyRules[1]["expr"]
      var dstMatch: JsonNode
      for e in expr1:
        if e.hasKey("match") and e["match"]["left"].hasKey("payload"):
          if e["match"]["left"]["payload"]["field"].getStr() == "daddr":
            dstMatch = e
            break
      check dstMatch["match"]["left"]["payload"]["protocol"].getStr() == "ip6"
      check dstMatch["match"]["right"]["@"].getStr() == "blocked_v6"

    test "proto_all_without_ports_stays_single_rule":
      let interfaces = @[InterfaceInfo(name: "wan", device: "eth0", mark: 0x0100'u32, tableId: 100, clampMss: false)]
      let policies = @[PolicyInfo(
        name: "balanced",
        members: @[PolicyMember(interfaceName: "wan", mark: 0x0100'u32, weight: 1, metric: 0)],
        lastResort: Default,
      )]
      let rules = ruleSeq(RuleInfo(
        srcIp: @["10.0.0.0/8"], destIp: @[], srcPort: "", destPort: "",
        proto: namedProto(npAll), family: rfIpv4, srcIface: "", ipset: "",
        policy: "balanced", sticky: none(StickyInfo), log: false,
      ))
      let rs = buildRuleset(interfaces, policies, rules, @[], 0xFF00'u32, true, false)
      let parsed = parseJson($rs.toJson())
      let policyRules = getRulesForChain(parsed, "policy_rules")

      # proto:all without ports should stay as a single rule with no l4proto match
      check policyRules.len == 1
      let ruleStr = $policyRules[0]["expr"]
      check "l4proto" notin ruleStr

    test "ipv6_addresses_use_ip6_protocol":
      let interfaces = @[InterfaceInfo(name: "wan", device: "eth0", mark: 0x0100'u32, tableId: 100, clampMss: false)]
      let policies = @[PolicyInfo(
        name: "direct",
        members: @[PolicyMember(interfaceName: "wan", mark: 0x0100'u32, weight: 1, metric: 0)],
        lastResort: Default,
      )]
      let rules = ruleSeq(RuleInfo(
        srcIp: @["2001:db8::/32"], destIp: @["10.0.0.0/8"],
        srcPort: "", destPort: "",
        proto: namedProto(npAll), family: rfAny, srcIface: "", ipset: "",
        policy: "direct", sticky: none(StickyInfo), log: false,
      ))
      let rs = buildRuleset(interfaces, policies, rules, @[], 0xFF00'u32, true, false)
      let parsed = parseJson($rs.toJson())
      let policyRules = getRulesForChain(parsed, "policy_rules")
      let expr = policyRules[0]["expr"]

      # IPv6 src address should use "ip6" protocol
      var saddrMatch: JsonNode
      for e in expr:
        if e.hasKey("match") and e["match"]["left"].hasKey("payload"):
          if e["match"]["left"]["payload"]["field"].getStr() == "saddr":
            saddrMatch = e
            break
      check saddrMatch["match"]["left"]["payload"]["protocol"].getStr() == "ip6"

      # IPv4 dst address should use "ip" protocol
      var daddrMatch: JsonNode
      for e in expr:
        if e.hasKey("match") and e["match"]["left"].hasKey("payload"):
          if e["match"]["left"]["payload"]["field"].getStr() == "daddr":
            daddrMatch = e
            break
      check daddrMatch["match"]["left"]["payload"]["protocol"].getStr() == "ip"

    # ------------------------------------------------------------------
    # LOW priority tests
    # ------------------------------------------------------------------

    test "per_rule_logging":
      let (interfaces, policies, _) = twoInterfaceSetup()
      let rules = ruleSeq(
        # Rule with logging enabled
        RuleInfo(
          srcIp: @[], destIp: @[], srcPort: "", destPort: "",
          proto: namedProto(npAll), family: rfAny, srcIface: "", ipset: "",
          policy: "balanced", sticky: none(StickyInfo), log: true,
        ),
        # Rule without logging
        RuleInfo(
          srcIp: @[], destIp: @[], srcPort: "", destPort: "",
          proto: namedProto(npTcp), family: rfAny, srcIface: "", ipset: "",
          policy: "balanced", sticky: none(StickyInfo), log: false,
        ),
      )
      let rs = buildRuleset(interfaces, policies, rules, @[], 0xFF00'u32, true, false)
      let parsed = parseJson($rs.toJson())
      let policyRules = getRulesForChain(parsed, "policy_rules")

      check policyRules.len == 2

      # First rule should have a log statement
      let expr0 = policyRules[0]["expr"]
      var hasLog0 = false
      for e in expr0:
        if e.hasKey("log"):
          hasLog0 = true
          check e["log"]["prefix"].getStr() == "nopal:balanced "
          break
      check hasLog0

      # Second rule should NOT have a log statement
      let expr1 = policyRules[1]["expr"]
      var hasLog1 = false
      for e in expr1:
        if e.hasKey("log"):
          hasLog1 = true
          break
      check not hasLog1
