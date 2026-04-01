## nftables chain builder -- generates the complete inet nopal ruleset.
##
## Ported from the Rust implementation in chains.rs. Builds all base chains,
## regular chains, expression helpers, and rule generation for policy routing.

import std/[json, strutils, options, algorithm, sequtils]
import ./ruleset

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
    mode*: string   # "flow", "src_ip", "src_dst"
    timeout*: uint32

  RuleInfo* = object
    srcIp*, destIp*: seq[string]
    srcPort*, destPort*, proto*, family*: string
    srcIface*, ipset*: string
    policy*: string
    sticky*: Option[StickyInfo]
    log*: bool

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

proc ipProtocol(address: string): string =
  if ':' in address: "ip6" else: "ip"

proc ipProtocolFor(address, ruleFamily: string): string =
  if address.startsWith('@'):
    if ruleFamily == "ipv6": "ip6" else: "ip"
  else:
    ipProtocol(address)

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

proc matchIpList(addrs: seq[string], field, ruleFamily: string): JsonNode =
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

proc matchDaddrNamedSet(setName, family: string): JsonNode =
  let protocol = if family == "ipv6": "ip6" else: "ip"
  %*{"match": {"op": "==", "left": {"payload": {"protocol": protocol, "field": "daddr"}}, "right": "@" & setName}}

proc parsePort(port: string): JsonNode =
  let dashIdx = port.find('-')
  if dashIdx >= 0:
    let loPart = port[0 ..< dashIdx]
    let hiPart = port[dashIdx + 1 .. ^1]
    try:
      let lo = parseInt(loPart)
      let hi = parseInt(hiPart)
      return %*{"range": [lo, hi]}
    except ValueError:
      discard
  try:
    let n = parseInt(port)
    return %*n
  except ValueError:
    discard
  return %*port

proc matchSrcPort(port, proto: string): JsonNode =
  %*{"match": {"op": "==", "left": {"payload": {"protocol": proto, "field": "sport"}}, "right": parsePort(port)}}

proc matchDstPort(port, proto: string): JsonNode =
  %*{"match": {"op": "==", "left": {"payload": {"protocol": proto, "field": "dport"}}, "right": parsePort(port)}}

# ---------------------------------------------------------------------------
# Sticky map helpers
# ---------------------------------------------------------------------------

proc stickyKeyExpr(proto, mode: string): JsonNode =
  let saddr = %*{"payload": {"protocol": proto, "field": "saddr"}}
  if mode == "src_dst":
    let daddr = %*{"payload": {"protocol": proto, "field": "daddr"}}
    %*{"concat": [saddr, daddr]}
  else:
    saddr

proc setMarkFromMap(key: JsonNode, mapName: string): JsonNode =
  %*{"mangle": {"key": {"meta": {"key": "mark"}}, "value": {"map": {"key": key, "data": {"@": mapName}}}}}

proc updateMap(key: JsonNode, mapName: string): JsonNode =
  %*{"map": {"op": "update", "elem": key, "data": {"meta": {"key": "mark"}}, "map": {"@": mapName}}}

# ---------------------------------------------------------------------------
# Tier grouping helper
# ---------------------------------------------------------------------------

type Tier = tuple[metric: uint32, members: seq[PolicyMember]]

proc groupByMetric(members: seq[PolicyMember]): seq[Tier] =
  var tiers: seq[Tier] = @[]
  for member in members:
    var found = false
    for i in 0 ..< tiers.len:
      if tiers[i].metric == member.metric:
        tiers[i].members.add(member)
        found = true
        break
    if not found:
      tiers.add((metric: member.metric, members: @[member]))
  tiers.sort(proc(a, b: Tier): int = cmp(a.metric, b.metric))
  tiers

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
  rs.addRule(chain, @[matchDaddrNamedSet("bypass_v4", "ipv4"), nftAccept()])
  rs.addRule(chain, @[matchDaddrNamedSet("bypass_v6", "ipv6"), nftAccept()])

proc buildPrerouting(rs: var Ruleset, interfaces: openArray[InterfaceInfo], markMask: uint32) =
  # Exception: skip probe packets
  rs.addRule("prerouting", @[matchMetaMarkEq(ProbeMark), nftAccept()])

  # Exception: accept IPv6 NDP/RA (ICMPv6 types 133-137)
  rs.addRule("prerouting", @[matchNfprotoIpv6(), matchProtocol("icmpv6"),
    matchIcmpv6TypeRange(133, 137), nftAccept()])

  # Restore conntrack mark -> packet mark when ct mark has WAN bits set
  rs.addRule("prerouting", @[matchCtMarkMaskedNeq(markMask, 0), setMarkFromCt(markMask)])

  # Mark inbound new connections per interface
  for iface in interfaces:
    rs.addRule("prerouting", @[matchIifname(iface.device), matchCtStateNew(), setCtMark(iface.mark)])

proc buildForward(rs: var Ruleset, connected: openArray[string], markMask: uint32) =
  addConnectedBypass(rs, "forward", connected)
  rs.addRule("forward", @[matchCtMarkMaskedNeq(markMask, 0), setMarkFromCt(markMask)])
  rs.addRule("forward", @[matchMetaMarkMaskedEq(markMask, 0), jump("policy_rules")])

proc buildOutput(rs: var Ruleset, connected: openArray[string], markMask: uint32) =
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
    let isIcmp = rule.proto == "icmp"

    # Build list of (proto, familyOverride) pairs
    type ProtoFamilyPair = tuple[proto: string, familyOverride: string]
    var pairs: seq[ProtoFamilyPair]

    if isIcmp:
      case rule.family
      of "ipv4": pairs = @[("icmp", "")]
      of "ipv6": pairs = @[("icmpv6", "")]
      else: pairs = @[("icmp", "ipv4"), ("icmpv6", "ipv6")]
    elif rule.proto == "all" and hasPorts:
      pairs = @[("tcp", ""), ("udp", "")]
    else:
      pairs = @[(rule.proto, "")]

    for pair in pairs:
      let (proto, familyOverride) = pair
      var expr: seq[JsonNode] = @[]

      # Address family filter
      let family = if familyOverride.len > 0: familyOverride else: rule.family
      case family
      of "ipv4": expr.add(matchNfprotoIpv4())
      of "ipv6": expr.add(matchNfprotoIpv6())
      else: discard  # "any" -- no family filter

      # Inbound interface match
      if rule.srcIface.len > 0:
        expr.add(matchIifname(rule.srcIface))

      # Protocol match
      if proto != "all":
        expr.add(matchProtocol(proto))

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
        expr.add(matchSrcPort(rule.srcPort, proto))

      # Destination port (skip for ICMP)
      if not isIcmp and rule.destPort.len > 0:
        expr.add(matchDstPort(rule.destPort, proto))

      # Log matching packets if enabled
      if rule.log:
        expr.add(logPrefix("nopal:" & rule.policy & " "))

      # "default" policy = accept (bypass policy routing)
      if rule.policy == "default":
        expr.add(nftAccept())
      else:
        let needsStickyChain = rule.sticky.isSome and rule.sticky.get.mode != "flow"
        if needsStickyChain:
          expr.add(jump("sticky_r" & $i))
        else:
          expr.add(jump("policy_" & rule.policy))

      rs.addRule("policy_rules", expr)

proc buildPolicyChain(rs: var Ruleset, policy: PolicyInfo) =
  let chainName = "policy_" & policy.name

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
      rs.addRule(chainName, @[goto("mark_" & members[0].interfaceName)])
    else:
      # Weighted round-robin via numgen vmap
      var total: uint32 = 0
      for m in members:
        total += m.weight
      var vmapEntries = newJArray()
      var slot: uint32 = 0
      for member in members:
        for _ in 0 ..< member.weight:
          vmapEntries.add(%*[slot, {"goto": {"target": "mark_" & member.interfaceName}}])
          slot += 1
      rs.addRule(chainName, @[
        %*{"vmap": {"key": {"numgen": {"mode": "inc", "mod": total, "offset": 0}}, "data": vmapEntries}}
      ])

proc buildMarkChain(rs: var Ruleset, iface: InterfaceInfo) =
  let chainName = "mark_" & iface.name
  rs.addRule(chainName, @[setMetaMark(iface.mark), saveMarkToCt(), nftAccept()])

proc buildStickyMapAndChain(rs: var Ruleset, ruleIndex: int, rule: RuleInfo,
                             sticky: StickyInfo, markMask: uint32, policy: PolicyInfo) =
  let families =
    case rule.family
    of "ipv4": @["ipv4"]
    of "ipv6": @["ipv6"]
    else: @["ipv4", "ipv6"]

  # Create map(s) for this rule
  for fam in families:
    let suffix =
      if families.len > 1:
        if fam == "ipv4": "_v4" else: "_v6"
      else:
        ""
    let mapName = "sticky_r" & $ruleIndex & suffix
    let addrType = if fam == "ipv4": "ipv4_addr" else: "ipv6_addr"
    let keyType =
      if sticky.mode == "src_dst":
        %*[addrType, addrType]
      else:
        %*addrType
    rs.addMap(mapName, keyType, "mark", sticky.timeout)

  # Create the sticky helper chain
  let chainName = "sticky_r" & $ruleIndex
  rs.addRegularChain(chainName)

  # Phase 1: Map lookup
  for fam in families:
    let suffix =
      if families.len > 1:
        if fam == "ipv4": "_v4" else: "_v6"
      else:
        ""
    let mapName = "sticky_r" & $ruleIndex & suffix
    let proto = if fam == "ipv4": "ip" else: "ip6"
    let lookupKey = stickyKeyExpr(proto, sticky.mode)

    var lookupExpr: seq[JsonNode] = @[]
    if families.len > 1:
      if fam == "ipv4":
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
      %*{"mangle": {"key": {"meta": {"key": "mark"}}, "value": {"map": {"key": {"numgen": {"mode": "inc", "mod": total, "offset": 0}}, "data": mapEntries}}}},
      saveMarkToCt()
    ])

  # Phase 3: Update sticky map with assigned mark
  for fam in families:
    let suffix =
      if families.len > 1:
        if fam == "ipv4": "_v4" else: "_v6"
      else:
        ""
    let mapName = "sticky_r" & $ruleIndex & suffix
    let proto = if fam == "ipv4": "ip" else: "ip6"
    let updateKey = stickyKeyExpr(proto, sticky.mode)

    var updateExpr: seq[JsonNode] = @[]
    if families.len > 1:
      if fam == "ipv4":
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
                   markMask: uint32, ipv6Enabled, logging: bool): Ruleset =
  # TODO: ipv6Enabled gates IPv6 chain generation; logging gates per-rule log stmts
  var rs = initRuleset()

  # Table setup: add (idempotent create) then flush (clear old rules)
  rs.addTable()
  rs.addFlushTable()

  # Dynamic bypass sets
  rs.addSet("bypass_v4", "ipv4_addr", @["interval"])
  rs.addSet("bypass_v6", "ipv6_addr", @["interval"])

  # Base chains
  rs.addBaseChain("prerouting", "filter", "prerouting", -150, "accept")
  rs.addBaseChain("forward", "filter", "forward", -150, "accept")
  rs.addBaseChain("output", "filter", "output", -150, "accept")
  rs.addBaseChain("postrouting", "filter", "postrouting", 150, "accept")

  # Regular chains
  rs.addRegularChain("policy_rules")
  for iface in interfaces:
    rs.addRegularChain("mark_" & iface.name)
  for policy in policies:
    rs.addRegularChain("policy_" & policy.name)

  # Prerouting rules
  buildPrerouting(rs, interfaces, markMask)

  # Forward rules
  buildForward(rs, connected, markMask)

  # Output rules
  buildOutput(rs, connected, markMask)

  # Postrouting rules
  buildPostrouting(rs, interfaces)

  # Sticky maps and chains
  for i, rule in rules:
    if rule.sticky.isSome:
      let sticky = rule.sticky.get
      if sticky.mode != "flow":
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
    let rules = @[RuleInfo(
      srcIp: @[], destIp: @[], srcPort: "", destPort: "",
      proto: "all", family: "any", srcIface: "", ipset: "",
      policy: "balanced", sticky: none(StickyInfo), log: false,
    )]
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
      check "forward" in chainNames
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
      let rules = @[RuleInfo(
        srcIp: @[], destIp: @[], srcPort: "", destPort: "",
        proto: "all", family: "any", srcIface: "", ipset: "",
        policy: "failover", sticky: none(StickyInfo), log: false,
      )]
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
      let rules = @[RuleInfo(
        srcIp: @[], destIp: @[], srcPort: "", destPort: "80",
        proto: "all", family: "any", srcIface: "", ipset: "",
        policy: "balanced", sticky: none(StickyInfo), log: false,
      )]
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
      let rules = @[RuleInfo(
        srcIp: @[], destIp: @[], srcPort: "", destPort: "",
        proto: "all", family: "any", srcIface: "", ipset: "",
        policy: "failover", sticky: none(StickyInfo), log: false,
      )]
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
      let rules = @[RuleInfo(
        srcIp: @[], destIp: @[], srcPort: "", destPort: "",
        proto: "all", family: "any", srcIface: "", ipset: "",
        policy: "blocked", sticky: none(StickyInfo), log: false,
      )]
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
      let rules = @[RuleInfo(
        srcIp: @[], destIp: @[], srcPort: "", destPort: "",
        proto: "all", family: "ipv4", srcIface: "", ipset: "",
        policy: "balanced",
        sticky: some(StickyInfo(mode: "src_ip", timeout: 600)),
        log: false,
      )]
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
      let rules = @[RuleInfo(
        srcIp: @[], destIp: @[], srcPort: "", destPort: "",
        proto: "all", family: "any", srcIface: "", ipset: "",
        policy: "balanced",
        sticky: some(StickyInfo(mode: "flow", timeout: 600)),
        log: false,
      )]
      let rs = buildRuleset(interfaces, policies, rules, @[], 0xFF00'u32, true, false)
      let parsed = parseJson($rs.toJson())

      let maps = getMaps(parsed)
      check maps.len == 0

      let policyRules = getRulesForChain(parsed, "policy_rules")
      let ruleStr = $policyRules[0]["expr"]
      check "policy_balanced" in ruleStr

    test "connected networks bypass policy routing":
      let (interfaces, policies, rules) = twoInterfaceSetup()
      let connected = @["192.168.1.0/24", "10.0.0.0/8", "fd00::/64"]
      let rs = buildRuleset(interfaces, policies, rules, connected, 0xFF00'u32, true, false)
      let parsed = parseJson($rs.toJson())
      let forwardRules = getRulesForChain(parsed, "forward")

      check forwardRules.len >= 4
      let firstStr = $forwardRules[0]["expr"]
      check "192.168.1.0" in firstStr
      check "10.0.0.0" in firstStr
      check "accept" in firstStr

      let secondStr = $forwardRules[1]["expr"]
      check "fd00::" in secondStr
