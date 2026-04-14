## WAN interface auto-discovery from OpenWrt firewall/network config.
##
## Reads /etc/config/firewall to find WAN zones (masq=1 or name=wan),
## then reads /etc/config/network to resolve device names for each
## interface in those zones. Skips DHCPv6 interfaces.

import std/[strformat, logging, os, osproc, json]
import ./parser
import ./schema

type
  DiscoveredWan* = object
    name*: string      ## UCI interface name (e.g., "wan", "wan2")
    device*: string    ## Physical device (e.g., "wan", "lan2")
    proto*: string     ## "dhcp", "static", etc.

proc discoverWanInterfaces*(
    firewallPath: string = "/etc/config/firewall",
    networkPath: string = "/etc/config/network"
): seq[DiscoveredWan] =
  ## Discover WAN interfaces from OpenWrt firewall zone and network config.
  ## Returns empty seq if config files don't exist (non-OpenWrt environment).

  if not fileExists(firewallPath):
    info fmt"WAN discovery: {firewallPath} not found, skipping"
    return @[]
  if not fileExists(networkPath):
    info fmt"WAN discovery: {networkPath} not found, skipping"
    return @[]

  # Parse firewall config to find WAN zones
  let fwText = readFile(firewallPath)
  let fwSections = parseUci(fwText)

  var wanInterfaceNames: seq[string] = @[]
  for sec in fwSections:
    if sec.sectionType != "zone": continue
    let name = sec.get("name")
    let masq = sec.getBool("masq", false)
    if masq or name == "wan":
      # Collect all network interfaces in this zone
      for n in sec.getAll("network"):
        if n notin wanInterfaceNames:
          wanInterfaceNames.add(n)

  if wanInterfaceNames.len == 0:
    info "WAN discovery: no WAN zone found in firewall config"
    return @[]

  # Parse network config to resolve device names
  let netText = readFile(networkPath)
  let netSections = parseUci(netText)

  for ifName in wanInterfaceNames:
    for sec in netSections:
      if sec.sectionType != "interface": continue
      if sec.name != ifName: continue

      let proto = sec.get("proto")
      # Skip DHCPv6 interfaces (IPv6 companions, not separate WANs)
      if proto == "dhcpv6":
        continue

      let device = sec.get("device")
      if device == "":
        warn fmt"WAN discovery: interface '{ifName}' has no device configured, skipping"
        continue

      result.add(DiscoveredWan(name: ifName, device: device, proto: proto))
      break

  if result.len > 0:
    info fmt"WAN discovery: found {result.len} interface(s): {result}"

type
  InterfaceGateway* = object
    name*: string
    gateway4*: string  ## IPv4 gateway (e.g., "192.168.100.1") or ""
    gateway6*: string  ## IPv6 gateway or ""

proc getInterfaceGateways*(interfaceNames: openArray[string]): seq[InterfaceGateway] =
  ## Query ubus for the default gateway of each named interface.
  ## Returns gateway info for interfaces that have routes.
  ## This is a one-time init call, not a hot-path operation.
  for name in interfaceNames:
    var gw = InterfaceGateway(name: name)
    try:
      let (output, exitCode) = execCmdEx("ubus call network.interface." & name & " status")
      if exitCode != 0:
        result.add(gw)
        continue
      let j = parseJson(output)
      # IPv4 routes
      for route in j.getOrDefault("route").getElems():
        if route.getOrDefault("target").getStr() == "0.0.0.0" and
           route.getOrDefault("mask").getInt() == 0:
          gw.gateway4 = route.getOrDefault("nexthop").getStr()
          break
      # IPv6 routes
      for route in j.getOrDefault("route6").getElems():
        if route.getOrDefault("target").getStr() == "::" and
           route.getOrDefault("mask").getInt() == 0:
          gw.gateway6 = route.getOrDefault("nexthop").getStr()
          break
    except CatchableError:
      discard
    result.add(gw)

proc applyGlobalsDefaults*(iface: var InterfaceConfig, globals: GlobalsConfig) =
  ## Fill unset interface fields from globals defaults.
  ## Fields at their zero/empty value are considered unset.
  if iface.trackIp.len == 0:
    iface.trackIp = globals.trackIp
  if iface.trackMethod == tmPing and iface.probeInterval == 0:
    # trackMethod defaults to tmPing in defaultInterface, so we can't
    # distinguish "user set ping" from "default". Use probeInterval==0
    # as the sentinel for "nothing was explicitly configured".
    iface.trackMethod = globals.trackMethod
  if iface.probeInterval == 0:
    iface.probeInterval = globals.probeInterval
  if iface.probeTimeout == 0:
    iface.probeTimeout = globals.probeTimeout
  if iface.upCount == 0:
    iface.upCount = globals.upCount
  if iface.downCount == 0:
    iface.downCount = globals.downCount

proc makeDiscoveredInterface*(wan: DiscoveredWan, globals: GlobalsConfig): InterfaceConfig =
  ## Create an InterfaceConfig for a discovered WAN with globals defaults.
  result = InterfaceConfig(
    name: wan.name,
    enabled: true,
    device: wan.device,
    family: afIpv4,
    metric: 0,
    weight: 50,
    trackMethod: globals.trackMethod,
    trackIp: globals.trackIp,
    probeInterval: globals.probeInterval,
    probeTimeout: globals.probeTimeout,
    upCount: globals.upCount,
    downCount: globals.downCount,
    count: 1,
    reliability: 1,
    maxTtl: 128,
    probeSize: 56,
    initialState: initOffline,
    checkQuality: true,
    qualityWindow: 10,
    clampMss: true,
    flushConntrack: @[cftDisconnected],
  )

proc buildDiscoveredConfig*(
    discovered: seq[DiscoveredWan],
    globals: GlobalsConfig,
    existingInterfaces: seq[InterfaceConfig],
    existingMembers: seq[MemberConfig],
    existingPolicies: seq[PolicyConfig],
    existingRules: seq[RuleConfig],
): tuple[
    interfaces: seq[InterfaceConfig],
    members: seq[MemberConfig],
    policies: seq[PolicyConfig],
    rules: seq[RuleConfig],
] =
  ## Build a complete config from discovered WANs and existing overrides.
  ##
  ## - For each discovered WAN: use existing interface section if present
  ##   (with globals inheritance), otherwise create one from globals.
  ## - If no members/policies/rules exist, auto-generate a balanced setup.

  # Build interfaces
  for wan in discovered:
    var found = false
    for existing in existingInterfaces:
      if existing.name == wan.name:
        var iface = existing
        # Fill device from discovery if not explicitly set
        if iface.device == "":
          iface.device = wan.device
        applyGlobalsDefaults(iface, globals)
        result.interfaces.add(iface)
        found = true
        break
    if not found:
      result.interfaces.add(makeDiscoveredInterface(wan, globals))

  # Auto-generate members, policy, and rule if none configured
  if existingMembers.len > 0:
    result.members = existingMembers
  else:
    for iface in result.interfaces:
      result.members.add(MemberConfig(
        name: iface.name & "_m1_w50",
        interfaceName: iface.name,
        metric: 1,
        weight: 50,
      ))

  if existingPolicies.len > 0:
    result.policies = existingPolicies
  else:
    var memberNames: seq[string] = @[]
    for m in result.members:
      memberNames.add(m.name)
    result.policies.add(PolicyConfig(
      name: "balanced",
      members: memberNames,
      lastResort: lrDefault,
    ))

  if existingRules.len > 0:
    result.rules = existingRules
  else:
    let policyName = if result.policies.len > 0: result.policies[0].name
                     else: "balanced"
    result.rules.add(RuleConfig(
      name: "default_rule",
      proto: namedProto(npAll),
      family: rfAny,
      sticky: true,
      stickyTimeout: 600,
      stickyMode: smFlow,
      usePolicy: policyName,
    ))


when isMainModule:
  import std/unittest

  # Sample firewall config
  const sampleFirewall = """
config defaults
    option syn_flood '1'
    option input 'REJECT'
    option output 'ACCEPT'
    option forward 'REJECT'

config zone
    option name 'lan'
    list network 'lan'
    option input 'ACCEPT'
    option output 'ACCEPT'
    option forward 'ACCEPT'

config zone
    option name 'wan'
    option masq '1'
    list network 'wan'
    list network 'wan6'
    list network 'wan2'
    option input 'REJECT'
    option output 'ACCEPT'
    option forward 'REJECT'
"""

  # Sample network config
  const sampleNetwork = """
config interface 'loopback'
    option device 'lo'
    option proto 'static'
    option ipaddr '127.0.0.1/8'

config interface 'lan'
    option device 'br-lan'
    option proto 'dhcp'

config interface 'wan'
    option device 'wan'
    option proto 'dhcp'

config interface 'wan6'
    option device 'wan'
    option proto 'dhcpv6'

config interface 'wan2'
    option device 'lan2'
    option proto 'dhcp'
"""

  var passed = 0
  var failed = 0

  template test(name: string, body: untyped) =
    block:
      try:
        body
        inc passed
        echo "  PASS: ", name
      except AssertionDefect:
        inc failed
        echo "  FAIL: ", name, " - ", getCurrentExceptionMsg()
      except CatchableError:
        inc failed
        echo "  FAIL: ", name, " - ", getCurrentExceptionMsg()

  echo "=== WAN discovery tests ==="

  test "discover_from_sample_configs":
    # Write sample configs to temp files
    let fwPath = "/tmp/nopal_test_firewall"
    let netPath = "/tmp/nopal_test_network"
    writeFile(fwPath, sampleFirewall)
    writeFile(netPath, sampleNetwork)
    defer:
      removeFile(fwPath)
      removeFile(netPath)

    let wans = discoverWanInterfaces(fwPath, netPath)
    doAssert wans.len == 2, "expected 2 WANs, got " & $wans.len
    doAssert wans[0].name == "wan"
    doAssert wans[0].device == "wan"
    doAssert wans[0].proto == "dhcp"
    doAssert wans[1].name == "wan2"
    doAssert wans[1].device == "lan2"
    doAssert wans[1].proto == "dhcp"

  test "dhcpv6_filtered":
    let fwPath = "/tmp/nopal_test_firewall"
    let netPath = "/tmp/nopal_test_network"
    writeFile(fwPath, sampleFirewall)
    writeFile(netPath, sampleNetwork)
    defer:
      removeFile(fwPath)
      removeFile(netPath)

    let wans = discoverWanInterfaces(fwPath, netPath)
    for w in wans:
      doAssert w.name != "wan6", "wan6 (dhcpv6) should be filtered"

  test "masq_detection":
    let fw = """
config zone
    option name 'vpn_out'
    option masq '1'
    list network 'wg0'

config zone
    option name 'lan'
    list network 'lan'
"""
    let net = """
config interface 'wg0'
    option device 'wg0'
    option proto 'wireguard'
"""
    let fwPath = "/tmp/nopal_test_fw2"
    let netPath = "/tmp/nopal_test_net2"
    writeFile(fwPath, fw)
    writeFile(netPath, net)
    defer:
      removeFile(fwPath)
      removeFile(netPath)

    let wans = discoverWanInterfaces(fwPath, netPath)
    doAssert wans.len == 1
    doAssert wans[0].name == "wg0"
    doAssert wans[0].device == "wg0"

  test "missing_files_returns_empty":
    let wans = discoverWanInterfaces("/nonexistent/firewall", "/nonexistent/network")
    doAssert wans.len == 0

  test "no_wan_zone_returns_empty":
    let fw = """
config zone
    option name 'lan'
    list network 'lan'
"""
    let fwPath = "/tmp/nopal_test_fw3"
    let netPath = "/tmp/nopal_test_net3"
    writeFile(fwPath, fw)
    writeFile(netPath, "")
    defer:
      removeFile(fwPath)
      removeFile(netPath)

    let wans = discoverWanInterfaces(fwPath, netPath)
    doAssert wans.len == 0

  echo ""
  echo "=== Config building tests ==="

  test "build_zero_config":
    let wans = @[
      DiscoveredWan(name: "wan", device: "wan", proto: "dhcp"),
      DiscoveredWan(name: "wan2", device: "lan2", proto: "dhcp"),
    ]
    let globals = defaultGlobals()
    let (ifaces, members, policies, rules) = buildDiscoveredConfig(
      wans, globals, @[], @[], @[], @[])

    doAssert ifaces.len == 2
    doAssert ifaces[0].name == "wan"
    doAssert ifaces[0].device == "wan"
    doAssert ifaces[0].trackMethod == tmPing
    doAssert ifaces[0].trackIp == @["8.8.8.8", "1.1.1.1"]
    doAssert ifaces[1].name == "wan2"
    doAssert ifaces[1].device == "lan2"

    doAssert members.len == 2
    doAssert members[0].interfaceName == "wan"
    doAssert members[0].metric == 1
    doAssert members[0].weight == 50
    doAssert members[1].interfaceName == "wan2"

    doAssert policies.len == 1
    doAssert policies[0].name == "balanced"
    doAssert policies[0].members.len == 2

    doAssert rules.len == 1
    doAssert rules[0].usePolicy == "balanced"

  test "build_with_interface_override":
    let wans = @[
      DiscoveredWan(name: "wan", device: "wan", proto: "dhcp"),
      DiscoveredWan(name: "wan2", device: "lan2", proto: "dhcp"),
    ]
    let globals = defaultGlobals()
    # User overrides wan with DNS probes and metric 20
    var wanOverride = InterfaceConfig(name: "wan", enabled: true,
                                       trackMethod: tmDns,
                                       metric: 20)
    let (ifaces, _, _, _) = buildDiscoveredConfig(
      wans, globals, @[wanOverride], @[], @[], @[])

    doAssert ifaces.len == 2
    doAssert ifaces[0].name == "wan"
    doAssert ifaces[0].device == "wan"  # filled from discovery
    doAssert ifaces[0].trackMethod == tmDns  # from override
    doAssert ifaces[0].metric == 20  # from override
    doAssert ifaces[0].trackIp == @["8.8.8.8", "1.1.1.1"]  # inherited from globals
    doAssert ifaces[1].name == "wan2"  # fully from discovery

  test "build_preserves_existing_policy":
    let wans = @[
      DiscoveredWan(name: "wan", device: "wan", proto: "dhcp"),
    ]
    let globals = defaultGlobals()
    let existingPolicy = PolicyConfig(name: "custom", members: @["wan_primary"],
                                       lastResort: lrUnreachable)
    let (_, _, policies, _) = buildDiscoveredConfig(
      wans, globals, @[], @[], @[existingPolicy], @[])

    doAssert policies.len == 1
    doAssert policies[0].name == "custom"  # preserved, not overwritten

  test "globals_inheritance":
    var globals = defaultGlobals()
    globals.trackMethod = tmDns
    globals.trackIp = @["9.9.9.9"]
    globals.probeInterval = 10

    var iface = InterfaceConfig(name: "wan", device: "wan")
    # probeInterval is 0 (unset), should inherit
    applyGlobalsDefaults(iface, globals)
    doAssert iface.trackMethod == tmDns
    doAssert iface.trackIp == @["9.9.9.9"]
    doAssert iface.probeInterval == 10

  echo ""
  echo "=== Results ==="
  echo "  Passed: ", passed
  echo "  Failed: ", failed
  if failed > 0:
    quit(1)
  else:
    echo "  All tests passed!"
