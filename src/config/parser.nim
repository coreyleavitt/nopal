## UCI config parser for /etc/config/nopal.
##
## Parses OpenWrt UCI config files and produces a validated NopalConfig.

import schema
import ../errors
import std/[tables, sets, strutils, parseutils, net, logging]

type
  UciSection* = object
    sectionType*: string
    name*: string  ## empty if unnamed
    options*: Table[string, seq[string]]

proc get*(s: UciSection, key: string): string =
  ## Return first value for key, or "" if missing.
  if key in s.options and s.options[key].len > 0:
    return s.options[key][0]
  return ""

proc getAll*(s: UciSection, key: string): seq[string] =
  ## Return all values for key, or empty seq if missing.
  if key in s.options:
    return s.options[key]
  return @[]

proc getU32*(s: UciSection, key: string, default: uint32): uint32 =
  ## Parse a uint32 from the first value of key, or return default.
  let v = s.get(key)
  if v == "":
    return default
  try:
    let parsed = parseUInt(v)
    return uint32(parsed)
  except ValueError:
    return default

proc getBool*(s: UciSection, key: string, default: bool): bool =
  ## Parse a boolean value. Recognizes 1/yes/true/on and 0/no/false/off.
  let v = s.get(key).toLowerAscii()
  if v == "":
    return default
  case v
  of "1", "yes", "true", "on":
    return true
  of "0", "no", "false", "off":
    return false
  else:
    return default

proc stripQuotes*(s: string): string =
  ## Strip matching single or double quotes from start and end.
  if s.len >= 2:
    if (s[0] == '"' and s[^1] == '"') or (s[0] == '\'' and s[^1] == '\''):
      return s[1 ..< s.len - 1]
  return s

proc validateName*(kind, name: string) =
  ## Raise ConfigError if name is empty, contains /\0/.., or non-[a-zA-Z0-9_.-].
  if name.len == 0:
    raise newException(ConfigError, kind & " name must not be empty")
  if ".." in name:
    raise newException(ConfigError, kind & " name '" & name & "' contains '..'")
  for c in name:
    if c == '/' or c == '\0':
      raise newException(ConfigError, kind & " name '" & name & "' contains invalid character '" & $c & "'")
    if not (c in {'a'..'z', 'A'..'Z', '0'..'9', '_', '.', '-'}):
      raise newException(ConfigError, kind & " name '" & name & "' contains invalid character '" & $c & "'")

proc parseUci*(text: string): seq[UciSection] =
  ## Tokenize UCI text into sections. Handle config/option/list directives.
  ## Skip blanks and comments. Raise on option outside section.
  result = @[]
  var current: ptr UciSection = nil
  var lineNum = 0

  for rawLine in text.splitLines():
    inc lineNum
    let line = rawLine.strip()

    # Skip blanks and comments
    if line.len == 0 or line[0] == '#':
      continue

    let parts = line.splitWhitespace()
    if parts.len == 0:
      continue

    let directive = parts[0]

    case directive
    of "config":
      if parts.len < 2:
        raise newException(ConfigError, "line " & $lineNum & ": config directive requires a type")
      var sec = UciSection(
        sectionType: stripQuotes(parts[1]),
        name: "",
        options: initTable[string, seq[string]](),
      )
      if parts.len >= 3:
        sec.name = stripQuotes(parts[2])
      result.add(sec)
      current = addr result[result.len - 1]

    of "option":
      if current == nil:
        raise newException(ConfigError, "line " & $lineNum & ": option outside of section")
      if parts.len < 3:
        raise newException(ConfigError, "line " & $lineNum & ": option directive requires key and value")
      let key = stripQuotes(parts[1])
      # Value is everything after the key, joined and stripped of quotes
      let value = stripQuotes(parts[2 ..< parts.len].join(" "))
      current[].options[key] = @[value]

    of "list":
      if current == nil:
        raise newException(ConfigError, "line " & $lineNum & ": list outside of section")
      if parts.len < 3:
        raise newException(ConfigError, "line " & $lineNum & ": list directive requires key and value")
      let key = stripQuotes(parts[1])
      let value = stripQuotes(parts[2 ..< parts.len].join(" "))
      if key in current[].options:
        current[].options[key].add(value)
      else:
        current[].options[key] = @[value]

    else:
      raise newException(ConfigError, "line " & $lineNum & ": unknown directive '" & directive & "'")

proc isContiguousBits(mask: uint32): bool =
  ## Check that a bitmask has contiguous set bits (no gaps).
  if mask == 0:
    return false
  # A contiguous mask + its lowest bit forms a power of 2
  let filled = mask or (mask - 1)  # fill bits below lowest set bit
  return (filled and (filled + 1)) == 0

proc parseGlobals*(sec: UciSection): GlobalsConfig =
  ## Convert a UCI section of type 'globals' to GlobalsConfig.
  result = defaultGlobals()
  result.enabled = sec.getBool("enabled", result.enabled)
  let ll = sec.get("log_level")
  if ll != "":
    result.logLevel = ll
  result.logging = sec.getBool("logging", result.logging)
  result.ipv6Enabled = sec.getBool("ipv6_enabled", result.ipv6Enabled)

  let ipcSock = sec.get("ipc_socket")
  if ipcSock != "":
    result.ipcSocket = ipcSock

  let hook = sec.get("hook_script")
  if hook != "":
    result.hookScript = hook

  let flushStr = sec.get("conntrack_flush")
  if flushStr != "":
    case flushStr.toLowerAscii()
    of "none", "0":
      result.conntrackFlush = cfmNone
    of "selective":
      result.conntrackFlush = cfmSelective
    of "full":
      result.conntrackFlush = cfmFull
    else:
      warn "Unknown conntrack_flush value '" & flushStr & "', using default"

  # Parse mark_mask (hex)
  let maskStr = sec.get("mark_mask")
  if maskStr != "":
    try:
      let parsed = parseHexInt(maskStr)
      result.markMask = uint32(parsed)
    except ValueError:
      raise newException(ConfigError, "globals: invalid mark_mask '" & maskStr & "' (expected hex like 0xFF00)")

  if result.markMask == 0:
    raise newException(ConfigError, "globals: mark_mask must not be zero")

  if not isContiguousBits(result.markMask):
    raise newException(ConfigError, "globals: mark_mask 0x" & toHex(result.markMask) & " must have contiguous bits")

  # rt_table_lookup
  for v in sec.getAll("rt_table_lookup"):
    try:
      result.rtTableLookup.add(uint32(parseUInt(v)))
    except ValueError:
      warn "Ignoring invalid rt_table_lookup value '" & v & "'"

proc mapTrackMethod(s: string, ifaceName: string): TrackMethod =
  ## Map a string to TrackMethod, with mwan3 compatibility warnings.
  case s.toLowerAscii()
  of "ping":
    return tmPing
  of "dns":
    return tmDns
  of "http":
    return tmHttp
  of "https":
    return tmHttps
  of "arping":
    return tmArping
  of "composite":
    return tmComposite
  # mwan3 compatibility
  of "nping-tcp":
    warn "interface '" & ifaceName & "': track_method 'nping-tcp' is not supported, using 'http' instead"
    return tmHttp
  of "nping-udp":
    warn "interface '" & ifaceName & "': track_method 'nping-udp' is not supported, using 'dns' instead"
    return tmDns
  of "nping-icmp":
    warn "interface '" & ifaceName & "': track_method 'nping-icmp' is not supported, using 'ping' instead"
    return tmPing
  else:
    raise newException(ConfigError, "interface '" & ifaceName & "': unknown track_method '" & s & "'")

proc parseFlushTrigger(s: string): ConntrackFlushTrigger =
  case s.toLowerAscii()
  of "ifup":
    return cftIfUp
  of "ifdown":
    return cftIfDown
  of "connected":
    return cftConnected
  of "disconnected":
    return cftDisconnected
  else:
    raise newException(ConfigError, "unknown flush_conntrack trigger '" & s & "'")

proc parseInterface*(sec: UciSection): InterfaceConfig =
  ## Convert a UCI section of type 'interface' to InterfaceConfig.
  result = defaultInterface()

  if sec.name == "":
    raise newException(ConfigError, "interface section must have a name")
  validateName("interface", sec.name)
  result.name = sec.name

  # mwan3 field name warnings
  if sec.get("track_ip") == "" and sec.getAll("track_ip").len == 0:
    # Check for mwan3-style 'track_ip' as option vs list - handled below
    discard
  if sec.get("list_type") != "":
    warn "interface '" & sec.name & "': 'list_type' is an mwan3 field, ignored by nopal"

  result.enabled = sec.getBool("enabled", result.enabled)

  let dev = sec.get("device")
  if dev != "":
    result.device = dev

  let familyStr = sec.get("family")
  if familyStr != "":
    case familyStr.toLowerAscii()
    of "ipv4":
      result.family = afIpv4
    of "ipv6":
      result.family = afIpv6
    of "both":
      result.family = afBoth
    else:
      raise newException(ConfigError, "interface '" & sec.name & "': unknown family '" & familyStr & "'")

  result.metric = sec.getU32("metric", result.metric)
  result.weight = sec.getU32("weight", result.weight)
  if result.weight == 0:
    result.weight = 1

  let methodStr = sec.get("track_method")
  if methodStr != "":
    result.trackMethod = mapTrackMethod(methodStr, sec.name)

  # track_ip can be option (single) or list (multiple)
  let trackIps = sec.getAll("track_ip")
  for ip in trackIps:
    try:
      discard parseIpAddress(ip)
      result.trackIp.add(ip)
    except ValueError:
      raise newException(ConfigError, "interface '" & sec.name & "': invalid track_ip '" & ip & "'")

  result.trackPort = int(sec.getU32("track_port", uint32(result.trackPort)))
  result.reliability = sec.getU32("reliability", result.reliability)
  result.probeInterval = sec.getU32("probe_interval", result.probeInterval)
  # Clamp probe_interval
  result.probeInterval = clamp(result.probeInterval, 1'u32, 3600'u32)

  result.failureInterval = int(sec.getU32("failure_interval", uint32(result.failureInterval)))
  result.recoveryInterval = int(sec.getU32("recovery_interval", uint32(result.recoveryInterval)))
  result.keepFailureInterval = sec.getBool("keep_failure_interval", result.keepFailureInterval)
  result.probeTimeout = sec.getU32("probe_timeout", result.probeTimeout)
  result.probeTimeout = clamp(result.probeTimeout, 1'u32, 60'u32)

  result.count = sec.getU32("count", result.count)
  result.count = clamp(result.count, 1'u32, 100'u32)

  result.maxTtl = sec.getU32("max_ttl", result.maxTtl)
  result.probeSize = sec.getU32("probe_size", result.probeSize)
  result.probeSize = clamp(result.probeSize, 0'u32, 65507'u32)

  result.upCount = sec.getU32("up", result.upCount)
  result.upCount = clamp(result.upCount, 1'u32, 100'u32)
  result.downCount = sec.getU32("down", result.downCount)
  result.downCount = clamp(result.downCount, 1'u32, 100'u32)

  let initStr = sec.get("initial_state")
  if initStr != "":
    case initStr.toLowerAscii()
    of "offline":
      result.initialState = isOffline
    of "online":
      result.initialState = isOnline
    else:
      warn "interface '" & sec.name & "': unknown initial_state '" & initStr & "', using offline"

  result.checkQuality = sec.getBool("check_quality", result.checkQuality)
  result.latencyThreshold = int(sec.getU32("latency_threshold", uint32(result.latencyThreshold)))
  result.lossThreshold = int(sec.getU32("loss_threshold", uint32(result.lossThreshold)))
  result.recoveryLatency = int(sec.getU32("recovery_latency", uint32(result.recoveryLatency)))
  result.recoveryLoss = int(sec.getU32("recovery_loss", uint32(result.recoveryLoss)))
  result.qualityWindow = sec.getU32("quality_window", result.qualityWindow)
  result.qualityWindow = clamp(result.qualityWindow, 1'u32, 1000'u32)

  result.dampening = sec.getBool("dampening", result.dampening)
  result.dampeningHalflife = sec.getU32("dampening_halflife", result.dampeningHalflife)
  result.dampeningCeiling = sec.getU32("dampening_ceiling", result.dampeningCeiling)
  result.dampeningSuppress = sec.getU32("dampening_suppress", result.dampeningSuppress)
  result.dampeningReuse = sec.getU32("dampening_reuse", result.dampeningReuse)

  let dqn = sec.get("dns_query_name")
  if dqn != "":
    if dqn.len > 253:
      raise newException(ConfigError, "interface '" & sec.name & "': dns_query_name too long (max 253)")
    result.dnsQueryName = dqn

  result.localSource = sec.getBool("local_source", result.localSource)
  result.updateDns = sec.getBool("update_dns", result.updateDns)
  result.clampMss = sec.getBool("clamp_mss", result.clampMss)

  for ds in sec.getAll("dns_server"):
    try:
      discard parseIpAddress(ds)
      result.dnsServers.add(ds)
    except ValueError:
      raise newException(ConfigError, "interface '" & sec.name & "': invalid dns_server '" & ds & "'")

  # flush_conntrack list
  let flushList = sec.getAll("flush_conntrack")
  if flushList.len > 0:
    result.flushConntrack = @[]
    for ft in flushList:
      result.flushConntrack.add(parseFlushTrigger(ft))

proc parseMember*(sec: UciSection): MemberConfig =
  ## Convert a UCI section of type 'member' to MemberConfig.
  if sec.name == "":
    raise newException(ConfigError, "member section must have a name")
  validateName("member", sec.name)

  let ifaceName = sec.get("interface")
  if ifaceName == "":
    raise newException(ConfigError, "member '" & sec.name & "': 'interface' field is required")

  result = MemberConfig(
    name: sec.name,
    `interface`: ifaceName,
    metric: sec.getU32("metric", 0),
    weight: sec.getU32("weight", 1),
  )
  if result.weight == 0:
    result.weight = 1

proc parsePolicy*(sec: UciSection): PolicyConfig =
  ## Convert a UCI section of type 'policy' to PolicyConfig.
  if sec.name == "":
    raise newException(ConfigError, "policy section must have a name")
  validateName("policy", sec.name)

  result = PolicyConfig(
    name: sec.name,
    members: sec.getAll("use_member"),
    lastResort: lrDefault,
  )

  let lr = sec.get("last_resort")
  if lr != "":
    case lr.toLowerAscii()
    of "default":
      result.lastResort = lrDefault
    of "unreachable":
      result.lastResort = lrUnreachable
    of "blackhole":
      result.lastResort = lrBlackhole
    else:
      warn "policy '" & sec.name & "': unknown last_resort '" & lr & "', using default"

proc validatePortSpec(spec: string, context: string) =
  ## Validate a port specification: either a single u16 or a range "lo-hi".
  if spec == "":
    return
  let parts = spec.split('-')
  if parts.len == 1:
    try:
      let p = parseInt(parts[0])
      if p < 0 or p > 65535:
        raise newException(ConfigError, context & ": port " & parts[0] & " out of range (0-65535)")
    except ValueError:
      raise newException(ConfigError, context & ": invalid port '" & parts[0] & "'")
  elif parts.len == 2:
    var lo, hi: int
    try:
      lo = parseInt(parts[0])
    except ValueError:
      raise newException(ConfigError, context & ": invalid port range start '" & parts[0] & "'")
    try:
      hi = parseInt(parts[1])
    except ValueError:
      raise newException(ConfigError, context & ": invalid port range end '" & parts[1] & "'")
    if lo < 0 or lo > 65535 or hi < 0 or hi > 65535:
      raise newException(ConfigError, context & ": port range out of bounds")
    if lo > hi:
      raise newException(ConfigError, context & ": port range start (" & $lo & ") > end (" & $hi & ")")
  else:
    raise newException(ConfigError, context & ": invalid port specification '" & spec & "'")

proc validateCidr(s: string, context: string) =
  ## Validate an IP address or CIDR notation (addr/prefix).
  let slashIdx = s.find('/')
  if slashIdx >= 0:
    let addrPart = s[0 ..< slashIdx]
    let prefixPart = s[slashIdx + 1 ..< s.len]
    try:
      let ipAddr = parseIpAddress(addrPart)
      let prefix = parseInt(prefixPart)
      let maxPrefix = if ipAddr.family == IpAddressFamily.IPv4: 32 else: 128
      if prefix < 0 or prefix > maxPrefix:
        raise newException(ConfigError, context & ": prefix length " & $prefix & " out of range for " & s)
    except ValueError:
      raise newException(ConfigError, context & ": invalid CIDR '" & s & "'")
  else:
    try:
      discard parseIpAddress(s)
    except ValueError:
      raise newException(ConfigError, context & ": invalid IP address '" & s & "'")

proc parseRule*(sec: UciSection): RuleConfig =
  ## Convert a UCI section of type 'rule' to RuleConfig.
  if sec.name == "":
    raise newException(ConfigError, "rule section must have a name")
  validateName("rule", sec.name)

  result = defaultRule()
  result.name = sec.name

  let ctx = "rule '" & sec.name & "'"

  # src_ip (list)
  for ip in sec.getAll("src_ip"):
    validateCidr(ip, ctx)
    result.srcIp.add(ip)

  # dest_ip (list)
  for ip in sec.getAll("dest_ip"):
    validateCidr(ip, ctx)
    result.destIp.add(ip)

  # src_port
  let srcPort = sec.get("src_port")
  if srcPort != "":
    validatePortSpec(srcPort, ctx)
    result.srcPort = srcPort

  # dest_port
  let destPort = sec.get("dest_port")
  if destPort != "":
    validatePortSpec(destPort, ctx)
    result.destPort = destPort

  # proto
  let proto = sec.get("proto")
  if proto != "":
    case proto.toLowerAscii()
    of "tcp", "udp", "icmp", "all":
      result.proto = proto.toLowerAscii()
    else:
      # Allow numeric protocol numbers
      try:
        let pnum = parseInt(proto)
        if pnum < 0 or pnum > 255:
          raise newException(ConfigError, ctx & ": protocol number " & $pnum & " out of range (0-255)")
        result.proto = proto
      except ValueError:
        raise newException(ConfigError, ctx & ": unknown protocol '" & proto & "'")

  # family
  let familyStr = sec.get("family")
  if familyStr != "":
    case familyStr.toLowerAscii()
    of "any":
      result.family = rfAny
    of "ipv4":
      result.family = rfIpv4
    of "ipv6":
      result.family = rfIpv6
    else:
      raise newException(ConfigError, ctx & ": unknown family '" & familyStr & "'")

  # src_iface
  let srcIface = sec.get("src_iface")
  if srcIface != "":
    validateName("src_iface", srcIface)
    result.srcIface = srcIface

  # ipset
  let ipset = sec.get("ipset")
  if ipset != "":
    result.ipset = ipset

  # sticky
  result.sticky = sec.getBool("sticky", result.sticky)
  result.stickyTimeout = sec.getU32("sticky_timeout", result.stickyTimeout)

  let stickyModeStr = sec.get("sticky_mode")
  if stickyModeStr != "":
    case stickyModeStr.toLowerAscii()
    of "flow":
      result.stickyMode = smFlow
    of "src_ip", "srcip":
      result.stickyMode = smSrcIp
    of "src_dst", "srcdst":
      result.stickyMode = smSrcDst
    else:
      warn ctx & ": unknown sticky_mode '" & stickyModeStr & "', using flow"

  # use_policy (required for rules that route traffic)
  let usePolicy = sec.get("use_policy")
  if usePolicy != "":
    result.usePolicy = usePolicy

  result.log = sec.getBool("log", result.log)

proc validate*(config: var NopalConfig) =
  ## Validate cross-references and uniqueness in the config.

  # Check duplicate interface names
  var ifaceNames = initHashSet[string]()
  for iface in config.interfaces:
    if iface.name in ifaceNames:
      raise newException(ConfigError, "duplicate interface name '" & iface.name & "'")
    ifaceNames.incl(iface.name)

  # Check duplicate member names
  var memberNames = initHashSet[string]()
  for member in config.members:
    if member.name in memberNames:
      raise newException(ConfigError, "duplicate member name '" & member.name & "'")
    memberNames.incl(member.name)

  # Check duplicate policy names
  var policyNames = initHashSet[string]()
  for policy in config.policies:
    if policy.name in policyNames:
      raise newException(ConfigError, "duplicate policy name '" & policy.name & "'")
    policyNames.incl(policy.name)

  # Check duplicate rule names
  var ruleNames = initHashSet[string]()
  for rule in config.rules:
    if rule.name in ruleNames:
      raise newException(ConfigError, "duplicate rule name '" & rule.name & "'")
    ruleNames.incl(rule.name)

  # Members must reference existing interfaces
  for member in config.members:
    if member.`interface` notin ifaceNames:
      raise newException(ConfigError, "member '" & member.name & "' references non-existent interface '" & member.`interface` & "'")

  # Policies must reference existing members
  for policy in config.policies:
    for memberName in policy.members:
      if memberName notin memberNames:
        raise newException(ConfigError, "policy '" & policy.name & "' references non-existent member '" & memberName & "'")

  # Rules must reference existing policies (unless "default")
  for rule in config.rules:
    if rule.usePolicy != "" and rule.usePolicy != "default":
      if rule.usePolicy notin policyNames:
        raise newException(ConfigError, "rule '" & rule.name & "' references non-existent policy '" & rule.usePolicy & "'")

  # Warn on interfaces with no track_ip
  for iface in config.interfaces:
    if iface.enabled and iface.trackIp.len == 0:
      warn "interface '" & iface.name & "' has no track_ip configured, probes will not run"

proc loadFromStr*(text: string): NopalConfig =
  ## Parse UCI text and return a validated NopalConfig.
  let sections = parseUci(text)

  result = NopalConfig(
    globals: defaultGlobals(),
  )

  for sec in sections:
    case sec.sectionType
    of "globals":
      result.globals = parseGlobals(sec)
    of "interface":
      result.interfaces.add(parseInterface(sec))
    of "member":
      result.members.add(parseMember(sec))
    of "policy":
      result.policies.add(parsePolicy(sec))
    of "rule":
      result.rules.add(parseRule(sec))
    else:
      warn "unknown section type '" & sec.sectionType & "', skipping"

  validate(result)

proc loadConfig*(path: string): NopalConfig =
  ## Read a UCI config file and parse it.
  let text = try:
    readFile(path)
  except IOError:
    raise newException(ConfigError, "cannot read config file '" & path & "'")
  return loadFromStr(text)


when isMainModule:
  import std/unittest

  const sampleConfig = """
config globals globals
  option enabled '1'
  option mark_mask '0xFF00'
  option log_level 'info'

config interface wan1
  option enabled '1'
  option device 'eth0'
  option track_method 'ping'
  list track_ip '8.8.8.8'
  list track_ip '8.8.4.4'
  option reliability '2'
  option probe_interval '5'
  option probe_timeout '2'
  option down '3'
  option up '3'
  option metric '10'
  option weight '3'

config interface wan2
  option enabled '1'
  option device 'eth1'
  option track_method 'dns'
  list track_ip '1.1.1.1'
  option reliability '1'
  option probe_interval '5'
  option probe_timeout '2'
  option down '3'
  option up '3'
  option metric '20'
  option weight '2'

config member wan1_m1
  option interface 'wan1'
  option metric '10'
  option weight '3'

config member wan2_m1
  option interface 'wan2'
  option metric '10'
  option weight '2'

config policy balanced
  list use_member 'wan1_m1'
  list use_member 'wan2_m1'
  option last_resort 'unreachable'

config rule default_rule
  option use_policy 'balanced'
  option proto 'all'
"""

  suite "UCI Config Parser":
    test "parse_sample_config":
      let cfg = loadFromStr(sampleConfig)
      check cfg.globals.enabled == true
      check cfg.globals.markMask == 0xFF00'u32
      check cfg.globals.logLevel == "info"
      check cfg.interfaces.len == 2
      check cfg.interfaces[0].name == "wan1"
      check cfg.interfaces[0].device == "eth0"
      check cfg.interfaces[0].trackMethod == tmPing
      check cfg.interfaces[0].trackIp == @["8.8.8.8", "8.8.4.4"]
      check cfg.interfaces[0].reliability == 2'u32
      check cfg.interfaces[0].metric == 10'u32
      check cfg.interfaces[0].weight == 3'u32
      check cfg.interfaces[1].name == "wan2"
      check cfg.interfaces[1].device == "eth1"
      check cfg.interfaces[1].trackMethod == tmDns
      check cfg.interfaces[1].trackIp == @["1.1.1.1"]
      check cfg.interfaces[1].weight == 2'u32
      check cfg.members.len == 2
      check cfg.members[0].name == "wan1_m1"
      check cfg.members[0].`interface` == "wan1"
      check cfg.members[1].name == "wan2_m1"
      check cfg.policies.len == 1
      check cfg.policies[0].name == "balanced"
      check cfg.policies[0].members == @["wan1_m1", "wan2_m1"]
      check cfg.policies[0].lastResort == lrUnreachable
      check cfg.rules.len == 1
      check cfg.rules[0].name == "default_rule"
      check cfg.rules[0].usePolicy == "balanced"
      check cfg.rules[0].proto == "all"

    test "parse_empty_config":
      let cfg = loadFromStr("")
      check cfg.interfaces.len == 0
      check cfg.members.len == 0
      check cfg.policies.len == 0
      check cfg.rules.len == 0

    test "parse_comments_and_blanks":
      let text = """
# This is a comment

  # Indented comment

config globals globals
  option enabled '1'
  option mark_mask '0xFF00'
"""
      let cfg = loadFromStr(text)
      check cfg.globals.enabled == true

    test "option_outside_section_is_error":
      let text = "option enabled '1'\n"
      expect ConfigError:
        discard loadFromStr(text)

    test "unquoted_values":
      let text = """
config globals globals
  option enabled 1
  option mark_mask 0xFF00
"""
      let cfg = loadFromStr(text)
      check cfg.globals.enabled == true
      check cfg.globals.markMask == 0xFF00'u32

    test "double_quoted_values":
      let text = """
config globals globals
  option enabled "1"
  option mark_mask "0xFF00"
"""
      let cfg = loadFromStr(text)
      check cfg.globals.enabled == true
      check cfg.globals.markMask == 0xFF00'u32

    test "strip_quotes_helper":
      check stripQuotes("'hello'") == "hello"
      check stripQuotes("\"hello\"") == "hello"
      check stripQuotes("hello") == "hello"
      check stripQuotes("'") == "'"
      check stripQuotes("''") == ""
      check stripQuotes("\"\"") == ""
      check stripQuotes("'mixed\"") == "'mixed\""

    test "member_missing_interface_is_error":
      let text = """
config member bad_member
  option metric '10'
"""
      expect ConfigError:
        discard loadFromStr(text)

    test "rule_missing_policy_is_error":
      # A rule without use_policy is allowed (empty string),
      # but a rule referencing a non-existent policy is an error.
      # This test verifies that referencing a bad policy fails.
      let text = """
config rule bad_rule
  option use_policy 'nonexistent_policy'
"""
      expect ConfigError:
        discard loadFromStr(text)

    test "duplicate_interface_name_is_error":
      let text = """
config interface wan1
  option device 'eth0'
  list track_ip '8.8.8.8'

config interface wan1
  option device 'eth1'
  list track_ip '1.1.1.1'
"""
      expect ConfigError:
        discard loadFromStr(text)

    test "member_references_nonexistent_interface":
      let text = """
config interface wan1
  option device 'eth0'
  list track_ip '8.8.8.8'

config member m1
  option interface 'nonexistent'
  option metric '10'
"""
      expect ConfigError:
        discard loadFromStr(text)

    test "policy_references_nonexistent_member":
      let text = """
config interface wan1
  option device 'eth0'
  list track_ip '8.8.8.8'

config member m1
  option interface 'wan1'

config policy p1
  list use_member 'nonexistent'
"""
      expect ConfigError:
        discard loadFromStr(text)

    test "rule_references_nonexistent_policy":
      let text = """
config interface wan1
  option device 'eth0'
  list track_ip '8.8.8.8'

config rule r1
  option use_policy 'nonexistent'
"""
      expect ConfigError:
        discard loadFromStr(text)

    test "rule_with_use_policy_default_is_valid":
      let text = """
config interface wan1
  option device 'eth0'
  list track_ip '8.8.8.8'

config rule r1
  option use_policy 'default'
  option proto 'tcp'
"""
      let cfg = loadFromStr(text)
      check cfg.rules.len == 1
      check cfg.rules[0].usePolicy == "default"

    test "valid_cross_references_pass":
      let text = """
config interface wan1
  option device 'eth0'
  list track_ip '8.8.8.8'

config interface wan2
  option device 'eth1'
  list track_ip '1.1.1.1'

config member m1
  option interface 'wan1'
  option metric '10'

config member m2
  option interface 'wan2'
  option metric '20'

config policy balanced
  list use_member 'm1'
  list use_member 'm2'

config rule r1
  option use_policy 'balanced'
"""
      let cfg = loadFromStr(text)
      check cfg.interfaces.len == 2
      check cfg.members.len == 2
      check cfg.policies.len == 1
      check cfg.rules.len == 1
