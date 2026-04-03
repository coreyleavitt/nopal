## UCI config parser for /etc/config/nopal.
##
## Parses OpenWrt UCI config files and produces a validated NopalConfig.

import ./schema
import ../errors
import std/[tables, sets, strutils, strformat, options, logging]

type
  UciSection* = object
    sectionType*: string
    name*: string  ## empty if unnamed
    options*: Table[string, seq[string]]

func get*(s: UciSection, key: string): string =
  ## Return first value for key, or "" if missing.
  if key in s.options and s.options[key].len > 0:
    return s.options[key][0]
  return ""

func getAll*(s: UciSection, key: string): seq[string] =
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
    if parsed > uint32.high:
      return default
    return uint32(parsed)
  except ValueError:
    return default

func getBool*(s: UciSection, key: string, default: bool): bool =
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

func stripQuotes*(s: string): string =
  ## Strip matching single or double quotes from start and end.
  if s.len >= 2:
    if (s[0] == '"' and s[^1] == '"') or (s[0] == '\'' and s[^1] == '\''):
      return s[1 ..< s.len - 1]
  return s

func isValidIpv4(s: string): bool {.raises: [].} =
  ## Validate an IPv4 address: 4 dot-separated octets 0-255, no leading zeros.
  let parts = s.split('.')
  if parts.len != 4:
    return false
  for part in parts:
    if part.len == 0 or part.len > 3:
      return false
    # No leading zeros (except "0" itself)
    if part.len > 1 and part[0] == '0':
      return false
    for c in part:
      if c < '0' or c > '9':
        return false
    # Manual int conversion (already validated digits above, avoids parseInt raises)
    var val = 0
    for c in part:
      val = val * 10 + (ord(c) - ord('0'))
    if val > 255:
      return false
  return true

func isValidIpv6(s: string): bool {.raises: [].} =
  ## Validate an IPv6 address with optional :: compression and mixed notation.
  if s.len == 0:
    return false

  # Check for mixed notation (IPv6 with embedded IPv4 at the end)
  # e.g. ::ffff:192.168.1.1 or 64:ff9b::192.168.1.1
  if '.' in s:
    # Find the start of the IPv4 part by scanning backwards for a colon
    # that is followed by a digit (not another colon)
    var splitPos = -1
    for i in countdown(s.len - 1, 0):
      if s[i] == ':':
        splitPos = i
        break
    if splitPos < 0:
      return false
    let ipv4Part = s[splitPos + 1 ..< s.len]
    if not isValidIpv4(ipv4Part):
      return false
    # The prefix is the IPv6 portion including trailing colon
    # Strip the trailing colon to get just the hex groups
    let prefix = s[0 ..< splitPos]
    # Validate the prefix as IPv6 groups (with :: allowed)
    # IPv4 replaces the last 2 of 8 groups, so prefix can have at most 6
    let dcCount = prefix.count("::")
    if dcCount > 1:
      return false
    if dcCount == 1:
      let dcParts = prefix.split("::")
      var groupCount = 0
      for p in dcParts:
        if p.len > 0:
          for g in p.split(':'):
            if g.len == 0 or g.len > 4: return false
            for c in g:
              if c notin {'0'..'9', 'a'..'f', 'A'..'F'}: return false
            inc groupCount
      if groupCount > 6: return false
    else:
      # No :: — must have exactly 6 explicit groups
      if prefix.len == 0: return false
      let groups = prefix.split(':')
      for g in groups:
        if g.len == 0 or g.len > 4: return false
        for c in g:
          if c notin {'0'..'9', 'a'..'f', 'A'..'F'}: return false
      if groups.len != 6: return false
    return true

  # Pure IPv6 validation
  let dcCount = s.count("::")
  if dcCount > 1:
    return false

  if dcCount == 1:
    let dcParts = s.split("::")
    var groupCount = 0
    for p in dcParts:
      if p.len > 0:
        for g in p.split(':'):
          if g.len == 0 or g.len > 4:
            return false
          for c in g:
            if c notin {'0'..'9', 'a'..'f', 'A'..'F'}:
              return false
          inc groupCount
    if groupCount >= 8:
      return false
  else:
    let groups = s.split(':')
    if groups.len != 8:
      return false
    for g in groups:
      if g.len == 0 or g.len > 4:
        return false
      for c in g:
        if c notin {'0'..'9', 'a'..'f', 'A'..'F'}:
          return false
  return true

func isValidIpAddress*(s: string): bool {.raises: [].} =
  ## Validate an IPv4 or IPv6 address string.
  return isValidIpv4(s) or isValidIpv6(s)

func isIpv6*(s: string): bool {.raises: [].} =
  ## Check whether a valid IP address string is IPv6.
  ## Assumes s is a valid IP address (call isValidIpAddress first).
  return ':' in s

proc validateName*(kind, name: string) =
  ## Raise ConfigError if name is empty, contains /\0/.., or non-[a-zA-Z0-9_.-].
  if name.len == 0:
    raise newException(ConfigError, fmt"{kind} name must not be empty")
  if ".." in name:
    raise newException(ConfigError, fmt"{kind} name '{name}' contains '..'")
  for c in name:
    if c == '/' or c == '\0':
      raise newException(ConfigError, fmt"{kind} name '{name}' contains invalid character '{c}'")
    if not (c in {'a'..'z', 'A'..'Z', '0'..'9', '_', '.', '-'}):
      raise newException(ConfigError, fmt"{kind} name '{name}' contains invalid character '{c}'")

proc parseUci*(text: string): seq[UciSection] =
  ## Tokenize UCI text into sections. Handle config/option/list directives.
  ## Skip blanks and comments. Raise on option outside section.
  result = @[]
  var currentIdx = -1
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
        raise newException(ConfigError, fmt"line {lineNum}: config directive requires a type")
      var sec = UciSection(
        sectionType: stripQuotes(parts[1]),
        name: "",
        options: initTable[string, seq[string]](),
      )
      if parts.len >= 3:
        sec.name = stripQuotes(parts[2])
      result.add(sec)
      currentIdx = result.len - 1

    of "option":
      if currentIdx < 0:
        raise newException(ConfigError, fmt"line {lineNum}: option outside of section")
      if parts.len < 2:
        raise newException(ConfigError, fmt"line {lineNum}: option directive requires a key")
      let key = stripQuotes(parts[1])
      let value = if parts.len >= 3: stripQuotes(parts[2 ..< parts.len].join(" ")) else: ""
      result[currentIdx].options[key] = @[value]

    of "list":
      if currentIdx < 0:
        raise newException(ConfigError, fmt"line {lineNum}: list outside of section")
      if parts.len < 2:
        raise newException(ConfigError, fmt"line {lineNum}: list directive requires a key")
      let key = stripQuotes(parts[1])
      let value = if parts.len >= 3: stripQuotes(parts[2 ..< parts.len].join(" ")) else: ""
      if key in result[currentIdx].options:
        result[currentIdx].options[key].add(value)
      else:
        result[currentIdx].options[key] = @[value]

    else:
      warn fmt"line {lineNum}: unknown directive '{directive}', skipping"
      continue

func isValidMarkMask(mask: uint32): bool {.raises: [].} =
  ## Check that a bitmask has contiguous set bits and at least 2 usable slots.
  if mask == 0:
    return false
  let filled = mask or (mask - 1)  # fill bits below lowest set bit
  if (filled and (filled + 1)) != 0:
    return false  # non-contiguous
  let step = mask and (not mask + 1)  # lowest set bit
  mask div step >= 2

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
    warn fmt"interface '{ifaceName}': track_method 'nping-tcp' is not supported, using 'http' instead"
    return tmHttp
  of "nping-udp":
    warn fmt"interface '{ifaceName}': track_method 'nping-udp' is not supported, using 'dns' instead"
    return tmDns
  of "nping-icmp":
    warn fmt"interface '{ifaceName}': track_method 'nping-icmp' is not supported, using 'ping' instead"
    return tmPing
  of "nping-arp":
    warn fmt"interface '{ifaceName}': track_method 'nping-arp' is not supported, using 'arping' instead"
    return tmArping
  else:
    warn fmt"interface '{ifaceName}': unknown track_method '{s}', using 'ping'"
    return tmPing

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
      warn fmt"Unknown conntrack_flush value '{flushStr}', using default"

  # Parse mark_mask (hex)
  let maskStr = sec.get("mark_mask")
  if maskStr != "":
    try:
      let parsed = parseHexInt(maskStr)
      result.markMask = uint32(parsed)
    except ValueError:
      warn fmt"globals: invalid mark_mask '{maskStr}' (expected hex like 0xFF00), using default"
      result.markMask = defaultGlobals().markMask

  if result.markMask == 0:
    warn "globals: mark_mask must not be zero, using default"
    result.markMask = defaultGlobals().markMask

  if not isValidMarkMask(result.markMask):
    warn fmt"globals: mark_mask 0x{toHex(result.markMask)} must have contiguous bits with >=2 slots, using default"
    result.markMask = defaultGlobals().markMask

  # Default probe settings (inherited by interfaces that don't override)
  let tm = sec.get("track_method")
  if tm != "":
    result.trackMethod = mapTrackMethod(tm, "globals")
  let ips = sec.getAll("track_ip")
  if ips.len > 0:
    result.trackIp = ips
  result.probeInterval = sec.getU32("probe_interval", result.probeInterval)
  result.probeTimeout = sec.getU32("probe_timeout", result.probeTimeout)
  result.upCount = sec.getU32("up_count", result.upCount)
  result.downCount = sec.getU32("down_count", result.downCount)

  # rt_table_lookup
  for v in sec.getAll("rt_table_lookup"):
    try:
      result.rtTableLookup.add(uint32(parseUInt(v)))
    except ValueError:
      warn fmt"Ignoring invalid rt_table_lookup value '{v}'"

func parseFlushTrigger(s: string): options.Option[ConntrackFlushTrigger] =
  case s.toLowerAscii()
  of "ifup": some(cftIfUp)
  of "ifdown": some(cftIfDown)
  of "connected": some(cftConnected)
  of "disconnected": some(cftDisconnected)
  else: none(ConntrackFlushTrigger)

proc parseInterface*(sec: UciSection): InterfaceConfig =
  ## Convert a UCI section of type 'interface' to InterfaceConfig.
  result = defaultInterface()

  if sec.name == "":
    raise newException(ConfigError, "interface section must have a name")
  validateName("interface", sec.name)
  result.name = sec.name

  # mwan3 field name warnings
  const mwan3Renames = [
    ("interval", "probe_interval"),
    ("timeout", "probe_timeout"),
    ("up", "up_count"),
    ("down", "down_count"),
    ("size", "probe_size"),
    ("failure_latency", "latency_threshold"),
    ("failure_loss", "loss_threshold"),
  ]
  for (oldName, newName) in mwan3Renames:
    if sec.get(oldName) != "":
      warn fmt"interface '{sec.name}': mwan3 option '{oldName}' has been renamed to '{newName}'"
  if sec.get("httping_ssl") != "":
    warn fmt"interface '{sec.name}': 'httping_ssl' is deprecated, use track_method 'https' instead"

  if sec.get("list_type") != "":
    warn fmt"interface '{sec.name}': 'list_type' is an mwan3 field, ignored by nopal"

  result.enabled = sec.getBool("enabled", result.enabled)

  let dev = sec.get("device")
  if dev != "":
    validateName("device", dev)
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
      raise newException(ConfigError, fmt"interface '{sec.name}': unknown family '{familyStr}'")

  result.metric = sec.getU32("metric", result.metric)
  result.weight = sec.getU32("weight", result.weight)
  result.weight = clamp(result.weight, 1'u32, 1000'u32)

  let methodStr = sec.get("track_method")
  if methodStr != "":
    result.trackMethod = mapTrackMethod(methodStr, sec.name)

  # track_ip can be option (single) or list (multiple)
  let trackIps = sec.getAll("track_ip")
  for ip in trackIps:
    if not isValidIpAddress(ip):
      warn fmt"interface '{sec.name}': invalid track_ip '{ip}', skipping"
      continue
    result.trackIp.add(ip)

  result.trackPort = int(sec.getU32("track_port", uint32(result.trackPort)))
  result.reliability = sec.getU32("reliability", result.reliability)
  result.probeInterval = sec.getU32("probe_interval", result.probeInterval)

  result.failureInterval = int(sec.getU32("failure_interval", uint32(result.failureInterval)))
  result.recoveryInterval = int(sec.getU32("recovery_interval", uint32(result.recoveryInterval)))
  result.keepFailureInterval = sec.getBool("keep_failure_interval", result.keepFailureInterval)
  result.probeTimeout = sec.getU32("probe_timeout", result.probeTimeout)

  result.count = sec.getU32("count", result.count)
  result.count = max(result.count, 1'u32)

  result.maxTtl = sec.getU32("max_ttl", result.maxTtl)
  result.maxTtl = clamp(result.maxTtl, 1'u32, 255'u32)
  result.probeSize = sec.getU32("probe_size", result.probeSize)
  result.probeSize = clamp(result.probeSize, 0'u32, 1400'u32)

  result.upCount = sec.getU32("up_count", result.upCount)
  result.upCount = max(result.upCount, 1'u32)
  result.downCount = sec.getU32("down_count", result.downCount)
  result.downCount = max(result.downCount, 1'u32)

  let initStr = sec.get("initial_state")
  if initStr != "":
    case initStr.toLowerAscii()
    of "offline":
      result.initialState = initOffline
    of "online":
      result.initialState = initOnline
    else:
      warn fmt"interface '{sec.name}': unknown initial_state '{initStr}', using offline"

  result.checkQuality = sec.getBool("check_quality", result.checkQuality)
  result.latencyThreshold = int(sec.getU32("latency_threshold", uint32(result.latencyThreshold)))
  result.lossThreshold = int(sec.getU32("loss_threshold", uint32(result.lossThreshold)))
  result.recoveryLatency = int(sec.getU32("recovery_latency", uint32(result.recoveryLatency)))
  result.recoveryLoss = int(sec.getU32("recovery_loss", uint32(result.recoveryLoss)))
  result.qualityWindow = sec.getU32("quality_window", result.qualityWindow)

  result.dampening = sec.getBool("dampening", result.dampening)
  result.dampeningHalflife = sec.getU32("dampening_halflife", result.dampeningHalflife)
  result.dampeningCeiling = sec.getU32("dampening_ceiling", result.dampeningCeiling)
  result.dampeningSuppress = sec.getU32("dampening_suppress", result.dampeningSuppress)
  result.dampeningReuse = sec.getU32("dampening_reuse", result.dampeningReuse)

  let dqn = sec.get("dns_query_name")
  if dqn != "":
    if dqn.len > 253:
      raise newException(ConfigError, fmt"interface '{sec.name}': dns_query_name too long (max 253)")
    for label in dqn.split('.'):
      if label.len > 63:
        raise newException(ConfigError, fmt"interface '{sec.name}': dns_query_name label too long (max 63): '{label}'")
    result.dnsQueryName = dqn

  result.localSource = sec.getBool("local_source", result.localSource)
  result.updateDns = sec.getBool("update_dns", result.updateDns)
  result.clampMss = sec.getBool("clamp_mss", result.clampMss)

  for ds in sec.getAll("dns_server"):
    if not isValidIpAddress(ds):
      warn fmt"interface '{sec.name}': invalid dns_server '{ds}', skipping"
      continue
    result.dnsServers.add(ds)

  # composite_method list
  for cm in sec.getAll("composite_method"):
    case cm.toLowerAscii()
    of "ping": result.compositeMethods.add(tmPing)
    of "dns": result.compositeMethods.add(tmDns)
    of "http": result.compositeMethods.add(tmHttp)
    of "https": result.compositeMethods.add(tmHttps)
    of "arping": result.compositeMethods.add(tmArping)
    else: warn fmt"interface '{sec.name}': unknown composite_method '{cm}'"

  # flush_conntrack list
  let flushList = sec.getAll("flush_conntrack")
  if flushList.len > 0:
    result.flushConntrack = @[]
    for ft in flushList:
      let parsed = parseFlushTrigger(ft)
      if parsed.isSome:
        result.flushConntrack.add(parsed.get)
      else:
        warn fmt"interface '{sec.name}': unknown flush_conntrack trigger '{ft}', skipping"

proc parseMember*(sec: UciSection): MemberConfig =
  ## Convert a UCI section of type 'member' to MemberConfig.
  if sec.name == "":
    raise newException(ConfigError, "member section must have a name")
  validateName("member", sec.name)

  let ifaceName = sec.get("interface")
  if ifaceName == "":
    raise newException(ConfigError, fmt"member '{sec.name}': 'interface' field is required")

  result = MemberConfig(
    name: sec.name,
    interfaceName: ifaceName,
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
      warn fmt"policy '{sec.name}': unknown last_resort '{lr}', using default"

proc validatePortSpec(spec: string, context: string) =
  ## Validate a port specification: either a single u16 or a range "lo-hi".
  if spec == "":
    return
  let parts = spec.split('-')
  if parts.len == 1:
    try:
      let p = parseInt(parts[0])
      if p < 0 or p > 65535:
        raise newException(ConfigError, fmt"{context}: port {parts[0]} out of range (0-65535)")
    except ValueError:
      raise newException(ConfigError, fmt"{context}: invalid port '{parts[0]}'")
  elif parts.len == 2:
    var lo, hi: int
    try:
      lo = parseInt(parts[0])
    except ValueError:
      raise newException(ConfigError, fmt"{context}: invalid port range start '{parts[0]}'")
    try:
      hi = parseInt(parts[1])
    except ValueError:
      raise newException(ConfigError, fmt"{context}: invalid port range end '{parts[1]}'")
    if lo < 0 or lo > 65535 or hi < 0 or hi > 65535:
      raise newException(ConfigError, fmt"{context}: port range out of bounds")
    if lo > hi:
      raise newException(ConfigError, fmt"{context}: port range start ({lo}) > end ({hi})")
  else:
    raise newException(ConfigError, fmt"{context}: invalid port specification '{spec}'")

proc validateCidr(s: string, context: string) =
  ## Validate an IP address or CIDR notation (addr/prefix).
  ## Strings starting with '@' are nftables set references and skip validation.
  if s.len > 0 and s[0] == '@':
    return
  let slashIdx = s.find('/')
  if slashIdx >= 0:
    let addrPart = s[0 ..< slashIdx]
    let prefixPart = s[slashIdx + 1 ..< s.len]
    if not isValidIpAddress(addrPart):
      raise newException(ConfigError, fmt"{context}: invalid CIDR '{s}'")
    try:
      let prefix = parseInt(prefixPart)
      let maxPrefix = if isIpv6(addrPart): 128 else: 32
      if prefix < 0 or prefix > maxPrefix:
        raise newException(ConfigError, fmt"{context}: prefix length {prefix} out of range for {s}")
    except ValueError:
      raise newException(ConfigError, fmt"{context}: invalid CIDR '{s}'")
  else:
    if not isValidIpAddress(s):
      raise newException(ConfigError, fmt"{context}: invalid IP address '{s}'")

proc parseRule*(sec: UciSection): RuleConfig =
  ## Convert a UCI section of type 'rule' to RuleConfig.
  if sec.name == "":
    raise newException(ConfigError, "rule section must have a name")
  validateName("rule", sec.name)

  result = defaultRule()
  result.name = sec.name

  let ctx = fmt"rule '{sec.name}'"

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
    of "tcp", "udp", "icmp", "icmpv6", "sctp", "gre", "esp", "ah", "all":
      result.proto = proto.toLowerAscii()
    else:
      # Allow numeric protocol numbers
      try:
        let pnum = parseInt(proto)
        if pnum < 0 or pnum > 255:
          raise newException(ConfigError, fmt"{ctx}: protocol number {pnum} out of range (0-255)")
        result.proto = proto
      except ValueError:
        raise newException(ConfigError, fmt"{ctx}: unknown protocol '{proto}'")

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
      raise newException(ConfigError, fmt"{ctx}: unknown family '{familyStr}'")

  # src_iface
  let srcIface = sec.get("src_iface")
  if srcIface != "":
    validateName("src_iface", srcIface)
    result.srcIface = srcIface

  # ipset
  let ipset = sec.get("ipset")
  if ipset != "":
    validateName(fmt"{ctx} ipset", ipset)
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
      warn fmt"{ctx}: unknown sticky_mode '{stickyModeStr}', using flow"

  # use_policy (required)
  let usePolicy = sec.get("use_policy")
  if usePolicy == "":
    raise newException(ConfigError, fmt"{ctx}: 'use_policy' is required")
  result.usePolicy = usePolicy

  result.log = sec.getBool("log", result.log)

proc validate*(config: var NopalConfig) =
  ## Validate cross-references and uniqueness in the config.

  # Check duplicate interface names
  var ifaceNames = initHashSet[string]()
  for iface in config.interfaces:
    if iface.name in ifaceNames:
      raise newException(ConfigError, fmt"duplicate interface name '{iface.name}'")
    ifaceNames.incl(iface.name)

  # Check duplicate member names
  var memberNames = initHashSet[string]()
  for member in config.members:
    if member.name in memberNames:
      raise newException(ConfigError, fmt"duplicate member name '{member.name}'")
    memberNames.incl(member.name)

  # Check duplicate policy names
  var policyNames = initHashSet[string]()
  for policy in config.policies:
    if policy.name in policyNames:
      raise newException(ConfigError, fmt"duplicate policy name '{policy.name}'")
    policyNames.incl(policy.name)

  # Check duplicate rule names
  var ruleNames = initHashSet[string]()
  for rule in config.rules:
    if rule.name in ruleNames:
      raise newException(ConfigError, fmt"duplicate rule name '{rule.name}'")
    ruleNames.incl(rule.name)

  # Members must reference existing interfaces
  for member in config.members:
    if member.interfaceName notin ifaceNames:
      raise newException(ConfigError, fmt"member '{member.name}' references non-existent interface '{member.interfaceName}'")

  # Policies must reference existing members
  for policy in config.policies:
    for memberName in policy.members:
      if memberName notin memberNames:
        raise newException(ConfigError, fmt"policy '{policy.name}' references non-existent member '{memberName}'")

  # Rules must reference existing policies (unless "default")
  for rule in config.rules:
    if rule.usePolicy != "" and rule.usePolicy != "default":
      if rule.usePolicy notin policyNames:
        raise newException(ConfigError, fmt"rule '{rule.name}' references non-existent policy '{rule.usePolicy}'")

  # Warn on interfaces with no track_ip
  for iface in config.interfaces:
    if iface.enabled and iface.trackIp.len == 0:
      warn fmt"interface '{iface.name}' has no track_ip configured, probes will not run"

  # Warn on unreferenced members
  var referencedMembers = initHashSet[string]()
  for policy in config.policies:
    for memberName in policy.members:
      referencedMembers.incl(memberName)
  for member in config.members:
    if member.name notin referencedMembers:
      warn fmt"member '{member.name}' is not referenced by any policy"

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
      warn fmt"unknown section type '{sec.sectionType}', skipping"

  validate(result)

proc loadConfig*(path: string): NopalConfig =
  ## Read a UCI config file and parse it.
  let text = try:
    readFile(path)
  except IOError:
    raise newException(ConfigError, fmt"cannot read config file '{path}'")
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
  option down_count '3'
  option up_count '3'
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
  option down_count '3'
  option up_count '3'
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
      check cfg.members[0].interfaceName == "wan1"
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

    test "conntrack_flush_modes":
      for (val, expected) in [("none", cfmNone), ("selective", cfmSelective), ("full", cfmFull)]:
        let text = "config globals globals\n  option conntrack_flush '" & val & "'\n"
        let cfg = loadFromStr(text)
        check cfg.globals.conntrackFlush == expected

    test "ipv6_enabled_and_family_parsing":
      let text = """
config globals globals
  option ipv6_enabled '1'

config interface wan6
  option device 'eth0'
  option family 'ipv6'
  list track_ip '2001:4860:4860::8888'

config interface wan_dual
  option device 'eth1'
  option family 'both'
  list track_ip '1.1.1.1'

config policy balanced
  option last_resort 'default'

config rule v6_only
  option family 'ipv6'
  option use_policy 'balanced'

config rule dual
  option family 'any'
  option use_policy 'balanced'
"""
      let cfg = loadFromStr(text)
      check cfg.globals.ipv6Enabled
      check cfg.interfaces[0].family == afIpv6
      check cfg.interfaces[1].family == afBoth
      check cfg.rules[0].family == rfIpv6
      check cfg.rules[1].family == rfAny

    test "rule_with_all_fields":
      let text = """
config interface wan
  option device 'eth0'
  list track_ip '1.1.1.1'

config member wan_m
  option interface 'wan'

config policy balanced
  list use_member 'wan_m'

config rule custom
  list src_ip '10.0.0.0/8'
  option src_port '1024-65535'
  list dest_ip '192.168.1.0/24'
  option dest_port '80'
  option proto 'tcp'
  option family 'ipv4'
  option sticky '1'
  option sticky_timeout '300'
  option sticky_mode 'src_ip'
  option use_policy 'balanced'
  option log '1'
"""
      let cfg = loadFromStr(text)
      let rule = cfg.rules[0]
      check rule.srcIp == @["10.0.0.0/8"]
      check rule.srcPort == "1024-65535"
      check rule.destIp == @["192.168.1.0/24"]
      check rule.destPort == "80"
      check rule.proto == "tcp"
      check rule.family == rfIpv4
      check rule.sticky == true
      check rule.stickyTimeout == 300'u32
      check rule.stickyMode == smSrcIp
      check rule.log == true

    test "duplicate_member_name_is_error":
      let text = """
config interface wan
  option device 'eth0'
config member wan_m
  option interface 'wan'
config member wan_m
  option interface 'wan'
"""
      expect ConfigError:
        discard loadFromStr(text)

    test "duplicate_policy_name_is_error":
      let text = """
config policy balanced
  option last_resort 'default'
config policy balanced
  option last_resort 'unreachable'
"""
      expect ConfigError:
        discard loadFromStr(text)

    test "duplicate_rule_name_is_error":
      let text = """
config policy balanced
  option last_resort 'default'
config rule r1
  option use_policy 'balanced'
config rule r1
  option use_policy 'balanced'
"""
      expect ConfigError:
        discard loadFromStr(text)

    test "interface_missing_name_is_error":
      let text = "config interface\n  option device 'eth0'\n"
      expect ConfigError:
        discard loadFromStr(text)

    test "parse_empty_config_checks_defaults":
      let cfg = loadFromStr("")
      check cfg.globals.enabled == true
      check cfg.globals.markMask == 0xFF00'u32
      check cfg.globals.conntrackFlush == cfmSelective
      check cfg.interfaces.len == 0
