## nopal -- Multi-WAN policy routing manager for OpenWrt
##
## Single binary, dual mode: dispatches based on argv[0].
## Invoked as "nopald" or with --daemon/-d: runs the daemon.
## Otherwise: CLI tool that talks to the daemon over Unix socket IPC.

import std/[posix, os, strutils, strformat, json, endians, net, nativesockets]
import daemon
import ipc/protocol
import logging
import std/[osproc, strtabs, algorithm]

const
  Version = "0.1.0-alpha.2"
  DefaultConfig = "/etc/config/nopal"
  DefaultSocket = "/var/run/nopal.sock"

# ---------------------------------------------------------------------------
# Signal state -- module-level globals for async-signal-safe self-pipe trick
# ---------------------------------------------------------------------------

var signalWriteFd: cint = -1

proc handleSigterm(sig: cint) {.noconv.} =
  let b = byte('T')
  discard posix.write(signalWriteFd, unsafeAddr b, 1)

proc handleSighup(sig: cint) {.noconv.} =
  let b = byte('R')
  discard posix.write(signalWriteFd, unsafeAddr b, 1)

# ---------------------------------------------------------------------------
# Daemon entry point
# ---------------------------------------------------------------------------

proc runDaemon(args: seq[string]) =
  ## Parse arguments, set up signal pipe, install handlers, run daemon loop.
  var configPath = DefaultConfig

  # Parse -c / --config
  var i = 1
  while i < args.len:
    let a = args[i]
    if a == "-c" or a == "--config":
      inc i
      if i < args.len:
        configPath = args[i]
      else:
        stderr.writeLine "error: -c/--config requires an argument"
        quit(1)
    i.inc

  # Initialize logging (stderr fallback for now)
  initStderrFallback()

  # Create self-pipe for signal delivery
  var pipeFds: array[2, cint]
  if pipe(pipeFds) != 0:
    stderr.writeLine fmt"failed to create signal pipe: {strerror(errno)}"
    quit(1)

  # Set O_NONBLOCK and O_CLOEXEC on both ends
  for fd in pipeFds:
    let flags = fcntl(fd, F_GETFL)
    discard fcntl(fd, F_SETFL, flags or O_NONBLOCK)
    let fdFlags = fcntl(fd, F_GETFD)
    discard fcntl(fd, F_SETFD, fdFlags or FD_CLOEXEC)

  signalWriteFd = pipeFds[1]

  # Install signal handlers via sigaction
  var sa: Sigaction
  discard sigemptyset(sa.sa_mask)
  sa.sa_flags = SA_RESTART

  sa.sa_handler = handleSigterm
  discard sigaction(SIGTERM, sa, nil)
  discard sigaction(SIGINT, sa, nil)

  sa.sa_handler = handleSighup
  discard sigaction(SIGHUP, sa, nil)

  sa.sa_handler = SIG_IGN
  discard sigaction(SIGPIPE, sa, nil)

  stderr.writeLine fmt"nopal v{Version} starting"

  var d = initDaemon(configPath, pipeFds[0])
  d.run()

# ---------------------------------------------------------------------------
# IPC client (blocking, for CLI tool)
# ---------------------------------------------------------------------------

proc sendIpcRequest(socketPath: string, req: IpcRequest): IpcResponse =
  ## Connect to daemon Unix socket, send length-prefixed JSON request,
  ## read length-prefixed JSON response.
  let fd = createNativeSocket(Domain.AF_UNIX, SockType.SOCK_STREAM,
                               Protocol.IPPROTO_IP)
  if fd == osInvalidSocket:
    raise newException(IOError, fmt"failed to create socket: {strerror(errno)}")

  # Build sockaddr_un
  var sa: Sockaddr_un
  sa.sun_family = posix.AF_UNIX.TSa_Family
  let pathBytes = socketPath
  if pathBytes.len >= sizeof(sa.sun_path):
    raise newException(ValueError, "socket path too long")
  copyMem(addr sa.sun_path[0], unsafeAddr pathBytes[0], pathBytes.len)
  sa.sun_path[pathBytes.len] = '\0'

  if connect(fd, cast[ptr SockAddr](addr sa),
             SockLen(sizeof(sa))) != 0:
    discard posix.close(fd.cint)
    raise newException(IOError, fmt"failed to connect to {socketPath}: {strerror(errno)}")

  # Serialize request to JSON, then frame with u32 BE length prefix
  var reqJson = %*{"id": req.id, "method": req.rpcMethod}
  if req.params != nil:
    reqJson["params"] = req.params
  let payload = $reqJson
  let payloadLen = payload.len.uint32
  var lenBuf: array[4, byte]
  bigEndian32(addr lenBuf[0], unsafeAddr payloadLen)

  # Send length + payload
  if send(fd, unsafeAddr lenBuf[0], 4, 0) != 4:
    discard posix.close(fd.cint)
    raise newException(IOError, "failed to send request length")
  if send(fd, unsafeAddr payload[0], payload.len, 0) != payload.len:
    discard posix.close(fd.cint)
    raise newException(IOError, "failed to send request payload")

  # Read response length (4 bytes)
  var respLenBuf: array[4, byte]
  var totalRead = 0
  while totalRead < 4:
    let n = recv(fd, addr respLenBuf[totalRead], (4 - totalRead).cint, 0)
    if n <= 0:
      discard posix.close(fd.cint)
      raise newException(IOError, "failed to read response length")
    totalRead += n

  var respLen: uint32
  bigEndian32(addr respLen, addr respLenBuf[0])

  if respLen > MaxMsgSize:
    discard posix.close(fd.cint)
    raise newException(IOError, fmt"response too large ({respLen} bytes)")

  # Read response payload
  var respBuf = newString(respLen.int)
  totalRead = 0
  while totalRead < respLen.int:
    let n = recv(fd, addr respBuf[totalRead], (respLen.int - totalRead).cint, 0)
    if n <= 0:
      discard posix.close(fd.cint)
      raise newException(IOError, "failed to read response payload")
    totalRead += n

  discard posix.close(fd.cint)

  result = parseResponse(parseJson(respBuf))

# ---------------------------------------------------------------------------
# CLI helpers
# ---------------------------------------------------------------------------

proc fetchStatus(socketPath: string): DaemonStatus =
  let req = IpcRequest(id: 1, rpcMethod: "status")
  let resp = sendIpcRequest(socketPath, req)
  if not resp.success:
    stderr.writeLine fmt"error: {resp.error}"
    quit(1)
  if resp.data.kind != JObject or not resp.data.hasKey("version"):
    stderr.writeLine "unexpected response from daemon"
    quit(1)
  result = parseDaemonStatus(resp.data)

proc formatUptime(secs: int64): string =
  let days = secs div 86400
  let hours = (secs mod 86400) div 3600
  let mins = (secs mod 3600) div 60
  if days > 0:
    result = fmt"{days}d {hours}h {mins}m"
  elif hours > 0:
    result = fmt"{hours}h {mins}m"
  else:
    result = fmt"{mins}m"

proc printInterfaceTable(interfaces: JsonNode) =
  echo "  " & alignLeft("INTERFACE", 12) & " " &
       alignLeft("DEVICE", 10) & " " &
       alignLeft("STATE", 10) & " " &
       alignLeft("ENABLED", 8) & " " &
       align("RTT", 7) & " " &
       align("LOSS", 6) & " " &
       align("SCORE", 6)

  for iface in interfaces:
    let name = iface{"name"}.getStr("-")
    let device = iface{"device"}.getStr("-")
    let state = iface{"state"}.getStr("-")
    let enabled = if iface{"enabled"}.getBool(false): "yes" else: "no"
    let rttVal = iface{"avg_rtt_ms"}
    let rtt = if rttVal.kind != JNull: fmt"{rttVal.getFloat()}ms" else: "-"
    let lossVal = iface{"loss_percent"}.getInt(0)
    let loss = fmt"{lossVal}%"
    let successes = iface{"success_count"}.getInt(0)
    let failures = iface{"fail_count"}.getInt(0)
    let score = fmt"{successes}/{successes + failures}"

    echo "  " & alignLeft(name, 12) & " " &
         alignLeft(device, 10) & " " &
         alignLeft(state, 10) & " " &
         alignLeft(enabled, 8) & " " &
         align(rtt, 7) & " " &
         align(loss, 6) & " " &
         align(score, 6)

proc printInterfaceDetail(iface: JsonNode) =
  let name = iface{"name"}.getStr("-")
  let device = iface{"device"}.getStr("-")
  let state = iface{"state"}.getStr("-")
  let enabled = if iface{"enabled"}.getBool(false): "yes" else: "no"
  let mark = iface{"mark"}.getInt(0).toHex(4).toLowerAscii()
  let tableId = iface{"table_id"}.getInt(0)
  echo fmt"Interface: {name}"
  echo fmt"  Device:    {device}"
  echo fmt"  State:     {state}"
  echo fmt"  Enabled:   {enabled}"
  echo fmt"  Mark:      0x{mark}"
  echo fmt"  Table:     {tableId}"
  let rttVal = iface{"avg_rtt_ms"}
  let rtt = if rttVal.kind != JNull: fmt"{rttVal.getFloat()}ms" else: "-"
  let lossVal = iface{"loss_percent"}.getInt(0)
  let okCount = iface{"success_count"}.getInt(0)
  let failCount = iface{"fail_count"}.getInt(0)
  echo fmt"  RTT:       {rtt}"
  echo fmt"  Loss:      {lossVal}%"
  echo fmt"  Probes:    {okCount} ok / {failCount} fail"

proc printPolicyTable(policies: JsonNode) =
  echo "  " & alignLeft("POLICY", 16) & " " &
       alignLeft("TIER", 8) & " " &
       "ACTIVE MEMBERS"

  for policy in policies:
    let name = policy{"name"}.getStr("-")
    let tier = if policy{"active_tier"}.kind != JNull:
                 $policy{"active_tier"}.getInt()
               else:
                 "-"
    let members = policy{"active_members"}
    let membersStr = if members.kind == JArray and members.len > 0:
                       var parts: seq[string] = @[]
                       for m in members:
                         parts.add m.getStr()
                       parts.join(", ")
                     else:
                       "(none)"
    echo "  " & alignLeft(name, 16) & " " &
         alignLeft(tier, 8) & " " &
         membersStr

# ---------------------------------------------------------------------------
# CLI subcommands
# ---------------------------------------------------------------------------

proc cliStatus(socketPath: string, iface: string, jsonMode: bool) =
  if iface.len > 0:
    # Single interface detail
    let req = IpcRequest(id: 1, rpcMethod: "interface.status",
                         params: %*{"interface": iface})
    let resp = sendIpcRequest(socketPath, req)
    if not resp.success:
      stderr.writeLine fmt"error: {resp.error}"
      quit(1)
    if jsonMode:
      echo resp.data.pretty()
    else:
      printInterfaceDetail(resp.data)
    return

  let req = IpcRequest(id: 1, rpcMethod: "status")
  let resp = sendIpcRequest(socketPath, req)
  if not resp.success:
    stderr.writeLine fmt"error: {resp.error}"
    quit(1)

  if jsonMode:
    echo resp.data.pretty()
    return

  let uptime = formatUptime(resp.data{"uptime_secs"}.getBiggestInt(0))
  let version = resp.data{"version"}.getStr(Version)
  echo fmt"nopal v{version} -- uptime {uptime}"
  echo ""

  let interfaces = resp.data{"interfaces"}
  if interfaces.kind != JArray or interfaces.len == 0:
    echo "No interfaces configured."
  else:
    echo "Interfaces:"
    printInterfaceTable(interfaces)

  echo ""

  let policies = resp.data{"policies"}
  if policies.kind != JArray or policies.len == 0:
    echo "No policies configured."
  else:
    echo "Policies:"
    printPolicyTable(policies)

proc cliInterfaces(socketPath: string, jsonMode: bool) =
  let req = IpcRequest(id: 1, rpcMethod: "status")
  let resp = sendIpcRequest(socketPath, req)
  if not resp.success:
    stderr.writeLine fmt"error: {resp.error}"
    quit(1)

  let interfaces = resp.data{"interfaces"}
  if jsonMode:
    echo interfaces.pretty()
    return

  if interfaces.kind != JArray or interfaces.len == 0:
    echo "No interfaces configured."
  else:
    printInterfaceTable(interfaces)

proc cliPolicies(socketPath: string, jsonMode: bool) =
  let req = IpcRequest(id: 1, rpcMethod: "status")
  let resp = sendIpcRequest(socketPath, req)
  if not resp.success:
    stderr.writeLine fmt"error: {resp.error}"
    quit(1)

  let policies = resp.data{"policies"}
  if jsonMode:
    echo policies.pretty()
    return

  if policies.kind != JArray or policies.len == 0:
    echo "No policies configured."
  else:
    printPolicyTable(policies)

proc cliConnected(socketPath: string, jsonMode: bool) =
  let req = IpcRequest(id: 1, rpcMethod: "connected")
  let resp = sendIpcRequest(socketPath, req)
  if not resp.success:
    stderr.writeLine fmt"error: {resp.error}"
    quit(1)

  if jsonMode:
    echo resp.data.pretty()
    return

  echo "Connected networks (bypassed from policy routing):"
  let networks = resp.data{"networks"}
  if networks.kind == JArray:
    for net in networks:
      echo fmt"  {net.getStr()}"

proc cliReload(socketPath: string) =
  let req = IpcRequest(id: 1, rpcMethod: "config.reload")
  let resp = sendIpcRequest(socketPath, req)
  if resp.success:
    echo "configuration reloaded"
  else:
    stderr.writeLine fmt"reload failed: {resp.error}"
    quit(1)

proc cliUse(socketPath: string, iface: string, cmdArgs: seq[string]) =
  ## Run a command with traffic routed through a specific interface.
  ## Adds uidrange ip rules, runs the command, cleans up rules on exit.

  # Query daemon for interface table_id and device
  let req = IpcRequest(id: 1, rpcMethod: "interface.status",
                       params: %*{"interface": iface})
  let resp = sendIpcRequest(socketPath, req)
  if not resp.success:
    stderr.writeLine fmt"error: {resp.error}"
    quit(1)
  let tableId = resp.data{"table_id"}.getInt()
  let device = resp.data{"device"}.getStr()
  if tableId == 0:
    stderr.writeLine fmt"error: interface '{iface}' has no routing table"
    quit(1)

  # Get UID for uidrange rule
  let uid = getuid()
  let uidRange = fmt"{uid}-{uid}"
  let tableStr = $tableId

  # Add IPv4 uidrange ip rule (required)
  var v4Added, v6Added = false
  let v4ret = execCmd(fmt"ip -4 rule add uidrange {uidRange} lookup {tableStr} prio 1")
  if v4ret != 0:
    stderr.writeLine "error: failed to add IPv4 routing rule"
    quit(1)
  v4Added = true

  # Try IPv6 rule (tolerate failure — IPv6 may be disabled)
  let v6ret = execCmd(fmt"ip -6 rule add uidrange {uidRange} lookup {tableStr} prio 1")
  v6Added = v6ret == 0

  # Run user command with DEVICE and INTERFACE added to inherited env
  var exitCode = 1
  try:
    putEnv("DEVICE", device)
    putEnv("INTERFACE", iface)
    let p = startProcess(cmdArgs[0], args = cmdArgs[1..^1],
                         options = {poParentStreams, poUsePath})
    exitCode = p.waitForExit()
    p.close()
  except OSError:
    stderr.writeLine fmt"error: {getCurrentExceptionMsg()}"

  # Cleanup rules (always, even on error)
  if v4Added:
    discard execCmd(fmt"ip -4 rule del uidrange {uidRange} lookup {tableStr} prio 1")
  if v6Added:
    discard execCmd(fmt"ip -6 rule del uidrange {uidRange} lookup {tableStr} prio 1")

  quit(exitCode)

proc cliInternal() =
  ## Dump diagnostic information: ip rules, routing tables, nftables.
  echo "=== IPv4 IP Rules ==="
  discard execCmd("ip -4 rule show")
  echo ""
  echo "=== IPv6 IP Rules ==="
  discard execCmd("ip -6 rule show")
  echo ""

  # Find nopal routing tables (101-354) from rules output
  echo "=== Nopal Routing Tables ==="
  let rulesOutput = execProcess("ip -4 rule show")
  var tables: seq[int]
  for line in rulesOutput.splitLines():
    let idx = line.find("lookup ")
    if idx >= 0:
      try:
        var numStr = ""
        for i in (idx + 7) ..< min(idx + 11, line.len):
          if line[i] in {'0'..'9'}: numStr.add(line[i])
          else: break
        if numStr.len > 0:
          let tableId = parseInt(numStr)
          if tableId >= 101 and tableId <= 354 and tableId notin tables:
            tables.add(tableId)
      except ValueError: discard
  tables.sort()
  # Two passes: all IPv4 first, then all IPv6 (matches Rust output order)
  for t in tables:
    echo fmt"--- table {t} (IPv4) ---"
    discard execCmd(fmt"ip -4 route show table {t}")
  for t in tables:
    echo fmt"--- table {t} (IPv6) ---"
    discard execCmd(fmt"ip -6 route show table {t}")
  echo ""

  echo "=== nftables Ruleset ==="
  discard execCmd("nft list table inet nopal")

proc cliRules() =
  ## Dump the nopal nftables ruleset.
  let exitCode = execShellCmd("nft list chain inet nopal policy_rules")
  if exitCode != 0:
    echo "nopal nftables rules not loaded (daemon not running?)"

proc printUsage() =
  echo fmt"nopal {Version} -- Multi-WAN manager for OpenWrt"
  echo ""
  echo "Usage:"
  echo "  nopal status [<interface>]   Show daemon/interface status"
  echo "  nopal interfaces             Show interface table"
  echo "  nopal policies               Show policy table"
  echo "  nopal connected              Show connected networks"
  echo "  nopal use <iface> <cmd...>   Run command via specific WAN"
  echo "  nopal rules                  Show active nftables rules"
  echo "  nopal reload                 Reload configuration"
  echo "  nopal version                Show version"
  echo "  nopal help                   Show this help"
  echo ""
  echo "Daemon:"
  echo "  nopald [-c <config>]         Run the daemon"
  echo ""
  echo "Options:"
  echo fmt"  -c, --config <path>         Config file path (default: {DefaultConfig})"
  echo fmt"  -s, --socket <path>         IPC socket path (default: {DefaultSocket})"
  echo "  -j, --json                  Output in JSON format"

# ---------------------------------------------------------------------------
# CLI entry point
# ---------------------------------------------------------------------------

proc runCli(args: seq[string]) =
  var socketPath = DefaultSocket
  var jsonMode = false
  var positional: seq[string] = @[]
  var i = 1

  while i < args.len:
    let a = args[i]
    case a
    of "-s", "--socket":
      inc i
      if i < args.len:
        socketPath = args[i]
      else:
        stderr.writeLine "error: -s/--socket requires an argument"
        quit(1)
    of "-j", "--json":
      jsonMode = true
    of "--help", "-h":
      printUsage()
      return
    of "--version", "-V":
      echo fmt"nopal {Version}"
      return
    else:
      positional.add a
    inc i

  let command = if positional.len > 0: positional[0] else: "status"

  try:
    case command
    of "status":
      let ifaceName = if positional.len > 1: positional[1] else: ""
      cliStatus(socketPath, ifaceName, jsonMode)
    of "interfaces":
      cliInterfaces(socketPath, jsonMode)
    of "policies":
      cliPolicies(socketPath, jsonMode)
    of "connected":
      cliConnected(socketPath, jsonMode)
    of "use":
      if positional.len < 3:
        stderr.writeLine "usage: nopal use <interface> <command...>"
        quit(1)
      cliUse(socketPath, positional[1], positional[2..^1])
    of "rules":
      cliRules()
    of "internal":
      cliInternal()
    of "reload":
      cliReload(socketPath)
    of "help":
      printUsage()
    of "version":
      echo fmt"nopal {Version}"
    else:
      stderr.writeLine fmt"unknown command: {command}"
      printUsage()
      quit(1)
  except IOError as e:
    stderr.writeLine fmt"failed to connect to nopal daemon: {e.msg}"
    stderr.writeLine "is nopald running?"
    quit(1)

# ---------------------------------------------------------------------------
# Main -- argv[0] dispatch
# ---------------------------------------------------------------------------

when isMainModule:
  let args = commandLineParams()

  # Use argv[0] for dispatch — paramStr(0) preserves the symlink name
  # (unlike getAppFilename() which resolves symlinks on Linux).
  let argv0 = paramStr(0)
  let prog = extractFilename(argv0)
  let allArgs = @[argv0] & args

  if prog == "nopald" or "--daemon" in args or "-d" in args:
    runDaemon(allArgs)
  else:
    runCli(allArgs)
