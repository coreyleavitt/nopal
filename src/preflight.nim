## Startup preflight checks — validates runtime environment before daemon init.
##
## Pure module: takes config values, returns results. The daemon decides
## policy (fatal vs warn vs ignore).

import std/[osproc, os, strutils]

type
  PreflightSeverity* = enum
    pfPass
    pfWarn
    pfFail

  PreflightResult* = object
    name*: string
    severity*: PreflightSeverity
    message*: string

proc pass(name: string): PreflightResult =
  PreflightResult(name: name, severity: pfPass, message: "")

proc warn(name, msg: string): PreflightResult =
  PreflightResult(name: name, severity: pfWarn, message: msg)

proc fail(name, msg: string): PreflightResult =
  PreflightResult(name: name, severity: pfFail, message: msg)

const ProbeTable = "_nopal_preflight"

proc runPreflight*(markMask: uint32): seq[PreflightResult] =
  ## Validate the runtime environment. Checks nft binary, kernel nftables
  ## features (ct mark, numgen), and ip-full uidrange support.
  ## Creates a temporary nftables table for feature probing, then deletes it.

  # 1. nft binary
  let nftPath = findExe("nft")
  if nftPath.len == 0:
    result.add(fail("nft", "nft binary not found — install the nftables package"))
    return  # can't run any further checks without nft

  result.add(pass("nft"))

  # 2. Create probe table + chain
  let (_, rcTable) = execCmdEx("nft add table inet " & ProbeTable)
  if rcTable != 0:
    result.add(fail("inet_family",
      "cannot create inet table — kernel may be missing IPv6 support. " &
      "Rebuild with CONFIG_NF_TABLES_INET=y or see issue #145"))
    discard execCmdEx("nft delete table inet " & ProbeTable)
    return

  discard execCmdEx("nft add chain inet " & ProbeTable &
    " _c '{ type filter hook prerouting priority 0; }'")

  # 3. ct mark support (CONFIG_NF_CONNTRACK_MARK)
  let (ctOut, rcCt) = execCmdEx("nft add rule inet " & ProbeTable &
    " _c ct mark set 0x1")
  if rcCt != 0:
    result.add(fail("ct_mark",
      "ct mark not supported — rebuild kernel with CONFIG_NF_CONNTRACK_MARK=y. " &
      "Without this, connection-based mark persistence is unavailable and " &
      "policy routing will not work correctly"))
    discard execCmdEx("nft delete table inet " & ProbeTable)
    return

  result.add(pass("ct_mark"))

  # 4. numgen expression (weighted load balancing)
  let (_, rcNumgen) = execCmdEx("nft add rule inet " & ProbeTable &
    " _c numgen inc mod 2 vmap { 0 : accept, 1 : drop }")
  if rcNumgen != 0:
    result.add(fail("numgen",
      "numgen expression not supported — install kmod-nft-numgen. " &
      "Without this, weighted load balancing will not work"))
    discard execCmdEx("nft delete table inet " & ProbeTable)
    return

  result.add(pass("numgen"))

  # 5. Cleanup probe table
  discard execCmdEx("nft delete table inet " & ProbeTable)

  # 6. ip-full uidrange support (for nopal use)
  let (ipOut, rcIp) = execCmdEx("ip rule help 2>&1")
  if "uidrange" notin ipOut:
    result.add(warn("ip_uidrange",
      "ip binary lacks uidrange support — install ip-full package. " &
      "'nopal use' will not work without it"))
  else:
    result.add(pass("ip_uidrange"))


when isMainModule:
  echo "Running preflight checks..."
  let results = runPreflight(0xFF00'u32)
  for r in results:
    case r.severity
    of pfPass: echo "  PASS: ", r.name
    of pfWarn: echo "  WARN: ", r.name, " — ", r.message
    of pfFail: echo "  FAIL: ", r.name, " — ", r.message
