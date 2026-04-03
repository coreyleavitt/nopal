## nftables engine: pipes JSON ruleset to `nft -j -f -` for atomic application.
##
## The entire ruleset is replaced in one transaction. Either all rules
## apply or none do. This avoids intermediate states where traffic could
## be misrouted.

import std/[osproc, json, logging, streams, strutils, strformat]
import ./ruleset

proc applyRuleset*(rs: Ruleset): bool =
  ## Serialize ruleset to JSON and pipe to nft for atomic application.
  ## Returns true on success, false on error (logged).
  let jsonStr = $rs.toJson()
  debug fmt"applying nftables ruleset ({jsonStr.len} bytes)"

  let process = startProcess("nft", args = ["-j", "-f", "-"],
                             options = {poUsePath, poStdErrToStdOut})
  let input = process.inputStream()
  input.write(jsonStr)
  input.close()

  # Read output BEFORE waitForExit to avoid deadlock if nft fills pipe buffer
  let output = process.outputStream().readAll()
  let exitCode = process.waitForExit()
  if exitCode != 0:
    error fmt"nft failed (exit {exitCode}): {output}"
    process.close()
    return false

  process.close()
  true

proc applyElementChange(op, setName, cidr: string): bool =
  ## Add or delete a single element from an nftables named set.
  ## op is "add" or "delete".
  let slashIdx = cidr.find('/')
  var elemJson: JsonNode
  if slashIdx >= 0:
    let addrPart = cidr[0 ..< slashIdx]
    let prefLen = cidr[slashIdx + 1 .. ^1]
    elemJson = %*{"prefix": {"addr": addrPart, "len": parseInt(prefLen)}}
  else:
    elemJson = %*cidr

  let json = %*{"nftables": [{op: {"element": {
    "family": TableFamily, "table": TableName,
    "name": setName, "elem": [elemJson]
  }}}]}

  let jsonStr = $json
  let process = startProcess("nft", args = ["-j", "-f", "-"],
                             options = {poUsePath, poStdErrToStdOut})
  let input = process.inputStream()
  input.write(jsonStr)
  input.close()
  let output = process.outputStream().readAll()
  let exitCode = process.waitForExit()
  if exitCode != 0:
    error fmt"nft element {op} failed for {setName}: {output}"
    process.close()
    return false
  process.close()
  true

proc addSetElement*(setName, cidr: string): bool =
  ## Add a CIDR to an nftables named set. Returns true on success.
  applyElementChange("add", setName, cidr)

proc delSetElement*(setName, cidr: string): bool =
  ## Delete a CIDR from an nftables named set. Returns true on success.
  applyElementChange("delete", setName, cidr)

proc cleanup*(): bool =
  ## Delete the nopal nftables table. Ignores "table not found" errors.
  let process = startProcess("nft", args = ["delete", "table", TableFamily, TableName],
                             options = {poUsePath, poStdErrToStdOut})
  let output = process.outputStream().readAll()
  let exitCode = process.waitForExit()
  process.close()
  if exitCode != 0:
    if "No such file or directory" notin output and
       "does not exist" notin output:
      warn fmt"nft cleanup failed: {output}"
      return false
  true
