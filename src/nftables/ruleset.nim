## nftables JSON ruleset types and builder.
##
## Provides a Ruleset type that accumulates nftables JSON commands
## (table, chain, rule, set, map) and serializes to the format
## expected by `nft -j -f -`.

import std/json

const
  TableFamily* = "inet"
  TableName* = "nopal"

type
  Ruleset* = object
    cmds: seq[JsonNode]

proc initRuleset*(): Ruleset =
  Ruleset(cmds: @[])

proc addFlushTable*(rs: var Ruleset) =
  rs.cmds.add(%*{"flush": {"table": {"family": TableFamily, "name": TableName}}})

proc addTable*(rs: var Ruleset) =
  rs.cmds.add(%*{"add": {"table": {"family": TableFamily, "name": TableName}}})

proc addBaseChain*(rs: var Ruleset, name, chainType, hook: string,
                   prio: int, policy: string) =
  rs.cmds.add(%*{"add": {"chain": {
    "family": TableFamily, "table": TableName, "name": name,
    "type": chainType, "hook": hook, "prio": prio, "policy": policy,
  }}})

proc addRegularChain*(rs: var Ruleset, name: string) =
  rs.cmds.add(%*{"add": {"chain": {
    "family": TableFamily, "table": TableName, "name": name,
  }}})

proc addRule*(rs: var Ruleset, chain: string, expr: varargs[JsonNode]) =
  var exprArr = newJArray()
  for e in expr:
    exprArr.add(e)
  rs.cmds.add(%*{"add": {"rule": {
    "family": TableFamily, "table": TableName, "chain": chain,
    "expr": exprArr,
  }}})

proc addSet*(rs: var Ruleset, name, setType: string,
             flags: openArray[string] = []) =
  var s = %*{"family": TableFamily, "table": TableName,
             "name": name, "type": setType}
  if flags.len > 0:
    var f = newJArray()
    for flag in flags: f.add(%flag)
    s["flags"] = f
  rs.cmds.add(%*{"add": {"set": s}})

proc addMap*(rs: var Ruleset, name: string, keyType: JsonNode,
             valueType: string, timeout: uint32 = 0) =
  var m = %*{"family": TableFamily, "table": TableName,
             "name": name, "type": keyType, "map": valueType}
  if timeout > 0:
    var f = newJArray()
    f.add(%"timeout")
    m["flags"] = f
    m["timeout"] = %(int(timeout))
  rs.cmds.add(%*{"add": {"map": m}})

proc toJson*(rs: Ruleset): JsonNode =
  var arr = newJArray()
  # Metainfo first (nftables convention)
  arr.add(%*{"metainfo": {"json_schema_version": 1}})
  for cmd in rs.cmds:
    arr.add(cmd)
  %*{"nftables": arr}

when isMainModule:
  import std/unittest

  suite "Ruleset":
    test "empty ruleset has metainfo":
      let rs = initRuleset()
      let j = rs.toJson()
      check j["nftables"].len == 1
      check j["nftables"][0].hasKey("metainfo")

    test "addTable produces correct JSON":
      var rs = initRuleset()
      rs.addTable()
      let j = rs.toJson()
      let cmd = j["nftables"][1]
      check cmd["add"]["table"]["family"].getStr == "inet"
      check cmd["add"]["table"]["name"].getStr == "nopal"

    test "addBaseChain with hook and priority":
      var rs = initRuleset()
      rs.addBaseChain("prerouting", "filter", "prerouting", -150, "accept")
      let j = rs.toJson()
      let chain = j["nftables"][1]["add"]["chain"]
      check chain["name"].getStr == "prerouting"
      check chain["type"].getStr == "filter"
      check chain["hook"].getStr == "prerouting"
      check chain["prio"].getInt == -150
      check chain["policy"].getStr == "accept"

    test "addRule appends expr array":
      var rs = initRuleset()
      let expr1 = %*{"match": {"op": "==", "left": 1, "right": 2}}
      let expr2 = %*{"accept": nil}
      rs.addRule("forward", expr1, expr2)
      let j = rs.toJson()
      let rule = j["nftables"][1]["add"]["rule"]
      check rule["chain"].getStr == "forward"
      check rule["expr"].len == 2

    test "addSet with flags":
      var rs = initRuleset()
      rs.addSet("bypass_v4", "ipv4_addr", ["interval"])
      let j = rs.toJson()
      let s = j["nftables"][1]["add"]["set"]
      check s["name"].getStr == "bypass_v4"
      check s["type"].getStr == "ipv4_addr"
      check s["flags"][0].getStr == "interval"

    test "addMap with timeout":
      var rs = initRuleset()
      rs.addMap("sticky_r0_v4", %"ipv4_addr", "mark", 600)
      let j = rs.toJson()
      let m = j["nftables"][1]["add"]["map"]
      check m["name"].getStr == "sticky_r0_v4"
      check m["map"].getStr == "mark"
      check m["timeout"].getInt == 600
      check m["flags"][0].getStr == "timeout"
