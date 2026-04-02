## Config change detection for hot reload.
##
## Compares two NopalConfig values and returns a structured diff
## so the daemon can apply targeted updates instead of a full
## teardown/rebuild on every reload.

import std/strformat
import ./schema

type
  ConfigDiff* = object
    changed*: bool
    globalsChanged*: bool
    addedInterfaces*: seq[string]
    removedInterfaces*: seq[string]
    changedInterfaces*: seq[string]
    routingChanged*: bool
    interfaceOrderChanged*: bool

func needsFullRebuild*(d: ConfigDiff): bool =
  ## Whether a full rebuild is required (globals, interface set changes).
  d.globalsChanged or
    d.addedInterfaces.len > 0 or
    d.removedInterfaces.len > 0 or
    d.interfaceOrderChanged

func needsNftables*(d: ConfigDiff): bool =
  ## Whether nftables regeneration is needed.
  d.routingChanged or d.changedInterfaces.len > 0

proc diff*(old, new: NopalConfig): ConfigDiff =
  ## Compare two configurations and return a detailed diff summary.
  if old == new:
    return ConfigDiff(changed: false)

  let globalsChanged = old.globals != new.globals

  var added: seq[string]
  var removed: seq[string]
  var changed: seq[string]

  # Find added and changed interfaces
  for newIface in new.interfaces:
    var found = false
    for oldIface in old.interfaces:
      if oldIface.name == newIface.name:
        found = true
        if oldIface != newIface:
          changed.add(newIface.name)
        break
    if not found:
      added.add(newIface.name)

  # Find removed interfaces
  for oldIface in old.interfaces:
    var found = false
    for newIface in new.interfaces:
      if newIface.name == oldIface.name:
        found = true
        break
    if not found:
      removed.add(oldIface.name)

  # Detect interface reorder: same set of names but different positions
  var orderChanged = false
  if added.len == 0 and removed.len == 0:
    var oldNames: seq[string]
    var newNames: seq[string]
    for i in old.interfaces: oldNames.add(i.name)
    for i in new.interfaces: newNames.add(i.name)
    orderChanged = oldNames != newNames

  let routingChanged = old.members != new.members or
    old.policies != new.policies or
    old.rules != new.rules

  ConfigDiff(
    changed: true,
    globalsChanged: globalsChanged,
    addedInterfaces: added,
    removedInterfaces: removed,
    changedInterfaces: changed,
    routingChanged: routingChanged,
    interfaceOrderChanged: orderChanged,
  )

when isMainModule:
  import std/unittest

  proc minimalConfig(): NopalConfig =
    NopalConfig(globals: defaultGlobals())

  proc testInterface(name: string): InterfaceConfig =
    var iface = defaultInterface()
    iface.name = name
    iface.device = fmt"eth-{name}"
    iface

  suite "config diff":
    test "identical configs not changed":
      let a = minimalConfig()
      let b = minimalConfig()
      let d = diff(a, b)
      check not d.changed
      check not d.globalsChanged
      check d.addedInterfaces.len == 0
      check d.removedInterfaces.len == 0
      check d.changedInterfaces.len == 0
      check not d.routingChanged

    test "different globals are changed":
      let a = minimalConfig()
      var b = minimalConfig()
      b.globals.enabled = false
      let d = diff(a, b)
      check d.changed
      check d.globalsChanged

    test "interface added":
      let a = minimalConfig()
      var b = minimalConfig()
      b.interfaces.add(testInterface("wan"))
      let d = diff(a, b)
      check d.changed
      check not d.globalsChanged
      check d.addedInterfaces == @["wan"]
      check d.removedInterfaces.len == 0
      check d.needsFullRebuild

    test "interface removed":
      var a = minimalConfig()
      a.interfaces.add(testInterface("wan"))
      let b = minimalConfig()
      let d = diff(a, b)
      check d.changed
      check d.removedInterfaces == @["wan"]
      check d.addedInterfaces.len == 0
      check d.needsFullRebuild

    test "interface changed":
      var a = minimalConfig()
      a.interfaces.add(testInterface("wan"))
      var b = minimalConfig()
      var wan = testInterface("wan")
      wan.probeInterval = 10
      b.interfaces.add(wan)
      let d = diff(a, b)
      check d.changed
      check d.addedInterfaces.len == 0
      check d.removedInterfaces.len == 0
      check d.changedInterfaces == @["wan"]
      check not d.needsFullRebuild

    test "policy change only":
      var a = minimalConfig()
      a.policies.add(PolicyConfig(
        name: "balanced", members: @["wan_m"], lastResort: lrDefault,
      ))
      var b = minimalConfig()
      b.policies.add(PolicyConfig(
        name: "balanced", members: @["wan_m", "lte_m"], lastResort: lrDefault,
      ))
      let d = diff(a, b)
      check d.changed
      check not d.globalsChanged
      check d.addedInterfaces.len == 0
      check d.changedInterfaces.len == 0
      check d.routingChanged
      check not d.needsFullRebuild
      check d.needsNftables

    test "unchanged interface preserves state on reload":
      # When an interface exists in both old and new configs with same settings,
      # it should NOT appear in addedInterfaces, removedInterfaces, or
      # changedInterfaces — meaning the daemon preserves its tracker state
      # (including Degraded) without interruption.
      var a = minimalConfig()
      a.interfaces.add(testInterface("wan"))
      var b = minimalConfig()
      b.interfaces.add(testInterface("wan"))
      let d = diff(a, b)
      check not d.changed  # identical configs

    test "changed threshold triggers interface change":
      # Changing quality thresholds on an interface marks it as changed.
      # The daemon will rebuild its probe engine, resetting the quality window.
      var a = minimalConfig()
      a.interfaces.add(testInterface("wan"))
      var b = minimalConfig()
      var wan = testInterface("wan")
      wan.latencyThreshold = 200
      b.interfaces.add(wan)
      let d = diff(a, b)
      check d.changed
      check d.changedInterfaces == @["wan"]
      check d.addedInterfaces.len == 0
      check d.removedInterfaces.len == 0
