## Config change detection for hot reload.

import schema

type
  ConfigDiff* = object
    changed*: bool
    globalsChanged*: bool
    addedInterfaces*: seq[string]
    removedInterfaces*: seq[string]
    changedInterfaces*: seq[string]
    routingChanged*: bool
    interfaceOrderChanged*: bool

proc computeDiff*(old, new: NopalConfig): ConfigDiff =
  discard # not yet implemented

proc needsFullRebuild*(diff: ConfigDiff): bool =
  diff.globalsChanged or
    diff.addedInterfaces.len > 0 or
    diff.removedInterfaces.len > 0 or
    diff.interfaceOrderChanged

proc needsNftables*(diff: ConfigDiff): bool =
  diff.routingChanged or diff.changedInterfaces.len > 0
