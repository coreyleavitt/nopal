## Interface state machine and tracker.

type
  InterfaceState* = enum
    isInit, isProbing, isOnline, isDegraded, isOffline

  InterfaceTracker* = object
    name*: string
    index*: int
    device*: string
    ifindex*: uint32
    mark*: uint32
    tableId*: uint32
    state*: InterfaceState
    enabled*: bool
    successCount*: uint32
    failCount*: uint32
    upCount*: uint32
    downCount*: uint32
