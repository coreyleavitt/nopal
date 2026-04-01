## Interface state machine and tracker.

type
  InterfaceState* = enum
    isInit      ## Waiting for netifd to report interface up
    isProbing   ## Link up, probes running, not yet confirmed
    isOnline    ## Healthy, participating in policies
    isDegraded  ## Failing probes or quality exceeded, still in policies
    isOffline   ## Down, removed from policies

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

proc newTracker*(name: string, index: int, mark: uint32, tableId: uint32,
                 device: string, upCount, downCount: uint32): InterfaceTracker =
  InterfaceTracker(
    name: name,
    index: index,
    mark: mark,
    tableId: tableId,
    device: device,
    state: isInit,
    enabled: true,
    successCount: 0,
    failCount: 0,
    upCount: upCount,
    downCount: downCount,
  )

func isActive*(t: InterfaceTracker): bool =
  ## Returns true if enabled and (Online or Degraded).
  t.enabled and (t.state == isOnline or t.state == isDegraded)
