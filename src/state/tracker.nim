## Interface tracker: mutable shell around the pure state machine.
##
## Owns the mutable InterfaceTracker state. Provides snapshot() to create
## immutable input for the pure decide() function, and apply() to write
## decisions back.
##
## Architecture: tracker.nim (mutable shell) wraps machine.nim (pure core)

import std/[monotimes, options]
import ./machine
import ../health/dampening

export machine

type
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
    dampening*: Option[DampeningState]
    avgRttMs*: Option[uint32]
    lossPercent*: uint32
    onlineSince*: Option[MonoTime]
    offlineSince*: Option[MonoTime]

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
    dampening: none[DampeningState](),
    avgRttMs: none[uint32](),
    lossPercent: 0,
    onlineSince: none[MonoTime](),
    offlineSince: none[MonoTime](),
  )

proc setDampening*(t: var InterfaceTracker, halflife, ceiling, suppress, reuse: uint32) =
  t.dampening = some(newDampeningState(halflife, ceiling, suppress, reuse))

func isActive*(t: InterfaceTracker): bool =
  ## Returns true if enabled and (Online or Degraded).
  t.enabled and (t.state == isOnline or t.state == isDegraded)

proc snapshot*(t: InterfaceTracker, now: MonoTime): TrackerSnapshot =
  ## Create an immutable snapshot for the pure state machine.
  ## Computes dampening elapsed time from lastUpdate to now.
  let dampSnap = if t.dampening.isSome:
    some(t.dampening.get.toDampeningSnapshot(now))
  else:
    none[DampeningSnapshot]()

  TrackerSnapshot(
    state: t.state,
    successCount: t.successCount,
    failCount: t.failCount,
    upCount: t.upCount,
    downCount: t.downCount,
    dampening: dampSnap,
  )

proc apply*(t: var InterfaceTracker, d: StateDecision, now: MonoTime) =
  ## Write the pure function's decision back to mutable state.
  t.successCount = d.newSuccessCount
  t.failCount = d.newFailCount

  # Update dampening
  if d.newDampening.isSome and t.dampening.isSome:
    var damp = t.dampening.get
    damp.applySnapshot(d.newDampening.get, now)
    t.dampening = some(damp)

  if d.transitioned:
    let oldState = t.state
    t.state = d.newState

    # Update timestamps on state transitions
    case d.newState
    of isOnline:
      if oldState != isDegraded:  # Degraded→Online doesn't reset onlineSince
        t.onlineSince = some(now)
      t.offlineSince = none[MonoTime]()
    of isDegraded:
      if oldState == isProbing:  # First time joining policy
        t.onlineSince = some(now)
      t.offlineSince = none[MonoTime]()
    of isOffline:
      t.offlineSince = some(now)
      t.onlineSince = none[MonoTime]()
    of isProbing:
      t.offlineSince = none[MonoTime]()
    of isInit:
      discard

when isMainModule:
  import std/unittest

  proc makeTracker(): InterfaceTracker =
    newTracker("wan", 0, 0x0100, 100, "eth0.2", 3, 5)

  proc makeDampenedTracker(): InterfaceTracker =
    var t = newTracker("wan", 0, 0x0100, 100, "eth0.2", 3, 3)
    t.setDampening(300, 1000, 500, 250)
    t

  suite "tracker snapshot/apply round-trip":
    test "snapshot captures current state":
      var t = makeTracker()
      t.state = isProbing
      t.successCount = 5
      t.failCount = 2
      let now = getMonoTime()
      let snap = t.snapshot(now)
      check snap.state == isProbing
      check snap.successCount == 5
      check snap.failCount == 2
      check snap.upCount == 3
      check snap.downCount == 5
      check snap.dampening.isNone

    test "snapshot with dampening":
      var t = makeDampenedTracker()
      t.dampening.get.penalty = 500.0
      let now = getMonoTime()
      let snap = t.snapshot(now)
      check snap.dampening.isSome
      check snap.dampening.get.penalty == 500.0

    test "apply writes counters":
      var t = makeTracker()
      let d = StateDecision(
        newSuccessCount: 10,
        newFailCount: 3,
        newDampening: none[DampeningSnapshot](),
        transitioned: false,
      )
      t.apply(d, getMonoTime())
      check t.successCount == 10
      check t.failCount == 3

    test "apply writes state on transition":
      var t = makeTracker()
      t.state = isProbing
      let d = StateDecision(
        newSuccessCount: 3,
        newFailCount: 0,
        newDampening: none[DampeningSnapshot](),
        transitioned: true,
        newState: isOnline,
        effects: {efAddRoutes, efRegenerateNftables},
      )
      let now = getMonoTime()
      t.apply(d, now)
      check t.state == isOnline
      check t.onlineSince.isSome

    test "apply sets offlineSince on offline":
      var t = makeTracker()
      t.state = isDegraded
      let d = StateDecision(
        newSuccessCount: 0,
        newFailCount: 5,
        newDampening: none[DampeningSnapshot](),
        transitioned: true,
        newState: isOffline,
        effects: {efRemoveRoutes},
      )
      let now = getMonoTime()
      t.apply(d, now)
      check t.state == isOffline
      check t.offlineSince.isSome
      check t.onlineSince.isNone

    test "full decide round-trip: probing to online":
      var t = makeTracker()
      t.state = isProbing
      t.successCount = 2
      let now = getMonoTime()
      let snap = t.snapshot(now)
      let event = StateEvent(kind: sekProbeResult, success: true, qualityOk: true)
      let d = decide(snap, event)
      check d.transitioned
      check d.newState == isOnline
      t.apply(d, now)
      check t.state == isOnline
      check t.successCount == 3

    test "full decide round-trip: link down from online":
      var t = makeTracker()
      t.state = isOnline
      t.successCount = 10
      let now = getMonoTime()
      let snap = t.snapshot(now)
      let d = decide(snap, StateEvent(kind: sekLinkDown))
      check d.transitioned
      check d.newState == isOffline
      t.apply(d, now)
      check t.state == isOffline
      check t.successCount == 0
      check t.failCount == 0

    test "isActive check":
      var t = makeTracker()
      check not t.isActive
      t.state = isOnline
      check t.isActive
      t.state = isDegraded
      check t.isActive
      t.state = isOffline
      check not t.isActive
      t.state = isOnline
      t.enabled = false
      check not t.isActive
