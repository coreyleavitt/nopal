## Interface state machine and tracker.
##
## Manages the lifecycle of each WAN interface through five states:
##   Init -> Probing -> Online <-> Degraded -> Offline
##
## Both Online and Degraded participate in routing. Degraded means
## reachable but with poor quality, not unreachable.

import std/[monotimes, options, logging, strformat]
import ../health/dampening

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
    dampening*: Option[DampeningState]
    avgRttMs*: Option[uint32]
    lossPercent*: uint32
    onlineSince*: Option[MonoTime]
    offlineSince*: Option[MonoTime]

func `$`*(s: InterfaceState): string =
  case s
  of isInit: "init"
  of isProbing: "probing"
  of isOnline: "online"
  of isDegraded: "degraded"
  of isOffline: "offline"

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

proc probeSuccess*(t: var InterfaceTracker, qualityOk: bool): Option[InterfaceState] =
  ## Record a successful probe. Returns new state if a transition occurred.
  t.failCount = 0
  t.successCount += 1

  case t.state
  of isProbing:
    if t.successCount >= t.upCount:
      # Check dampening
      if t.dampening.isSome:
        var damp = t.dampening.get
        damp.decay()
        t.dampening = some(damp)
        if damp.isSuppressed:
          info fmt"{t.name}: probing -> online blocked by dampening"
          return none[InterfaceState]()

      if qualityOk:
        t.state = isOnline
        t.onlineSince = some(getMonoTime())
        t.offlineSince = none[MonoTime]()
        info fmt"{t.name}: probing -> online ({t.successCount} successes)"
        return some(isOnline)
      else:
        t.state = isDegraded
        warn fmt"{t.name}: probing -> degraded (quality threshold)"
        return some(isDegraded)
    return none[InterfaceState]()

  of isDegraded:
    if not qualityOk:
      return none[InterfaceState]()
    # Check dampening
    if t.dampening.isSome:
      var damp = t.dampening.get
      damp.decay()
      t.dampening = some(damp)
      if damp.isSuppressed:
        info fmt"{t.name}: degraded -> online blocked by dampening"
        return none[InterfaceState]()
    t.state = isOnline
    info fmt"{t.name}: degraded -> online (recovered)"
    return some(isOnline)

  of isOnline:
    if not qualityOk:
      t.state = isDegraded
      warn fmt"{t.name}: online -> degraded (quality threshold)"
      return some(isDegraded)
    return none[InterfaceState]()

  else:
    return none[InterfaceState]()

proc applyDampeningFailure(t: var InterfaceTracker) =
  if t.dampening.isSome:
    var damp = t.dampening.get
    let suppressed = damp.applyFailure()
    t.dampening = some(damp)
    if suppressed:
      warn fmt"{t.name}: dampening suppressed (penalty: {damp.penalty})"

proc probeFailure*(t: var InterfaceTracker): Option[InterfaceState] =
  ## Record a failed probe. Returns new state if a transition occurred.
  t.successCount = 0
  t.failCount += 1

  case t.state
  of isOnline:
    t.state = isDegraded
    warn fmt"{t.name}: online -> degraded (probe failure)"
    return some(isDegraded)

  of isDegraded:
    if t.failCount >= t.downCount:
      t.applyDampeningFailure()
      t.state = isOffline
      t.offlineSince = some(getMonoTime())
      t.onlineSince = none[MonoTime]()
      warn fmt"{t.name}: degraded -> offline ({t.failCount} failures)"
      return some(isOffline)
    return none[InterfaceState]()

  of isProbing:
    if t.failCount >= t.downCount:
      t.applyDampeningFailure()
      t.state = isOffline
      t.offlineSince = some(getMonoTime())
      t.onlineSince = none[MonoTime]()
      warn fmt"{t.name}: probing -> offline ({t.failCount} failures)"
      return some(isOffline)
    return none[InterfaceState]()

  else:
    return none[InterfaceState]()

proc linkUp*(t: var InterfaceTracker): Option[InterfaceState] =
  ## Interface came up via netifd. Returns new state if a transition occurred.
  case t.state
  of isInit, isOffline:
    t.successCount = 0
    t.failCount = 0
    t.state = isProbing
    t.offlineSince = none[MonoTime]()
    info fmt"{t.name}: {t.state} -> probing (link up)"
    return some(isProbing)
  else:
    return none[InterfaceState]()

proc linkDown*(t: var InterfaceTracker): Option[InterfaceState] =
  ## Interface went down via netifd. Returns new state if a transition occurred.
  case t.state
  of isOffline, isInit:
    return none[InterfaceState]()
  else:
    let prev = t.state
    t.successCount = 0
    t.failCount = 0
    t.state = isOffline
    t.offlineSince = some(getMonoTime())
    t.onlineSince = none[MonoTime]()
    warn fmt"{t.name}: {prev} -> offline (link down)"
    return some(isOffline)

when isMainModule:
  import std/unittest

  proc makeTracker(): InterfaceTracker =
    newTracker("wan", 0, 0x0100, 100, "eth0.2", 3, 5)

  proc makeDampenedTracker(): InterfaceTracker =
    var t = newTracker("wan", 0, 0x0100, 100, "eth0.2", 3, 3)
    t.setDampening(300, 1000, 500, 250)
    t

  suite "interface state machine":
    test "init to probing on link up":
      var t = makeTracker()
      check t.state == isInit
      let s = t.linkUp()
      check s.isSome
      check s.get == isProbing
      check t.state == isProbing

    test "probing to online after up_count":
      var t = makeTracker()
      discard t.linkUp()
      check t.probeSuccess(true).isNone
      check t.probeSuccess(true).isNone
      let s = t.probeSuccess(true)
      check s.isSome
      check s.get == isOnline
      check t.state == isOnline

    test "online to degraded to offline":
      var t = makeTracker()
      discard t.linkUp()
      for i in 0 ..< 3: discard t.probeSuccess(true)
      check t.state == isOnline

      # First failure: degrade
      let s1 = t.probeFailure()
      check s1.isSome
      check s1.get == isDegraded

      # Next 3 failures: stay degraded (need 5 total)
      for i in 0 ..< 3:
        check t.probeFailure().isNone

      # 5th failure: offline
      let s2 = t.probeFailure()
      check s2.isSome
      check s2.get == isOffline

    test "degraded recovers on success":
      var t = makeTracker()
      discard t.linkUp()
      for i in 0 ..< 3: discard t.probeSuccess(true)
      discard t.probeFailure()  # -> degraded
      let s = t.probeSuccess(true)
      check s.isSome
      check s.get == isOnline

    test "offline to probing on link up":
      var t = makeTracker()
      discard t.linkUp()
      for i in 0 ..< 3: discard t.probeSuccess(true)
      discard t.probeFailure()
      for i in 0 ..< 4: discard t.probeFailure()  # -> offline
      check t.state == isOffline

      let s = t.linkUp()
      check s.isSome
      check s.get == isProbing

    test "link down from online":
      var t = makeTracker()
      discard t.linkUp()
      for i in 0 ..< 3: discard t.probeSuccess(true)
      let s = t.linkDown()
      check s.isSome
      check s.get == isOffline
      check t.successCount == 0
      check t.failCount == 0

    test "dampening blocks online after flap":
      var t = makeDampenedTracker()
      discard t.linkUp()
      for i in 0 ..< 3: discard t.probeSuccess(true)
      check t.state == isOnline

      # Go offline (3 failures)
      discard t.probeFailure()  # -> degraded
      discard t.probeFailure()
      let s = t.probeFailure()
      check s.isSome
      check s.get == isOffline

      # Dampening should be suppressed
      check t.dampening.isSome
      check t.dampening.get.isSuppressed

      # Link back up, start probing
      discard t.linkUp()
      check t.state == isProbing

      # Probes succeed but dampening blocks Online
      for i in 0 ..< 10:
        check t.probeSuccess(true).isNone
      check t.state == isProbing

    test "dampening allows online after decay":
      var t = makeDampenedTracker()
      discard t.linkUp()
      for i in 0 ..< 3: discard t.probeSuccess(true)

      # Go offline -> dampening suppressed
      discard t.probeFailure()
      discard t.probeFailure()
      discard t.probeFailure()
      check t.state == isOffline
      check t.dampening.get.isSuppressed

      # Simulate decay: manually set penalty below reuse
      var damp = t.dampening.get
      damp.penalty = 100.0
      damp.suppressed = false
      t.dampening = some(damp)

      # Link up, probe
      discard t.linkUp()
      for i in 0 ..< 3: discard t.probeSuccess(true)
      check t.state == isOnline

    test "no dampening does not block":
      var t = makeTracker()
      discard t.linkUp()
      for i in 0 ..< 3: discard t.probeSuccess(true)

      # Go offline
      discard t.probeFailure()
      for i in 0 ..< 4: discard t.probeFailure()
      check t.state == isOffline

      # Come back: no dampening, immediate online after up_count
      discard t.linkUp()
      for i in 0 ..< 3: discard t.probeSuccess(true)
      check t.state == isOnline

    test "quality degrades online to degraded":
      var t = makeTracker()
      discard t.linkUp()
      for i in 0 ..< 3: discard t.probeSuccess(true)
      check t.state == isOnline

      let s = t.probeSuccess(false)
      check s.isSome
      check s.get == isDegraded

    test "quality recovery degraded to online":
      var t = makeTracker()
      discard t.linkUp()
      for i in 0 ..< 3: discard t.probeSuccess(true)
      discard t.probeSuccess(false)  # -> degraded
      check t.state == isDegraded

      let s = t.probeSuccess(true)
      check s.isSome
      check s.get == isOnline

    test "quality stays degraded while bad":
      var t = makeTracker()
      discard t.linkUp()
      for i in 0 ..< 3: discard t.probeSuccess(true)
      discard t.probeSuccess(false)  # -> degraded

      check t.probeSuccess(false).isNone
      check t.state == isDegraded

    test "probing to degraded on bad quality":
      var t = makeTracker()
      discard t.linkUp()
      discard t.probeSuccess(true)
      discard t.probeSuccess(true)
      let s = t.probeSuccess(false)
      check s.isSome
      check s.get == isDegraded

    test "quality degraded then probe failure goes offline":
      var t = makeTracker()
      discard t.linkUp()
      for i in 0 ..< 3: discard t.probeSuccess(true)
      discard t.probeSuccess(false)  # -> degraded via quality
      check t.state == isDegraded

      # Now actual probe failures accumulate
      for i in 0 ..< 4:
        check t.probeFailure().isNone
      # 5th failure: offline (down_count=5)
      let s = t.probeFailure()
      check s.isSome
      check s.get == isOffline
