## Pure state machine core for interface lifecycle management.
##
## This module is the testable heart of nopal's state machine.
## It contains only pure functions and value types — no I/O, no time reads,
## no logging, no mutation of external state.
##
## Architecture: "functional core, imperative shell"
##   machine.nim (pure) ← tracker.nim (mutable shell) ← daemon.nim (orchestrator)
##
## The single entry point is `decide`, which takes a snapshot of the current
## state and an event, and returns a decision (new state + effects).

import std/[options, math]

type
  InterfaceState* = enum
    isInit      ## Waiting for netifd to report interface up
    isProbing   ## Link up, probes running, not yet confirmed
    isOnline    ## Healthy, participating in policies
    isDegraded  ## Failing probes or quality exceeded, still in policies
    isOffline   ## Down, removed from policies

  Effect* = enum
    efRegenerateNftables
    efAddRoutes
    efRemoveRoutes
    efUpdateDns
    efRemoveDns
    efBroadcastEvent
    efWriteStatus
    efCancelProbeTimers
    efResetProbeCounters
    efScheduleFirstProbe
    efFlushConntrack
    efScheduleDampenDecay

  StateEventKind* = enum
    sekProbeResult
    sekLinkUp
    sekLinkDown
    sekDampenDecay

  StateEvent* {.requiresInit.} = object
    case kind*: StateEventKind
    of sekProbeResult:
      success*: bool
      qualityOk*: bool
    of sekLinkUp, sekLinkDown, sekDampenDecay: discard

  DampeningSnapshot* = object
    penalty*: float64
    suppressed*: bool
    halflife*: uint32
    ceiling*: uint32
    suppressThreshold*: uint32
    reuseThreshold*: uint32
    elapsedSecs*: float64  ## Pre-computed by caller from MonoTime delta

  TrackerSnapshot* {.requiresInit.} = object
    state*: InterfaceState
    successCount*: uint32
    failCount*: uint32
    upCount*: uint32
    downCount*: uint32
    dampening*: Option[DampeningSnapshot]

  StateDecision* {.requiresInit.} = object
    newSuccessCount*: uint32
    newFailCount*: uint32
    newDampening*: Option[DampeningSnapshot]
    case transitioned*: bool
    of true:
      newState*: InterfaceState
      effects*: set[Effect]
    of false: discard

func `$`*(s: InterfaceState): string =
  case s
  of isInit: "init"
  of isProbing: "probing"
  of isOnline: "online"
  of isDegraded: "degraded"
  of isOffline: "offline"

# ---------------------------------------------------------------------------
# Pure dampening helpers
# ---------------------------------------------------------------------------

const PenaltyPerFailure* = 1000.0

func decayPenalty*(snap: DampeningSnapshot): DampeningSnapshot {.raises: [].} =
  ## Apply exponential decay to penalty based on elapsed time.
  ## Returns a new snapshot with updated penalty and suppression.
  result = snap
  if snap.halflife == 0 or snap.elapsedSecs <= 0.0:
    return
  let decayFactor = pow(2.0, -snap.elapsedSecs / snap.halflife.float64)
  result.penalty = snap.penalty * decayFactor
  if result.penalty < 0.1:
    result.penalty = 0.0
  if result.suppressed and result.penalty < snap.reuseThreshold.float64:
    result.suppressed = false

func applyFailurePenalty*(snap: DampeningSnapshot): DampeningSnapshot {.raises: [].} =
  ## Decay first, then apply failure penalty. Returns new snapshot.
  result = decayPenalty(snap)
  result.penalty = result.penalty + PenaltyPerFailure
  if result.penalty > snap.ceiling.float64:
    result.penalty = snap.ceiling.float64
  if result.penalty >= snap.suppressThreshold.float64:
    result.suppressed = true

# ---------------------------------------------------------------------------
# Effect sets for each transition
# ---------------------------------------------------------------------------

const
  # Going online: add to routing
  OnlineEffects = {efAddRoutes, efRegenerateNftables, efUpdateDns,
                   efBroadcastEvent, efWriteStatus}
  # Going offline: remove from routing
  OfflineEffects = {efRemoveRoutes, efRegenerateNftables, efRemoveDns,
                    efBroadcastEvent, efWriteStatus, efFlushConntrack}
  # No route changes (degraded ↔ online, probing → offline)
  StatusOnlyEffects = {efBroadcastEvent, efWriteStatus}
  # Link up: start probing
  LinkUpEffects = {efCancelProbeTimers, efResetProbeCounters,
                   efScheduleFirstProbe, efBroadcastEvent, efWriteStatus}
  # Link down: go offline, cancel probes
  LinkDownEffects = {efRemoveRoutes, efRegenerateNftables, efRemoveDns,
                     efCancelProbeTimers, efFlushConntrack,
                     efBroadcastEvent, efWriteStatus}

# ---------------------------------------------------------------------------
# Core decision function
# ---------------------------------------------------------------------------

func noTransition(snap: TrackerSnapshot,
                  newSucc, newFail: uint32,
                  newDamp: Option[DampeningSnapshot]): StateDecision {.inline, raises: [].} =
  StateDecision(
    newSuccessCount: newSucc,
    newFailCount: newFail,
    newDampening: newDamp,
    transitioned: false,
  )

func transition(snap: TrackerSnapshot,
                newSucc, newFail: uint32,
                newDamp: Option[DampeningSnapshot],
                newState: InterfaceState,
                effects: set[Effect]): StateDecision {.inline, raises: [].} =
  StateDecision(
    newSuccessCount: newSucc,
    newFailCount: newFail,
    newDampening: newDamp,
    transitioned: true,
    newState: newState,
    effects: effects,
  )

func effectsForTransition(oldState, newState: InterfaceState): set[Effect] {.raises: [].} =
  ## Determine which effects to emit based on old → new state transition.
  case oldState
  of isDegraded:
    case newState
    of isOnline: StatusOnlyEffects
    of isOffline: OfflineEffects
    else: StatusOnlyEffects
  of isOnline:
    case newState
    of isDegraded: StatusOnlyEffects
    of isOffline: OfflineEffects
    else: StatusOnlyEffects
  of isProbing:
    case newState
    of isOnline, isDegraded: OnlineEffects
    of isOffline: StatusOnlyEffects
    else: StatusOnlyEffects
  of isOffline, isInit:
    case newState
    of isProbing: LinkUpEffects
    of isOnline: OnlineEffects
    else: StatusOnlyEffects

func decideProbeSuccess(snap: TrackerSnapshot,
                        qualityOk: bool): StateDecision {.raises: [].} =
  let newSucc = snap.successCount + 1
  let newFail = uint32(0)
  let damp = snap.dampening

  case snap.state
  of isProbing:
    if newSucc >= snap.upCount:
      # Check dampening before transitioning
      if damp.isSome:
        let decayed = decayPenalty(damp.get)
        if decayed.suppressed:
          return noTransition(snap, newSucc, newFail, some(decayed))
        # Not suppressed — proceed with transition
        let newState = if qualityOk: isOnline else: isDegraded
        return transition(snap, newSucc, newFail, some(decayed), newState,
                         effectsForTransition(snap.state, newState))
      # No dampening
      let newState = if qualityOk: isOnline else: isDegraded
      return transition(snap, newSucc, newFail, damp, newState,
                       effectsForTransition(snap.state, newState))
    noTransition(snap, newSucc, newFail, damp)

  of isDegraded:
    if not qualityOk:
      return noTransition(snap, newSucc, newFail, damp)
    # Quality recovered — check dampening
    if damp.isSome:
      let decayed = decayPenalty(damp.get)
      if decayed.suppressed:
        return noTransition(snap, newSucc, newFail, some(decayed))
      return transition(snap, newSucc, newFail, some(decayed), isOnline,
                       effectsForTransition(isDegraded, isOnline))
    transition(snap, newSucc, newFail, damp, isOnline,
             effectsForTransition(isDegraded, isOnline))

  of isOnline:
    if not qualityOk:
      return transition(snap, newSucc, newFail, damp, isDegraded,
                       effectsForTransition(isOnline, isDegraded))
    noTransition(snap, newSucc, newFail, damp)

  else:
    noTransition(snap, newSucc, newFail, damp)

func decideProbeFailure(snap: TrackerSnapshot): StateDecision {.raises: [].} =
  let newSucc = uint32(0)
  let newFail = snap.failCount + 1
  var damp = snap.dampening

  case snap.state
  of isOnline:
    # First failure: always degrade
    return transition(snap, newSucc, newFail, damp, isDegraded,
                     effectsForTransition(isOnline, isDegraded))

  of isDegraded:
    if newFail >= snap.downCount:
      # Apply dampening failure penalty
      if damp.isSome:
        damp = some(applyFailurePenalty(damp.get))
      var effects = effectsForTransition(isDegraded, isOffline)
      if damp.isSome and damp.get.suppressed:
        effects.incl(efScheduleDampenDecay)
      return transition(snap, newSucc, newFail, damp, isOffline, effects)
    noTransition(snap, newSucc, newFail, damp)

  of isProbing:
    if newFail >= snap.downCount:
      if damp.isSome:
        damp = some(applyFailurePenalty(damp.get))
      var effects = effectsForTransition(isProbing, isOffline)
      if damp.isSome and damp.get.suppressed:
        effects.incl(efScheduleDampenDecay)
      return transition(snap, newSucc, newFail, damp, isOffline, effects)
    noTransition(snap, newSucc, newFail, damp)

  else:
    noTransition(snap, newSucc, newFail, damp)

func decideLinkUp(snap: TrackerSnapshot): StateDecision {.raises: [].} =
  case snap.state
  of isInit, isOffline:
    transition(snap, 0, 0, snap.dampening, isProbing,
              effectsForTransition(snap.state, isProbing))
  else:
    noTransition(snap, snap.successCount, snap.failCount, snap.dampening)

func decideLinkDown(snap: TrackerSnapshot): StateDecision {.raises: [].} =
  case snap.state
  of isOffline, isInit:
    noTransition(snap, snap.successCount, snap.failCount, snap.dampening)
  else:
    transition(snap, 0, 0, snap.dampening, isOffline,
              LinkDownEffects)

func decideDampenDecay(snap: TrackerSnapshot): StateDecision {.raises: [].} =
  ## Dampening decay timer fired. Decay penalty and check if reuse threshold
  ## crossed — if so, transition from Offline to Probing.
  if snap.dampening.isNone:
    return noTransition(snap, snap.successCount, snap.failCount, snap.dampening)

  let decayed = decayPenalty(snap.dampening.get)

  if decayed.suppressed:
    # Still suppressed — update dampening, schedule another decay check
    var d = noTransition(snap, snap.successCount, snap.failCount, some(decayed))
    return d

  # Penalty dropped below reuse — unsuppressed
  if snap.state == isOffline:
    return transition(snap, 0, 0, some(decayed), isProbing,
                     effectsForTransition(isOffline, isProbing))

  # Not offline — just update dampening
  noTransition(snap, snap.successCount, snap.failCount, some(decayed))

func decide*(snap: TrackerSnapshot, event: StateEvent): StateDecision {.raises: [].} =
  ## Pure state machine decision function.
  ## Takes an immutable snapshot of current state and an event.
  ## Returns the complete decision: new counters, new dampening, and
  ## optional state transition with effect set.
  case event.kind
  of sekProbeResult:
    if event.success:
      decideProbeSuccess(snap, event.qualityOk)
    else:
      decideProbeFailure(snap)
  of sekLinkUp:
    decideLinkUp(snap)
  of sekLinkDown:
    decideLinkDown(snap)
  of sekDampenDecay:
    decideDampenDecay(snap)

# ===========================================================================
# Tests
# ===========================================================================

when isMainModule:
  import std/[unittest, math]

  func makeSnap(state: InterfaceState, successes: uint32 = 0, failures: uint32 = 0,
                upCount: uint32 = 3, downCount: uint32 = 5): TrackerSnapshot =
    TrackerSnapshot(
      state: state,
      successCount: successes,
      failCount: failures,
      upCount: upCount,
      downCount: downCount,
      dampening: none[DampeningSnapshot](),
    )

  func makeDampSnap(penalty: float64 = 0.0, suppressed: bool = false,
                    elapsed: float64 = 0.0): DampeningSnapshot =
    DampeningSnapshot(
      penalty: penalty, suppressed: suppressed,
      halflife: 300, ceiling: 1000,
      suppressThreshold: 500, reuseThreshold: 250,
      elapsedSecs: elapsed,
    )

  func probeOk(qualityOk: bool = true): StateEvent =
    StateEvent(kind: sekProbeResult, success: true, qualityOk: qualityOk)

  func probeFail(): StateEvent =
    StateEvent(kind: sekProbeResult, success: false, qualityOk: false)

  func linkUp(): StateEvent = StateEvent(kind: sekLinkUp)
  func linkDown(): StateEvent = StateEvent(kind: sekLinkDown)
  func dampenDecay(): StateEvent = StateEvent(kind: sekDampenDecay)

  suite "decide: probe success":
    test "probing increments success count without transition":
      let snap = makeSnap(isProbing, successes = 0)
      let d = decide(snap, probeOk())
      check not d.transitioned
      check d.newSuccessCount == 1
      check d.newFailCount == 0

    test "probing to online after up_count":
      let snap = makeSnap(isProbing, successes = 2)
      let d = decide(snap, probeOk())
      check d.transitioned
      check d.newState == isOnline
      check d.newSuccessCount == 3
      check efAddRoutes in d.effects
      check efRegenerateNftables in d.effects
      check efUpdateDns in d.effects
      check efBroadcastEvent in d.effects
      check efWriteStatus in d.effects

    test "probing to degraded on bad quality after up_count":
      let snap = makeSnap(isProbing, successes = 2)
      let d = decide(snap, probeOk(qualityOk = false))
      check d.transitioned
      check d.newState == isDegraded
      check efAddRoutes in d.effects

    test "degraded recovers to online on good quality":
      let snap = makeSnap(isDegraded, successes = 5)
      let d = decide(snap, probeOk())
      check d.transitioned
      check d.newState == isOnline
      check efAddRoutes notin d.effects  # routes already present
      check efBroadcastEvent in d.effects

    test "degraded stays degraded on bad quality":
      let snap = makeSnap(isDegraded, successes = 5)
      let d = decide(snap, probeOk(qualityOk = false))
      check not d.transitioned

    test "online degrades on bad quality":
      let snap = makeSnap(isOnline, successes = 10)
      let d = decide(snap, probeOk(qualityOk = false))
      check d.transitioned
      check d.newState == isDegraded
      check efAddRoutes notin d.effects
      check efRemoveRoutes notin d.effects

    test "online stays online on good quality":
      let snap = makeSnap(isOnline, successes = 10)
      let d = decide(snap, probeOk())
      check not d.transitioned
      check d.newSuccessCount == 11

    test "success resets fail count":
      let snap = makeSnap(isProbing, successes = 0, failures = 3)
      let d = decide(snap, probeOk())
      check d.newFailCount == 0
      check d.newSuccessCount == 1

  suite "decide: probe failure":
    test "online immediately degrades on failure":
      let snap = makeSnap(isOnline)
      let d = decide(snap, probeFail())
      check d.transitioned
      check d.newState == isDegraded
      check d.newSuccessCount == 0
      check d.newFailCount == 1

    test "degraded goes offline after down_count":
      let snap = makeSnap(isDegraded, failures = 4, downCount = 5)
      let d = decide(snap, probeFail())
      check d.transitioned
      check d.newState == isOffline
      check d.newFailCount == 5
      check efRemoveRoutes in d.effects
      check efFlushConntrack in d.effects

    test "degraded stays degraded before down_count":
      let snap = makeSnap(isDegraded, failures = 2, downCount = 5)
      let d = decide(snap, probeFail())
      check not d.transitioned
      check d.newFailCount == 3

    test "probing goes offline after down_count":
      let snap = makeSnap(isProbing, failures = 4, downCount = 5)
      let d = decide(snap, probeFail())
      check d.transitioned
      check d.newState == isOffline

    test "failure resets success count":
      let snap = makeSnap(isDegraded, successes = 10, failures = 0)
      let d = decide(snap, probeFail())
      check d.newSuccessCount == 0
      check d.newFailCount == 1

  suite "decide: link events":
    test "init to probing on link up":
      let snap = makeSnap(isInit)
      let d = decide(snap, linkUp())
      check d.transitioned
      check d.newState == isProbing
      check d.newSuccessCount == 0
      check d.newFailCount == 0
      check efCancelProbeTimers in d.effects
      check efResetProbeCounters in d.effects
      check efScheduleFirstProbe in d.effects

    test "offline to probing on link up":
      let snap = makeSnap(isOffline, failures = 10)
      let d = decide(snap, linkUp())
      check d.transitioned
      check d.newState == isProbing
      check d.newSuccessCount == 0
      check d.newFailCount == 0

    test "link up from online is no-op":
      let snap = makeSnap(isOnline, successes = 5)
      let d = decide(snap, linkUp())
      check not d.transitioned
      check d.newSuccessCount == 5

    test "link down from online goes offline":
      let snap = makeSnap(isOnline, successes = 10)
      let d = decide(snap, linkDown())
      check d.transitioned
      check d.newState == isOffline
      check d.newSuccessCount == 0
      check d.newFailCount == 0
      check efRemoveRoutes in d.effects
      check efCancelProbeTimers in d.effects
      check efFlushConntrack in d.effects

    test "link down from probing goes offline":
      let snap = makeSnap(isProbing, successes = 2)
      let d = decide(snap, linkDown())
      check d.transitioned
      check d.newState == isOffline

    test "link down from offline is no-op":
      let snap = makeSnap(isOffline)
      let d = decide(snap, linkDown())
      check not d.transitioned

    test "link down from init is no-op":
      let snap = makeSnap(isInit)
      let d = decide(snap, linkDown())
      check not d.transitioned

  suite "decide: dampening":
    test "dampening blocks probing to online":
      var snap = makeSnap(isProbing, successes = 2)
      snap.dampening = some(makeDampSnap(penalty = 800.0, suppressed = true))
      let d = decide(snap, probeOk())
      check not d.transitioned
      check d.newDampening.isSome
      check d.newDampening.get.suppressed

    test "dampening blocks degraded to online":
      var snap = makeSnap(isDegraded)
      snap.dampening = some(makeDampSnap(penalty = 800.0, suppressed = true))
      let d = decide(snap, probeOk())
      check not d.transitioned

    test "unsuppressed dampening allows transition":
      var snap = makeSnap(isProbing, successes = 2)
      snap.dampening = some(makeDampSnap(penalty = 100.0, suppressed = false))
      let d = decide(snap, probeOk())
      check d.transitioned
      check d.newState == isOnline

    test "failure with dampening applies penalty":
      var snap = makeSnap(isDegraded, failures = 4, downCount = 5)
      snap.dampening = some(makeDampSnap(penalty = 0.0, elapsed = 1.0))
      let d = decide(snap, probeFail())
      check d.transitioned
      check d.newState == isOffline
      check d.newDampening.isSome
      check d.newDampening.get.penalty >= PenaltyPerFailure - 1.0
      check d.newDampening.get.suppressed
      check efScheduleDampenDecay in d.effects

    test "failure without dampening no schedule":
      let snap = makeSnap(isDegraded, failures = 4, downCount = 5)
      let d = decide(snap, probeFail())
      check d.transitioned
      check d.newState == isOffline
      check efScheduleDampenDecay notin d.effects

  suite "decide: dampening decay event":
    test "decay reduces penalty":
      var snap = makeSnap(isOffline)
      # halflife=300, elapsed=300 -> penalty halves
      snap.dampening = some(makeDampSnap(penalty = 1000.0, suppressed = true, elapsed = 300.0))
      let d = decide(snap, dampenDecay())
      check not d.transitioned  # still suppressed (500 > 250 reuse)
      check d.newDampening.isSome
      check d.newDampening.get.penalty < 1000.0
      check abs(d.newDampening.get.penalty - 500.0) < 1.0

    test "decay crosses reuse threshold -> probing":
      var snap = makeSnap(isOffline)
      # penalty=300, halflife=300, elapsed=300 -> 150 (below reuse=250)
      snap.dampening = some(makeDampSnap(penalty = 300.0, suppressed = true, elapsed = 300.0))
      let d = decide(snap, dampenDecay())
      check d.transitioned
      check d.newState == isProbing
      check d.newDampening.isSome
      check not d.newDampening.get.suppressed

    test "decay on non-offline just updates penalty":
      var snap = makeSnap(isProbing)
      snap.dampening = some(makeDampSnap(penalty = 400.0, suppressed = false, elapsed = 100.0))
      let d = decide(snap, dampenDecay())
      check not d.transitioned
      check d.newDampening.isSome
      check d.newDampening.get.penalty < 400.0

    test "decay without dampening is no-op":
      let snap = makeSnap(isOffline)
      let d = decide(snap, dampenDecay())
      check not d.transitioned
      check d.newDampening.isNone

  suite "TDD invariants":
    test "probe success never decreases success count":
      for state in [isProbing, isOnline, isDegraded]:
        for succ in [uint32(0), 1, 5, 10]:
          let snap = makeSnap(state, successes = succ)
          let d = decide(snap, probeOk())
          check d.newSuccessCount >= succ

    test "addRoutes always paired with regenerateNftables":
      for state in [isInit, isProbing, isOnline, isDegraded, isOffline]:
        for event in [probeOk(), probeFail(), linkUp(), linkDown()]:
          let snap = makeSnap(state)
          let d = decide(snap, event)
          if d.transitioned:
            if efAddRoutes in d.effects:
              check efRegenerateNftables in d.effects
            if efRemoveRoutes in d.effects:
              check efRegenerateNftables in d.effects

    test "dampening suppressed never transitions to online":
      for state in [isProbing, isDegraded]:
        var snap = makeSnap(state, successes = 100, upCount = 1)
        snap.dampening = some(makeDampSnap(penalty = 800.0, suppressed = true))
        let d = decide(snap, probeOk())
        check not d.transitioned or d.newState != isOnline

    test "every transition includes broadcast and status":
      for oldState in InterfaceState:
        for event in [probeOk(), probeOk(false), probeFail(), linkUp(), linkDown()]:
          let snap = makeSnap(oldState, successes = 100, failures = 100,
                             upCount = 1, downCount = 1)
          let d = decide(snap, event)
          if d.transitioned:
            check efBroadcastEvent in d.effects
            check efWriteStatus in d.effects
