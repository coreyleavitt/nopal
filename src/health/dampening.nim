## RFC 2439 route dampening: mutable state + snapshot conversion.
##
## This module holds the mutable DampeningState that the daemon owns.
## Pure decay/failure logic lives in state/machine.nim (DampeningSnapshot).
## This module provides conversion between the mutable state and immutable
## snapshots for the pure state machine.

import std/[monotimes, times]
import ../state/machine

type
  DampeningState* = object
    penalty*: float64
    suppressed*: bool
    halflife*: uint32      ## seconds for 50% decay
    ceiling*: uint32       ## max penalty
    suppress*: uint32      ## penalty >= this -> suppress
    reuse*: uint32         ## penalty < this -> unsuppress
    lastUpdate*: MonoTime  ## for elapsed time calculation

proc newDampeningState*(halflife, ceiling, suppress, reuse: uint32): DampeningState =
  DampeningState(
    penalty: 0.0,
    suppressed: false,
    halflife: halflife,
    ceiling: ceiling,
    suppress: suppress,
    reuse: reuse,
    lastUpdate: getMonoTime(),
  )

proc toDampeningSnapshot*(ds: DampeningState, now: MonoTime): DampeningSnapshot =
  ## Create an immutable snapshot for the pure state machine.
  ## Computes elapsedSecs from lastUpdate to now.
  let elapsed = (now - ds.lastUpdate).inNanoseconds.float64 / 1_000_000_000.0
  DampeningSnapshot(
    penalty: ds.penalty,
    suppressed: ds.suppressed,
    halflife: ds.halflife,
    ceiling: ds.ceiling,
    suppressThreshold: ds.suppress,
    reuseThreshold: ds.reuse,
    elapsedSecs: elapsed,
  )

proc applySnapshot*(ds: var DampeningState, snap: DampeningSnapshot, now: MonoTime) =
  ## Write the pure function's decision back to mutable state.
  ds.penalty = snap.penalty
  ds.suppressed = snap.suppressed
  ds.lastUpdate = now

func isSuppressed*(ds: DampeningState): bool =
  ds.suppressed

proc reset*(ds: var DampeningState) =
  ds.penalty = 0.0
  ds.suppressed = false
  ds.lastUpdate = getMonoTime()

when isMainModule:
  import std/[unittest, math]

  suite "dampening":
    test "new state is not suppressed":
      let state = newDampeningState(300, 1000, 500, 250)
      check not state.isSuppressed
      check state.penalty == 0.0

    test "snapshot computes elapsed time":
      var state = newDampeningState(300, 1000, 500, 250)
      let past = state.lastUpdate
      let future = past + initDuration(seconds = 60)
      let snap = state.toDampeningSnapshot(future)
      check abs(snap.elapsedSecs - 60.0) < 0.1
      check snap.halflife == 300
      check snap.suppressThreshold == 500
      check snap.reuseThreshold == 250

    test "applySnapshot writes back":
      var state = newDampeningState(300, 1000, 500, 250)
      let now = getMonoTime()
      var snap = state.toDampeningSnapshot(now)
      snap.penalty = 750.0
      snap.suppressed = true
      state.applySnapshot(snap, now)
      check state.penalty == 750.0
      check state.suppressed

    test "pure decay via snapshot round-trip":
      var state = newDampeningState(300, 1000, 500, 250)
      state.penalty = 1000.0
      state.suppressed = true
      let now = state.lastUpdate + initDuration(seconds = 300)
      let snap = state.toDampeningSnapshot(now)
      let decayed = decayPenalty(snap)
      state.applySnapshot(decayed, now)
      # After one half-life, penalty should be ~500
      check abs(state.penalty - 500.0) < 1.0
      # 500 > 250 reuse, still suppressed
      check state.suppressed

    test "pure failure via snapshot round-trip":
      var state = newDampeningState(300, 1000, 500, 250)
      let now = getMonoTime()
      let snap = state.toDampeningSnapshot(now)
      let failed = applyFailurePenalty(snap)
      state.applySnapshot(failed, now)
      check state.penalty >= PenaltyPerFailure - 1.0
      check state.suppressed

    test "reset clears state":
      var state = newDampeningState(300, 1000, 500, 250)
      state.penalty = 800.0
      state.suppressed = true
      state.reset()
      check not state.isSuppressed
      check state.penalty == 0.0
