## RFC 2439 route dampening: exponential penalty/decay.
##
## Prevents rapid interface flapping from causing constant routing churn.
## When an interface fails, a penalty is added. If the penalty exceeds the
## suppress threshold, the interface is suppressed (kept offline even if
## probes start succeeding). The penalty decays exponentially with a
## configurable half-life. Once the penalty drops below the reuse threshold,
## the interface is eligible to come back online.

import std/monotimes
import std/times
import std/math

const PenaltyPerFailure* = 1000.0

type
  DampeningState* = object
    penalty*: float64
    suppressed*: bool
    halflife*: uint32      ## seconds for 50% decay
    ceiling*: uint32       ## max penalty
    suppress*: uint32      ## penalty >= this -> suppress
    reuse*: uint32         ## penalty < this -> unsuppress
    lastUpdate*: MonoTime  ## for decay calculation

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

proc decay*(ds: var DampeningState) =
  ## Apply exponential decay based on elapsed time since last update.
  ## Formula: penalty * 2^(-elapsed / halflife)
  let now = getMonoTime()
  let elapsed = (now - ds.lastUpdate).inNanoseconds.float64 / 1_000_000_000.0
  ds.lastUpdate = now

  if elapsed <= 0.0 or ds.halflife == 0:
    return

  let decayFactor = pow(2.0, -elapsed / ds.halflife.float64)
  ds.penalty *= decayFactor

  # Snap to zero if negligibly small
  if ds.penalty < 0.1:
    ds.penalty = 0.0

  # Check if we've dropped below the reuse threshold
  if ds.suppressed and ds.penalty < ds.reuse.float64:
    ds.suppressed = false

proc applyFailure*(ds: var DampeningState): bool =
  ## Record a probe failure: decay existing penalty, then add failure penalty.
  ## Returns true if the interface is now suppressed.
  ds.decay()

  ds.penalty += PenaltyPerFailure
  if ds.penalty > ds.ceiling.float64:
    ds.penalty = ds.ceiling.float64

  if ds.penalty >= ds.suppress.float64:
    ds.suppressed = true

  ds.suppressed

func isSuppressed*(ds: DampeningState): bool =
  ds.suppressed

func shouldReuse*(ds: DampeningState): bool =
  ds.penalty < ds.reuse.float64

proc reset*(ds: var DampeningState) =
  ds.penalty = 0.0
  ds.suppressed = false
  ds.lastUpdate = getMonoTime()

when isMainModule:
  import std/unittest
  import std/os

  suite "dampening":
    test "new state is not suppressed":
      let state = newDampeningState(300, 1000, 500, 250)
      check not state.isSuppressed
      check state.shouldReuse
      check state.penalty == 0.0

    test "single failure suppresses":
      # penalty=1000 per failure, suppress=500 -> one failure suppresses
      var state = newDampeningState(300, 1000, 500, 250)
      let suppressed = state.applyFailure()
      check suppressed
      check state.isSuppressed
      check not state.shouldReuse

    test "penalty capped at ceiling":
      var state = newDampeningState(300, 1000, 500, 250)
      discard state.applyFailure()
      discard state.applyFailure()
      discard state.applyFailure()
      check state.penalty == 1000.0

    test "reset clears state":
      var state = newDampeningState(300, 1000, 500, 250)
      discard state.applyFailure()
      check state.isSuppressed

      state.reset()
      check not state.isSuppressed
      check state.penalty == 0.0

    test "decay with zero halflife is noop":
      var state = newDampeningState(0, 1000, 500, 250)
      state.penalty = 800.0
      state.lastUpdate = getMonoTime() - initDuration(seconds = 100)
      state.decay()
      check state.penalty == 800.0
