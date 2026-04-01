## RFC 2439 route dampening: exponential penalty/decay.

type
  DampeningState* = object
    penalty*: float64
    suppressed*: bool
    halflife*: uint32
    ceiling*: uint32
    suppress*: uint32
    reuse*: uint32

const PenaltyPerFailure* = 1000.0

proc newDampeningState*(halflife, ceiling, suppress, reuse: uint32): DampeningState =
  DampeningState(
    penalty: 0.0,
    suppressed: false,
    halflife: halflife,
    ceiling: ceiling,
    suppress: suppress,
    reuse: reuse,
  )
