## Probe engine: per-interface health check orchestration.

type
  ProbeResult* = object
    interfaceIndex*: int
    cycleSuccess*: bool
    avgRttMs*: int
    lossPercent*: int

  ProbeEngine* = object
