## Probe engine: per-interface health check orchestration.
##
## Manages health probes across multiple interfaces with round-robin
## target cycling, reliability thresholds, and quality sliding windows.
## The engine is a pure data structure — it does not own the selector
## or timers. The daemon event loop orchestrates probe/reply/timeout flow.

import std/[options, monotimes, times]
import ../config/schema

# =============================================================================
# Quality Window (ring buffer)
# =============================================================================

type
  QualityEntry* = object
    rttMs*: uint32   ## 0 = timeout/failure
    success*: bool

  QualityWindow* = object
    entries: seq[QualityEntry]
    head: int
    count: int
    capacity: int

proc initQualityWindow*(capacity: int): QualityWindow =
  QualityWindow(
    entries: newSeq[QualityEntry](max(capacity, 1)),
    head: 0,
    count: 0,
    capacity: max(capacity, 1),
  )

proc push*(w: var QualityWindow, entry: QualityEntry) =
  w.entries[w.head] = entry
  w.head = (w.head + 1) mod w.capacity
  if w.count < w.capacity:
    inc w.count

func avgRttMs*(w: QualityWindow): Option[uint32] =
  ## Average RTT in milliseconds across successful probes in the window.
  var sum: uint64 = 0
  var n = 0
  for i in 0 ..< w.count:
    let e = w.entries[i]
    if e.success and e.rttMs > 0:
      sum += uint64(e.rttMs)
      inc n
  if n > 0: some(uint32(sum div uint64(n)))
  else: none(uint32)

func lossPercent*(w: QualityWindow): uint32 =
  ## Percentage of probes that failed (0-100).
  if w.count == 0: return 0
  var failures = 0
  for i in 0 ..< w.count:
    if not w.entries[i].success:
      inc failures
  uint32((failures * 100) div w.count)

func isFull*(w: QualityWindow): bool =
  w.count >= w.capacity

# =============================================================================
# Probe Result
# =============================================================================

type
  ProbeResult* = object
    interfaceIndex*: int
    success*: bool          ## cycle succeeded (enough targets responded)
    qualityOk*: bool        ## quality within thresholds
    avgRttMs*: Option[uint32]
    lossPercent*: uint32

# =============================================================================
# Tests
# =============================================================================

when isMainModule:
  import std/unittest

  suite "QualityWindow":
    test "empty window returns no avg and 0% loss":
      let w = initQualityWindow(10)
      check w.avgRttMs.isNone
      check w.lossPercent == 0
      check not w.isFull

    test "single success":
      var w = initQualityWindow(10)
      w.push(QualityEntry(rttMs: 50, success: true))
      check w.avgRttMs.isSome
      check w.avgRttMs.get == 50
      check w.lossPercent == 0

    test "mixed success and failure":
      var w = initQualityWindow(4)
      w.push(QualityEntry(rttMs: 100, success: true))
      w.push(QualityEntry(rttMs: 0, success: false))
      w.push(QualityEntry(rttMs: 200, success: true))
      w.push(QualityEntry(rttMs: 0, success: false))
      check w.avgRttMs.get == 150  # (100 + 200) / 2
      check w.lossPercent == 50    # 2 of 4 failed
      check w.isFull

    test "ring buffer wraps correctly":
      var w = initQualityWindow(3)
      w.push(QualityEntry(rttMs: 10, success: true))
      w.push(QualityEntry(rttMs: 20, success: true))
      w.push(QualityEntry(rttMs: 30, success: true))
      check w.avgRttMs.get == 20  # (10+20+30)/3
      check w.isFull

      # Push one more — overwrites oldest (10)
      w.push(QualityEntry(rttMs: 40, success: true))
      check w.avgRttMs.get == 30  # (20+30+40)/3
      check w.count == 3  # still capped at capacity

    test "all failures":
      var w = initQualityWindow(5)
      for i in 0 ..< 5:
        w.push(QualityEntry(rttMs: 0, success: false))
      check w.avgRttMs.isNone
      check w.lossPercent == 100

    test "loss calculation with partial window":
      var w = initQualityWindow(10)
      w.push(QualityEntry(rttMs: 50, success: true))
      w.push(QualityEntry(rttMs: 0, success: false))
      # 2 entries, 1 failure = 50%
      check w.lossPercent == 50
      check not w.isFull
