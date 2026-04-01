## Timer wheel using heapqueue for probe scheduling.

import std/heapqueue
import std/monotimes
import std/times

type
  TimerKind* = enum
    tkProbe, tkProbeTimeout, tkDampenDecay, tkIpcTimeout

  TimerEntry* = object
    deadline*: MonoTime
    kind*: TimerKind
    index*: int

func `<`*(a, b: TimerEntry): bool =
  a.deadline < b.deadline

type
  TimerWheel* = object
    heap: HeapQueue[TimerEntry]

proc newTimerWheel*(): TimerWheel =
  TimerWheel(heap: initHeapQueue[TimerEntry]())

proc push*(tw: var TimerWheel, entry: TimerEntry) =
  tw.heap.push(entry)

proc nextDeadline*(tw: TimerWheel): MonoTime =
  if tw.heap.len > 0:
    tw.heap[0].deadline
  else:
    getMonoTime() + initDuration(seconds = 60)

proc popExpired*(tw: var TimerWheel, now: MonoTime, buf: var seq[TimerEntry]) =
  ## Pop all expired entries into buf, reusing its existing capacity.
  buf.setLen(0)
  while tw.heap.len > 0 and tw.heap[0].deadline <= now:
    buf.add(tw.heap.pop())
