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

proc cancelByIndex*(tw: var TimerWheel, index: int, kinds: set[TimerKind]) =
  ## Remove all entries matching the given index and any kind in the set.
  var newHeap = initHeapQueue[TimerEntry]()
  while tw.heap.len > 0:
    let entry = tw.heap.pop()
    if not (entry.kind in kinds and entry.index == index):
      newHeap.push(entry)
  tw.heap = newHeap

proc cancelAll*(tw: var TimerWheel, keepKinds: set[TimerKind]) =
  ## Remove all entries except those with kinds in keepKinds.
  var newHeap = initHeapQueue[TimerEntry]()
  while tw.heap.len > 0:
    let entry = tw.heap.pop()
    if entry.kind in keepKinds:
      newHeap.push(entry)
  tw.heap = newHeap

when isMainModule:
  import std/unittest

  proc makeEntry(offsetMs: int, kind: TimerKind, index: int = 0): TimerEntry =
    TimerEntry(
      deadline: getMonoTime() + initDuration(milliseconds = offsetMs),
      kind: kind,
      index: index,
    )

  suite "TimerWheel":
    test "push and popExpired returns entries in deadline order":
      var tw = newTimerWheel()
      let now = getMonoTime()
      # Push in reverse order
      tw.push(TimerEntry(deadline: now + initDuration(milliseconds = 30), kind: tkProbe, index: 2))
      tw.push(TimerEntry(deadline: now + initDuration(milliseconds = 10), kind: tkProbe, index: 0))
      tw.push(TimerEntry(deadline: now + initDuration(milliseconds = 20), kind: tkProbe, index: 1))

      var buf: seq[TimerEntry]
      let future = now + initDuration(milliseconds = 50)
      tw.popExpired(future, buf)
      check buf.len == 3
      check buf[0].index == 0  # earliest deadline first
      check buf[1].index == 1
      check buf[2].index == 2

    test "popExpired only returns expired entries":
      var tw = newTimerWheel()
      let now = getMonoTime()
      tw.push(TimerEntry(deadline: now - initDuration(milliseconds = 10), kind: tkProbe, index: 0))
      tw.push(TimerEntry(deadline: now + initDuration(seconds = 60), kind: tkProbe, index: 1))

      var buf: seq[TimerEntry]
      tw.popExpired(now, buf)
      check buf.len == 1
      check buf[0].index == 0

    test "nextDeadline returns earliest entry":
      var tw = newTimerWheel()
      let now = getMonoTime()
      let early = now + initDuration(milliseconds = 100)
      let late = now + initDuration(milliseconds = 500)
      tw.push(TimerEntry(deadline: late, kind: tkProbe, index: 1))
      tw.push(TimerEntry(deadline: early, kind: tkProbe, index: 0))
      check tw.nextDeadline() == early

    test "nextDeadline on empty returns future":
      var tw = newTimerWheel()
      let now = getMonoTime()
      check tw.nextDeadline() > now

    test "cancelByIndex removes matching entries":
      var tw = newTimerWheel()
      let now = getMonoTime()
      tw.push(TimerEntry(deadline: now, kind: tkProbe, index: 0))
      tw.push(TimerEntry(deadline: now, kind: tkProbeTimeout, index: 0))
      tw.push(TimerEntry(deadline: now, kind: tkProbe, index: 1))
      tw.push(TimerEntry(deadline: now, kind: tkDampenDecay, index: 0))

      tw.cancelByIndex(0, {tkProbe, tkProbeTimeout})

      var buf: seq[TimerEntry]
      tw.popExpired(now + initDuration(seconds = 1), buf)
      check buf.len == 2  # index=1 probe + index=0 dampenDecay kept

    test "cancelAll keeps only specified kinds":
      var tw = newTimerWheel()
      let now = getMonoTime()
      tw.push(TimerEntry(deadline: now, kind: tkProbe, index: 0))
      tw.push(TimerEntry(deadline: now, kind: tkIpcTimeout, index: 1))
      tw.push(TimerEntry(deadline: now, kind: tkDampenDecay, index: 2))

      tw.cancelAll({tkIpcTimeout})

      var buf: seq[TimerEntry]
      tw.popExpired(now + initDuration(seconds = 1), buf)
      check buf.len == 1
      check buf[0].kind == tkIpcTimeout
