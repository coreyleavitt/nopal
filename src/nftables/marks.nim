## FNV-1a mark hashing for stable firewall mark assignment.
##
## Maps interface names to (mark, tableId) pairs using FNV-1a-32 hash.
## The mark_mask defines the bit range and slot count. Marks are stable
## across config reorder (name-based, not position-based). Linear probing
## resolves collisions.

const
  FnvOffsetBasis = 2166136261'u32
  FnvPrime = 16777619'u32
  TableBase = 100'u32

func fnv1a(name: string): uint32 =
  result = FnvOffsetBasis
  for b in name:
    result = result xor uint32(b)
    result = result * FnvPrime  # uint32 wraps naturally

proc assignMarks*(names: openArray[string], markMask: uint32): seq[tuple[mark: uint32, tableId: uint32]] =
  ## Assign stable firewall marks to interface names.
  ## Returns (mark, tableId) in the same order as input names.
  ## markMask must be a valid contiguous bitmask with >=2 slots.
  result = newSeq[tuple[mark: uint32, tableId: uint32]](names.len)

  if markMask == 0 or names.len == 0:
    for i in 0 ..< result.len:
      result[i] = (mark: 0'u32, tableId: TableBase)
    return

  let step = markMask and (not markMask + 1)  # lowest set bit
  let maxSlots = int(markMask div step) - 1    # usable slots (1..maxSlots)

  if maxSlots < 1:
    return

  var usedSlots = newSeq[bool](maxSlots + 1)  # index 0 unused, 1..maxSlots

  # Truncate to maxSlots if more interfaces than available slots (log, don't crash)
  let assignCount = min(names.len, maxSlots)

  for i in 0 ..< assignCount:
    let h = fnv1a(names[i])
    var slot = int(h mod uint32(maxSlots)) + 1  # 1..maxSlots

    # Linear probing for collisions
    var probes = 0
    while usedSlots[slot] and probes < maxSlots:
      slot = (slot mod maxSlots) + 1
      inc probes

    usedSlots[slot] = true
    result[i] = (mark: uint32(slot) * step, tableId: TableBase + uint32(slot))

when isMainModule:
  import std/unittest

  suite "FNV-1a mark assignment":
    test "deterministic: same name always gets same mark":
      let r1 = assignMarks(["wan", "lte"], 0xFF00'u32)
      let r2 = assignMarks(["wan", "lte"], 0xFF00'u32)
      check r1[0].mark == r2[0].mark
      check r1[1].mark == r2[1].mark

    test "order independent: same names in different order get same marks":
      let r1 = assignMarks(["wan", "lte"], 0xFF00'u32)
      let r2 = assignMarks(["lte", "wan"], 0xFF00'u32)
      # wan should get the same mark regardless of position
      check r1[0].mark == r2[1].mark
      check r1[1].mark == r2[0].mark

    test "marks are within mask range":
      let r = assignMarks(["wan", "lte", "wanb"], 0xFF00'u32)
      for item in r:
        check (item.mark and 0xFF00'u32) == item.mark
        check item.mark > 0

    test "table IDs start at base + slot":
      let r = assignMarks(["wan"], 0xFF00'u32)
      check r[0].tableId >= TableBase + 1
      check r[0].tableId <= TableBase + 254

    test "no duplicate marks":
      let names = ["wan", "lte", "wanb", "wan2", "wan3"]
      let r = assignMarks(names, 0xFF00'u32)
      for i in 0 ..< r.len:
        for j in (i + 1) ..< r.len:
          check r[i].mark != r[j].mark

    test "handles small mask (0x0300 = 2 slots)":
      let r = assignMarks(["wan", "lte"], 0x0300'u32)
      check r[0].mark != r[1].mark
      check (r[0].mark and 0x0300'u32) == r[0].mark
      check (r[1].mark and 0x0300'u32) == r[1].mark
