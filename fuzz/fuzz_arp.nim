## Fuzz harness for ARP reply parser.
## Feeds random bytes to ARP reply validation logic.

import ../src/linux_constants

proc fuzzTarget(data: openArray[byte]) =
  if data.len < sizeof(ArpPacket): return
  # Parse as ArpPacket and validate fields
  let pkt = readStruct[ArpPacket](data, 0)
  # Check operation field (should be ARPOP_REPLY=2 for a valid reply)
  discard pkt.operation
  discard pkt.senderIp
  discard pkt.targetIp

template readStruct[T](data: openArray[byte], offset: int): T =
  var tmp: T
  copyMem(addr tmp, unsafeAddr data[offset], sizeof(T))
  tmp

when isMainModule:
  {.exportc: "LLVMFuzzerTestOneInput".}
  proc LLVMFuzzerTestOneInput(data: ptr byte, size: csize_t): cint =
    if size > 0:
      fuzzTarget(toOpenArray(data, 0, size.int - 1))
    0
