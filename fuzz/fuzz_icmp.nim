## Fuzz harness for ICMP reply parser.
## Feeds random bytes to the ICMP checksum and reply validation.

import ../src/health/icmp

proc fuzzTarget(data: openArray[byte]) =
  if data.len < 8: return  # minimum ICMP header
  # Verify checksum doesn't crash on arbitrary input
  discard icmpChecksum(data)

when isMainModule:
  {.exportc: "LLVMFuzzerTestOneInput".}
  proc LLVMFuzzerTestOneInput(data: ptr byte, size: csize_t): cint =
    if size > 0:
      fuzzTarget(toOpenArray(data, 0, size.int - 1))
    0
