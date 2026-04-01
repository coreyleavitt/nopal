## Fuzz harness for DNS query encoder.
## Feeds random strings to encodeDnsQuery.

import ../src/health/dns

proc fuzzTarget(data: openArray[byte]) =
  if data.len == 0: return
  var input = newString(data.len)
  copyMem(addr input[0], unsafeAddr data[0], data.len)
  var buf: array[512, byte]
  discard encodeDnsQuery(input, buf)

when isMainModule:
  {.exportc: "LLVMFuzzerTestOneInput".}
  proc LLVMFuzzerTestOneInput(data: ptr byte, size: csize_t): cint =
    if size > 0:
      fuzzTarget(toOpenArray(data, 0, size.int - 1))
    0
