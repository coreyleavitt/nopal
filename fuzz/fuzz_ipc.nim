## Fuzz harness for IPC JSON request parser.
## Feeds random bytes to JSON parsing + IPC request extraction.

import std/json
import ../src/ipc/protocol

proc fuzzTarget(data: openArray[byte]) =
  if data.len == 0: return
  var input = newString(data.len)
  copyMem(addr input[0], unsafeAddr data[0], data.len)
  try:
    let j = parseJson(input)
    # Exercise parseRequest on all JSON types (objects, arrays, strings, etc.)
    discard parseRequest(j)
    # Also test parseResponse path
    discard parseResponse(j)
  except JsonParsingError:
    discard
  except CatchableError:
    discard

when isMainModule:
  {.exportc: "LLVMFuzzerTestOneInput".}
  proc LLVMFuzzerTestOneInput(data: ptr byte, size: csize_t): cint =
    if size > 0:
      fuzzTarget(toOpenArray(data, 0, size.int - 1))
    0
