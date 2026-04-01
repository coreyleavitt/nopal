## Fuzz harness for UCI config parser.
## Build: nim c -d:useFuzzer --passC:"-fsanitize=fuzzer,address" fuzz/fuzz_uci_parser.nim
## Run:   ./fuzz_uci_parser fuzz/corpus/

import ../src/config/parser
import ../src/errors

proc fuzzTarget(data: openArray[byte]) =
  if data.len == 0: return
  var input = newString(data.len)
  copyMem(addr input[0], unsafeAddr data[0], data.len)
  try:
    discard loadFromStr(input)
  except ConfigError:
    discard
  except CatchableError:
    discard

when isMainModule:
  # libFuzzer entry point
  {.exportc: "LLVMFuzzerTestOneInput".}
  proc LLVMFuzzerTestOneInput(data: ptr byte, size: csize_t): cint =
    if size > 0:
      fuzzTarget(toOpenArray(data, 0, size.int - 1))
    0
