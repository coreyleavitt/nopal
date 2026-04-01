## Fuzz harness for netlink message parser.
## Feeds random bytes to nlMsgs + nlAttrs iterators.

import ../src/netlink/socket
import ../src/linux_constants

proc fuzzTarget(data: openArray[byte]) =
  if data.len < 16: return  # minimum NlMsgHdr size
  # Try parsing as a sequence of netlink messages
  for (hdr, payloadSlice) in nlMsgs(data, data.len):
    # Try parsing attributes within each message
    let attrStart = payloadSlice.a
    for (attrType, s) in nlAttrs(data, attrStart):
      discard attrU32(data, s)

when isMainModule:
  {.exportc: "LLVMFuzzerTestOneInput".}
  proc LLVMFuzzerTestOneInput(data: ptr byte, size: csize_t): cint =
    if size > 0:
      fuzzTarget(toOpenArray(data, 0, size.int - 1))
    0
