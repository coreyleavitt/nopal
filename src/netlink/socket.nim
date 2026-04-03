## Netlink socket abstraction: message builder, attribute parsing, send/recv.
##
## This module provides the two unsafe bridge functions (readStruct/writeStruct)
## that all byte-level operations in the project go through. Everything else
## builds on these two templates.

import std/[posix, monotimes, times, os]
import ../linux_constants

# =============================================================================
# The unsafe bridge: exactly two functions
# =============================================================================

template readStruct*[T](data: openArray[byte], offset: int): T =
  ## Read a packed struct from a byte buffer. Caller must bounds-check.
  ## This and writeStruct are the ONLY places in the project that call copyMem
  ## for struct serialization.
  var tmp: T
  copyMem(addr tmp, unsafeAddr data[offset], sizeof(T))
  tmp

template writeStruct*[T](buf: var seq[byte], val: T) =
  ## Append a packed struct to the buffer as raw bytes.
  let pos = buf.len
  buf.setLen(pos + sizeof(T))
  copyMem(addr buf[pos], unsafeAddr val, sizeof(T))

# =============================================================================
# Alignment
# =============================================================================

func nlmsgAlign*(len: int): int {.inline.} =
  ## Round up to 4-byte NLMSG_ALIGN boundary.
  (len + 3) and (not 3)

# =============================================================================
# Message builder
# =============================================================================

type
  NlMsgBuilder* = object
    buf*: seq[byte]

proc initBuilder*(msgType: uint16, flags: uint16, seq: uint32,
                  pid: uint32 = 0): NlMsgBuilder =
  ## Start a new netlink message. Header length is patched by finish().
  var b = NlMsgBuilder(buf: newSeqOfCap[byte](256))
  let hdr = NlMsgHdr(
    nlmsgLen: 0,  # placeholder, patched in finish()
    nlmsgType: msgType,
    nlmsgFlags: flags,
    nlmsgSeq: seq,
    nlmsgPid: pid,
  )
  writeStruct(b.buf, hdr)
  b

proc addPayload*[T](b: var NlMsgBuilder, payload: T) =
  ## Append a protocol-specific header (RtMsg, IfInfoMsg, NfGenMsg, etc.)
  writeStruct(b.buf, payload)

proc pad*(b: var NlMsgBuilder) =
  ## Pad buffer to 4-byte alignment.
  let aligned = nlmsgAlign(b.buf.len)
  while b.buf.len < aligned:
    b.buf.add(0)

proc addAttr*(b: var NlMsgBuilder, attrType: uint16, data: openArray[byte]) =
  ## Add a netlink attribute (NLA header + data + padding).
  let hdr = NlAttr(
    nlaLen: uint16(sizeof(NlAttr) + data.len),
    nlaType: attrType,
  )
  writeStruct(b.buf, hdr)
  for i in 0 ..< data.len:
    b.buf.add(data[i])
  b.pad()

proc addAttrU32*(b: var NlMsgBuilder, attrType: uint16, val: uint32) =
  ## Convenience: add a 4-byte attribute.
  var bytes: array[4, byte]
  copyMem(addr bytes[0], unsafeAddr val, 4)
  b.addAttr(attrType, bytes)

proc finish*(b: var NlMsgBuilder): lent seq[byte] =
  ## Patch nlmsg_len and return the complete message buffer.
  let totalLen = uint32(b.buf.len)
  copyMem(addr b.buf[0], unsafeAddr totalLen, sizeof(uint32))
  b.buf

# =============================================================================
# Message and attribute iterators
# =============================================================================

iterator nlMsgs*(data: openArray[byte], len: int): tuple[hdr: NlMsgHdr, payloadSlice: Slice[int]] =
  ## Iterate netlink messages in a receive buffer.
  var pos = 0
  while pos + sizeof(NlMsgHdr) <= len:
    let hdr = readStruct[NlMsgHdr](data, pos)
    if hdr.nlmsgLen < uint32(sizeof(NlMsgHdr)) or pos + int(hdr.nlmsgLen) > len:
      break
    let payloadStart = pos + sizeof(NlMsgHdr)
    let payloadEnd = pos + int(hdr.nlmsgLen)
    yield (hdr, payloadStart ..< payloadEnd)
    pos = nlmsgAlign(pos + int(hdr.nlmsgLen))

iterator nlAttrs*(data: openArray[byte], offset: int): tuple[attrType: uint16, payloadSlice: Slice[int]] =
  ## Iterate netlink attributes starting at offset within data.
  var pos = offset
  while pos + sizeof(NlAttr) <= data.len:
    let attr = readStruct[NlAttr](data, pos)
    let nlaLen = int(attr.nlaLen)
    if nlaLen < sizeof(NlAttr):
      break
    let payloadStart = pos + sizeof(NlAttr)
    let payloadEnd = min(pos + nlaLen, data.len)
    if payloadStart <= payloadEnd:
      yield (attr.nlaType, payloadStart ..< payloadEnd)
    pos = nlmsgAlign(pos + nlaLen)

proc attrU32*(data: openArray[byte], s: Slice[int]): uint32 =
  ## Extract a uint32 from an attribute payload slice (inclusive range).
  if s.b - s.a + 1 >= 4:
    result = readStruct[uint32](data, s.a)

proc attrStr*(data: openArray[byte], s: Slice[int]): string =
  ## Extract a null-terminated string from an attribute payload slice.
  var endPos = s.a
  while endPos <= s.b and data[endPos] != 0:
    inc endPos
  let strLen = endPos - s.a
  if strLen > 0:
    result = newString(strLen)
    copyMem(addr result[0], unsafeAddr data[s.a], strLen)

# =============================================================================
# NetlinkSocket
# =============================================================================

type
  NlAckKind* = enum
    nakSendFailed      ## sendMsg syscall failed
    nakRecvFailed      ## recvMsg syscall failed
    nakTimeout         ## No ACK received within deadline
    nakKernelError     ## ACK received with non-zero errno

  NlAckResult* = object
    case ok*: bool
    of true: discard
    of false:
      kind*: NlAckKind
      osError*: int32  ## Socket/kernel errno (0 for nakTimeout)

  NetlinkSocket* = object
    fd*: cint

func nlAckOk*(): NlAckResult {.inline.} =
  NlAckResult(ok: true)

func nlAckErr*(kind: NlAckKind, osError: int32 = 0): NlAckResult {.inline.} =
  NlAckResult(ok: false, kind: kind, osError: osError)

proc openNetlink*(protocol: cint, groups: uint32 = 0): NetlinkSocket =
  ## Open an AF_NETLINK socket, bind with optional multicast groups.
  let fd = cint(posix.socket(AF_NETLINK.cint, posix.SOCK_RAW or posix.SOCK_CLOEXEC, protocol))
  if fd < 0:
    raiseOSError(osLastError())

  # Set non-blocking
  let flags = posix.fcntl(fd, posix.F_GETFL)
  if posix.fcntl(fd, posix.F_SETFL, flags or posix.O_NONBLOCK) < 0:
    discard posix.close(fd)
    raiseOSError(osLastError())

  # Increase receive buffer for dumps (1 MB)
  var rcvbuf: cint = 1024 * 1024
  let sh = SocketHandle(fd)
  if posix.setsockopt(sh, posix.SOL_SOCKET, posix.SO_RCVBUF,
                      addr rcvbuf, sizeof(rcvbuf).SockLen) < 0:
    discard posix.close(fd)
    raiseOSError(osLastError())

  # Bind with multicast groups
  # sockaddr_nl: family=AF_NETLINK(16), pad=0, pid=0(kernel assigns), groups
  var saNl: array[12, byte]
  let family = uint16(AF_NETLINK)
  copyMem(addr saNl[0], unsafeAddr family, 2)
  copyMem(addr saNl[8], unsafeAddr groups, 4)
  if posix.bindSocket(sh, cast[ptr SockAddr](addr saNl[0]),
                      SockLen(sizeof(saNl))) < 0:
    discard posix.close(fd)
    raiseOSError(osLastError())

  NetlinkSocket(fd: fd)

proc sendMsg*(s: NetlinkSocket, data: openArray[byte]): NlAckResult =
  ## Send a netlink message. Returns NlAckResult with errno on failure.
  let sh = SocketHandle(s.fd)
  let n = posix.send(sh, cast[pointer](unsafeAddr data[0]), data.len, 0'i32)
  if n < 0:
    return nlAckErr(nakSendFailed, errno.int32)
  nlAckOk()

proc recvMsg*(s: NetlinkSocket, buf: var seq[byte]): int =
  ## Receive into buffer. Returns bytes read, 0 on EAGAIN, -1 on error.
  let sh = SocketHandle(s.fd)
  let n = posix.recv(sh, cast[pointer](addr buf[0]), buf.len, linux_constants.MSG_TRUNC)
  if n < 0:
    if errno == EAGAIN or errno == EWOULDBLOCK:
      return 0
    return -1
  # Clamp to buffer size: MSG_TRUNC returns the real message size even
  # when truncated, which would cause OOB reads in nlMsgs callers.
  min(int(n), buf.len)

proc sendAndAck*(s: NetlinkSocket, data: openArray[byte],
                 buf: var seq[byte], timeoutMs: int = 5000): NlAckResult =
  ## Send message and wait for ACK. Returns NlAckResult with error details.
  let sendResult = s.sendMsg(data)
  if not sendResult.ok:
    return sendResult

  let deadline = getMonoTime() + initDuration(milliseconds = timeoutMs)
  while getMonoTime() < deadline:
    let n = s.recvMsg(buf)
    if n < 0:
      return nlAckErr(nakRecvFailed, errno.int32)
    if n == 0:
      # EAGAIN — brief sleep and retry
      discard posix.poll(nil, 0, 1)  # 1ms sleep
      continue
    if n < sizeof(NlMsgHdr):
      continue

    let hdr = readStruct[NlMsgHdr](buf, 0)
    if hdr.nlmsgType == NLMSG_ERROR:
      if n >= sizeof(NlMsgHdr) + sizeof(int32):
        let errCode = readStruct[int32](buf, sizeof(NlMsgHdr))
        if errCode == 0:
          return nlAckOk()
        # Kernel returns negative errno in NLMSG_ERROR
        return nlAckErr(nakKernelError, -errCode)
    # Not an error message — might be a multicast notification, skip
  nlAckErr(nakTimeout)

proc close*(s: var NetlinkSocket) =
  if s.fd >= 0:
    discard posix.close(s.fd)
    s.fd = -1

# =============================================================================
# Tests
# =============================================================================

when isMainModule:
  import std/unittest

  suite "readStruct / writeStruct":
    test "round-trip NlMsgHdr":
      let original = NlMsgHdr(
        nlmsgLen: 32, nlmsgType: 24, nlmsgFlags: 0x0301,
        nlmsgSeq: 1, nlmsgPid: 0,
      )
      var buf: seq[byte]
      writeStruct(buf, original)
      check buf.len == sizeof(NlMsgHdr)
      let decoded = readStruct[NlMsgHdr](buf, 0)
      check decoded.nlmsgLen == 32
      check decoded.nlmsgType == 24
      check decoded.nlmsgFlags == 0x0301
      check decoded.nlmsgSeq == 1
      check decoded.nlmsgPid == 0

    test "round-trip RtMsg":
      let original = RtMsg(
        rtmFamily: 2, rtmDstLen: 0, rtmSrcLen: 0, rtmTos: 0,
        rtmTable: 100, rtmProtocol: 4, rtmScope: 0, rtmType: 1,
        rtmFlags: 0,
      )
      var buf: seq[byte]
      writeStruct(buf, original)
      check buf.len == sizeof(RtMsg)
      let decoded = readStruct[RtMsg](buf, 0)
      check decoded.rtmFamily == 2
      check decoded.rtmTable == 100
      check decoded.rtmType == 1

  suite "NlMsgBuilder":
    test "build simple message with header and payload":
      var b = initBuilder(RTM_NEWROUTE.uint16, NLM_F_REQUEST.uint16 or NLM_F_ACK.uint16, 1)
      let rt = RtMsg(
        rtmFamily: 2, rtmDstLen: 0, rtmSrcLen: 0, rtmTos: 0,
        rtmTable: 100, rtmProtocol: 4, rtmScope: 0, rtmType: 1,
        rtmFlags: 0,
      )
      b.addPayload(rt)
      let msg = b.finish()
      # Header (16) + RtMsg (12) = 28 bytes
      check msg.len == 28
      let hdr = readStruct[NlMsgHdr](msg, 0)
      check hdr.nlmsgLen == 28
      check hdr.nlmsgType == RTM_NEWROUTE.uint16

    test "addAttr pads to 4-byte alignment":
      var b = initBuilder(RTM_NEWROUTE.uint16, 0, 1)
      let rt = RtMsg()
      b.addPayload(rt)
      # Add a 3-byte attribute → NlAttr(4) + 3 data + 1 pad = 8
      b.addAttr(RTA_DST.uint16, [1'u8, 2, 3])
      let msg = b.finish()
      # Header(16) + RtMsg(12) + NlAttr(4) + 3 + 1pad = 36
      check msg.len == 36

    test "addAttrU32 produces 8-byte attribute":
      var b = initBuilder(RTM_NEWROUTE.uint16, 0, 1)
      let rt = RtMsg()
      b.addPayload(rt)
      b.addAttrU32(RTA_TABLE.uint16, 200)
      let msg = b.finish()
      # Header(16) + RtMsg(12) + NlAttr(4) + 4 = 36
      check msg.len == 36

  suite "nlmsgAlign":
    test "alignment values":
      check nlmsgAlign(0) == 0
      check nlmsgAlign(1) == 4
      check nlmsgAlign(4) == 4
      check nlmsgAlign(5) == 8
      check nlmsgAlign(16) == 16
      check nlmsgAlign(17) == 20

  suite "nlMsgs iterator":
    test "parse single message":
      var b = initBuilder(24, 1, 1)
      b.addPayload(RtMsg())
      let msg = b.finish()
      var count = 0
      for (hdr, payload) in nlMsgs(msg, msg.len):
        check hdr.nlmsgType == 24
        check payload.a == sizeof(NlMsgHdr)
        inc count
      check count == 1

  suite "nlAttrs iterator":
    test "parse attributes from constructed message":
      var b = initBuilder(24, 0, 1)
      b.addPayload(RtMsg())
      b.addAttrU32(RTA_TABLE.uint16, 42)
      b.addAttrU32(RTA_OIF.uint16, 7)
      let msg = b.finish()

      let attrStart = sizeof(NlMsgHdr) + sizeof(RtMsg)
      var attrs: seq[tuple[t: uint16, v: uint32]]
      for (attrType, s) in nlAttrs(msg, attrStart):
        attrs.add((attrType, attrU32(msg, s)))

      check attrs.len == 2
      check attrs[0].t == RTA_TABLE.uint16
      check attrs[0].v == 42
      check attrs[1].t == RTA_OIF.uint16
      check attrs[1].v == 7
