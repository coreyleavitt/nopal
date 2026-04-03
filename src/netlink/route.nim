## Route manager: add/delete routes, ip rules, address queries via NETLINK_ROUTE.
##
## Manages kernel routing tables and ip rules through native netlink messages.
## All operations use a single NETLINK_ROUTE socket with sequence numbering.
## Returns NlResult for all operations — callers decide error policy.

import std/[posix, os, monotimes, times]
import ../linux_constants
import ../errors
import ./socket

const
  RecvBufSize = 65536
  AF_INET = uint8(2)
  AF_INET6 = uint8(10)
  DumpTimeoutMs = 5000

type
  RouteManager* = object
    sock: NetlinkSocket
    nlSeq: uint32
    recvBuf: seq[byte]

  DumpMsg* = object
    ## Self-contained dump message. Owns its payload bytes (copied from recvBuf)
    ## so fold functions operate on independent data with no aliasing.
    hdr*: NlMsgHdr
    payload*: seq[byte]

proc newRouteManager*(): RouteManager =
  ## Create a RouteManager with a NETLINK_ROUTE socket.
  result = RouteManager(
    sock: openNetlink(NETLINK_ROUTE, 0),
    nlSeq: 0,
    recvBuf: newSeq[byte](RecvBufSize),
  )

proc nextSeq(m: var RouteManager): uint32 =
  ## Return the next sequence number, wrapping on overflow.
  m.nlSeq = m.nlSeq + 1
  m.nlSeq

# ---------------------------------------------------------------------------
# NlAckResult → NlResult mapping
# ---------------------------------------------------------------------------

func toNlResult(ack: NlAckResult, operation, detail: string): NlResult[void] {.inline.} =
  ## Map a transport-level NlAckResult to a domain-level NlResult[void].
  if ack.ok:
    nlOk()
  else:
    nlErr[void](NlError(
      kind: case ack.kind
        of nakSendFailed: nekSendFailed
        of nakRecvFailed: nekRecvFailed
        of nakTimeout: nekTimeout
        of nakKernelError: nekKernelError,
      osError: ack.osError,
      operation: operation,
      detail: detail,
    ))

# ---------------------------------------------------------------------------
# foldDump — monadic fold over netlink dump responses
# ---------------------------------------------------------------------------

proc foldDump*[A](m: var RouteManager, init: sink A,
                  msgType: uint16, payload: openArray[byte],
                  f: proc(acc: sink A, msg: DumpMsg): A {.raises: [].}
                 ): NlResult[A] {.raises: [].} =
  ## Send a dump request and fold over response messages.
  ## Returns NlResult[A] with the accumulated value or an error.
  ## The fold function f receives self-contained DumpMsg values.
  let seq = m.nextSeq()

  var b = initBuilder(
    msgType,
    NLM_F_REQUEST.uint16 or NLM_F_DUMP.uint16,
    seq,
  )
  # Add raw payload bytes (already serialized by caller)
  for i in 0 ..< payload.len:
    b.buf.add(payload[i])
  let msg = b.finish()

  let sendResult = m.sock.sendMsg(msg)
  if not sendResult.ok:
    return nlErr[A](NlError(
      kind: nekSendFailed, osError: sendResult.osError,
      operation: "foldDump", detail: "send dump request"))

  var acc = init
  let deadline = getMonoTime() + initDuration(milliseconds = DumpTimeoutMs)
  var done = false

  while not done:
    let n = m.sock.recvMsg(m.recvBuf)
    if n < 0:
      return nlErr[A](NlError(
        kind: nekRecvFailed, osError: errno.int32,
        operation: "foldDump", detail: "recv dump response"))
    if n == 0:
      if getMonoTime() >= deadline:
        return nlErr[A](NlError(
          kind: nekTimeout, osError: 0,
          operation: "foldDump", detail: "dump response timeout"))
      discard posix.poll(nil, 0, 1)  # 1ms sleep
      continue

    for (hdr, payloadSlice) in nlMsgs(m.recvBuf, n):
      if hdr.nlmsgType == NLMSG_DONE:
        done = true
        break
      if hdr.nlmsgType == NLMSG_ERROR:
        if payloadSlice.b - payloadSlice.a + 1 >= sizeof(int32):
          let errCode = readStruct[int32](m.recvBuf, payloadSlice.a)
          if errCode != 0:
            return nlErr[A](NlError(
              kind: nekKernelError, osError: -errCode,
              operation: "foldDump", detail: "kernel error in dump"))
        done = true
        break

      # Build self-contained DumpMsg (copy payload from recvBuf)
      let pStart = payloadSlice.a
      let pEnd = payloadSlice.b + 1
      var ownedPayload = newSeq[byte](pEnd - pStart)
      if ownedPayload.len > 0:
        copyMem(addr ownedPayload[0], unsafeAddr m.recvBuf[pStart], ownedPayload.len)
      acc = f(acc, DumpMsg(hdr: hdr, payload: ownedPayload))

  NlResult[A](ok: true, value: acc)

# ---------------------------------------------------------------------------
# addRoute
# ---------------------------------------------------------------------------

proc addRoute*(m: var RouteManager, table: uint32, gateway: openArray[byte],
               oif: uint32, metric: uint32, family: uint8): NlResult[void] {.raises: [].} =
  ## Add a default route to a routing table.
  ## gateway: raw IP bytes (4 for IPv4, 16 for IPv6).
  ## oif: output interface index.
  ## metric: route priority for tier-based selection.
  let seq = m.nextSeq()

  let rtm = RtMsg(
    rtmFamily: family,
    rtmDstLen: 0,         # default route
    rtmSrcLen: 0,
    rtmTos: 0,
    rtmTable: (if table <= 255: uint8(table) else: 0),
    rtmProtocol: RTPROT_STATIC,
    rtmScope: RT_SCOPE_UNIVERSE,
    rtmType: RTN_UNICAST,
    rtmFlags: 0,
  )

  var b = initBuilder(
    RTM_NEWROUTE.uint16,
    NLM_F_REQUEST.uint16 or NLM_F_ACK.uint16 or
      NLM_F_CREATE.uint16 or NLM_F_EXCL.uint16,
    seq,
  )
  b.addPayload(rtm)
  b.addAttrU32(RTA_TABLE.uint16, table)
  b.addAttr(RTA_GATEWAY.uint16, gateway)
  b.addAttrU32(RTA_OIF.uint16, oif)
  b.addAttrU32(RTA_PRIORITY.uint16, metric)

  let msg = b.finish()
  let familyStr = if family == AF_INET: "IPv4" else: "IPv6"
  m.sock.sendAndAck(msg, m.recvBuf).toNlResult(
    "addRoute", "table " & $table & ", family " & familyStr)

# ---------------------------------------------------------------------------
# delRoute
# ---------------------------------------------------------------------------

proc delRoute*(m: var RouteManager, table: uint32,
               family: uint8): NlResult[void] {.raises: [].} =
  ## Delete the default route from a routing table.
  let seq = m.nextSeq()

  let rtm = RtMsg(
    rtmFamily: family,
    rtmDstLen: 0,
    rtmSrcLen: 0,
    rtmTos: 0,
    rtmTable: (if table <= 255: uint8(table) else: 0),
    rtmProtocol: RTPROT_STATIC,
    rtmScope: RT_SCOPE_UNIVERSE,
    rtmType: RTN_UNICAST,
    rtmFlags: 0,
  )

  var b = initBuilder(
    RTM_DELROUTE.uint16,
    NLM_F_REQUEST.uint16 or NLM_F_ACK.uint16,
    seq,
  )
  b.addPayload(rtm)
  b.addAttrU32(RTA_TABLE.uint16, table)

  let msg = b.finish()
  let familyStr = if family == AF_INET: "IPv4" else: "IPv6"
  m.sock.sendAndAck(msg, m.recvBuf).toNlResult(
    "delRoute", "table " & $table & ", family " & familyStr)

# ---------------------------------------------------------------------------
# addRule / delRule
# ---------------------------------------------------------------------------

proc modifyRule(m: var RouteManager, msgType: uint16, mark, mask, table,
                priority: uint32, family: uint8): NlResult[void] {.raises: [].} =
  ## Internal helper to add or delete an ip rule (fwmark/mask -> table).
  let seq = m.nextSeq()

  let flags = if msgType == RTM_NEWRULE.uint16:
    NLM_F_REQUEST.uint16 or NLM_F_ACK.uint16 or
      NLM_F_CREATE.uint16 or NLM_F_EXCL.uint16
  else:
    NLM_F_REQUEST.uint16 or NLM_F_ACK.uint16

  # FibRuleHdr has the same layout as RtMsg
  let ruleHdr = RtMsg(
    rtmFamily: family,
    rtmDstLen: 0,
    rtmSrcLen: 0,
    rtmTos: 0,
    rtmTable: (if table <= 255: uint8(table) else: 0),
    rtmProtocol: RTPROT_STATIC,
    rtmScope: RT_SCOPE_UNIVERSE,
    rtmType: FR_ACT_TO_TBL,
    rtmFlags: 0,
  )

  var b = initBuilder(msgType, flags, seq)
  b.addPayload(ruleHdr)

  b.addAttrU32(FRA_TABLE.uint16, table)
  b.addAttrU32(FRA_FWMARK.uint16, mark)
  b.addAttrU32(FRA_FWMASK.uint16, mask)
  b.addAttrU32(FRA_PRIORITY.uint16, priority)

  let msg = b.finish()
  let op = if msgType == RTM_NEWRULE.uint16: "addRule" else: "delRule"
  let familyStr = if family == AF_INET: "IPv4" else: "IPv6"
  m.sock.sendAndAck(msg, m.recvBuf).toNlResult(
    op, "mark " & $mark & ", table " & $table & ", family " & familyStr)

proc addRule*(m: var RouteManager, mark, mask, table, priority: uint32,
              family: uint8): NlResult[void] {.raises: [].} =
  ## Add an ip rule: fwmark/mask -> table at given priority.
  m.modifyRule(RTM_NEWRULE.uint16, mark, mask, table, priority, family)

proc delRule*(m: var RouteManager, mark, mask, table, priority: uint32,
              family: uint8): NlResult[void] {.raises: [].} =
  ## Delete an ip rule: fwmark/mask -> table.
  m.modifyRule(RTM_DELRULE.uint16, mark, mask, table, priority, family)

# ---------------------------------------------------------------------------
# flushTable
# ---------------------------------------------------------------------------

proc flushTableFamily(m: var RouteManager, table: uint32,
                      family: uint8): NlResult[void] {.raises: [].} =
  ## Dump routes for one family, collect those in `table`, then delete each.

  # Serialize the RtMsg payload for the dump request
  let rtm = RtMsg(
    rtmFamily: family,
    rtmDstLen: 0, rtmSrcLen: 0, rtmTos: 0,
    rtmTable: 0, rtmProtocol: 0, rtmScope: 0, rtmType: 0, rtmFlags: 0,
  )
  var payloadBuf: seq[byte]
  writeStruct(payloadBuf, rtm)

  # Fold over dump messages, collecting delete buffers for matching routes
  let collectResult = m.foldDump(newSeq[seq[byte]](), RTM_GETROUTE.uint16, payloadBuf,
    proc(acc: sink seq[seq[byte]], msg: DumpMsg): seq[seq[byte]] {.raises: [].} =
      var res = acc
      if msg.hdr.nlmsgType != RTM_NEWROUTE.uint16:
        return res
      if msg.payload.len < sizeof(RtMsg):
        return res

      let rtmMsg = readStruct[RtMsg](msg.payload, 0)

      # Extract the route table (may be in RTA_TABLE attribute for tables > 255)
      var routeTable = uint32(rtmMsg.rtmTable)
      let attrStart = nlmsgAlign(sizeof(RtMsg))
      for (attrType, s) in nlAttrs(msg.payload, attrStart):
        if attrType == RTA_TABLE.uint16:
          routeTable = attrU32(msg.payload, s)
          break

      if routeTable != table:
        return res

      # Build a delete message from the original payload
      let totalLen = uint32(sizeof(NlMsgHdr) + msg.payload.len)
      let delHdr = NlMsgHdr(
        nlmsgLen: totalLen,
        nlmsgType: RTM_DELROUTE.uint16,
        nlmsgFlags: NLM_F_REQUEST.uint16 or NLM_F_ACK.uint16,
        nlmsgSeq: 0,  # Will be overridden if needed
        nlmsgPid: 0,
      )

      var delBuf = newSeq[byte](int(totalLen))
      copyMem(addr delBuf[0], unsafeAddr delHdr, sizeof(NlMsgHdr))
      if msg.payload.len > 0:
        copyMem(addr delBuf[sizeof(NlMsgHdr)], unsafeAddr msg.payload[0], msg.payload.len)

      res.add(delBuf)
      res
  )

  if not collectResult.ok:
    return nlErr[void](NlError(
      kind: collectResult.error.kind, osError: collectResult.error.osError,
      operation: "flushTable",
      detail: "dump failed for table " & $table))

  let deleteMsgs = collectResult.value

  # Send all delete messages, accumulating failures
  var failCount = 0
  let total = deleteMsgs.len
  for delBuf in deleteMsgs:
    let ack = m.sock.sendAndAck(delBuf, m.recvBuf)
    if not ack.ok:
      inc failCount

  if failCount > 0:
    let familyStr = if family == AF_INET: "IPv4" else: "IPv6"
    return nlErr[void](NlError(
      kind: nekKernelError, osError: 0,
      operation: "flushTable",
      detail: "flushed " & $(total - failCount) & "/" & $total &
              " routes from table " & $table & ", family " & familyStr))

  nlOk()

proc flushTable*(m: var RouteManager, table: uint32,
                 family: uint8): NlResult[void] {.raises: [].} =
  ## Flush all routes in a routing table for the given address family.
  m.flushTableFamily(table, family)

proc flushTableBoth*(m: var RouteManager, table: uint32): NlResult[void] {.raises: [].} =
  ## Flush all routes in a routing table (both IPv4 and IPv6).
  let r4 = m.flushTableFamily(table, AF_INET)
  let r6 = m.flushTableFamily(table, AF_INET6)
  # Return first error if any
  if not r4.ok: return r4
  if not r6.ok: return r6
  nlOk()

# ---------------------------------------------------------------------------
# getAddresses
# ---------------------------------------------------------------------------

type
  AddrInfo* = object
    address*: seq[byte]   ## Raw IP bytes (4 for IPv4, 16 for IPv6)
    prefixLen*: uint8

proc getAddresses*(m: var RouteManager, ifindex: uint32,
                   family: uint8): NlResult[seq[AddrInfo]] {.raises: [].} =
  ## Dump addresses via RTM_GETADDR, filter by ifindex, return matching ones.

  let ifa = IfAddrMsg(
    ifaFamily: family,
    ifaPrefixLen: 0,
    ifaFlags: 0,
    ifaScope: 0,
    ifaIndex: 0,
  )
  var payloadBuf: seq[byte]
  writeStruct(payloadBuf, ifa)

  m.foldDump(newSeq[AddrInfo](), RTM_GETADDR.uint16, payloadBuf,
    proc(acc: sink seq[AddrInfo], msg: DumpMsg): seq[AddrInfo] {.raises: [].} =
      var res = acc
      if msg.hdr.nlmsgType != RTM_NEWADDR.uint16:
        return res
      if msg.payload.len < sizeof(IfAddrMsg):
        return res

      let ifaMsg = readStruct[IfAddrMsg](msg.payload, 0)
      if ifaMsg.ifaIndex != ifindex or ifaMsg.ifaFamily != family:
        return res

      let attrStart = nlmsgAlign(sizeof(IfAddrMsg))
      for (attrType, s) in nlAttrs(msg.payload, attrStart):
        if attrType == IFA_ADDRESS.uint16:
          let addrLen = s.b - s.a + 1
          let expectedLen = if family == AF_INET: 4 else: 16
          if addrLen >= expectedLen:
            var addrBytes = newSeq[byte](expectedLen)
            copyMem(addr addrBytes[0], unsafeAddr msg.payload[s.a], expectedLen)
            res.add(AddrInfo(address: addrBytes, prefixLen: ifaMsg.ifaPrefixLen))
          break

      res
  )
