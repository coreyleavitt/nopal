## Route manager: add/delete routes, ip rules, address queries via NETLINK_ROUTE.
##
## Manages kernel routing tables and ip rules through native netlink messages.
## All operations use a single NETLINK_ROUTE socket with sequence numbering.

import std/[posix, os, monotimes, times]
import ../linux_constants
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
# addRoute
# ---------------------------------------------------------------------------

proc addRoute*(m: var RouteManager, table: uint32, gateway: openArray[byte],
               oif: uint32, family: uint8) =
  ## Add a default route to a routing table.
  ## gateway: raw IP bytes (4 for IPv4, 16 for IPv6).
  ## oif: output interface index.
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

  # RTA_TABLE (supports tables > 255)
  b.addAttrU32(RTA_TABLE.uint16, table)

  # RTA_GATEWAY
  b.addAttr(RTA_GATEWAY.uint16, gateway)

  # RTA_OIF
  b.addAttrU32(RTA_OIF.uint16, oif)

  let msg = b.finish()
  discard m.sock.sendAndAck(msg, m.recvBuf)

# ---------------------------------------------------------------------------
# delRoute
# ---------------------------------------------------------------------------

proc delRoute*(m: var RouteManager, table: uint32, family: uint8) =
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
  discard m.sock.sendAndAck(msg, m.recvBuf)

# ---------------------------------------------------------------------------
# addRule / delRule
# ---------------------------------------------------------------------------

proc modifyRule(m: var RouteManager, msgType: uint16, mark, mask, table,
                priority: uint32, family: uint8) =
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
  discard m.sock.sendAndAck(msg, m.recvBuf)

proc addRule*(m: var RouteManager, mark, mask, table, priority: uint32,
              family: uint8) =
  ## Add an ip rule: fwmark/mask -> table at given priority.
  m.modifyRule(RTM_NEWRULE.uint16, mark, mask, table, priority, family)

proc delRule*(m: var RouteManager, mark, mask, table, priority: uint32,
              family: uint8) =
  ## Delete an ip rule: fwmark/mask -> table.
  m.modifyRule(RTM_DELRULE.uint16, mark, mask, table, priority, family)

# ---------------------------------------------------------------------------
# Dump helper
# ---------------------------------------------------------------------------

proc recvDump(m: var RouteManager, callback: proc(hdr: NlMsgHdr,
              data: openArray[byte], payloadSlice: Slice[int]): bool) =
  ## Receive a netlink dump response, calling callback for each message.
  ## callback returns true to stop iteration (like break).
  ## Stops on NLMSG_DONE or NLMSG_ERROR with error=0.
  let deadline = getMonoTime() + initDuration(milliseconds = DumpTimeoutMs)

  while true:
    let n = m.sock.recvMsg(m.recvBuf)
    if n < 0:
      raiseOSError(osLastError())
    if n == 0:
      if getMonoTime() >= deadline:
        raise newException(IOError, "timeout waiting for netlink dump")
      discard posix.poll(nil, 0, 1)  # 1ms sleep
      continue

    for (hdr, payloadSlice) in nlMsgs(m.recvBuf, n):
      if hdr.nlmsgType == NLMSG_DONE:
        return
      if hdr.nlmsgType == NLMSG_ERROR:
        if payloadSlice.b - payloadSlice.a + 1 >= sizeof(int32):
          let errCode = readStruct[int32](m.recvBuf, payloadSlice.a)
          if errCode != 0:
            raise newException(IOError, "netlink dump error: " & $errCode)
        return
      if callback(hdr, m.recvBuf[0 ..< n], payloadSlice):
        return

# ---------------------------------------------------------------------------
# flushTable
# ---------------------------------------------------------------------------

proc flushTableFamily(m: var RouteManager, table: uint32, family: uint8) =
  ## Dump routes for one family, collect those in `table`, then delete each.
  let seq = m.nextSeq()

  let rtm = RtMsg(
    rtmFamily: family,
    rtmDstLen: 0, rtmSrcLen: 0, rtmTos: 0,
    rtmTable: 0, rtmProtocol: 0, rtmScope: 0, rtmType: 0, rtmFlags: 0,
  )

  var b = initBuilder(
    RTM_GETROUTE.uint16,
    NLM_F_REQUEST.uint16 or NLM_F_DUMP.uint16,
    seq,
  )
  b.addPayload(rtm)
  let msg = b.finish()
  discard m.sock.sendMsg(msg)

  # Collect delete messages (we can't send while receiving the dump)
  var deleteMsgs: seq[seq[byte]]

  m.recvDump(proc(hdr: NlMsgHdr, data: openArray[byte],
                   payloadSlice: Slice[int]): bool =
    if hdr.nlmsgType != RTM_NEWROUTE.uint16:
      return false

    let msgStart = payloadSlice.a
    let msgEnd = payloadSlice.b + 1  # exclusive end
    if msgEnd - msgStart < sizeof(RtMsg):
      return false

    let rtmMsg = readStruct[RtMsg](data, msgStart)

    # Determine table from rtm_table and RTA_TABLE attribute
    var routeTable = uint32(rtmMsg.rtmTable)
    let attrStart = msgStart + nlmsgAlign(sizeof(RtMsg))
    for (attrType, s) in nlAttrs(data[0 ..< msgEnd], attrStart):
      if attrType == RTA_TABLE.uint16:
        routeTable = attrU32(data[0 ..< msgEnd], s)
        break

    if routeTable != table:
      return false

    # Build RTM_DELROUTE by reusing the original payload with a new header
    let delSeq = m.nlSeq + 1  # peek next seq
    m.nlSeq = delSeq
    let payload = data[msgStart ..< msgEnd]
    let totalLen = uint32(sizeof(NlMsgHdr) + payload.len)

    let delHdr = NlMsgHdr(
      nlmsgLen: totalLen,
      nlmsgType: RTM_DELROUTE.uint16,
      nlmsgFlags: NLM_F_REQUEST.uint16 or NLM_F_ACK.uint16,
      nlmsgSeq: delSeq,
      nlmsgPid: 0,
    )

    var delBuf = newSeq[byte](int(totalLen))
    copyMem(addr delBuf[0], unsafeAddr delHdr, sizeof(NlMsgHdr))
    if payload.len > 0:
      copyMem(addr delBuf[sizeof(NlMsgHdr)], unsafeAddr payload[0], payload.len)

    deleteMsgs.add(delBuf)
    false  # continue iterating
  )

  # Now send all delete messages
  for delBuf in deleteMsgs:
    discard m.sock.sendAndAck(delBuf, m.recvBuf)

proc flushTable*(m: var RouteManager, table: uint32, family: uint8) =
  ## Flush all routes in a routing table for the given address family.
  m.flushTableFamily(table, family)

proc flushTableBoth*(m: var RouteManager, table: uint32) =
  ## Flush all routes in a routing table (both IPv4 and IPv6).
  m.flushTableFamily(table, AF_INET)
  m.flushTableFamily(table, AF_INET6)

# ---------------------------------------------------------------------------
# getAddresses
# ---------------------------------------------------------------------------

type
  AddrInfo* = object
    address*: seq[byte]   ## Raw IP bytes (4 for IPv4, 16 for IPv6)
    prefixLen*: uint8

proc getAddresses*(m: var RouteManager, ifindex: uint32,
                   family: uint8): seq[AddrInfo] =
  ## Dump addresses via RTM_GETADDR, filter by ifindex, return matching ones.
  let seq = m.nextSeq()

  let ifa = IfAddrMsg(
    ifaFamily: family,
    ifaPrefixLen: 0,
    ifaFlags: 0,
    ifaScope: 0,
    ifaIndex: 0,
  )

  var b = initBuilder(
    RTM_GETADDR.uint16,
    NLM_F_REQUEST.uint16 or NLM_F_DUMP.uint16,
    seq,
  )
  b.addPayload(ifa)
  let msg = b.finish()
  discard m.sock.sendMsg(msg)

  var addrs: seq[AddrInfo]

  m.recvDump(proc(hdr: NlMsgHdr, data: openArray[byte],
                   payloadSlice: Slice[int]): bool =
    if hdr.nlmsgType != RTM_NEWADDR.uint16:
      return false

    let msgStart = payloadSlice.a
    let msgEnd = payloadSlice.b + 1  # exclusive end
    if msgEnd - msgStart < sizeof(IfAddrMsg):
      return false

    let ifaMsg = readStruct[IfAddrMsg](data, msgStart)

    if ifaMsg.ifaIndex != ifindex or ifaMsg.ifaFamily != family:
      return false

    # Scan for IFA_ADDRESS attribute
    let attrStart = msgStart + nlmsgAlign(sizeof(IfAddrMsg))
    for (attrType, s) in nlAttrs(data[0 ..< msgEnd], attrStart):
      if attrType == IFA_ADDRESS.uint16:
        let addrLen = s.b - s.a + 1
        let expectedLen = if family == AF_INET: 4 else: 16
        if addrLen >= expectedLen:
          var addrBytes = newSeq[byte](expectedLen)
          copyMem(addr addrBytes[0], unsafeAddr data[s.a], expectedLen)
          addrs.add(AddrInfo(address: addrBytes, prefixLen: ifaMsg.ifaPrefixLen))
        break

    false  # continue iterating
  )

  addrs
