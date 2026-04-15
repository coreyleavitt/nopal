## Route manager: add/delete routes, ip rules, address queries via NETLINK_ROUTE.
##
## Manages kernel routing tables and ip rules through native netlink messages.
## All operations use a single NETLINK_ROUTE socket with sequence numbering.
## Returns NlResult for all operations — callers decide error policy.

import std/[posix, os, monotimes, times, strutils]
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

proc close*(m: var RouteManager) {.raises: [].} =
  ## Close the netlink socket.
  m.sock.close()

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

  var deleteMsgs = collectResult.value

  # Send all delete messages, accumulating failures.
  # Stamp each with a unique sequence number for ACK matching.
  var failCount = 0
  let total = deleteMsgs.len
  for i in 0 ..< deleteMsgs.len:
    let seq = m.nextSeq()
    if deleteMsgs[i].len >= sizeof(NlMsgHdr):
      var hdr = readStruct[NlMsgHdr](deleteMsgs[i], 0)
      hdr.nlmsgSeq = seq
      copyMem(addr deleteMsgs[i][0], unsafeAddr hdr, sizeof(NlMsgHdr))
    let ack = m.sock.sendAndAck(deleteMsgs[i], m.recvBuf)
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
  `?`(m.flushTableFamily(table, AF_INET))
  `?`(m.flushTableFamily(table, AF_INET6))
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

# ---------------------------------------------------------------------------
# getDefaultRoutes
# ---------------------------------------------------------------------------

type
  DefaultRouteInfo* = object
    ifindex*: uint32
    family*: uint8
    gateway*: array[16, byte]  ## Raw gateway IP (4 bytes for IPv4, 16 for IPv6)
    metric*: uint32

proc getDefaultRoutes*(m: var RouteManager): NlResult[seq[DefaultRouteInfo]] {.raises: [].} =
  ## Dump default routes from the main table.
  ## Returns gateway, OIF ifindex, family, and metric for each.
  let rtm = RtMsg(
    rtmFamily: 0,  # both families
    rtmDstLen: 0, rtmSrcLen: 0, rtmTos: 0,
    rtmTable: 0, rtmProtocol: 0, rtmScope: 0, rtmType: 0, rtmFlags: 0,
  )
  var payloadBuf: seq[byte]
  writeStruct(payloadBuf, rtm)

  m.foldDump(newSeq[DefaultRouteInfo](), RTM_GETROUTE.uint16, payloadBuf,
    proc(acc: sink seq[DefaultRouteInfo], msg: DumpMsg): seq[DefaultRouteInfo] {.raises: [].} =
      var res = acc
      if msg.hdr.nlmsgType != RTM_NEWROUTE.uint16:
        return res
      if msg.payload.len < sizeof(RtMsg):
        return res

      let rtmMsg = readStruct[RtMsg](msg.payload, 0)

      # Only default routes (dstLen=0), unicast, main table
      if rtmMsg.rtmDstLen != 0 or rtmMsg.rtmType != RTN_UNICAST:
        return res
      let family = rtmMsg.rtmFamily
      if family != AF_INET and family != AF_INET6:
        return res

      # Extract attributes
      let attrStart = nlmsgAlign(sizeof(RtMsg))
      var routeTable = uint32(rtmMsg.rtmTable)
      var oif: uint32 = 0
      var hasOif = false
      var gw: array[16, byte]
      var hasGw = false
      var metric: uint32 = 0

      for (attrType, s) in nlAttrs(msg.payload, attrStart):
        if attrType == RTA_TABLE.uint16:
          routeTable = attrU32(msg.payload, s)
        elif attrType == RTA_OIF.uint16:
          oif = attrU32(msg.payload, s)
          hasOif = true
        elif attrType == RTA_GATEWAY.uint16:
          let gwLen = if family == AF_INET: 4 else: 16
          if s.a + gwLen <= msg.payload.len:
            copyMem(addr gw[0], unsafeAddr msg.payload[s.a], gwLen)
            hasGw = true
        elif attrType == RTA_PRIORITY.uint16:
          metric = attrU32(msg.payload, s)

      # Only main table, must have OIF and gateway
      if routeTable != uint32(RT_TABLE_MAIN) or not hasOif or not hasGw:
        return res

      res.add(DefaultRouteInfo(
        ifindex: oif, family: family, gateway: gw, metric: metric))
      res
  )

# ---------------------------------------------------------------------------
# getConnectedNetworks
# ---------------------------------------------------------------------------

func formatIpv4Cidr(ip: openArray[byte], prefixLen: uint8): string {.raises: [].} =
  ## Format raw IPv4 bytes + prefix length as CIDR string.
  if ip.len < 4: return ""
  $ip[0] & "." & $ip[1] & "." & $ip[2] & "." & $ip[3] & "/" & $prefixLen

func formatIpv6Cidr(ip: openArray[byte], prefixLen: uint8): string {.raises: [].} =
  ## Format raw IPv6 bytes + prefix length as CIDR string.
  if ip.len < 16: return ""
  var parts: array[8, string]
  for i in 0 ..< 8:
    let val = (uint16(ip[i * 2]) shl 8) or uint16(ip[i * 2 + 1])
    parts[i] = val.toHex(4).toLowerAscii().strip(chars = {'0'}, trailing = false)
    if parts[i].len == 0: parts[i] = "0"
  var s = parts[0]
  for i in 1 ..< 8:
    s &= ":" & parts[i]
  s & "/" & $prefixLen

proc getConnectedNetworksFamily(m: var RouteManager,
                                family: uint8): NlResult[seq[string]] {.raises: [].} =
  ## Dump connected (scope-link) routes for one address family.
  let rtm = RtMsg(
    rtmFamily: family,
    rtmDstLen: 0, rtmSrcLen: 0, rtmTos: 0,
    rtmTable: 0, rtmProtocol: 0, rtmScope: 0, rtmType: 0, rtmFlags: 0,
  )
  var payloadBuf: seq[byte]
  writeStruct(payloadBuf, rtm)

  m.foldDump(newSeq[string](), RTM_GETROUTE.uint16, payloadBuf,
    proc(acc: sink seq[string], msg: DumpMsg): seq[string] {.raises: [].} =
      var res = acc
      if msg.hdr.nlmsgType != RTM_NEWROUTE.uint16:
        return res
      if msg.payload.len < sizeof(RtMsg):
        return res

      let rtmMsg = readStruct[RtMsg](msg.payload, 0)

      # Filter: scope-link routes (directly connected subnets)
      if rtmMsg.rtmScope != RT_SCOPE_LINK:
        return res
      if rtmMsg.rtmType != RTN_UNICAST:
        return res
      # Skip routes with no destination (default routes)
      if rtmMsg.rtmDstLen == 0:
        return res

      # Extract RTA_DST attribute
      let attrStart = nlmsgAlign(sizeof(RtMsg))
      for (attrType, s) in nlAttrs(msg.payload, attrStart):
        if attrType == RTA_DST.uint16:
          let addrLen = s.b - s.a + 1
          let expectedLen = if family == AF_INET: 4 else: 16
          if addrLen >= expectedLen:
            let cidr = if family == AF_INET:
              formatIpv4Cidr(msg.payload[s.a ..< s.a + expectedLen], rtmMsg.rtmDstLen)
            else:
              formatIpv6Cidr(msg.payload[s.a ..< s.a + expectedLen], rtmMsg.rtmDstLen)
            if cidr.len > 0:
              res.add(cidr)
          break

      res
  )

proc getConnectedNetworks*(m: var RouteManager): NlResult[seq[string]] {.raises: [].} =
  ## Dump all connected networks (scope-link routes) from the kernel routing table.
  ## Returns CIDRs for directly connected subnets. Always includes loopback fallbacks.
  var networks: seq[string] = @["127.0.0.0/8"]

  let r4 = m.getConnectedNetworksFamily(AF_INET)
  if r4.ok:
    for cidr in r4.value:
      if cidr notin networks:
        networks.add(cidr)

  let r6 = m.getConnectedNetworksFamily(AF_INET6)
  if r6.ok:
    for cidr in r6.value:
      if cidr notin networks:
        networks.add(cidr)
  elif networks.len == 1:
    # Only loopback so far — add IPv6 loopback fallback
    networks.add("::1/128")

  # Ensure IPv6 loopback is present
  if "::1/128" notin networks:
    networks.add("::1/128")

  nlOk(networks)

proc getLocalRoutesFamily(m: var RouteManager, family: uint8,
                          wanIfindexes: openArray[uint32]): NlResult[seq[string]] {.raises: [].} =
  ## Dump non-default unicast routes in the main table whose OIF is NOT
  ## a managed WAN interface. These are locally-routable destinations
  ## (VPN tunnels, static routes to local infrastructure) that should
  ## bypass policy routing.
  let rtm = RtMsg(
    rtmFamily: family,
    rtmDstLen: 0, rtmSrcLen: 0, rtmTos: 0,
    rtmTable: 0, rtmProtocol: 0, rtmScope: 0, rtmType: 0, rtmFlags: 0,
  )
  var payloadBuf: seq[byte]
  writeStruct(payloadBuf, rtm)

  # Capture wanIfindexes in a seq for the closure
  var wanSet: seq[uint32]
  for idx in wanIfindexes: wanSet.add(idx)

  m.foldDump(newSeq[string](), RTM_GETROUTE.uint16, payloadBuf,
    proc(acc: sink seq[string], msg: DumpMsg): seq[string] {.raises: [].} =
      var res = acc
      if msg.hdr.nlmsgType != RTM_NEWROUTE.uint16:
        return res
      if msg.payload.len < sizeof(RtMsg):
        return res

      let rtmMsg = readStruct[RtMsg](msg.payload, 0)

      # Only unicast, non-default, main table
      if rtmMsg.rtmType != RTN_UNICAST or rtmMsg.rtmDstLen == 0:
        return res
      # Skip scope-link (already handled by getConnectedNetworks)
      if rtmMsg.rtmScope == RT_SCOPE_LINK:
        return res

      # Extract table and OIF
      let attrStart = nlmsgAlign(sizeof(RtMsg))
      var routeTable = uint32(rtmMsg.rtmTable)
      var oif: uint32 = 0
      var hasOif = false
      var dst: array[16, byte]
      var hasDst = false

      for (attrType, s) in nlAttrs(msg.payload, attrStart):
        if attrType == RTA_TABLE.uint16:
          routeTable = attrU32(msg.payload, s)
        elif attrType == RTA_OIF.uint16:
          oif = attrU32(msg.payload, s)
          hasOif = true
        elif attrType == RTA_DST.uint16:
          let addrLen = if family == AF_INET: 4 else: 16
          if s.a + addrLen <= msg.payload.len:
            copyMem(addr dst[0], unsafeAddr msg.payload[s.a], addrLen)
            hasDst = true

      # Must be main table, have OIF and destination
      if routeTable != uint32(RT_TABLE_MAIN) or not hasOif or not hasDst:
        return res

      # Skip routes through managed WAN interfaces
      for wanIdx in wanSet:
        if oif == wanIdx:
          return res

      # Format as CIDR
      let cidr = if family == AF_INET:
        formatIpv4Cidr(dst[0 ..< 4], rtmMsg.rtmDstLen)
      else:
        formatIpv6Cidr(dst, rtmMsg.rtmDstLen)
      if cidr.len > 0:
        res.add(cidr)

      res
  )

proc getBypassNetworks*(m: var RouteManager,
                        wanIfindexes: openArray[uint32]): NlResult[seq[string]] {.raises: [].} =
  ## Dump all networks that should bypass policy routing:
  ## 1. Connected subnets (scope-link routes) — directly attached networks
  ## 2. Routes through non-WAN interfaces (VPN tunnels, local infrastructure)
  ## Always includes loopback fallbacks.
  var networks: seq[string] = @["127.0.0.0/8"]

  # Connected subnets (scope-link)
  let r4 = m.getConnectedNetworksFamily(AF_INET)
  if r4.ok:
    for cidr in r4.value:
      if cidr notin networks:
        networks.add(cidr)

  let r6 = m.getConnectedNetworksFamily(AF_INET6)
  if r6.ok:
    for cidr in r6.value:
      if cidr notin networks:
        networks.add(cidr)

  # Locally-routable destinations (non-WAN OIF)
  let lr4 = m.getLocalRoutesFamily(AF_INET, wanIfindexes)
  if lr4.ok:
    for cidr in lr4.value:
      if cidr notin networks:
        networks.add(cidr)

  let lr6 = m.getLocalRoutesFamily(AF_INET6, wanIfindexes)
  if lr6.ok:
    for cidr in lr6.value:
      if cidr notin networks:
        networks.add(cidr)

  # Ensure IPv6 loopback is present
  if "::1/128" notin networks:
    networks.add("::1/128")

  nlOk(networks)

when isMainModule:
  import std/unittest

  suite "IP CIDR formatting":
    test "formatIpv4Cidr":
      check formatIpv4Cidr([192'u8, 168, 1, 0], 24) == "192.168.1.0/24"
      check formatIpv4Cidr([10'u8, 0, 0, 0], 8) == "10.0.0.0/8"

    test "formatIpv6Cidr":
      var ip: array[16, byte]
      ip[0] = 0xfd; ip[1] = 0x00
      let cidr = formatIpv6Cidr(ip, 48)
      check cidr.startsWith("fd00:")
      check cidr.endsWith("/48")

  suite "toNlResult mapping":
    test "ok maps to success":
      let r = toNlResult(nlAckOk(), "test", "detail")
      check r.ok

    test "sendFailed maps with osError":
      let r = toNlResult(nlAckErr(nakSendFailed, 13), "addRoute", "table 100")
      check not r.ok
      check r.error.kind == nekSendFailed
      check r.error.osError == 13
      check r.error.operation == "addRoute"
      check r.error.detail == "table 100"

    test "recvFailed maps correctly":
      let r = toNlResult(nlAckErr(nakRecvFailed, 104), "delRoute", "table 200")
      check not r.ok
      check r.error.kind == nekRecvFailed
      check r.error.osError == 104

    test "timeout maps with zero osError":
      let r = toNlResult(nlAckErr(nakTimeout), "addRule", "mark 0x100")
      check not r.ok
      check r.error.kind == nekTimeout
      check r.error.osError == 0

    test "kernelError maps with errno":
      let r = toNlResult(nlAckErr(nakKernelError, 17), "addRoute", "table 100")
      check not r.ok
      check r.error.kind == nekKernelError
      check r.error.osError == 17

  suite "DumpMsg attribute extraction":
    test "extract RTA_TABLE from RtMsg payload":
      var payload: seq[byte]
      let rtm = RtMsg(
        rtmFamily: AF_INET, rtmDstLen: 0, rtmSrcLen: 0, rtmTos: 0,
        rtmTable: 0, rtmProtocol: RTPROT_STATIC, rtmScope: RT_SCOPE_UNIVERSE,
        rtmType: RTN_UNICAST, rtmFlags: 0,
      )
      writeStruct(payload, rtm)

      let attrHdr = NlAttr(nlaLen: uint16(sizeof(NlAttr) + 4), nlaType: RTA_TABLE.uint16)
      writeStruct(payload, attrHdr)
      var tableVal = 142'u32
      let pos = payload.len
      payload.setLen(pos + 4)
      copyMem(addr payload[pos], addr tableVal, 4)

      let msg = DumpMsg(
        hdr: NlMsgHdr(nlmsgLen: 0, nlmsgType: RTM_NEWROUTE.uint16,
                      nlmsgFlags: 0, nlmsgSeq: 0, nlmsgPid: 0),
        payload: payload,
      )

      let rtmMsg = readStruct[RtMsg](msg.payload, 0)
      var routeTable = uint32(rtmMsg.rtmTable)
      let attrStart = nlmsgAlign(sizeof(RtMsg))
      for (attrType, s) in nlAttrs(msg.payload, attrStart):
        if attrType == RTA_TABLE.uint16:
          routeTable = attrU32(msg.payload, s)
          break
      check routeTable == 142

    test "extract IFA_ADDRESS from IfAddrMsg payload":
      var payload: seq[byte]
      let ifa = IfAddrMsg(
        ifaFamily: AF_INET, ifaPrefixLen: 24, ifaFlags: 0, ifaScope: 0, ifaIndex: 5,
      )
      writeStruct(payload, ifa)

      let addrBytes = [192'u8, 168, 1, 1]
      let attrHdr = NlAttr(nlaLen: uint16(sizeof(NlAttr) + 4), nlaType: IFA_ADDRESS.uint16)
      writeStruct(payload, attrHdr)
      for b in addrBytes:
        payload.add(b)

      let msg = DumpMsg(
        hdr: NlMsgHdr(nlmsgLen: 0, nlmsgType: RTM_NEWADDR.uint16,
                      nlmsgFlags: 0, nlmsgSeq: 0, nlmsgPid: 0),
        payload: payload,
      )

      let ifaMsg = readStruct[IfAddrMsg](msg.payload, 0)
      check ifaMsg.ifaIndex == 5
      check ifaMsg.ifaPrefixLen == 24

      let attrStart = nlmsgAlign(sizeof(IfAddrMsg))
      var foundAddr = false
      for (attrType, s) in nlAttrs(msg.payload, attrStart):
        if attrType == IFA_ADDRESS.uint16:
          let addrLen = s.b - s.a + 1
          check addrLen >= 4
          check msg.payload[s.a] == 192
          check msg.payload[s.a + 1] == 168
          check msg.payload[s.a + 2] == 1
          check msg.payload[s.a + 3] == 1
          foundAddr = true
          break
      check foundAddr
