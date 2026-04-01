## Route monitor: subscribes to route/address change notifications.
##
## Monitors default route and interface address changes in the main routing
## table via netlink multicast. Used to detect external route/address changes
## that require re-syncing policy routing state.

import std/posix
import ../linux_constants
import ./socket

const
  RecvBufSize = 65536
  AF_INET = uint8(2)
  AF_INET6 = uint8(10)
  RT_TABLE_MAIN_U32 = uint32(254)

type
  RouteChangeKind* = enum
    rckRouteAdd
    rckRouteDel
    rckAddrAdd
    rckAddrDel

  RouteChange* = object
    kind*: RouteChangeKind
    ifindex*: uint32
    family*: uint8
    table*: uint32

  RouteMonitor* = object
    sock: NetlinkSocket
    recvBuf: seq[byte]

proc newRouteMonitor*(): RouteMonitor =
  ## Subscribe to RTNLGRP_IPV4_ROUTE (7), IPV6_ROUTE (11),
  ## IPV4_IFADDR (5), IPV6_IFADDR (9).
  ## Groups are bitmasks: 1 shl (group - 1).
  let groups = uint32(
    (1 shl (7 - 1)) or   # RTNLGRP_IPV4_ROUTE
    (1 shl (11 - 1)) or  # RTNLGRP_IPV6_ROUTE
    (1 shl (5 - 1)) or   # RTNLGRP_IPV4_IFADDR
    (1 shl (9 - 1))      # RTNLGRP_IPV6_IFADDR
  )
  result = RouteMonitor(
    sock: openNetlink(NETLINK_ROUTE, groups),
    recvBuf: newSeq[byte](RecvBufSize),
  )

proc fd*(m: RouteMonitor): cint =
  ## Return the raw fd for selector/poll registration.
  m.sock.fd

proc processEvents*(m: var RouteMonitor, changes: var seq[RouteChange]) =
  ## Read pending events. Route events are filtered to default routes
  ## (dstLen=0) in the main table (254) with unicast type, and deduplicated
  ## by (ifindex, family). Address events produce add/del changes.
  let n = m.sock.recvMsg(m.recvBuf)
  if n <= 0:
    return

  for (hdr, payloadSlice) in nlMsgs(m.recvBuf, n):
    let msgStart = payloadSlice.a
    let msgEnd = payloadSlice.b + 1  # convert inclusive end to exclusive

    case hdr.nlmsgType
    of RTM_NEWROUTE.uint16, RTM_DELROUTE.uint16:
      # Parse route message
      if msgEnd - msgStart < sizeof(RtMsg):
        continue

      let rtm = readStruct[RtMsg](m.recvBuf, msgStart)

      # Only default routes (dstLen=0), unicast type
      if rtm.rtmDstLen != 0 or rtm.rtmType != RTN_UNICAST:
        continue

      let family = rtm.rtmFamily
      if family != AF_INET and family != AF_INET6:
        continue

      # Scan attributes for table and OIF
      let attrStart = msgStart + nlmsgAlign(sizeof(RtMsg))
      var routeTable = uint32(rtm.rtmTable)
      var oif: uint32 = 0
      var hasOif = false

      for (attrType, s) in nlAttrs(m.recvBuf[0 ..< msgEnd], attrStart):
        if attrType == RTA_TABLE.uint16:
          routeTable = attrU32(m.recvBuf[0 ..< msgEnd], s)
        elif attrType == RTA_OIF.uint16:
          oif = attrU32(m.recvBuf[0 ..< msgEnd], s)
          hasOif = true

      # Only main table (254)
      if routeTable != RT_TABLE_MAIN_U32:
        continue

      # Must have an output interface
      if not hasOif:
        continue

      let kind = if hdr.nlmsgType == RTM_NEWROUTE.uint16: rckRouteAdd
                 else: rckRouteDel

      # Dedup by (ifindex, family): remove existing entry with same key
      var i = 0
      while i < changes.len:
        if changes[i].ifindex == oif and changes[i].family == family and
           (changes[i].kind == rckRouteAdd or changes[i].kind == rckRouteDel):
          changes.delete(i)
        else:
          inc i

      changes.add(RouteChange(
        kind: kind, ifindex: oif, family: family, table: routeTable))

    of RTM_NEWADDR.uint16, RTM_DELADDR.uint16:
      # Parse address message
      if msgEnd - msgStart < sizeof(IfAddrMsg):
        continue

      let ifa = readStruct[IfAddrMsg](m.recvBuf, msgStart)

      let family = ifa.ifaFamily
      if family != AF_INET and family != AF_INET6:
        continue

      let kind = if hdr.nlmsgType == RTM_NEWADDR.uint16: rckAddrAdd
                 else: rckAddrDel

      changes.add(RouteChange(
        kind: kind, ifindex: ifa.ifaIndex, family: family, table: 0))

    else:
      discard
