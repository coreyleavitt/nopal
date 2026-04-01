## Link monitor: subscribes to RTNLGRP_LINK for interface up/down events.
##
## Parses RTM_NEWLINK / RTM_DELLINK messages to detect interface state
## transitions (up/down) based on IFF_UP and IFF_RUNNING flags.

import std/posix
import ../linux_constants
import ./socket

const
  RecvBufSize = 65536

type
  LinkEvent* = object
    ifindex*: uint32
    ifname*: string
    up*: bool

  LinkMonitor* = object
    sock: NetlinkSocket
    recvBuf: seq[byte]

proc newLinkMonitor*(): LinkMonitor =
  ## Create a LinkMonitor subscribed to RTNLGRP_LINK (group 1 -> bit 0).
  let groups = uint32(1 shl 0)  # RTNLGRP_LINK
  result = LinkMonitor(
    sock: openNetlink(NETLINK_ROUTE, groups),
    recvBuf: newSeq[byte](RecvBufSize),
  )

proc fd*(m: LinkMonitor): cint =
  ## Return the raw fd for selector/poll registration.
  m.sock.fd

proc processEvents*(m: var LinkMonitor, events: var seq[LinkEvent]) =
  ## Read pending link events from the socket and append to events.
  ## Non-blocking: returns immediately if no data available.
  let n = m.sock.recvMsg(m.recvBuf)
  if n <= 0:
    return

  for (hdr, payloadSlice) in nlMsgs(m.recvBuf, n):
    if hdr.nlmsgType != RTM_NEWLINK.uint16 and hdr.nlmsgType != RTM_DELLINK.uint16:
      continue

    # Need at least IfInfoMsg after the header
    let msgStart = payloadSlice.a  # start of payload after NlMsgHdr
    let msgEnd = payloadSlice.b + 1  # convert inclusive end to exclusive
    if msgEnd - msgStart < sizeof(IfInfoMsg):
      continue

    let ifi = readStruct[IfInfoMsg](m.recvBuf, msgStart)
    let ifindex = uint32(ifi.ifIndex)

    # Find IFLA_IFNAME in attributes
    let attrStart = msgStart + nlmsgAlign(sizeof(IfInfoMsg))
    var ifname = ""
    for (attrType, s) in nlAttrs(m.recvBuf[0 ..< msgEnd], attrStart):
      if attrType == IFLA_IFNAME.uint16:
        ifname = attrStr(m.recvBuf[0 ..< msgEnd], s)
        break

    if ifname.len == 0:
      continue

    # Determine link state
    let up = if hdr.nlmsgType == RTM_DELLINK.uint16:
      false
    else:
      (ifi.ifFlags and IFF_UP.uint32) != 0 and
        (ifi.ifFlags and IFF_RUNNING.uint32) != 0

    events.add(LinkEvent(ifindex: ifindex, ifname: ifname, up: up))
