## Route manager: add/delete routes, ip rules, address queries via NETLINK_ROUTE.

import ./socket

type
  RouteManager* = object
    sock: NetlinkSocket
    seq: uint32
    recvBuf: seq[byte]
