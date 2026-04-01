## Netlink socket abstraction: NlMsgBuilder, send/recv, ACK handling.

import ../linux_constants

type
  NetlinkSocket* = object
    fd*: cint
