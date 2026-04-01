## Conntrack manager: selective flush by firewall mark via NETLINK_NETFILTER.

import ./socket

type
  ConntrackManager* = object
    sock: NetlinkSocket
