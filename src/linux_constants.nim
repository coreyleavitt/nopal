## Linux-specific constants not available in Nim's posix module.
## All values are for Linux; this module should not be imported on other OSes.

# Netlink families
const AF_NETLINK* = cint(16)
const AF_PACKET* = cint(17)

# Netlink protocols
const NETLINK_ROUTE* = cint(0)
const NETLINK_NETFILTER* = cint(12)

# Socket options
const SO_MARK* = cint(36)
const SO_BINDTODEVICE* = cint(25)

# Ethernet protocol for ARP
const ETH_P_ARP* = cushort(0x0806)

# Netlink message types (NETLINK_ROUTE)
const RTM_NEWLINK* = cushort(16)
const RTM_DELLINK* = cushort(17)
const RTM_GETLINK* = cushort(18)
const RTM_NEWADDR* = cushort(20)
const RTM_DELADDR* = cushort(21)
const RTM_GETADDR* = cushort(22)
const RTM_NEWROUTE* = cushort(24)
const RTM_DELROUTE* = cushort(25)
const RTM_GETROUTE* = cushort(26)
const RTM_NEWRULE* = cushort(32)
const RTM_DELRULE* = cushort(33)

# Netlink message flags
const NLM_F_REQUEST* = cushort(0x01)
const NLM_F_MULTI* = cushort(0x02)
const NLM_F_ACK* = cushort(0x04)
const NLM_F_ROOT* = cushort(0x100)
const NLM_F_MATCH* = cushort(0x200)
const NLM_F_DUMP* = cushort(NLM_F_ROOT or NLM_F_MATCH)
const NLM_F_CREATE* = cushort(0x400)
const NLM_F_EXCL* = cushort(0x200)

# Netlink multicast groups
const RTNLGRP_LINK* = cuint(1)
const RTNLGRP_IPV4_IFADDR* = cuint(5)
const RTNLGRP_IPV4_ROUTE* = cuint(7)
const RTNLGRP_IPV6_IFADDR* = cuint(9)
const RTNLGRP_IPV6_ROUTE* = cuint(11)

# Route attributes
const RTA_DST* = cushort(1)
const RTA_SRC* = cushort(2)
const RTA_IIF* = cushort(3)
const RTA_OIF* = cushort(4)
const RTA_GATEWAY* = cushort(5)
const RTA_TABLE* = cushort(15)

# Interface flags
const IFF_UP* = cuint(0x1)
const IFF_RUNNING* = cuint(0x40)

# Interface attributes
const IFLA_IFNAME* = cushort(3)

# Ioctl requests
const SIOCGIFINDEX* = culong(0x8933)
const SIOCGIFHWADDR* = culong(0x8927)
const SIOCGIFADDR* = culong(0x8915)

# Conntrack (NETLINK_NETFILTER)
const NFNL_SUBSYS_CTNETLINK* = cuchar(1)
const IPCTNL_MSG_CT_DELETE* = cuchar(2)
const CTA_MARK* = cushort(8)
const CTA_MARK_MASK* = cushort(18)

# Netlink header struct
type
  NlMsgHdr* {.packed.} = object
    nlmsgLen*: uint32
    nlmsgType*: uint16
    nlmsgFlags*: uint16
    nlmsgSeq*: uint32
    nlmsgPid*: uint32

static:
  assert sizeof(NlMsgHdr) == 16

# Route message header
type
  RtMsg* {.packed.} = object
    rtmFamily*: uint8
    rtmDstLen*: uint8
    rtmSrcLen*: uint8
    rtmTos*: uint8
    rtmTable*: uint8
    rtmProtocol*: uint8
    rtmScope*: uint8
    rtmType*: uint8
    rtmFlags*: uint32

static:
  assert sizeof(RtMsg) == 12

# Interface info message header
type
  IfInfoMsg* {.packed.} = object
    ifFamily*: uint8
    pad*: uint8
    ifType*: uint16
    ifIndex*: int32
    ifFlags*: uint32
    ifChange*: uint32

static:
  assert sizeof(IfInfoMsg) == 16
