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
const NLM_F_DUMP* = cushort(NLM_F_ROOT.int or NLM_F_MATCH.int)
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

# Netlink attribute header
type
  NlAttr* {.packed.} = object
    nlaLen*: uint16
    nlaType*: uint16

static:
  assert sizeof(NlAttr) == 4

# Address message (RTM_NEWADDR / RTM_GETADDR)
type
  IfAddrMsg* {.packed.} = object
    ifaFamily*: uint8
    ifaPrefixLen*: uint8
    ifaFlags*: uint8
    ifaScope*: uint8
    ifaIndex*: uint32

static:
  assert sizeof(IfAddrMsg) == 8

# Netfilter generic header (for conntrack)
type
  NfGenMsg* {.packed.} = object
    nfgenFamily*: uint8
    version*: uint8
    resId*: uint16

static:
  assert sizeof(NfGenMsg) == 4

# Netlink error response
type
  NlMsgErr* {.packed.} = object
    error*: int32
    msg*: NlMsgHdr

static:
  assert sizeof(NlMsgErr) == 20

# ICMP echo header (shared layout for ICMPv4 and ICMPv6)
type
  IcmpEchoHdr* {.packed.} = object
    icmpType*: uint8
    icmpCode*: uint8
    icmpChecksum*: uint16
    icmpId*: uint16
    icmpSeq*: uint16

static:
  assert sizeof(IcmpEchoHdr) == 8

# ARP packet (28 bytes for IPv4-over-Ethernet)
type
  ArpPacket* {.packed.} = object
    hwType*: uint16       # 1 = Ethernet
    protoType*: uint16    # 0x0800 = IPv4
    hwLen*: uint8         # 6
    protoLen*: uint8      # 4
    operation*: uint16    # 1=request, 2=reply
    senderMac*: array[6, byte]
    senderIp*: array[4, byte]
    targetMac*: array[6, byte]
    targetIp*: array[4, byte]

static:
  assert sizeof(ArpPacket) == 28

# Netlink message types (generic)
const NLMSG_NOOP* = uint16(1)
const NLMSG_ERROR* = uint16(2)
const NLMSG_DONE* = uint16(3)

# Address attributes (IFA_*)
const IFA_ADDRESS* = cushort(1)
const IFA_LOCAL* = cushort(2)
const IFA_LABEL* = cushort(3)

# Route table/protocol/scope/type constants
const RT_TABLE_MAIN* = uint8(254)
const RTPROT_STATIC* = uint8(4)
const RTPROT_NOPAL* = uint8(99)
const RT_SCOPE_UNIVERSE* = uint8(0)
const RT_SCOPE_LINK* = uint8(253)
const RTN_UNICAST* = uint8(1)
const RTN_UNREACHABLE* = uint8(7)
const RTN_BLACKHOLE* = uint8(6)

# Routing rule attributes (FRA_*)
const FRA_PRIORITY* = cushort(6)
const FRA_FWMARK* = cushort(10)
const FRA_FWMASK* = cushort(16)
const FRA_TABLE* = cushort(15)
const FRA_SRC* = cushort(2)

# ICMP types
const ICMP_ECHO_REQUEST* = uint8(8)
const ICMP_ECHO_REPLY* = uint8(0)
const ICMPV6_ECHO_REQUEST* = uint8(128)
const ICMPV6_ECHO_REPLY* = uint8(129)

# ARP operations
const ARPOP_REQUEST* = uint16(1)
const ARPOP_REPLY* = uint16(2)

# Socket/IP options not in Nim posix
const IP_TTL* = cint(2)
const IPV6_UNICAST_HOPS* = cint(16)
const MSG_NOSIGNAL* = cint(0x4000)
const MSG_TRUNC* = cint(0x20)

# Poll events
const POLLOUT* = cshort(0x04)
const POLLERR* = cshort(0x08)
const POLLHUP* = cshort(0x10)

# Probe identification mark
const PROBE_MARK* = uint32(0xDEAD)
