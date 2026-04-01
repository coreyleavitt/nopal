## ARP health probe socket.
##
## Sends ARP requests to a configured gateway target and checks for ARP
## replies. Useful for detecting local gateway failures without requiring
## internet reachability. ARP operates at layer 2 and is IPv4-only.
##
## The socket uses AF_PACKET with SOCK_DGRAM (kernel handles Ethernet
## framing). Like other probe types, it is bound to a specific interface.

import std/[posix, os]
import ../linux_constants

const
  ARPHRD_ETHER = 1'u16
  ARP_PKT_LEN = 28
  IFNAMSIZ = 16

type
  ArpProbeState* = object
    ifindex*: cint
    senderMac*: array[6, byte]
    senderIp*: array[4, byte]

  SockaddrLl {.importc: "struct sockaddr_ll", header: "<linux/if_packet.h>".} = object
    sll_family: uint16
    sll_protocol: uint16
    sll_ifindex: cint
    sll_hatype: uint16
    sll_pkttype: uint8
    sll_halen: uint8
    sll_addr: array[8, byte]

  Ifreq {.importc: "struct ifreq", header: "<net/if.h>".} = object
    ifr_name: array[IFNAMSIZ, char]
    ifr_data: array[24, byte]  # union of various fields

proc ioctl(fd: cint, request: culong, arg: pointer): cint
  {.importc, header: "<sys/ioctl.h>".}

proc createArpSocket*(device: string): tuple[fd: cint, state: ArpProbeState] =
  ## Create an AF_PACKET ARP socket bound to `device`.
  ## Returns the fd and an ArpProbeState populated with interface info.
  assert device.len < IFNAMSIZ, "device name too long: " & device

  # Create AF_PACKET socket for ARP
  let proto = htons(ETH_P_ARP).cint
  let fd = cint(socket(linux_constants.AF_PACKET.cint, SOCK_DGRAM.cint, proto))
  if fd < 0:
    raiseOSError(osLastError())

  # Open a temp AF_INET socket for ioctl queries
  let inetFd = cint(socket(AF_INET.cint, SOCK_DGRAM.cint, 0))
  if inetFd < 0:
    discard close(fd)
    raiseOSError(osLastError())

  var state: ArpProbeState

  # Prepare ifreq with device name
  var ifr: Ifreq
  for i in 0 ..< device.len:
    ifr.ifr_name[i] = device[i]

  # SIOCGIFINDEX -- get interface index
  if ioctl(inetFd, SIOCGIFINDEX, addr ifr) < 0:
    discard close(inetFd)
    discard close(fd)
    raiseOSError(osLastError())
  copyMem(addr state.ifindex, addr ifr.ifr_data[0], sizeof(cint))

  # SIOCGIFHWADDR -- get MAC address
  # Reset ifr_data, keep name
  for i in 0 ..< ifr.ifr_data.len:
    ifr.ifr_data[i] = 0
  if ioctl(inetFd, SIOCGIFHWADDR, addr ifr) < 0:
    discard close(inetFd)
    discard close(fd)
    raiseOSError(osLastError())
  # MAC is at offset 2 in ifr_data (sa_data within sockaddr)
  copyMem(addr state.senderMac[0], addr ifr.ifr_data[2], 6)

  # SIOCGIFADDR -- get IPv4 address
  for i in 0 ..< ifr.ifr_data.len:
    ifr.ifr_data[i] = 0
  if ioctl(inetFd, SIOCGIFADDR, addr ifr) < 0:
    # No address assigned -- use 0.0.0.0
    state.senderIp = [0'u8, 0, 0, 0]
  else:
    # IPv4 address is at offset 4 in ifr_data (sin_addr within sockaddr_in)
    copyMem(addr state.senderIp[0], addr ifr.ifr_data[4], 4)

  discard close(inetFd)

  # SO_MARK
  var mark = PROBE_MARK
  if setsockopt(SocketHandle(fd), SOL_SOCKET.cint, linux_constants.SO_MARK.cint,
                addr mark, sizeof(mark).SockLen) < 0:
    discard close(fd)
    raiseOSError(osLastError())

  # Bind to interface via sockaddr_ll
  var sll: SockaddrLl
  sll.sll_family = linux_constants.AF_PACKET.uint16
  sll.sll_protocol = htons(ETH_P_ARP)
  sll.sll_ifindex = state.ifindex
  if bindSocket(SocketHandle(fd), cast[ptr SockAddr](addr sll),
                sizeof(SockaddrLl).SockLen) < 0:
    discard close(fd)
    raiseOSError(osLastError())

  # Set non-blocking
  let flags = fcntl(fd, F_GETFL)
  if flags < 0:
    discard close(fd)
    raiseOSError(osLastError())
  if fcntl(fd, F_SETFL, flags or O_NONBLOCK) < 0:
    discard close(fd)
    raiseOSError(osLastError())

  result = (fd: fd, state: state)

proc buildArpRequest*(pkt: var ArpPacket, state: ArpProbeState,
                      targetIp: array[4, byte]) =
  ## Fill an ArpPacket with a request for targetIp.
  ## All values in network byte order (big-endian).
  pkt.hwType = htons(ARPHRD_ETHER)
  pkt.protoType = htons(0x0800'u16)
  pkt.hwLen = 6
  pkt.protoLen = 4
  pkt.operation = htons(ARPOP_REQUEST)
  pkt.senderMac = state.senderMac
  pkt.senderIp = state.senderIp
  # Target MAC: zeros (who-has query)
  pkt.targetMac = [0'u8, 0, 0, 0, 0, 0]
  pkt.targetIp = targetIp

proc sendArpProbe*(fd: cint, pkt: ArpPacket, ifindex: cint): bool =
  ## Send an ARP request via sockaddr_ll with broadcast MAC.
  ## Returns true on success.
  var dst: SockaddrLl
  dst.sll_family = linux_constants.AF_PACKET.uint16
  dst.sll_protocol = htons(ETH_P_ARP)
  dst.sll_ifindex = ifindex
  dst.sll_halen = 6
  dst.sll_addr[0] = 0xFF
  dst.sll_addr[1] = 0xFF
  dst.sll_addr[2] = 0xFF
  dst.sll_addr[3] = 0xFF
  dst.sll_addr[4] = 0xFF
  dst.sll_addr[5] = 0xFF

  let ret = sendto(SocketHandle(fd), cast[pointer](unsafeAddr pkt), sizeof(ArpPacket), 0'i32,
                   cast[ptr SockAddr](addr dst),
                   sizeof(SockaddrLl).SockLen)
  result = ret >= 0

proc recvArpReply*(fd: cint, buf: var array[64, byte],
                   targetIp: array[4, byte]): bool =
  ## Non-blocking receive of an ARP reply.
  ## Returns true if the reply is ARPOP_REPLY from the expected target IP.
  let n = recv(SocketHandle(fd), cast[pointer](addr buf[0]), buf.len, 0)
  if n < ARP_PKT_LEN:
    return false

  # Check operation is ARP reply (bytes 6-7, big-endian)
  let op = (uint16(buf[6]) shl 8) or uint16(buf[7])
  if op != ARPOP_REPLY:
    return false

  # Sender protocol address (bytes 14-17) must match our target
  result = buf[14] == targetIp[0] and buf[15] == targetIp[1] and
           buf[16] == targetIp[2] and buf[17] == targetIp[3]
