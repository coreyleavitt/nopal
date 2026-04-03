## ICMP health probe socket.
##
## Sends ICMP echo requests to configured targets and checks for valid
## echo replies. Uses SOCK_DGRAM for unprivileged ICMP (kernel handles
## the IP header). Each socket is bound to a device via SO_BINDTODEVICE
## and marked with SO_MARK so nftables rules can identify and skip probe
## packets.

import std/[posix, os]
import ../linux_constants

# Protocol numbers not in Nim's posix module
const
  IPPROTO_ICMP = 1.cint
  IPPROTO_ICMPV6 = 58.cint

func icmpChecksum*(data: openArray[byte]): uint16 =
  ## RFC 1071 ones-complement checksum.
  ## Sum all 16-bit words (big-endian), fold carry into lower 16 bits, invert.
  var sum: uint32 = 0
  var i = 0

  # Sum 16-bit words
  while i + 1 < data.len:
    sum += (uint32(data[i]) shl 8) or uint32(data[i + 1])
    i += 2

  # Handle trailing odd byte
  if i < data.len:
    sum += uint32(data[i]) shl 8

  # Fold 32-bit sum into 16 bits
  while (sum shr 16) != 0:
    sum = (sum and 0xFFFF) + (sum shr 16)

  result = not uint16(sum)

proc createIcmpSocket*(device: string, family: uint8, ttl: int): cint =
  ## Create an ICMP socket bound to `device`.
  ## `family` is AF_INET or AF_INET6. Returns raw fd.
  let af = if family == AF_INET.uint8: AF_INET.cint else: AF_INET6.cint
  let proto = if family == AF_INET.uint8: IPPROTO_ICMP else: IPPROTO_ICMPV6

  result = cint(socket(af, SOCK_RAW.cint, proto))
  if result < 0:
    raiseOSError(osLastError())

  let fd = result

  # SO_MARK
  var mark = PROBE_MARK
  if setsockopt(SocketHandle(fd), SOL_SOCKET.cint, linux_constants.SO_MARK.cint,
                addr mark, sizeof(mark).SockLen) < 0:
    discard close(fd)
    raiseOSError(osLastError())

  # SO_BINDTODEVICE
  if setsockopt(SocketHandle(fd), SOL_SOCKET.cint, linux_constants.SO_BINDTODEVICE.cint,
                cstring(device), device.len.SockLen) < 0:
    discard close(fd)
    raiseOSError(osLastError())

  # IP_TTL or IPV6_UNICAST_HOPS
  var ttlVal = ttl.cint
  if family == AF_INET.uint8:
    if setsockopt(SocketHandle(fd), IPPROTO_IP.cint, linux_constants.IP_TTL.cint,
                  addr ttlVal, sizeof(ttlVal).SockLen) < 0:
      discard close(fd)
      raiseOSError(osLastError())
  else:
    if setsockopt(SocketHandle(fd), IPPROTO_IPV6.cint, linux_constants.IPV6_UNICAST_HOPS.cint,
                  addr ttlVal, sizeof(ttlVal).SockLen) < 0:
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

proc buildIcmpPacket*(buf: var array[1500, byte], typ, code: uint8,
                      id, seq: uint16, payloadSize: int): int =
  ## Build an ICMP echo request packet in `buf`.
  ## Returns total packet length.
  let payloadLen = max(payloadSize, 8)
  let totalLen = 8 + payloadLen  # 8-byte ICMP header + payload

  # Zero the packet buffer
  zeroMem(addr buf[0], totalLen)

  # Fill IcmpEchoHdr fields
  buf[0] = typ         # type
  buf[1] = code        # code
  buf[2] = 0           # checksum high (zeroed for calculation)
  buf[3] = 0           # checksum low
  buf[4] = uint8(id shr 8)     # identifier high (network byte order)
  buf[5] = uint8(id and 0xFF)  # identifier low
  buf[6] = uint8(seq shr 8)    # sequence high (network byte order)
  buf[7] = uint8(seq and 0xFF) # sequence low

  # Payload: fill with "nopalprb" repeating pattern
  const pattern = [0x6E'u8, 0x6F, 0x70, 0x61, 0x6C, 0x70, 0x72, 0x62] # "nopalprb"
  for i in 0 ..< payloadLen:
    buf[8 + i] = pattern[i mod pattern.len]

  # Compute checksum for IPv4 (skip for IPv6 -- kernel handles pseudo-header)
  if typ == ICMP_ECHO_REQUEST:
    let cksum = icmpChecksum(buf.toOpenArray(0, totalLen - 1))
    buf[2] = uint8(cksum shr 8)
    buf[3] = uint8(cksum and 0xFF)

  result = totalLen

proc sendIcmpProbe*(fd: cint, target: openArray[byte], family: uint8,
                    buf: openArray[byte], len: int): bool =
  ## Send an ICMP echo request to `target`. Returns true on success.
  if family == AF_INET.uint8:
    var sa: Sockaddr_in
    sa.sin_family = AF_INET.TSa_Family
    copyMem(addr sa.sin_addr, unsafeAddr target[0], 4)
    let ret = sendto(SocketHandle(fd), cast[pointer](unsafeAddr buf[0]), len, 0'i32,
                     cast[ptr SockAddr](addr sa),
                     sizeof(Sockaddr_in).SockLen)
    result = ret >= 0
  else:
    var sa: Sockaddr_in6
    sa.sin6_family = AF_INET6.TSa_Family
    copyMem(addr sa.sin6_addr, unsafeAddr target[0], 16)
    let ret = sendto(SocketHandle(fd), cast[pointer](unsafeAddr buf[0]), len, 0'i32,
                     cast[ptr SockAddr](addr sa),
                     sizeof(Sockaddr_in6).SockLen)
    result = ret >= 0

proc recvIcmpReply*(fd: cint, buf: var array[1500, byte]): tuple[ok: bool, id, seq: uint16] =
  ## Non-blocking receive of an ICMP echo reply.
  ## Returns (ok, id, seq). ok is false if no valid reply available.
  ## For SOCK_RAW IPv4, the kernel includes the 20-byte IP header.
  ## For SOCK_RAW IPv6, the kernel strips the IP header.
  result = (ok: false, id: 0'u16, seq: 0'u16)

  let n = recv(SocketHandle(fd), cast[pointer](addr buf[0]), buf.len, 0)
  if n < 28:  # min: 20 IP header + 8 ICMP header
    return

  # IPv4 SOCK_RAW: skip the IP header (IHL field gives length in 32-bit words)
  let ihl = int(buf[0] and 0x0F) * 4
  if ihl < 20 or ihl + 8 > n:
    return

  let icmpOff = ihl
  let replyType = buf[icmpOff]
  if replyType != ICMP_ECHO_REPLY and replyType != ICMPV6_ECHO_REPLY:
    return

  let id = (uint16(buf[icmpOff + 4]) shl 8) or uint16(buf[icmpOff + 5])
  let seq = (uint16(buf[icmpOff + 6]) shl 8) or uint16(buf[icmpOff + 7])
  result = (ok: true, id: id, seq: seq)

when isMainModule:
  import std/unittest

  suite "ICMP checksum":
    test "all-zero buffer produces 0xFFFF":
      var data: array[16, byte]
      check icmpChecksum(data) == 0xFFFF'u16

    test "known payload produces non-zero checksum":
      let data = [0x6E'u8, 0x6F, 0x70, 0x61, 0x6C, 0x70, 0x72, 0x62]
      let cksum = icmpChecksum(data)
      check cksum != 0
      var withCksum: array[10, byte]
      for i in 0 ..< 8:
        withCksum[i] = data[i]
      withCksum[8] = uint8(cksum shr 8)
      withCksum[9] = uint8(cksum and 0xFF)
      check icmpChecksum(withCksum) == 0

    test "odd-length payload":
      let data = [byte 0xAA, 0xBB, 0xCC]
      check icmpChecksum(data) != 0

    test "ICMP echo request validation property":
      var pkt: array[16, byte]
      pkt[0] = ICMP_ECHO_REQUEST
      pkt[1] = 0
      pkt[4] = 0; pkt[5] = 1
      pkt[6] = 0; pkt[7] = 1
      let pattern = [0x6E'u8, 0x6F, 0x70, 0x61, 0x6C, 0x70, 0x72, 0x62]
      for i in 0 ..< 8:
        pkt[8 + i] = pattern[i]
      let cksum = icmpChecksum(pkt)
      pkt[2] = uint8(cksum shr 8)
      pkt[3] = uint8(cksum and 0xFF)
      check icmpChecksum(pkt) == 0
