## DNS health probe socket.
##
## Sends minimal DNS queries to configured DNS server targets over UDP
## port 53. Any valid DNS response with a matching transaction ID
## indicates the server is reachable.
##
## Like ICMP probes, DNS sockets are bound to a specific device via
## SO_BINDTODEVICE and marked with SO_MARK = 0xDEAD for nftables
## exemption.

import std/[posix, os]
import ../linux_constants

const DNS_PORT = 53'u16

proc encodeDnsQuery*(name: string, buf: var array[512, byte]): int =
  ## Encode a DNS A query. Returns bytes written.
  ##
  ## Layout:
  ##   - Header (12 bytes): txid=0, flags=0x0100 (standard query, RD=1), qdcount=1
  ##   - Question: label-encoded name + type A (0x0001) + class IN (0x0001)
  var pos = 0

  # Transaction ID (0 -- filled at send time)
  buf[0] = 0; buf[1] = 0
  pos = 2

  # Flags: standard query, recursion desired (0x0100)
  buf[2] = 0x01; buf[3] = 0x00
  pos = 4

  # QDCOUNT = 1
  buf[4] = 0x00; buf[5] = 0x01
  pos = 6

  # ANCOUNT, NSCOUNT, ARCOUNT = 0
  buf[6] = 0; buf[7] = 0   # ANCOUNT
  buf[8] = 0; buf[9] = 0   # NSCOUNT
  buf[10] = 0; buf[11] = 0 # ARCOUNT
  pos = 12

  # Question section: encode domain name as DNS labels
  # Trim leading and trailing dots (inline to avoid std/strutils dependency)
  var trimStart = 0
  var trimEnd = name.len - 1
  while trimStart <= trimEnd and name[trimStart] == '.': inc trimStart
  while trimEnd >= trimStart and name[trimEnd] == '.': dec trimEnd
  let trimmed = if trimStart > trimEnd: "" else: name[trimStart .. trimEnd]
  if trimmed.len == 0:
    # Root query: single null byte
    buf[pos] = 0x00
    pos += 1
  else:
    # Split on '.' and encode each label (with bounds checking)
    var start = 0
    while start <= trimmed.len:
      var dotPos = trimmed.len
      for i in start ..< trimmed.len:
        if trimmed[i] == '.':
          dotPos = i
          break
      let labelLen = dotPos - start
      let writeLen = min(labelLen, 63)
      # Bounds check: need 1 (length byte) + writeLen + 1 (null term) + 4 (type+class)
      if pos + 1 + writeLen + 1 + 4 > buf.len:
        break  # truncate — name too long for buffer
      buf[pos] = uint8(writeLen)
      pos += 1
      for i in 0 ..< writeLen:
        buf[pos] = uint8(trimmed[start + i])
        pos += 1
      start = dotPos + 1
    # Terminating root label
    if pos < buf.len:
      buf[pos] = 0x00
      pos += 1

  # Type A (0x0001) + Class IN (0x0001)
  if pos + 4 <= buf.len:
    buf[pos] = 0x00; buf[pos + 1] = 0x01
    pos += 2
    buf[pos] = 0x00; buf[pos + 1] = 0x01
    pos += 2

  result = pos

proc createDnsSocket*(device: string, family: uint8): cint =
  ## Create a UDP socket for DNS probes.
  ## `family` is AF_INET or AF_INET6. Returns raw fd.
  let af = if family == AF_INET.uint8: AF_INET.cint else: AF_INET6.cint

  result = cint(socket(af, SOCK_DGRAM.cint, 0))
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

  # Set non-blocking
  let flags = fcntl(fd, F_GETFL)
  if flags < 0:
    discard close(fd)
    raiseOSError(osLastError())
  if fcntl(fd, F_SETFL, flags or O_NONBLOCK) < 0:
    discard close(fd)
    raiseOSError(osLastError())

proc sendDnsProbe*(fd: cint, target: openArray[byte], family: uint8,
                   txid: uint16, queryBuf: var openArray[byte],
                   queryLen: int): bool =
  ## Stamp txid into bytes 0-1 of query, sendto() to port 53.
  ## Returns true on success.
  queryBuf[0] = uint8(txid shr 8)
  queryBuf[1] = uint8(txid and 0xFF)

  if family == AF_INET.uint8:
    var sa: Sockaddr_in
    sa.sin_family = AF_INET.TSa_Family
    sa.sin_port = htons(DNS_PORT)
    copyMem(addr sa.sin_addr, unsafeAddr target[0], 4)
    let ret = sendto(SocketHandle(fd), cast[pointer](addr queryBuf[0]), queryLen, 0'i32,
                     cast[ptr SockAddr](addr sa),
                     sizeof(Sockaddr_in).SockLen)
    result = ret >= 0
  else:
    var sa: Sockaddr_in6
    sa.sin6_family = AF_INET6.TSa_Family
    sa.sin6_port = htons(DNS_PORT)
    copyMem(addr sa.sin6_addr, unsafeAddr target[0], 16)
    let ret = sendto(SocketHandle(fd), cast[pointer](addr queryBuf[0]), queryLen, 0'i32,
                     cast[ptr SockAddr](addr sa),
                     sizeof(Sockaddr_in6).SockLen)
    result = ret >= 0

proc recvDnsReply*(fd: cint, buf: var array[512, byte]): tuple[ok: bool, txid: uint16] =
  ## Non-blocking receive of a DNS response.
  ## Checks QR bit (byte 2, bit 7), extracts txid from bytes 0-1.
  result = (ok: false, txid: 0'u16)

  let n = recv(SocketHandle(fd), cast[pointer](addr buf[0]), buf.len, 0)
  if n < 12:
    return  # DNS header is 12 bytes minimum

  # Check QR bit (bit 7 of byte 2) -- must be 1 (response)
  if (buf[2] and 0x80) == 0:
    return

  let txid = (uint16(buf[0]) shl 8) or uint16(buf[1])
  result = (ok: true, txid: txid)

when isMainModule:
  # Tests for encodeDnsQuery

  block testGoogleCom:
    ## "google.com" produces correct label sequence.
    var buf: array[512, byte]
    let n = encodeDnsQuery("google.com", buf)

    # Header: txid=0, flags=0x0100, qdcount=1
    doAssert buf[0] == 0 and buf[1] == 0, "txid should be 0"
    doAssert buf[2] == 0x01 and buf[3] == 0x00, "flags should be 0x0100"
    doAssert buf[4] == 0x00 and buf[5] == 0x01, "qdcount should be 1"

    # Question starts at byte 12
    # "google" label: length 6
    doAssert buf[12] == 6, "google label length"
    doAssert buf[13] == uint8('g')
    doAssert buf[14] == uint8('o')
    doAssert buf[15] == uint8('o')
    doAssert buf[16] == uint8('g')
    doAssert buf[17] == uint8('l')
    doAssert buf[18] == uint8('e')

    # "com" label: length 3
    doAssert buf[19] == 3, "com label length"
    doAssert buf[20] == uint8('c')
    doAssert buf[21] == uint8('o')
    doAssert buf[22] == uint8('m')

    # Root terminator
    doAssert buf[23] == 0x00, "root terminator"

    # Type A
    doAssert buf[24] == 0x00 and buf[25] == 0x01, "type A"

    # Class IN
    doAssert buf[26] == 0x00 and buf[27] == 0x01, "class IN"

    # Total: 12 header + 1+6 + 1+3 + 1 + 2+2 = 28
    doAssert n == 28, "total length for google.com should be 28"

  block testRootQuery:
    ## Root query "." produces single null byte after header.
    var buf: array[512, byte]
    let n = encodeDnsQuery(".", buf)

    # Root label (single null byte)
    doAssert buf[12] == 0x00, "root label should be null"

    # Type A
    doAssert buf[13] == 0x00 and buf[14] == 0x01, "type A"

    # Class IN
    doAssert buf[15] == 0x00 and buf[16] == 0x01, "class IN"

    # Total: 12 + 1 + 2 + 2 = 17
    doAssert n == 17, "total length for root query should be 17"

  block testTrailingDot:
    ## Name with trailing dot "example.com." works correctly.
    var buf1: array[512, byte]
    var buf2: array[512, byte]
    let n1 = encodeDnsQuery("example.com.", buf1)
    let n2 = encodeDnsQuery("example.com", buf2)

    # Trailing dot should be stripped, producing identical output
    doAssert n1 == n2, "trailing dot should not change length"
    for i in 12 ..< n1:
      doAssert buf1[i] == buf2[i],
        fmt"trailing dot: byte {i} differs"

  echo "All encodeDnsQuery tests passed."
