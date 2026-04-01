## HTTP health probe socket.
##
## Sends HTTP HEAD requests to configured targets and checks for valid
## HTTP responses. Each probe creates a new non-blocking TCP connection
## to the target on port 80.
##
## Unlike ICMP and DNS probes which use persistent sockets, HTTP probes
## create a new TCP connection per probe.

import std/[posix, os]
import ../linux_constants

const
  HTTP_PORT = 80'u16
  HTTP_REQUEST = "HEAD / HTTP/1.0\r\nHost: health-check\r\nConnection: close\r\n\r\n"
  linux_constants.MSG_NOSIGNAL = 0x4000.cint

type
  HttpProbeState* = enum
    hpsIdle
    hpsConnecting
    hpsSent

proc createHttpSocket*(device: string, family: uint8): cint =
  ## Create a non-blocking TCP socket for HTTP probes.
  ## `family` is AF_INET or AF_INET6. Returns raw fd.
  let af = if family == AF_INET.uint8: AF_INET.cint else: AF_INET6.cint

  # SOCK_STREAM | SOCK_NONBLOCK | SOCK_CLOEXEC
  result = cint(socket(af, SOCK_STREAM.cint or SOCK_NONBLOCK.cint or SOCK_CLOEXEC.cint, 0))
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

proc startHttpConnect*(fd: cint, target: openArray[byte], family: uint8,
                       port: uint16): bool =
  ## Initiate a non-blocking TCP connect to target:port.
  ## Returns true if connect started (EINPROGRESS is expected success).
  if family == AF_INET.uint8:
    var sa: Sockaddr_in
    sa.sin_family = AF_INET.TSa_Family
    sa.sin_port = htons(port)
    copyMem(addr sa.sin_addr, unsafeAddr target[0], 4)
    let ret = connect(fd, cast[ptr SockAddr](addr sa),
                      sizeof(Sockaddr_in).SockLen)
    if ret == 0:
      return true
    let err = errno
    if err == EINPROGRESS:
      return true
    return false
  else:
    var sa: Sockaddr_in6
    sa.sin6_family = AF_INET6.TSa_Family
    sa.sin6_port = htons(port)
    copyMem(addr sa.sin6_addr, unsafeAddr target[0], 16)
    let ret = connect(fd, cast[ptr SockAddr](addr sa),
                      sizeof(Sockaddr_in6).SockLen)
    if ret == 0:
      return true
    let err = errno
    if err == EINPROGRESS:
      return true
    return false

proc checkHttpConnect*(fd: cint): bool =
  ## Zero-timeout poll to check if TCP connect completed successfully.
  ## Returns true if connected with no socket error.
  var pfd: TPollfd
  pfd.fd = fd
  pfd.events = POLLOUT.cshort
  pfd.revents = 0

  let ret = poll(addr pfd, 1, 0)
  if ret <= 0:
    return false

  if (pfd.revents.cint and (POLLERR.cint or POLLHUP.cint)) != 0:
    return false

  # Verify no error on the socket via getsockopt(SO_ERROR)
  var sockErr: cint = 0
  var errLen: SockLen = sizeof(sockErr).SockLen
  let gret = getsockopt(SocketHandle(fd), SOL_SOCKET.cint, SO_ERROR.cint,
                         addr sockErr, addr errLen)
  result = gret == 0 and sockErr == 0

proc sendHttpHead*(fd: cint): bool =
  ## Send the HTTP HEAD request. Returns true on success.
  let ret = send(fd, cstring(HTTP_REQUEST), HTTP_REQUEST.len.cint, linux_constants.MSG_NOSIGNAL)
  result = ret >= 0

proc recvHttpResponse*(fd: cint, buf: var array[512, byte]): bool =
  ## Non-blocking receive of HTTP response.
  ## Returns true if response starts with "HTTP/" and status is 2xx.
  let n = recv(fd, addr buf[0], buf.len.cint, 0)
  if n < 12:
    return false

  # Check starts with "HTTP/"
  if buf[0] != uint8('H') or buf[1] != uint8('T') or
     buf[2] != uint8('T') or buf[3] != uint8('P') or
     buf[4] != uint8('/'):
    return false

  # Status code starts at byte 9: "HTTP/1.x NNN"
  # Check first digit is '2' for 2xx status
  result = buf[9] == uint8('2')
