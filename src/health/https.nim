## HTTPS health probe socket.
##
## Sends HTTPS HEAD requests to configured targets and checks for valid
## HTTP responses over TLS. Uses nim-mbedtls for the TLS layer, dynamically
## linking against system mbedTLS (zero binary size cost on OpenWrt).
##
## Like HTTP probes, HTTPS probes create a new connection per probe and
## do not register with the selector. Connection state is advanced via
## polling in checkHttpsResponse (called from the probe engine).
##
## Compile with -d:https to enable.

when defined(https):
  import std/[posix, os, logging]
  import ../linux_constants

  # Import nim-mbedtls
  import mbedtls

  const
    HttpsPort* = 443'u16
    HttpsRequest = "HEAD / HTTP/1.0\r\nHost: health-check\r\nConnection: close\r\n\r\n"
    SockNonblock = 0x800.cint
    SockCloexec = 0x80000.cint

  type
    HttpsPhase* = enum
      hpTcpConnecting
      hpTlsHandshaking
      hpSendingRequest
      hpWaitingResponse

    HttpsConn = object
      fd: cint
      tls: TlsContext
      phase: HttpsPhase
      seqNum: uint16

    HttpsProbeState* = object
      device*: string
      port*: uint16
      conn: Option[HttpsConn]

  proc createHttpsProbeState*(device: string, port: uint16 = HttpsPort): HttpsProbeState =
    HttpsProbeState(device: device, port: port, conn: none(HttpsConn))

  proc configureSocket(fd: cint, device: string) =
    ## Apply SO_MARK and SO_BINDTODEVICE to a TCP socket.
    var mark = PROBE_MARK
    if setsockopt(SocketHandle(fd), SOL_SOCKET, linux_constants.SO_MARK,
                  addr mark, sizeof(mark).SockLen) < 0:
      raiseOSError(osLastError())

    if device.len > 0:
      if setsockopt(SocketHandle(fd), SOL_SOCKET, linux_constants.SO_BINDTODEVICE,
                    cstring(device), device.len.SockLen) < 0:
        raiseOSError(osLastError())

  proc isConnected(fd: cint): bool =
    ## Check if a non-blocking TCP connect has completed.
    var pfd: Pollfd
    pfd.fd = fd
    pfd.events = linux_constants.POLLOUT
    pfd.revents = 0

    if poll(addr pfd, 1, 0) <= 0:
      return false
    if (pfd.revents.cshort and (linux_constants.POLLERR or linux_constants.POLLHUP)) != 0:
      return false

    var err: cint = 0
    var errLen = sizeof(err).SockLen
    if getsockopt(SocketHandle(fd), SOL_SOCKET, SO_ERROR,
                  addr err, addr errLen) != 0:
      return false
    err == 0

  proc startHttpsConnect*(state: var HttpsProbeState, target: openArray[byte],
                          family: uint8, seqNum: uint16): bool =
    ## Create TCP socket, start non-blocking connect, initialize TLS context.
    ## Returns true on success (EINPROGRESS is expected).

    # Close any existing connection
    if state.conn.isSome:
      let conn = state.conn.get
      discard posix.close(conn.fd)
      state.conn = none(HttpsConn)

    let af = if family == 2: AF_INET.cint else: AF_INET6.cint
    let fd = cint(socket(af, SOCK_STREAM.cint or SockNonblock or SockCloexec, 0))
    if fd < 0:
      return false

    try:
      configureSocket(fd, state.device)
    except:
      discard posix.close(fd)
      return false

    # Build sockaddr and connect
    var ret: cint
    if family == 2:  # AF_INET
      var sa: Sockaddr_in
      sa.sin_family = AF_INET.TSa_Family
      sa.sin_port = htons(state.port)
      copyMem(addr sa.sin_addr, unsafeAddr target[0], 4)
      ret = connect(SocketHandle(fd), cast[ptr SockAddr](addr sa), sizeof(sa).SockLen)
    else:  # AF_INET6
      var sa: Sockaddr_in6
      sa.sin6_family = AF_INET6.TSa_Family
      sa.sin6_port = htons(state.port)
      copyMem(addr sa.sin6_addr, unsafeAddr target[0], 16)
      ret = connect(SocketHandle(fd), cast[ptr SockAddr](addr sa), sizeof(sa).SockLen)

    if ret < 0 and errno != EINPROGRESS:
      discard posix.close(fd)
      return false

    # Initialize TLS context (handshake happens after TCP connect completes)
    var tlsCtx: TlsContext
    try:
      tlsCtx = newTlsContext()
    except:
      discard posix.close(fd)
      return false

    state.conn = some(HttpsConn(
      fd: fd,
      tls: tlsCtx,
      phase: hpTcpConnecting,
      seqNum: seqNum,
    ))
    true

  proc checkHttpsResponse*(state: var HttpsProbeState, probeId: uint16): tuple[ok: bool, seqNum, id: uint16] =
    ## Drive the HTTPS state machine forward. Returns (true, seq, id) when
    ## a valid 2xx HTTP response is received over TLS.
    result = (ok: false, seqNum: 0'u16, id: 0'u16)

    if state.conn.isNone:
      return

    var conn = state.conn.get

    case conn.phase
    of hpTcpConnecting:
      if not isConnected(conn.fd):
        return
      # TCP connected — start TLS handshake
      try:
        conn.tls.connect("health-check", state.port)
      except:
        debug "HTTPS probe TLS setup error"
        discard posix.close(conn.fd)
        state.conn = none(HttpsConn)
        return
      conn.phase = hpTlsHandshaking
      state.conn = some(conn)

    of hpTlsHandshaking:
      # Attempt to complete TLS handshake (may need multiple calls for non-blocking)
      # For now, treat handshake as blocking since mbedTLS net_connect handles it
      conn.phase = hpSendingRequest
      state.conn = some(conn)

    of hpSendingRequest:
      # Send HTTP HEAD request over TLS
      try:
        let written = conn.tls.write(HttpsRequest)
        if written <= 0:
          discard posix.close(conn.fd)
          state.conn = none(HttpsConn)
          return
      except:
        debug "HTTPS probe write error"
        discard posix.close(conn.fd)
        state.conn = none(HttpsConn)
        return
      conn.phase = hpWaitingResponse
      state.conn = some(conn)

    of hpWaitingResponse:
      # Read HTTP response over TLS
      var buf: array[64, byte]
      try:
        let response = conn.tls.read(64)
        if response.len >= 12 and response[0..4] == "HTTP/":
          let status0 = response[9]
          if status0 == '2':
            let seq = conn.seqNum
            discard posix.close(conn.fd)
            conn.tls.close()
            state.conn = none(HttpsConn)
            return (ok: true, seqNum: seq, id: probeId)
      except:
        debug "HTTPS probe read error"

      discard posix.close(conn.fd)
      state.conn = none(HttpsConn)

  proc closeHttpsConn*(state: var HttpsProbeState) =
    if state.conn.isSome:
      let conn = state.conn.get
      discard posix.close(conn.fd)
      state.conn = none(HttpsConn)
