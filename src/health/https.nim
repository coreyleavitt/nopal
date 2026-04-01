## HTTPS health probe socket (non-blocking TLS via low-level mbedtls API).
##
## Uses mbedtls_ssl_set_bio with custom send/recv callbacks on a non-blocking
## TCP socket. The TLS handshake is driven incrementally across event loop
## iterations, handling WANT_READ/WANT_WRITE as "try again later."
##
## Like HTTP probes, HTTPS probes create a new connection per probe and
## do not register with the selector. Connection state is advanced via
## polling in checkHttpsResponse.
##
## Compile with -d:https to enable. Requires nim-mbedtls package.

when defined(https):
  import std/[posix, os, logging]
  import ../linux_constants
  import mbedtls/[ssl, net, entropy, ctr_drbg, x509_crt]

  const
    HttpsPort* = 443'u16
    HttpsRequest = "HEAD / HTTP/1.0\r\nHost: health-check\r\nConnection: close\r\n\r\n"
    SockNonblockVal = 0x800.cint
    SockCloexecVal = 0x80000.cint
    CaPath = "/etc/ssl/certs"  # OpenWrt standard CA certificate path

  type
    HttpsPhase* = enum
      hpTcpConnecting, hpTlsHandshaking, hpSendingRequest, hpWaitingResponse

    HttpsConn* = object
      fd: cint
      sslCtx: ptr SslContext
      sslConf: ptr SslConfig
      entropyCtx: ptr EntropyContext
      ctrDrbgCtx: ptr CtrDrbgContext
      cacert: ptr X509Crt
      phase: HttpsPhase
      seqNum: uint16

    HttpsProbeState* = object
      device*: string
      port*: uint16
      conn*: ptr HttpsConn  ## nil when no active connection

  # ---------------------------------------------------------------
  # BIO callbacks for non-blocking I/O on our own fd
  # ---------------------------------------------------------------

  proc bioSend(ctx: pointer, buf: ptr byte, len: csize_t): cint {.cdecl.} =
    let fd = cast[cint](ctx)
    result = cint(posix.send(SocketHandle(fd), cast[pointer](buf), len.int,
                             linux_constants.MSG_NOSIGNAL))
    if result < 0:
      if errno == EAGAIN or errno == EWOULDBLOCK:
        return MBEDTLS_ERR_SSL_WANT_WRITE
      return -1

  proc bioRecv(ctx: pointer, buf: ptr byte, len: csize_t): cint {.cdecl.} =
    let fd = cast[cint](ctx)
    result = cint(posix.recv(SocketHandle(fd), cast[pointer](buf), len.int, 0))
    if result < 0:
      if errno == EAGAIN or errno == EWOULDBLOCK:
        return MBEDTLS_ERR_SSL_WANT_READ
      return -1

  # ---------------------------------------------------------------
  # Lifecycle
  # ---------------------------------------------------------------

  proc createHttpsProbeState*(device: string, port: uint16 = HttpsPort): HttpsProbeState =
    HttpsProbeState(device: device, port: port, conn: nil)

  proc freeConn(conn: ptr HttpsConn) =
    ## Free all heap-allocated mbedtls contexts and close the fd.
    if conn == nil: return
    if conn.sslCtx != nil:
      mbedtls_ssl_free(conn.sslCtx)
      dealloc(conn.sslCtx)
    if conn.sslConf != nil:
      mbedtls_ssl_config_free(conn.sslConf)
      dealloc(conn.sslConf)
    if conn.ctrDrbgCtx != nil:
      mbedtls_ctr_drbg_free(conn.ctrDrbgCtx)
      dealloc(conn.ctrDrbgCtx)
    if conn.entropyCtx != nil:
      mbedtls_entropy_free(conn.entropyCtx)
      dealloc(conn.entropyCtx)
    if conn.cacert != nil:
      mbedtls_x509_crt_free(conn.cacert)
      dealloc(conn.cacert)
    if conn.fd >= 0:
      discard posix.close(conn.fd)
    dealloc(conn)

  proc closeHttpsConn*(state: var HttpsProbeState) =
    if state.conn != nil:
      freeConn(state.conn)
      state.conn = nil

  proc configureSocket(fd: cint, device: string) =
    var mark = PROBE_MARK
    if setsockopt(SocketHandle(fd), SOL_SOCKET, linux_constants.SO_MARK,
                  addr mark, sizeof(mark).SockLen) < 0:
      raiseOSError(osLastError())
    if device.len > 0:
      if setsockopt(SocketHandle(fd), SOL_SOCKET, linux_constants.SO_BINDTODEVICE,
                    cstring(device), device.len.SockLen) < 0:
        raiseOSError(osLastError())

  proc isConnected(fd: cint): bool =
    var pfd: Pollfd
    pfd.fd = fd
    pfd.events = linux_constants.POLLOUT
    pfd.revents = 0
    if poll(addr pfd, 1, 0) <= 0: return false
    if (pfd.revents.cshort and (linux_constants.POLLERR or linux_constants.POLLHUP)) != 0:
      return false
    var err: cint = 0
    var errLen = sizeof(err).SockLen
    if getsockopt(SocketHandle(fd), SOL_SOCKET, SO_ERROR, addr err, addr errLen) != 0:
      return false
    err == 0

  proc startHttpsConnect*(state: var HttpsProbeState, target: openArray[byte],
                          family: uint8, seqNum: uint16,
                          targetIpStr: string): bool =
    ## Create TCP socket, start non-blocking connect, initialize TLS context.
    ## targetIpStr is the string representation of the target IP for SNI.
    state.closeHttpsConn()

    let af = if family == 2: AF_INET.cint else: AF_INET6.cint
    let fd = cint(socket(af, SOCK_STREAM.cint or SockNonblockVal or SockCloexecVal, 0))
    if fd < 0: return false

    try:
      configureSocket(fd, state.device)
    except:
      discard posix.close(fd)
      return false

    # Non-blocking TCP connect
    var ret: cint
    if family == 2:
      var sa: Sockaddr_in
      sa.sin_family = AF_INET.TSa_Family
      sa.sin_port = htons(state.port)
      copyMem(addr sa.sin_addr, unsafeAddr target[0], 4)
      ret = connect(SocketHandle(fd), cast[ptr SockAddr](addr sa), SockLen(sizeof(sa)))
    else:
      var sa: Sockaddr_in6
      sa.sin6_family = AF_INET6.TSa_Family
      sa.sin6_port = htons(state.port)
      copyMem(addr sa.sin6_addr, unsafeAddr target[0], 16)
      ret = connect(SocketHandle(fd), cast[ptr SockAddr](addr sa), SockLen(sizeof(sa)))

    if ret < 0 and errno != EINPROGRESS:
      discard posix.close(fd)
      return false

    # Allocate and initialize mbedtls contexts
    var conn = cast[ptr HttpsConn](alloc0(sizeof(HttpsConn)))
    conn.fd = fd
    conn.phase = hpTcpConnecting
    conn.seqNum = seqNum

    conn.entropyCtx = cast[ptr EntropyContext](alloc0(sizeof(EntropyContext)))
    mbedtls_entropy_init(conn.entropyCtx)

    conn.ctrDrbgCtx = cast[ptr CtrDrbgContext](alloc0(sizeof(CtrDrbgContext)))
    mbedtls_ctr_drbg_init(conn.ctrDrbgCtx)
    if mbedtls_ctr_drbg_seed(conn.ctrDrbgCtx, mbedtls_entropy_func,
                              conn.entropyCtx, nil, 0) != 0:
      freeConn(conn)
      return false

    conn.cacert = cast[ptr X509Crt](alloc0(sizeof(X509Crt)))
    mbedtls_x509_crt_init(conn.cacert)
    # Load system CA certificates (best effort — probe works without)
    discard mbedtls_x509_crt_parse_path(conn.cacert, cstring(CaPath))

    conn.sslConf = cast[ptr SslConfig](alloc0(sizeof(SslConfig)))
    mbedtls_ssl_config_init(conn.sslConf)
    if mbedtls_ssl_config_defaults(conn.sslConf,
                                    MBEDTLS_SSL_IS_CLIENT,
                                    MBEDTLS_SSL_TRANSPORT_STREAM,
                                    MBEDTLS_SSL_PRESET_DEFAULT) != 0:
      freeConn(conn)
      return false

    mbedtls_ssl_conf_authmode(conn.sslConf, MBEDTLS_SSL_VERIFY_OPTIONAL)
    mbedtls_ssl_conf_ca_chain(conn.sslConf, cast[pointer](conn.cacert), nil)
    mbedtls_ssl_conf_rng(conn.sslConf, cast[pointer](mbedtls_ctr_drbg_random),
                          cast[pointer](conn.ctrDrbgCtx))

    conn.sslCtx = cast[ptr SslContext](alloc0(sizeof(SslContext)))
    mbedtls_ssl_init(conn.sslCtx)
    if mbedtls_ssl_setup(conn.sslCtx, conn.sslConf) != 0:
      freeConn(conn)
      return false

    # Set SNI hostname (use target IP string for SAN validation)
    discard mbedtls_ssl_set_hostname(conn.sslCtx, cstring(targetIpStr))

    # Wire custom BIO callbacks — fd passed as context pointer
    mbedtls_ssl_set_bio(conn.sslCtx, cast[pointer](fd),
                         cast[pointer](bioSend), cast[pointer](bioRecv), nil)

    state.conn = conn
    true

  proc checkHttpsResponse*(state: var HttpsProbeState,
                           probeId: uint16): tuple[ok: bool, seqNum, id: uint16] =
    ## Drive the HTTPS state machine. Returns (true, seq, id) on valid 2xx response.
    result = (ok: false, seqNum: 0'u16, id: 0'u16)

    if state.conn == nil: return
    let conn = state.conn

    case conn.phase
    of hpTcpConnecting:
      if not isConnected(conn.fd):
        return
      conn.phase = hpTlsHandshaking

    of hpTlsHandshaking:
      let ret = mbedtls_ssl_handshake(conn.sslCtx)
      if ret == MBEDTLS_ERR_SSL_WANT_READ or ret == MBEDTLS_ERR_SSL_WANT_WRITE:
        return  # try again next poll
      if ret != 0:
        debug "HTTPS probe TLS handshake failed: " & $ret
        state.closeHttpsConn()
        return
      conn.phase = hpSendingRequest

    of hpSendingRequest:
      let reqBytes = HttpsRequest
      let ret = mbedtls_ssl_write(conn.sslCtx, cast[ptr byte](cstring(reqBytes)),
                                   csize_t(reqBytes.len))
      if ret == MBEDTLS_ERR_SSL_WANT_WRITE:
        return
      if ret < 0:
        debug "HTTPS probe write failed: " & $ret
        state.closeHttpsConn()
        return
      conn.phase = hpWaitingResponse

    of hpWaitingResponse:
      var buf: array[64, byte]
      let ret = mbedtls_ssl_read(conn.sslCtx, addr buf[0], csize_t(buf.len))
      if ret == MBEDTLS_ERR_SSL_WANT_READ:
        return
      if ret < 12:
        if ret == MBEDTLS_ERR_SSL_PEER_CLOSE_NOTIFY:
          debug "HTTPS probe: peer closed before response"
        elif ret < 0:
          debug "HTTPS probe read failed: " & $ret
        else:
          debug "HTTPS probe: response too short (" & $ret & " bytes)"
        state.closeHttpsConn()
        return

      # Validate HTTP response: "HTTP/x.x NNN"
      let n = ret
      if buf[0] == byte('H') and buf[1] == byte('T') and buf[2] == byte('T') and
         buf[3] == byte('P') and buf[4] == byte('/'):
        let s0 = char(buf[9])
        let s1 = char(buf[10])
        let s2 = char(buf[11])
        if s0 == '2' and s1 in {'0'..'9'} and s2 in {'0'..'9'}:
          let seq = conn.seqNum
          state.closeHttpsConn()
          return (ok: true, seqNum: seq, id: probeId)
        debug "HTTPS probe non-2xx status: " & s0 & s1 & s2

      state.closeHttpsConn()
