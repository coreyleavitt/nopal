## IPC server: Unix socket at /var/run/nopal.sock with length-prefixed JSON framing.
##
## Non-blocking accept, read, write. Clients receive length-prefixed JSON
## frames (u32 BE prefix + payload). Supports event subscriptions.

import std/[posix, os, tables, logging, json, selectors, endians]
import ./protocol

const
  MaxClients* = 8
  IpcClientBase* = 1000

type
  ClientConn = object
    fd: cint
    readBuf: seq[byte]
    subscribed: bool

  IpcServer* = object
    listenerFd*: cint
    socketPath: string
    clients*: Table[int, ClientConn]
    nextClientId: int

proc initIpcServer*(path: string, selector: Selector[int]): IpcServer =
  ## Create and bind the IPC Unix socket with restrictive permissions.
  result.socketPath = path
  result.clients = initTable[int, ClientConn]()
  result.nextClientId = 0

  # Remove stale socket (use lstat to avoid following symlinks)
  var st: Stat
  if lstat(cstring(path), st) == 0:
    if S_ISSOCK(st.st_mode):
      discard unlink(cstring(path))

  # Create socket with 0o600 permissions via umask
  let oldUmask = umask(0o177)
  result.listenerFd = cint(posix.socket(AF_UNIX.cint, SOCK_STREAM.cint or 0x80000, 0))  # SOCK_CLOEXEC
  if result.listenerFd < 0:
    discard umask(oldUmask)
    raiseOSError(osLastError())

  # Bind
  var sa: Sockaddr_un
  sa.sun_family = AF_UNIX.TSa_Family
  let pathBytes = path
  if pathBytes.len >= sizeof(sa.sun_path):
    discard posix.close(result.listenerFd)
    discard umask(oldUmask)
    raise newException(OSError, "IPC socket path too long")
  copyMem(addr sa.sun_path[0], unsafeAddr pathBytes[0], pathBytes.len)

  if bindSocket(SocketHandle(result.listenerFd), cast[ptr SockAddr](addr sa),
                SockLen(sizeof(sa))) < 0:
    discard posix.close(result.listenerFd)
    discard umask(oldUmask)
    raiseOSError(osLastError())

  discard umask(oldUmask)

  # Listen
  if listen(SocketHandle(result.listenerFd), 4) < 0:
    discard posix.close(result.listenerFd)
    raiseOSError(osLastError())

  # Set non-blocking
  let flags = fcntl(result.listenerFd, F_GETFL)
  discard fcntl(result.listenerFd, F_SETFL, flags or O_NONBLOCK)

  # Register with selector
  selector.registerHandle(result.listenerFd.int, {Event.Read}, 1)

proc acceptClient*(s: var IpcServer, selector: Selector[int]): int =
  ## Accept a new client. Returns client ID or -1 on EWOULDBLOCK/max clients.
  if s.clients.len >= MaxClients:
    return -1

  var clientAddr: Sockaddr_un
  var addrLen = SockLen(sizeof(clientAddr))
  let clientFd = cint(accept(SocketHandle(s.listenerFd),
                             cast[ptr SockAddr](addr clientAddr), addr addrLen))
  if clientFd < 0:
    return -1

  # Set non-blocking
  let flags = fcntl(clientFd, F_GETFL)
  discard fcntl(clientFd, F_SETFL, flags or O_NONBLOCK)

  let id = s.nextClientId
  s.nextClientId += 1

  s.clients[id] = ClientConn(fd: clientFd, readBuf: @[], subscribed: false)

  # Register with selector
  selector.registerHandle(clientFd.int, {Event.Read}, IpcClientBase + id)

  id

proc removeClient*(s: var IpcServer, clientId: int, selector: Selector[int])
  ## Forward declaration — defined below.

proc readClient*(s: var IpcServer, clientId: int, selector: Selector[int]): seq[IpcRequest] =
  ## Read and parse complete frames from a client. Returns parsed requests.
  ## On disconnect, removes client via removeClient (proper selector cleanup).
  result = @[]
  if clientId notin s.clients:
    return

  var buf: array[4096, byte]
  let client = addr s.clients[clientId]

  # Non-blocking read loop with per-client buffer budget
  while true:
    let n = posix.recv(SocketHandle(client.fd), cast[pointer](addr buf[0]), buf.len, 0)
    if n <= 0:
      if n == 0 or (n < 0 and errno != EAGAIN and errno != EWOULDBLOCK):
        s.removeClient(clientId, selector)
        return
      break  # EAGAIN
    # Budget check: cap readBuf to MaxMsgSize + 4 (one max frame)
    if client.readBuf.len + n > int(MaxMsgSize) + 4:
      warn "IPC client " & $clientId & " readbuf overflow, disconnecting"
      s.removeClient(clientId, selector)
      return
    for i in 0 ..< n:
      client.readBuf.add(buf[i])

  # Parse frames
  while client.readBuf.len >= 4:
    var frameLen: uint32
    bigEndian32(addr frameLen, addr client.readBuf[0])
    if frameLen > MaxMsgSize:
      warn "IPC client " & $clientId & " sent oversized message, disconnecting"
      s.removeClient(clientId, selector)
      return

    let totalLen = 4 + int(frameLen)
    if client.readBuf.len < totalLen:
      break  # Incomplete frame

    # Parse JSON payload
    try:
      var jsonStr = newString(int(frameLen))
      if frameLen > 0:
        copyMem(addr jsonStr[0], addr client.readBuf[4], int(frameLen))
      let j = parseJson(jsonStr)
      let req = parseRequest(j)
      if req.rpcMethod == "subscribe":
        client.subscribed = true
      result.add(req)
    except:
      warn "IPC client " & $clientId & " sent malformed JSON"

    # Remove consumed bytes
    client.readBuf = client.readBuf[totalLen .. ^1]

proc sendResponse*(s: var IpcServer, clientId: int, resp: IpcResponse,
                   selector: Selector[int]) =
  ## Send a framed response to a client.
  if clientId notin s.clients:
    return

  let jsonStr = $resp.toJson()
  let dataLen = uint32(jsonStr.len)
  if dataLen > MaxMsgSize:
    return

  var frame: seq[byte] = newSeqOfCap[byte](4 + jsonStr.len)
  var lenBE: uint32
  bigEndian32(addr lenBE, unsafeAddr dataLen)
  frame.setLen(4)
  copyMem(addr frame[0], addr lenBE, 4)
  for c in jsonStr:
    frame.add(byte(c))

  let client = addr s.clients[clientId]
  var sent = 0
  while sent < frame.len:
    let n = posix.send(SocketHandle(client.fd),
                       cast[pointer](addr frame[sent]),
                       frame.len - sent, 0x4000)  # MSG_NOSIGNAL
    if n <= 0:
      s.removeClient(clientId, selector)
      return
    sent += n

proc broadcastEvent*(s: var IpcServer, event: IpcResponse, selector: Selector[int]) =
  ## Send event to all subscribed clients.
  var ids: seq[int]
  for id, client in s.clients:
    if client.subscribed:
      ids.add(id)
  for id in ids:
    s.sendResponse(id, event, selector)

proc removeClient*(s: var IpcServer, clientId: int, selector: Selector[int]) =
  ## Deregister and close a client connection.
  if clientId in s.clients:
    let fd = s.clients[clientId].fd
    try: selector.unregister(fd.int)
    except: discard
    discard posix.close(fd)
    s.clients.del(clientId)

proc close*(s: var IpcServer) =
  ## Close the listener and all client connections.
  if s.listenerFd >= 0:
    discard posix.close(s.listenerFd)
    s.listenerFd = -1
  for id, client in s.clients:
    discard posix.close(client.fd)
  s.clients.clear()
  discard unlink(cstring(s.socketPath))
