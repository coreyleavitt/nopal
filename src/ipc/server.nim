## IPC server: Unix socket at /var/run/nopal.sock with length-prefixed JSON framing.

const
  SocketPath* = "/var/run/nopal.sock"
  MaxMessageSize* = 65536
  MaxClients* = 8

type
  IpcServer* = object
    fd*: cint
