## IPC request/response types (JSON over Unix socket).

import std/json

type
  IpcRequest* = object
    id*: uint64
    `method`*: string
    params*: JsonNode

  IpcResponse* = object
    id*: uint64
    success*: bool
    error*: string
    data*: JsonNode
