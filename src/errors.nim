## Error types for nopal.

type
  NopalError* = object of CatchableError
  ConfigError* = object of NopalError
  NetlinkError* = object of NopalError
  NftablesError* = object of NopalError
  IpcError* = object of NopalError
  ProbeError* = object of NopalError
