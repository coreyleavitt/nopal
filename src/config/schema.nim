## Configuration schema types for nopal.
## Maps to UCI config sections in /etc/config/nopal.

type
  TrackMethod* = enum
    tmPing, tmDns, tmHttp, tmHttps, tmArping, tmComposite

  AddressFamily* = enum
    afIpv4, afIpv6, afBoth

  StickyMode* = enum
    smFlow, smSrcIp, smSrcDst

  ConntrackFlushMode* = enum
    cfmNone, cfmSelective, cfmFull

  ConntrackFlushTrigger* = enum
    cftIfUp, cftIfDown, cftConnected, cftDisconnected

  LastResort* = enum
    lrDefault, lrUnreachable, lrBlackhole

  RuleFamily* = enum
    rfAny, rfIpv4, rfIpv6

  InitialState* = enum
    isOffline, isOnline

  GlobalsConfig* = object
    markMask*: uint32
    conntrackFlushMode*: ConntrackFlushMode
    conntrackFlushTrigger*: seq[ConntrackFlushTrigger]

  InterfaceConfig* = object
    name*: string
    device*: string
    enabled*: bool
    family*: AddressFamily
    trackMethod*: TrackMethod
    trackIp*: seq[string]
    probeInterval*: uint32
    probeTimeout*: uint32
    failureInterval*: uint32
    recoveryInterval*: uint32
    upCount*: uint32
    downCount*: uint32
    initialState*: InitialState
    reliabilityThreshold*: uint32
    qualityWindowSize*: uint32
    latencyThreshold*: uint32
    lossThreshold*: uint32
    clampMss*: bool
    dampenHalflife*: uint32
    dampenCeiling*: uint32
    dampenSuppress*: uint32
    dampenReuse*: uint32

  MemberConfig* = object
    name*: string
    interface*: string
    policy*: string
    metric*: uint32
    weight*: uint32

  PolicyConfig* = object
    name*: string
    lastResort*: LastResort
    stickyMode*: StickyMode
    stickyTimeout*: uint32

  RuleConfig* = object
    name*: string
    policy*: string
    family*: RuleFamily
    proto*: string
    srcIp*: seq[string]
    destIp*: seq[string]
    srcPort*: string
    destPort*: string
    srcIface*: string
    log*: bool

  NopalConfig* = object
    globals*: GlobalsConfig
    interfaces*: seq[InterfaceConfig]
    members*: seq[MemberConfig]
    policies*: seq[PolicyConfig]
    rules*: seq[RuleConfig]
