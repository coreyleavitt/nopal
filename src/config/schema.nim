## Configuration schema types for nopal.
## Maps to UCI config sections in /etc/config/nopal.

type
  ConntrackFlushMode* = enum
    cfmNone, cfmSelective, cfmFull

  AddressFamily* = enum
    afIpv4, afIpv6, afBoth

  TrackMethod* = enum
    tmPing, tmDns, tmHttp, tmHttps, tmArping, tmComposite

  StickyMode* = enum
    smFlow, smSrcIp, smSrcDst

  ConntrackFlushTrigger* = enum
    cftIfUp,          ## Flush when interface link comes up (-> Probing)
    cftIfDown,        ## Flush when interface link goes down (-> Offline via link event)
    cftConnected,     ## Flush when interface is confirmed online (-> Online)
    cftDisconnected   ## Flush when interface goes offline due to probe failures (-> Offline)

  LastResort* = enum
    lrDefault, lrUnreachable, lrBlackhole

  RuleFamily* = enum
    rfAny, rfIpv4, rfIpv6

  InitialState* = enum
    initOffline,  ## Wait for probes to confirm interface is online (default, safe)
    initOnline    ## Assume interface is online at startup

  GlobalsConfig* = object
    enabled*: bool
    logLevel*: string
    conntrackFlush*: ConntrackFlushMode
    ipv6Enabled*: bool
    ipcSocket*: string
    hookScript*: string
    rtTableLookup*: seq[uint32]
    logging*: bool
    markMask*: uint32
    # Default probe settings — inherited by interfaces that don't override them
    trackMethod*: TrackMethod
    trackIp*: seq[string]
    probeInterval*: uint32
    probeTimeout*: uint32
    upCount*: uint32
    downCount*: uint32

  InterfaceConfig* = object
    name*: string
    enabled*: bool
    device*: string
    family*: AddressFamily
    metric*: uint32
    weight*: uint32
    trackMethod*: TrackMethod
    trackIp*: seq[string]
    trackPort*: int      ## 0 = default (80 for HTTP, 443 for HTTPS)
    reliability*: uint32
    probeInterval*: uint32
    failureInterval*: int   ## 0 = use probeInterval
    recoveryInterval*: int  ## 0 = use probeInterval
    keepFailureInterval*: bool
    probeTimeout*: uint32
    count*: uint32
    maxTtl*: uint32
    probeSize*: uint32
    upCount*: uint32
    downCount*: uint32
    initialState*: InitialState
    checkQuality*: bool
    latencyThreshold*: int  ## 0 = disabled
    lossThreshold*: int     ## 0 = disabled
    recoveryLatency*: int   ## 0 = use latencyThreshold
    recoveryLoss*: int      ## 0 = use lossThreshold
    qualityWindow*: uint32
    dampening*: bool
    dampeningHalflife*: uint32
    dampeningCeiling*: uint32
    dampeningSuppress*: uint32
    dampeningReuse*: uint32
    dnsQueryName*: string
    compositeMethods*: seq[TrackMethod]
    localSource*: bool
    updateDns*: bool
    dnsServers*: seq[string]
    clampMss*: bool
    flushConntrack*: seq[ConntrackFlushTrigger]

  MemberConfig* = object
    name*: string
    interfaceName*: string
    metric*: uint32
    weight*: uint32

  PolicyConfig* = object
    name*: string
    members*: seq[string]
    lastResort*: LastResort

  RuleConfig* = object
    name*: string
    srcIp*: seq[string]
    srcPort*: string
    destIp*: seq[string]
    destPort*: string
    proto*: string
    family*: RuleFamily
    srcIface*: string
    ipset*: string
    sticky*: bool
    stickyTimeout*: uint32
    stickyMode*: StickyMode
    usePolicy*: string
    log*: bool

  NopalConfig* = object
    globals*: GlobalsConfig
    interfaces*: seq[InterfaceConfig]
    members*: seq[MemberConfig]
    policies*: seq[PolicyConfig]
    rules*: seq[RuleConfig]

proc defaultGlobals*(): GlobalsConfig =
  GlobalsConfig(
    enabled: true,
    logLevel: "info",
    conntrackFlush: cfmSelective,
    ipv6Enabled: false,
    ipcSocket: "/var/run/nopal.sock",
    hookScript: "/etc/nopal.user",
    rtTableLookup: @[],
    logging: false,
    markMask: 0xFF00'u32,
    trackMethod: tmPing,
    trackIp: @["8.8.8.8", "1.1.1.1"],
    probeInterval: 5,
    probeTimeout: 2,
    upCount: 3,
    downCount: 3,
  )

proc defaultInterface*(): InterfaceConfig =
  InterfaceConfig(
    enabled: true,
    family: afIpv4,
    metric: 0,
    weight: 1,
    trackMethod: tmPing,
    trackPort: 0,
    reliability: 1,
    probeInterval: 5,
    failureInterval: 0,
    recoveryInterval: 0,
    keepFailureInterval: false,
    probeTimeout: 2,
    count: 1,
    maxTtl: 128,
    probeSize: 56,
    upCount: 3,
    downCount: 3,
    initialState: initOffline,
    checkQuality: true,
    latencyThreshold: 0,
    lossThreshold: 0,
    recoveryLatency: 0,
    recoveryLoss: 0,
    qualityWindow: 10,
    dampening: false,
    dampeningHalflife: 300,
    dampeningCeiling: 1000,
    dampeningSuppress: 500,
    dampeningReuse: 250,
    localSource: false,
    updateDns: false,
    clampMss: true,
    flushConntrack: @[cftDisconnected],
  )

proc defaultRule*(): RuleConfig =
  RuleConfig(
    proto: "all",
    family: rfAny,
    stickyMode: smFlow,
    stickyTimeout: 600,
  )
