## Health probe orchestration for multi-WAN interfaces.
##
## The ProbeEngine manages health probes for each configured interface,
## tracking consecutive successes and failures to determine when an interface
## should transition online or offline. Each interface probes its configured
## targets in round-robin cycles: one probe per target per cycle, with the
## cycle evaluated after all targets have been probed. A cycle succeeds when
## at least `reliability` targets respond.

import std/[options, times, deques, monotimes, strutils]

# ---------------------------------------------------------------------------
# Forward-declared stub types from Phase 2 transport modules.
# In production these come from icmp.nim, dns.nim, http.nim, arp.nim.
# ---------------------------------------------------------------------------

type
  HttpProbeState* = enum
    hsIdle, hsConnecting, hsSending, hsReceiving

# ===================================================================
# QualityWindow — fixed-size ring buffer for probe quality metrics
# ===================================================================

type
  QualityWindow* = object
    buf: seq[Option[uint32]]  ## None = loss, Some(rtt_ms) = success
    pos: int                  ## next write position
    count: int                ## number of valid entries
    capacity*: int            ## max window size (0 = quality monitoring disabled)

proc initQualityWindow*(capacity: int = 10): QualityWindow =
  ## Create a quality window. Capacity 0 disables quality monitoring.
  let cap = max(capacity, 0)
  result = QualityWindow(pos: 0, count: 0, capacity: cap)
  if cap > 0:
    result.buf = newSeq[Option[uint32]](cap)

proc push*(w: var QualityWindow, val: Option[uint32]) =
  if w.capacity <= 0: return
  w.buf[w.pos] = val
  w.pos = (w.pos + 1) mod w.capacity
  if w.count < w.capacity:
    inc w.count

proc len*(w: QualityWindow): int = w.count

proc isFull*(w: QualityWindow): bool =
  w.capacity > 0 and w.count >= w.capacity

proc clear*(w: var QualityWindow) =
  for i in 0 ..< w.buf.len:
    w.buf[i] = none(uint32)
  w.pos = 0
  w.count = 0

proc avgRtt*(w: QualityWindow): Option[uint32] =
  var total: uint64 = 0
  var n: uint32 = 0
  for i in 0 ..< w.count:
    if w.buf[i].isSome:
      total += w.buf[i].get.uint64
      inc n
  if n == 0: none(uint32)
  else: some((total div n.uint64).uint32)

proc lossPercent*(w: QualityWindow): uint32 =
  if w.count == 0: return 0
  var losses: uint32 = 0
  for i in 0 ..< w.count:
    if w.buf[i].isNone:
      inc losses
  (losses * 100) div w.count.uint32

# ===================================================================
# ProbeTransport case object
# ===================================================================

type
  ProbeTransportKind* = enum
    tkIcmp, tkDns, tkHttp, tkArp, tkComposite

  ProbeTransport* = object
    case kind*: ProbeTransportKind
    of tkIcmp:
      icmpFd*: cint
      icmpFamily*: uint8
    of tkDns:
      dnsFd*: cint
      dnsFamily*: uint8
      dnsQueryBuf*: array[512, byte]
      dnsQueryLen*: int
    of tkHttp:
      httpFd*: cint
      httpFamily*: uint8
      httpDevice*: string
      httpPort*: uint16
      httpState*: HttpProbeState
    of tkArp:
      arpFd*: cint
      arpIfindex*: cint
      arpSenderMac*: array[6, byte]
      arpSenderIp*: array[4, byte]
    of tkComposite:
      subs*: seq[ProbeTransport]

# ===================================================================
# TargetStatus and InterfaceProbe
# ===================================================================

type
  TargetStatus* = object
    ip*: array[16, byte]
    isV6*: bool
    up*: bool
    lastRttMs*: Option[uint32]

  InterfaceProbe = object
    index: int
    name, device: string
    targets: seq[array[16, byte]]  ## expanded by count
    targetIsV6: bool
    transport: ProbeTransport
    reliability: uint32
    pending: bool
    seqNum: uint16
    cycleResults: seq[bool]
    cycleRtts: seq[Option[uint32]]
    targetStatus: seq[TargetStatus]
    cyclePos: int
    sendTime: MonoTime
    sendTimeValid: bool
    lastRtt: Option[uint32]
    quality: QualityWindow
    latencyThreshold, lossThreshold: Option[uint32]
    recoveryLatency, recoveryLoss: Option[uint32]
    qualityDegraded: bool
    probeSize: int

  ProbeResult* = object
    interfaceIndex*: int
    success*: bool
    qualityOk*: bool
    avgRttMs*: Option[uint32]
    lossPercent*: uint32

  ProbeEngine* = object
    probes: seq[InterfaceProbe]

# ===================================================================
# QualityWindow on InterfaceProbe — helper
# ===================================================================

proc pushQuality(p: var InterfaceProbe, rtt: Option[uint32]) =
  p.quality.push(rtt)

proc computeMetrics(p: InterfaceProbe): (Option[uint32], uint32) =
  (p.quality.avgRtt, p.quality.lossPercent)

# ===================================================================
# evaluateQuality (private) — hysteresis logic
# ===================================================================

proc evaluateQuality(p: var InterfaceProbe): (Option[uint32], uint32, bool) =
  let (avgRtt, lossPct) = p.computeMetrics()
  if p.quality.capacity <= 0 or p.quality.len == 0:
    return (none(uint32), 0'u32, true)

  # Only evaluate thresholds once the window is full
  if not p.quality.isFull:
    return (avgRtt, lossPct, true)

  var qualityOk: bool
  if p.qualityDegraded:
    # Currently degraded: use recovery thresholds to recover.
    let latThresh = if p.recoveryLatency.isSome: p.recoveryLatency
                    else: p.latencyThreshold
    let lossThresh = if p.recoveryLoss.isSome: p.recoveryLoss
                     else: p.lossThreshold

    let latOk = if latThresh.isSome:
                  if avgRtt.isSome: avgRtt.get < latThresh.get
                  else: true
                else: true
    let lossOk = if lossThresh.isSome: lossPct < lossThresh.get
                 else: true
    let recovered = latOk and lossOk
    if recovered:
      p.qualityDegraded = false
    qualityOk = recovered
  else:
    # Currently healthy: use failure thresholds to detect degradation.
    var ok = true
    if p.latencyThreshold.isSome:
      if avgRtt.isSome:
        if avgRtt.get > p.latencyThreshold.get:
          ok = false
    if p.lossThreshold.isSome:
      if lossPct > p.lossThreshold.get:
        ok = false
    if not ok:
      p.qualityDegraded = true
    qualityOk = ok

  (avgRtt, lossPct, qualityOk)

# ===================================================================
# Dispatch procs — switch on transport.kind, call Phase 2 procs
# ===================================================================

proc dispatchSend*(transport: var ProbeTransport, target: array[16, byte],
                   isV6: bool, seqNum: uint16, id: uint16,
                   payloadSize: int): bool =
  ## Send a probe via the appropriate transport. Returns true on success.
  ## In production, this calls the Phase 2 module procs.
  case transport.kind
  of tkIcmp:
    # Would call: sendIcmpProbe(transport.icmpFd, target, seqNum, id, payloadSize)
    return false  # stub — real impl in icmp.nim
  of tkDns:
    # Would call: sendDnsProbe(transport.dnsFd, target, transport.dnsQueryBuf, transport.dnsQueryLen)
    return false
  of tkHttp:
    # Would call: startHttpConnect(transport.httpFd, target, transport.httpPort)
    return false
  of tkArp:
    # Would call: sendArpProbe(transport.arpFd, target, transport.arpIfindex, ...)
    return false
  of tkComposite:
    var anyOk = false
    for sub in transport.subs.mitems:
      if dispatchSend(sub, target, isV6, seqNum, id, payloadSize):
        anyOk = true
    return anyOk

proc dispatchRecv*(transport: var ProbeTransport): Option[tuple[seqNum: uint16, id: uint16]] =
  ## Non-blocking receive. Returns (seq, id) on match, none otherwise.
  case transport.kind
  of tkIcmp:
    return none(tuple[seqNum: uint16, id: uint16])
  of tkDns:
    return none(tuple[seqNum: uint16, id: uint16])
  of tkHttp:
    return none(tuple[seqNum: uint16, id: uint16])
  of tkArp:
    return none(tuple[seqNum: uint16, id: uint16])
  of tkComposite:
    for sub in transport.subs.mitems:
      let r = dispatchRecv(sub)
      if r.isSome:
        return r
    return none(tuple[seqNum: uint16, id: uint16])

proc dispatchGetFds*(transport: ProbeTransport): seq[cint] =
  ## Collect all file descriptors from the transport.
  case transport.kind
  of tkIcmp: @[transport.icmpFd]
  of tkDns: @[transport.dnsFd]
  of tkHttp: @[transport.httpFd]
  of tkArp: @[transport.arpFd]
  of tkComposite:
    var fds: seq[cint] = @[]
    for sub in transport.subs:
      fds.add(dispatchGetFds(sub))
    fds

proc dispatchClose*(transport: var ProbeTransport) =
  ## Close file descriptors held by the transport.
  case transport.kind
  of tkIcmp: discard  # Would call: close(transport.icmpFd)
  of tkDns: discard
  of tkHttp: discard
  of tkArp: discard
  of tkComposite:
    for sub in transport.subs.mitems:
      dispatchClose(sub)

# ===================================================================
# ProbeEngine API
# ===================================================================

proc initProbeEngine*(): ProbeEngine =
  ProbeEngine(probes: @[])

proc parseIpToBytes*(ipStr: string, outBuf: var array[16, byte]): bool =
  ## Parse an IPv4 or IPv6 string into a 16-byte buffer.
  ## IPv4 is stored in the first 4 bytes. Returns true on success.
  for i in 0 ..< 16: outBuf[i] = 0
  # Simple IPv4 parser
  var parts: seq[string] = @[]
  var cur = ""
  for c in ipStr:
    if c == '.':
      parts.add(cur)
      cur = ""
    else:
      cur.add(c)
  parts.add(cur)
  if parts.len == 4:
    for i in 0 ..< 4:
      let v = try: parseInt(parts[i]) except ValueError: return false
      if v < 0 or v > 255: return false
      outBuf[i] = v.byte
    return true
  # IPv6 not fully implemented here — stub returns false
  return false

proc addInterface*(engine: var ProbeEngine, index: int, name, device: string,
                   targetIps: seq[string], isV6: bool,
                   transport: ProbeTransport, reliability: uint32,
                   count: int = 1,
                   latencyThreshold: Option[uint32] = none(uint32),
                   lossThreshold: Option[uint32] = none(uint32),
                   recoveryLatency: Option[uint32] = none(uint32),
                   recoveryLoss: Option[uint32] = none(uint32),
                   qualityWindowSize: int = 10,
                   probeSize: int = 56) =
  ## Parse target IPs to bytes, expand by count, create transport socket,
  ## initialise cycle state. Adds the interface to the engine.
  var uniqueTargets: seq[array[16, byte]] = @[]
  for ip in targetIps:
    var buf: array[16, byte]
    if parseIpToBytes(ip, buf):
      uniqueTargets.add(buf)

  # Expand targets by count
  let effectiveCount = max(count, 1)
  var expanded: seq[array[16, byte]] = @[]
  for t in uniqueTargets:
    for _ in 0 ..< effectiveCount:
      expanded.add(t)

  let numTargets = expanded.len
  let effectiveReliability = max(min(reliability, uniqueTargets.len.uint32), 1'u32)

  var tStatus: seq[TargetStatus] = @[]
  for t in uniqueTargets:
    tStatus.add(TargetStatus(ip: t, isV6: isV6, up: false, lastRttMs: none(uint32)))

  engine.probes.add(InterfaceProbe(
    index: index,
    name: name,
    device: device,
    targets: expanded,
    targetIsV6: isV6,
    transport: transport,
    reliability: effectiveReliability,
    pending: false,
    seqNum: 0,
    cycleResults: newSeq[bool](numTargets),
    cycleRtts: newSeqOfCap[Option[uint32]](numTargets),
    targetStatus: tStatus,
    cyclePos: 0,
    sendTime: getMonoTime(),
    sendTimeValid: false,
    lastRtt: none(uint32),
    quality: initQualityWindow(qualityWindowSize),
    latencyThreshold: latencyThreshold,
    lossThreshold: lossThreshold,
    recoveryLatency: recoveryLatency,
    recoveryLoss: recoveryLoss,
    qualityDegraded: false,
    probeSize: probeSize,
  ))
  # Ensure cycleRtts is properly sized
  engine.probes[^1].cycleRtts.setLen(numTargets)

proc removeInterface*(engine: var ProbeEngine, index: int) =
  ## Close transport and remove the interface from the engine.
  for i in 0 ..< engine.probes.len:
    if engine.probes[i].index == index:
      dispatchClose(engine.probes[i].transport)
      engine.probes.delete(i)
      return

proc sendProbe*(engine: var ProbeEngine, index: int): bool =
  ## Send a probe for the current cycle target. Returns true on success.
  for p in engine.probes.mitems:
    if p.index == index:
      if p.targets.len == 0: return false
      let target = p.targets[p.cyclePos]
      p.seqNum = p.seqNum + 1
      let id = p.index.uint16
      let ok = dispatchSend(p.transport, target, p.targetIsV6,
                            p.seqNum, id, p.probeSize)
      if ok:
        p.pending = true
        p.sendTime = getMonoTime()
        p.sendTimeValid = true
        p.lastRtt = none(uint32)
      return ok
  return false

proc checkResponses*(engine: var ProbeEngine) =
  ## Non-blocking recv on all pending probes. Match seq/id, compute RTT.
  for p in engine.probes.mitems:
    if not p.pending: continue
    let reply = dispatchRecv(p.transport)
    if reply.isSome:
      let (rSeq, rId) = reply.get
      if rSeq == p.seqNum and rId == p.index.uint16:
        var rtt: Option[uint32] = none(uint32)
        if p.sendTimeValid:
          let elapsed = getMonoTime() - p.sendTime
          rtt = some(elapsed.inMilliseconds.uint32)
        p.pending = false
        p.cycleResults[p.cyclePos] = true
        p.cycleRtts[p.cyclePos] = rtt
        p.lastRtt = rtt

proc recordTimeout*(engine: var ProbeEngine, index: int): Option[ProbeResult] =
  ## Advance cycle position. Returns Some(ProbeResult) when cycle completes.
  var probeIdx = -1
  for i in 0 ..< engine.probes.len:
    if engine.probes[i].index == index:
      probeIdx = i
      break
  if probeIdx < 0: return none(ProbeResult)

  template p: untyped = engine.probes[probeIdx]

  # Record quality sample
  if p.pending:
    p.pushQuality(none(uint32))
  elif p.cycleResults[p.cyclePos]:
    p.pushQuality(p.lastRtt)
  else:
    p.pushQuality(none(uint32))
  p.pending = false

  # Advance
  p.cyclePos += 1

  if p.cyclePos < p.targets.len:
    return none(ProbeResult)

  # Cycle complete — evaluate
  var successes: uint32 = 0
  for r in p.cycleResults:
    if r: inc successes
  let cycleOk = successes >= p.reliability

  # Update per-target status
  for ts in p.targetStatus.mitems:
    var up = false
    var rtt: Option[uint32] = none(uint32)
    for i in 0 ..< p.targets.len:
      if p.targets[i] == ts.ip and p.cycleResults[i]:
        up = true
        rtt = p.cycleRtts[i]
    ts.up = up
    if up:
      ts.lastRttMs = rtt

  # Reset cycle
  p.cyclePos = 0
  for i in 0 ..< p.cycleResults.len:
    p.cycleResults[i] = false
  for i in 0 ..< p.cycleRtts.len:
    p.cycleRtts[i] = none(uint32)

  # Evaluate quality
  let (avgRtt, lossPct, qualityOk) = p.evaluateQuality()

  some(ProbeResult(
    interfaceIndex: index,
    success: cycleOk,
    qualityOk: qualityOk,
    avgRttMs: avgRtt,
    lossPercent: lossPct,
  ))

proc getFds*(engine: ProbeEngine): seq[tuple[slot: int, fd: cint]] =
  var res: seq[tuple[slot: int, fd: cint]] = @[]
  var slot = 0
  for p in engine.probes:
    let fds = dispatchGetFds(p.transport)
    for fd in fds:
      res.add((slot: slot, fd: fd))
      inc slot
  res

proc resetCounters*(engine: var ProbeEngine, index: int) =
  ## Clear cycle, quality window, qualityDegraded for the given interface.
  for p in engine.probes.mitems:
    if p.index == index:
      p.pending = false
      p.cyclePos = 0
      for i in 0 ..< p.cycleResults.len:
        p.cycleResults[i] = false
      for i in 0 ..< p.cycleRtts.len:
        p.cycleRtts[i] = none(uint32)
      p.sendTimeValid = false
      p.lastRtt = none(uint32)
      p.quality.clear()
      p.qualityDegraded = false
      return

when isMainModule:
  # Test helpers — simulated probes (no real sockets)

  proc addTestInterface(engine: var ProbeEngine, index: int, name: string,
                        numTargets: int, reliability: uint32,
                        latencyThreshold: Option[uint32] = none(uint32),
                        lossThreshold: Option[uint32] = none(uint32),
                        recoveryLatency: Option[uint32] = none(uint32),
                        recoveryLoss: Option[uint32] = none(uint32)) =
    ## Create an InterfaceProbe with a dummy no-op transport for testing.
    var targets: seq[array[16, byte]] = @[]
    var tStatus: seq[TargetStatus] = @[]
    for i in 0 ..< numTargets:
      var ip: array[16, byte]
      ip[0] = 8; ip[1] = 8; ip[2] = 8; ip[3] = (i + 1).byte
      targets.add(ip)
      tStatus.add(TargetStatus(ip: ip, isV6: false, up: false, lastRttMs: none(uint32)))

    let effectiveReliability = max(min(reliability, numTargets.uint32), 1'u32)

    engine.probes.add(InterfaceProbe(
      index: index,
      name: name,
      device: "test0",
      targets: targets,
      targetIsV6: false,
      transport: ProbeTransport(kind: tkIcmp, icmpFd: -1, icmpFamily: 4),
      reliability: effectiveReliability,
      pending: false,
      seqNum: 0,
      cycleResults: newSeq[bool](numTargets),
      cycleRtts: newSeqOfCap[Option[uint32]](numTargets),
      targetStatus: tStatus,
      cyclePos: 0,
      sendTime: getMonoTime(),
      sendTimeValid: false,
      lastRtt: none(uint32),
      quality: initQualityWindow(6),
      latencyThreshold: latencyThreshold,
      lossThreshold: lossThreshold,
      recoveryLatency: recoveryLatency,
      recoveryLoss: recoveryLoss,
      qualityDegraded: false,
      probeSize: 56,
    ))
    engine.probes[^1].cycleRtts.setLen(numTargets)

  proc simulateSend(engine: var ProbeEngine, index: int) =
    ## Set pending=true and sendTime without using a real socket.
    for p in engine.probes.mitems:
      if p.index == index:
        p.pending = true
        p.seqNum += 1
        p.sendTime = getMonoTime()
        p.sendTimeValid = true
        p.lastRtt = none(uint32)
        return

  proc simulateResponse(engine: var ProbeEngine, index: int) =
    ## Record a success for the current cycle position.
    for p in engine.probes.mitems:
      if p.index == index:
        p.pending = false
        p.cycleResults[p.cyclePos] = true
        p.lastRtt = some(10'u32)  # default 10ms RTT
        return

  proc simulateResponseWithRtt(engine: var ProbeEngine, index: int, rttMs: uint32) =
    ## Record a success with a specific RTT.
    for p in engine.probes.mitems:
      if p.index == index:
        p.pending = false
        p.cycleResults[p.cyclePos] = true
        p.lastRtt = some(rttMs)
        return

  # ===================================================================
  # Tests
  # ===================================================================

  var passed = 0
  var failed = 0

  template test(name: string, body: untyped) =
    block:
      try:
        body
        inc passed
        echo "  PASS: ", name
      except AssertionDefect:
        inc failed
        echo "  FAIL: ", name, " - ", getCurrentExceptionMsg()
      except CatchableError:
        inc failed
        echo "  FAIL: ", name, " - ", getCurrentExceptionMsg()

  echo "=== QualityWindow tests ==="

  test "empty window returns zero loss and no avg":
    var w = initQualityWindow(6)
    assert w.len == 0
    assert w.avgRtt.isNone
    assert w.lossPercent == 0

  test "push and read single success":
    var w = initQualityWindow(6)
    w.push(some(42'u32))
    assert w.len == 1
    assert w.avgRtt == some(42'u32)
    assert w.lossPercent == 0

  test "push and read single loss":
    var w = initQualityWindow(6)
    w.push(none(uint32))
    assert w.len == 1
    assert w.avgRtt.isNone
    assert w.lossPercent == 100

  test "mixed success and loss":
    var w = initQualityWindow(6)
    w.push(some(100'u32))
    w.push(none(uint32))
    w.push(some(200'u32))
    assert w.len == 3
    assert w.avgRtt == some(150'u32)  # (100+200)/2
    assert w.lossPercent == 33        # 1/3 = 33%

  test "wraps around at capacity 6":
    var w = initQualityWindow(6)
    for i in 1 .. 6:
      w.push(some(i.uint32 * 10))
    assert w.len == 6
    # [10, 20, 30, 40, 50, 60] -> avg = 35
    assert w.avgRtt == some(35'u32)
    # Push a 7th — oldest (10) drops off
    w.push(some(70'u32))
    assert w.len == 6
    # [70, 20, 30, 40, 50, 60] -> avg = (20+30+40+50+60+70)/6 = 270/6 = 45
    assert w.avgRtt == some(45'u32)

  test "clear resets window":
    var w = initQualityWindow(6)
    w.push(some(50'u32))
    w.push(some(60'u32))
    w.clear()
    assert w.len == 0
    assert w.avgRtt.isNone

  echo ""
  echo "=== ProbeEngine tests ==="

  test "single_target_cycle_success":
    var engine = initProbeEngine()
    engine.addTestInterface(0, "wan", 1, 1)
    engine.simulateSend(0)
    engine.simulateResponse(0)
    let r = engine.recordTimeout(0)
    assert r.isSome
    assert r.get.success

  test "single_target_cycle_failure":
    var engine = initProbeEngine()
    engine.addTestInterface(0, "wan", 1, 1)
    engine.simulateSend(0)
    # No response — timeout fires with pending still true
    let r = engine.recordTimeout(0)
    assert r.isSome
    assert not r.get.success

  test "multi_target_reliability_met":
    # 3 targets, reliability=2: cycle succeeds if >= 2 targets respond
    var engine = initProbeEngine()
    engine.addTestInterface(0, "wan", 3, 2)

    # Target 0: success
    engine.simulateSend(0)
    engine.simulateResponse(0)
    assert engine.recordTimeout(0).isNone  # mid-cycle

    # Target 1: success
    engine.simulateSend(0)
    engine.simulateResponse(0)
    assert engine.recordTimeout(0).isNone  # mid-cycle

    # Target 2: timeout
    engine.simulateSend(0)
    let r = engine.recordTimeout(0)
    assert r.isSome
    assert r.get.success  # 2/3 >= reliability(2)

  test "multi_target_reliability_not_met":
    # 3 targets, reliability=2: cycle fails if < 2 targets respond
    var engine = initProbeEngine()
    engine.addTestInterface(0, "wan", 3, 2)

    # Target 0: success
    engine.simulateSend(0)
    engine.simulateResponse(0)
    assert engine.recordTimeout(0).isNone

    # Target 1: timeout
    engine.simulateSend(0)
    assert engine.recordTimeout(0).isNone

    # Target 2: timeout
    engine.simulateSend(0)
    let r = engine.recordTimeout(0)
    assert r.isSome
    assert not r.get.success  # 1/3 < reliability(2)

  test "reset_counters_clears_cycle_state":
    var engine = initProbeEngine()
    engine.addTestInterface(0, "wan", 3, 2)

    # Start a cycle (probe target 0)
    engine.simulateSend(0)
    engine.simulateResponse(0)
    discard engine.recordTimeout(0)  # advances to pos 1

    # Reset mid-cycle
    engine.resetCounters(0)

    # Should start a fresh cycle from position 0
    engine.simulateSend(0)
    engine.simulateResponse(0)
    assert engine.recordTimeout(0).isNone  # mid-cycle at pos 1

    engine.simulateSend(0)
    engine.simulateResponse(0)
    assert engine.recordTimeout(0).isNone  # mid-cycle at pos 2

    engine.simulateSend(0)
    engine.simulateResponse(0)
    let r = engine.recordTimeout(0)
    assert r.isSome
    assert r.get.success  # 3/3 >= 2

  test "quality_ok_without_thresholds":
    # No quality thresholds configured -> qualityOk always true
    var engine = initProbeEngine()
    engine.addTestInterface(0, "wan", 1, 1)

    engine.simulateSend(0)
    engine.simulateResponse(0)
    let r = engine.recordTimeout(0)
    assert r.isSome
    assert r.get.qualityOk
    assert r.get.success

  test "latency_threshold_triggers_degradation":
    # latencyThreshold=100ms, window=6 (fixed). Fill with 150ms -> avg > 100
    var engine = initProbeEngine()
    engine.addTestInterface(0, "wan", 1, 1, latencyThreshold = some(100'u32))

    # Fill the quality window (6 entries) with 150ms RTT
    for i in 0 ..< 6:
      engine.simulateSend(0)
      engine.simulateResponseWithRtt(0, 150)
      let r = engine.recordTimeout(0)
      if i < 5:
        assert r.isSome
        assert r.get.qualityOk  # window not full yet
      else:
        assert r.isSome
        assert not r.get.qualityOk  # avg 150 > 100
        assert r.get.avgRttMs == some(150'u32)

  test "recovery_latency_hysteresis":
    # latencyThreshold=100ms, recoveryLatency=50ms, window=6
    # Degrades at avg > 100, recovers only when avg < 50
    var engine = initProbeEngine()
    engine.addTestInterface(0, "wan", 1, 1,
                            latencyThreshold = some(100'u32),
                            recoveryLatency = some(50'u32))

    # Fill window: 6x 150ms -> degraded
    for i in 0 ..< 6:
      engine.simulateSend(0)
      engine.simulateResponseWithRtt(0, 150)
      discard engine.recordTimeout(0)
    assert engine.probes[0].qualityDegraded

    # Replace with 75ms: below failure (100) but above recovery (50)
    for i in 0 ..< 6:
      engine.simulateSend(0)
      engine.simulateResponseWithRtt(0, 75)
      discard engine.recordTimeout(0)
    # Still degraded because 75 >= 50
    assert engine.probes[0].qualityDegraded

    # Replace with 40ms: below recovery (50) -> recovered
    for i in 0 ..< 6:
      engine.simulateSend(0)
      engine.simulateResponseWithRtt(0, 40)
      discard engine.recordTimeout(0)
    assert not engine.probes[0].qualityDegraded

  test "loss_threshold_triggers_degradation":
    # lossThreshold=30%, window=6: > 30% loss triggers degradation
    var engine = initProbeEngine()
    engine.addTestInterface(0, "wan", 1, 1, lossThreshold = some(30'u32))

    # 3 successes, 3 timeouts -> 50% loss > 30%
    for i in 0 ..< 6:
      engine.simulateSend(0)
      if i mod 2 == 0:
        engine.simulateResponse(0)
      # else: no response (timeout)
      let r = engine.recordTimeout(0)
      if i < 5:
        assert r.isSome
        assert r.get.qualityOk  # window not full
      else:
        assert r.isSome
        assert not r.get.qualityOk
        assert r.get.lossPercent == 50

  echo ""
  echo "=== Results ==="
  echo "  Passed: ", passed
  echo "  Failed: ", failed
  if failed > 0:
    quit(1)
  else:
    echo "  All tests passed!"
