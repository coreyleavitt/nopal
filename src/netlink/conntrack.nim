## Conntrack manager: selective flush by firewall mark via NETLINK_NETFILTER.
##
## Sends IPCTNL_MSG_CT_DELETE messages to flush conntrack entries matching
## a specific fwmark/mask. Socket is lazily opened on first use.
## Returns NlResult — callers decide error policy.

import std/[posix, endians]
import ../linux_constants
import ../errors
import ./socket

const
  RecvBufSize = 65536

type
  ConntrackManager* = object
    sock: NetlinkSocket
    opened: bool
    recvBuf: seq[byte]

proc newConntrackManager*(): ConntrackManager =
  ## Create a ConntrackManager with no socket yet (lazy-opened).
  result = ConntrackManager(
    sock: NetlinkSocket(fd: -1),
    opened: false,
    recvBuf: newSeq[byte](RecvBufSize),
  )

proc ensureOpen(m: var ConntrackManager) =
  ## Lazily open the NETLINK_NETFILTER socket on first use.
  ## Raises OSError if the socket cannot be opened (precondition violation).
  if not m.opened:
    m.sock = openNetlink(NETLINK_NETFILTER, 0)
    m.opened = true

proc flushByMark*(m: var ConntrackManager, mark, mask: uint32): NlResult[void] =
  ## Flush conntrack entries where (ct_mark & mask) == (mark & mask).
  ## Opens the netlink socket on first call.
  ## OSError may propagate from ensureOpen (precondition violation).
  m.ensureOpen()

  # Message type: (NFNL_SUBSYS_CTNETLINK << 8) | IPCTNL_MSG_CT_DELETE
  let msgType = uint16((uint16(NFNL_SUBSYS_CTNETLINK) shl 8) or
                        uint16(IPCTNL_MSG_CT_DELETE))

  var b = initBuilder(msgType, NLM_F_REQUEST.uint16 or NLM_F_ACK.uint16, 0)

  # NfGenMsg payload: AF_UNSPEC, version=0, res_id=0
  let nfg = NfGenMsg(nfgenFamily: 0, version: 0, resId: 0)
  b.addPayload(nfg)

  # CTA_MARK and CTA_MARK_MASK in network byte order
  var markBe: uint32
  var maskBe: uint32
  bigEndian32(addr markBe, unsafeAddr mark)
  bigEndian32(addr maskBe, unsafeAddr mask)

  var markBytes: array[4, byte]
  var maskBytes: array[4, byte]
  copyMem(addr markBytes[0], addr markBe, 4)
  copyMem(addr maskBytes[0], addr maskBe, 4)

  b.addAttr(CTA_MARK.uint16, markBytes)
  b.addAttr(CTA_MARK_MASK.uint16, maskBytes)

  let msg = b.finish()
  let ack = m.sock.sendAndAck(msg, m.recvBuf)
  if ack.ok:
    nlOk()
  else:
    nlErr[void](NlError(
      kind: case ack.kind
        of nakSendFailed: nekSendFailed
        of nakRecvFailed: nekRecvFailed
        of nakTimeout: nekTimeout
        of nakKernelError: nekKernelError,
      osError: ack.osError,
      operation: "flushByMark",
      detail: "mark=0x" & $mark & ", mask=0x" & $mask))
