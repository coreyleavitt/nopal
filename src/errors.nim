## Error types for nopal.

type
  NopalError* = object of CatchableError
  ConfigError* = object of NopalError
  NftablesError* = object of NopalError
  IpcError* = object of NopalError
  ProbeError* = object of NopalError

  # ---------------------------------------------------------------------------
  # Netlink Result types (used instead of exceptions for expected failures)
  # ---------------------------------------------------------------------------

  NlErrorKind* = enum
    nekSendFailed      ## sendMsg returned error — message never left userspace
    nekRecvFailed      ## recvMsg returned error — socket-level I/O failure
    nekTimeout         ## No ACK received within deadline
    nekKernelError     ## ACK received with non-zero errno from kernel

  NlError* = object
    kind*: NlErrorKind
    osError*: int32       ## Kernel/socket errno (0 for nekTimeout)
    operation*: string  ## Domain operation name (e.g., "addRoute", "delRule")
    detail*: string     ## Context (e.g., "table 102, family IPv4")

  NlResult*[T] {.requiresInit.} = object
    case ok*: bool
    of true:
      value*: T
    of false:
      error*: NlError

func nlOk*[T](val: sink T): NlResult[T] {.inline.} =
  ## Construct a successful NlResult with a value.
  NlResult[T](ok: true, value: val)

func nlOk*(): NlResult[void] {.inline.} =
  ## Construct a successful void NlResult.
  NlResult[void](ok: true)

func nlErr*[T](error: sink NlError): NlResult[T] {.inline.} =
  ## Construct a failed NlResult from an NlError.
  NlResult[T](ok: false, error: error)

func nlErr*[T](kind: NlErrorKind, osError: int32,
               operation, detail: string): NlResult[T] {.inline.} =
  ## Construct a failed NlResult from individual fields.
  NlResult[T](ok: false, error: NlError(
    kind: kind, osError: osError, operation: operation, detail: detail))

func `$`*(e: NlError): string =
  ## Format an NlError for logging.
  result = e.operation & ": " & $e.kind
  if e.osError != 0:
    result &= " (errno " & $e.osError & ")"
  if e.detail.len > 0:
    result &= " [" & e.detail & "]"

# ---------------------------------------------------------------------------
# Error propagation operator (Rust-style ?)
# ---------------------------------------------------------------------------

template `?`*[T](r: NlResult[T]): T =
  ## Rust-style error propagation: unwrap Ok value or return Err from
  ## the calling function. Only usable in functions that return NlResult.
  ## Compiler enforces this via the `return` statement.
  let tmp = r
  if not tmp.ok:
    return NlResult[void](ok: false, error: tmp.error)
  tmp.value

template `?`*(r: NlResult[void]) =
  ## Void variant: propagate error or continue execution.
  let tmp = r
  if not tmp.ok:
    return NlResult[void](ok: false, error: tmp.error)
