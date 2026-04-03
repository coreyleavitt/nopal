## Hook script runner: fork/exec lifecycle for user state-change scripts.
##
## Deep module hiding process management behind a simple interface.
## The daemon calls runHook() on state changes and reapChildren() periodically.

import std/[posix, logging, strformat, os]
import ./state/machine

const MaxInFlightHooks* = 4

type
  HookRunner* = object
    scriptPath*: string
    scriptExists*: bool
    inFlightHooks: int
    firstConnectFired: bool

proc checkScriptExists(path: string): bool =
  if path.len == 0: return false
  try:
    fileExists(path)
  except OSError:
    false

proc initHookRunner*(scriptPath: string): HookRunner =
  HookRunner(
    scriptPath: scriptPath,
    scriptExists: checkScriptExists(scriptPath),
    inFlightHooks: 0,
    firstConnectFired: false,
  )

proc updateScript*(hr: var HookRunner, scriptPath: string) =
  ## Update the hook script path (e.g., on config reload).
  hr.scriptPath = scriptPath
  hr.scriptExists = checkScriptExists(scriptPath)

func inFlight*(hr: HookRunner): int {.inline.} =
  hr.inFlightHooks

proc runHook*(hr: var HookRunner, interfaceName, device: string,
              newState: InterfaceState) =
  ## Execute the user hook script on state changes.
  ## Fire-and-forget: errors are logged but not propagated.
  if not hr.scriptExists: return

  let action = case newState
    of isOnline: "connected"
    of isOffline: "disconnected"
    of isProbing: "ifup"
    of isDegraded: "degraded"
    of isInit: return

  let firstConnect = action == "connected" and not hr.firstConnectFired
  if firstConnect:
    hr.firstConnectFired = true

  if hr.inFlightHooks >= MaxInFlightHooks:
    warn fmt"hook script skipped ({hr.inFlightHooks} already in flight)"
    return

  info fmt"running hook: {hr.scriptPath} ACTION={action} INTERFACE={interfaceName} DEVICE={device}"

  let pid = posix.fork()
  if pid < 0:
    warn fmt"failed to fork for hook script: {strerror(errno)}"
  elif pid == 0:
    # Child process
    putEnv("ACTION", action)
    putEnv("INTERFACE", interfaceName)
    putEnv("DEVICE", device)
    if firstConnect:
      putEnv("FIRSTCONNECT", "1")
    discard posix.execl(cstring(hr.scriptPath), cstring(hr.scriptPath), nil)
    posix.exitnow(127)
  else:
    # Parent process
    inc hr.inFlightHooks
    var status: cint
    let res = posix.waitpid(pid, status, WNOHANG)
    if res > 0:
      dec hr.inFlightHooks
      if WEXITSTATUS(status) != 0:
        warn fmt"hook script exited with {WEXITSTATUS(status)}"

proc reapChildren*(hr: var HookRunner) =
  ## Non-blocking reap of any finished hook child processes.
  while hr.inFlightHooks > 0:
    var status: cint
    let res = posix.waitpid(-1, status, WNOHANG)
    if res <= 0: break
    dec hr.inFlightHooks
    if WIFEXITED(status) and WEXITSTATUS(status) != 0:
      warn fmt"hook script exited with {WEXITSTATUS(status)}"
