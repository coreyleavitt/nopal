## Status file manager: atomic writes for interface state to /var/run/nopal/.
##
## Deep module hiding POSIX atomic-write mechanics behind a simple interface.
## Each interface gets a directory with a `status` file containing state + metrics.

import std/[posix, os, logging, strformat]
import ./state/machine

const
  DefaultBasePath* = "/var/run/nopal"

type
  StatusMetrics* = object
    ## Metrics snapshot for status file writing.
    ## Decouples status files from InterfaceTracker internals.
    successCount*: uint32
    failCount*: uint32
    avgRttMs*: int           ## -1 if unavailable
    lossPercent*: uint32
    uptimeSecs*: int64       ## -1 if not online
    downtimeSecs*: int64     ## -1 if not offline

  StatusFileManager* = object
    basePath*: string

proc initStatusFileManager*(basePath: string = DefaultBasePath): StatusFileManager =
  StatusFileManager(basePath: basePath)

proc createDirs*(sm: StatusFileManager, names: openArray[string]) =
  ## Create status directories for all interfaces.
  for name in names:
    let dir = sm.basePath & "/" & name
    try:
      createDir(dir)
    except OSError as e:
      warn fmt"failed to create status dir {dir}: {e.msg}"

proc writeStatus*(sm: StatusFileManager, name: string,
                  state: InterfaceState, metrics: StatusMetrics) =
  ## Atomically write status file for an interface.
  ## Uses temp file + fsync + rename for crash safety.
  let dir = sm.basePath & "/" & name
  var content = $state & "\n"

  if metrics.uptimeSecs >= 0:
    content.add(fmt"uptime={metrics.uptimeSecs}" & "\n")
  if metrics.downtimeSecs >= 0:
    content.add(fmt"downtime={metrics.downtimeSecs}" & "\n")
  content.add(fmt"success_count={metrics.successCount}" & "\n")
  content.add(fmt"fail_count={metrics.failCount}" & "\n")
  if metrics.avgRttMs >= 0:
    content.add(fmt"avg_rtt_ms={metrics.avgRttMs}" & "\n")
  content.add(fmt"loss_percent={metrics.lossPercent}" & "\n")

  # Atomic write via temp + rename
  let pid = posix.getpid()
  let tmpPath = fmt"{dir}/status.tmp.{pid}"
  let finalPath = fmt"{dir}/status"

  try: removeFile(tmpPath)
  except OSError: discard

  let fd = posix.open(cstring(tmpPath),
                      O_WRONLY or O_CREAT or O_EXCL, 0o644)
  if fd < 0:
    warn fmt"failed to create status file {tmpPath}"
    return

  let written = posix.write(fd, cstring(content), content.len)
  if written < 0 or written != content.len:
    warn "failed to write status file"
    discard posix.close(fd)
    try: removeFile(tmpPath)
    except OSError: discard
    return

  discard posix.fsync(fd)
  discard posix.close(fd)

  try:
    moveFile(tmpPath, finalPath)
  except OSError as e:
    warn fmt"failed to rename status file: {e.msg}"
    try: removeFile(tmpPath)
    except OSError: discard

proc cleanup*(sm: StatusFileManager) =
  ## Remove all status files and directories.
  try:
    removeDir(sm.basePath)
  except OSError:
    debug "failed to clean up status files"
