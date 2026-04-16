## Logging setup for nopal daemon.
##
## Uses Nim's std/logging with stderr output. On OpenWrt, procd captures
## stdout/stderr and routes to syslog via logd — no direct /dev/log
## socket needed.

import std/[logging, strutils]

proc initStderrFallback*(level: Level = lvlInfo) =
  ## Set up stderr logging. On OpenWrt, procd routes this to syslog.
  addHandler(newConsoleLogger(level, "[$levelname] "))

func parseLogLevel*(s: string): Level {.raises: [].} =
  ## Parse a log level string from config. Returns lvlInfo on unrecognized input.
  case s.toLowerAscii()
  of "debug": lvlDebug
  of "info": lvlInfo
  of "notice": lvlNotice
  of "warn", "warning": lvlWarn
  of "error", "err": lvlError
  of "fatal": lvlFatal
  of "none": lvlNone
  else: lvlInfo

proc setLogLevel*(level: Level) =
  ## Update the threshold on all registered handlers.
  for handler in logging.getHandlers():
    handler.levelThreshold = level
