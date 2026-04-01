## Syslog logger for nopal daemon.
##
## Writes log messages to syslog via /dev/log Unix datagram socket,
## matching OpenWrt's logd expectations.

import std/logging
import std/strutils
import std/posix
import std/times

const
  LOG_DAEMON = 3 shl 3  # facility
  LOG_ERR = 3
  LOG_WARNING = 4
  LOG_NOTICE = 5
  LOG_INFO = 6
  LOG_DEBUG = 7

type
  SyslogHandler* = ref object of Logger
    ident: string
    fd: cint

proc levelToSyslog(level: Level): cint =
  case level
  of lvlAll, lvlDebug: LOG_DEBUG
  of lvlInfo: LOG_INFO
  of lvlNotice: LOG_NOTICE
  of lvlWarn: LOG_WARNING
  of lvlError, lvlFatal: LOG_ERR
  of lvlNone: LOG_INFO

proc newSyslogHandler*(ident: string = "nopal", level: Level = lvlInfo): SyslogHandler =
  new(result)
  result.levelThreshold = level
  result.ident = ident
  result.fd = -1

proc initStderrFallback*(level: Level = lvlInfo) =
  ## Set up stderr logging (for development / non-OpenWrt environments).
  addHandler(newConsoleLogger(level, "[$levelname] "))
