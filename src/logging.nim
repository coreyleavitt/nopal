## Syslog logger for nopal daemon.

import std/logging

type
  SyslogHandler* = ref object of Logger

proc newSyslogHandler*(level: Level = lvlInfo): SyslogHandler =
  new(result)
  result.levelThreshold = level
