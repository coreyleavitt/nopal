## nopal - Multi-WAN policy routing manager for OpenWrt
##
## Single binary, dual mode: daemon (nopald) or CLI tool (nopal)
## selected by argv[0].

import std/os

proc runDaemon(configPath: string) =
  quit("daemon not yet implemented")

proc runCli(args: openArray[string]) =
  quit("cli not yet implemented")

when isMainModule:
  let binName = extractFilename(getAppFilename())
  if binName == "nopald" or "--daemon" in commandLineParams():
    runDaemon("/etc/config/nopal")
  else:
    runCli(commandLineParams())
