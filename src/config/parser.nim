## UCI config parser for /etc/config/nopal.

import schema
import ../errors

proc parseConfig*(path: string): NopalConfig =
  raise newException(ConfigError, "not yet implemented")
