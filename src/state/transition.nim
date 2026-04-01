## State transition -> action mapping.

import tracker

type
  TransitionAction* = enum
    taRegenerateNftables
    taAddRoutes
    taRemoveRoutes
    taUpdateDns
    taRemoveDns
    taBroadcastEvent
    taWriteStatus
