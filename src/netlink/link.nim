## Link monitor: subscribes to RTNLGRP_LINK for interface up/down events.

import ./socket

type
  LinkMonitor* = object
    sock: NetlinkSocket
