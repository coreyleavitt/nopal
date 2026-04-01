## Route monitor: subscribes to route/address change notifications.

import socket

type
  RouteMonitor* = object
    sock: NetlinkSocket
