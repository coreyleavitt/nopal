## ARP probe via AF_PACKET (IPv4 only).

type
  ArpSocket* = object
    fd*: cint
