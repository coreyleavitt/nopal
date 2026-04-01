## DNS query probe (UDP port 53).

type
  DnsSocket* = object
    fd*: cint
