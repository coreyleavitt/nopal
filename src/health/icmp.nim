## ICMP echo probe (IPv4 + IPv6).

type
  IcmpSocket* = object
    fd4*: cint
    fd6*: cint
