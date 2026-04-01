## Policy resolution: group members by metric tier, select active members.

type
  ActiveMember* = object
    interfaceIndex*: int
    mark*: uint32
    weight*: uint32

  Tier* = object
    metric*: uint32
    members*: seq[ActiveMember]

  ResolvedPolicy* = object
    name*: string
    tiers*: seq[Tier]
