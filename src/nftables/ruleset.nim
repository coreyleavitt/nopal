## nftables JSON ruleset types.

import std/json

type
  Ruleset* = object
    nftables*: JsonNode
