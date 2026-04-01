## nftables engine: pipes JSON ruleset to `nft -j -f -` for atomic application.

import ./ruleset

proc applyRuleset*(rs: Ruleset): bool =
  discard # not yet implemented
