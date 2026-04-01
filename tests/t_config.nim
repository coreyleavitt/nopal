## Tier 1 tests: UCI parsing, validation, diff.

import std/unittest

suite "config schema":
  test "TrackMethod enum has all expected variants":
    check tmPing.ord == 0
    check tmComposite.ord == 5

suite "config diff":
  test "identical configs produce no changes":
    skip() # implement after parser is complete

suite "UCI parser":
  test "placeholder":
    skip() # implement after parser is complete
