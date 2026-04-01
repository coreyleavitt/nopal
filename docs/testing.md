# Testing

## Core principle

Every test must prove something specific. If you can't say what would break if the test were deleted, the test shouldn't exist.

A test is not "covers function X." A test is "proves that 3 equal-weight members in 100 slots get 34+33+33 (remainder distributed to first N)." The distinction matters: the first test survives refactoring, the second breaks when you rename a function.

## Three test tiers

### Tier 1: Unit tests

Pure logic tests with zero system dependencies. Run on any host via `nimble test`. No root required, no network namespaces, no real sockets.

**What belongs here:**
- Config parsing: UCI tokenizer, validation, cross-references, error messages
- Config diff: change detection, `needs_full_rebuild()` vs `needs_nftables()` decisions
- State machine: transition logic, counter behavior, dampening decay math
- Policy resolution: tier grouping, active member selection, weight distribution
- nftables chain generation: JSON output for known config inputs
- FNV-1a mark hashing: stability across config reorder, collision resolution
- ICMP checksum: RFC 1071 ones-complement over known payloads
- DNS label encoding: domain name to wire format
- Timer wheel: ordering, expiry, deadline calculation

**How to write them:**
```nim
suite "policy resolution":
  test "single tier, two members, selects both when online":
    var trackers = @[
      newTracker("wan", mark = 0x100, state = Online),
      newTracker("lte", mark = 0x200, state = Online),
    ]
    let members = @[
      MemberConfig(interface: "wan", policy: "balanced", metric: 1, weight: 50),
      MemberConfig(interface: "lte", policy: "balanced", metric: 1, weight: 30),
    ]
    let policy = resolvePolicy("balanced", members, trackers, lastResort = Default)
    check policy.tiers.len == 1
    check policy.tiers[0].members.len == 2
    check policy.tiers[0].members[0].weight == 50
    check policy.tiers[0].members[1].weight == 30
```

**Assertion standards:**
- Config tests: exact error messages, exact parsed values
- State machine tests: exact state after each transition, exact counter values
- nftables tests: exact JSON structure (use `parseJson` comparison, not string matching)
- Numeric tests: exact values, not approximations. "34+33+33" not "roughly 33 each"

### Tier 2: Namespace tests

Tests that exercise real kernel interfaces (netlink, nftables, raw sockets) inside Linux network namespaces. Run in CI on any Linux host with `CAP_NET_ADMIN` / root. No real hardware required.

**What belongs here:**
- Netlink route/rule add/delete and verification via `ip route show table N`
- Netlink link monitoring with veth pair up/down events
- nftables ruleset application and verification via `nft list table inet nopal`
- Conntrack flush by mark
- ICMP probe send/receive across a veth pair
- ARP probe send/receive across a veth pair
- Socket options: `SO_BINDTODEVICE`, `SO_MARK` applied correctly

**Setup pattern:**
```nim
suite "netlink routes":
  setup:
    let ns = createNetworkNamespace("nopal_test")
    ns.addVethPair("wan0", "wan0_peer")
    ns.setAddr("wan0", "10.0.0.1/24")
    ns.linkUp("wan0")

  teardown:
    destroyNetworkNamespace("nopal_test")

  test "add route to custom table and verify":
    let rm = newRouteManager()
    rm.addRoute(table = 100, dst = "0.0.0.0/0", gateway = "10.0.0.254", dev = "wan0")
    let output = execInNamespace(ns, "ip route show table 100")
    check "default via 10.0.0.254 dev wan0" in output
```

**CI requirements:**
- Linux runner with namespace support (any modern kernel)
- Root or `CAP_NET_ADMIN` capability
- `ip`, `nft` utilities installed (for verification commands, not for the code under test)

### Tier 3: Device tests

End-to-end tests on real OpenWrt hardware or VM. Validate the full daemon lifecycle: startup, probe cycling, failover, config reload, IPC.

**What belongs here:**
- Daemon startup with real config, verify nftables and routes are applied
- Interface failover: disable upstream, verify state transitions and route changes
- Config hot reload: modify UCI config, send SIGHUP, verify partial vs full rebuild
- IPC: `nopal status`, `nopal interfaces`, `nopal reload` produce correct output
- Binary compatibility: runs on all 4 target architectures (aarch64, armv7hf, mips, mipsel)
- Binary size: verify within expected range per target

**Not automated in CI.** Run manually on hardware or in an OpenWrt VM (x86 target) before releases.

**Verification method:** Run both the Rust reference binary and Nim binary on the same device. Compare:
- `nft list table inet nopal` output (should be identical)
- `ip rule show` / `ip route show table N` output
- `nopal status` JSON output
- `strace` syscall sequences for probe cycles

### Fuzz testing

Coverage-guided fuzzing for all parsers that consume external input. These are the highest-risk code paths -- they process bytes from the kernel, the network, and IPC clients.

**Targets:**

| Target | Input source | Risk |
|---|---|---|
| UCI config parser | User-edited config file | Low (trusted input, but complex grammar) |
| Netlink message parser | Kernel netlink responses | Medium (kernel shouldn't send garbage, but truncation/race is possible) |
| ICMP reply parser | Network packets | High (attacker-controlled on WAN) |
| DNS response parser | Network packets | High (attacker-controlled, label compression is tricky) |
| ARP reply parser | Network packets | High (attacker-controlled on LAN segment) |
| IPC request parser | Local Unix socket | Low (local only, but malformed JSON should never crash) |

**Approach:** Compile with libFuzzer integration (`-d:useFuzzer --passC:"-fsanitize=fuzzer,address"`) or use AFL++ on the generated C code (`nim c --compileOnly`, then `afl-clang-fast`). Each fuzz target is a standalone Nim file that takes `stdin` bytes and feeds them to the parser.

**Invariant:** No input should cause a crash, use-after-free, buffer overread, or infinite loop. Parse errors are expected and must be handled gracefully (return error, not panic).

**Fuzz harness pattern:**
```nim
# fuzz/fuzz_uci_parser.nim
proc fuzzTarget(data: openArray[byte]) =
  let input = cast[string](data)  # raw bytes as string
  try:
    discard parseUciConfig(input)
  except ConfigError:
    discard  # expected for invalid input

when isMainModule:
  # libFuzzer entry point
  {.exportc: "LLVMFuzzerTestOneInput".}
  proc LLVMFuzzerTestOneInput(data: ptr byte, size: csize_t): cint =
    if size > 0:
      fuzzTarget(toOpenArray(data, 0, size.int - 1))
    return 0
```

**When to run:** Before releases and after any changes to parser code. Fuzz corpus should be committed to the repo for reproducibility.

## What not to test

- Don't test that Nim's `json` module serializes correctly. It does.
- Don't test that `posix.socket()` returns a file descriptor. It does.
- Don't test that `selectors.select()` returns ready events. It does.
- Don't test private helper functions that exist only to make the implementation cleaner. Test the public behavior they contribute to.
- Don't test error paths that can't happen (e.g., "what if `mark_mask` is 0" when the config validator already rejects it).

## Test organization

```
tests/
  t_config.nim       -- Tier 1: UCI parsing, validation, diff
  t_state.nim        -- Tier 1: state transitions, dampening, policy
  t_health.nim       -- Tier 1: probe engine cycles, quality window, checksum
  t_nftables.nim     -- Tier 1: chain generation, mark assignment
  t_netlink.nim      -- Tier 2: route/rule/link operations in namespaces
  t_probes.nim       -- Tier 2: ICMP/ARP send/recv across veth pairs
  t_integration.nim  -- Tier 2: nftables application + verification
fuzz/
  fuzz_uci_parser.nim   -- config parser fuzz harness
  fuzz_netlink.nim      -- netlink message parser fuzz harness
  fuzz_icmp.nim         -- ICMP reply parser fuzz harness
  fuzz_dns.nim          -- DNS response parser fuzz harness
  fuzz_arp.nim          -- ARP reply parser fuzz harness
  fuzz_ipc.nim          -- IPC JSON request parser fuzz harness
  corpus/               -- committed seed inputs for reproducibility
```

Tier 3 tests are manual procedures documented in a release checklist, not automated test files.

## Adding tests for new code

**New config option:** Add a parse test (valid value), validation test (invalid value), and diff test (option changed vs unchanged).

**New probe type:** Add Tier 1 tests for packet construction and parsing. Add Tier 2 test for send/receive across veth pair.

**New state transition:** Add Tier 1 test showing the exact sequence of probe results that triggers the transition, the resulting state, and the actions generated.

**New nftables rule pattern:** Add Tier 1 test with a minimal config that produces the rule, assert exact JSON output.
