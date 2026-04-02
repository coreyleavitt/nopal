## Tests for argv[0] dispatch logic.
##
## Verifies isDaemonMode correctly determines CLI vs daemon mode
## based on the program name (symlink-aware) and command-line flags.

import ../src/nopal

# Simple test framework matching the project pattern
var passed = 0
var failed = 0

template test(name: string, body: untyped) =
  block:
    try:
      body
      inc passed
      echo "  PASS: ", name
    except AssertionDefect:
      inc failed
      echo "  FAIL: ", name, " - ", getCurrentExceptionMsg()
    except CatchableError:
      inc failed
      echo "  FAIL: ", name, " - ", getCurrentExceptionMsg()

echo "=== Dispatch (isDaemonMode) tests ==="

test "nopald_path_is_daemon":
  doAssert isDaemonMode("/usr/sbin/nopald", @[]) == true

test "nopal_path_is_cli":
  doAssert isDaemonMode("/usr/sbin/nopal", @[]) == false

test "symlink_nopal_must_not_resolve_to_daemon":
  # The original bug: getAppFilename() resolves symlinks, so
  # nopal -> nopald would always dispatch to daemon mode.
  # isDaemonMode uses argv0 literally, not the resolved path.
  doAssert isDaemonMode("/usr/sbin/nopal", @[]) == false

test "daemon_flag_overrides_name":
  doAssert isDaemonMode("/usr/bin/nopal", @["--daemon"]) == true

test "d_flag_overrides_name":
  doAssert isDaemonMode("/usr/bin/nopal", @["-d"]) == true

test "cli_args_do_not_trigger_daemon":
  doAssert isDaemonMode("/usr/bin/nopal", @["status"]) == false
  doAssert isDaemonMode("/usr/bin/nopal", @["reload"]) == false
  doAssert isDaemonMode("/usr/bin/nopal", @["version"]) == false

test "bare_nopald_is_daemon":
  doAssert isDaemonMode("nopald", @[]) == true

test "bare_nopal_is_cli":
  doAssert isDaemonMode("nopal", @[]) == false

test "unrelated_binary_name_is_cli":
  doAssert isDaemonMode("/usr/bin/nopal-v2", @[]) == false
  doAssert isDaemonMode("something-else", @[]) == false

echo ""
echo "=== Results ==="
echo "  Passed: ", passed
echo "  Failed: ", failed
if failed > 0:
  quit(1)
else:
  echo "  All tests passed!"
