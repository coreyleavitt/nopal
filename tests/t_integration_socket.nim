## Integration tests for socket creation.
## Requires CAP_NET_RAW. Run in privileged CI container.

import std/[posix, strformat]
import ../src/health/icmp
import ../src/health/dns

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

echo "=== Socket creation integration tests ==="

test "icmp_socket_creates_valid_fd_on_loopback":
  let fd = createIcmpSocket("lo", 2, 64)  # AF_INET=2
  doAssert fd >= 0, "createIcmpSocket returned " & $fd
  # Verify it's actually a valid open fd
  let flags = fcntl(fd, F_GETFL)
  doAssert flags >= 0, "fd not valid (fcntl failed)"
  discard posix.close(fd)

test "dns_socket_creates_valid_fd_on_loopback":
  let fd = createDnsSocket("lo", 2)  # AF_INET=2
  doAssert fd >= 0, "createDnsSocket returned " & $fd
  let flags = fcntl(fd, F_GETFL)
  doAssert flags >= 0, "fd not valid (fcntl failed)"
  discard posix.close(fd)

echo ""
echo "=== Results ==="
echo "  Passed: ", passed
echo "  Failed: ", failed
if failed > 0:
  quit(1)
else:
  echo "  All tests passed!"
