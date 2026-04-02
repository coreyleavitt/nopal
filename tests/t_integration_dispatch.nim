## Integration tests for probe dispatch wiring.
## Verifies dispatch functions call real implementations (not stubs).
## Requires CAP_NET_RAW. Run in privileged CI container.

import std/posix
import ../src/health/icmp
import ../src/health/dns
import ../src/health/engine

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

echo "=== Dispatch integration tests ==="

test "dispatchSend_icmp_returns_true_on_loopback":
  # Creates a real ICMP socket, sends a probe to 127.0.0.1.
  # A stub returning false would fail immediately.
  let fd = createIcmpSocket("lo", 2, 64)  # AF_INET=2
  doAssert fd >= 0
  var transport = ProbeTransport(kind: tkIcmp, icmpFd: fd, icmpFamily: 2)
  var target: array[16, byte]
  target[0] = 127; target[3] = 1  # 127.0.0.1
  let ok = dispatchSend(transport, target, false, 1'u16, 1'u16, 56)
  doAssert ok, "dispatchSend ICMP returned false — dispatch may be stubbed"
  dispatchClose(transport)
  doAssert transport.icmpFd == -1, "dispatchClose should set fd to -1"

test "dispatchSend_dns_returns_true_on_loopback":
  # Creates a real DNS socket, sends a probe to 127.0.0.1:53.
  # The send succeeds even if nothing is listening — UDP is fire-and-forget.
  let fd = createDnsSocket("lo", 2)  # AF_INET=2
  doAssert fd >= 0
  var transport = ProbeTransport(kind: tkDns, dnsFd: fd, dnsFamily: 2,
                                  dnsQueryLen: 0)
  # Build a minimal DNS query
  let queryLen = encodeDnsQuery("example.com", transport.dnsQueryBuf)
  transport.dnsQueryLen = queryLen
  var target: array[16, byte]
  target[0] = 127; target[3] = 1
  let ok = dispatchSend(transport, target, false, 1'u16, 1'u16, 56)
  doAssert ok, "dispatchSend DNS returned false — dispatch may be stubbed"
  dispatchClose(transport)
  doAssert transport.dnsFd == -1

test "dispatchClose_sets_fd_to_negative_one":
  let fd = createIcmpSocket("lo", 2, 64)
  doAssert fd >= 0
  var transport = ProbeTransport(kind: tkIcmp, icmpFd: fd, icmpFamily: 2)
  dispatchClose(transport)
  doAssert transport.icmpFd == -1, "fd should be -1 after close"
  # Verify the fd is actually closed (fcntl should fail)
  let flags = fcntl(fd, F_GETFL)
  doAssert flags < 0, "fd should be invalid after close"

echo ""
echo "=== Results ==="
echo "  Passed: ", passed
echo "  Failed: ", failed
if failed > 0:
  quit(1)
else:
  echo "  All tests passed!"
