#!/bin/bash
# Integration test: daemon starts, responds to IPC.
# Requires: nopald binary, nft, CAP_NET_RAW + CAP_NET_ADMIN.
set -uo pipefail

BINARY="${1:-./nopald}"
CFG="/tmp/nopal_ipc_test.cfg"
SOCK="/tmp/nopal_ipc_test.sock"

passed=0
failed=0

pass() { echo "  PASS: $1"; ((passed++)); }
fail() { echo "  FAIL: $1 — $2"; ((failed++)); }

cleanup() {
    killall nopald 2>/dev/null || true
    sleep 1
    rm -f "$CFG" "$SOCK" /etc/config/firewall /etc/config/network
}

echo "=== IPC integration tests ==="
echo "  Binary: $BINARY"

# Setup
cleanup
mkdir -p /etc/config

cat > "$CFG" << 'EOF'
config globals 'globals'
    option enabled '1'
    option ipc_socket '/tmp/nopal_ipc_test.sock'
    option track_method 'ping'
    list track_ip '127.0.0.1'
    option probe_interval '2'
    option probe_timeout '1'
    option up_count '2'
    option down_count '3'
EOF

cat > /etc/config/firewall << 'EOF'
config zone
    option name 'wan'
    option masq '1'
    list network 'testwan'
EOF

cat > /etc/config/network << 'EOF'
config interface 'testwan'
    option device 'lo'
    option proto 'static'
EOF

# Create CLI symlink (must use absolute path, and name must NOT be "nopald")
ABSBINARY="$(realpath "$BINARY")"
ln -sf "$ABSBINARY" /tmp/nopal_cli

# --- Test 1: daemon starts and IPC responds ---
"$BINARY" -c "$CFG" >/dev/null 2>&1 &
DAEMON_PID=$!

# Wait for socket
for i in $(seq 1 30); do
    [ -S "$SOCK" ] && break
    sleep 0.5
done

if [ -S "$SOCK" ]; then
    pass "daemon creates IPC socket"
else
    fail "daemon creates IPC socket" "socket not found after 15s"
    kill $DAEMON_PID 2>/dev/null || true
    exit 1
fi

# Query status
echo "  Querying status via /tmp/nopal_cli..."
STATUS=$(/tmp/nopal_cli status --json -s "$SOCK" 2>&1) || echo "  CLI exit code: $?"
echo "  Status output (first 200 chars): ${STATUS:0:200}"

if echo "$STATUS" | python3 -c "import sys,json; d=json.load(sys.stdin); assert 'version' in d" 2>/dev/null; then
    pass "IPC status has version"
else
    fail "IPC status has version" "$STATUS"
fi

if echo "$STATUS" | python3 -c "import sys,json; d=json.load(sys.stdin); assert len(d['interfaces']) >= 1" 2>/dev/null; then
    pass "IPC status has interfaces"
else
    fail "IPC status has interfaces" "$STATUS"
fi

if echo "$STATUS" | python3 -c "import sys,json; d=json.load(sys.stdin); assert d['interfaces'][0]['device'] == 'lo'" 2>/dev/null; then
    pass "discovered interface uses loopback device"
else
    fail "discovered interface uses loopback device" "$STATUS"
fi

if echo "$STATUS" | python3 -c "import sys,json; d=json.load(sys.stdin); assert len(d['policies']) >= 1" 2>/dev/null; then
    pass "auto-generated policy exists"
else
    fail "auto-generated policy exists" "$STATUS"
fi

# --- Test 2: wait for probes and check online ---
echo ""
echo "  Waiting 10s for probes..."
sleep 10

STATUS=$(/tmp/nopal_cli status --json -s "$SOCK" 2>&1) || true

if echo "$STATUS" | python3 -c "import sys,json; d=json.load(sys.stdin); assert d['interfaces'][0]['success_count'] > 0" 2>/dev/null; then
    pass "probes succeed on loopback"
else
    fail "probes succeed on loopback" "$STATUS"
fi

if echo "$STATUS" | python3 -c "import sys,json; d=json.load(sys.stdin); assert d['interfaces'][0]['state'] in ('online','probing')" 2>/dev/null; then
    pass "interface reaches online or probing"
else
    fail "interface reaches online or probing" "$STATUS"
fi

# Cleanup
kill $DAEMON_PID 2>/dev/null || true
wait $DAEMON_PID 2>/dev/null || true
cleanup

echo ""
echo "=== Results ==="
echo "  Passed: $passed"
echo "  Failed: $failed"
[ $failed -eq 0 ] && echo "  All tests passed!" || exit 1
