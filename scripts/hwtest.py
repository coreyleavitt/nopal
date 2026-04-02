#!/usr/bin/env python3
"""Hardware test harness for nopal.

Runs on the OpenWrt device itself. Exercises daemon lifecycle, health probes,
failover, hot reload, and IPC. Uses `nopal status --json` for assertions.

Usage:
    # Install python3 to tmpfs (doesn't eat flash)
    apk add python3 --root /tmp/py --initdb
    export PATH="/tmp/py/usr/bin:$PATH"

    # Copy this script to the device and run
    python3 hwtest.py [--phase PHASE]

Phases:
    1  Binary and install validation
    2  Daemon lifecycle (start, status, stop)
    3  Health probes (requires configured WAN)
    4  Failover (requires dual WAN)
    5  Hot reload
    all  Run all phases (default)
"""

import argparse
import json
import os
import subprocess
import sys
import time

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

PASS = 0
FAIL = 0
SKIP = 0


def run(cmd, check=True, capture=True, timeout=30):
    """Run a shell command, return stdout."""
    r = subprocess.run(
        cmd, shell=True, capture_output=capture, text=True, timeout=timeout
    )
    if check and r.returncode != 0:
        raise RuntimeError(f"command failed ({r.returncode}): {cmd}\n{r.stderr}")
    return r


def nopal(args="", json_output=False):
    """Run the nopal CLI."""
    cmd = f"nopal {args}"
    if json_output:
        cmd += " --json"
    return run(cmd)


def nopal_status(iface=None):
    """Get daemon status as parsed JSON."""
    cmd = "nopal status --json"
    if iface:
        cmd += f" {iface}"
    r = run(cmd)
    return json.loads(r.stdout)


def service(action):
    """Control the init service."""
    return run(f"/etc/init.d/nopal {action}")


def wait_for_state(iface, target_state, timeout=120, poll=2):
    """Poll until interface reaches target state or timeout."""
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            status = nopal_status()
            for i in status.get("interfaces", []):
                if i["name"] == iface and i["state"] == target_state:
                    return True
        except Exception:
            pass
        time.sleep(poll)
    return False


def log(msg):
    print(f"  {msg}")


def test(name, condition, skip_reason=None):
    """Record a test result."""
    global PASS, FAIL, SKIP
    if skip_reason:
        SKIP += 1
        print(f"  SKIP  {name} ({skip_reason})")
        return
    if condition:
        PASS += 1
        print(f"  PASS  {name}")
    else:
        FAIL += 1
        print(f"  FAIL  {name}")


def section(name):
    print(f"\n{'='*60}")
    print(f"  {name}")
    print(f"{'='*60}")


# ---------------------------------------------------------------------------
# Phase 1: Binary and install validation
# ---------------------------------------------------------------------------

def phase1():
    section("Phase 1: Binary and install validation")

    test("nopald exists", os.path.isfile("/usr/sbin/nopald"))
    test("nopal symlink exists", os.path.islink("/usr/sbin/nopal"))

    if os.path.islink("/usr/sbin/nopal"):
        target = os.readlink("/usr/sbin/nopal")
        test("nopal symlink points to nopald", "nopald" in target)

    r = run("nopal version", check=False)
    test("nopal version runs", r.returncode == 0)
    if r.returncode == 0:
        ver = r.stdout.strip()
        log(f"version: {ver}")
        test("version is not empty", len(ver) > 0)

    test("init script exists", os.path.isfile("/etc/init.d/nopal"))
    test("default config exists", os.path.isfile("/etc/config/nopal"))
    test("rpcd plugin exists", os.path.isfile("/usr/libexec/rpcd/nopal"))


# ---------------------------------------------------------------------------
# Phase 2: Daemon lifecycle
# ---------------------------------------------------------------------------

def phase2():
    section("Phase 2: Daemon lifecycle")

    # Make sure it's stopped first
    run("/etc/init.d/nopal stop", check=False)
    time.sleep(1)

    # Start
    log("Starting daemon...")
    r = run("/etc/init.d/nopal start", check=False)
    test("daemon starts", r.returncode == 0)

    time.sleep(3)

    # Check process
    r = run("pidof nopald", check=False)
    test("nopald process running", r.returncode == 0)
    if r.returncode == 0:
        log(f"PID: {r.stdout.strip()}")

    # Check socket
    test("IPC socket exists", os.path.exists("/var/run/nopal.sock"))

    # Query status
    r = run("nopal status --json", check=False)
    test("nopal status succeeds", r.returncode == 0)
    if r.returncode == 0:
        status = json.loads(r.stdout)
        test("status has version", "version" in status)
        test("status has uptime", "uptime_secs" in status)
        test("status has interfaces", "interfaces" in status)
        log(f"version: {status.get('version')}, uptime: {status.get('uptime_secs')}s")
        log(f"interfaces: {len(status.get('interfaces', []))}")

    # Check memory
    r = run("pidof nopald", check=False)
    if r.returncode == 0:
        pid = r.stdout.strip()
        r2 = run(f"cat /proc/{pid}/status | grep VmRSS", check=False)
        if r2.returncode == 0:
            log(f"Memory: {r2.stdout.strip()}")

    # Stop
    log("Stopping daemon...")
    service("stop")
    time.sleep(2)

    r = run("pidof nopald", check=False)
    test("daemon stopped cleanly", r.returncode != 0)


# ---------------------------------------------------------------------------
# Phase 3: Health probes
# ---------------------------------------------------------------------------

def phase3():
    section("Phase 3: Health probes")

    # Daemon must be running with at least one interface configured
    r = run("pidof nopald", check=False)
    if r.returncode != 0:
        log("Starting daemon...")
        service("start")
        time.sleep(3)

    status = nopal_status()
    interfaces = status.get("interfaces", [])
    if not interfaces:
        test("has configured interfaces", False)
        return

    log(f"Found {len(interfaces)} interface(s)")

    for iface in interfaces:
        name = iface["name"]
        state = iface["state"]
        log(f"\n  Interface: {name}, state: {state}, device: {iface.get('device', '?')}")

        if state == "init":
            log(f"  Waiting for {name} to leave init state...")
            wait_for_state(name, "probing", timeout=15)
            # Refresh
            status = nopal_status()
            for i in status["interfaces"]:
                if i["name"] == name:
                    iface = i
                    state = i["state"]
                    break

        test(f"{name}: not stuck in init", state != "init")

        if state == "online":
            test(f"{name}: has success count", iface.get("success_count", 0) > 0)
            rtt = iface.get("avg_rtt_ms")
            if rtt is not None and rtt >= 0:
                log(f"  RTT: {rtt}ms")
                test(f"{name}: RTT is reasonable (<1000ms)", rtt < 1000)
            loss = iface.get("loss_percent", 0)
            log(f"  Loss: {loss}%")
        elif state == "probing":
            log(f"  Waiting for {name} to come online (up to 60s)...")
            came_online = wait_for_state(name, "online", timeout=60)
            test(f"{name}: transitions to online", came_online)
            if came_online:
                updated = nopal_status()
                for i in updated["interfaces"]:
                    if i["name"] == name:
                        log(f"  RTT: {i.get('avg_rtt_ms', '?')}ms, "
                            f"Loss: {i.get('loss_percent', '?')}%")


# ---------------------------------------------------------------------------
# Phase 4: Failover
# ---------------------------------------------------------------------------

def phase4():
    section("Phase 4: Failover (manual)")

    status = nopal_status()
    online = [i for i in status["interfaces"] if i["state"] == "online"]

    if len(online) < 2:
        test("has 2+ online interfaces for failover", False,
             skip_reason=f"only {len(online)} online")
        return

    log(f"Online interfaces: {[i['name'] for i in online]}")
    primary = online[0]["name"]

    log(f"\n  To test failover:")
    log(f"  1. Note current state: all interfaces online")
    log(f"  2. Disconnect primary WAN ({primary}) - unplug cable")
    log(f"  3. Run: python3 hwtest.py --phase 4wait")
    log(f"     (will poll until {primary} goes offline)")
    log(f"  4. Reconnect and run --phase 4wait again to verify recovery")

    test("failover preconditions met", True)


def phase4_wait():
    """Called after manual cable disconnect — polls for state change."""
    section("Phase 4: Waiting for state change...")

    status = nopal_status()
    log("Current states:")
    for i in status["interfaces"]:
        log(f"  {i['name']}: {i['state']}")

    log("\nPolling every 5s for 120s...")
    seen_states = {}
    deadline = time.time() + 120
    while time.time() < deadline:
        status = nopal_status()
        changed = False
        for i in status["interfaces"]:
            key = i["name"]
            state = i["state"]
            prev = seen_states.get(key)
            if prev != state:
                if prev is not None:
                    log(f"  {key}: {prev} -> {state}")
                    changed = True
                seen_states[key] = state
        if changed:
            log("State change detected!")
            for i in status["interfaces"]:
                log(f"  {i['name']}: {i['state']}")
            break
        time.sleep(5)
    else:
        log("No state change detected within 120s")

    # Dump final nftables state
    r = run("nopal rules", check=False)
    if r.returncode == 0:
        log(f"\nActive rules:\n{r.stdout[:500]}")


# ---------------------------------------------------------------------------
# Phase 5: Hot reload
# ---------------------------------------------------------------------------

def phase5():
    section("Phase 5: Hot reload")

    r = run("pidof nopald", check=False)
    if r.returncode != 0:
        log("Starting daemon...")
        service("start")
        time.sleep(3)

    # Get state before reload
    before = nopal_status()
    before_states = {i["name"]: i["state"] for i in before["interfaces"]}
    log(f"Before reload: {before_states}")

    # Reload
    log("Sending reload...")
    r = run("nopal reload", check=False)
    test("reload command succeeds", r.returncode == 0)

    time.sleep(3)

    # Check daemon still running
    r = run("pidof nopald", check=False)
    test("daemon still running after reload", r.returncode == 0)

    # Check states preserved
    after = nopal_status()
    after_states = {i["name"]: i["state"] for i in after["interfaces"]}
    log(f"After reload: {after_states}")

    for name, state in before_states.items():
        if name in after_states:
            preserved = after_states[name] == state
            test(f"{name}: state preserved ({state})", preserved)


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():
    parser = argparse.ArgumentParser(description="nopal hardware test harness")
    parser.add_argument(
        "--phase", default="all",
        help="Phase to run: 1, 2, 3, 4, 4wait, 5, or all"
    )
    args = parser.parse_args()

    print(f"nopal hardware test harness")
    print(f"device: {os.uname().machine}")

    phases = {
        "1": phase1,
        "2": phase2,
        "3": phase3,
        "4": phase4,
        "4wait": phase4_wait,
        "5": phase5,
    }

    if args.phase == "all":
        for p in ["1", "2", "3", "4", "5"]:
            phases[p]()
    elif args.phase in phases:
        phases[args.phase]()
    else:
        print(f"Unknown phase: {args.phase}")
        sys.exit(1)

    print(f"\n{'='*60}")
    print(f"  Results: {PASS} passed, {FAIL} failed, {SKIP} skipped")
    print(f"{'='*60}")

    sys.exit(1 if FAIL > 0 else 0)


if __name__ == "__main__":
    main()
