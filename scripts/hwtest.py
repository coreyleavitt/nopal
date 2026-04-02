#!/usr/bin/env python3
"""Hardware test harness for nopal.

Runs on the OpenWrt device itself. Exercises daemon lifecycle, health probes,
failover, hot reload, and IPC. Uses `nopal status --json` for assertions.

Usage:
    # Install python3 (uses tmpfs overlay, doesn't eat flash)
    apk add python3

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
import re
import subprocess
import sys
import time

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

PASS = 0
FAIL = 0
SKIP = 0


def timestamp():
    """Return HH:MM:SS for log correlation with logread."""
    return time.strftime("%H:%M:%S")


def run(cmd, check=True, capture=True, timeout=60):
    """Run a command, return CompletedProcess."""
    try:
        r = subprocess.run(
            cmd, shell=isinstance(cmd, str),
            capture_output=capture, text=True, timeout=timeout
        )
    except subprocess.TimeoutExpired:
        raise RuntimeError(f"command timed out ({timeout}s): {cmd}")
    if check and r.returncode != 0:
        raise RuntimeError(f"command failed ({r.returncode}): {cmd}\n{r.stderr}")
    return r


def nopal_cmd(args):
    """Run the nopal CLI as a list (no shell injection)."""
    if isinstance(args, str):
        args = args.split()
    return run(["nopal"] + args, check=True)


def nopal_status(iface=None):
    """Get daemon status as parsed JSON."""
    cmd = ["nopal", "status", "--json"]
    if iface:
        cmd.append(iface)
    r = run(cmd, check=True)
    try:
        return json.loads(r.stdout)
    except (json.JSONDecodeError, ValueError) as e:
        raise RuntimeError(f"invalid JSON from 'nopal status --json': {e}\n{r.stdout[:200]}")


def service(action):
    """Control the init service."""
    return run(f"/etc/init.d/nopal {action}")


def get_pid():
    """Get nopald PID, or None if not running."""
    r = run("pidof nopald", check=False)
    if r.returncode != 0:
        return None
    pid = r.stdout.strip().split()[0]
    if not pid.isdigit():
        return None
    return pid


def get_rss_kb(pid):
    """Read VmRSS from /proc directly (no shell piping)."""
    try:
        with open(f"/proc/{pid}/status") as f:
            for line in f:
                if line.startswith("VmRSS:"):
                    return line.strip()
    except (OSError, IOError):
        pass
    return None


def daemon_is_running():
    """Check if nopald is alive."""
    return get_pid() is not None


def wait_for_state(iface, target_state, timeout=120, poll=2):
    """Poll until interface reaches target state or timeout.

    Returns (reached, last_state) — last_state is useful for diagnostics.
    """
    deadline = time.time() + timeout
    last_state = "unknown"
    while time.time() < deadline:
        try:
            if not daemon_is_running():
                return False, "daemon_dead"
            status = nopal_status()
            for i in status.get("interfaces", []):
                if i["name"] == iface:
                    last_state = i["state"]
                    if last_state == target_state:
                        return True, last_state
        except Exception as e:
            last_state = f"error: {e}"
        time.sleep(poll)
    return False, last_state


def log(msg):
    print(f"  [{timestamp()}] {msg}")


def test(name, condition, detail=None, skip_reason=None):
    """Record a test result with optional detail on failure."""
    global PASS, FAIL, SKIP
    if skip_reason:
        SKIP += 1
        print(f"  [{timestamp()}] SKIP  {name} ({skip_reason})")
        return
    if condition:
        PASS += 1
        print(f"  [{timestamp()}] PASS  {name}")
    else:
        FAIL += 1
        extra = f" — got: {detail}" if detail else ""
        print(f"  [{timestamp()}] FAIL  {name}{extra}")


def section(name):
    print(f"\n{'='*60}")
    print(f"  [{timestamp()}] {name}")
    print(f"{'='*60}")


def ensure_daemon():
    """Start daemon if not running. Returns True if running after attempt."""
    if daemon_is_running():
        return True
    log("Starting daemon...")
    r = run("/etc/init.d/nopal start", check=False)
    if r.returncode != 0:
        log(f"init script failed: {r.stderr.strip()}")
        return False
    time.sleep(3)
    return daemon_is_running()


# ---------------------------------------------------------------------------
# Phase 1: Binary and install validation
# ---------------------------------------------------------------------------

def phase1():
    section("Phase 1: Binary and install validation")

    test("nopald exists", os.path.isfile("/usr/sbin/nopald"))
    test("nopal symlink exists", os.path.islink("/usr/sbin/nopal"))

    if os.path.islink("/usr/sbin/nopal"):
        target = os.readlink("/usr/sbin/nopal")
        test("nopal symlink points to nopald", "nopald" in target, detail=target)

    # Check ELF architecture matches device
    r = run("file /usr/sbin/nopald", check=False)
    if r.returncode == 0:
        log(f"binary: {r.stdout.strip()}")
        machine = os.uname().machine
        elf_info = r.stdout.lower()
        # Basic arch sanity: mipsel device should have MIPS ELF, etc.
        if "mips" in machine.lower():
            test("binary matches arch", "mips" in elf_info, detail=elf_info[:80])
        elif "aarch64" in machine.lower():
            test("binary matches arch", "aarch64" in elf_info, detail=elf_info[:80])
        elif "arm" in machine.lower():
            test("binary matches arch", "arm" in elf_info, detail=elf_info[:80])
    else:
        log("'file' command not available, skipping arch check")

    r = run("nopal version", check=False)
    test("nopal version runs", r.returncode == 0,
         detail=r.stderr.strip() if r.returncode != 0 else None)
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
    test("daemon starts", r.returncode == 0,
         detail=r.stderr.strip() if r.returncode != 0 else None)

    time.sleep(3)

    # Check process
    pid = get_pid()
    test("nopald process running", pid is not None)
    if pid:
        log(f"PID: {pid}")

    # Check socket
    test("IPC socket exists", os.path.exists("/var/run/nopal.sock"))

    # Query status
    try:
        status = nopal_status()
        test("nopal status succeeds", True)
        test("status has version", "version" in status)
        test("status has uptime", "uptime_secs" in status)
        test("status has interfaces", "interfaces" in status)
        log(f"version: {status.get('version')}, uptime: {status.get('uptime_secs')}s")
        log(f"interfaces: {len(status.get('interfaces', []))}")
    except RuntimeError as e:
        test("nopal status succeeds", False, detail=str(e))

    # Check memory
    pid = get_pid()
    if pid:
        rss = get_rss_kb(pid)
        if rss:
            log(f"Memory: {rss}")

    # Stop
    log("Stopping daemon...")
    service("stop")
    time.sleep(2)

    test("daemon stopped cleanly", not daemon_is_running())


# ---------------------------------------------------------------------------
# Phase 3: Health probes
# ---------------------------------------------------------------------------

def phase3():
    section("Phase 3: Health probes")

    if not ensure_daemon():
        test("daemon running", False, detail="could not start daemon")
        return

    try:
        status = nopal_status()
    except RuntimeError as e:
        test("fetch status", False, detail=str(e))
        return

    interfaces = status.get("interfaces", [])
    if not interfaces:
        test("has configured interfaces", False, detail="no interfaces in status")
        return

    log(f"Found {len(interfaces)} interface(s)")

    for iface in interfaces:
        name = iface["name"]
        state = iface["state"]
        log(f"\n  Interface: {name}, state: {state}, device: {iface.get('device', '?')}")

        if state == "init":
            log(f"  Waiting for {name} to leave init state...")
            reached, last_state = wait_for_state(name, "probing", timeout=15)
            if not reached:
                # Maybe it went straight to online, or daemon died
                reached_online, last_state = wait_for_state(name, "online", timeout=5)
                if reached_online:
                    state = "online"
                else:
                    test(f"{name}: not stuck in init", False, detail=f"last state: {last_state}")
                    continue
            else:
                state = "probing"

        test(f"{name}: not stuck in init", state != "init", detail=f"state={state}")

        if state == "online":
            test(f"{name}: has success count",
                 iface.get("success_count", 0) > 0,
                 detail=f"success_count={iface.get('success_count', 0)}")
            rtt = iface.get("avg_rtt_ms")
            if rtt is not None and rtt >= 0:
                log(f"  RTT: {rtt}ms")
                test(f"{name}: RTT is reasonable (<1000ms)", rtt < 1000, detail=f"rtt={rtt}")
            loss = iface.get("loss_percent", 0)
            log(f"  Loss: {loss}%")
        elif state == "probing":
            log(f"  Waiting for {name} to come online (up to 60s)...")
            came_online, last_state = wait_for_state(name, "online", timeout=60)
            test(f"{name}: transitions to online", came_online,
                 detail=f"last state: {last_state}")
            if came_online:
                try:
                    updated = nopal_status()
                    for i in updated["interfaces"]:
                        if i["name"] == name:
                            log(f"  RTT: {i.get('avg_rtt_ms', '?')}ms, "
                                f"Loss: {i.get('loss_percent', '?')}%")
                except RuntimeError:
                    pass
        elif state == "offline":
            test(f"{name}: expected online or probing", False, detail=f"state=offline")


# ---------------------------------------------------------------------------
# Phase 4: Failover
# ---------------------------------------------------------------------------

def phase4():
    section("Phase 4: Failover (manual)")

    if not ensure_daemon():
        test("daemon running for failover", False, detail="could not start daemon")
        return

    try:
        status = nopal_status()
    except RuntimeError as e:
        test("fetch status for failover", False, detail=str(e))
        return

    online = [i for i in status["interfaces"] if i["state"] == "online"]

    if len(online) < 2:
        test("has 2+ online interfaces for failover", False,
             skip_reason=f"only {len(online)} online")
        return

    log(f"Online interfaces: {[i['name'] for i in online]}")
    primary = online[0]["name"]

    test("failover preconditions met (2+ WANs online)", True)

    log(f"\n  To test failover:")
    log(f"  1. Note current state: all interfaces online")
    log(f"  2. Disconnect primary WAN ({primary}) - unplug cable")
    log(f"  3. Run: python3 hwtest.py --phase 4wait")
    log(f"     (will poll until {primary} goes offline)")
    log(f"  4. Reconnect and run --phase 4wait again to verify recovery")


def phase4_wait():
    """Called after manual cable disconnect — polls for state change."""
    section("Phase 4: Waiting for state change...")

    if not daemon_is_running():
        test("daemon running", False, detail="nopald not running")
        return

    try:
        status = nopal_status()
    except RuntimeError as e:
        test("fetch initial status", False, detail=str(e))
        return

    log("Current states:")
    seen_states = {}
    for i in status["interfaces"]:
        log(f"  {i['name']}: {i['state']}")
        seen_states[i["name"]] = i["state"]

    log("\nPolling every 5s for 120s...")
    transitions = []
    deadline = time.time() + 120
    while time.time() < deadline:
        try:
            status = nopal_status()
        except RuntimeError:
            log("  Failed to query status (daemon may have crashed)")
            break

        for i in status["interfaces"]:
            key = i["name"]
            state = i["state"]
            prev = seen_states.get(key)
            if prev != state:
                if prev is not None:
                    log(f"  {key}: {prev} -> {state}")
                    transitions.append((key, prev, state))
                seen_states[key] = state

        if transitions:
            log("State change detected!")
            for i in status["interfaces"]:
                log(f"  {i['name']}: {i['state']}")
            break
        time.sleep(5)
    else:
        log("No state change detected within 120s")

    test("observed state transition", len(transitions) > 0,
         detail="no transitions" if not transitions else
         f"{transitions[0][0]}: {transitions[0][1]} -> {transitions[0][2]}")

    # Dump final nftables state
    r = run("nopal rules", check=False)
    if r.returncode == 0:
        log(f"\nActive rules:\n{r.stdout[:500]}")


# ---------------------------------------------------------------------------
# Phase 5: Hot reload
# ---------------------------------------------------------------------------

def phase5():
    section("Phase 5: Hot reload")

    if not ensure_daemon():
        test("daemon running for reload", False, detail="could not start daemon")
        return

    # Get state before reload
    try:
        before = nopal_status()
    except RuntimeError as e:
        test("fetch pre-reload status", False, detail=str(e))
        return

    before_states = {i["name"]: i["state"] for i in before["interfaces"]}
    log(f"Before reload: {before_states}")

    # Reload
    log("Sending reload...")
    r = run("nopal reload", check=False)
    test("reload command succeeds", r.returncode == 0,
         detail=r.stderr.strip() if r.returncode != 0 else None)

    time.sleep(3)

    # Check daemon still running
    test("daemon still running after reload", daemon_is_running())

    # Check states preserved (online/offline should be stable; probing is transient)
    try:
        after = nopal_status()
    except RuntimeError as e:
        test("fetch post-reload status", False, detail=str(e))
        return

    after_states = {i["name"]: i["state"] for i in after["interfaces"]}
    log(f"After reload: {after_states}")

    for name, state in before_states.items():
        if name not in after_states:
            test(f"{name}: still exists after reload", False, detail="interface disappeared")
            continue
        after_state = after_states[name]
        # Online should stay online; offline should stay offline.
        # Probing is transient — probing->online is healthy, not a failure.
        if state in ("online", "offline"):
            test(f"{name}: state preserved ({state})",
                 after_state == state,
                 detail=f"was {state}, now {after_state}")
        else:
            # For transient states, just verify it didn't go backwards
            test(f"{name}: state ok after reload ({state} -> {after_state})",
                 after_state != "init",
                 detail=f"was {state}, now {after_state}")


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
    try:
        print(f"device: {os.uname().machine}")
    except Exception:
        print("device: unknown")

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
            try:
                phases[p]()
            except Exception as e:
                log(f"Phase {p} crashed: {e}")
                global FAIL
                FAIL += 1
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
