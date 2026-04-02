#!/usr/bin/env python3
"""Hardware test harness for nopal.

Runs on the OpenWrt device itself. Exercises daemon lifecycle, health probes,
failover, hot reload, policy routing, and memory stability.
Uses `nopal status --json` for assertions.

Usage:
    # Install python3 (uses tmpfs overlay, doesn't eat flash)
    apk add python3

    # Copy this script to the device and run
    python3 hwtest.py [--phase PHASE]

Phases:
    1      Binary and install validation
    2      Daemon lifecycle (start, status, stop)
    3      Health probes (requires configured WAN)
    4      Failover (requires dual WAN)
    4wait  Poll for state change after manual cable disconnect
    5      Hot reload
    6      Policy routing and connected bypass
    soak   Memory stability (long-running, Ctrl-C to stop)
    all    Run phases 1-6 (default)
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

SOCKET_PATH = "/var/run/nopal.sock"
SAFE_NAME_RE = re.compile(r'^[A-Za-z0-9._-]+$')


def timestamp():
    """Return HH:MM:SS for log correlation with logread."""
    return time.strftime("%H:%M:%S")


def run(cmd, check=True, capture=True, timeout=60):
    """Run a command as a list (no shell). Strings are split into args."""
    if isinstance(cmd, str):
        cmd = cmd.split()
    try:
        r = subprocess.run(
            cmd, capture_output=capture, text=True, timeout=timeout
        )
    except subprocess.TimeoutExpired:
        raise RuntimeError(f"command timed out ({timeout}s): {cmd}")
    if check and r.returncode != 0:
        raise RuntimeError(f"command failed ({r.returncode}): {cmd}\n{r.stderr}")
    return r


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
    """Read VmRSS from /proc directly (no shell piping). Returns int KB or None."""
    try:
        with open(f"/proc/{pid}/status") as f:
            for line in f:
                if line.startswith("VmRSS:"):
                    # "VmRSS:    1234 kB"
                    parts = line.split()
                    if len(parts) >= 2 and parts[1].isdigit():
                        return int(parts[1])
                    return None
    except (OSError, IOError):
        pass
    return None


def daemon_is_running():
    """Check if nopald is alive."""
    return get_pid() is not None


def wait_for_socket(timeout=15):
    """Poll until the IPC socket appears. Returns True if found."""
    deadline = time.time() + timeout
    while time.time() < deadline:
        if os.path.exists(SOCKET_PATH):
            return True
        time.sleep(0.5)
    return False


def wait_for_exit(timeout=10):
    """Poll until nopald process is gone."""
    deadline = time.time() + timeout
    while time.time() < deadline:
        if not daemon_is_running():
            return True
        time.sleep(0.5)
    return False


def wait_for_state(iface, target_states, timeout=120, poll=2):
    """Poll until interface reaches one of the target states or timeout.

    target_states can be a string or list of strings.
    Returns (reached, last_state) — last_state is one of the target states
    on success, or the actual last observed interface state on failure.
    Special values: "daemon_dead", "not_found", "error: ...".
    """
    if isinstance(target_states, str):
        target_states = [target_states]
    deadline = time.time() + timeout
    last_state = "unknown"
    while time.time() < deadline:
        try:
            if not daemon_is_running():
                return False, "daemon_dead"
            status = nopal_status()
            found = False
            for i in status.get("interfaces", []):
                if i["name"] == iface:
                    found = True
                    last_state = i["state"]
                    if last_state in target_states:
                        return True, last_state
            if not found:
                last_state = "not_found"
        except Exception as e:
            last_state = f"error: {e}"
        time.sleep(poll)
    return False, last_state


def check_logs_for_errors(since_lines=None):
    """Check logread for nopal error/critical messages.

    If since_lines is provided, only return errors not in that set.
    Returns list of error lines.
    """
    r = run("logread", check=False)
    if r.returncode != 0:
        return []
    if since_lines is None:
        since_lines = set()
    errors = []
    for line in r.stdout.splitlines():
        low = line.lower()
        if "nopal" in low and any(k in low for k in ["error", "crit", "panic", "segfault"]):
            stripped = line.strip()
            if stripped not in since_lines:
                errors.append(stripped)
    return errors


def get_all_log_lines():
    """Snapshot current logread output for baseline comparison."""
    r = run("logread", check=False)
    if r.returncode != 0:
        return set()
    return set(r.stdout.splitlines())


def is_valid_iface_name(name):
    """Validate interface name is safe for path construction."""
    return bool(SAFE_NAME_RE.match(name))


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
    """Start daemon if not running, wait for socket. Returns True if ready."""
    if daemon_is_running() and os.path.exists(SOCKET_PATH):
        return True
    log("Starting daemon...")
    r = run("/etc/init.d/nopal start", check=False)
    if r.returncode != 0:
        log(f"init script failed: {r.stderr.strip()}")
        return False
    if not wait_for_socket(timeout=15):
        log("Timed out waiting for IPC socket")
        return daemon_is_running()
    return True


def stop_daemon():
    """Stop daemon and wait for process exit."""
    run("/etc/init.d/nopal stop", check=False)
    if not wait_for_exit(timeout=10):
        log("Warning: daemon still running after stop + 10s")
        return False
    return True


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

    r = run(["nopal", "--help"], check=False)
    test("nopal --help runs", r.returncode == 0,
         detail=r.stderr.strip() if r.returncode != 0 else None)

    test("init script exists", os.path.isfile("/etc/init.d/nopal"))
    test("default config exists", os.path.isfile("/etc/config/nopal"))
    test("rpcd plugin exists", os.path.isfile("/usr/libexec/rpcd/nopal"))


# ---------------------------------------------------------------------------
# Phase 2: Daemon lifecycle
# ---------------------------------------------------------------------------

def phase2():
    section("Phase 2: Daemon lifecycle")

    # Make sure it's stopped first
    stop_daemon()

    # Start
    log("Starting daemon...")
    r = run("/etc/init.d/nopal start", check=False)
    test("daemon starts", r.returncode == 0,
         detail=r.stderr.strip() if r.returncode != 0 else None)

    socket_ready = wait_for_socket(timeout=15)
    test("IPC socket appears", socket_ready)

    # Check process
    pid = get_pid()
    test("nopald process running", pid is not None)
    if pid:
        log(f"PID: {pid}")

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
            log(f"Memory: VmRSS {rss} kB")

    # Check for error-level log messages
    errors = check_logs_for_errors()
    test("no error-level log messages", len(errors) == 0,
         detail=f"{len(errors)} errors, first: {errors[0][:100]}" if errors else None)

    # Stop
    log("Stopping daemon...")
    stopped = stop_daemon()
    test("daemon stopped cleanly", stopped)


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

        # Wait for interface to leave init if needed
        if state == "init":
            log(f"  Waiting for {name} to leave init state...")
            reached, new_state = wait_for_state(name, ["probing", "online"], timeout=20)
            if not reached:
                # Only report as "stuck in init" if the actual state is init,
                # not if daemon died or interface disappeared
                is_init = new_state == "init"
                test(f"{name}: not stuck in init", not is_init,
                     detail=f"last state: {new_state}")
                continue
            state = new_state

        test(f"{name}: not stuck in init", state in ("probing", "online", "degraded", "offline"),
             detail=f"state={state}")

        if state == "online":
            # Re-fetch to get current counters
            try:
                fresh = nopal_status()
                found = False
                for i in fresh["interfaces"]:
                    if i["name"] == name:
                        iface = i
                        found = True
                        break
                if not found:
                    log(f"  Warning: {name} disappeared from status on re-fetch")
            except RuntimeError:
                pass
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

    # Check for errors after probe cycle
    errors = check_logs_for_errors()
    if errors:
        log(f"Warning: {len(errors)} error-level log message(s) during probing")
        for e in errors[:3]:
            log(f"  {e[:120]}")


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

    # Capture before-state for comparison
    log("Capturing nftables rules before disconnect...")
    r = run("nopal rules", check=False)
    if r.returncode == 0:
        log(f"Rules (first 300 chars):\n{r.stdout[:300]}")

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

    poll_interval = 5
    log(f"\nPolling every {poll_interval}s for 120s...")
    transitions = []
    deadline = time.time() + 120
    while time.time() < deadline:
        try:
            if not daemon_is_running():
                log("  Daemon died during poll!")
                break
            status = nopal_status()
        except RuntimeError:
            log("  Failed to query status (daemon may have crashed)")
            break

        for i in status["interfaces"]:
            key = i["name"]
            state = i["state"]
            prev = seen_states.get(key)
            if prev is None:
                # New interface appeared
                log(f"  {key}: appeared in state {state}")
                seen_states[key] = state
            elif prev != state:
                log(f"  {key}: {prev} -> {state}")
                transitions.append((key, prev, state))
                seen_states[key] = state

        if transitions:
            log("State change detected!")
            for i in status["interfaces"]:
                log(f"  {i['name']}: {i['state']}")
            break
        time.sleep(poll_interval)
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

    # Wait for socket readiness (reload may briefly disrupt)
    if not wait_for_socket(timeout=10):
        log("Warning: IPC socket did not reappear after reload")

    # Check daemon still running
    test("daemon still running after reload", daemon_is_running())

    # Check states preserved
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
        # Online should stay online.
        # Offline -> probing is legitimate (daemon re-checks on reload).
        # Probing -> online is healthy progression.
        if state == "online":
            test(f"{name}: state preserved ({state})",
                 after_state == "online",
                 detail=f"was {state}, now {after_state}")
        elif state == "offline":
            # offline -> probing is fine (daemon retries on reload)
            test(f"{name}: state ok after reload ({state} -> {after_state})",
                 after_state in ("offline", "probing"),
                 detail=f"was {state}, now {after_state}")
        else:
            # For transient states, just verify it didn't regress to init
            test(f"{name}: state ok after reload ({state} -> {after_state})",
                 after_state != "init",
                 detail=f"was {state}, now {after_state}")


# ---------------------------------------------------------------------------
# Phase 6: Policy routing and connected bypass
# ---------------------------------------------------------------------------

def phase6():
    section("Phase 6: Policy routing and connected bypass")

    if not ensure_daemon():
        test("daemon running for policy test", False, detail="could not start daemon")
        return

    try:
        status = nopal_status()
    except RuntimeError as e:
        test("fetch status", False, detail=str(e))
        return

    # Policies
    policies = status.get("policies", [])
    test("has policies", len(policies) > 0)

    for pol in policies:
        name = pol.get("name", "?")
        members = pol.get("active_members", [])
        tier = pol.get("active_tier", -1)
        log(f"  Policy: {name}, active members: {members}, tier: {tier}")
        test(f"policy '{name}': has active members",
             len(members) > 0,
             detail=f"members={members}")

    # Connected bypass
    try:
        r = run(["nopal", "connected"])
        test("nopal connected succeeds", True)
        if r.stdout.strip():
            lines = r.stdout.strip().splitlines()
            log(f"  Bypass networks: {len(lines)} entries")
            for line in lines[:5]:
                log(f"    {line.strip()}")
    except RuntimeError as e:
        test("nopal connected succeeds", False, detail=str(e))

    # nftables rules
    try:
        r = run(["nopal", "rules"])
        test("nopal rules succeeds", True)
        rules_out = r.stdout
        test("nftables has policy rules",
             "policy" in rules_out.lower() or "nopal" in rules_out.lower(),
             detail=f"output length: {len(rules_out)}")
        log(f"  Rules output: {len(rules_out)} bytes")
    except RuntimeError as e:
        test("nopal rules succeeds", False, detail=str(e))

    # Status files (validate interface names before path construction)
    for iface in status.get("interfaces", []):
        name = iface["name"]
        if not is_valid_iface_name(name):
            log(f"  Warning: skipping status file check for invalid name: {name!r}")
            continue
        status_file = f"/var/run/nopal/{name}/status"
        test(f"{name}: status file exists",
             os.path.isfile(status_file),
             detail=status_file)


# ---------------------------------------------------------------------------
# Soak: Memory stability
# ---------------------------------------------------------------------------

def phase_soak():
    section("Soak: Memory stability test")

    if not ensure_daemon():
        test("daemon running for soak", False, detail="could not start daemon")
        return

    pid = get_pid()
    if not pid:
        test("got daemon PID", False)
        return

    initial_rss = get_rss_kb(pid)
    if initial_rss is None:
        test("read initial RSS", False, detail="could not read /proc/*/status")
        return

    log(f"Initial PID: {pid}, RSS: {initial_rss} kB")
    log("Sampling every 60s. Press Ctrl-C to stop and see results.")
    log("Will also query status and reload periodically to exercise the daemon.\n")

    # Baseline log errors so we only report new ones
    baseline_logs = get_all_log_lines()

    samples = [(time.time(), initial_rss)]
    interval = 60
    iteration = 0

    try:
        while True:
            time.sleep(interval)
            iteration += 1

            # Check daemon is still alive and refresh PID
            pid = get_pid()
            if pid is None:
                log("DAEMON DIED! Soak test aborted.")
                test("daemon survived soak", False, detail=f"died after {iteration} iterations")
                break

            rss = get_rss_kb(pid)
            if rss is None:
                log(f"  [{iteration}] Could not read RSS for PID {pid}")
                continue

            samples.append((time.time(), rss))
            delta = rss - initial_rss
            elapsed_min = (samples[-1][0] - samples[0][0]) / 60
            log(f"  [{iteration}] RSS: {rss} kB (delta: {delta:+d} kB, "
                f"elapsed: {elapsed_min:.0f}m)")

            # Periodically exercise the daemon
            if iteration % 5 == 0:
                try:
                    nopal_status()
                    log(f"  [{iteration}] Status query OK")
                except RuntimeError:
                    log(f"  [{iteration}] Status query FAILED")

            if iteration % 15 == 0:
                r = run("nopal reload", check=False)
                if r.returncode == 0:
                    log(f"  [{iteration}] Reload OK")
                else:
                    log(f"  [{iteration}] Reload FAILED")
                # Refresh PID in case reload caused restart
                new_pid = get_pid()
                if new_pid and new_pid != pid:
                    log(f"  [{iteration}] PID changed after reload: {pid} -> {new_pid}")
                    pid = new_pid

            # Check for NEW error logs only
            new_errors = check_logs_for_errors(since_lines=baseline_logs)
            if new_errors:
                log(f"  [{iteration}] {len(new_errors)} new error-level log messages")
                for e in new_errors[:2]:
                    log(f"    {e[:120]}")

    except KeyboardInterrupt:
        log("\nSoak interrupted by user.")

    if len(samples) >= 2:
        final_rss = samples[-1][1]
        growth = final_rss - initial_rss
        elapsed_min = (samples[-1][0] - samples[0][0]) / 60
        log(f"\nSoak results:")
        log(f"  Duration: {elapsed_min:.0f} minutes, {len(samples)} samples")
        log(f"  Initial RSS: {initial_rss} kB")
        log(f"  Final RSS:   {final_rss} kB")
        log(f"  Growth:      {growth:+d} kB")

        test("memory growth < 100 kB", growth < 100,
             detail=f"grew {growth} kB over {elapsed_min:.0f}m")
    else:
        log("Not enough samples for analysis")
        test("soak ran long enough", False, detail="need at least 2 samples")


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():
    parser = argparse.ArgumentParser(description="nopal hardware test harness")
    parser.add_argument(
        "--phase", default="all",
        help="Phase to run: 1, 2, 3, 4, 4wait, 5, 6, soak, or all"
    )
    args = parser.parse_args()

    print(f"nopal hardware test harness")
    try:
        machine = os.uname().machine
        print(f"device: {machine}")
    except Exception:
        machine = "unknown"
        print(f"device: {machine}")

    phases = {
        "1": phase1,
        "2": phase2,
        "3": phase3,
        "4": phase4,
        "4wait": phase4_wait,
        "5": phase5,
        "6": phase6,
        "soak": phase_soak,
    }

    if args.phase == "all":
        for p in ["1", "2", "3", "4", "5", "6"]:
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
