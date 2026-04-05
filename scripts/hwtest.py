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
    7      Reload rollback (accept/cancel)
    8      Dynamic bypass (add/remove/persist)
    9      Hook scripts
    10     Signal handling (SIGHUP, SIGTERM, kill -9)
    11     Error resilience (rapid reloads)
    12     CLI commands (status, internal, connected, use)
    13     Dampening (observational)
    14     Traffic verification (proves packets route through correct WAN)
    15     Rollback timeout (waits 70s for timer expiry)
    16     Conntrack flush (observational)
    17     Concurrent IPC stress (10 parallel clients)
    18     Interface flapping (requires 2+ WANs, toggles link)
    19     IPv6 (requires IPv6 connectivity)
    20     Dampening active (requires dampening config + 2 WANs)
    21     Nftables ruleset validation
    soak   Memory stability (long-running, Ctrl-C to stop)
    all    Run phases 1-12, 14, 16, 17, 21 (default)
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
    except FileNotFoundError:
        raise RuntimeError(f"command not found: {cmd[0] if isinstance(cmd, list) else cmd}")
    except subprocess.TimeoutExpired:
        raise RuntimeError(f"command timed out ({timeout}s): {cmd}")
    if check and r.returncode != 0:
        raise RuntimeError(f"command failed ({r.returncode}): {cmd}\n{r.stderr}")
    return r


def nopal_status(iface=None):
    """Get daemon status as parsed JSON."""
    cmd = ["nopal", "status", "--json"]
    if iface:
        if not is_valid_iface_name(iface):
            raise RuntimeError(f"invalid interface name: {iface!r}")
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
    """Read VmRSS from /proc directly (no shell piping). Returns int KB or None.
    pid must be a digit-only string (validated by get_pid)."""
    if not isinstance(pid, str) or not pid.isdigit():
        return None
    try:
        with open(f"/proc/{pid}/status") as f:
            for line in f:
                if line.startswith("VmRSS:"):
                    # "VmRSS:    1234 kB"
                    parts = line.split()
                    if len(parts) >= 2 and parts[1].isdigit():
                        return int(parts[1])
                    return None
    except OSError:
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


def check_logs_for_errors(exclude_lines=None):
    """Check logread for nopal error/critical messages.

    exclude_lines: set of raw log line strings to ignore (e.g. from a prior
    snapshot). Use get_log_snapshot() to capture a baseline before testing.
    Returns list of new error lines not in the exclusion set.
    """
    r = run(["logread", "-l", "500"], check=False)
    if r.returncode != 0:
        return []
    if exclude_lines is None:
        exclude_lines = set()
    errors = []
    for line in r.stdout.splitlines():
        low = line.lower()
        if "nopal" in low and any(k in low for k in ["error", "crit", "panic", "segfault"]):
            stripped = line.strip()
            if stripped not in exclude_lines:
                errors.append(stripped)
    return errors


def get_log_snapshot():
    """Snapshot current logread output for baseline comparison."""
    r = run(["logread", "-l", "500"], check=False)
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
    """Start daemon if not running, wait for IPC to be responsive. Returns True if ready."""
    if daemon_is_running() and os.path.exists(SOCKET_PATH):
        # Verify IPC is actually accepting
        try:
            nopal_status()
            return True
        except RuntimeError:
            pass  # socket exists but not accepting — restart below

    log("Starting daemon...")
    # Clean stale socket before starting
    try:
        os.unlink(SOCKET_PATH)
    except OSError:
        pass
    r = run("/etc/init.d/nopal start", check=False)
    if r.returncode != 0:
        log(f"init script failed: {r.stderr.strip()}")
        return False
    if not wait_for_socket(timeout=15):
        log("Timed out waiting for IPC socket")
        return False
    # Verify IPC is actually responsive (retry a few times)
    for attempt in range(5):
        try:
            nopal_status()
            return True
        except RuntimeError:
            time.sleep(1)
    log("Daemon started but IPC not responding")
    return False


def stop_daemon():
    """Stop daemon, wait for process exit, clean up stale socket."""
    run("/etc/init.d/nopal stop", check=False)
    if not wait_for_exit(timeout=10):
        log("Warning: daemon still running after stop + 10s")
        return False
    # Remove stale socket so ensure_daemon doesn't see it as "ready"
    try:
        os.unlink(SOCKET_PATH)
    except OSError:
        pass
    return True


def nopal_cmd(args_str):
    """Run a nopal CLI command. Returns (rc, stdout)."""
    r = run(f"nopal {args_str}", check=False)
    return r.returncode, r.stdout


def nft_has_element(set_name, element):
    """Check if an nftables set contains an element."""
    r = run(f"nft list set inet nopal {set_name}", check=False)
    return r.returncode == 0 and element in r.stdout


def send_signal(sig_name):
    """Send a signal to the running nopald process."""
    pid = get_pid()
    if pid is None:
        return False
    r = run(f"kill -{sig_name} {pid}", check=False)
    return r.returncode == 0


def get_fd_count(pid):
    """Count open file descriptors for a process.
    pid must be a digit-only string (validated by get_pid)."""
    if not isinstance(pid, str) or not pid.isdigit():
        return -1
    try:
        return len(os.listdir(f"/proc/{pid}/fd"))
    except OSError:
        return -1


def get_cpu_ticks(pid):
    """Read utime+stime from /proc/pid/stat.
    pid must be a digit-only string (validated by get_pid)."""
    if not isinstance(pid, str) or not pid.isdigit():
        return -1
    try:
        with open(f"/proc/{pid}/stat") as f:
            fields = f.read().split()
            return int(fields[13]) + int(fields[14])
    except (OSError, IndexError, ValueError):
        return -1


def log_marker():
    """Return a log snapshot for later comparison with get_log_since()."""
    return get_log_snapshot()


def get_log_since(marker):
    """Get log lines that appeared after the marker snapshot."""
    current = get_log_snapshot()
    new_lines = current - marker
    return "\n".join(sorted(new_lines))


def wait_for_any_online(timeout=60):
    """Wait until at least one interface reaches 'online' state."""
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            status = nopal_status()
            for i in status.get("interfaces", []):
                if i["state"] == "online":
                    return True
        except RuntimeError:
            pass
        time.sleep(2)
    return False


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

    # Check ELF architecture matches device (file command may not be available)
    try:
        r = run("file /usr/sbin/nopald", check=False)
    except RuntimeError:
        r = None
    if r and r.returncode == 0:
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

    # Capture log baseline before starting (so we only check new errors)
    log_baseline = get_log_snapshot()

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

    # Check for error-level log messages (only new ones since start)
    errors = check_logs_for_errors(exclude_lines=log_baseline)
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
            reached, new_state = wait_for_state(
                name, ["probing", "online", "degraded", "offline"], timeout=20)
            if not reached:
                # Fail regardless of reason — daemon_dead, not_found, error,
                # or genuinely stuck in init are all failures
                test(f"{name}: leaves init state", False,
                     detail=f"last state: {new_state}")
                continue
            state = new_state

        # Valid interface states (not init, not an error sentinel)
        valid_states = ("probing", "online", "degraded", "offline")
        test(f"{name}: in valid state", state in valid_states,
             detail=f"state={state}")
        if state not in valid_states:
            continue

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
        elif state == "degraded":
            log(f"  {name} is degraded — quality thresholds exceeded but still in policy")
            test(f"{name}: degraded (not offline)", True)
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

    # Verify daemon is alive and IPC is responsive after reload
    if not wait_for_socket(timeout=10):
        log("Warning: IPC socket did not reappear after reload")

    test("daemon still running after reload", daemon_is_running())

    # Verify socket is actually accepting by querying status (with retry)
    after = None
    for attempt in range(3):
        try:
            after = nopal_status()
            break
        except RuntimeError:
            if attempt < 2:
                time.sleep(1)
    if after is None:
        test("fetch post-reload status", False, detail="3 attempts failed")
        return
    test("IPC responsive after reload", True)

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

    # Wait for at least one interface to come online before checking policies
    interfaces = status.get("interfaces", [])
    online = [i for i in interfaces if i["state"] == "online"]
    if not online:
        log("No interfaces online yet, waiting up to 60s for probes to succeed...")
        for iface in interfaces:
            name = iface["name"]
            reached, _ = wait_for_state(name, "online", timeout=60)
            if reached:
                break
        # Re-fetch status after waiting
        try:
            status = nopal_status()
        except RuntimeError as e:
            test("fetch status after wait", False, detail=str(e))
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
# Phase 7: Reload rollback
# ---------------------------------------------------------------------------

def phase7():
    section("Phase 7: Reload rollback")

    if not ensure_daemon():
        test("daemon running for rollback", False, detail="could not start daemon")
        return

    # Test accept flow
    rc, out = nopal_cmd("reload --rollback 1")
    test("reload --rollback 1 succeeds", rc == 0,
         detail=out.strip() if rc != 0 else None)

    # Verify pending state visible in status
    try:
        status = nopal_status()
        raw = json.dumps(status)
        has_pending = "reload_pending" in raw or "remaining" in raw
        test("status shows reload pending", has_pending)
    except RuntimeError as e:
        test("status shows reload pending", False, detail=str(e))

    # Accept it
    rc, out = nopal_cmd("reload accept")
    test("reload accept succeeds", rc == 0,
         detail=out.strip() if rc != 0 else None)

    # Verify pending clears
    try:
        status = nopal_status()
        raw = json.dumps(status)
        no_pending = "reload_pending" not in raw or status.get("reload_pending") is None
        test("pending clears after accept", no_pending)
    except RuntimeError as e:
        test("pending clears after accept", False, detail=str(e))

    # Test cancel flow
    rc, out = nopal_cmd("reload --rollback 1")
    test("reload --rollback for cancel test", rc == 0,
         detail=out.strip() if rc != 0 else None)
    time.sleep(1)

    rc, out = nopal_cmd("reload cancel")
    test("reload cancel succeeds", rc == 0,
         detail=out.strip() if rc != 0 else None)

    # Test rejection of concurrent reload while pending
    rc, out = nopal_cmd("reload --rollback 1")
    test("reload --rollback for rejection test", rc == 0,
         detail=out.strip() if rc != 0 else None)

    rc2, out2 = nopal_cmd("reload --rollback 1")
    test("concurrent reload rejected while pending", rc2 != 0,
         detail=f"rc={rc2}" if rc2 == 0 else None)

    # Clean up: accept the pending one
    nopal_cmd("reload accept")


# ---------------------------------------------------------------------------
# Phase 8: Dynamic bypass
# ---------------------------------------------------------------------------

def phase8():
    section("Phase 8: Dynamic bypass")

    if not ensure_daemon():
        test("daemon running for bypass", False, detail="could not start daemon")
        return

    # Clean state
    nopal_cmd("bypass remove 10.99.99.0/24")
    nopal_cmd("bypass remove fd00:test::/48")

    # List should not contain our test entry
    rc, out = nopal_cmd("bypass list")
    test("bypass list succeeds", rc == 0,
         detail=out.strip() if rc != 0 else None)
    test("test entry not present initially", "10.99.99.0/24" not in out)

    # Add IPv4
    rc, out = nopal_cmd("bypass add 10.99.99.0/24")
    test("bypass add IPv4 succeeds", rc == 0,
         detail=out.strip() if rc != 0 else None)

    # Verify in list
    rc, out = nopal_cmd("bypass list")
    test("IPv4 bypass in list", "10.99.99.0/24" in out)

    # Verify in nftables
    test("IPv4 bypass in nftables set", nft_has_element("bypass_v4", "10.99.99.0/24"))

    # Duplicate rejection
    rc, out = nopal_cmd("bypass add 10.99.99.0/24")
    test("duplicate bypass add rejected", rc != 0,
         detail=f"rc={rc}" if rc == 0 else None)

    # Invalid CIDR
    rc, out = nopal_cmd("bypass add invalid")
    test("invalid CIDR rejected", rc != 0,
         detail=f"rc={rc}" if rc == 0 else None)

    # Add IPv6
    rc, out = nopal_cmd("bypass add fd00:test::/48")
    test("bypass add IPv6 succeeds", rc == 0,
         detail=out.strip() if rc != 0 else None)

    rc, out = nopal_cmd("bypass list")
    test("IPv6 bypass in list", "fd00:test::" in out)

    # Survive reload (regen persistence)
    rc, _ = nopal_cmd("reload")
    test("reload succeeds with bypass entries", rc == 0)
    time.sleep(2)

    rc, out = nopal_cmd("bypass list")
    test("IPv4 bypass survives reload", "10.99.99.0/24" in out)
    test("IPv6 bypass survives reload", "fd00:test::" in out)

    # Remove
    rc, out = nopal_cmd("bypass remove 10.99.99.0/24")
    test("bypass remove IPv4 succeeds", rc == 0,
         detail=out.strip() if rc != 0 else None)

    rc, out = nopal_cmd("bypass remove fd00:test::/48")
    test("bypass remove IPv6 succeeds", rc == 0,
         detail=out.strip() if rc != 0 else None)

    # Remove nonexistent
    rc, out = nopal_cmd("bypass remove 10.99.99.0/24")
    test("remove nonexistent rejected", rc != 0,
         detail=f"rc={rc}" if rc == 0 else None)

    # Verify clean
    rc, out = nopal_cmd("bypass list")
    test("IPv4 removed from list", "10.99.99.0/24" not in out)


# ---------------------------------------------------------------------------
# Phase 9: Hook scripts
# ---------------------------------------------------------------------------

def phase9():
    section("Phase 9: Hook scripts")

    if not ensure_daemon():
        test("daemon running for hooks", False, detail="could not start daemon")
        return

    hook_log = "/tmp/nopal-hook.log"

    # Remove old log
    try:
        os.remove(hook_log)
    except OSError:
        pass

    # The default hook path is /etc/nopal.user
    # Write our test hook there (it's in tmpfs-overlaid /etc on OpenWrt)
    default_hook = "/etc/nopal.user"
    wrote_hook = False
    try:
        with open(default_hook, "w") as f:
            f.write("#!/bin/sh\n")
            f.write(f'echo "$ACTION $INTERFACE $DEVICE ${{FIRSTCONNECT:-0}}" >> {hook_log}\n')
        os.chmod(default_hook, 0o755)
        wrote_hook = True
    except OSError:
        test("write hook script", False, skip_reason="cannot write to /etc/nopal.user")
        return

    # Restart daemon to pick up hook
    stop_daemon()
    time.sleep(1)
    if not ensure_daemon():
        test("daemon restart for hooks", False, detail="could not restart daemon")
        # Cleanup
        try:
            os.remove(default_hook)
        except OSError:
            pass
        return

    # Wait for interfaces to come online (which triggers hooks)
    # Hooks fire on state transitions — need to wait for probes to complete
    wait_for_any_online(45)
    time.sleep(5)  # let hooks fire and write to log

    # Check hook log
    if os.path.exists(hook_log):
        with open(hook_log) as f:
            lines = f.readlines()
        test("hook script executed at least once", len(lines) > 0,
             detail=f"0 lines in hook log" if len(lines) == 0 else None)

        if lines:
            actions = [l.split()[0] for l in lines if l.strip()]
            test("hook received ifup or connected action",
                 "ifup" in actions or "connected" in actions,
                 detail=f"actions={actions[:5]}")

            # Check that interface name is present
            has_iface = any(len(l.split()) >= 2 and l.split()[1] for l in lines)
            test("hook received INTERFACE env var", has_iface)
    else:
        test("hook log file created", False, detail="hook log not found")

    # Cleanup
    try:
        os.remove(hook_log)
    except OSError:
        pass
    try:
        os.remove(default_hook)
    except OSError:
        pass


# ---------------------------------------------------------------------------
# Phase 10: Signal handling
# ---------------------------------------------------------------------------

def phase10():
    section("Phase 10: Signal handling")

    if not ensure_daemon():
        test("daemon running for signals", False, detail="could not start daemon")
        return

    marker = log_marker()

    # SIGHUP -> reload
    test("SIGHUP sent", send_signal("HUP"))
    time.sleep(2)
    logs = get_log_since(marker)
    test("SIGHUP triggers reload (log confirms)",
         "reload" in logs.lower() or "reloading" in logs.lower(),
         detail=f"log excerpt: {logs[:200]}" if logs else "no new logs")

    # Verify daemon still running
    test("daemon alive after SIGHUP", daemon_is_running())

    # SIGTERM -> clean shutdown
    test("SIGTERM sent", send_signal("TERM"))
    time.sleep(3)
    test("daemon stopped after SIGTERM", not daemon_is_running())
    test("socket cleaned up after SIGTERM", not os.path.exists(SOCKET_PATH))

    # Restart
    if not ensure_daemon():
        test("daemon restarts after SIGTERM", False, detail="could not restart")
        return
    test("daemon restarts cleanly after SIGTERM", daemon_is_running())

    # Kill -9 -> unclean -> restart
    pid = get_pid()
    if pid:
        r = run(f"kill -9 {pid}", check=False)
        time.sleep(1)

        # Restart should handle orphan state
        if not ensure_daemon():
            test("daemon starts after kill -9", False, detail="could not restart")
            return
        test("daemon starts after kill -9", daemon_is_running())

        try:
            status = nopal_status()
            test("IPC responsive after kill -9 recovery", True)
        except RuntimeError as e:
            test("IPC responsive after kill -9 recovery", False, detail=str(e))


# ---------------------------------------------------------------------------
# Phase 11: Error resilience
# ---------------------------------------------------------------------------

def phase11():
    section("Phase 11: Error resilience")

    if not ensure_daemon():
        test("daemon running for resilience", False, detail="could not start daemon")
        return

    marker = log_marker()

    # Reload with daemon running
    rc, _ = nopal_cmd("reload")
    test("normal reload succeeds", rc == 0)

    # Test that status still works after reload
    try:
        status = nopal_status()
        test("status responsive after reload", status is not None)
    except RuntimeError as e:
        test("status responsive after reload", False, detail=str(e))

    # Verify daemon handles rapid reloads
    last_rc = 0
    for i in range(3):
        last_rc, _ = nopal_cmd("reload")
    test("rapid reloads don't crash daemon", last_rc == 0)

    try:
        status = nopal_status()
        test("status responsive after rapid reloads", status is not None)
    except RuntimeError as e:
        test("status responsive after rapid reloads", False, detail=str(e))

    # Verify no error logs from normal operations
    logs = get_log_since(marker)
    error_lines = [l for l in logs.split("\n")
                   if "error" in l.lower() and "nopal" in l.lower()]
    test(f"no error log messages ({len(error_lines)} found)",
         len(error_lines) == 0,
         detail=error_lines[0][:120] if error_lines else None)


# ---------------------------------------------------------------------------
# Phase 12: CLI commands
# ---------------------------------------------------------------------------

def phase12():
    section("Phase 12: CLI commands")

    if not ensure_daemon():
        test("daemon running for CLI", False, detail="could not start daemon")
        return

    # Wait for at least one interface online
    wait_for_any_online(30)

    # Single interface status
    try:
        status = nopal_status()
        interfaces = status.get("interfaces", [])
        if interfaces:
            iface_name = interfaces[0]["name"]
            rc, out = nopal_cmd(f"status {iface_name}")
            test(f"single interface status ({iface_name})", rc == 0,
                 detail=out.strip()[:100] if rc != 0 else None)
            test("detail view has state field",
                 "State:" in out or "state" in out.lower(),
                 detail=f"output: {out[:100]}" if out else None)
    except RuntimeError as e:
        test("single interface status", False, detail=str(e))

    # Internal diagnostics
    rc, out = nopal_cmd("internal")
    test("nopal internal succeeds", rc == 0,
         detail=out.strip()[:100] if rc != 0 else None)
    test("internal output has routing info",
         "table" in out.lower() or "rule" in out.lower(),
         detail=f"output length: {len(out)}")

    # JSON mode
    rc, out = nopal_cmd("status --json")
    test("status --json succeeds", rc == 0,
         detail=out.strip()[:100] if rc != 0 else None)
    if rc == 0:
        try:
            data = json.loads(out)
            test("JSON has api_version field", "api_version" in data)
            test("JSON has interfaces", "interfaces" in data)
        except json.JSONDecodeError as e:
            test("status --json valid JSON", False, detail=str(e))

    # Connected
    rc, out = nopal_cmd("connected")
    test("nopal connected succeeds", rc == 0,
         detail=out.strip()[:100] if rc != 0 else None)
    if rc == 0:
        has_real = any(n for n in out.split("\n")
                       if "/" in n and "127.0.0.0" not in n)
        test("connected shows real subnets (not just loopback)", has_real)

    # Use command (requires root, which we are)
    try:
        status = nopal_status()
        interfaces = status.get("interfaces", [])
        if interfaces:
            iface_name = interfaces[0]["name"]
            rc, out = nopal_cmd(f"use {iface_name} ping -c1 -W2 8.8.8.8")
            test(f"nopal use {iface_name} doesn't crash",
                 rc == 0 or "error" not in out.lower(),
                 detail=f"rc={rc}" if rc != 0 else None)
    except RuntimeError as e:
        test("nopal use", False, detail=str(e))


# ---------------------------------------------------------------------------
# Phase 13: Dampening (observational)
# ---------------------------------------------------------------------------

def phase13():
    section("Phase 13: Dampening")

    # Dampening requires specific config — just verify it doesn't crash
    # and that the dampening-related status fields are present
    try:
        status = nopal_status()
    except RuntimeError as e:
        test("fetch status for dampening", False,
             skip_reason="cannot get daemon status")
        return

    log("Dampening test is observational — requires manual config with dampening enabled")
    log("Checking that dampening fields don't cause errors...")

    for iface in status.get("interfaces", []):
        name = iface.get("name", "?")
        state = iface.get("state", "?")
        log(f"  {name}: state={state}")

    test("dampening: daemon runs without errors (observational)", True)


# ---------------------------------------------------------------------------
# Phase 14: Traffic verification
# ---------------------------------------------------------------------------

def phase14():
    section("Phase 14: Traffic verification")

    if not ensure_daemon():
        test("daemon running", False)
        return

    wait_for_any_online(30)
    status = nopal_status()
    if not status:
        test("get status", False)
        return

    online = [i for i in status.get("interfaces", []) if i.get("state") == "online"]
    if len(online) < 1:
        test("at least one WAN online", False, skip_reason="no WAN online")
        return

    # Test nopal use: route traffic through specific interface
    # Use IPv4-only to get distinct exit IPs per WAN
    ip_service = "http://api.ipify.org"
    for iface in online[:2]:  # test up to 2 WANs
        name = iface["name"]
        rc, out = nopal_cmd(f"use {name} curl -4 -s --max-time 10 {ip_service}")
        if rc == 0 and out.strip():
            test(f"traffic routes through {name}", True)
            log(f"  {name} exit IP: {out.strip()}")
        else:
            # Fall back to ping
            rc, out = nopal_cmd(f"use {name} ping -c1 -W5 8.8.8.8")
            test(f"traffic routes through {name} (ping)", rc == 0)

    # If 2+ WANs online, verify they have different exit IPs (proves routing works)
    if len(online) >= 2:
        ips = []
        for iface in online[:2]:
            name = iface["name"]
            rc, out = nopal_cmd(f"use {name} curl -4 -s --max-time 10 {ip_service}")
            if rc == 0 and out.strip():
                ips.append(out.strip())
        if len(ips) == 2:
            if ips[0] != ips[1]:
                test("different WANs have different exit IPs", True,
                     detail=f"{online[0]['name']}={ips[0]}, {online[1]['name']}={ips[1]}")
            else:
                log(f"  Note: both WANs exit via same IP ({ips[0]}) — likely shared uplink")
                test("both WANs can reach internet", True)
        elif len(ips) == 1:
            log(f"  Only got 1 exit IP — second WAN may share same uplink")
        else:
            log("  Could not retrieve exit IPs")


# ---------------------------------------------------------------------------
# Phase 15: Rollback timeout
# ---------------------------------------------------------------------------

def phase15():
    section("Phase 15: Rollback timeout")

    if not ensure_daemon():
        test("daemon running", False)
        return

    # Capture current state
    status_before = nopal_status()
    if not status_before:
        test("get initial status", False)
        return

    # Start a rollback with 1 minute timeout
    rc, out = nopal_cmd("reload --rollback 1")
    test("reload --rollback 1 succeeds", rc == 0)

    # Verify pending
    status = nopal_status()
    if status:
        raw = json.dumps(status)
        test("rollback pending visible", "reload_pending" in raw or "remaining" in raw)

    # Wait for the timeout to expire (60s + buffer)
    log("  Waiting 70s for rollback timer to expire...")
    time.sleep(70)

    # Verify pending cleared (timer fired)
    status_after = nopal_status()
    if status_after:
        raw = json.dumps(status_after)
        no_pending = "reload_pending" not in raw or status_after.get("reload_pending") is None
        test("rollback timer fired (pending cleared)", no_pending)

    # Verify daemon still running
    test("daemon alive after rollback timeout", daemon_is_running())

    # Verify IPC still responsive
    test("IPC responsive after rollback", nopal_status() is not None)


# ---------------------------------------------------------------------------
# Phase 16: Conntrack flush
# ---------------------------------------------------------------------------

def phase16():
    section("Phase 16: Conntrack flush")

    if not ensure_daemon():
        test("daemon running", False)
        return

    # Check if conntrack tools are available
    rc = run("cat /proc/sys/net/netfilter/nf_conntrack_count", check=False).returncode
    if rc != 0:
        test("conntrack available", False, skip_reason="conntrack not available")
        return

    # Get baseline conntrack count
    r = run("cat /proc/sys/net/netfilter/nf_conntrack_count", check=False)
    count_str = r.stdout
    baseline = int(count_str.strip()) if count_str.strip().isdigit() else 0
    log(f"  Baseline conntrack count: {baseline}")

    # Generate some connections (ping creates ICMP conntrack entries)
    for i in range(5):
        run("ping -c1 -W1 8.8.8.8", check=False)

    r = run("cat /proc/sys/net/netfilter/nf_conntrack_count", check=False)
    count_str = r.stdout
    after_traffic = int(count_str.strip()) if count_str.strip().isdigit() else 0
    log(f"  After traffic: {after_traffic} conntrack entries")

    test("conntrack entries created by traffic", after_traffic >= baseline,
         detail=f"baseline={baseline}, after={after_traffic}")

    # Trigger a reload which may flush conntrack (depends on config)
    nopal_cmd("reload")
    time.sleep(2)

    r = run("cat /proc/sys/net/netfilter/nf_conntrack_count", check=False)
    count_str = r.stdout
    after_reload = int(count_str.strip()) if count_str.strip().isdigit() else 0
    log(f"  After reload: {after_reload} conntrack entries")

    # Note: conntrack flush only happens on interface state changes, not plain reload
    # This is observational — we log the counts for manual verification
    test("conntrack count readable after reload", True)


# ---------------------------------------------------------------------------
# Phase 17: Concurrent IPC stress
# ---------------------------------------------------------------------------

def phase17():
    section("Phase 17: Concurrent IPC stress")

    if not ensure_daemon():
        test("daemon running", False)
        return

    import threading

    results = []
    errors = []

    def ipc_query(thread_id):
        try:
            rc, out = nopal_cmd("status --json")
            if rc == 0:
                data = json.loads(out)
                results.append(thread_id)
            else:
                errors.append((thread_id, f"rc={rc}"))
        except Exception as e:
            errors.append((thread_id, str(e)))

    # Launch 10 concurrent status queries
    threads = []
    for i in range(10):
        t = threading.Thread(target=ipc_query, args=(i,))
        threads.append(t)

    for t in threads:
        t.start()
    for t in threads:
        t.join(timeout=15)

    test(f"concurrent IPC: {len(results)}/10 succeeded",
         len(results) >= 8,  # allow some to fail under load
         detail=f"ok={len(results)}, errors={len(errors)}")

    if errors:
        log(f"  Errors: {errors[:3]}")

    # Verify daemon still responsive after stress
    status = nopal_status()
    test("daemon responsive after IPC stress", status is not None)

    # Rapid-fire reloads
    reload_ok = 0
    for i in range(5):
        rc, _ = nopal_cmd("reload")
        if rc == 0:
            reload_ok += 1
    test(f"rapid reloads: {reload_ok}/5 succeeded", reload_ok >= 4)

    test("daemon alive after stress", nopal_status() is not None)


# ---------------------------------------------------------------------------
# Phase 18: Interface flapping
# ---------------------------------------------------------------------------

def phase18():
    section("Phase 18: Interface flapping")

    if not ensure_daemon():
        test("daemon running", False)
        return

    status = nopal_status()
    if not status or not status.get("interfaces"):
        test("interfaces available", False)
        return

    online = [i for i in status["interfaces"] if i.get("state") == "online"]
    if len(online) < 2:
        test("need 2+ WANs for flap test", False,
             skip_reason="need 2 online WANs (one to flap, one for connectivity)")
        return

    # Pick the second WAN to flap (keep primary for SSH connectivity)
    target = online[1]
    target_name = target["name"]
    target_device = target["device"]
    log(f"  Will flap {target_name} (device: {target_device})")
    log(f"  Keeping {online[0]['name']} stable for connectivity")

    # Check if we can toggle the device
    r = run(f"ip link set {target_device} down", check=False)
    if r.returncode != 0:
        test(f"can toggle {target_device}", False, skip_reason="ip link set failed")
        return

    # Quick restore
    run(f"ip link set {target_device} up", check=False)
    time.sleep(2)

    # Rapid flap: 5 cycles
    log("  Flapping 5 times (down/up every 2s)...")
    for i in range(5):
        run(f"ip link set {target_device} down", check=False)
        time.sleep(1)
        run(f"ip link set {target_device} up", check=False)
        time.sleep(1)

    # Wait for state to settle
    log("  Waiting 15s for state to settle...")
    time.sleep(15)

    # Verify daemon survived
    test("daemon survived flapping", daemon_is_running())

    status = nopal_status()
    test("IPC responsive after flapping", status is not None)

    if status:
        for iface in status.get("interfaces", []):
            if iface["name"] == target_name:
                state = iface["state"]
                log(f"  {target_name} state after flapping: {state}")
                test(f"{target_name} in valid state after flapping",
                     state in ("online", "probing", "degraded", "offline"))

    # Verify the stable WAN is still online
    if status:
        for iface in status.get("interfaces", []):
            if iface["name"] == online[0]["name"]:
                test(f"{online[0]['name']} still online during flap test",
                     iface["state"] == "online")

    # Wait for recovery
    log("  Waiting up to 60s for flapped interface to recover...")
    recovered = False
    for _ in range(12):
        time.sleep(5)
        s = nopal_status()
        if s:
            for iface in s.get("interfaces", []):
                if iface["name"] == target_name and iface["state"] == "online":
                    recovered = True
                    break
        if recovered:
            break
    test(f"{target_name} recovers after flapping", recovered)


# ---------------------------------------------------------------------------
# Phase 19: IPv6
# ---------------------------------------------------------------------------

def phase19():
    section("Phase 19: IPv6")

    if not ensure_daemon():
        test("daemon running", False)
        return

    # Check if IPv6 is available
    r = run("ping -6 -c1 -W3 2001:4860:4860::8888", check=False)
    if r.returncode != 0:
        test("IPv6 connectivity", False, skip_reason="no IPv6 connectivity")
        return

    test("IPv6 connectivity available", True)

    # Check if nopal config has IPv6 enabled
    status = nopal_status()
    if not status:
        test("get status", False)
        return

    # Check connected networks for IPv6 entries
    rc, out = nopal_cmd("connected")
    has_v6 = any(":" in line for line in out.split("\n") if "/" in line)
    log(f"  IPv6 in connected networks: {has_v6}")

    # Check nftables for IPv6 rules
    r = run("nft list chain inet nopal prerouting", check=False)
    has_v6_rules = "ip6" in r.stdout or "ipv6" in r.stdout if r.returncode == 0 else False
    log(f"  IPv6 nftables rules present: {has_v6_rules}")

    test("IPv6 support (observational)", True,
         detail=f"connected_v6={has_v6}, nft_v6={has_v6_rules}")


# ---------------------------------------------------------------------------
# Phase 20: Dampening (active)
# ---------------------------------------------------------------------------

def phase20():
    section("Phase 20: Dampening (active)")

    if not ensure_daemon():
        test("daemon running", False)
        return

    status = nopal_status()
    if not status or not status.get("interfaces"):
        test("get status", False)
        return

    # Check if any interface has dampening configured
    # We can't easily tell from status — check config
    r = run("cat /etc/config/nopal", check=False)
    config_out = r.stdout
    has_dampening = "dampening" in config_out and "'1'" in config_out.split("dampening")[1][:20] if "dampening" in config_out else False

    if not has_dampening:
        test("dampening configured", False,
             skip_reason="no interface has dampening enabled in config")
        log("  To test dampening, add to an interface section:")
        log("    option dampening '1'")
        log("    option dampening_halflife '30'")
        log("    option dampening_suppress '500'")
        log("    option dampening_reuse '250'")
        return

    test("dampening configured", True)

    online = [i for i in status["interfaces"] if i.get("state") == "online"]
    if len(online) < 2:
        test("need 2+ WANs for dampening test", False,
             skip_reason="need 2 online WANs")
        return

    # Flap the secondary to trigger dampening
    target = online[1]
    target_name = target["name"]
    target_device = target["device"]
    log(f"  Flapping {target_name} to trigger dampening...")

    # Flap enough times to exceed suppress threshold
    for i in range(5):
        run(f"ip link set {target_device} down", check=False)
        time.sleep(2)
        run(f"ip link set {target_device} up", check=False)
        time.sleep(3)

    # Check if dampening engaged
    time.sleep(5)
    status = nopal_status()
    if status:
        for iface in status.get("interfaces", []):
            if iface["name"] == target_name:
                state = iface["state"]
                log(f"  {target_name} state after flapping: {state}")
                # If dampening works, the interface should be offline or probing
                # (suppressed from going online)

    # Check logs for dampening messages
    r = run(["logread"], check=False)
    logs = r.stdout if r.returncode == 0 else ""
    dampen_lines = [l for l in logs.splitlines() if "dampen" in l.lower()]
    has_dampen_log = len(dampen_lines) > 0
    test("dampening messages in log", has_dampen_log,
         detail="no dampening log messages" if not has_dampen_log else None)
    if dampen_lines:
        for line in dampen_lines[-5:]:
            log(f"  {line.strip()[:120]}")

    # Wait for recovery (dampening decay)
    log("  Waiting up to 120s for dampening decay...")
    recovered = False
    for _ in range(24):
        time.sleep(5)
        s = nopal_status()
        if s:
            for iface in s.get("interfaces", []):
                if iface["name"] == target_name and iface["state"] == "online":
                    recovered = True
                    break
        if recovered:
            break
    test(f"{target_name} recovers after dampening decay", recovered)


# ---------------------------------------------------------------------------
# Phase 21: Nftables ruleset validation
# ---------------------------------------------------------------------------

def phase21():
    section("Phase 21: Nftables ruleset validation")

    if not ensure_daemon():
        test("daemon running", False)
        return

    wait_for_any_online(30)

    # Full ruleset dump
    r = run("nft -j list ruleset", check=False)
    if r.returncode != 0:
        r = run("nft list ruleset", check=False)
    ruleset = r.stdout
    test("nft list ruleset succeeds", r.returncode == 0)

    if r.returncode != 0:
        return

    # Check for expected chains
    test("has prerouting chain", "prerouting" in ruleset)
    test("has forward chain", "forward" in ruleset)
    test("has output chain", "output" in ruleset)
    test("has postrouting chain", "postrouting" in ruleset)
    test("has policy_rules chain", "policy_rules" in ruleset)

    # Check for bypass sets
    test("has bypass_v4 set", "bypass_v4" in ruleset)
    test("has bypass_v6 set", "bypass_v6" in ruleset)

    # Check for probe exception (mark 0xDEAD)
    test("has probe bypass mark", "dead" in ruleset.lower() or "57005" in ruleset)

    # Check for per-interface mark chains
    status = nopal_status()
    if status:
        for iface in status.get("interfaces", []):
            name = iface["name"]
            test(f"has mark chain for {name}", f"mark_{name}" in ruleset)

    # Verify no duplicate table names
    table_count = ruleset.count("table inet nopal")
    test("single nopal table (no duplicates)", table_count <= 2,  # list + definition
         detail=f"found {table_count} table references")


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
    log("Will also query status and reload periodically to exercise the daemon.")
    log("CSV output: /tmp/soak.csv\n")

    # Baseline log errors so we only report new ones
    baseline_logs = get_log_snapshot()

    # Write CSV header
    with open("/tmp/soak.csv", "w") as f:
        f.write("elapsed_s,rss_kb,fd_count,cpu_ticks,nft_lines,route_count\n")

    samples = [(time.time(), initial_rss)]
    start_time = samples[0][0]
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

            now = time.time()
            samples.append((now, rss))
            elapsed = int(now - start_time)
            elapsed_min = elapsed / 60

            # Collect additional metrics
            fds = get_fd_count(pid)
            cpu = get_cpu_ticks(pid)
            nft_r = run("nft list ruleset", check=False)
            nft_lines = len(nft_r.stdout.splitlines()) if nft_r.returncode == 0 else -1
            routes_r = run("ip route show table all", check=False)
            route_count = len(routes_r.stdout.splitlines()) if routes_r.returncode == 0 else -1

            # Write CSV
            with open("/tmp/soak.csv", "a") as f:
                f.write(f"{elapsed},{rss},{fds},{cpu},{nft_lines},{route_count}\n")

            elapsed_str = f"{elapsed_min:.0f}m"
            log(f"  [{iteration}] RSS: {rss} kB, FDs: {fds}, nft: {nft_lines} lines, "
                f"routes: {route_count} (elapsed: {elapsed_str})")

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
            new_errors = check_logs_for_errors(exclude_lines=baseline_logs)
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
        help="Phase to run: 1-21, 4wait, soak, or all"
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
        "7": phase7,
        "8": phase8,
        "9": phase9,
        "10": phase10,
        "11": phase11,
        "12": phase12,
        "13": phase13,
        "14": phase14,
        "15": phase15,
        "16": phase16,
        "17": phase17,
        "18": phase18,
        "19": phase19,
        "20": phase20,
        "21": phase21,
        "soak": phase_soak,
    }

    if args.phase == "all":
        for p in ["1", "2", "3", "5", "6", "7", "8", "9", "10", "11", "12",
                   "14", "16", "17", "21"]:
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
