mod config;
mod daemon;
mod dns;
mod error;
mod health;
mod ipc;
mod logging;
mod netlink;
mod nftables;
mod state;
mod timer;

use std::env;
use std::io::{Read, Write};
use std::os::unix::net::UnixStream;
use std::process;
use std::sync::atomic::{AtomicI32, Ordering};

const DEFAULT_CONFIG: &str = "/etc/config/nopal";
const DEFAULT_SOCKET: &str = "/var/run/nopal.sock";

/// Write end of the self-pipe used by signal handlers to wake the event loop.
/// Set to a valid fd before signals are installed.
static SIGNAL_WRITE_FD: AtomicI32 = AtomicI32::new(-1);

fn main() {
    let args: Vec<String> = env::args().collect();

    // Determine mode: if invoked as "nopald" or with "--daemon", run the daemon.
    // Otherwise, treat as CLI tool.
    let prog = args
        .first()
        .and_then(|a| a.rsplit('/').next())
        .unwrap_or("nopal");

    if prog == "nopald" || args.iter().any(|a| a == "--daemon" || a == "-d") {
        run_daemon(&args);
    } else {
        run_cli(&args);
    }
}

fn run_daemon(args: &[String]) {
    let config_path = args
        .iter()
        .position(|a| a == "-c" || a == "--config")
        .and_then(|i| args.get(i + 1))
        .map(|s| s.as_str())
        .unwrap_or(DEFAULT_CONFIG);

    // Initialize logging (parse level from config later; start with info)
    if let Err(e) = logging::init(log::Level::Info) {
        eprintln!("failed to initialize logging: {e}");
        process::exit(1);
    }

    // Create self-pipe for signal delivery into the mio event loop
    let signal_read_fd = create_signal_pipe();

    // Install signal handlers (must happen after pipe is created)
    install_signal_handlers();

    log::info!("nopal v{} starting", env!("CARGO_PKG_VERSION"));

    let mut daemon = match daemon::Daemon::new(config_path, signal_read_fd) {
        Ok(d) => d,
        Err(e) => {
            log::error!("failed to initialize daemon: {e}");
            process::exit(1);
        }
    };

    match daemon.run() {
        Ok(()) => {}
        Err(e) => {
            log::error!("daemon error: {e}");
            process::exit(1);
        }
    }
}

/// Create a non-blocking pipe for signal delivery. Stores the write fd
/// globally for signal handlers and returns the read fd for mio.
fn create_signal_pipe() -> i32 {
    let mut fds = [0i32; 2];
    let ret = unsafe { libc::pipe2(fds.as_mut_ptr(), libc::O_NONBLOCK | libc::O_CLOEXEC) };
    if ret < 0 {
        eprintln!(
            "failed to create signal pipe: {}",
            std::io::Error::last_os_error()
        );
        process::exit(1);
    }
    SIGNAL_WRITE_FD.store(fds[1], Ordering::Release);
    fds[0]
}

fn install_signal_handlers() {
    unsafe {
        let mut sa: libc::sigaction = std::mem::zeroed();
        sa.sa_flags = libc::SA_RESTART;

        sa.sa_sigaction = handle_sigterm as usize;
        libc::sigaction(libc::SIGTERM, &sa, std::ptr::null_mut());
        libc::sigaction(libc::SIGINT, &sa, std::ptr::null_mut());

        sa.sa_sigaction = handle_sighup as usize;
        libc::sigaction(libc::SIGHUP, &sa, std::ptr::null_mut());

        sa.sa_sigaction = libc::SIG_IGN;
        libc::sigaction(libc::SIGPIPE, &sa, std::ptr::null_mut());
    }
}

/// Write a single byte to the signal pipe. Safe to call from a signal handler
/// (write() is async-signal-safe, AtomicI32::load is safe in practice).
fn signal_pipe_write(byte: u8) {
    let fd = SIGNAL_WRITE_FD.load(Ordering::Acquire);
    if fd >= 0 {
        unsafe {
            libc::write(fd, &byte as *const u8 as *const libc::c_void, 1);
        }
    }
}

extern "C" fn handle_sigterm(_sig: libc::c_int) {
    signal_pipe_write(b'T');
}

extern "C" fn handle_sighup(_sig: libc::c_int) {
    signal_pipe_write(b'R');
}

// -- CLI tool -----------------------------------------------------------

fn run_cli(args: &[String]) {
    // Extract positional args, consuming flag values
    let mut socket_path = DEFAULT_SOCKET;
    let mut json_mode = false;
    let mut positional = Vec::new();
    let mut i = 1;
    while i < args.len() {
        let a = args[i].as_str();
        match a {
            "-s" | "--socket" => {
                i += 1;
                if let Some(v) = args.get(i) {
                    socket_path = v.as_str();
                }
            }
            "-j" | "--json" => json_mode = true,
            "--help" | "-h" => {
                print_usage();
                return;
            }
            "--version" | "-V" => {
                println!("nopal {}", env!("CARGO_PKG_VERSION"));
                return;
            }
            _ => positional.push(a),
        }
        i += 1;
    }

    let command = positional.first().copied().unwrap_or("status");

    match command {
        "status" => {
            let iface = positional.get(1).copied();
            cli_status(socket_path, iface, json_mode);
        }
        "interfaces" => cli_interfaces(socket_path, json_mode),
        "policies" => cli_policies(socket_path, json_mode),
        "connected" => cli_connected(socket_path, json_mode),
        "use" => {
            let iface = match positional.get(1) {
                Some(i) => *i,
                None => {
                    eprintln!("usage: nopal use <interface> <command...>");
                    process::exit(1);
                }
            };
            let cmd_args: Vec<&str> = positional[2..].to_vec();
            if cmd_args.is_empty() {
                eprintln!("usage: nopal use <interface> <command...>");
                process::exit(1);
            }
            cli_use(socket_path, iface, &cmd_args);
        }
        "rules" => cli_rules(),
        "internal" => cli_internal(),
        "reload" => cli_reload(socket_path),
        "help" => print_usage(),
        "version" => {
            println!("nopal {}", env!("CARGO_PKG_VERSION"));
        }
        other => {
            eprintln!("unknown command: {other}");
            print_usage();
            process::exit(1);
        }
    }
}

fn fetch_status(socket_path: &str) -> ipc::protocol::DaemonStatus {
    let request = ipc::protocol::Request {
        id: 1,
        method: "status".to_string(),
        params: ipc::protocol::RequestParams::default(),
    };

    match send_ipc_request(socket_path, &request) {
        Ok(response) => {
            if !response.success {
                eprintln!(
                    "error: {}",
                    response.error.unwrap_or_else(|| "unknown error".into())
                );
                process::exit(1);
            }
            match response.data {
                Some(ipc::protocol::ResponseData::Status(s)) => s,
                _ => {
                    eprintln!("unexpected response from daemon");
                    process::exit(1);
                }
            }
        }
        Err(e) => {
            eprintln!("failed to connect to nopal daemon: {e}");
            eprintln!("is nopald running?");
            process::exit(1);
        }
    }
}

fn cli_status(socket_path: &str, interface: Option<&str>, json_mode: bool) {
    if let Some(name) = interface {
        let request = ipc::protocol::Request {
            id: 1,
            method: "interface.status".to_string(),
            params: ipc::protocol::RequestParams {
                interface: Some(name.to_string()),
            },
        };

        match send_ipc_request(socket_path, &request) {
            Ok(response) => {
                if !response.success {
                    eprintln!(
                        "error: {}",
                        response.error.unwrap_or_else(|| "unknown error".into())
                    );
                    process::exit(1);
                }
                if json_mode {
                    let json = serde_json::to_string_pretty(&response.data).unwrap_or_default();
                    println!("{json}");
                } else if let Some(ipc::protocol::ResponseData::InterfaceStatus(iface)) =
                    response.data
                {
                    print_interface_detail(&iface);
                }
            }
            Err(e) => {
                eprintln!("failed to connect to nopal daemon: {e}");
                eprintln!("is nopald running?");
                process::exit(1);
            }
        }
        return;
    }

    let status = fetch_status(socket_path);

    if json_mode {
        let json = serde_json::to_string_pretty(&status).unwrap_or_default();
        println!("{json}");
        return;
    }

    // Human-readable full status
    let uptime = format_uptime(status.uptime_secs);
    println!("nopal v{} -- uptime {uptime}", status.version);
    println!();

    if status.interfaces.is_empty() {
        println!("No interfaces configured.");
    } else {
        println!("Interfaces:");
        print_interface_table(&status.interfaces);
    }

    println!();

    if status.policies.is_empty() {
        println!("No policies configured.");
    } else {
        println!("Policies:");
        print_policy_table(&status.policies);
    }
}

fn cli_interfaces(socket_path: &str, json_mode: bool) {
    let status = fetch_status(socket_path);

    if json_mode {
        let json = serde_json::to_string_pretty(&status.interfaces).unwrap_or_default();
        println!("{json}");
        return;
    }

    if status.interfaces.is_empty() {
        println!("No interfaces configured.");
    } else {
        print_interface_table(&status.interfaces);
    }
}

fn cli_policies(socket_path: &str, json_mode: bool) {
    let status = fetch_status(socket_path);

    if json_mode {
        let json = serde_json::to_string_pretty(&status.policies).unwrap_or_default();
        println!("{json}");
        return;
    }

    if status.policies.is_empty() {
        println!("No policies configured.");
    } else {
        print_policy_table(&status.policies);
    }
}

fn cli_use(socket_path: &str, iface: &str, cmd_args: &[&str]) {
    // Query the daemon for interface info
    let request = ipc::protocol::Request {
        id: 1,
        method: "interface.status".to_string(),
        params: ipc::protocol::RequestParams {
            interface: Some(iface.to_string()),
        },
    };

    let iface_data = match send_ipc_request(socket_path, &request) {
        Ok(response) => {
            if !response.success {
                eprintln!(
                    "error: {}",
                    response.error.unwrap_or_else(|| "unknown error".into())
                );
                process::exit(1);
            }
            match response.data {
                Some(ipc::protocol::ResponseData::InterfaceStatus(data)) => data,
                _ => {
                    eprintln!("unexpected response from daemon");
                    process::exit(1);
                }
            }
        }
        Err(e) => {
            eprintln!("failed to connect to nopal daemon: {e}");
            eprintln!("is nopald running?");
            process::exit(1);
        }
    };

    let table_id = iface_data.table_id;
    let uid = unsafe { libc::getuid() };
    let uid_range = format!("{uid}-{uid}");
    let table_str = table_id.to_string();

    // Add temporary ip rules (IPv4 and IPv6) to route traffic from our UID
    // through the interface's routing table. uidrange rules only affect
    // locally-originated traffic, not forwarded packets.
    let mut rules_added = Vec::new();

    for family in &["-4", "-6"] {
        let status = process::Command::new("ip")
            .args([family, "rule", "add",
                   "uidrange", uid_range.as_str(),
                   "lookup", table_str.as_str(),
                   "prio", "1"])
            .status();
        match status {
            Ok(s) if s.success() => rules_added.push(*family),
            Ok(_) => {
                // IPv6 rule may fail if IPv6 is disabled, that's OK
                if *family == "-4" {
                    eprintln!("failed to add ip rule for {iface}");
                    cleanup_use_rules(&rules_added, uid, table_id);
                    process::exit(1);
                }
            }
            Err(e) => {
                eprintln!("failed to run ip command: {e}");
                cleanup_use_rules(&rules_added, uid, table_id);
                process::exit(1);
            }
        }
    }

    // Run the user's command with interface info in env vars
    let exit_code = match process::Command::new(cmd_args[0])
        .args(&cmd_args[1..])
        .env("DEVICE", &iface_data.device)
        .env("INTERFACE", iface)
        .status()
    {
        Ok(status) => status.code().unwrap_or(1),
        Err(e) => {
            eprintln!("failed to execute {}: {e}", cmd_args[0]);
            cleanup_use_rules(&rules_added, uid, table_id);
            process::exit(1);
        }
    };

    cleanup_use_rules(&rules_added, uid, table_id);
    process::exit(exit_code);
}

fn cleanup_use_rules(families: &[&str], uid: u32, table_id: u32) {
    let uid_range = format!("{uid}-{uid}");
    let table_str = table_id.to_string();
    for family in families {
        let _ = process::Command::new("ip")
            .args([family, "rule", "del",
                   "uidrange", uid_range.as_str(),
                   "lookup", table_str.as_str(),
                   "prio", "1"])
            .status();
    }
}

fn cli_rules() {
    // Dump the nopal nftables ruleset (policy_rules chain)
    let output = process::Command::new("nft")
        .args(["list", "chain", "inet", "nopal", "policy_rules"])
        .output();
    match output {
        Ok(out) => {
            if out.status.success() {
                print!("{}", String::from_utf8_lossy(&out.stdout));
            } else {
                let stderr = String::from_utf8_lossy(&out.stderr);
                if stderr.contains("No such") {
                    println!("nopal nftables rules not loaded (daemon not running?)");
                } else {
                    eprint!("{stderr}");
                    process::exit(1);
                }
            }
        }
        Err(e) => {
            eprintln!("failed to run nft: {e}");
            process::exit(1);
        }
    }
}

fn cli_internal() {
    println!("=== IPv4 ip rules ===");
    let _ = process::Command::new("ip")
        .args(["-4", "rule", "show"])
        .status();

    println!("\n=== IPv6 ip rules ===");
    let _ = process::Command::new("ip")
        .args(["-6", "rule", "show"])
        .status();

    // Find nopal routing tables (100+) by scanning ip rules for fwmark references
    println!("\n=== nopal routing tables ===");
    if let Ok(output) = process::Command::new("ip")
        .args(["-4", "rule", "show"])
        .output()
    {
        let text = String::from_utf8_lossy(&output.stdout);
        let mut tables = std::collections::BTreeSet::new();
        for line in text.lines() {
            if let Some(idx) = line.find("lookup ") {
                let table_str = line[idx + 7..].split_whitespace().next().unwrap_or("");
                if let Ok(table_id) = table_str.parse::<u32>() {
                    if (101..=354).contains(&table_id) {
                        tables.insert(table_id);
                    }
                }
            }
        }
        for table_id in &tables {
            println!("\n--- table {table_id} (IPv4) ---");
            let _ = process::Command::new("ip")
                .args(["-4", "route", "show", "table", &table_id.to_string()])
                .status();
        }
        for table_id in &tables {
            println!("\n--- table {table_id} (IPv6) ---");
            let _ = process::Command::new("ip")
                .args(["-6", "route", "show", "table", &table_id.to_string()])
                .status();
        }
    }

    println!("\n=== nftables ruleset ===");
    let _ = process::Command::new("nft")
        .args(["list", "table", "inet", "nopal"])
        .status();
}

fn cli_connected(socket_path: &str, json_mode: bool) {
    let request = ipc::protocol::Request {
        id: 1,
        method: "connected".to_string(),
        params: ipc::protocol::RequestParams::default(),
    };

    match send_ipc_request(socket_path, &request) {
        Ok(response) => {
            if !response.success {
                eprintln!(
                    "error: {}",
                    response.error.unwrap_or_else(|| "unknown error".into())
                );
                process::exit(1);
            }
            match response.data {
                Some(ipc::protocol::ResponseData::Connected(data)) => {
                    if json_mode {
                        let json = serde_json::to_string_pretty(&data.networks)
                            .unwrap_or_default();
                        println!("{json}");
                    } else {
                        println!("Connected networks (bypassed from policy routing):");
                        for net in &data.networks {
                            println!("  {net}");
                        }
                    }
                }
                _ => {
                    eprintln!("unexpected response from daemon");
                    process::exit(1);
                }
            }
        }
        Err(e) => {
            eprintln!("failed to connect to nopal daemon: {e}");
            eprintln!("is nopald running?");
            process::exit(1);
        }
    }
}

fn cli_reload(socket_path: &str) {
    let request = ipc::protocol::Request {
        id: 1,
        method: "config.reload".to_string(),
        params: ipc::protocol::RequestParams::default(),
    };

    match send_ipc_request(socket_path, &request) {
        Ok(response) => {
            if response.success {
                println!("configuration reloaded");
            } else {
                eprintln!(
                    "reload failed: {}",
                    response.error.unwrap_or_else(|| "unknown error".into())
                );
                process::exit(1);
            }
        }
        Err(e) => {
            eprintln!("failed to connect to nopal daemon: {e}");
            process::exit(1);
        }
    }
}

// -- Output formatting --------------------------------------------------

fn print_interface_table(interfaces: &[ipc::protocol::InterfaceStatusData]) {
    // Header
    println!(
        "  {:<12} {:<10} {:<10} {:<8} {:>7} {:>6} {:>6}",
        "INTERFACE", "DEVICE", "STATE", "ENABLED", "RTT", "LOSS", "SCORE"
    );

    for iface in interfaces {
        let rtt = match iface.avg_rtt_ms {
            Some(ms) => format!("{ms}ms"),
            None => "-".to_string(),
        };
        let loss = format!("{}%", iface.loss_percent);
        let score = format!("{}/{}", iface.success_count, iface.success_count + iface.fail_count);

        println!(
            "  {:<12} {:<10} {:<10} {:<8} {:>7} {:>6} {:>6}",
            iface.name, iface.device, iface.state,
            if iface.enabled { "yes" } else { "no" },
            rtt, loss, score,
        );
    }
}

fn print_interface_detail(iface: &ipc::protocol::InterfaceStatusData) {
    println!("Interface: {}", iface.name);
    println!("  Device:    {}", iface.device);
    println!("  State:     {}", iface.state);
    println!("  Enabled:   {}", if iface.enabled { "yes" } else { "no" });
    println!("  Mark:      0x{:04x}", iface.mark);
    println!("  Table:     {}", iface.table_id);
    println!(
        "  RTT:       {}",
        iface.avg_rtt_ms.map(|ms| format!("{ms}ms")).unwrap_or_else(|| "-".to_string())
    );
    println!("  Loss:      {}%", iface.loss_percent);
    println!("  Probes:    {} ok / {} fail", iface.success_count, iface.fail_count);
}

fn print_policy_table(policies: &[ipc::protocol::PolicyStatusData]) {
    println!(
        "  {:<16} {:<8} {}",
        "POLICY", "TIER", "ACTIVE MEMBERS"
    );

    for policy in policies {
        let tier = match policy.active_tier {
            Some(t) => t.to_string(),
            None => "-".to_string(),
        };
        let members = if policy.active_members.is_empty() {
            "(none)".to_string()
        } else {
            policy.active_members.join(", ")
        };

        println!("  {:<16} {:<8} {}", policy.name, tier, members);
    }
}

fn format_uptime(secs: u64) -> String {
    let days = secs / 86400;
    let hours = (secs % 86400) / 3600;
    let mins = (secs % 3600) / 60;
    if days > 0 {
        format!("{days}d {hours}h {mins}m")
    } else if hours > 0 {
        format!("{hours}h {mins}m")
    } else {
        format!("{mins}m")
    }
}

fn send_ipc_request(
    socket_path: &str,
    request: &ipc::protocol::Request,
) -> std::result::Result<ipc::protocol::Response, Box<dyn std::error::Error>> {
    let mut stream = UnixStream::connect(socket_path)?;

    // Serialize and send with length prefix
    let data = rmp_serde::to_vec(request)?;
    let len = (data.len() as u32).to_be_bytes();
    stream.write_all(&len)?;
    stream.write_all(&data)?;

    // Read length-prefixed response
    let mut len_buf = [0u8; 4];
    stream.read_exact(&mut len_buf)?;
    let resp_len = u32::from_be_bytes(len_buf) as usize;
    if resp_len > 64 * 1024 {
        return Err(format!("response too large ({resp_len} bytes)").into());
    }

    let mut resp_buf = vec![0u8; resp_len];
    stream.read_exact(&mut resp_buf)?;

    let response: ipc::protocol::Response = rmp_serde::from_slice(&resp_buf)?;
    Ok(response)
}

fn print_usage() {
    println!(
        "nopal {} -- Multi-WAN manager for OpenWrt\n\
         \n\
         Usage:\n\
         \x20 nopal status [<interface>]   Show daemon/interface status\n\
         \x20 nopal interfaces             Show interface table\n\
         \x20 nopal policies               Show policy table\n\
         \x20 nopal connected              Show connected networks\n\
         \x20 nopal use <iface> <cmd...>   Run command via specific WAN\n\
         \x20 nopal rules                  Show active nftables rules\n\
         \x20 nopal internal               Full diagnostic dump\n\
         \x20 nopal reload                 Reload configuration\n\
         \x20 nopal version                Show version\n\
         \x20 nopal help                   Show this help\n\
         \n\
         Daemon:\n\
         \x20 nopald [-c <config>]         Run the daemon\n\
         \n\
         Options:\n\
         \x20 -c, --config <path>         Config file path (default: {DEFAULT_CONFIG})\n\
         \x20 -s, --socket <path>         IPC socket path (default: {DEFAULT_SOCKET})\n\
         \x20 -j, --json                  Output in JSON format",
        env!("CARGO_PKG_VERSION")
    );
}
