use log::{Level, Log, Metadata, Record, SetLoggerError};
use std::io::Write;
use std::os::unix::net::UnixDatagram;

/// Minimal syslog logger that writes to /dev/log (Unix domain datagram socket)
/// or falls back to stderr. Designed for procd stdout/stderr capture.
struct SyslogLogger {
    /// If true, write to stderr (procd captures this).
    /// If false, write to /dev/log syslog socket.
    use_stderr: bool,
    level: Level,
    /// Pre-connected syslog socket (reused across log calls).
    syslog_sock: Option<UnixDatagram>,
}

impl Log for SyslogLogger {
    fn enabled(&self, metadata: &Metadata) -> bool {
        metadata.level() <= self.level
    }

    fn log(&self, record: &Record) {
        if !self.enabled(record.metadata()) {
            return;
        }

        let priority = match record.level() {
            Level::Error => 3,   // LOG_ERR
            Level::Warn => 4,    // LOG_WARNING
            Level::Info => 6,    // LOG_INFO
            Level::Debug => 7,   // LOG_DEBUG
            Level::Trace => 7,   // LOG_DEBUG
        };

        if self.use_stderr {
            let _ = writeln!(
                std::io::stderr(),
                "<{priority}>nopal: {}: {}",
                record.target(),
                record.args()
            );
        } else if let Some(ref sock) = self.syslog_sock {
            // Best-effort write to pre-connected /dev/log
            let msg = format!(
                "<{}>nopal: {}: {}",
                // facility = LOG_DAEMON (24) | priority
                (3 << 3) | priority,
                record.target(),
                record.args()
            );
            let _ = sock.send(msg.as_bytes());
        }
    }

    fn flush(&self) {}
}

/// Initialize the logger. Under procd, stderr is captured and forwarded to
/// logd, so we default to stderr output.
pub fn init(level: Level) -> Result<(), SetLoggerError> {
    let logger = SyslogLogger {
        use_stderr: true,
        level,
        syslog_sock: None,
    };
    log::set_boxed_logger(Box::new(logger))?;
    log::set_max_level(level.to_level_filter());
    Ok(())
}

/// Parse a log level string from UCI config.
#[allow(dead_code)]
pub fn parse_level(s: &str) -> Level {
    match s {
        "error" | "err" => Level::Error,
        "warn" | "warning" => Level::Warn,
        "info" => Level::Info,
        "debug" => Level::Debug,
        "trace" => Level::Trace,
        _ => Level::Info,
    }
}
