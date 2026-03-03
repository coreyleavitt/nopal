use std::fmt;
use std::io;

#[derive(Debug)]
pub enum Error {
    Io(io::Error),
    Config(String),
    Netlink(String),
    Nftables(String),
    Ipc(String),
    State(String),
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::Io(e) => write!(f, "I/O error: {e}"),
            Error::Config(msg) => write!(f, "config error: {msg}"),
            Error::Netlink(msg) => write!(f, "netlink error: {msg}"),
            Error::Nftables(msg) => write!(f, "nftables error: {msg}"),
            Error::Ipc(msg) => write!(f, "IPC error: {msg}"),
            Error::State(msg) => write!(f, "state error: {msg}"),
        }
    }
}

impl std::error::Error for Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Error::Io(e) => Some(e),
            _ => None,
        }
    }
}

impl From<io::Error> for Error {
    fn from(e: io::Error) -> Self {
        Error::Io(e)
    }
}

pub type Result<T> = std::result::Result<T, Error>;
