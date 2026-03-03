//! HTTP health probe socket.
//!
//! Sends HTTP HEAD requests to configured targets and checks for valid
//! HTTP responses. Each probe creates a new non-blocking TCP connection
//! to the target on port 80.
//!
//! Unlike ICMP and DNS probes which use persistent sockets, HTTP probes
//! create a new TCP connection per probe and do not register with mio.
//! Instead, connection state is checked via zero-timeout poll() in
//! [`check_responses`](super::ProbeEngine::check_responses).

use std::io;
use std::mem;
use std::net::IpAddr;
use std::os::unix::io::RawFd;

use crate::error::{Error, Result};
use super::ProbeTransport;

/// Firewall mark applied to all health-probe packets (shared with ICMP/DNS).
const PROBE_MARK: u32 = 0xDEAD;

/// Default HTTP port.
const HTTP_PORT: u16 = 80;

/// Minimal HTTP HEAD request.
const HTTP_REQUEST: &[u8] = b"HEAD / HTTP/1.0\r\nHost: health-check\r\nConnection: close\r\n\r\n";

/// Active TCP connection state for a single probe.
struct HttpConn {
    fd: RawFd,
    request_sent: bool,
    seq: u16,
}

impl Drop for HttpConn {
    fn drop(&mut self) {
        unsafe { libc::close(self.fd) };
    }
}

/// HTTP health probe manager for a single interface.
///
/// Creates a new TCP connection for each probe. The connection is closed
/// when the next probe starts or when the socket is dropped.
pub struct HttpSocket {
    device: String,
    probe_id: u16,
    port: u16,
    conn: Option<HttpConn>,
}

impl HttpSocket {
    /// Create an HTTP probe socket bound to `device`.
    ///
    /// `port` overrides the default HTTP port (80). No connection is
    /// established until `send_request` is called.
    pub fn new(device: &str, probe_id: u16, port: Option<u16>) -> Self {
        Self {
            device: device.to_string(),
            probe_id,
            port: port.unwrap_or(HTTP_PORT),
            conn: None,
        }
    }

    /// Initiate a non-blocking TCP connection to `target` on the configured port.
    ///
    /// Closes any existing connection from a previous probe. The `seq`
    /// parameter is not encoded in the HTTP request but is returned by
    /// `check_response` for matching.
    pub fn send_request(&mut self, target: IpAddr, seq: u16, _id: u16) -> Result<()> {
        // Close previous connection
        self.conn = None;

        let family = if target.is_ipv6() {
            libc::AF_INET6
        } else {
            libc::AF_INET
        };

        let fd = unsafe {
            libc::socket(
                family,
                libc::SOCK_STREAM | libc::SOCK_CLOEXEC | libc::SOCK_NONBLOCK,
                0,
            )
        };
        if fd < 0 {
            return Err(Error::Io(io::Error::last_os_error()));
        }

        if let Err(e) = Self::configure(fd, &self.device) {
            unsafe { libc::close(fd) };
            return Err(e);
        }

        let ret = match target {
            IpAddr::V4(addr) => {
                let mut sa: libc::sockaddr_in = unsafe { mem::zeroed() };
                sa.sin_family = libc::AF_INET as libc::sa_family_t;
                sa.sin_port = self.port.to_be();
                sa.sin_addr.s_addr = u32::from_ne_bytes(addr.octets());
                unsafe {
                    libc::connect(
                        fd,
                        &sa as *const libc::sockaddr_in as *const libc::sockaddr,
                        mem::size_of::<libc::sockaddr_in>() as libc::socklen_t,
                    )
                }
            }
            IpAddr::V6(addr) => {
                let mut sa: libc::sockaddr_in6 = unsafe { mem::zeroed() };
                sa.sin6_family = libc::AF_INET6 as libc::sa_family_t;
                sa.sin6_port = self.port.to_be();
                sa.sin6_addr.s6_addr = addr.octets();
                unsafe {
                    libc::connect(
                        fd,
                        &sa as *const libc::sockaddr_in6 as *const libc::sockaddr,
                        mem::size_of::<libc::sockaddr_in6>() as libc::socklen_t,
                    )
                }
            }
        };

        if ret < 0 {
            let err = io::Error::last_os_error();
            if err.raw_os_error() != Some(libc::EINPROGRESS) {
                unsafe { libc::close(fd) };
                return Err(Error::Io(err));
            }
            // EINPROGRESS is expected for non-blocking connect
        }

        self.conn = Some(HttpConn {
            fd,
            request_sent: false,
            seq,
        });

        Ok(())
    }

    /// Check for a completed HTTP response.
    ///
    /// Uses zero-timeout poll to check the TCP connection state without
    /// blocking. Returns `Ok(Some((seq, id)))` if a valid HTTP response
    /// was received, where seq is 0 (unused) and id is the stored probe_id.
    ///
    /// The actual seq matching is handled by the caller always accepting
    /// any response from this socket within the timeout window.
    pub fn check_response(&mut self) -> Result<Option<(u16, u16)>> {
        let conn = match self.conn.as_mut() {
            Some(c) => c,
            None => return Ok(None),
        };

        if !conn.request_sent {
            // Check if TCP connect completed
            if !Self::is_connected(conn.fd) {
                return Ok(None);
            }

            // Connection established -- send HTTP HEAD request
            let ret = unsafe {
                libc::send(
                    conn.fd,
                    HTTP_REQUEST.as_ptr() as *const libc::c_void,
                    HTTP_REQUEST.len(),
                    libc::MSG_NOSIGNAL,
                )
            };
            if ret < 0 {
                let err = io::Error::last_os_error();
                if err.kind() == io::ErrorKind::WouldBlock {
                    return Ok(None);
                }
                return Err(Error::Io(err));
            }

            conn.request_sent = true;
        }

        // Try to read the response
        let mut buf = [0u8; 64];
        let ret = unsafe {
            libc::recv(
                conn.fd,
                buf.as_mut_ptr() as *mut libc::c_void,
                buf.len(),
                0,
            )
        };

        if ret < 0 {
            let err = io::Error::last_os_error();
            if err.kind() == io::ErrorKind::WouldBlock {
                return Ok(None);
            }
            return Err(Error::Io(err));
        }

        let n = ret as usize;

        // Minimum valid response: "HTTP/1.x NNN" = 12 bytes
        if n < 12 || &buf[..5] != b"HTTP/" {
            return Ok(None);
        }

        // Extract the 3-digit status code after "HTTP/1.x "
        // Format: "HTTP/1.0 200 OK\r\n" or "HTTP/1.1 302 Found\r\n"
        // The status code starts at byte 9 (after "HTTP/1.x ")
        let status = &buf[9..12];
        if status[0] == b'2' && status[1].is_ascii_digit() && status[2].is_ascii_digit() {
            return Ok(Some((conn.seq, self.probe_id)));
        }

        // Non-2xx status: treat as probe failure (captive portal, redirect, etc.)
        log::debug!(
            "HTTP probe got non-2xx status: {}",
            String::from_utf8_lossy(&buf[9..n.min(32)])
        );
        Ok(None)
    }

    /// Check if a non-blocking TCP connect has completed.
    fn is_connected(fd: RawFd) -> bool {
        let mut pfd = libc::pollfd {
            fd,
            events: libc::POLLOUT,
            revents: 0,
        };

        let ret = unsafe { libc::poll(&mut pfd, 1, 0) };
        if ret <= 0 {
            return false;
        }

        if pfd.revents & (libc::POLLERR | libc::POLLHUP) != 0 {
            return false;
        }

        // Verify no error on the socket
        let mut err: libc::c_int = 0;
        let mut len = mem::size_of::<libc::c_int>() as libc::socklen_t;
        let ret = unsafe {
            libc::getsockopt(
                fd,
                libc::SOL_SOCKET,
                libc::SO_ERROR,
                &mut err as *mut _ as *mut libc::c_void,
                &mut len,
            )
        };
        ret == 0 && err == 0
    }

    /// Apply SO_MARK and SO_BINDTODEVICE to the TCP socket.
    fn configure(fd: RawFd, device: &str) -> Result<()> {
        let mark = PROBE_MARK;
        let ret = unsafe {
            libc::setsockopt(
                fd,
                libc::SOL_SOCKET,
                libc::SO_MARK,
                &mark as *const u32 as *const libc::c_void,
                mem::size_of::<u32>() as libc::socklen_t,
            )
        };
        if ret < 0 {
            return Err(Error::Io(io::Error::last_os_error()));
        }

        let dev_bytes = device.as_bytes();
        if dev_bytes.len() >= libc::IFNAMSIZ {
            return Err(Error::Config(format!(
                "device name too long: {device}"
            )));
        }
        let ret = unsafe {
            libc::setsockopt(
                fd,
                libc::SOL_SOCKET,
                libc::SO_BINDTODEVICE,
                dev_bytes.as_ptr() as *const libc::c_void,
                dev_bytes.len() as libc::socklen_t,
            )
        };
        if ret < 0 {
            return Err(Error::Io(io::Error::last_os_error()));
        }

        Ok(())
    }
}

impl ProbeTransport for HttpSocket {
    fn send(&mut self, target: IpAddr, seq: u16, id: u16, _payload_size: usize) -> Result<()> {
        self.send_request(target, seq, id)
    }
    fn recv(&mut self) -> Result<Option<(u16, u16)>> {
        self.check_response()
    }
    fn fds(&self) -> Vec<RawFd> {
        vec![]
    }
}

impl Drop for HttpSocket {
    fn drop(&mut self) {
        // HttpConn's Drop handles closing the fd
        self.conn = None;
    }
}
