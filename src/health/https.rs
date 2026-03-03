//! HTTPS health probe socket.
//!
//! Sends HTTPS HEAD requests to configured targets and checks for valid
//! HTTP responses over TLS. Each probe creates a new non-blocking TCP
//! connection, performs a TLS handshake using `rustls`, sends an HTTP
//! request, and validates the response.
//!
//! Like HTTP probes, HTTPS probes create a new connection per probe and
//! do not register with mio. Connection state is advanced via polling in
//! [`check_response`] (called from `recv`).

use std::io::{self, Read, Write};
use std::mem;
use std::net::IpAddr;
use std::os::unix::io::RawFd;
use std::sync::{Arc, OnceLock};

use rustls::ClientConnection;

use crate::error::{Error, Result};
use super::ProbeTransport;

/// Firewall mark applied to all health-probe packets.
const PROBE_MARK: u32 = 0xDEAD;

/// Default HTTPS port.
const HTTPS_PORT: u16 = 443;

/// Minimal HTTP HEAD request sent after TLS handshake.
const HTTPS_REQUEST: &[u8] = b"HEAD / HTTP/1.0\r\nHost: health-check\r\nConnection: close\r\n\r\n";

/// Shared TLS client configuration (lazily initialized once).
static TLS_CONFIG: OnceLock<Arc<rustls::ClientConfig>> = OnceLock::new();

fn tls_config() -> Arc<rustls::ClientConfig> {
    TLS_CONFIG
        .get_or_init(|| {
            let root_store =
                rustls::RootCertStore::from_iter(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
            let config = rustls::ClientConfig::builder()
                .with_root_certificates(root_store)
                .with_no_client_auth();
            Arc::new(config)
        })
        .clone()
}

/// TLS handshake / HTTP exchange phases.
enum Phase {
    TcpConnecting,
    TlsHandshaking,
    SendingRequest,
    WaitingResponse,
}

/// Active TCP+TLS connection state for a single probe.
struct HttpsConn {
    fd: RawFd,
    tls: Option<ClientConnection>,
    phase: Phase,
    seq: u16,
    target: IpAddr,
}

impl Drop for HttpsConn {
    fn drop(&mut self) {
        unsafe { libc::close(self.fd) };
    }
}

/// HTTPS health probe manager for a single interface.
pub struct HttpsSocket {
    device: String,
    probe_id: u16,
    port: u16,
    conn: Option<HttpsConn>,
}

impl HttpsSocket {
    pub fn new(device: &str, probe_id: u16, port: Option<u16>) -> Self {
        Self {
            device: device.to_string(),
            probe_id,
            port: port.unwrap_or(HTTPS_PORT),
            conn: None,
        }
    }

    /// Initiate a non-blocking TCP connection to `target:443`.
    fn start_connect(&mut self, target: IpAddr, seq: u16) -> Result<()> {
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

        if let Err(e) = configure_socket(fd, &self.device) {
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
        }

        self.conn = Some(HttpsConn {
            fd,
            tls: None,
            phase: Phase::TcpConnecting,
            seq,
            target,
        });

        Ok(())
    }

    /// Drive the HTTPS state machine forward. Returns the probe result
    /// when a valid HTTP response is received.
    fn check_response(&mut self) -> Result<Option<(u16, u16)>> {
        let conn = match self.conn.as_mut() {
            Some(c) => c,
            None => return Ok(None),
        };

        loop {
            match conn.phase {
                Phase::TcpConnecting => {
                    if !is_connected(conn.fd) {
                        return Ok(None);
                    }
                    // TCP connected -- start TLS handshake using the
                    // actual target IP for certificate validation (IP SAN).
                    let server_name = match conn.target {
                        IpAddr::V4(v4) => rustls::pki_types::ServerName::IpAddress(
                            rustls::pki_types::IpAddr::V4(
                                rustls::pki_types::Ipv4Addr::from(v4.octets()),
                            ),
                        ),
                        IpAddr::V6(v6) => rustls::pki_types::ServerName::IpAddress(
                            rustls::pki_types::IpAddr::V6(
                                rustls::pki_types::Ipv6Addr::from(v6.segments()),
                            ),
                        ),
                    };
                    let tls_conn = ClientConnection::new(
                        tls_config(),
                        server_name,
                    )
                    .map_err(|e| Error::Io(io::Error::new(io::ErrorKind::Other, e)))?;
                    conn.tls = Some(tls_conn);
                    conn.phase = Phase::TlsHandshaking;
                    // Fall through to handshaking
                }
                Phase::TlsHandshaking => {
                    let tls = conn.tls.as_mut().unwrap();
                    let mut stream = RawTcpStream(conn.fd);

                    // Process TLS I/O
                    match tls.complete_io(&mut stream) {
                        Ok(_) => {
                            if !tls.is_handshaking() {
                                conn.phase = Phase::SendingRequest;
                                // Fall through to send request
                            } else {
                                return Ok(None);
                            }
                        }
                        Err(e) if e.kind() == io::ErrorKind::WouldBlock => {
                            return Ok(None);
                        }
                        Err(e) => {
                            log::debug!("HTTPS probe TLS handshake error: {e}");
                            self.conn = None;
                            return Ok(None);
                        }
                    }
                }
                Phase::SendingRequest => {
                    let tls = conn.tls.as_mut().unwrap();

                    // Write the HTTP request into the TLS session
                    if let Err(e) = tls.writer().write_all(HTTPS_REQUEST) {
                        log::debug!("HTTPS probe write error: {e}");
                        self.conn = None;
                        return Ok(None);
                    }

                    // Flush TLS data to the TCP socket
                    let mut stream = RawTcpStream(conn.fd);
                    match tls.complete_io(&mut stream) {
                        Ok(_) => {}
                        Err(e) if e.kind() == io::ErrorKind::WouldBlock => {
                            // Partial write is fine, we'll continue next poll
                        }
                        Err(e) => {
                            log::debug!("HTTPS probe flush error: {e}");
                            self.conn = None;
                            return Ok(None);
                        }
                    }

                    conn.phase = Phase::WaitingResponse;
                    return Ok(None);
                }
                Phase::WaitingResponse => {
                    let tls = conn.tls.as_mut().unwrap();
                    let mut stream = RawTcpStream(conn.fd);

                    // Drive TLS I/O to read incoming data
                    match tls.complete_io(&mut stream) {
                        Ok(_) => {}
                        Err(e) if e.kind() == io::ErrorKind::WouldBlock => {
                            return Ok(None);
                        }
                        Err(e) => {
                            log::debug!("HTTPS probe read I/O error: {e}");
                            self.conn = None;
                            return Ok(None);
                        }
                    }

                    // Try to read decrypted data
                    let mut buf = [0u8; 64];
                    match tls.reader().read(&mut buf) {
                        Ok(n) if n >= 12 && &buf[..5] == b"HTTP/" => {
                            let status = &buf[9..12];
                            if status[0] == b'2'
                                && status[1].is_ascii_digit()
                                && status[2].is_ascii_digit()
                            {
                                let seq = conn.seq;
                                let id = self.probe_id;
                                self.conn = None;
                                return Ok(Some((seq, id)));
                            }
                            log::debug!(
                                "HTTPS probe got non-2xx status: {}",
                                String::from_utf8_lossy(&buf[9..n.min(32)])
                            );
                            self.conn = None;
                            return Ok(None);
                        }
                        Ok(_) => {
                            self.conn = None;
                            return Ok(None);
                        }
                        Err(e) if e.kind() == io::ErrorKind::WouldBlock => {
                            return Ok(None);
                        }
                        Err(e) => {
                            log::debug!("HTTPS probe read error: {e}");
                            self.conn = None;
                            return Ok(None);
                        }
                    }
                }
            }
        }
    }
}

impl ProbeTransport for HttpsSocket {
    fn send(&mut self, target: IpAddr, seq: u16, _id: u16, _payload_size: usize) -> Result<()> {
        self.start_connect(target, seq)
    }
    fn recv(&mut self) -> Result<Option<(u16, u16)>> {
        self.check_response()
    }
    fn fds(&self) -> Vec<RawFd> {
        vec![]
    }
}

impl Drop for HttpsSocket {
    fn drop(&mut self) {
        self.conn = None;
    }
}

/// Apply SO_MARK and SO_BINDTODEVICE to a TCP socket.
fn configure_socket(fd: RawFd, device: &str) -> Result<()> {
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
        return Err(Error::Config(format!("device name too long: {device}")));
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

/// Wrapper around a raw fd that implements `Read` and `Write` for rustls.
struct RawTcpStream(RawFd);

impl Read for RawTcpStream {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let ret = unsafe {
            libc::recv(self.0, buf.as_mut_ptr() as *mut libc::c_void, buf.len(), 0)
        };
        if ret < 0 {
            Err(io::Error::last_os_error())
        } else {
            Ok(ret as usize)
        }
    }
}

impl Write for RawTcpStream {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        let ret = unsafe {
            libc::send(
                self.0,
                buf.as_ptr() as *const libc::c_void,
                buf.len(),
                libc::MSG_NOSIGNAL,
            )
        };
        if ret < 0 {
            Err(io::Error::last_os_error())
        } else {
            Ok(ret as usize)
        }
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}
