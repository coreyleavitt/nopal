//! DNS health probe socket.
//!
//! Sends minimal DNS queries (root "." A record) to configured DNS server
//! targets over UDP port 53. Any valid DNS response with a matching
//! transaction ID indicates the server is reachable.
//!
//! Like ICMP probes, DNS sockets are bound to a specific device via
//! `SO_BINDTODEVICE` and marked with `SO_MARK = 0xDEAD` for nftables
//! exemption.

use std::io;
use std::mem;
use std::net::IpAddr;
use std::os::unix::io::RawFd;

use crate::error::{Error, Result};
use super::ProbeTransport;

/// Firewall mark applied to all health-probe packets (shared with ICMP).
const PROBE_MARK: u32 = 0xDEAD;

/// Standard DNS port.
const DNS_PORT: u16 = 53;

/// UDP socket for DNS health probes.
pub struct DnsSocket {
    fd: RawFd,
    /// Interface identifier returned on recv to match the probe engine's
    /// (seq, id) protocol. Stored at construction time since DNS responses
    /// don't carry this information.
    probe_id: u16,
    /// Pre-built DNS query template (txid=0). Bytes 0-1 are overwritten per send.
    query_template: Vec<u8>,
}

impl DnsSocket {
    /// Create a UDP socket for DNS probes over IPv4.
    pub fn new_v4(device: &str, probe_id: u16, query_name: &str) -> Result<Self> {
        let fd = unsafe {
            libc::socket(
                libc::AF_INET,
                libc::SOCK_DGRAM | libc::SOCK_CLOEXEC,
                0,
            )
        };
        if fd < 0 {
            return Err(Error::Io(io::Error::last_os_error()));
        }

        if let Err(e) = Self::configure(fd, device) {
            unsafe { libc::close(fd) };
            return Err(e);
        }

        let query_template = build_dns_query_for(0, query_name);
        Ok(Self { fd, probe_id, query_template })
    }

    /// Create a UDP socket for DNS probes over IPv6.
    pub fn new_v6(device: &str, probe_id: u16, query_name: &str) -> Result<Self> {
        let fd = unsafe {
            libc::socket(
                libc::AF_INET6,
                libc::SOCK_DGRAM | libc::SOCK_CLOEXEC,
                0,
            )
        };
        if fd < 0 {
            return Err(Error::Io(io::Error::last_os_error()));
        }

        if let Err(e) = Self::configure(fd, device) {
            unsafe { libc::close(fd) };
            return Err(e);
        }

        let query_template = build_dns_query_for(0, query_name);
        Ok(Self { fd, probe_id, query_template })
    }

    /// Apply common socket options: SO_MARK, SO_BINDTODEVICE, non-blocking.
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

        let flags = unsafe { libc::fcntl(fd, libc::F_GETFL) };
        if flags < 0 {
            return Err(Error::Io(io::Error::last_os_error()));
        }
        let ret = unsafe { libc::fcntl(fd, libc::F_SETFL, flags | libc::O_NONBLOCK) };
        if ret < 0 {
            return Err(Error::Io(io::Error::last_os_error()));
        }

        Ok(())
    }

    /// Send a DNS query to `target:53`.
    ///
    /// Builds a minimal query for "." (root) type A. The DNS transaction ID
    /// is set to `seq` so the response can be matched back to the probe.
    pub fn send_query(&mut self, target: IpAddr, seq: u16, _id: u16) -> Result<()> {
        // Stamp the txid into the cached template (bytes 0-1)
        self.query_template[0] = (seq >> 8) as u8;
        self.query_template[1] = (seq & 0xFF) as u8;
        let query = &self.query_template;

        match target {
            IpAddr::V4(addr) => {
                let octets = addr.octets();
                let mut sa: libc::sockaddr_in = unsafe { mem::zeroed() };
                sa.sin_family = libc::AF_INET as libc::sa_family_t;
                sa.sin_port = DNS_PORT.to_be();
                sa.sin_addr.s_addr = u32::from_ne_bytes(octets);

                let ret = unsafe {
                    libc::sendto(
                        self.fd,
                        query.as_ptr() as *const libc::c_void,
                        query.len(),
                        0,
                        &sa as *const libc::sockaddr_in as *const libc::sockaddr,
                        mem::size_of::<libc::sockaddr_in>() as libc::socklen_t,
                    )
                };
                if ret < 0 {
                    return Err(Error::Io(io::Error::last_os_error()));
                }
            }
            IpAddr::V6(addr) => {
                let mut sa: libc::sockaddr_in6 = unsafe { mem::zeroed() };
                sa.sin6_family = libc::AF_INET6 as libc::sa_family_t;
                sa.sin6_port = DNS_PORT.to_be();
                sa.sin6_addr.s6_addr = addr.octets();

                let ret = unsafe {
                    libc::sendto(
                        self.fd,
                        query.as_ptr() as *const libc::c_void,
                        query.len(),
                        0,
                        &sa as *const libc::sockaddr_in6 as *const libc::sockaddr,
                        mem::size_of::<libc::sockaddr_in6>() as libc::socklen_t,
                    )
                };
                if ret < 0 {
                    return Err(Error::Io(io::Error::last_os_error()));
                }
            }
        }

        Ok(())
    }

    /// Non-blocking receive of a DNS response.
    ///
    /// Returns `Ok(Some((seq, id)))` if a valid DNS response was received
    /// (transaction ID maps to seq, id is the stored probe_id),
    /// `Ok(None)` if no data is available (EAGAIN), or an error.
    pub fn recv_response(&self) -> Result<Option<(u16, u16)>> {
        let mut buf = [0u8; 512];
        let ret = unsafe {
            libc::recv(
                self.fd,
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

        // DNS header is 12 bytes minimum
        if n < 12 {
            return Ok(None);
        }

        // Check QR bit (bit 15 of flags) -- must be 1 (response)
        if buf[2] & 0x80 == 0 {
            return Ok(None);
        }

        // Extract transaction ID
        let txid = u16::from_be_bytes([buf[0], buf[1]]);

        Ok(Some((txid, self.probe_id)))
    }

    /// Return the raw file descriptor for mio registration.
    pub fn fd(&self) -> RawFd {
        self.fd
    }
}

impl ProbeTransport for DnsSocket {
    fn send(&mut self, target: IpAddr, seq: u16, id: u16, _payload_size: usize) -> Result<()> {
        self.send_query(target, seq, id)
    }
    fn recv(&mut self) -> Result<Option<(u16, u16)>> {
        self.recv_response()
    }
    fn fds(&self) -> Vec<RawFd> {
        vec![self.fd()]
    }
}

impl Drop for DnsSocket {
    fn drop(&mut self) {
        unsafe { libc::close(self.fd) };
    }
}

/// Build a DNS query for a given domain name (or root "." if empty).
///
/// Layout:
///   - Header (12 bytes): txid, flags=0x0100 (standard query, RD=1), qdcount=1
///   - Question: encoded domain name, type A (1), class IN (1)
fn build_dns_query_for(txid: u16, name: &str) -> Vec<u8> {
    let mut q = vec![0u8; 12];

    // Transaction ID
    q[0] = (txid >> 8) as u8;
    q[1] = (txid & 0xFF) as u8;

    // Flags: standard query, recursion desired
    q[2] = 0x01;
    q[3] = 0x00;

    // QDCOUNT = 1
    q[4] = 0x00;
    q[5] = 0x01;

    // Question section: encode domain name as DNS labels
    if name.is_empty() {
        q.push(0x00); // root label
    } else {
        for label in name.trim_end_matches('.').split('.') {
            let len = label.len().min(63) as u8;
            q.push(len);
            q.extend_from_slice(&label.as_bytes()[..len as usize]);
        }
        q.push(0x00); // terminating root label
    }

    // Type A (1)
    q.push(0x00);
    q.push(0x01);

    // Class IN (1)
    q.push(0x00);
    q.push(0x01);

    q
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dns_query_structure() {
        let q = build_dns_query_for(0x1234, "");

        // Transaction ID
        assert_eq!(q[0], 0x12);
        assert_eq!(q[1], 0x34);

        // Flags: standard query, RD=1
        assert_eq!(q[2], 0x01);
        assert_eq!(q[3], 0x00);

        // QDCOUNT = 1
        assert_eq!(u16::from_be_bytes([q[4], q[5]]), 1);

        // ANCOUNT, NSCOUNT, ARCOUNT = 0
        assert_eq!(u16::from_be_bytes([q[6], q[7]]), 0);
        assert_eq!(u16::from_be_bytes([q[8], q[9]]), 0);
        assert_eq!(u16::from_be_bytes([q[10], q[11]]), 0);

        // Root label
        assert_eq!(q[12], 0x00);

        // Type A
        assert_eq!(u16::from_be_bytes([q[13], q[14]]), 1);

        // Class IN
        assert_eq!(u16::from_be_bytes([q[15], q[16]]), 1);

        // Total length
        assert_eq!(q.len(), 17);
    }

    #[test]
    fn dns_query_with_domain_name() {
        let q = build_dns_query_for(0xABCD, "example.com");

        // Transaction ID
        assert_eq!(q[0], 0xAB);
        assert_eq!(q[1], 0xCD);

        // Question section starts at byte 12
        // "example" label: length 7, then "example"
        assert_eq!(q[12], 7);
        assert_eq!(&q[13..20], b"example");

        // "com" label: length 3, then "com"
        assert_eq!(q[20], 3);
        assert_eq!(&q[21..24], b"com");

        // Root terminator
        assert_eq!(q[24], 0x00);

        // Type A
        assert_eq!(u16::from_be_bytes([q[25], q[26]]), 1);

        // Class IN
        assert_eq!(u16::from_be_bytes([q[27], q[28]]), 1);

        // Total: 12 header + 1+7 + 1+3 + 1 + 2+2 = 29
        assert_eq!(q.len(), 29);
    }

    #[test]
    fn dns_query_trailing_dot_stripped() {
        let q1 = build_dns_query_for(1, "example.com.");
        let q2 = build_dns_query_for(1, "example.com");
        // Trailing dot should be stripped, producing identical question sections
        assert_eq!(q1[12..], q2[12..]);
    }
}
