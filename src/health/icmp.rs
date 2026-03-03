use std::io;
use std::mem;
use std::net::IpAddr;
use std::os::unix::io::RawFd;

use crate::error::{Error, Result};
use super::ProbeTransport;

/// Firewall mark applied to all health-probe packets.
///
/// nopal's nftables rules skip packets with this mark, preventing probe traffic
/// from being re-marked by policy routing. This avoids the IPv6 routing loops
/// that plague mwan3 (where probe packets get caught in the same rules they are
/// trying to test).
const PROBE_MARK: u32 = 0xDEAD;

// ICMP type constants
const ICMP_ECHO_REQUEST: u8 = 8;
const ICMP_ECHO_REPLY: u8 = 0;
const ICMPV6_ECHO_REQUEST: u8 = 128;
const ICMPV6_ECHO_REPLY: u8 = 129;

/// Raw ICMP socket bound to a specific network device.
///
/// Uses `SOCK_DGRAM` for unprivileged ICMP (kernel handles the IP header).
/// Each socket is bound to a device via `SO_BINDTODEVICE` and marked with
/// `SO_MARK` so nftables rules can identify and skip probe packets.
pub struct IcmpSocket {
    fd: RawFd,
    is_v6: bool,
    send_buf: Vec<u8>,
}

impl IcmpSocket {
    /// Create an ICMPv4 socket bound to `device`.
    pub fn new_v4(device: &str) -> Result<Self> {
        let fd = unsafe {
            libc::socket(
                libc::AF_INET,
                libc::SOCK_DGRAM | libc::SOCK_CLOEXEC,
                libc::IPPROTO_ICMP,
            )
        };
        if fd < 0 {
            return Err(Error::Io(io::Error::last_os_error()));
        }

        if let Err(e) = Self::configure(fd, device) {
            unsafe { libc::close(fd) };
            return Err(e);
        }

        Ok(Self { fd, is_v6: false, send_buf: Vec::new() })
    }

    /// Create an ICMPv6 socket bound to `device`.
    pub fn new_v6(device: &str) -> Result<Self> {
        let fd = unsafe {
            libc::socket(
                libc::AF_INET6,
                libc::SOCK_DGRAM | libc::SOCK_CLOEXEC,
                libc::IPPROTO_ICMPV6,
            )
        };
        if fd < 0 {
            return Err(Error::Io(io::Error::last_os_error()));
        }

        if let Err(e) = Self::configure(fd, device) {
            unsafe { libc::close(fd) };
            return Err(e);
        }

        Ok(Self { fd, is_v6: true, send_buf: Vec::new() })
    }

    /// Set the IP TTL (or IPv6 hop limit) on this socket.
    pub fn set_ttl(&self, ttl: u32) -> Result<()> {
        let ttl_val = ttl as libc::c_int;
        let (level, optname) = if self.is_v6 {
            (libc::IPPROTO_IPV6, libc::IPV6_UNICAST_HOPS)
        } else {
            (libc::IPPROTO_IP, libc::IP_TTL)
        };
        let ret = unsafe {
            libc::setsockopt(
                self.fd,
                level,
                optname,
                &ttl_val as *const libc::c_int as *const libc::c_void,
                mem::size_of::<libc::c_int>() as libc::socklen_t,
            )
        };
        if ret < 0 {
            return Err(Error::Io(io::Error::last_os_error()));
        }
        Ok(())
    }

    /// Apply common socket options: SO_MARK, SO_BINDTODEVICE, non-blocking.
    fn configure(fd: RawFd, device: &str) -> Result<()> {
        // Set SO_MARK so nftables can identify probe packets
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

        // Bind to the specific network device
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

        // Set non-blocking
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

    /// Send an ICMP echo request to `target` with the given `seq` and `id`.
    ///
    /// Builds the ICMP packet manually: type, code, checksum, identifier,
    /// sequence number, plus `payload_size` bytes of payload (min 8).
    pub fn send_echo(&mut self, target: IpAddr, seq: u16, id: u16, payload_size: usize) -> Result<()> {
        let payload_len = payload_size.max(8);
        let total_len = 8 + payload_len; // 8-byte ICMP header + payload

        // Resize and reuse the pre-allocated buffer
        self.send_buf.resize(total_len, 0);
        let pkt = &mut self.send_buf;

        // Type and code
        let icmp_type = if self.is_v6 {
            ICMPV6_ECHO_REQUEST
        } else {
            ICMP_ECHO_REQUEST
        };
        pkt[0] = icmp_type;
        pkt[1] = 0; // code
        pkt[2] = 0; // checksum (zeroed for calculation)
        pkt[3] = 0;

        // Identifier (network byte order)
        pkt[4] = (id >> 8) as u8;
        pkt[5] = (id & 0xFF) as u8;

        // Sequence number (network byte order)
        pkt[6] = (seq >> 8) as u8;
        pkt[7] = (seq & 0xFF) as u8;

        // Payload: fill with a recognizable repeating pattern
        let pattern = b"nopalprb";
        for (i, byte) in pkt[8..].iter_mut().enumerate() {
            *byte = pattern[i % pattern.len()];
        }

        // Checksum: For SOCK_DGRAM ICMP sockets, the kernel computes the
        // ICMPv6 checksum (which includes a pseudo-header). For ICMPv4 we
        // must compute it ourselves.
        if !self.is_v6 {
            let cksum = internet_checksum(pkt);
            pkt[2] = (cksum >> 8) as u8;
            pkt[3] = (cksum & 0xFF) as u8;
        }

        match target {
            IpAddr::V4(addr) => {
                let octets = addr.octets();
                let mut sa: libc::sockaddr_in = unsafe { mem::zeroed() };
                sa.sin_family = libc::AF_INET as libc::sa_family_t;
                sa.sin_addr.s_addr = u32::from_ne_bytes(octets);

                let ret = unsafe {
                    libc::sendto(
                        self.fd,
                        pkt.as_ptr() as *const libc::c_void,
                        pkt.len(),
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
                sa.sin6_addr.s6_addr = addr.octets();

                let ret = unsafe {
                    libc::sendto(
                        self.fd,
                        pkt.as_ptr() as *const libc::c_void,
                        pkt.len(),
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

    /// Non-blocking receive of an ICMP echo reply.
    ///
    /// Returns `Ok(Some((seq, id)))` if a valid echo reply was read,
    /// `Ok(None)` if no data is available (EAGAIN), or an error.
    pub fn recv_echo(&self) -> Result<Option<(u16, u16)>> {
        let mut buf = [0u8; 256];
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

        // For SOCK_DGRAM ICMP sockets the kernel strips the IP header, so
        // the buffer starts directly with the ICMP header.
        if n < 8 {
            // Too short to be a valid ICMP message
            return Ok(None);
        }

        let expected_reply = if self.is_v6 {
            ICMPV6_ECHO_REPLY
        } else {
            ICMP_ECHO_REPLY
        };

        if buf[0] != expected_reply {
            // Not an echo reply (could be destination unreachable, etc.)
            return Ok(None);
        }

        let id = u16::from_be_bytes([buf[4], buf[5]]);
        let seq = u16::from_be_bytes([buf[6], buf[7]]);

        Ok(Some((seq, id)))
    }

    /// Return the raw file descriptor for mio registration.
    pub fn fd(&self) -> RawFd {
        self.fd
    }

    /// Whether this is an IPv6 socket.
    #[allow(dead_code)]
    pub fn is_v6(&self) -> bool {
        self.is_v6
    }
}

impl ProbeTransport for IcmpSocket {
    fn send(&mut self, target: IpAddr, seq: u16, id: u16, payload_size: usize) -> Result<()> {
        self.send_echo(target, seq, id, payload_size)
    }
    fn recv(&mut self) -> Result<Option<(u16, u16)>> {
        self.recv_echo()
    }
    fn fds(&self) -> Vec<RawFd> {
        vec![self.fd()]
    }
}

impl Drop for IcmpSocket {
    fn drop(&mut self) {
        unsafe { libc::close(self.fd) };
    }
}

/// Compute the ones-complement (Internet) checksum over a byte slice.
///
/// This is the standard algorithm from RFC 1071, used for ICMPv4 checksums.
/// The checksum field in the input must be zeroed before calling.
fn internet_checksum(data: &[u8]) -> u16 {
    let mut sum: u32 = 0;
    let mut i = 0;

    // Sum 16-bit words
    while i + 1 < data.len() {
        sum += u16::from_be_bytes([data[i], data[i + 1]]) as u32;
        i += 2;
    }

    // Handle trailing odd byte
    if i < data.len() {
        sum += (data[i] as u32) << 8;
    }

    // Fold 32-bit sum into 16 bits
    while sum >> 16 != 0 {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }

    !sum as u16
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn checksum_zeroed_buffer() {
        // All-zero buffer should produce 0xFFFF checksum
        let data = [0u8; 16];
        assert_eq!(internet_checksum(&data), 0xFFFF);
    }

    #[test]
    fn checksum_echo_request() {
        // Build a mock ICMPv4 echo request and verify the checksum is
        // consistent (recomputing over the packet with checksum filled in
        // should yield 0).
        let mut pkt = [0u8; 16];
        pkt[0] = ICMP_ECHO_REQUEST;
        pkt[1] = 0;
        // id = 1, seq = 1
        pkt[4] = 0;
        pkt[5] = 1;
        pkt[6] = 0;
        pkt[7] = 1;
        pkt[8..16].copy_from_slice(b"nopalprb");

        let cksum = internet_checksum(&pkt);
        pkt[2] = (cksum >> 8) as u8;
        pkt[3] = (cksum & 0xFF) as u8;

        // Verifying: checksum of the entire packet (with checksum filled in)
        // should be zero.
        assert_eq!(internet_checksum(&pkt), 0);
    }

    #[test]
    fn checksum_odd_length() {
        let data = [0xAA, 0xBB, 0xCC];
        let cksum = internet_checksum(&data);
        // Verify it is a valid 16-bit value and not obviously wrong
        assert_ne!(cksum, 0);
    }
}
