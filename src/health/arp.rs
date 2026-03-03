//! ARP health probe socket.
//!
//! Sends ARP requests to a configured gateway target and checks for ARP
//! replies. Useful for detecting local gateway failures without requiring
//! internet reachability -- ICMP probes may succeed if the gateway forwards
//! pings upstream, masking a local link issue.
//!
//! ARP operates at layer 2 and is IPv4-only. The socket uses AF_PACKET
//! with SOCK_DGRAM (kernel handles Ethernet framing). Like other probe
//! types, it is persistent and registered with mio for readability events.

use std::io;
use std::mem;
use std::net::IpAddr;
use std::os::unix::io::RawFd;

use crate::error::{Error, Result};
use super::ProbeTransport;

/// Firewall mark applied to all health-probe packets (shared with ICMP/DNS).
const PROBE_MARK: u32 = 0xDEAD;

/// EtherType for ARP (0x0806).
const ETH_P_ARP: u16 = 0x0806;

/// ARP hardware type: Ethernet.
const ARPHRD_ETHER: u16 = 1;

/// ARP operation: request.
const ARPOP_REQUEST: u16 = 1;

/// ARP operation: reply.
const ARPOP_REPLY: u16 = 2;

/// ARP packet length for IPv4-over-Ethernet (no padding).
const ARP_PKT_LEN: usize = 28;

/// ARP health probe socket bound to a single interface.
///
/// Creates an AF_PACKET SOCK_DGRAM socket filtered to ETH_P_ARP.
/// The source MAC and IPv4 address are captured at creation time via
/// ioctl and used to build ARP request packets.
pub struct ArpSocket {
    fd: RawFd,
    ifindex: i32,
    src_mac: [u8; 6],
    src_ip: [u8; 4],
    /// Target IP from the most recent send, used to match replies.
    pending_target: Option<[u8; 4]>,
    pending_seq: u16,
    probe_id: u16,
}

impl ArpSocket {
    /// Create an ARP probe socket bound to `device`.
    ///
    /// Retrieves the interface's MAC and IPv4 address via ioctl. If no
    /// IPv4 address is assigned yet, 0.0.0.0 is used (ARP probe style).
    pub fn new(device: &str, probe_id: u16) -> Result<Self> {
        let fd = unsafe {
            libc::socket(
                libc::AF_PACKET,
                libc::SOCK_DGRAM | libc::SOCK_CLOEXEC | libc::SOCK_NONBLOCK,
                (ETH_P_ARP.to_be()) as libc::c_int,
            )
        };
        if fd < 0 {
            return Err(Error::Io(io::Error::last_os_error()));
        }

        match Self::configure(fd, device, probe_id) {
            Ok(sock) => Ok(sock),
            Err(e) => {
                unsafe { libc::close(fd) };
                Err(e)
            }
        }
    }

    /// Send an ARP request for `target` (must be IPv4).
    ///
    /// The `seq` parameter is stored internally and returned by
    /// `recv_reply` for matching -- ARP has no sequence number field.
    pub fn send_request(&mut self, target: IpAddr, seq: u16, _id: u16) -> Result<()> {
        let target_ip = match target {
            IpAddr::V4(v4) => v4.octets(),
            IpAddr::V6(_) => {
                return Err(Error::Config(
                    "ARP probes only support IPv4 targets".into(),
                ));
            }
        };

        // Build ARP request (28 bytes)
        let mut pkt = [0u8; ARP_PKT_LEN];
        pkt[0..2].copy_from_slice(&ARPHRD_ETHER.to_be_bytes()); // hardware type
        pkt[2..4].copy_from_slice(&0x0800u16.to_be_bytes()); // protocol type (IPv4)
        pkt[4] = 6; // hardware address length
        pkt[5] = 4; // protocol address length
        pkt[6..8].copy_from_slice(&ARPOP_REQUEST.to_be_bytes()); // operation
        pkt[8..14].copy_from_slice(&self.src_mac); // sender hardware address
        pkt[14..18].copy_from_slice(&self.src_ip); // sender protocol address
        // target hardware address: zeros (bytes 18..24 already zeroed)
        pkt[24..28].copy_from_slice(&target_ip); // target protocol address

        // Send to Ethernet broadcast via sockaddr_ll
        let mut dst: libc::sockaddr_ll = unsafe { mem::zeroed() };
        dst.sll_family = libc::AF_PACKET as u16;
        dst.sll_protocol = ETH_P_ARP.to_be();
        dst.sll_ifindex = self.ifindex;
        dst.sll_halen = 6;
        dst.sll_addr[..6].copy_from_slice(&[0xFF; 6]);

        let ret = unsafe {
            libc::sendto(
                self.fd,
                pkt.as_ptr() as *const libc::c_void,
                pkt.len(),
                0,
                &dst as *const libc::sockaddr_ll as *const libc::sockaddr,
                mem::size_of::<libc::sockaddr_ll>() as libc::socklen_t,
            )
        };
        if ret < 0 {
            return Err(Error::Io(io::Error::last_os_error()));
        }

        self.pending_target = Some(target_ip);
        self.pending_seq = seq;
        Ok(())
    }

    /// Non-blocking check for an ARP reply from the pending target.
    ///
    /// Returns `Ok(Some((seq, id)))` if a matching ARP reply was received,
    /// `Ok(None)` if no data is available (EAGAIN) or the reply doesn't
    /// match, or an error.
    pub fn recv_reply(&mut self) -> Result<Option<(u16, u16)>> {
        let pending_target = match self.pending_target {
            Some(t) => t,
            None => return Ok(None),
        };

        let mut buf = [0u8; 64];
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
        if n < ARP_PKT_LEN {
            return Ok(None);
        }

        // Check operation is ARP reply (2)
        let op = u16::from_be_bytes([buf[6], buf[7]]);
        if op != ARPOP_REPLY {
            return Ok(None);
        }

        // Sender protocol address (bytes 14..18) must match our target
        if buf[14..18] != pending_target {
            return Ok(None);
        }

        Ok(Some((self.pending_seq, self.probe_id)))
    }

    /// Return the raw file descriptor for mio registration.
    pub fn fd(&self) -> RawFd {
        self.fd
    }

    /// Configure the AF_PACKET socket: get interface info, set mark, bind.
    fn configure(fd: RawFd, device: &str, probe_id: u16) -> Result<ArpSocket> {
        let name_bytes = device.as_bytes();
        if name_bytes.len() >= libc::IFNAMSIZ {
            return Err(Error::Config(format!("device name too long: {device}")));
        }

        // Get interface index (SIOCGIFINDEX)
        let mut ifr: libc::ifreq = unsafe { mem::zeroed() };
        unsafe {
            std::ptr::copy_nonoverlapping(
                name_bytes.as_ptr(),
                ifr.ifr_name.as_mut_ptr() as *mut u8,
                name_bytes.len(),
            );
        }
        if unsafe { libc::ioctl(fd, libc::SIOCGIFINDEX as _, &mut ifr) } < 0 {
            return Err(Error::Io(io::Error::last_os_error()));
        }
        let ifindex = unsafe { ifr.ifr_ifru.ifru_ifindex };

        // Get hardware (MAC) address (SIOCGIFHWADDR)
        let mut ifr_hw: libc::ifreq = unsafe { mem::zeroed() };
        unsafe {
            std::ptr::copy_nonoverlapping(
                name_bytes.as_ptr(),
                ifr_hw.ifr_name.as_mut_ptr() as *mut u8,
                name_bytes.len(),
            );
        }
        if unsafe { libc::ioctl(fd, libc::SIOCGIFHWADDR as _, &mut ifr_hw) } < 0 {
            return Err(Error::Io(io::Error::last_os_error()));
        }
        let mut src_mac = [0u8; 6];
        unsafe {
            std::ptr::copy_nonoverlapping(
                ifr_hw.ifr_ifru.ifru_hwaddr.sa_data.as_ptr() as *const u8,
                src_mac.as_mut_ptr(),
                6,
            );
        }

        // Get IPv4 address (SIOCGIFADDR -- needs an AF_INET socket)
        let src_ip = Self::get_ipv4(device)?;

        // Set SO_MARK for nftables identification
        let mark = PROBE_MARK;
        if unsafe {
            libc::setsockopt(
                fd,
                libc::SOL_SOCKET,
                libc::SO_MARK,
                &mark as *const u32 as *const libc::c_void,
                mem::size_of::<u32>() as libc::socklen_t,
            )
        } < 0
        {
            return Err(Error::Io(io::Error::last_os_error()));
        }

        // Bind to the interface via sockaddr_ll
        let mut sll: libc::sockaddr_ll = unsafe { mem::zeroed() };
        sll.sll_family = libc::AF_PACKET as u16;
        sll.sll_protocol = ETH_P_ARP.to_be();
        sll.sll_ifindex = ifindex;
        if unsafe {
            libc::bind(
                fd,
                &sll as *const libc::sockaddr_ll as *const libc::sockaddr,
                mem::size_of::<libc::sockaddr_ll>() as libc::socklen_t,
            )
        } < 0
        {
            return Err(Error::Io(io::Error::last_os_error()));
        }

        Ok(ArpSocket {
            fd,
            ifindex,
            src_mac,
            src_ip,
            pending_target: None,
            pending_seq: 0,
            probe_id,
        })
    }

    /// Retrieve the interface's IPv4 address via a temporary AF_INET socket.
    ///
    /// Returns `[0, 0, 0, 0]` if no address is assigned (ARP probe style).
    fn get_ipv4(device: &str) -> Result<[u8; 4]> {
        let inet_fd = unsafe {
            libc::socket(libc::AF_INET, libc::SOCK_DGRAM | libc::SOCK_CLOEXEC, 0)
        };
        if inet_fd < 0 {
            return Err(Error::Io(io::Error::last_os_error()));
        }

        let name_bytes = device.as_bytes();
        let mut ifr: libc::ifreq = unsafe { mem::zeroed() };
        unsafe {
            std::ptr::copy_nonoverlapping(
                name_bytes.as_ptr(),
                ifr.ifr_name.as_mut_ptr() as *mut u8,
                name_bytes.len(),
            );
        }

        let ret = unsafe { libc::ioctl(inet_fd, libc::SIOCGIFADDR as _, &mut ifr) };
        unsafe { libc::close(inet_fd) };
        if ret < 0 {
            // No address assigned -- use 0.0.0.0
            return Ok([0, 0, 0, 0]);
        }

        let sa = unsafe {
            &*(&ifr.ifr_ifru.ifru_addr as *const libc::sockaddr as *const libc::sockaddr_in)
        };
        Ok(sa.sin_addr.s_addr.to_ne_bytes())
    }
}

impl ProbeTransport for ArpSocket {
    fn send(&mut self, target: IpAddr, seq: u16, id: u16, _payload_size: usize) -> Result<()> {
        self.send_request(target, seq, id)
    }
    fn recv(&mut self) -> Result<Option<(u16, u16)>> {
        self.recv_reply()
    }
    fn fds(&self) -> Vec<RawFd> {
        vec![self.fd()]
    }
}

impl Drop for ArpSocket {
    fn drop(&mut self) {
        unsafe { libc::close(self.fd) };
    }
}
