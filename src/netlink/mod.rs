pub mod conntrack;
pub mod link;
pub mod route;
pub mod route_monitor;

use crate::error::{Error, Result};

use std::io;
use std::mem;
use std::os::fd::{AsRawFd, RawFd};

use mio::event::Source;
use mio::unix::SourceFd;
use mio::{Interest, Registry, Token};

// ---------------------------------------------------------------------------
// Netlink constants
// ---------------------------------------------------------------------------

pub const NETLINK_ROUTE: i32 = 0;
pub const NETLINK_NETFILTER: i32 = 12;

pub const NLM_F_REQUEST: u16 = 0x0001;
#[allow(dead_code)]
pub const NLM_F_MULTI: u16 = 0x0002;
pub const NLM_F_ACK: u16 = 0x0004;
pub const NLM_F_DUMP: u16 = 0x0300;
pub const NLM_F_CREATE: u16 = 0x0400;
pub const NLM_F_EXCL: u16 = 0x0200;

pub const NLMSG_ERROR: u16 = 0x0002;
pub const NLMSG_DONE: u16 = 0x0003;
#[allow(dead_code)]
pub const NLMSG_NOOP: u16 = 0x0001;

pub const RTM_NEWLINK: u16 = 16;
pub const RTM_DELLINK: u16 = 17;
#[allow(dead_code)]
pub const RTM_GETLINK: u16 = 18;
pub const RTM_NEWROUTE: u16 = 24;
pub const RTM_DELROUTE: u16 = 25;
pub const RTM_GETROUTE: u16 = 26;
pub const RTM_NEWADDR: u16 = 20;
pub const RTM_DELADDR: u16 = 21;
pub const RTM_GETADDR: u16 = 22;
pub const RTM_NEWRULE: u16 = 32;
pub const RTM_DELRULE: u16 = 33;

/// Netlink message header, matches struct nlmsghdr from linux/netlink.h.
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct NlMsgHdr {
    pub nlmsg_len: u32,
    pub nlmsg_type: u16,
    pub nlmsg_flags: u16,
    pub nlmsg_seq: u32,
    pub nlmsg_pid: u32,
}

pub const NLMSG_HDR_LEN: usize = mem::size_of::<NlMsgHdr>();

/// Align a length to a 4-byte boundary (NLMSG_ALIGN).
#[inline]
pub fn nlmsg_align(len: usize) -> usize {
    (len + 3) & !3
}

/// Read a `Copy` type from a byte buffer at the given offset.
///
/// Uses `ptr::read_unaligned` to avoid undefined behavior on architectures
/// with strict alignment requirements (e.g. MIPS).
///
/// # Safety
/// The caller must ensure `offset + size_of::<T>() <= buf.len()`.
#[inline]
pub(crate) unsafe fn read_struct<T: Copy>(buf: &[u8], offset: usize) -> T {
    unsafe { std::ptr::read_unaligned(buf.as_ptr().add(offset) as *const T) }
}

/// Netlink error response payload (struct nlmsgerr).
#[repr(C)]
#[derive(Debug, Clone, Copy)]
#[allow(dead_code)]
pub struct NlMsgErr {
    pub error: i32,
    pub msg: NlMsgHdr,
}

// ---------------------------------------------------------------------------
// NetlinkSocket
// ---------------------------------------------------------------------------

/// Raw netlink socket abstraction.
///
/// Wraps a non-blocking `AF_NETLINK` socket and provides low-level send/recv
/// operations as well as mio `Source` integration for event-loop registration.
pub struct NetlinkSocket {
    fd: RawFd,
}

impl NetlinkSocket {
    /// Open a netlink socket for the given protocol (e.g. `NETLINK_ROUTE`).
    ///
    /// The socket is bound to the kernel (pid 0) and set to non-blocking mode.
    /// Pass `groups != 0` to subscribe to multicast groups (e.g. RTNLGRP_LINK).
    pub fn open(protocol: i32, groups: u32) -> Result<Self> {
        let fd = unsafe {
            libc::socket(
                libc::AF_NETLINK,
                libc::SOCK_RAW | libc::SOCK_CLOEXEC,
                protocol,
            )
        };
        if fd < 0 {
            return Err(Error::Io(io::Error::last_os_error()));
        }

        // Bind the socket to the kernel
        let mut addr: libc::sockaddr_nl = unsafe { mem::zeroed() };
        addr.nl_family = libc::AF_NETLINK as u16;
        addr.nl_pid = 0; // let kernel assign
        addr.nl_groups = groups;

        let ret = unsafe {
            libc::bind(
                fd,
                &addr as *const libc::sockaddr_nl as *const libc::sockaddr,
                mem::size_of::<libc::sockaddr_nl>() as libc::socklen_t,
            )
        };
        if ret < 0 {
            let err = io::Error::last_os_error();
            unsafe { libc::close(fd) };
            return Err(Error::Io(err));
        }

        // Set non-blocking
        let flags = unsafe { libc::fcntl(fd, libc::F_GETFL) };
        if flags < 0 {
            let err = io::Error::last_os_error();
            unsafe { libc::close(fd) };
            return Err(Error::Io(err));
        }
        let ret = unsafe { libc::fcntl(fd, libc::F_SETFL, flags | libc::O_NONBLOCK) };
        if ret < 0 {
            let err = io::Error::last_os_error();
            unsafe { libc::close(fd) };
            return Err(Error::Io(err));
        }

        // Increase receive buffer for dump operations
        let buf_size: libc::c_int = 1024 * 1024;
        unsafe {
            libc::setsockopt(
                fd,
                libc::SOL_SOCKET,
                libc::SO_RCVBUF,
                &buf_size as *const libc::c_int as *const libc::c_void,
                mem::size_of::<libc::c_int>() as libc::socklen_t,
            );
        }

        Ok(Self { fd })
    }

    /// Send raw bytes over the netlink socket.
    pub fn send(&self, buf: &[u8]) -> Result<usize> {
        let ret = unsafe {
            libc::send(
                self.fd,
                buf.as_ptr() as *const libc::c_void,
                buf.len(),
                0,
            )
        };
        if ret < 0 {
            Err(Error::Io(io::Error::last_os_error()))
        } else {
            Ok(ret as usize)
        }
    }

    /// Receive raw bytes from the netlink socket into the provided buffer.
    ///
    /// Returns the number of bytes read on success. Returns `Ok(0)` if the
    /// socket would block (EAGAIN/EWOULDBLOCK). Returns an error if the
    /// kernel message was truncated (larger than the buffer).
    pub fn recv(&self, buf: &mut [u8]) -> Result<usize> {
        let ret = unsafe {
            libc::recv(
                self.fd,
                buf.as_mut_ptr() as *mut libc::c_void,
                buf.len(),
                libc::MSG_TRUNC,
            )
        };
        if ret < 0 {
            let err = io::Error::last_os_error();
            if err.kind() == io::ErrorKind::WouldBlock {
                return Ok(0);
            }
            Err(Error::Io(err))
        } else {
            let n = ret as usize;
            if n > buf.len() {
                log::warn!(
                    "netlink: message truncated ({n} bytes, buffer is {})",
                    buf.len()
                );
                // Return the buffer size -- the data in buf is valid up to
                // buf.len(), the trailing message is lost. Callers parse
                // individual nlmsghdr frames and will stop at the boundary.
                Ok(buf.len())
            } else {
                Ok(n)
            }
        }
    }

    /// Send a fully constructed netlink message and wait for the kernel ACK.
    ///
    /// The message must include `NLM_F_ACK` in its flags. This method blocks
    /// (via a loop with non-blocking recv) until an ACK or error is received.
    pub fn send_and_ack(&self, buf: &[u8]) -> Result<()> {
        self.send(buf)?;

        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
        let mut resp = [0u8; 4096];
        loop {
            let n = self.recv(&mut resp)?;
            if n == 0 {
                if std::time::Instant::now() >= deadline {
                    return Err(Error::Netlink("timeout waiting for kernel ACK".into()));
                }
                // Would block -- sleep briefly for the ACK. In practice
                // kernel ACKs arrive nearly instantly.
                std::thread::sleep(std::time::Duration::from_micros(100));
                continue;
            }
            return self.check_ack(&resp[..n]);
        }
    }

    /// Parse a received buffer for a netlink ACK (NLMSG_ERROR with error == 0)
    /// or return the kernel error.
    fn check_ack(&self, buf: &[u8]) -> Result<()> {
        if buf.len() < NLMSG_HDR_LEN {
            return Err(Error::Netlink("response too short".into()));
        }

        let hdr: NlMsgHdr = unsafe { read_struct(buf, 0) };

        if hdr.nlmsg_type == NLMSG_ERROR {
            if buf.len() < NLMSG_HDR_LEN + mem::size_of::<i32>() {
                return Err(Error::Netlink("truncated error response".into()));
            }
            let errcode: i32 = unsafe { read_struct(buf, NLMSG_HDR_LEN) };
            if errcode == 0 {
                Ok(())
            } else {
                Err(Error::Netlink(format!(
                    "kernel returned error: {}",
                    io::Error::from_raw_os_error(-errcode)
                )))
            }
        } else {
            // Not an error message -- treat as unexpected
            Err(Error::Netlink(format!(
                "unexpected response type: {}",
                hdr.nlmsg_type
            )))
        }
    }

    /// Return the raw file descriptor.
    pub fn fd(&self) -> RawFd {
        self.fd
    }
}

impl AsRawFd for NetlinkSocket {
    fn as_raw_fd(&self) -> RawFd {
        self.fd
    }
}

impl Drop for NetlinkSocket {
    fn drop(&mut self) {
        unsafe { libc::close(self.fd) };
    }
}

impl Source for NetlinkSocket {
    fn register(
        &mut self,
        registry: &Registry,
        token: Token,
        interests: Interest,
    ) -> io::Result<()> {
        SourceFd(&self.fd).register(registry, token, interests)
    }

    fn reregister(
        &mut self,
        registry: &Registry,
        token: Token,
        interests: Interest,
    ) -> io::Result<()> {
        SourceFd(&self.fd).reregister(registry, token, interests)
    }

    fn deregister(&mut self, registry: &Registry) -> io::Result<()> {
        SourceFd(&self.fd).deregister(registry)
    }
}

// ---------------------------------------------------------------------------
// Message builder helper
// ---------------------------------------------------------------------------

/// A simple buffer-based netlink message builder.
///
/// Builds a message by appending a header, a protocol payload (e.g. rtmsg),
/// and a sequence of netlink attributes (RTAs). The header length field is
/// updated automatically when `finish()` is called.
pub struct NlMsgBuilder {
    buf: Vec<u8>,
}

impl NlMsgBuilder {
    /// Create a new builder with the given message type and flags.
    pub fn new(nlmsg_type: u16, flags: u16, seq: u32) -> Self {
        let hdr = NlMsgHdr {
            nlmsg_len: 0, // filled in by finish()
            nlmsg_type,
            nlmsg_flags: flags,
            nlmsg_seq: seq,
            nlmsg_pid: 0,
        };
        let mut buf = Vec::with_capacity(256);
        let hdr_bytes = unsafe {
            std::slice::from_raw_parts(
                &hdr as *const NlMsgHdr as *const u8,
                NLMSG_HDR_LEN,
            )
        };
        buf.extend_from_slice(hdr_bytes);
        Self { buf }
    }

    /// Append a protocol-level payload struct (e.g. RtMsg, IfInfoMsg).
    pub fn push_payload<T: Sized>(&mut self, payload: &T) {
        let bytes = unsafe {
            std::slice::from_raw_parts(
                payload as *const T as *const u8,
                mem::size_of::<T>(),
            )
        };
        self.buf.extend_from_slice(bytes);
    }

    /// Append a netlink attribute (struct rtattr + value).
    pub fn push_attr(&mut self, rta_type: u16, data: &[u8]) {
        let rta_len = 4 + data.len(); // sizeof(rtattr) == 4
        // rtattr header: rta_len (u16) + rta_type (u16)
        self.buf.extend_from_slice(&(rta_len as u16).to_ne_bytes());
        self.buf.extend_from_slice(&rta_type.to_ne_bytes());
        self.buf.extend_from_slice(data);
        // Pad to 4-byte alignment
        let aligned = nlmsg_align(rta_len);
        let pad = aligned - rta_len;
        for _ in 0..pad {
            self.buf.push(0);
        }
    }

    /// Finalize the message, updating the nlmsg_len field.
    /// Returns the completed byte buffer.
    pub fn finish(mut self) -> Vec<u8> {
        let len = self.buf.len() as u32;
        // Write nlmsg_len at the start of the buffer (first 4 bytes of NlMsgHdr)
        self.buf[..4].copy_from_slice(&len.to_ne_bytes());
        self.buf
    }
}
