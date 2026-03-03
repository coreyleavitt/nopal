use crate::error::Result;
use crate::netlink::{
    NlMsgHdr, NetlinkSocket, NETLINK_ROUTE, NLMSG_HDR_LEN, RTM_DELLINK, RTM_NEWLINK,
    nlmsg_align, read_struct,
};

use std::mem;
use std::os::fd::RawFd;

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// RTNLGRP_LINK multicast group (group 1 -> bit 0).
const RTNLGRP_LINK: u32 = 1;

/// Interface info message (struct ifinfomsg from linux/rtnetlink.h).
#[repr(C)]
#[derive(Debug, Clone, Copy)]
struct IfInfoMsg {
    ifi_family: u8,
    __ifi_pad: u8,
    ifi_type: u16,
    ifi_index: i32,
    ifi_flags: u32,
    ifi_change: u32,
}

// Interface flags from linux/if.h
const IFF_UP: u32 = 0x1;
const IFF_RUNNING: u32 = 0x40;

// Interface link attribute types (IFLA_*)
const IFLA_IFNAME: u16 = 3;

// ---------------------------------------------------------------------------
// LinkEvent
// ---------------------------------------------------------------------------

/// A link state change event parsed from a netlink notification.
#[derive(Debug, Clone)]
pub enum LinkEvent {
    /// Interface is up and running.
    Up { ifname: String, ifindex: u32 },
    /// Interface is down or no longer running.
    Down { ifname: String, #[allow(dead_code)] ifindex: u32 },
}

// ---------------------------------------------------------------------------
// LinkMonitor
// ---------------------------------------------------------------------------

/// Monitors network link state changes via a netlink multicast subscription.
///
/// Subscribes to `RTNLGRP_LINK` and parses `RTM_NEWLINK` / `RTM_DELLINK`
/// messages to detect interface up/down transitions.
pub struct LinkMonitor {
    sock: NetlinkSocket,
    recv_buf: Vec<u8>,
}

impl LinkMonitor {
    /// Create a new `LinkMonitor` subscribed to the link multicast group.
    pub fn new() -> Result<Self> {
        let sock = NetlinkSocket::open(NETLINK_ROUTE, RTNLGRP_LINK)?;
        Ok(Self { sock, recv_buf: vec![0u8; 65536] })
    }

    /// Return the raw file descriptor for mio registration.
    #[allow(dead_code)]
    pub fn fd(&self) -> RawFd {
        self.sock.fd()
    }

    /// Return a mutable reference to the underlying socket for mio
    /// `Source` registration.
    pub fn source(&mut self) -> &mut NetlinkSocket {
        &mut self.sock
    }

    /// Read and parse pending link events from the socket.
    ///
    /// Returns an empty `Vec` if no data is available (non-blocking).
    /// Multiple events may be returned if several netlink messages are
    /// batched in a single read.
    pub fn read_events(&mut self) -> Result<Vec<LinkEvent>> {
        let n = self.sock.recv(&mut self.recv_buf)?;
        if n == 0 {
            return Ok(Vec::new());
        }

        let mut events = Vec::new();
        let mut offset = 0;

        while offset + NLMSG_HDR_LEN <= n {
            let hdr: NlMsgHdr = unsafe { read_struct(&self.recv_buf, offset) };
            let msg_len = hdr.nlmsg_len as usize;
            if msg_len < NLMSG_HDR_LEN || offset + msg_len > n {
                break;
            }

            if hdr.nlmsg_type == RTM_NEWLINK || hdr.nlmsg_type == RTM_DELLINK {
                if let Some(event) = self.parse_link_msg(
                    &self.recv_buf[offset..offset + msg_len],
                    hdr.nlmsg_type,
                ) {
                    events.push(event);
                }
            }

            offset += nlmsg_align(msg_len);
        }

        Ok(events)
    }

    /// Parse a single RTM_NEWLINK or RTM_DELLINK message into a `LinkEvent`.
    fn parse_link_msg(&self, msg: &[u8], msg_type: u16) -> Option<LinkEvent> {
        let ifi_offset = NLMSG_HDR_LEN;
        let ifi_size = mem::size_of::<IfInfoMsg>();

        if msg.len() < ifi_offset + ifi_size {
            return None;
        }

        let ifi: IfInfoMsg = unsafe { read_struct(msg, ifi_offset) };

        let ifindex = ifi.ifi_index as u32;

        // Parse attributes to find IFLA_IFNAME
        let attr_start = ifi_offset + nlmsg_align(ifi_size);
        let ifname = self.find_ifname(msg, attr_start)?;

        // Determine link state:
        // - RTM_DELLINK always means "down" (interface removed)
        // - RTM_NEWLINK: check IFF_UP and IFF_RUNNING flags
        if msg_type == RTM_DELLINK {
            Some(LinkEvent::Down { ifname, ifindex })
        } else {
            let up = (ifi.ifi_flags & IFF_UP) != 0
                && (ifi.ifi_flags & IFF_RUNNING) != 0;
            if up {
                Some(LinkEvent::Up { ifname, ifindex })
            } else {
                Some(LinkEvent::Down { ifname, ifindex })
            }
        }
    }

    /// Scan netlink attributes for IFLA_IFNAME and return the interface name.
    fn find_ifname(&self, msg: &[u8], start: usize) -> Option<String> {
        let mut offset = start;

        while offset + 4 <= msg.len() {
            let rta_len =
                u16::from_ne_bytes([msg[offset], msg[offset + 1]]) as usize;
            let rta_type =
                u16::from_ne_bytes([msg[offset + 2], msg[offset + 3]]);

            if rta_len < 4 || offset + rta_len > msg.len() {
                break;
            }

            if rta_type == IFLA_IFNAME {
                // Payload is a null-terminated string
                let data = &msg[offset + 4..offset + rta_len];
                let name = data
                    .split(|&b| b == 0)
                    .next()
                    .unwrap_or(data);
                return Some(String::from_utf8_lossy(name).into_owned());
            }

            offset += nlmsg_align(rta_len);
        }

        None
    }
}
