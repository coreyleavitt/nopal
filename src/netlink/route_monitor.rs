use crate::error::Result;
use crate::netlink::{
    NlMsgHdr, NetlinkSocket, NETLINK_ROUTE, NLMSG_HDR_LEN, RTM_DELADDR, RTM_DELROUTE,
    RTM_NEWADDR, RTM_NEWROUTE, nlmsg_align, read_struct,
};
use crate::netlink::route::RtMsg;

use std::mem;
use std::net::IpAddr;
use std::os::fd::RawFd;

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// RTNLGRP_IPV4_IFADDR multicast group (group 5 -> bit 4).
const RTNLGRP_IPV4_IFADDR: u32 = 1 << 4;

/// RTNLGRP_IPV4_ROUTE multicast group (group 7 -> bit 6).
const RTNLGRP_IPV4_ROUTE: u32 = 1 << 6;

/// RTNLGRP_IPV6_IFADDR multicast group (group 15 -> bit 14).
const RTNLGRP_IPV6_IFADDR: u32 = 1 << 14;

/// RTNLGRP_IPV6_ROUTE multicast group (group 17 -> bit 16).
const RTNLGRP_IPV6_ROUTE: u32 = 1 << 16;

// Route attribute types (RTA_*)
const RTA_OIF: u16 = 4;
const RTA_GATEWAY: u16 = 5;
const RTA_TABLE: u16 = 15;

// Interface address attribute types (IFA_*)
const IFA_ADDRESS: u16 = 1;

// Route types (RTN_*)
const RTN_UNICAST: u8 = 1;

// Address families
const AF_INET: u8 = libc::AF_INET as u8;
const AF_INET6: u8 = libc::AF_INET6 as u8;

/// Kernel ifaddrmsg structure (struct ifaddrmsg from linux/if_addr.h).
#[repr(C)]
#[derive(Debug, Clone, Copy)]
struct IfAddrMsg {
    ifa_family: u8,
    ifa_prefixlen: u8,
    ifa_flags: u8,
    ifa_scope: u8,
    ifa_index: u32,
}

// ---------------------------------------------------------------------------
// Event types
// ---------------------------------------------------------------------------

/// A default route change event parsed from a netlink notification.
#[derive(Debug, Clone)]
pub struct RouteEvent {
    /// Interface index of the affected device.
    pub ifindex: u32,
    /// Address family (`AF_INET` or `AF_INET6`).
    pub family: u8,
    /// New gateway address (present for additions, absent for deletions).
    pub gateway: Option<IpAddr>,
    /// Whether this was a route deletion.
    pub is_delete: bool,
}

/// An interface address change event parsed from a netlink notification.
#[derive(Debug, Clone)]
pub struct AddrEvent {
    /// Interface index of the affected device.
    pub ifindex: u32,
    /// Address family (`AF_INET` or `AF_INET6`).
    pub family: u8,
    /// The address that was added or removed.
    pub address: IpAddr,
    /// Prefix length (e.g. 24 for /24).
    #[allow(dead_code)]
    pub prefix_len: u8,
    /// Whether this was an address deletion.
    pub is_delete: bool,
}

/// Combined event type returned by the monitor.
#[derive(Debug, Clone)]
pub enum MonitorEvent {
    Route(RouteEvent),
    Address(AddrEvent),
}

// ---------------------------------------------------------------------------
// RouteMonitor
// ---------------------------------------------------------------------------

/// Monitors default route changes and interface address changes in the main
/// routing table via netlink multicast subscriptions.
///
/// Subscribes to `RTNLGRP_IPV4_ROUTE`, `RTNLGRP_IPV6_ROUTE`,
/// `RTNLGRP_IPV4_IFADDR`, and `RTNLGRP_IPV6_IFADDR`. Parses incoming
/// messages to detect:
/// - Default route additions/deletions (for route table sync)
/// - Address additions/deletions (for local_source rule sync)
pub struct RouteMonitor {
    sock: NetlinkSocket,
    recv_buf: Vec<u8>,
}

impl RouteMonitor {
    /// Create a new `RouteMonitor` subscribed to route and address multicast
    /// groups.
    ///
    /// Always subscribes to both IPv4 and IPv6 groups. Filtering by
    /// `ipv6_enabled` is done at the handler level.
    pub fn new() -> Result<Self> {
        let groups = RTNLGRP_IPV4_ROUTE
            | RTNLGRP_IPV6_ROUTE
            | RTNLGRP_IPV4_IFADDR
            | RTNLGRP_IPV6_IFADDR;
        let sock = NetlinkSocket::open(NETLINK_ROUTE, groups)?;
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

    /// Read and parse pending events from the socket.
    ///
    /// Route events are filtered to default routes (dst_len=0) in the main
    /// table (254) and deduplicated by (ifindex, family). Address events are
    /// returned for all interfaces without deduplication.
    pub fn read_events(&mut self) -> Result<Vec<MonitorEvent>> {
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

            let msg_slice = &self.recv_buf[offset..offset + msg_len];

            match hdr.nlmsg_type {
                RTM_NEWROUTE | RTM_DELROUTE => {
                    if let Some(re) = self.parse_route_msg(msg_slice, hdr.nlmsg_type) {
                        // Deduplicate route events by (ifindex, family)
                        events.retain(|e| {
                            !matches!(e, MonitorEvent::Route(r)
                                if r.ifindex == re.ifindex && r.family == re.family)
                        });
                        events.push(MonitorEvent::Route(re));
                    }
                }
                RTM_NEWADDR | RTM_DELADDR => {
                    if let Some(ae) = self.parse_addr_msg(msg_slice, hdr.nlmsg_type) {
                        events.push(MonitorEvent::Address(ae));
                    }
                }
                _ => {}
            }

            offset += nlmsg_align(msg_len);
        }

        Ok(events)
    }

    /// Parse a single RTM_NEWROUTE or RTM_DELROUTE message.
    ///
    /// Returns `Some(RouteEvent)` only for default routes (dst_len=0) in the
    /// main table (254) with a valid output interface.
    fn parse_route_msg(&self, msg: &[u8], msg_type: u16) -> Option<RouteEvent> {
        let rtm_offset = NLMSG_HDR_LEN;
        let rtm_size = mem::size_of::<RtMsg>();

        if msg.len() < rtm_offset + rtm_size {
            return None;
        }

        let rtm: RtMsg = unsafe { read_struct(msg, rtm_offset) };

        // Only default routes (dst_len == 0), unicast type
        if rtm.rtm_dst_len != 0 || rtm.rtm_type != RTN_UNICAST {
            return None;
        }

        let family = rtm.rtm_family;
        if family != AF_INET && family != AF_INET6 {
            return None;
        }

        // Scan attributes for table, OIF, and gateway
        let attr_start = rtm_offset + nlmsg_align(rtm_size);
        let mut offset = attr_start;

        let mut route_table = rtm.rtm_table as u32;
        let mut oif: Option<u32> = None;
        let mut gateway: Option<IpAddr> = None;

        while offset + 4 <= msg.len() {
            let rta_len = u16::from_ne_bytes(
                [msg[offset], msg[offset + 1]],
            ) as usize;
            let rta_type = u16::from_ne_bytes(
                [msg[offset + 2], msg[offset + 3]],
            );

            if rta_len < 4 || offset + rta_len > msg.len() {
                break;
            }

            let data = &msg[offset + 4..offset + rta_len];

            match rta_type {
                RTA_TABLE if data.len() >= 4 => {
                    route_table = u32::from_ne_bytes(
                        data[..4].try_into().ok()?,
                    );
                }
                RTA_OIF if data.len() >= 4 => {
                    oif = Some(u32::from_ne_bytes(
                        data[..4].try_into().ok()?,
                    ));
                }
                RTA_GATEWAY => {
                    gateway = match family {
                        AF_INET if data.len() >= 4 => {
                            let octets: [u8; 4] = data[..4].try_into().ok()?;
                            Some(IpAddr::from(octets))
                        }
                        AF_INET6 if data.len() >= 16 => {
                            let octets: [u8; 16] = data[..16].try_into().ok()?;
                            Some(IpAddr::from(octets))
                        }
                        _ => None,
                    };
                }
                _ => {}
            }

            offset += nlmsg_align(rta_len);
        }

        // Only main table (254 = RT_TABLE_MAIN)
        if route_table != 254 {
            return None;
        }

        // Must have an output interface
        let ifindex = oif?;

        Some(RouteEvent {
            ifindex,
            family,
            gateway,
            is_delete: msg_type == RTM_DELROUTE,
        })
    }

    /// Parse a single RTM_NEWADDR or RTM_DELADDR message.
    fn parse_addr_msg(&self, msg: &[u8], msg_type: u16) -> Option<AddrEvent> {
        let ifa_offset = NLMSG_HDR_LEN;
        let ifa_size = mem::size_of::<IfAddrMsg>();

        if msg.len() < ifa_offset + ifa_size {
            return None;
        }

        let ifa: IfAddrMsg = unsafe { read_struct(msg, ifa_offset) };

        let family = ifa.ifa_family;
        if family != AF_INET && family != AF_INET6 {
            return None;
        }

        // Scan attributes for IFA_ADDRESS
        let attr_start = ifa_offset + nlmsg_align(ifa_size);
        let mut offset = attr_start;
        let mut address: Option<IpAddr> = None;

        while offset + 4 <= msg.len() {
            let rta_len = u16::from_ne_bytes(
                [msg[offset], msg[offset + 1]],
            ) as usize;
            let rta_type = u16::from_ne_bytes(
                [msg[offset + 2], msg[offset + 3]],
            );

            if rta_len < 4 || offset + rta_len > msg.len() {
                break;
            }

            let data = &msg[offset + 4..offset + rta_len];

            if rta_type == IFA_ADDRESS {
                address = match family {
                    AF_INET if data.len() >= 4 => {
                        let octets: [u8; 4] = data[..4].try_into().ok()?;
                        Some(IpAddr::from(octets))
                    }
                    AF_INET6 if data.len() >= 16 => {
                        let octets: [u8; 16] = data[..16].try_into().ok()?;
                        Some(IpAddr::from(octets))
                    }
                    _ => None,
                };
            }

            offset += nlmsg_align(rta_len);
        }

        let address = address?;

        Some(AddrEvent {
            ifindex: ifa.ifa_index,
            family,
            address,
            prefix_len: ifa.ifa_prefixlen,
            is_delete: msg_type == RTM_DELADDR,
        })
    }
}
