use crate::error::{Error, Result};
use crate::netlink::{
    NlMsgBuilder, NlMsgHdr, NetlinkSocket, NETLINK_ROUTE, NLMSG_DONE, NLMSG_ERROR,
    NLMSG_HDR_LEN, NLM_F_ACK, NLM_F_CREATE, NLM_F_DUMP, NLM_F_EXCL, NLM_F_REQUEST,
    RTM_DELROUTE, RTM_DELRULE, RTM_GETADDR, RTM_GETROUTE, RTM_NEWADDR,
    RTM_NEWROUTE, RTM_NEWRULE,
    nlmsg_align, read_struct,
};

use std::mem;
use std::net::IpAddr;

// ---------------------------------------------------------------------------
// Route message structs and constants
// ---------------------------------------------------------------------------

/// Kernel rtmsg structure (struct rtmsg from linux/rtnetlink.h).
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct RtMsg {
    pub rtm_family: u8,
    pub rtm_dst_len: u8,
    pub rtm_src_len: u8,
    pub rtm_tos: u8,
    pub rtm_table: u8,
    pub rtm_protocol: u8,
    pub rtm_scope: u8,
    pub rtm_type: u8,
    pub rtm_flags: u32,
}

/// Used for ip rule messages. Same binary layout as RtMsg, different semantics.
pub type FibRuleHdr = RtMsg;

// Route attribute types (RTA_*)
#[allow(dead_code)]
const RTA_DST: u16 = 1;
const RTA_OIF: u16 = 4;
const RTA_GATEWAY: u16 = 5;
const RTA_PRIORITY: u16 = 6;
const RTA_TABLE: u16 = 15;

// FIB rule attribute types (FRA_*)
const FRA_SRC: u16 = 2;
const FRA_TABLE: u16 = 15;
const FRA_FWMARK: u16 = 10;
const FRA_FWMASK: u16 = 11;
const FRA_PRIORITY: u16 = 6;

// Interface address attribute types (IFA_*)
const IFA_ADDRESS: u16 = 1;

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

// Route types (RTN_*)
const RTN_UNICAST: u8 = 1;

// Route protocols (RTPROT_*)
const RTPROT_STATIC: u8 = 4;

// Route scopes (RT_SCOPE_*)
const RT_SCOPE_UNIVERSE: u8 = 0;
const RT_SCOPE_LINK: u8 = 253;

// Address families
const AF_INET: u8 = libc::AF_INET as u8;
const AF_INET6: u8 = libc::AF_INET6 as u8;

// FIB rule action
const FR_ACT_TO_TBL: u8 = 1;

// ---------------------------------------------------------------------------
// RouteManager
// ---------------------------------------------------------------------------

/// Manages kernel routing tables and ip rules via netlink.
pub struct RouteManager {
    sock: NetlinkSocket,
    seq: u32,
    /// Reusable buffer for netlink dump responses (allocated once, 64 KB).
    recv_buf: Vec<u8>,
}

impl RouteManager {
    /// Create a new `RouteManager` with a `NETLINK_ROUTE` socket.
    pub fn new() -> Result<Self> {
        let sock = NetlinkSocket::open(NETLINK_ROUTE, 0)?;
        Ok(Self { sock, seq: 0, recv_buf: vec![0u8; 65536] })
    }

    /// Return the next sequence number for a netlink message.
    fn next_seq(&mut self) -> u32 {
        self.seq = self.seq.wrapping_add(1);
        self.seq
    }

    /// Resolve a network device name to its interface index (ifindex).
    fn ifindex(device: &str) -> Result<u32> {
        let c_name = std::ffi::CString::new(device).map_err(|_| {
            Error::Netlink(format!("invalid device name: {device}"))
        })?;
        let idx = unsafe { libc::if_nametoindex(c_name.as_ptr()) };
        if idx == 0 {
            Err(Error::Netlink(format!(
                "device not found: {device}: {}",
                std::io::Error::last_os_error()
            )))
        } else {
            Ok(idx)
        }
    }

    /// Add a route to a specific routing table.
    ///
    /// - `table`: routing table ID (e.g. 100, 200).
    /// - `dest_default`: if true, this is a default route (dst_len = 0).
    /// - `gateway`: gateway IP address (parsed as IPv4 or IPv6).
    /// - `device`: outgoing network device name (e.g. "eth0").
    /// - `metric`: route metric / priority.
    /// - `family`: address family (`AF_INET` = 2, `AF_INET6` = 10).
    pub fn add_route(
        &mut self,
        table: u32,
        dest_default: bool,
        gateway: &str,
        device: &str,
        metric: u32,
        family: u8,
    ) -> Result<()> {
        let seq = self.next_seq();
        let ifindex = Self::ifindex(device)?;

        let gw_addr: IpAddr = gateway.parse().map_err(|e| {
            Error::Netlink(format!("invalid gateway address '{gateway}': {e}"))
        })?;

        // Verify family matches the parsed address
        match (&gw_addr, family) {
            (IpAddr::V4(_), AF_INET) | (IpAddr::V6(_), AF_INET6) => {}
            _ => {
                return Err(Error::Netlink(
                    "gateway address family does not match requested family".into(),
                ));
            }
        }

        let dst_len = if dest_default { 0 } else { if family == AF_INET { 32 } else { 128 } };
        let scope = if dest_default { RT_SCOPE_UNIVERSE } else { RT_SCOPE_LINK };

        let rtm = RtMsg {
            rtm_family: family,
            rtm_dst_len: dst_len,
            rtm_src_len: 0,
            rtm_tos: 0,
            rtm_table: if table <= 255 { table as u8 } else { 0 },
            rtm_protocol: RTPROT_STATIC,
            rtm_scope: scope,
            rtm_type: RTN_UNICAST,
            rtm_flags: 0,
        };

        let mut msg = NlMsgBuilder::new(
            RTM_NEWROUTE,
            NLM_F_REQUEST | NLM_F_ACK | NLM_F_CREATE | NLM_F_EXCL,
            seq,
        );
        msg.push_payload(&rtm);

        // Table attribute (supports tables > 255)
        msg.push_attr(RTA_TABLE, &table.to_ne_bytes());

        // Gateway
        match gw_addr {
            IpAddr::V4(v4) => {
                msg.push_attr(RTA_GATEWAY, &v4.octets());
            }
            IpAddr::V6(v6) => {
                msg.push_attr(RTA_GATEWAY, &v6.octets());
            }
        }

        // Output interface
        msg.push_attr(RTA_OIF, &ifindex.to_ne_bytes());

        // Metric / priority
        msg.push_attr(RTA_PRIORITY, &metric.to_ne_bytes());

        let buf = msg.finish();
        self.sock.send_and_ack(&buf)
    }

    /// Delete the default route from a routing table.
    ///
    /// - `table`: routing table ID.
    /// - `family`: address family (`AF_INET` or `AF_INET6`).
    pub fn del_route(&mut self, table: u32, family: u8) -> Result<()> {
        let seq = self.next_seq();

        let rtm = RtMsg {
            rtm_family: family,
            rtm_dst_len: 0, // default route
            rtm_src_len: 0,
            rtm_tos: 0,
            rtm_table: if table <= 255 { table as u8 } else { 0 },
            rtm_protocol: RTPROT_STATIC,
            rtm_scope: RT_SCOPE_UNIVERSE,
            rtm_type: RTN_UNICAST,
            rtm_flags: 0,
        };

        let mut msg = NlMsgBuilder::new(
            RTM_DELROUTE,
            NLM_F_REQUEST | NLM_F_ACK,
            seq,
        );
        msg.push_payload(&rtm);

        // Table attribute
        msg.push_attr(RTA_TABLE, &table.to_ne_bytes());

        let buf = msg.finish();
        self.sock.send_and_ack(&buf)
    }

    /// Add an ip rule: fwmark/mask -> table.
    ///
    /// - `mark`: fwmark value.
    /// - `mask`: fwmark mask.
    /// - `table`: target routing table.
    /// - `priority`: rule priority (lower = higher precedence).
    /// - `family`: address family (`AF_INET` or `AF_INET6`).
    pub fn add_rule(
        &mut self,
        mark: u32,
        mask: u32,
        table: u32,
        priority: u32,
        family: u8,
    ) -> Result<()> {
        self.modify_rule(RTM_NEWRULE, mark, mask, table, priority, family)
    }

    /// Delete an ip rule: fwmark/mask -> table.
    pub fn del_rule(
        &mut self,
        mark: u32,
        mask: u32,
        table: u32,
        priority: u32,
        family: u8,
    ) -> Result<()> {
        self.modify_rule(RTM_DELRULE, mark, mask, table, priority, family)
    }

    /// Internal helper to add or delete an ip rule.
    fn modify_rule(
        &mut self,
        msg_type: u16,
        mark: u32,
        mask: u32,
        table: u32,
        priority: u32,
        family: u8,
    ) -> Result<()> {
        let seq = self.next_seq();

        let flags = if msg_type == RTM_NEWRULE {
            NLM_F_REQUEST | NLM_F_ACK | NLM_F_CREATE | NLM_F_EXCL
        } else {
            NLM_F_REQUEST | NLM_F_ACK
        };

        // FibRuleHdr is the same struct as RtMsg.
        let rule_hdr = FibRuleHdr {
            rtm_family: family,
            rtm_dst_len: 0,
            rtm_src_len: 0,
            rtm_tos: 0,
            rtm_table: if table <= 255 { table as u8 } else { 0 },
            rtm_protocol: RTPROT_STATIC,
            rtm_scope: RT_SCOPE_UNIVERSE,
            rtm_type: FR_ACT_TO_TBL,
            rtm_flags: 0,
        };

        let mut msg = NlMsgBuilder::new(msg_type, flags, seq);
        msg.push_payload(&rule_hdr);

        // FRA_TABLE for tables > 255
        msg.push_attr(FRA_TABLE, &table.to_ne_bytes());

        // FRA_FWMARK
        msg.push_attr(FRA_FWMARK, &mark.to_ne_bytes());

        // FRA_FWMASK
        msg.push_attr(FRA_FWMASK, &mask.to_ne_bytes());

        // FRA_PRIORITY
        msg.push_attr(FRA_PRIORITY, &priority.to_ne_bytes());

        let buf = msg.finish();
        self.sock.send_and_ack(&buf)
    }

    /// Add a source-address-based ip rule: from `src` lookup `table`.
    ///
    /// Used for `local_source` routing: traffic originating from the router
    /// with a specific source IP is directed to the per-interface routing
    /// table, ensuring it exits through the correct WAN interface.
    pub fn add_source_rule(
        &mut self,
        src: IpAddr,
        prefix_len: u8,
        table: u32,
        priority: u32,
        family: u8,
    ) -> Result<()> {
        self.modify_source_rule(RTM_NEWRULE, src, prefix_len, table, priority, family)
    }

    /// Delete a source-address-based ip rule.
    pub fn del_source_rule(
        &mut self,
        src: IpAddr,
        prefix_len: u8,
        table: u32,
        priority: u32,
        family: u8,
    ) -> Result<()> {
        self.modify_source_rule(RTM_DELRULE, src, prefix_len, table, priority, family)
    }

    /// Internal helper for source-based ip rule add/delete.
    fn modify_source_rule(
        &mut self,
        msg_type: u16,
        src: IpAddr,
        prefix_len: u8,
        table: u32,
        priority: u32,
        family: u8,
    ) -> Result<()> {
        let seq = self.next_seq();

        let flags = if msg_type == RTM_NEWRULE {
            NLM_F_REQUEST | NLM_F_ACK | NLM_F_CREATE | NLM_F_EXCL
        } else {
            NLM_F_REQUEST | NLM_F_ACK
        };

        let rule_hdr = FibRuleHdr {
            rtm_family: family,
            rtm_dst_len: 0,
            rtm_src_len: prefix_len,
            rtm_tos: 0,
            rtm_table: if table <= 255 { table as u8 } else { 0 },
            rtm_protocol: RTPROT_STATIC,
            rtm_scope: RT_SCOPE_UNIVERSE,
            rtm_type: FR_ACT_TO_TBL,
            rtm_flags: 0,
        };

        let mut msg = NlMsgBuilder::new(msg_type, flags, seq);
        msg.push_payload(&rule_hdr);

        // FRA_TABLE
        msg.push_attr(FRA_TABLE, &table.to_ne_bytes());

        // FRA_SRC (source address)
        match src {
            IpAddr::V4(v4) => msg.push_attr(FRA_SRC, &v4.octets()),
            IpAddr::V6(v6) => msg.push_attr(FRA_SRC, &v6.octets()),
        }

        // FRA_PRIORITY
        msg.push_attr(FRA_PRIORITY, &priority.to_ne_bytes());

        let buf = msg.finish();
        self.sock.send_and_ack(&buf)
    }

    /// Get all IP addresses assigned to a network device.
    ///
    /// Returns `(address, prefix_len)` pairs for the specified address family.
    pub fn get_device_addresses(
        &mut self,
        device: &str,
        family: u8,
    ) -> Result<Vec<(IpAddr, u8)>> {
        let target_ifindex = Self::ifindex(device)?;
        let seq = self.next_seq();

        let ifa = IfAddrMsg {
            ifa_family: family,
            ifa_prefixlen: 0,
            ifa_flags: 0,
            ifa_scope: 0,
            ifa_index: 0,
        };

        let mut msg = NlMsgBuilder::new(
            RTM_GETADDR,
            NLM_F_REQUEST | NLM_F_DUMP,
            seq,
        );
        msg.push_payload(&ifa);
        let buf = msg.finish();
        self.sock.send(&buf)?;

        let mut addrs = Vec::new();
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);

        'outer: loop {
            let n = self.sock.recv(&mut self.recv_buf)?;
            if n == 0 {
                if std::time::Instant::now() >= deadline {
                    return Err(Error::Netlink("timeout waiting for netlink dump".into()));
                }
                std::thread::sleep(std::time::Duration::from_micros(100));
                continue;
            }

            let mut offset = 0;
            while offset + NLMSG_HDR_LEN <= n {
                let hdr: NlMsgHdr = unsafe { read_struct(&self.recv_buf, offset) };
                let msg_len = hdr.nlmsg_len as usize;
                if msg_len < NLMSG_HDR_LEN || offset + msg_len > n {
                    break;
                }

                match hdr.nlmsg_type {
                    NLMSG_DONE => break 'outer,
                    NLMSG_ERROR => {
                        let errcode: i32 = if offset + NLMSG_HDR_LEN + 4 <= n {
                            unsafe { read_struct(&self.recv_buf, offset + NLMSG_HDR_LEN) }
                        } else {
                            -1
                        };
                        if errcode != 0 {
                            return Err(Error::Netlink(format!(
                                "address dump error: {}",
                                std::io::Error::from_raw_os_error(-errcode)
                            )));
                        }
                        break 'outer;
                    }
                    RTM_NEWADDR => {
                        if let Some(entry) = self.extract_address(
                            &self.recv_buf[offset..offset + msg_len],
                            target_ifindex,
                            family,
                        ) {
                            addrs.push(entry);
                        }
                    }
                    _ => {}
                }

                offset += nlmsg_align(msg_len);
            }
        }

        Ok(addrs)
    }

    /// Parse an address message and extract the IP if it belongs to the
    /// target interface.
    fn extract_address(
        &self,
        msg_bytes: &[u8],
        target_ifindex: u32,
        family: u8,
    ) -> Option<(IpAddr, u8)> {
        if msg_bytes.len() < NLMSG_HDR_LEN + mem::size_of::<IfAddrMsg>() {
            return None;
        }

        let ifa: IfAddrMsg = unsafe { read_struct(msg_bytes, NLMSG_HDR_LEN) };

        if ifa.ifa_index != target_ifindex || ifa.ifa_family != family {
            return None;
        }

        let attr_start = NLMSG_HDR_LEN + nlmsg_align(mem::size_of::<IfAddrMsg>());
        let mut offset = attr_start;

        while offset + 4 <= msg_bytes.len() {
            let rta_len = u16::from_ne_bytes(
                [msg_bytes[offset], msg_bytes[offset + 1]],
            ) as usize;
            let rta_type = u16::from_ne_bytes(
                [msg_bytes[offset + 2], msg_bytes[offset + 3]],
            );

            if rta_len < 4 || offset + rta_len > msg_bytes.len() {
                break;
            }

            let data = &msg_bytes[offset + 4..offset + rta_len];

            if rta_type == IFA_ADDRESS {
                let addr = match family {
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
                if let Some(a) = addr {
                    return Some((a, ifa.ifa_prefixlen));
                }
            }

            offset += nlmsg_align(rta_len);
        }

        None
    }

    /// Copy the default route for `device` from the main table into
    /// the per-interface routing table `dest_table`.
    ///
    /// Dumps routes from the main table (254), finds the default route
    /// (dst_len=0) whose outgoing interface matches `device`, and installs
    /// it into `dest_table`. This mirrors what mwan3 does with
    /// `mwan3_set_iface_route`.
    ///
    /// Returns `Ok(true)` if a route was copied, `Ok(false)` if no matching
    /// default route was found in the main table.
    pub fn copy_default_route(
        &mut self,
        device: &str,
        dest_table: u32,
        family: u8,
    ) -> Result<bool> {
        let target_ifindex = Self::ifindex(device)?;
        let gateway = self.find_default_gateway(target_ifindex, family)?;

        let Some(gw) = gateway else {
            log::warn!(
                "no default route found for device {device} (family={})",
                if family == AF_INET { "ipv4" } else { "ipv6" }
            );
            return Ok(false);
        };

        let gw_str = gw.to_string();
        self.add_route(dest_table, true, &gw_str, device, 0, family)?;

        log::info!(
            "copied default route via {gw} dev {device} to table {dest_table}"
        );
        Ok(true)
    }

    /// Dump routes from the main table and find the default gateway for
    /// a specific interface index and address family.
    fn find_default_gateway(
        &mut self,
        target_ifindex: u32,
        family: u8,
    ) -> Result<Option<IpAddr>> {
        let seq = self.next_seq();

        let rtm = RtMsg {
            rtm_family: family,
            rtm_dst_len: 0,
            rtm_src_len: 0,
            rtm_tos: 0,
            rtm_table: 0,
            rtm_protocol: 0,
            rtm_scope: 0,
            rtm_type: 0,
            rtm_flags: 0,
        };

        let mut msg = NlMsgBuilder::new(
            RTM_GETROUTE,
            NLM_F_REQUEST | NLM_F_DUMP,
            seq,
        );
        msg.push_payload(&rtm);
        let buf = msg.finish();
        self.sock.send(&buf)?;

        let mut result: Option<IpAddr> = None;
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);

        'outer: loop {
            let n = self.sock.recv(&mut self.recv_buf)?;
            if n == 0 {
                if std::time::Instant::now() >= deadline {
                    return Err(Error::Netlink("timeout waiting for netlink dump".into()));
                }
                std::thread::sleep(std::time::Duration::from_micros(100));
                continue;
            }

            let mut offset = 0;
            while offset + NLMSG_HDR_LEN <= n {
                let hdr: NlMsgHdr = unsafe { read_struct(&self.recv_buf, offset) };
                let msg_len = hdr.nlmsg_len as usize;
                if msg_len < NLMSG_HDR_LEN || offset + msg_len > n {
                    break;
                }

                match hdr.nlmsg_type {
                    NLMSG_DONE => break 'outer,
                    NLMSG_ERROR => {
                        let errcode: i32 = if offset + NLMSG_HDR_LEN + 4 <= n {
                            unsafe { read_struct(&self.recv_buf, offset + NLMSG_HDR_LEN) }
                        } else {
                            -1
                        };
                        if errcode != 0 {
                            return Err(Error::Netlink(format!(
                                "route dump error: {}",
                                std::io::Error::from_raw_os_error(-errcode)
                            )));
                        }
                        break 'outer;
                    }
                    RTM_NEWROUTE => {
                        if result.is_none() {
                            result = self.extract_default_gateway(
                                &self.recv_buf[offset..offset + msg_len],
                                target_ifindex,
                                family,
                            );
                        }
                    }
                    _ => {}
                }

                offset += nlmsg_align(msg_len);
            }
        }

        Ok(result)
    }

    /// Parse a single route message. If it is a default route (dst_len=0)
    /// in the main table with the matching OIF, return the gateway address.
    fn extract_default_gateway(
        &self,
        msg_bytes: &[u8],
        target_ifindex: u32,
        family: u8,
    ) -> Option<IpAddr> {
        if msg_bytes.len() < NLMSG_HDR_LEN + mem::size_of::<RtMsg>() {
            return None;
        }

        let rtm: RtMsg = unsafe { read_struct(msg_bytes, NLMSG_HDR_LEN) };

        // Only default routes (dst_len == 0), unicast type
        if rtm.rtm_dst_len != 0 || rtm.rtm_type != RTN_UNICAST {
            return None;
        }

        let attr_start = NLMSG_HDR_LEN + nlmsg_align(mem::size_of::<RtMsg>());
        let mut offset = attr_start;

        let mut route_table = rtm.rtm_table as u32;
        let mut gateway: Option<IpAddr> = None;
        let mut oif: Option<u32> = None;

        while offset + 4 <= msg_bytes.len() {
            let rta_len = u16::from_ne_bytes(
                [msg_bytes[offset], msg_bytes[offset + 1]],
            ) as usize;
            let rta_type = u16::from_ne_bytes(
                [msg_bytes[offset + 2], msg_bytes[offset + 3]],
            );

            if rta_len < 4 || offset + rta_len > msg_bytes.len() {
                break;
            }

            let data = &msg_bytes[offset + 4..offset + rta_len];

            match rta_type {
                RTA_TABLE if data.len() >= 4 => {
                    route_table = u32::from_ne_bytes(
                        data[..4].try_into().ok()?,
                    );
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
                RTA_OIF if data.len() >= 4 => {
                    oif = Some(u32::from_ne_bytes(
                        data[..4].try_into().ok()?,
                    ));
                }
                _ => {}
            }

            offset += nlmsg_align(rta_len);
        }

        // Main table is 254 (RT_TABLE_MAIN)
        if route_table != 254 {
            return None;
        }

        // Must match our target device
        if oif != Some(target_ifindex) {
            return None;
        }

        gateway
    }

    /// Collect directly-connected network prefixes from the main routing table
    /// and any additional tables listed in `extra_tables`.
    ///
    /// These are routes with scope `RT_SCOPE_LINK` (directly reachable subnets
    /// like LAN networks). Returns CIDR strings like `"192.168.1.0/24"`.
    /// Also includes loopback and link-local ranges.
    pub fn get_connected_networks(
        &mut self,
        extra_tables: &[u32],
    ) -> Result<Vec<String>> {
        let mut tables = vec![254u32]; // main table always included
        for &t in extra_tables {
            if !tables.contains(&t) {
                tables.push(t);
            }
        }

        let mut networks = Vec::new();

        // Always include loopback and link-local
        networks.push("127.0.0.0/8".to_string());
        networks.push("::1/128".to_string());
        networks.push("fe80::/10".to_string());

        // Dump connected routes from each table for both address families
        for &table in &tables {
            self.collect_connected_family(AF_INET, table, &mut networks)?;
            self.collect_connected_family(AF_INET6, table, &mut networks)?;
        }

        log::debug!("connected networks: {:?}", networks);
        Ok(networks)
    }

    /// Dump routes for one address family and collect connected (scope=link)
    /// subnets from the given table.
    fn collect_connected_family(
        &mut self,
        family: u8,
        table: u32,
        networks: &mut Vec<String>,
    ) -> Result<()> {
        let seq = self.next_seq();

        let rtm = RtMsg {
            rtm_family: family,
            rtm_dst_len: 0,
            rtm_src_len: 0,
            rtm_tos: 0,
            rtm_table: 0,
            rtm_protocol: 0,
            rtm_scope: 0,
            rtm_type: 0,
            rtm_flags: 0,
        };

        let mut msg = NlMsgBuilder::new(
            RTM_GETROUTE,
            NLM_F_REQUEST | NLM_F_DUMP,
            seq,
        );
        msg.push_payload(&rtm);
        let buf = msg.finish();
        self.sock.send(&buf)?;

        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);

        'outer: loop {
            let n = self.sock.recv(&mut self.recv_buf)?;
            if n == 0 {
                if std::time::Instant::now() >= deadline {
                    return Err(Error::Netlink("timeout waiting for netlink dump".into()));
                }
                std::thread::sleep(std::time::Duration::from_micros(100));
                continue;
            }

            let mut offset = 0;
            while offset + NLMSG_HDR_LEN <= n {
                let hdr: NlMsgHdr = unsafe { read_struct(&self.recv_buf, offset) };
                let msg_len = hdr.nlmsg_len as usize;
                if msg_len < NLMSG_HDR_LEN || offset + msg_len > n {
                    break;
                }

                match hdr.nlmsg_type {
                    NLMSG_DONE => break 'outer,
                    NLMSG_ERROR => {
                        let errcode: i32 = if offset + NLMSG_HDR_LEN + 4 <= n {
                            unsafe { read_struct(&self.recv_buf, offset + NLMSG_HDR_LEN) }
                        } else {
                            -1
                        };
                        if errcode != 0 {
                            return Err(Error::Netlink(format!(
                                "route dump error: {}",
                                std::io::Error::from_raw_os_error(-errcode)
                            )));
                        }
                        break 'outer;
                    }
                    RTM_NEWROUTE => {
                        if let Some(cidr) = self.extract_connected_prefix(
                            &self.recv_buf[offset..offset + msg_len],
                            family,
                            table,
                        ) {
                            networks.push(cidr);
                        }
                    }
                    _ => {}
                }

                offset += nlmsg_align(msg_len);
            }
        }

        Ok(())
    }

    /// Parse a route message and return the CIDR prefix if it is a connected
    /// (scope=link) route in the specified table.
    fn extract_connected_prefix(
        &self,
        msg_bytes: &[u8],
        family: u8,
        target_table: u32,
    ) -> Option<String> {
        if msg_bytes.len() < NLMSG_HDR_LEN + mem::size_of::<RtMsg>() {
            return None;
        }

        let rtm: RtMsg = unsafe { read_struct(msg_bytes, NLMSG_HDR_LEN) };

        // Only connected routes: scope=link, type=unicast, with a prefix
        if rtm.rtm_scope != RT_SCOPE_LINK || rtm.rtm_type != RTN_UNICAST || rtm.rtm_dst_len == 0 {
            return None;
        }

        let attr_start = NLMSG_HDR_LEN + nlmsg_align(mem::size_of::<RtMsg>());
        let mut offset = attr_start;

        let mut route_table = rtm.rtm_table as u32;
        let mut dst: Option<IpAddr> = None;

        while offset + 4 <= msg_bytes.len() {
            let rta_len = u16::from_ne_bytes(
                [msg_bytes[offset], msg_bytes[offset + 1]],
            ) as usize;
            let rta_type = u16::from_ne_bytes(
                [msg_bytes[offset + 2], msg_bytes[offset + 3]],
            );

            if rta_len < 4 || offset + rta_len > msg_bytes.len() {
                break;
            }

            let data = &msg_bytes[offset + 4..offset + rta_len];

            match rta_type {
                RTA_TABLE if data.len() >= 4 => {
                    route_table = u32::from_ne_bytes(
                        data[..4].try_into().ok()?,
                    );
                }
                RTA_DST => {
                    dst = match family {
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

        if route_table != target_table {
            return None;
        }

        dst.map(|addr| format!("{}/{}", addr, rtm.rtm_dst_len))
    }

    /// Flush all routes in a routing table.
    ///
    /// Performs a RTM_GETROUTE dump filtered by table, then sends RTM_DELROUTE
    /// for each route found.
    pub fn flush_table(&mut self, table: u32) -> Result<()> {
        // Flush IPv4 routes, then IPv6
        self.flush_table_family(table, AF_INET)?;
        self.flush_table_family(table, AF_INET6)?;
        Ok(())
    }

    fn flush_table_family(&mut self, table: u32, family: u8) -> Result<()> {
        let seq = self.next_seq();

        // Send a dump request for all routes in this family
        let rtm = RtMsg {
            rtm_family: family,
            rtm_dst_len: 0,
            rtm_src_len: 0,
            rtm_tos: 0,
            rtm_table: 0,
            rtm_protocol: 0,
            rtm_scope: 0,
            rtm_type: 0,
            rtm_flags: 0,
        };

        let mut msg = NlMsgBuilder::new(
            RTM_GETROUTE,
            NLM_F_REQUEST | NLM_F_DUMP,
            seq,
        );
        msg.push_payload(&rtm);
        let buf = msg.finish();
        self.sock.send(&buf)?;

        // Read the dump response and collect routes belonging to our table.
        // Take recv_buf temporarily to avoid borrow conflict with
        // parse_route_for_delete(&mut self, ...).
        let mut delete_msgs: Vec<Vec<u8>> = Vec::new();
        let mut recv_buf = std::mem::take(&mut self.recv_buf);
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);

        'outer: loop {
            let n = self.sock.recv(&mut recv_buf)?;
            if n == 0 {
                if std::time::Instant::now() >= deadline {
                    self.recv_buf = recv_buf;
                    return Err(Error::Netlink("timeout waiting for netlink dump".into()));
                }
                std::thread::sleep(std::time::Duration::from_micros(100));
                continue;
            }

            let mut offset = 0;
            while offset + NLMSG_HDR_LEN <= n {
                let hdr: NlMsgHdr = unsafe { read_struct(&recv_buf, offset) };
                let msg_len = hdr.nlmsg_len as usize;
                if msg_len < NLMSG_HDR_LEN || offset + msg_len > n {
                    break;
                }

                match hdr.nlmsg_type {
                    NLMSG_DONE => break 'outer,
                    NLMSG_ERROR => {
                        // Error during dump
                        let errcode: i32 = if offset + NLMSG_HDR_LEN + 4 <= n {
                            unsafe { read_struct(&recv_buf, offset + NLMSG_HDR_LEN) }
                        } else {
                            -1
                        };
                        if errcode != 0 {
                            self.recv_buf = recv_buf;
                            return Err(Error::Netlink(format!(
                                "route dump error: {}",
                                std::io::Error::from_raw_os_error(-errcode)
                            )));
                        }
                        break 'outer;
                    }
                    RTM_NEWROUTE => {
                        if let Some(del) =
                            self.parse_route_for_delete(
                                &recv_buf[offset..offset + msg_len],
                                table,
                            )
                        {
                            delete_msgs.push(del);
                        }
                    }
                    _ => {}
                }

                offset += nlmsg_align(msg_len);
            }
        }
        self.recv_buf = recv_buf;

        // Now delete each collected route
        for del_buf in delete_msgs {
            // Best-effort: log errors but continue
            if let Err(e) = self.sock.send_and_ack(&del_buf) {
                log::warn!("failed to delete route during flush: {e}");
            }
        }

        Ok(())
    }

    /// Parse a RTM_NEWROUTE response and, if it belongs to the target table,
    /// construct a corresponding RTM_DELROUTE message.
    fn parse_route_for_delete(
        &mut self,
        msg_bytes: &[u8],
        target_table: u32,
    ) -> Option<Vec<u8>> {
        if msg_bytes.len() < NLMSG_HDR_LEN + mem::size_of::<RtMsg>() {
            return None;
        }

        let rtm: RtMsg = unsafe { read_struct(msg_bytes, NLMSG_HDR_LEN) };

        // Determine the table: use rtm_table unless an RTA_TABLE attribute
        // provides a larger value.
        let mut route_table = rtm.rtm_table as u32;
        let attr_start = NLMSG_HDR_LEN + nlmsg_align(mem::size_of::<RtMsg>());
        let mut offset = attr_start;

        while offset + 4 <= msg_bytes.len() {
            let rta_len = u16::from_ne_bytes([msg_bytes[offset], msg_bytes[offset + 1]]) as usize;
            let rta_type = u16::from_ne_bytes([msg_bytes[offset + 2], msg_bytes[offset + 3]]);

            if rta_len < 4 || offset + rta_len > msg_bytes.len() {
                break;
            }

            if rta_type == RTA_TABLE && rta_len >= 8 {
                let tbl_bytes: [u8; 4] = msg_bytes[offset + 4..offset + 8]
                    .try_into()
                    .ok()?;
                route_table = u32::from_ne_bytes(tbl_bytes);
            }

            offset += nlmsg_align(rta_len);
        }

        if route_table != target_table {
            return None;
        }

        // Build a delete message by reusing the original payload but with
        // RTM_DELROUTE type and appropriate flags.
        let seq = self.next_seq();
        let payload = &msg_bytes[NLMSG_HDR_LEN..];

        let hdr = NlMsgHdr {
            nlmsg_len: (NLMSG_HDR_LEN + payload.len()) as u32,
            nlmsg_type: RTM_DELROUTE,
            nlmsg_flags: NLM_F_REQUEST | NLM_F_ACK,
            nlmsg_seq: seq,
            nlmsg_pid: 0,
        };

        let mut buf = Vec::with_capacity(NLMSG_HDR_LEN + payload.len());
        let hdr_bytes = unsafe {
            std::slice::from_raw_parts(
                &hdr as *const NlMsgHdr as *const u8,
                NLMSG_HDR_LEN,
            )
        };
        buf.extend_from_slice(hdr_bytes);
        buf.extend_from_slice(payload);

        Some(buf)
    }
}
