//! Native netlink conntrack flush operations.
//!
//! Replaces the conntrack CLI tool with direct NETLINK_NETFILTER messages
//! (NFNL_SUBSYS_CTNETLINK). This removes the dependency on conntrack-tools
//! and avoids subprocess overhead.

use crate::error::Result;
use crate::netlink::{
    NlMsgBuilder, NetlinkSocket, NETLINK_NETFILTER, NLM_F_ACK, NLM_F_REQUEST,
};

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// NFNL_SUBSYS_CTNETLINK subsystem ID.
const NFNL_SUBSYS_CTNETLINK: u16 = 1;

/// IPCTNL_MSG_CT_DELETE message type (delete/flush conntrack entries).
const IPCTNL_MSG_CT_DELETE: u16 = 2;

/// CTA_MARK attribute (conntrack mark value, network byte order u32).
const CTA_MARK: u16 = 8;

/// CTA_MARK_MASK attribute (conntrack mark mask, network byte order u32).
const CTA_MARK_MASK: u16 = 21;

/// Kernel nfgenmsg header (struct nfgenmsg from linux/netfilter/nfnetlink.h).
#[repr(C)]
struct NfGenMsg {
    nfgen_family: u8,
    version: u8,
    res_id: u16,
}

// ---------------------------------------------------------------------------
// ConntrackManager
// ---------------------------------------------------------------------------

/// Manages connection tracking table cleanup via native netlink.
///
/// Sends IPCTNL_MSG_CT_DELETE messages through a NETLINK_NETFILTER socket.
/// When no tuple is specified, the kernel flushes entries matching the
/// optional mark filter (or all entries if no filter).
pub struct ConntrackManager {
    sock: Option<NetlinkSocket>,
}

impl ConntrackManager {
    pub fn new() -> Self {
        Self { sock: None }
    }

    /// Get or lazily open the NETLINK_NETFILTER socket.
    fn sock(&mut self) -> Result<&NetlinkSocket> {
        if self.sock.is_none() {
            self.sock = Some(NetlinkSocket::open(NETLINK_NETFILTER, 0)?);
        }
        Ok(self.sock.as_ref().unwrap())
    }

    /// Flush conntrack entries matching a specific fwmark/mask.
    ///
    /// Sends IPCTNL_MSG_CT_DELETE with CTA_MARK and CTA_MARK_MASK attributes.
    /// The kernel iterates the conntrack table and deletes entries where
    /// `(ct_mark & mask) == (mark & mask)`.
    pub fn flush_by_mark(&mut self, mark: u32, mask: u32) -> Result<()> {
        let msg = Self::build_ct_delete(Some((mark, mask)));
        self.sock()?.send_and_ack(&msg)?;
        log::debug!("conntrack flush mark 0x{mark:x}/0x{mask:x}: done");
        Ok(())
    }

    /// Flush all conntrack entries.
    ///
    /// Sends IPCTNL_MSG_CT_DELETE with no attributes, causing the kernel
    /// to delete every entry in the conntrack table.
    pub fn flush_all(&mut self) -> Result<()> {
        let msg = Self::build_ct_delete(None);
        self.sock()?.send_and_ack(&msg)?;
        log::debug!("conntrack flush all: done");
        Ok(())
    }

    /// Build an IPCTNL_MSG_CT_DELETE netlink message.
    ///
    /// When `mark_filter` is `Some((mark, mask))`, includes CTA_MARK and
    /// CTA_MARK_MASK attributes for selective flush. When `None`, flushes all.
    fn build_ct_delete(mark_filter: Option<(u32, u32)>) -> Vec<u8> {
        let msg_type = (NFNL_SUBSYS_CTNETLINK << 8) | IPCTNL_MSG_CT_DELETE;
        let mut builder = NlMsgBuilder::new(msg_type, NLM_F_REQUEST | NLM_F_ACK, 0);

        builder.push_payload(&NfGenMsg {
            nfgen_family: libc::AF_UNSPEC as u8,
            version: 0,
            res_id: 0,
        });

        if let Some((mark, mask)) = mark_filter {
            builder.push_attr(CTA_MARK, &mark.to_be_bytes());
            builder.push_attr(CTA_MARK_MASK, &mask.to_be_bytes());
        }

        builder.finish()
    }
}
