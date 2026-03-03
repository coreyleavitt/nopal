mod chains;
mod ruleset;

pub use chains::{ChainBuilder, InterfaceInfo, PolicyInfo, PolicyMember, RuleInfo, StickyInfo};
pub use ruleset::{Ruleset, TABLE_FAMILY, TABLE_NAME};

use crate::error::{Error, Result};
use std::io::Write;
use std::process::{Command, Stdio};

/// Engine that applies nftables rulesets atomically via `nft -j -f -`.
///
/// All mutations go through a single code path: serialize the `Ruleset` to
/// JSON, pipe it to nft's stdin, and check the exit status. This guarantees
/// atomic rule replacement -- either the entire ruleset applies or nothing
/// changes.
pub struct NftEngine;

impl NftEngine {
    pub fn new() -> Self {
        Self
    }

    /// Apply a complete ruleset atomically via `nft -j -f -`.
    ///
    /// The JSON is piped to nft's stdin. On failure the stderr output is
    /// logged at error level and an `Error::Nftables` is returned.
    pub fn apply(&self, ruleset: &Ruleset) -> Result<()> {
        let json = serde_json::to_string(ruleset).map_err(|e| {
            Error::Nftables(format!("failed to serialize ruleset: {e}"))
        })?;

        log::debug!("applying nftables ruleset ({} bytes)", json.len());
        log::trace!("nftables ruleset: {json}");

        let mut child = Command::new("nft")
            .args(["-j", "-f", "-"])
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .map_err(|e| Error::Nftables(format!("failed to spawn nft: {e}")))?;

        if let Some(ref mut stdin) = child.stdin {
            stdin.write_all(json.as_bytes()).map_err(|e| {
                Error::Nftables(format!("failed to write to nft stdin: {e}"))
            })?;
        }
        // Close stdin so nft reads EOF and processes the input.
        drop(child.stdin.take());

        let output = child.wait_with_output().map_err(|e| {
            Error::Nftables(format!("failed to wait on nft: {e}"))
        })?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            log::error!("nft failed (exit {}): {stderr}", output.status);
            return Err(Error::Nftables(format!(
                "nft exited with status {}: {stderr}",
                output.status
            )));
        }

        log::info!("nftables ruleset applied successfully");
        Ok(())
    }

    /// Delete the `inet nopal` table entirely.
    ///
    /// Used during shutdown to clean up. Ignores errors if the table does
    /// not exist (the `-e` flag is not used; we just check exit status
    /// loosely).
    pub fn cleanup(&self) -> Result<()> {
        log::info!("cleaning up nftables table {TABLE_FAMILY} {TABLE_NAME}");

        let output = Command::new("nft")
            .args(["delete", "table", TABLE_FAMILY, TABLE_NAME])
            .output()
            .map_err(|e| Error::Nftables(format!("failed to spawn nft: {e}")))?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            // If the table doesn't exist, that's fine -- we were cleaning up.
            if stderr.contains("No such file or directory")
                || stderr.contains("does not exist")
            {
                log::debug!("nopal table already absent, nothing to clean up");
                return Ok(());
            }
            log::error!("nft delete table failed: {stderr}");
            return Err(Error::Nftables(format!(
                "failed to delete table: {stderr}"
            )));
        }

        log::info!("nftables table {TABLE_FAMILY} {TABLE_NAME} deleted");
        Ok(())
    }
}
