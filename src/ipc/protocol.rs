use serde::{Deserialize, Serialize};

/// IPC request (MessagePack-RPC style).
///
/// Wire format: 4-byte big-endian length prefix followed by MessagePack payload.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Request {
    /// Unique request ID for matching responses.
    pub id: u32,
    /// Method name (e.g., "status", "reload", "interface.status").
    pub method: String,
    /// Optional parameters (interface name, etc.).
    #[serde(default)]
    pub params: RequestParams,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct RequestParams {
    /// Interface name for interface-specific methods.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub interface: Option<String>,
}

/// IPC response.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Response {
    /// Matches the request ID, or 0 for unsolicited events.
    pub id: u32,
    /// True if the operation succeeded.
    pub success: bool,
    /// Error message if success is false.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
    /// Response data.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub data: Option<ResponseData>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type")]
pub enum ResponseData {
    /// Full daemon status.
    Status(DaemonStatus),
    /// Single interface status.
    InterfaceStatus(InterfaceStatusData),
    /// Event notification.
    Event(EventData),
    /// Connected network prefixes.
    Connected(ConnectedData),
    /// Simple acknowledgment (for reload, enable/disable).
    Ok,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DaemonStatus {
    pub version: String,
    pub uptime_secs: u64,
    pub interfaces: Vec<InterfaceStatusData>,
    pub policies: Vec<PolicyStatusData>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InterfaceStatusData {
    pub name: String,
    pub state: String,
    pub device: String,
    pub enabled: bool,
    pub mark: u32,
    pub table_id: u32,
    pub success_count: u32,
    pub fail_count: u32,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub avg_rtt_ms: Option<u32>,
    pub loss_percent: u32,
    /// Seconds since the interface last went online (None if never online).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub uptime_secs: Option<u64>,
    /// Per-target probe status from the most recent cycle.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub targets: Vec<TargetStatusData>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TargetStatusData {
    pub ip: String,
    pub up: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub rtt_ms: Option<u32>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolicyStatusData {
    pub name: String,
    pub active_members: Vec<String>,
    pub active_tier: Option<u32>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EventData {
    pub event: String,
    pub interface: Option<String>,
    pub state: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConnectedData {
    pub networks: Vec<String>,
}

impl Response {
    pub fn ok(id: u32) -> Self {
        Self {
            id,
            success: true,
            error: None,
            data: Some(ResponseData::Ok),
        }
    }

    pub fn error(id: u32, msg: String) -> Self {
        Self {
            id,
            success: false,
            error: Some(msg),
            data: None,
        }
    }

    pub fn status(id: u32, status: DaemonStatus) -> Self {
        Self {
            id,
            success: true,
            error: None,
            data: Some(ResponseData::Status(status)),
        }
    }

    pub fn event(event: &str, interface: Option<&str>, state: Option<&str>) -> Self {
        Self {
            id: 0,
            success: true,
            error: None,
            data: Some(ResponseData::Event(EventData {
                event: event.to_string(),
                interface: interface.map(|s| s.to_string()),
                state: state.map(|s| s.to_string()),
            })),
        }
    }
}
