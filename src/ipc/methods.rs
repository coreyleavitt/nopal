use crate::health::ProbeEngine;
use crate::ipc::protocol::*;
use crate::state::InterfaceTracker;
use crate::state::policy::{ResolvedPolicy};
use std::time::Instant;

fn target_status_for(probe_engine: &ProbeEngine, index: usize) -> Vec<TargetStatusData> {
    probe_engine
        .target_status(index)
        .into_iter()
        .map(|ts| TargetStatusData {
            ip: ts.ip.to_string(),
            up: ts.up,
            rtt_ms: ts.last_rtt_ms,
        })
        .collect()
}

/// Build a full daemon status response.
pub fn build_status(
    start_time: Instant,
    trackers: &[InterfaceTracker],
    policies: &[ResolvedPolicy],
    probe_engine: &ProbeEngine,
) -> DaemonStatus {
    let uptime = start_time.elapsed().as_secs();

    let interfaces = trackers
        .iter()
        .map(|t| InterfaceStatusData {
            name: t.name.clone(),
            state: t.state.to_string(),
            device: t.device.clone(),
            enabled: t.enabled,
            mark: t.mark,
            table_id: t.table_id,
            success_count: t.success_count,
            fail_count: t.fail_count,
            avg_rtt_ms: t.avg_rtt_ms,
            loss_percent: t.loss_percent,
            uptime_secs: t.online_since.map(|s| s.elapsed().as_secs()),
            targets: target_status_for(probe_engine, t.index),
        })
        .collect();

    let policy_data = policies
        .iter()
        .map(|p| {
            let active_members = p
                .active_tier()
                .map(|t| t.members.iter().map(|m| m.interface.clone()).collect())
                .unwrap_or_default();
            let active_tier = p.active_tier().map(|t| t.metric);
            PolicyStatusData {
                name: p.name.clone(),
                active_members,
                active_tier,
            }
        })
        .collect();

    DaemonStatus {
        version: env!("CARGO_PKG_VERSION").to_string(),
        uptime_secs: uptime,
        interfaces,
        policies: policy_data,
    }
}

/// Build a single interface status response.
pub fn build_interface_status(
    trackers: &[InterfaceTracker],
    name: &str,
    probe_engine: &ProbeEngine,
) -> Option<InterfaceStatusData> {
    trackers
        .iter()
        .find(|t| t.name == name)
        .map(|t| InterfaceStatusData {
            name: t.name.clone(),
            state: t.state.to_string(),
            device: t.device.clone(),
            enabled: t.enabled,
            mark: t.mark,
            table_id: t.table_id,
            success_count: t.success_count,
            fail_count: t.fail_count,
            avg_rtt_ms: t.avg_rtt_ms,
            loss_percent: t.loss_percent,
            uptime_secs: t.online_since.map(|s| s.elapsed().as_secs()),
            targets: target_status_for(probe_engine, t.index),
        })
}

/// Dispatch an IPC request and build a response.
pub fn dispatch(
    request: &Request,
    start_time: Instant,
    trackers: &[InterfaceTracker],
    policies: &[ResolvedPolicy],
    connected_networks: &[String],
    probe_engine: &ProbeEngine,
) -> (Response, Option<DispatchAction>) {
    match request.method.as_str() {
        "status" => {
            let status = build_status(start_time, trackers, policies, probe_engine);
            (Response::status(request.id, status), None)
        }

        "interface.status" => {
            let name = match &request.params.interface {
                Some(n) => n.as_str(),
                None => {
                    return (
                        Response::error(request.id, "missing interface parameter".into()),
                        None,
                    );
                }
            };
            match build_interface_status(trackers, name, probe_engine) {
                Some(data) => (
                    Response {
                        id: request.id,
                        success: true,
                        error: None,
                        data: Some(ResponseData::InterfaceStatus(data)),
                    },
                    None,
                ),
                None => (
                    Response::error(request.id, format!("unknown interface: {name}")),
                    None,
                ),
            }
        }

        "connected" => {
            let data = ConnectedData {
                networks: connected_networks.to_vec(),
            };
            (
                Response {
                    id: request.id,
                    success: true,
                    error: None,
                    data: Some(ResponseData::Connected(data)),
                },
                None,
            )
        }

        "config.reload" => (Response::ok(request.id), Some(DispatchAction::Reload)),

        "subscribe" => (Response::ok(request.id), None),

        other => (
            Response::error(request.id, format!("unknown method: {other}")),
            None,
        ),
    }
}

/// Side-effects that the daemon should process after sending the IPC response.
#[derive(Debug)]
pub enum DispatchAction {
    /// Re-read config and apply changes.
    Reload,
}
