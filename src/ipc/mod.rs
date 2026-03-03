pub mod protocol;
pub mod methods;

use crate::error::{Error, Result};
use crate::ipc::protocol::{Request, Response};
use mio::net::UnixListener;
use std::collections::HashMap;
use std::io::{Read, Write};
use std::os::unix::fs::FileTypeExt;

const MAX_CLIENTS: usize = 8;
const MAX_MSG_SIZE: usize = 64 * 1024; // 64KB max message

/// IPC server state. Driven by the main mio event loop, not its own loop.
pub struct IpcServer {
    listener: UnixListener,
    clients: HashMap<usize, ClientConn>,
    next_client_id: usize,
    socket_path: String,
}

struct ClientConn {
    stream: mio::net::UnixStream,
    read_buf: Vec<u8>,
    write_buf: Vec<u8>,
    /// Whether this client is subscribed to events.
    subscribed: bool,
}

impl IpcServer {
    /// Create and bind the IPC server. Removes stale socket file if present.
    pub fn new(path: &str) -> Result<Self> {
        // Remove stale socket. Use symlink_metadata (lstat) to avoid
        // following symlinks, and only remove if it's actually a socket.
        if let Ok(meta) = std::fs::symlink_metadata(path) {
            if meta.file_type().is_socket() {
                let _ = std::fs::remove_file(path);
            } else {
                return Err(Error::Ipc(format!(
                    "IPC socket path {path} exists but is not a socket"
                )));
            }
        }

        // Set restrictive umask before bind so the socket is created with
        // 0o600 permissions atomically (no TOCTOU window).
        let old_umask = unsafe { libc::umask(0o177) };
        let listener = UnixListener::bind(path).map_err(|e| {
            unsafe { libc::umask(old_umask) };
            Error::Ipc(format!("failed to bind IPC socket at {path}: {e}"))
        })?;
        unsafe { libc::umask(old_umask) };

        log::info!("IPC server listening on {path}");

        Ok(Self {
            listener,
            clients: HashMap::new(),
            next_client_id: 0,
            socket_path: path.to_string(),
        })
    }

    /// Get a mutable reference to the listener for mio registration.
    pub fn listener_mut(&mut self) -> &mut UnixListener {
        &mut self.listener
    }

    /// Accept a new client connection. Returns the client ID for mio token mapping.
    pub fn accept(&mut self) -> Result<Option<(usize, &mio::net::UnixStream)>> {
        match self.listener.accept() {
            Ok((stream, _addr)) => {
                if self.clients.len() >= MAX_CLIENTS {
                    log::warn!("IPC: rejecting client, max connections reached");
                    return Ok(None);
                }

                let id = self.next_client_id;
                self.next_client_id = self.next_client_id.wrapping_add(1);
                // Skip IDs already in use (only relevant after wrapping on 32-bit)
                while self.clients.contains_key(&self.next_client_id) {
                    self.next_client_id = self.next_client_id.wrapping_add(1);
                }

                self.clients.insert(id, ClientConn {
                    stream,
                    read_buf: Vec::with_capacity(4096),
                    write_buf: Vec::new(),
                    subscribed: false,
                });

                log::debug!("IPC: client {id} connected");
                Ok(Some((id, &self.clients[&id].stream)))
            }
            Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => Ok(None),
            Err(e) => Err(Error::Ipc(format!("accept failed: {e}"))),
        }
    }

    /// Read and process data from a client. Returns parsed requests if complete messages are available.
    pub fn read_client(&mut self, client_id: usize, registry: &mio::Registry) -> Result<Vec<Request>> {
        let client = match self.clients.get_mut(&client_id) {
            Some(c) => c,
            None => return Ok(Vec::new()),
        };

        let mut buf = [0u8; 4096];
        loop {
            match client.stream.read(&mut buf) {
                Ok(0) => {
                    // Client disconnected
                    log::debug!("IPC: client {client_id} disconnected");
                    self.remove_client(client_id, registry);
                    return Ok(Vec::new());
                }
                Ok(n) => {
                    client.read_buf.extend_from_slice(&buf[..n]);
                    if client.read_buf.len() > MAX_MSG_SIZE {
                        log::warn!("IPC: client {client_id} exceeded max message size");
                        self.remove_client(client_id, registry);
                        return Ok(Vec::new());
                    }
                }
                Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => break,
                Err(e) => {
                    log::warn!("IPC: read error from client {client_id}: {e}");
                    self.remove_client(client_id, registry);
                    return Ok(Vec::new());
                }
            }
        }

        // Try to parse length-prefixed MessagePack frames
        let client = match self.clients.get_mut(&client_id) {
            Some(c) => c,
            None => return Ok(Vec::new()),
        };
        let mut requests = Vec::new();

        while client.read_buf.len() >= 4 {
            let len = u32::from_be_bytes([
                client.read_buf[0],
                client.read_buf[1],
                client.read_buf[2],
                client.read_buf[3],
            ]) as usize;

            if len > MAX_MSG_SIZE {
                log::warn!("IPC: client {client_id} sent oversized frame ({len} bytes)");
                self.remove_client(client_id, registry);
                return Ok(requests);
            }

            if client.read_buf.len() < 4 + len {
                break; // Incomplete frame
            }

            let frame = &client.read_buf[4..4 + len];
            match rmp_serde::from_slice::<Request>(frame) {
                Ok(req) => {
                    if req.method == "subscribe" {
                        client.subscribed = true;
                    }
                    requests.push(req);
                }
                Err(e) => {
                    log::warn!("IPC: failed to parse request from client {client_id}: {e}");
                }
            }

            client.read_buf.drain(..4 + len);
        }

        Ok(requests)
    }

    /// Send a response to a specific client.
    pub fn send_response(&mut self, client_id: usize, response: &Response, registry: &mio::Registry) -> Result<()> {
        let client = match self.clients.get_mut(&client_id) {
            Some(c) => c,
            None => return Ok(()),
        };

        let data = rmp_serde::to_vec(response)
            .map_err(|e| Error::Ipc(format!("failed to serialize response: {e}")))?;

        if data.len() > MAX_MSG_SIZE {
            log::warn!("IPC: response to client {client_id} exceeds max size ({} bytes), dropping", data.len());
            return Ok(());
        }

        // Build the complete framed message (length prefix + body) and write
        // it in a single call to avoid partial frames on the wire.
        client.write_buf.clear();
        client.write_buf.extend_from_slice(&(data.len() as u32).to_be_bytes());
        client.write_buf.extend_from_slice(&data);
        if let Err(e) = client.stream.write_all(&client.write_buf) {
            log::warn!("IPC: write error to client {client_id}: {e}");
            self.remove_client(client_id, registry);
        }

        Ok(())
    }

    /// Broadcast an event to all subscribed clients.
    pub fn broadcast_event(&mut self, event: &Response, registry: &mio::Registry) {
        let subscribed: Vec<usize> = self.clients.iter()
            .filter(|(_, c)| c.subscribed)
            .map(|(id, _)| *id)
            .collect();

        for id in subscribed {
            let _ = self.send_response(id, event, registry);
        }
    }

    /// Get a mutable reference to a client's stream for mio re-registration.
    pub fn client_stream(&mut self, client_id: usize) -> Option<&mut mio::net::UnixStream> {
        self.clients.get_mut(&client_id).map(|c| &mut c.stream)
    }

    /// Remove a client connection, deregistering from mio first.
    pub fn remove_client(&mut self, client_id: usize, registry: &mio::Registry) {
        if let Some(mut client) = self.clients.remove(&client_id) {
            let _ = registry.deregister(&mut client.stream);
        }
    }

    /// Clean up on shutdown.
    pub fn shutdown(&self) {
        let _ = std::fs::remove_file(&self.socket_path);
    }
}

impl Drop for IpcServer {
    fn drop(&mut self) {
        self.shutdown();
    }
}
