//! Unix socket IPC for daemon status queries.
//!
//! Protocol: client sends `"status\n"`, daemon responds with JSON `DaemonStatus`.

use std::path::Path;
use std::sync::Arc;

use serde::{Deserialize, Serialize};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::UnixListener;
use tracing::{error, warn};

/// Daemon status (serialized as JSON over IPC socket).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DaemonStatus {
    pub connected: bool,
    pub server: String,
    pub transport: String,
    pub client_ip: Option<String>,
    pub uptime_secs: u64,
    pub bytes_sent: u64,
    pub bytes_recv: u64,
    pub datagrams_sent: u64,
    pub datagrams_recv: u64,
}

/// Shared state that the IPC server reads to produce status.
pub struct DaemonState {
    pub connected: std::sync::atomic::AtomicBool,
    pub server: String,
    pub transport: parking_lot::RwLock<String>,
    pub client_ip: parking_lot::RwLock<Option<String>>,
    pub start: std::time::Instant,
    pub stats: Arc<crate::stats::Stats>,
}

impl DaemonState {
    pub fn to_status(&self) -> DaemonStatus {
        use std::sync::atomic::Ordering::Relaxed;
        DaemonStatus {
            connected: self.connected.load(Relaxed),
            server: self.server.clone(),
            transport: self.transport.read().clone(),
            client_ip: self.client_ip.read().clone(),
            uptime_secs: self.start.elapsed().as_secs(),
            bytes_sent: self.stats.bytes_sent.load(Relaxed),
            bytes_recv: self.stats.bytes_recv.load(Relaxed),
            datagrams_sent: self.stats.datagrams_sent.load(Relaxed),
            datagrams_recv: self.stats.datagrams_recv.load(Relaxed),
        }
    }
}

/// Bind the IPC socket synchronously (call before spawning the async server).
/// Returns the std UnixListener ready for conversion to tokio.
pub fn bind_ipc_socket(socket_path: &Path) -> anyhow::Result<std::os::unix::net::UnixListener> {
    let _ = std::fs::remove_file(socket_path);

    let listener = std::os::unix::net::UnixListener::bind(socket_path)
        .map_err(|e| anyhow::anyhow!("Failed to bind IPC socket {}: {e}", socket_path.display()))?;

    use std::os::unix::fs::PermissionsExt;
    let _ = std::fs::set_permissions(socket_path, std::fs::Permissions::from_mode(0o600));

    // Must be non-blocking for tokio::net::UnixListener::from_std
    listener.set_nonblocking(true)?;
    Ok(listener)
}

/// Spawn the IPC server on an already-bound Unix domain socket.
pub fn spawn_ipc_server(
    std_listener: std::os::unix::net::UnixListener,
    state: Arc<DaemonState>,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        let listener = match UnixListener::from_std(std_listener) {
            Ok(l) => l,
            Err(e) => {
                error!("Failed to convert IPC listener to async: {e}");
                return;
            }
        };

        loop {
            let (stream, _) = match listener.accept().await {
                Ok(s) => s,
                Err(e) => {
                    warn!("IPC accept error: {e}");
                    continue;
                }
            };

            let state = state.clone();
            tokio::spawn(async move {
                let (reader, mut writer) = stream.into_split();
                let mut reader = BufReader::new(reader);
                let mut line = String::new();

                match reader.read_line(&mut line).await {
                    Ok(0) => return,
                    Ok(_) => {}
                    Err(_) => return,
                }

                match line.trim() {
                    "status" => {
                        let status = state.to_status();
                        let json = serde_json::to_string(&status).unwrap_or_default();
                        let _ = writer.write_all(json.as_bytes()).await;
                        let _ = writer.write_all(b"\n").await;
                    }
                    other => {
                        let _ = writer
                            .write_all(format!("unknown command: {other}\n").as_bytes())
                            .await;
                    }
                }
            });
        }
    })
}

/// Query daemon status via IPC socket. Returns parsed DaemonStatus.
pub fn query_status(socket_path: &Path) -> anyhow::Result<DaemonStatus> {
    use std::io::{BufRead, Write};
    use std::os::unix::net::UnixStream;

    let mut stream = UnixStream::connect(socket_path).map_err(|e| {
        anyhow::anyhow!("Cannot connect to daemon ({}): {e}", socket_path.display())
    })?;
    stream.set_read_timeout(Some(std::time::Duration::from_secs(2)))?;

    stream.write_all(b"status\n")?;
    stream.flush()?;

    let mut reader = std::io::BufReader::new(stream);
    let mut line = String::new();
    reader.read_line(&mut line)?;

    let status: DaemonStatus =
        serde_json::from_str(&line).map_err(|e| anyhow::anyhow!("Invalid daemon response: {e}"))?;
    Ok(status)
}
