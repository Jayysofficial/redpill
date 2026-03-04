//! WebSocket CDN transport (Mode 3): IP packets over WebSocket binary frames.
//!
//! Last-resort transport when direct connections to the server are blocked.
//! Traffic flows through a CDN (e.g. Cloudflare) that proxies WebSocket
//! connections to the origin server.
//!
//! Wire format: each WebSocket binary message = one IP packet (no length prefix
//! needed since WebSocket already provides message framing).
//!
//! Client → CDN → Server:
//!   1. WebSocket connect to CDN domain (wss://cdn.example.com/ws)
//!   2. CDN proxies to origin (127.0.0.1:8443 on server)
//!   3. First binary message = ClientAuth (66 bytes)
//!   4. Server responds with SessionConfig (17 bytes)
//!   5. Subsequent binary messages = IP packets

use async_trait::async_trait;
use bytes::Bytes;
use futures_util::{SinkExt, StreamExt};
use tokio::net::TcpStream;
use tokio::sync::Mutex;
use tokio_tungstenite::tungstenite::Message;
use tracing::info;

use crate::auth::PskAuthenticator;
use crate::config::ClientWebSocketSection;
use crate::control::{ClientAuth, SessionConfig, SESSION_CONFIG_LEN};
use crate::PROTOCOL_VERSION;

use super::{SendResult, Transport, TransportError, TransportMode, TransportStats};

/// WebSocket CDN transport - each binary WS message is one IP packet.
///
/// Thread safety: sink and stream are split and protected by separate mutexes.
pub struct WebSocketTransport {
    sink: Mutex<
        futures_util::stream::SplitSink<
            tokio_tungstenite::WebSocketStream<tokio_tungstenite::MaybeTlsStream<TcpStream>>,
            Message,
        >,
    >,
    stream: Mutex<
        futures_util::stream::SplitStream<
            tokio_tungstenite::WebSocketStream<tokio_tungstenite::MaybeTlsStream<TcpStream>>,
        >,
    >,
}

impl WebSocketTransport {
    pub fn new(
        ws: tokio_tungstenite::WebSocketStream<tokio_tungstenite::MaybeTlsStream<TcpStream>>,
    ) -> Self {
        let (sink, stream) = ws.split();
        Self {
            sink: Mutex::new(sink),
            stream: Mutex::new(stream),
        }
    }
}

#[async_trait]
impl Transport for WebSocketTransport {
    async fn send(&self, data: Bytes) -> Result<SendResult, TransportError> {
        let mut sink = self.sink.lock().await;
        match sink.send(Message::Binary(data.to_vec())).await {
            Ok(()) => Ok(SendResult::Sent),
            Err(e) => Err(TransportError::ConnectionLost(e.to_string())),
        }
    }

    async fn recv(&self) -> Result<Bytes, TransportError> {
        let mut stream = self.stream.lock().await;
        loop {
            match stream.next().await {
                Some(Ok(Message::Binary(data))) => {
                    return Ok(Bytes::from(data));
                }
                Some(Ok(Message::Ping(_))) | Some(Ok(Message::Pong(_))) => {
                    continue;
                }
                Some(Ok(Message::Close(_))) => {
                    return Err(TransportError::ConnectionLost("WebSocket closed".into()));
                }
                Some(Ok(_)) => {
                    continue;
                }
                Some(Err(e)) => {
                    return Err(TransportError::ConnectionLost(e.to_string()));
                }
                None => {
                    return Err(TransportError::ConnectionLost(
                        "WebSocket stream ended".into(),
                    ));
                }
            }
        }
    }

    fn mode(&self) -> TransportMode {
        TransportMode::WebSocketCdn
    }

    fn stats(&self) -> TransportStats {
        TransportStats::default()
    }

    fn max_datagram_size(&self) -> Option<usize> {
        Some(65535)
    }
}

/// Builder for WebSocket CDN connections (client-side).
pub struct WebSocketConnector {
    ws_config: ClientWebSocketSection,
}

impl WebSocketConnector {
    pub fn new(ws_config: ClientWebSocketSection, _cert_path: String) -> Self {
        Self { ws_config }
    }

    /// Connect to the server via WebSocket through CDN.
    ///
    /// 1. WebSocket connect to CDN URL
    /// 2. Send ClientAuth as first binary message
    /// 3. Read SessionConfig response
    /// 4. Return (WebSocketTransport, SessionConfig)
    pub async fn connect(
        &self,
        auth: &PskAuthenticator,
    ) -> anyhow::Result<(WebSocketTransport, SessionConfig)> {
        let url = self
            .ws_config
            .url
            .as_deref()
            .ok_or_else(|| anyhow::anyhow!("WebSocket URL not configured"))?;

        info!("WebSocket: connecting to {url}...");

        let (mut ws_stream, _response) = tokio_tungstenite::connect_async(url)
            .await
            .map_err(|e| anyhow::anyhow!("WebSocket connect failed: {e}"))?;

        info!("WebSocket: connected");

        let mut nonce = [0u8; 32];
        rand::RngCore::fill_bytes(&mut rand::thread_rng(), &mut nonce);
        let mac = auth.compute_mac(&nonce);

        let client_auth = ClientAuth {
            nonce,
            mac,
            version: PROTOCOL_VERSION,
        };
        ws_stream
            .send(Message::Binary(client_auth.encode().to_vec()))
            .await
            .map_err(|e| anyhow::anyhow!("WebSocket send auth failed: {e}"))?;

        let config_msg = ws_stream
            .next()
            .await
            .ok_or_else(|| anyhow::anyhow!("WebSocket closed before session config"))?
            .map_err(|e| anyhow::anyhow!("WebSocket read session config failed: {e}"))?;

        let config_data = match config_msg {
            Message::Binary(data) => data,
            other => anyhow::bail!("Expected binary message, got: {other:?}"),
        };

        if config_data.len() < SESSION_CONFIG_LEN {
            anyhow::bail!(
                "Session config too short: {} bytes (expected {})",
                config_data.len(),
                SESSION_CONFIG_LEN,
            );
        }

        let session_config = SessionConfig::decode(&config_data[..SESSION_CONFIG_LEN])
            .ok_or_else(|| anyhow::anyhow!("Invalid session config from server"))?;

        info!(
            "WebSocket: authenticated, assigned IP {}",
            session_config.client_ip
        );

        Ok((WebSocketTransport::new(ws_stream), session_config))
    }
}

/// Server-side: run VPN tunnel over a WebSocket connection.
///
/// Similar to TCP Reality tunnel but uses WebSocket frames instead of
/// length-prefixed TCP. Each binary message = one IP packet.
pub async fn run_ws_vpn_tunnel(
    ws: tokio_tungstenite::WebSocketStream<TcpStream>,
    tun_fd: i32,
    client_ip: std::net::Ipv4Addr,
) -> anyhow::Result<()> {
    use crate::datagram::{validate_source_ip, write_to_tun};
    use tokio::io::unix::AsyncFd;

    let (mut ws_sink, mut ws_stream) = ws.split();

    let tun_async_fd =
        AsyncFd::new(unsafe { std::os::fd::BorrowedFd::borrow_raw(tun_fd) }.try_clone_to_owned()?)?;

    #[cfg(target_os = "macos")]
    const TUN_HDR: usize = 4;
    #[cfg(not(target_os = "macos"))]
    const TUN_HDR: usize = 0;

    let tun2ws: tokio::task::JoinHandle<anyhow::Result<()>> = tokio::spawn(async move {
        use std::os::fd::AsRawFd;
        let mut tun_buf = vec![0u8; crate::TUN_MTU as usize + 4];
        loop {
            let mut guard = tun_async_fd.readable().await?;
            loop {
                let n = match nix::unistd::read(tun_async_fd.as_raw_fd(), &mut tun_buf) {
                    Ok(n) if n > TUN_HDR => n,
                    Ok(_) => break,
                    Err(nix::errno::Errno::EAGAIN) => {
                        guard.clear_ready();
                        break;
                    }
                    Err(e) => return Err(e.into()),
                };

                let ip_pkt = &tun_buf[TUN_HDR..n];
                ws_sink.send(Message::Binary(ip_pkt.to_vec())).await?;
            }
        }
    });

    let ws2tun_result: anyhow::Result<()> = async {
        loop {
            match ws_stream.next().await {
                Some(Ok(Message::Binary(data))) => {
                    if !validate_source_ip(&data, client_ip) {
                        continue;
                    }
                    let _ = write_to_tun(tun_fd, &data);
                }
                Some(Ok(Message::Ping(_))) | Some(Ok(Message::Pong(_))) => continue,
                Some(Ok(Message::Close(_))) | None => {
                    anyhow::bail!("WebSocket closed");
                }
                Some(Ok(_)) => continue,
                Some(Err(e)) => {
                    anyhow::bail!("WebSocket error: {e}");
                }
            }
        }
    }
    .await;

    tun2ws.abort();
    ws2tun_result
}
