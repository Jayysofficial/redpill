//! Transport manager: probes transports in priority order, failover, upgrade.
//!
//! The manager holds a list of `TransportConnector` implementations ordered by
//! preference (fastest first: QUIC → TCP Reality → WebSocket). On each connect
//! attempt it tries connectors sequentially until one succeeds.

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use tracing::{info, warn};

use crate::auth::PskAuthenticator;
use crate::config::{ClientCamouflageSection, ClientRealitySection, ClientWebSocketSection};
use crate::control::SessionConfig;

use super::{Transport, TransportMode};

/// Result of a successful transport connection.
pub struct ConnectResult {
    /// The connected transport.
    pub transport: Arc<dyn Transport>,
    /// Session configuration received from the server.
    pub session_config: SessionConfig,
    /// QUIC connection handle (for QUIC-specific stats). None for TCP/WS transports.
    pub quic_conn: Option<quinn::Connection>,
    /// Which transport mode was used.
    pub mode: TransportMode,
    /// Control stream recv end - for reading SessionUpdate messages (dynamic MTU).
    /// None for non-QUIC transports or old servers that close the stream.
    pub control_recv: Option<quinn::RecvStream>,
}

/// Factory for creating transport connections.
#[async_trait]
pub trait TransportConnector: Send + Sync {
    /// Attempt to connect using this transport.
    async fn connect(&self) -> anyhow::Result<ConnectResult>;

    /// The transport mode this connector creates.
    fn mode(&self) -> TransportMode;
}

/// Transport manager: probes transports in priority order and connects.
pub struct TransportManager {
    connectors: Vec<Box<dyn TransportConnector>>,
}

/// Probe timeout per transport (10s - enough for TLS handshake + auth).
const PROBE_TIMEOUT: Duration = Duration::from_secs(10);

impl TransportManager {
    /// Create a new transport manager with connectors in priority order.
    /// The first connector is tried first (highest priority).
    pub fn new(connectors: Vec<Box<dyn TransportConnector>>) -> Self {
        Self { connectors }
    }

    /// Probe all transports in priority order.
    /// Returns the first successful connection.
    pub async fn probe_and_connect(&self) -> anyhow::Result<ConnectResult> {
        let mut last_error = None;

        for connector in &self.connectors {
            let mode = connector.mode();
            info!("Probing transport: {mode}...");

            match tokio::time::timeout(PROBE_TIMEOUT, connector.connect()).await {
                Ok(Ok(result)) => {
                    info!("Connected via {mode}");
                    return Ok(result);
                }
                Ok(Err(e)) => {
                    warn!("Transport {mode} probe failed: {e}");
                    last_error = Some(e);
                }
                Err(_) => {
                    warn!("Transport {mode} probe timed out");
                    last_error = Some(anyhow::anyhow!("{mode} connection timed out"));
                }
            }
        }

        Err(last_error.unwrap_or_else(|| anyhow::anyhow!("No transport connectors configured")))
    }

    /// Get the list of available transport modes.
    pub fn available_modes(&self) -> Vec<TransportMode> {
        self.connectors.iter().map(|c| c.mode()).collect()
    }
}

// ── QUIC Direct Connector (Mode 0) ─────────────────────────────────

/// QUIC direct connector - wraps quinn endpoint + PSK auth handshake.
pub struct QuicDirectConnector {
    endpoint: quinn::Endpoint,
    server_addr: SocketAddr,
    cert_path: String,
    auth: PskAuthenticator,
    /// When set, use WebPKI verification with this domain instead of cert pinning.
    domain: Option<String>,
}

impl QuicDirectConnector {
    pub fn new(
        endpoint: quinn::Endpoint,
        server_addr: SocketAddr,
        cert_path: String,
        auth: PskAuthenticator,
        domain: Option<String>,
    ) -> Self {
        Self {
            endpoint,
            server_addr,
            cert_path,
            auth,
            domain,
        }
    }
}

#[async_trait]
impl TransportConnector for QuicDirectConnector {
    async fn connect(&self) -> anyhow::Result<ConnectResult> {
        use crate::control::{ClientAuth, SESSION_CONFIG_LEN};
        use crate::transport::{build_transport_config, QuicRawTransport};
        use crate::{ALPN_VPN, PROTOCOL_VERSION};

        let (rustls_config, sni) = if let Some(ref domain) = self.domain {
            let mut root_store = rustls::RootCertStore::empty();
            root_store.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());

            let mut cfg = rustls::ClientConfig::builder()
                .with_root_certificates(root_store)
                .with_no_client_auth();
            cfg.alpn_protocols = vec![ALPN_VPN.to_vec()];
            cfg.resumption = rustls::client::Resumption::in_memory_sessions(256);
            (cfg, domain.as_str().to_string())
        } else {
            use crate::cert::pem_to_cert_der;
            let cert_pem = std::fs::read_to_string(&self.cert_path)?;
            let cert_der = pem_to_cert_der(&cert_pem)?;

            let mut root_store = rustls::RootCertStore::empty();
            root_store.add(cert_der)?;

            let mut cfg = rustls::ClientConfig::builder()
                .with_root_certificates(root_store)
                .with_no_client_auth();
            cfg.alpn_protocols = vec![ALPN_VPN.to_vec()];
            cfg.resumption = rustls::client::Resumption::in_memory_sessions(256);
            (cfg, "redpill-quic".to_string())
        };

        let mut client_config = quinn::ClientConfig::new(Arc::new(
            quinn::crypto::rustls::QuicClientConfig::try_from(rustls_config)?,
        ));
        let transport = build_transport_config();
        client_config.transport_config(Arc::new(transport));

        info!("QUIC: connecting to {}...", self.server_addr);
        let connecting = self
            .endpoint
            .connect_with(client_config, self.server_addr, &sni)?;
        let conn = connecting.await?;

        let (mut send, mut recv) = conn.open_bi().await?;

        let mut nonce = [0u8; 32];
        rand::RngCore::fill_bytes(&mut rand::thread_rng(), &mut nonce);
        let mac = self.auth.compute_mac(&nonce);

        let client_auth = ClientAuth {
            nonce,
            mac,
            version: PROTOCOL_VERSION,
        };
        send.write_all(&client_auth.encode()).await?;
        send.finish()?;

        let mut config_buf = vec![0u8; SESSION_CONFIG_LEN];
        recv.read_exact(&mut config_buf).await?;

        let session_config = SessionConfig::decode(&config_buf)
            .ok_or_else(|| anyhow::anyhow!("Invalid session config from server"))?;

        let transport = Arc::new(QuicRawTransport::new(conn.clone()));

        Ok(ConnectResult {
            transport,
            session_config,
            quic_conn: Some(conn),
            mode: TransportMode::QuicRaw,
            control_recv: Some(recv),
        })
    }

    fn mode(&self) -> TransportMode {
        TransportMode::QuicRaw
    }
}

// ── QUIC Camouflaged Connector Adapter (Mode 1) ─────────────────────

/// QUIC Camouflaged connector.
pub struct QuicCamouflagedConnectorAdapter {
    inner: super::quic_camouflaged::QuicCamouflagedConnector,
    endpoint: quinn::Endpoint,
    server_addr: SocketAddr,
    auth: PskAuthenticator,
}

impl QuicCamouflagedConnectorAdapter {
    pub fn new(
        inner: super::quic_camouflaged::QuicCamouflagedConnector,
        endpoint: quinn::Endpoint,
        server_addr: SocketAddr,
        auth: PskAuthenticator,
    ) -> Self {
        Self {
            inner,
            endpoint,
            server_addr,
            auth,
        }
    }
}

#[async_trait]
impl TransportConnector for QuicCamouflagedConnectorAdapter {
    async fn connect(&self) -> anyhow::Result<ConnectResult> {
        use crate::control::{ClientAuth, SESSION_CONFIG_LEN};
        use crate::PROTOCOL_VERSION;

        let (client_config, fake_sni) = self.inner.build_client_config()?;

        info!(
            "QUIC+Camo: connecting to {} (SNI={fake_sni})...",
            self.server_addr
        );
        let connecting = self
            .endpoint
            .connect_with(client_config, self.server_addr, &fake_sni)?;
        let conn = connecting.await?;

        let (mut send, mut recv) = conn.open_bi().await?;

        let mut nonce = [0u8; 32];
        rand::RngCore::fill_bytes(&mut rand::thread_rng(), &mut nonce);
        let mac = self.auth.compute_mac(&nonce);

        let client_auth = ClientAuth {
            nonce,
            mac,
            version: PROTOCOL_VERSION,
        };
        send.write_all(&client_auth.encode()).await?;
        send.finish()?;

        let mut config_buf = vec![0u8; SESSION_CONFIG_LEN];
        recv.read_exact(&mut config_buf).await?;

        let session_config = SessionConfig::decode(&config_buf)
            .ok_or_else(|| anyhow::anyhow!("Invalid session config from server"))?;

        let padding_enabled = self.inner.padding_enabled();
        let raw_transport = super::quic_raw::QuicRawTransport::new(conn.clone());
        let transport = Arc::new(super::quic_camouflaged::QuicCamouflagedTransport::new(
            raw_transport,
            padding_enabled,
        ));

        Ok(ConnectResult {
            transport,
            session_config,
            quic_conn: Some(conn),
            mode: TransportMode::QuicCamouflaged,
            control_recv: Some(recv),
        })
    }

    fn mode(&self) -> TransportMode {
        TransportMode::QuicCamouflaged
    }
}

// ── TCP Reality Connector Adapter (Mode 2) ──────────────────────────

/// TCP Reality connector.
pub struct TcpRealityConnectorAdapter {
    inner: super::tcp_reality::TcpRealityConnector,
    server_addr: String,
    auth: PskAuthenticator,
}

impl TcpRealityConnectorAdapter {
    pub fn new(
        inner: super::tcp_reality::TcpRealityConnector,
        server_addr: String,
        auth: PskAuthenticator,
    ) -> Self {
        Self {
            inner,
            server_addr,
            auth,
        }
    }
}

#[async_trait]
impl TransportConnector for TcpRealityConnectorAdapter {
    async fn connect(&self) -> anyhow::Result<ConnectResult> {
        let (transport, session_config) = self.inner.connect(&self.server_addr, &self.auth).await?;

        Ok(ConnectResult {
            transport: Arc::new(transport),
            session_config,
            quic_conn: None,
            mode: TransportMode::TcpReality,
            control_recv: None,
        })
    }

    fn mode(&self) -> TransportMode {
        TransportMode::TcpReality
    }
}

// ── WebSocket CDN Connector Adapter (Mode 3) ────────────────────────

/// WebSocket CDN connector.
pub struct WebSocketConnectorAdapter {
    inner: super::websocket_cdn::WebSocketConnector,
    auth: PskAuthenticator,
}

impl WebSocketConnectorAdapter {
    pub fn new(inner: super::websocket_cdn::WebSocketConnector, auth: PskAuthenticator) -> Self {
        Self { inner, auth }
    }
}

#[async_trait]
impl TransportConnector for WebSocketConnectorAdapter {
    async fn connect(&self) -> anyhow::Result<ConnectResult> {
        let (transport, session_config) = self.inner.connect(&self.auth).await?;

        Ok(ConnectResult {
            transport: Arc::new(transport),
            session_config,
            quic_conn: None,
            mode: TransportMode::WebSocketCdn,
            control_recv: None,
        })
    }

    fn mode(&self) -> TransportMode {
        TransportMode::WebSocketCdn
    }
}

// ── Builder ─────────────────────────────────────────────────────────

/// Configuration for building a TransportManager.
pub struct TransportBuildConfig<'a> {
    pub mode: &'a str,
    pub server_addr: SocketAddr,
    pub cert_path: &'a str,
    pub auth: &'a PskAuthenticator,
    pub camouflage_config: &'a ClientCamouflageSection,
    pub reality_config: &'a ClientRealitySection,
    pub ws_config: &'a ClientWebSocketSection,
    pub endpoint: quinn::Endpoint,
    pub domain: Option<String>,
}

/// Build a TransportManager based on client configuration.
///
/// Connectors are ordered by preference (fastest first).
/// Mode "auto" adds all available transports; specific modes add only one.
pub fn build_transport_manager(cfg: TransportBuildConfig<'_>) -> TransportManager {
    let TransportBuildConfig {
        mode,
        server_addr,
        cert_path,
        auth,
        camouflage_config,
        reality_config,
        ws_config,
        endpoint,
        domain,
    } = cfg;
    let mut connectors: Vec<Box<dyn TransportConnector>> = Vec::new();

    let add_quic = |connectors: &mut Vec<Box<dyn TransportConnector>>| {
        connectors.push(Box::new(QuicDirectConnector::new(
            endpoint.clone(),
            server_addr,
            cert_path.to_string(),
            auth.clone(),
            domain.clone(),
        )));
    };

    let add_quic_camouflaged = |connectors: &mut Vec<Box<dyn TransportConnector>>| {
        let camo_connector = super::quic_camouflaged::QuicCamouflagedConnector::new(
            cert_path.to_string(),
            camouflage_config.clone(),
        );
        connectors.push(Box::new(QuicCamouflagedConnectorAdapter::new(
            camo_connector,
            endpoint.clone(),
            server_addr,
            auth.clone(),
        )));
    };

    let add_tcp_reality = |connectors: &mut Vec<Box<dyn TransportConnector>>| {
        let tcp_connector = super::tcp_reality::TcpRealityConnector::new(
            cert_path.to_string(),
            reality_config.clone(),
            camouflage_config.clone(),
        );
        let reality_addr = reality_config
            .address
            .clone()
            .unwrap_or_else(|| server_addr.to_string());
        connectors.push(Box::new(TcpRealityConnectorAdapter::new(
            tcp_connector,
            reality_addr,
            auth.clone(),
        )));
    };

    let add_websocket = |connectors: &mut Vec<Box<dyn TransportConnector>>| {
        if ws_config.url.is_some() {
            let ws_connector = super::websocket_cdn::WebSocketConnector::new(
                ws_config.clone(),
                cert_path.to_string(),
            );
            connectors.push(Box::new(WebSocketConnectorAdapter::new(
                ws_connector,
                auth.clone(),
            )));
        }
    };

    match mode {
        "quic" => add_quic(&mut connectors),
        "quic-camouflaged" => add_quic_camouflaged(&mut connectors),
        "tcp-reality" => add_tcp_reality(&mut connectors),
        "websocket" => add_websocket(&mut connectors),
        // "auto" or unrecognized: try all in priority order
        _ => {
            add_quic(&mut connectors);
            add_quic_camouflaged(&mut connectors);
            add_tcp_reality(&mut connectors);
            add_websocket(&mut connectors);
        }
    }

    info!(
        "Transport manager: mode={mode}, available: {:?}",
        connectors.iter().map(|c| c.mode()).collect::<Vec<_>>()
    );
    TransportManager::new(connectors)
}
