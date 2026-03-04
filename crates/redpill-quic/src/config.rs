use serde::Deserialize;

/// Server configuration (loaded from TOML).
#[derive(Debug, Deserialize)]
pub struct ServerConfig {
    #[serde(default = "default_listen")]
    pub listen: String,
    #[serde(default = "default_tun_name")]
    pub tun_name: String,
    #[serde(default = "default_tun_address")]
    pub tun_address: String,
    #[serde(default = "default_tun_prefix_len")]
    pub tun_prefix_len: u8,
    #[serde(default = "default_mtu")]
    pub mtu: u32,
    #[serde(default = "default_max_connections")]
    pub max_connections: u32,
    #[serde(default)]
    pub max_bandwidth_mbps: u64,
    #[serde(default = "default_metrics_listen")]
    pub metrics_listen: String,
    #[serde(default = "default_psk_file")]
    pub psk_file: String,
    /// Directory containing per-user PSK files (*.key). When set, enables multi-user mode.
    /// Each file is named `<username>.key` and contains a 64-char hex PSK.
    pub users_dir: Option<String>,
    #[serde(default = "default_cert_file")]
    pub cert_file: String,
    #[serde(default = "default_key_file")]
    pub key_file: String,
    /// Domain name for Let's Encrypt autocert. When set, uses ACME instead of static cert.
    pub domain: Option<String>,
    /// Directory for ACME account key and certificate cache.
    #[serde(default = "default_acme_dir")]
    pub acme_dir: String,
    /// Contact email for Let's Encrypt (optional but recommended).
    pub acme_email: Option<String>,
    #[serde(default = "default_log_level")]
    pub log_level: String,
    #[serde(default = "default_dns")]
    pub dns: String,
    #[serde(default)]
    pub nat: NatConfig,
    #[serde(default)]
    pub decoy: DecoyConfig,
    #[serde(default)]
    pub reality: RealityServerConfig,
    #[serde(default)]
    pub websocket: WebSocketServerConfig,
    #[serde(default)]
    pub camouflage: CamouflageServerConfig,
}

#[derive(Debug, Deserialize)]
pub struct NatConfig {
    #[serde(default = "default_true")]
    pub enabled: bool,
    #[serde(default = "default_wan_interface")]
    pub interface: String,
}

#[derive(Debug, Deserialize)]
pub struct DecoyConfig {
    #[serde(default = "default_true")]
    pub enabled: bool,
    #[serde(default = "default_decoy_page")]
    pub page: String,
}

/// TLS Reality configuration for server-side active probe deflection.
#[derive(Debug, Deserialize)]
pub struct RealityServerConfig {
    #[serde(default)]
    pub enabled: bool,
    /// Listen address for TCP Reality (default: same IP as main, port 8443).
    #[serde(default = "default_reality_listen")]
    pub listen: String,
    /// Target host:port for active probe deflection (proxied when no VPN signal).
    #[serde(default = "default_reality_target")]
    pub target: String,
}

/// WebSocket listener configuration (server sits behind CDN reverse proxy).
#[derive(Debug, Deserialize)]
pub struct WebSocketServerConfig {
    #[serde(default)]
    pub enabled: bool,
    /// Listen address for WebSocket connections (usually 127.0.0.1:8443).
    #[serde(default = "default_ws_listen")]
    pub listen: String,
}

/// Server-side camouflage awareness (logging/validation of client SNI choices).
#[derive(Debug, Default, Deserialize)]
pub struct CamouflageServerConfig {
    /// Known SNI pool (informational - server logs unknown SNIs as warnings).
    #[serde(default)]
    pub sni_pool: Vec<String>,
}

impl Default for RealityServerConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            listen: default_reality_listen(),
            target: default_reality_target(),
        }
    }
}

impl Default for WebSocketServerConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            listen: default_ws_listen(),
        }
    }
}

impl Default for NatConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            interface: default_wan_interface(),
        }
    }
}

impl Default for DecoyConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            page: default_decoy_page(),
        }
    }
}

impl Default for ServerConfig {
    fn default() -> Self {
        Self {
            listen: default_listen(),
            tun_name: default_tun_name(),
            tun_address: default_tun_address(),
            tun_prefix_len: default_tun_prefix_len(),
            mtu: default_mtu(),
            max_connections: default_max_connections(),
            max_bandwidth_mbps: 0,
            metrics_listen: default_metrics_listen(),
            psk_file: default_psk_file(),
            users_dir: None,
            cert_file: default_cert_file(),
            key_file: default_key_file(),
            domain: None,
            acme_dir: default_acme_dir(),
            acme_email: None,
            log_level: default_log_level(),
            dns: default_dns(),
            nat: NatConfig::default(),
            decoy: DecoyConfig::default(),
            reality: RealityServerConfig::default(),
            websocket: WebSocketServerConfig::default(),
            camouflage: CamouflageServerConfig::default(),
        }
    }
}

impl ServerConfig {
    pub fn load(path: &str) -> anyhow::Result<Self> {
        let content = std::fs::read_to_string(path)?;
        let config: Self = toml::from_str(&content)?;
        config.validate()?;
        Ok(config)
    }

    fn validate(&self) -> anyhow::Result<()> {
        use std::net::{Ipv4Addr, SocketAddr};

        self.listen
            .parse::<SocketAddr>()
            .map_err(|e| anyhow::anyhow!("invalid listen address '{}': {e}", self.listen))?;
        self.tun_address
            .parse::<Ipv4Addr>()
            .map_err(|e| anyhow::anyhow!("invalid tun_address '{}': {e}", self.tun_address))?;
        self.dns
            .parse::<Ipv4Addr>()
            .map_err(|e| anyhow::anyhow!("invalid dns '{}': {e}", self.dns))?;
        self.metrics_listen.parse::<SocketAddr>().map_err(|e| {
            anyhow::anyhow!("invalid metrics_listen '{}': {e}", self.metrics_listen)
        })?;

        if self.mtu < 576 || self.mtu > 1500 {
            anyhow::bail!("mtu must be 576..1500, got {}", self.mtu);
        }
        if self.tun_prefix_len == 0 || self.tun_prefix_len > 32 {
            anyhow::bail!("tun_prefix_len must be 1..32, got {}", self.tun_prefix_len);
        }
        if self.max_connections == 0 {
            anyhow::bail!("max_connections must be > 0");
        }

        Ok(())
    }
}

/// Client configuration (CLI args, not TOML).
#[derive(Debug, Clone)]
pub struct ClientConfig {
    pub server_addr: String,
    pub cert_path: String,
    pub psk: [u8; 32],
    pub test_mode: bool,
    pub quiet: bool,
}

// ── Client TOML configuration ───────────────────────────────────────

/// Client TOML config file - loaded via `--config <path>`.
/// CLI args override values from the config file.
#[derive(Debug, Deserialize, Default)]
pub struct ClientTomlConfig {
    #[serde(default)]
    pub server: ClientServerSection,
    #[serde(default)]
    pub transport: ClientTransportSection,
    #[serde(default)]
    pub camouflage: ClientCamouflageSection,
    #[serde(default)]
    pub reality: ClientRealitySection,
    #[serde(default)]
    pub websocket: ClientWebSocketSection,
}

/// `[server]` - connection and auth settings.
#[derive(Debug, Deserialize, Default)]
pub struct ClientServerSection {
    /// Server address (IP:port or IP, default port 443).
    pub address: Option<String>,
    /// Path to server's certificate PEM.
    pub cert: Option<String>,
    /// PSK (64 hex chars).
    pub psk: Option<String>,
    /// Domain name - when set, uses WebPKI verification instead of cert pinning.
    pub domain: Option<String>,
}

/// `[transport]` - transport mode selection.
#[derive(Debug, Deserialize)]
pub struct ClientTransportSection {
    /// Transport mode: "auto", "quic", "quic-camouflaged", "tcp-reality", "websocket".
    #[serde(default = "default_transport_mode")]
    pub mode: String,
}

/// `[camouflage]` - QUIC camouflage settings (Mode 1).
#[derive(Debug, Clone, Deserialize)]
pub struct ClientCamouflageSection {
    /// SNI domains to rotate through.
    #[serde(default = "default_sni_pool")]
    pub sni_pool: Vec<String>,
    /// Pad packets to standard sizes (128/256/512/1024/1200/1400).
    #[serde(default = "default_true")]
    pub padding: bool,
    /// Mimic browser TLS fingerprint (cipher order + QUIC transport params).
    #[serde(default = "default_true")]
    pub chrome_fingerprint: bool,
    /// Browser profile for JA3/JA4 fingerprint mimicry.
    /// Options: "chrome" (default), "firefox", "safari", "random".
    #[serde(default = "default_browser_profile")]
    pub browser_profile: String,
}

/// `[reality]` - TCP Reality settings (Mode 2).
#[derive(Debug, Clone, Deserialize)]
pub struct ClientRealitySection {
    /// Target host:port for TLS Reality (used as SNI in ClientHello).
    #[serde(default = "default_reality_target")]
    pub target: String,
    /// Override server address for TCP Reality (e.g., "5.39.220.32:8444").
    /// If not set, uses the main server address.
    pub address: Option<String>,
}

/// `[websocket]` - WebSocket CDN settings (Mode 3).
#[derive(Debug, Clone, Deserialize, Default)]
pub struct ClientWebSocketSection {
    /// WebSocket URL (e.g., wss://cdn.example.com/ws).
    pub url: Option<String>,
    /// CDN host header override.
    pub host: Option<String>,
}

impl ClientTomlConfig {
    pub fn load(path: &str) -> anyhow::Result<Self> {
        let content = std::fs::read_to_string(path)?;
        let config: Self = toml::from_str(&content)?;
        Ok(config)
    }
}

impl Default for ClientTransportSection {
    fn default() -> Self {
        Self {
            mode: default_transport_mode(),
        }
    }
}

impl Default for ClientCamouflageSection {
    fn default() -> Self {
        Self {
            sni_pool: default_sni_pool(),
            padding: true,
            chrome_fingerprint: true,
            browser_profile: default_browser_profile(),
        }
    }
}

impl Default for ClientRealitySection {
    fn default() -> Self {
        Self {
            target: default_reality_target(),
            address: None,
        }
    }
}

fn default_listen() -> String {
    "0.0.0.0:443".into()
}
fn default_tun_name() -> String {
    "redpill1".into()
}
fn default_tun_address() -> String {
    "10.0.1.1".into()
}
fn default_tun_prefix_len() -> u8 {
    24
}
fn default_mtu() -> u32 {
    1200
}
fn default_max_connections() -> u32 {
    64
}
fn default_psk_file() -> String {
    "/etc/redpill/psk".into()
}
fn default_cert_file() -> String {
    "/etc/redpill/quic-cert.pem".into()
}
fn default_key_file() -> String {
    "/etc/redpill/quic-key.pem".into()
}
fn default_log_level() -> String {
    "info".into()
}
fn default_dns() -> String {
    "1.1.1.1".into()
}
fn default_wan_interface() -> String {
    "ens1".into()
}
fn default_decoy_page() -> String {
    "/etc/redpill/decoy.html".into()
}
fn default_metrics_listen() -> String {
    "127.0.0.1:9093".into()
}
fn default_acme_dir() -> String {
    "/etc/redpill/acme".into()
}
fn default_true() -> bool {
    true
}
fn default_reality_listen() -> String {
    "0.0.0.0:8443".into()
}
fn default_reality_target() -> String {
    "www.google.com:443".into()
}
fn default_ws_listen() -> String {
    "127.0.0.1:8443".into()
}
fn default_transport_mode() -> String {
    "auto".into()
}
fn default_browser_profile() -> String {
    "chrome".into()
}
fn default_sni_pool() -> Vec<String> {
    vec![
        "dl.google.com".into(),
        "www.google.com".into(),
        "fonts.gstatic.com".into(),
        "www.youtube.com".into(),
    ]
}
