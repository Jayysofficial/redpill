use std::net::{Ipv4Addr, SocketAddr};
use std::os::fd::AsRawFd;
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::Arc;

use bytes::Bytes;
use clap::Parser;
use quinn::SendDatagramError;
use tokio::io::unix::AsyncFd;
use tokio_util::sync::CancellationToken;
use tracing::{error, info, warn};

use redpill_quic::auth::{load_psk, PskAuthenticator};
use redpill_quic::cert::load_or_generate;
use redpill_quic::config::ServerConfig;
use redpill_quic::control::{ClientAuth, SessionConfig};
use redpill_quic::datagram::{extract_dst_ipv4, validate_source_ip, write_to_tun};
use redpill_quic::demux::ClientRouter;
use redpill_quic::ip_pool::IpPool;
use redpill_quic::metrics::{self, Metrics};
use redpill_quic::priority::PriorityQueue;
use redpill_quic::priority::{classify, Priority};
use redpill_quic::shaper::AdaptiveShaper;
use redpill_quic::stats::Stats;
use redpill_quic::transport::build_transport_config;
use redpill_quic::users::UserStore;
use redpill_quic::{
    ALPN_H3, ALPN_VPN, DATAGRAM_WAIT_TIMEOUT, ERR_AUTH_FAILED, MAX_TUN_BATCH, STATS_INTERVAL,
    TUN_MTU,
};
use redpill_tun::device::TunDevice;
use redpill_tun::route;

/// Per-client channel buffer size (~1.2MB at 1200B MTU).
const CLIENT_CHANNEL_SIZE: usize = 1024;

#[derive(Parser)]
#[command(name = "redpill-server", about = "QUIC DATAGRAM VPN server")]
struct Cli {
    /// Path to server config TOML
    #[arg(short, long, default_value = "/etc/redpill/server.toml")]
    config: String,

    #[command(subcommand)]
    command: Option<Command>,
}

#[derive(clap::Subcommand)]
enum Command {
    /// Add a new VPN user (generates random PSK)
    AddUser {
        /// Username
        name: String,
    },
    /// Remove a VPN user
    RemoveUser {
        /// Username
        name: String,
    },
    /// List all VPN users
    ListUsers,
}

/// Authentication mode: single PSK or multi-user directory.
#[derive(Clone)]
enum AuthMode {
    SinglePsk(PskAuthenticator),
    MultiUser(UserStore),
}

impl AuthMode {
    /// Verify client auth. Returns Some(username) on success, None on failure.
    /// For single PSK mode, username is "default".
    fn verify(&self, nonce: &[u8; 32], mac: &[u8; 32]) -> Option<String> {
        match self {
            AuthMode::SinglePsk(auth) => {
                if auth.verify(nonce, mac) {
                    Some("default".to_string())
                } else {
                    None
                }
            }
            AuthMode::MultiUser(store) => store.verify(nonce, mac).map(|r| r.username),
        }
    }
}

struct ServerState {
    auth: parking_lot::RwLock<AuthMode>,
    ip_pool: parking_lot::Mutex<IpPool>,
    active_connections: AtomicU32,
    max_connections: AtomicU32,
    cancel: CancellationToken,
    mtu: u32,
    server_ip: Ipv4Addr,
    dns_ip: Ipv4Addr,
    decoy_enabled: bool,
    decoy_page: parking_lot::RwLock<String>,
    router: Arc<ClientRouter>,
    shaper: Arc<AdaptiveShaper>,
    metrics: Arc<Metrics>,
    config_path: String,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // Explicitly install ring as the CryptoProvider (both ring and aws-lc-rs
    // features are active due to transitive deps from tokio-rustls/tungstenite).
    rustls::crypto::ring::default_provider()
        .install_default()
        .ok();

    let cli = Cli::parse();

    let config = if std::path::Path::new(&cli.config).exists() {
        ServerConfig::load(&cli.config)?
    } else {
        // For subcommands, config must exist
        if cli.command.is_some() {
            anyhow::bail!("Config not found at {}", cli.config);
        }
        info!("Config not found at {}, using defaults", cli.config);
        ServerConfig::default()
    };

    if let Some(cmd) = cli.command {
        let users_dir = config.users_dir.as_deref().ok_or_else(|| {
            anyhow::anyhow!("users_dir not set in config - multi-user mode not enabled")
        })?;
        let dir = std::path::Path::new(users_dir);
        if !dir.exists() {
            std::fs::create_dir_all(dir)?;
        }
        let mut store = UserStore::load(dir)?;
        match cmd {
            Command::AddUser { name } => {
                let hex = store.add_user(&name)?;
                println!("User '{name}' added. PSK: {hex}");
            }
            Command::RemoveUser { name } => {
                store.remove_user(&name)?;
                println!("User '{name}' removed.");
            }
            Command::ListUsers => {
                let mut names = store
                    .usernames()
                    .into_iter()
                    .map(String::from)
                    .collect::<Vec<_>>();
                names.sort();
                if names.is_empty() {
                    println!("No users configured.");
                } else {
                    println!("{} user(s):", names.len());
                    for name in names {
                        println!("  {name}");
                    }
                }
            }
        }
        return Ok(());
    }

    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| config.log_level.clone().into()),
        )
        .init();

    info!("Starting QUIC VPN server");

    let auth_mode = if let Some(ref users_dir) = config.users_dir {
        let dir = std::path::Path::new(users_dir);
        if !dir.exists() {
            std::fs::create_dir_all(dir)?;
        }
        let store = UserStore::load(dir)?;
        if store.is_empty() {
            warn!("users_dir is set but no *.key files found - no one can authenticate");
        }
        info!("Multi-user mode: {} user(s) from {users_dir}", store.len());
        AuthMode::MultiUser(store)
    } else {
        let psk = load_psk(&config.psk_file)?;
        info!("Single PSK mode (loaded from {})", config.psk_file);
        AuthMode::SinglePsk(PskAuthenticator::new(psk))
    };

    #[cfg(feature = "acme")]
    let _acme_task: Option<tokio::task::JoinHandle<()>>;

    let rustls_config = if let Some(ref domain) = config.domain {
        #[cfg(feature = "acme")]
        {
            let (resolver, task) = redpill_quic::acme::AcmeCertResolver::new(
                domain.clone(),
                config.acme_dir.clone(),
                config.acme_email.clone(),
            )
            .await?;
            _acme_task = Some(task);
            info!("ACME autocert enabled for domain {domain}");

            let mut cfg = rustls::ServerConfig::builder()
                .with_no_client_auth()
                .with_cert_resolver(Arc::new(resolver));
            cfg.alpn_protocols = vec![ALPN_VPN.to_vec(), ALPN_H3.to_vec()];
            cfg.max_early_data_size = u32::MAX;
            cfg
        }
        #[cfg(not(feature = "acme"))]
        {
            anyhow::bail!(
                "domain={domain} requires the 'acme' feature. \
                 Build with: cargo build --features acme"
            );
        }
    } else {
        let cert_pair = load_or_generate(&config.cert_file, &config.key_file)?;
        info!(
            "Certificate loaded from {} / {}",
            config.cert_file, config.key_file
        );

        #[cfg(feature = "acme")]
        {
            _acme_task = None;
        }

        let mut cfg = rustls::ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(vec![cert_pair.cert_der], cert_pair.key_der)?;
        cfg.alpn_protocols = vec![ALPN_VPN.to_vec(), ALPN_H3.to_vec()];
        cfg.max_early_data_size = u32::MAX;
        cfg
    };

    let mut server_config = quinn::ServerConfig::with_crypto(Arc::new(
        quinn::crypto::rustls::QuicServerConfig::try_from(rustls_config)?,
    ));
    let transport = build_transport_config();
    server_config.transport_config(Arc::new(transport));

    let addr: SocketAddr = config.listen.parse()?;
    let socket = std::net::UdpSocket::bind(addr)?;
    let sock2 = socket2::Socket::from(socket);
    sock2.set_recv_buffer_size(4 * 1024 * 1024)?;
    sock2.set_send_buffer_size(4 * 1024 * 1024)?;

    // XDP: try to attach BPF filter for conntrack bypass (Linux + xdp feature)
    #[cfg(all(target_os = "linux", feature = "xdp"))]
    {
        match redpill_quic::xdp::attach_bpf_filter(&sock2) {
            Ok(true) => info!("XDP kernel bypass attached"),
            Ok(false) => info!("XDP kernel bypass not available (non-critical)"),
            Err(e) => warn!("XDP attach failed (non-critical): {e}"),
        }
        if let Err(e) = redpill_quic::xdp::tune_socket(&sock2) {
            warn!("XDP socket tuning failed: {e}");
        }
    }

    let socket: std::net::UdpSocket = sock2.into();

    let endpoint = quinn::Endpoint::new(
        quinn::EndpointConfig::default(),
        Some(server_config),
        socket,
        quinn::default_runtime().unwrap(),
    )?;
    info!("QUIC endpoint listening on {}", config.listen);

    let tun = TunDevice::create(&config.tun_name)?;
    info!("TUN device: {}", tun.name());
    tun.set_mtu(config.mtu)?;

    let server_ip: Ipv4Addr = config.tun_address.parse()?;
    route::configure_interface(tun.name(), server_ip, config.tun_prefix_len)?;
    info!(
        "TUN configured: {}/{}",
        config.tun_address, config.tun_prefix_len
    );

    route::enable_ip_forwarding()?;
    let subnet = format!(
        "{}/{}",
        crate::subnet_from_config(&config),
        config.tun_prefix_len
    );
    if config.nat.enabled {
        route::setup_nat(&subnet, &config.nat.interface)?;
        info!("NAT enabled on {}", config.nat.interface);
    }

    route::setup_mss_clamping(tun.name(), config.mtu)?;
    info!(
        "MSS clamping: {} (mtu {} -> mss {})",
        tun.name(),
        config.mtu,
        config.mtu as i32 - 60
    );

    route::configure_tun_performance(tun.name(), 10000);

    let base_ip: Ipv4Addr = subnet_from_config(&config).parse()?;
    let dns_ip: Ipv4Addr = config.dns.parse()?;
    let router = Arc::new(ClientRouter::new());
    let shaper = Arc::new(AdaptiveShaper::new(config.max_bandwidth_mbps));
    let prom_metrics = Arc::new(Metrics::new());
    let state = Arc::new(ServerState {
        auth: parking_lot::RwLock::new(auth_mode),
        ip_pool: parking_lot::Mutex::new(IpPool::new(base_ip)),
        active_connections: AtomicU32::new(0),
        max_connections: AtomicU32::new(config.max_connections),
        cancel: CancellationToken::new(),
        mtu: config.mtu,
        server_ip,
        dns_ip,
        decoy_enabled: config.decoy.enabled,
        decoy_page: parking_lot::RwLock::new(config.decoy.page.clone()),
        router: router.clone(),
        shaper: shaper.clone(),
        metrics: prom_metrics.clone(),
        config_path: cli.config.clone(),
    });

    let metrics_addr: SocketAddr = config.metrics_listen.parse()?;
    let metrics_task = metrics::spawn_metrics_server(metrics_addr, prom_metrics.clone());

    let cancel = state.cancel.clone();
    tokio::spawn(async move {
        tokio::signal::ctrl_c().await.ok();
        info!("Shutdown signal received");
        cancel.cancel();
    });

    let tun_fd = tun.raw_fd();
    let tun_reader_router = router.clone();
    let tun_reader_cancel = state.cancel.clone();
    let tun_reader_limiter = shaper.clone();
    let tun_reader_metrics = prom_metrics.clone();
    let tun_reader_task = tokio::spawn(async move {
        if let Err(e) = run_global_tun_reader(
            tun_fd,
            tun_reader_router,
            tun_reader_cancel,
            tun_reader_limiter,
            tun_reader_metrics,
        )
        .await
        {
            error!("Global TUN reader exited: {e}");
        }
    });

    let tcp_reality_task = if config.reality.enabled {
        let tcp_addr: SocketAddr = config.reality.listen.parse()?;

        let cert_pair_tcp = load_or_generate(&config.cert_file, &config.key_file)?;
        let mut tcp_tls_config = rustls::ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(vec![cert_pair_tcp.cert_der], cert_pair_tcp.key_der)?;
        tcp_tls_config.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];

        info!("TCP Reality listening on {tcp_addr}");

        let tls_acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(tcp_tls_config));
        let tcp_state = state.clone();
        let reality_target = config.reality.target.clone();
        let tcp_tun_fd = tun.raw_fd();

        Some(tokio::spawn(async move {
            run_tcp_reality_listener(
                tcp_addr,
                tls_acceptor,
                tcp_state,
                reality_target,
                tcp_tun_fd,
            )
            .await;
        }))
    } else {
        None
    };

    let ws_task = if config.websocket.enabled {
        let ws_addr: SocketAddr = config.websocket.listen.parse()?;
        let ws_state = state.clone();
        let ws_tun_fd = tun.raw_fd();

        Some(tokio::spawn(async move {
            run_ws_listener(ws_addr, ws_state, ws_tun_fd).await;
        }))
    } else {
        None
    };

    let mut sighup = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::hangup())?;

    info!("Waiting for connections...");
    loop {
        tokio::select! {
            _ = state.cancel.cancelled() => {
                info!("Accept loop cancelled, draining...");
                break;
            }
            _ = sighup.recv() => {
                reload_config(&state);
                continue;
            }
            incoming = endpoint.accept() => {
                let Some(incoming) = incoming else {
                    break;
                };

                let current = state.active_connections.load(Ordering::Relaxed);
                let max = state.max_connections.load(Ordering::Relaxed);
                if current >= max {
                    warn!("Connection limit reached ({}/{}), refusing", current, max);
                    incoming.refuse();
                    continue;
                }

                let tun_fd = tun.raw_fd();
                let state = state.clone();
                tokio::spawn(async move {
                    handle_incoming(incoming, tun_fd, state).await;
                });
            }
        }
    }

    endpoint.close(quinn::VarInt::from_u32(0), b"server shutdown");
    info!("Endpoint closed, waiting for connections to drain...");
    endpoint.wait_idle().await;
    tun_reader_task.abort();
    if let Some(t) = tcp_reality_task {
        t.abort();
    }
    if let Some(t) = ws_task {
        t.abort();
    }
    metrics_task.abort();

    #[cfg(all(target_os = "linux", feature = "xdp"))]
    {
        redpill_quic::xdp::cleanup_notrack_iptables();
        info!("XDP NOTRACK rules removed");
    }
    if config.nat.enabled {
        route::cleanup_nat(&subnet, &config.nat.interface)?;
    }
    route::cleanup_mss_clamping(tun.name(), config.mtu);
    info!("Cleanup complete, exiting");

    Ok(())
}

/// Global TUN reader: reads packets from TUN and routes to the correct client.
async fn run_global_tun_reader(
    tun_fd: i32,
    router: Arc<ClientRouter>,
    cancel: CancellationToken,
    shaper: Arc<AdaptiveShaper>,
    metrics: Arc<Metrics>,
) -> anyhow::Result<()> {
    let async_fd =
        AsyncFd::new(unsafe { std::os::fd::BorrowedFd::borrow_raw(tun_fd) }.try_clone_to_owned()?)?;

    // macOS utun prepends 4-byte AF header on read; Linux gives raw IP
    #[cfg(target_os = "macos")]
    const TUN_HDR: usize = 4;
    #[cfg(not(target_os = "macos"))]
    const TUN_HDR: usize = 0;

    let mut tun_buf = vec![0u8; TUN_MTU as usize + 4];
    loop {
        tokio::select! {
            _ = cancel.cancelled() => return Ok(()),
            guard_result = async_fd.readable() => {
                let mut guard = guard_result?;
                let mut batch = 0;
                loop {
                    let n = match nix::unistd::read(async_fd.as_raw_fd(), &mut tun_buf) {
                        Ok(n) if n > TUN_HDR => n,
                        Ok(_) => break,
                        Err(nix::errno::Errno::EAGAIN) => {
                            guard.clear_ready();
                            break;
                        }
                        Err(e) => return Err(e.into()),
                    };

                    let ip_pkt = &tun_buf[TUN_HDR..n];

                    if !shaper.check(ip_pkt.len()) {
                        metrics.drops_rate_limit.inc();
                        batch += 1;
                        if batch >= MAX_TUN_BATCH {
                            break;
                        }
                        continue;
                    }

                    if let Some(dst_ip) = extract_dst_ipv4(ip_pkt) {
                        if !router.route(dst_ip, Bytes::copy_from_slice(ip_pkt)) {
                            metrics.drops_backpressure.inc();
                        }
                    }
                    // Non-IPv4 packets (IPv6, etc.) are dropped - no IPv6 pool yet

                    batch += 1;
                    if batch >= MAX_TUN_BATCH {
                        break;
                    }
                }
            }
        }
    }
}

async fn handle_incoming(incoming: quinn::Incoming, tun_fd: i32, state: Arc<ServerState>) {
    let conn = match incoming.await {
        Ok(conn) => conn,
        Err(e) => {
            error!("Accept error: {e}");
            return;
        }
    };

    let remote = conn.remote_address();
    info!("Connection from {remote}");

    let alpn = conn
        .handshake_data()
        .and_then(|hd| hd.downcast::<quinn::crypto::rustls::HandshakeData>().ok())
        .and_then(|hd| hd.protocol.clone());

    match alpn.as_deref() {
        Some(ALPN_VPN) => {
            handle_vpn(conn, tun_fd, state).await;
        }
        Some(b"h3") => {
            // Camouflaged VPN clients open a bi-stream for auth (first byte 0x01).
            // HTTP/3 probes open uni-streams for H3 settings frames.
            // Race: if bi-stream arrives within 2s → VPN client.
            match tokio::time::timeout(std::time::Duration::from_secs(2), conn.accept_bi()).await {
                Ok(Ok((send, recv))) => {
                    // Got a bi-stream - attempt VPN auth (with padding enabled)
                    handle_vpn_h3(conn, send, recv, tun_fd, state).await;
                }
                _ => {
                    // No bi-stream → HTTP/3 decoy probe
                    if state.decoy_enabled {
                        let page = state.decoy_page.read().clone();
                        redpill_quic::decoy::handle_http3(conn, &page).await;
                    } else {
                        conn.close(quinn::VarInt::from_u32(0x02), b"unknown");
                    }
                }
            }
        }
        other => {
            let alpn_str = other
                .map(|b| String::from_utf8_lossy(b).to_string())
                .unwrap_or_else(|| "none".into());
            warn!("Unknown ALPN from {remote}: {alpn_str}");
            conn.close(quinn::VarInt::from_u32(0x02), b"unknown ALPN");
        }
    }
}

async fn handle_vpn(conn: quinn::Connection, tun_fd: i32, state: Arc<ServerState>) {
    let remote = conn.remote_address();

    state.active_connections.fetch_add(1, Ordering::Relaxed);
    let _conn_guard = ConnectionGuard {
        counter: &state.active_connections,
    };

    let (mut send, mut recv) = match conn.accept_bi().await {
        Ok(streams) => streams,
        Err(e) => {
            error!("[{remote}] Failed to accept control stream: {e}");
            return;
        }
    };

    let mut auth_buf = vec![0u8; redpill_quic::control::CLIENT_AUTH_LEN];
    if let Err(e) = recv.read_exact(&mut auth_buf).await {
        error!("[{remote}] Failed to read auth: {e}");
        conn.close(ERR_AUTH_FAILED, b"auth read error");
        return;
    }

    let client_auth = match ClientAuth::decode(&auth_buf) {
        Some(auth) => auth,
        None => {
            warn!("[{remote}] Malformed auth message");
            conn.close(ERR_AUTH_FAILED, b"malformed auth");
            return;
        }
    };

    state.metrics.handshakes_total.inc();
    let username = match state
        .auth
        .read()
        .verify(&client_auth.nonce, &client_auth.mac)
    {
        Some(name) => name,
        None => {
            warn!("[{remote}] Auth failed: invalid PSK");
            state.metrics.handshakes_failed.inc();
            conn.close(ERR_AUTH_FAILED, b"auth failed");
            return;
        }
    };
    info!(
        "[{remote}] Authenticated as '{username}' (version {})",
        client_auth.version
    );
    state.metrics.active_sessions.inc();
    state
        .metrics
        .sessions_by_user
        .with_label_values(&[&username])
        .inc();
    let _session_guard = SessionGuard {
        metrics: state.metrics.clone(),
        username: username.clone(),
    };

    let client_ip = match state.ip_pool.lock().allocate() {
        Some(ip) => ip,
        None => {
            error!("[{remote}] IP pool exhausted");
            conn.close(quinn::VarInt::from_u32(0x03), b"ip pool exhausted");
            return; // SessionGuard::drop will dec metrics
        }
    };
    info!("[{remote}] Assigned IP: {client_ip}");

    let (_client_handle, client_queue) = state.router.register(client_ip, CLIENT_CHANNEL_SIZE);

    let session_config = SessionConfig {
        client_ip,
        server_ip: state.server_ip,
        dns_ip: state.dns_ip,
        mtu: state.mtu as u16,
        keepalive_secs: 10,
        flags: redpill_quic::batch::flags::BATCHING,
    };
    if let Err(e) = send.write_all(&session_config.encode()).await {
        error!("[{remote}] Failed to send session config: {e}");
        state.ip_pool.lock().release(client_ip);
        return; // SessionGuard::drop will dec metrics
    }
    // Don't call send.finish() - keep control stream open for SessionUpdate messages

    let pmtu_conn = conn.clone();
    let pmtu_remote = remote;
    let pmtu_task = tokio::spawn(async move {
        run_pmtu_monitor(pmtu_conn, send, pmtu_remote).await;
    });

    if let Err(e) = run_vpn_tunnel(&conn, tun_fd, client_ip, client_queue, &state, false).await {
        info!("[{remote}] Tunnel ended: {e}");
    }
    pmtu_task.abort();

    state.ip_pool.lock().release(client_ip);
    info!("[{remote}] Disconnected ({username}), released IP {client_ip}");
}

/// Handle a camouflaged VPN client that connected with h3 ALPN.
/// Padding is enabled for both send and receive paths.
async fn handle_vpn_h3(
    conn: quinn::Connection,
    mut send: quinn::SendStream,
    mut recv: quinn::RecvStream,
    tun_fd: i32,
    state: Arc<ServerState>,
) {
    let remote = conn.remote_address();

    state.active_connections.fetch_add(1, Ordering::Relaxed);
    let _conn_guard = ConnectionGuard {
        counter: &state.active_connections,
    };

    let mut auth_buf = vec![0u8; redpill_quic::control::CLIENT_AUTH_LEN];
    if let Err(e) = recv.read_exact(&mut auth_buf).await {
        error!("[{remote}] h3-vpn: Failed to read auth: {e}");
        conn.close(ERR_AUTH_FAILED, b"auth read error");
        return;
    }

    let client_auth = match ClientAuth::decode(&auth_buf) {
        Some(auth) => auth,
        None => {
            warn!("[{remote}] h3-vpn: Malformed auth message");
            conn.close(ERR_AUTH_FAILED, b"malformed auth");
            return;
        }
    };

    state.metrics.handshakes_total.inc();
    let username = match state
        .auth
        .read()
        .verify(&client_auth.nonce, &client_auth.mac)
    {
        Some(name) => name,
        None => {
            warn!("[{remote}] h3-vpn: Auth failed: invalid PSK");
            state.metrics.handshakes_failed.inc();
            conn.close(ERR_AUTH_FAILED, b"auth failed");
            return;
        }
    };
    info!(
        "[{remote}] h3-vpn: Authenticated as '{username}' (version {})",
        client_auth.version
    );
    state.metrics.active_sessions.inc();
    state
        .metrics
        .sessions_by_user
        .with_label_values(&[&username])
        .inc();
    let _session_guard = SessionGuard {
        metrics: state.metrics.clone(),
        username: username.clone(),
    };

    let client_ip = match state.ip_pool.lock().allocate() {
        Some(ip) => ip,
        None => {
            error!("[{remote}] h3-vpn: IP pool exhausted");
            conn.close(quinn::VarInt::from_u32(0x03), b"ip pool exhausted");
            return; // SessionGuard::drop will dec metrics
        }
    };
    info!("[{remote}] h3-vpn: Assigned IP: {client_ip}");

    let (_client_handle, client_queue) = state.router.register(client_ip, CLIENT_CHANNEL_SIZE);

    let session_config = SessionConfig {
        client_ip,
        server_ip: state.server_ip,
        dns_ip: state.dns_ip,
        mtu: state.mtu as u16,
        keepalive_secs: 10,
        flags: redpill_quic::batch::flags::BATCHING,
    };
    if let Err(e) = send.write_all(&session_config.encode()).await {
        error!("[{remote}] h3-vpn: Failed to send session config: {e}");
        state.ip_pool.lock().release(client_ip);
        return; // SessionGuard::drop will dec metrics
    }

    let pmtu_conn = conn.clone();
    let pmtu_remote = remote;
    let pmtu_task = tokio::spawn(async move {
        run_pmtu_monitor(pmtu_conn, send, pmtu_remote).await;
    });

    if let Err(e) = run_vpn_tunnel(&conn, tun_fd, client_ip, client_queue, &state, true).await {
        info!("[{remote}] h3-vpn: Tunnel ended: {e}");
    }
    pmtu_task.abort();

    state.ip_pool.lock().release(client_ip);
    info!("[{remote}] h3-vpn: Disconnected ({username}), released IP {client_ip}");
}

/// Monitor PMTU changes and send SessionUpdate messages over the control stream.
/// Checks every 5s, sends update if MTU changes by >50 bytes.
async fn run_pmtu_monitor(
    conn: quinn::Connection,
    mut send: quinn::SendStream,
    remote: SocketAddr,
) {
    use redpill_quic::control::SessionUpdate;

    let mut last_mtu: u16 = conn.stats().path.current_mtu;
    let mut interval = tokio::time::interval(std::time::Duration::from_secs(5));
    interval.tick().await; // skip initial tick

    loop {
        interval.tick().await;
        let current_mtu = conn.stats().path.current_mtu;

        // Only send update if change is significant (>50 bytes)
        let delta = (current_mtu as i32 - last_mtu as i32).unsigned_abs();
        if delta > 50 {
            info!("[{remote}] PMTU changed: {last_mtu} → {current_mtu}");
            let update = SessionUpdate { mtu: current_mtu };
            if let Err(e) = send.write_all(&update.encode()).await {
                // Old clients close their recv stream → write fails silently
                info!("[{remote}] PMTU update write failed (client may not support): {e}");
                return;
            }
            last_mtu = current_mtu;
        }
    }
}

async fn run_vpn_tunnel(
    conn: &quinn::Connection,
    tun_fd: i32,
    client_ip: Ipv4Addr,
    client_queue: Arc<PriorityQueue>,
    state: &ServerState,
    padded: bool,
) -> anyhow::Result<()> {
    let stats = Arc::new(Stats::new());
    let stats_report = stats.clone();
    let conn_stats = conn.clone();
    let cancel = state.cancel.clone();

    let stats_task = tokio::spawn(async move {
        let mut interval = tokio::time::interval(STATS_INTERVAL);
        loop {
            interval.tick().await;
            stats_report.report(&conn_stats);
        }
    });

    let shaper = state.shaper.clone();
    let conn_rtt = conn.clone();
    let rtt_metrics = state.metrics.clone();
    let rtt_task = tokio::spawn(async move {
        let mut interval = tokio::time::interval(std::time::Duration::from_millis(100));
        loop {
            interval.tick().await;
            let rtt = conn_rtt.stats().path.rtt;
            shaper.update_rtt(rtt);
            rtt_metrics.rtt_ms.observe(rtt.as_secs_f64() * 1000.0);
        }
    });

    // PriorityQueue → DATAGRAM task (packets from global TUN reader → QUIC to client)
    // Uses batching for small packets (<300B) to reduce per-datagram overhead.
    // Backpressure: bulk uses send_datagram_wait (blocks until space), realtime checks space first.
    let conn_send = conn.clone();
    let stats_send = stats.clone();
    let send_metrics = state.metrics.clone();
    let send_padded = padded;
    let queue2dg_task: tokio::task::JoinHandle<anyhow::Result<()>> = tokio::spawn(async move {
        use redpill_quic::batch::{DatagramBatcher, BATCH_SIZE_THRESHOLD};

        let mut batcher = DatagramBatcher::new();
        let flush_interval = tokio::time::Duration::from_millis(1);

        /// Send via instant send_datagram (realtime path or batched).
        fn send_rt(
            conn: &quinn::Connection,
            data: Bytes,
            stats: &Stats,
            metrics: &Metrics,
        ) -> Result<(), quinn::ConnectionError> {
            let size = data.len();
            match conn.send_datagram(data) {
                Ok(()) => {
                    stats.record_send(size);
                    metrics.datagrams_out.inc();
                    metrics.bytes_out.inc_by(size as u64);
                    Ok(())
                }
                Err(SendDatagramError::TooLarge) => {
                    stats.record_too_large();
                    Ok(())
                }
                Err(SendDatagramError::ConnectionLost(e)) => Err(e),
                Err(_e) => {
                    stats.record_blocked();
                    metrics.drops_backpressure.inc();
                    Ok(())
                }
            }
        }

        /// Send bulk: fast path via send_datagram when space available,
        /// slow path via send_datagram_wait when congested.
        async fn send_bulk(
            conn: &quinn::Connection,
            data: Bytes,
            stats: &Stats,
            metrics: &Metrics,
        ) -> Result<(), quinn::ConnectionError> {
            let size = data.len();
            // Fast path: buffer has space → instant send (no async overhead)
            if conn.datagram_send_buffer_space() >= size {
                return send_rt(conn, data, stats, metrics);
            }
            // Pre-check: if packet exceeds max_datagram_size, drop it immediately
            // to avoid waiting forever (quinn#2456).
            if let Some(max_dg) = conn.max_datagram_size() {
                if size > max_dg {
                    stats.record_too_large();
                    return Ok(());
                }
            }
            // Slow path: wait for space with timeout
            metrics.bp_wait_count.inc();
            match tokio::time::timeout(DATAGRAM_WAIT_TIMEOUT, conn.send_datagram_wait(data)).await {
                Ok(Ok(())) => {
                    stats.record_send(size);
                    metrics.datagrams_out.inc();
                    metrics.bytes_out.inc_by(size as u64);
                    Ok(())
                }
                Ok(Err(SendDatagramError::TooLarge)) => {
                    stats.record_too_large();
                    Ok(())
                }
                Ok(Err(SendDatagramError::ConnectionLost(e))) => Err(e),
                Ok(Err(_e)) => {
                    stats.record_blocked();
                    metrics.drops_backpressure.inc();
                    Ok(())
                }
                Err(_timeout) => {
                    // Wait timed out - drop packet, no leak (Bytes inside future is freed)
                    metrics.bp_wait_timeouts.inc();
                    stats.record_blocked();
                    Ok(())
                }
            }
        }

        loop {
            let packet = if batcher.has_pending() {
                tokio::select! {
                    pkt = client_queue.pop() => pkt,
                    _ = tokio::time::sleep(flush_interval) => {
                        // Flush timeout - batched packets are always small/realtime class
                        let batch = batcher.flush();
                        if !batch.is_empty() {
                            send_rt(&conn_send, batch, &stats_send, &send_metrics)
                                .map_err(|e| -> anyhow::Error { e.into() })?;
                        }
                        continue;
                    }
                }
            } else {
                client_queue.pop().await
            };

            let packet = if send_padded {
                Bytes::from(redpill_quic::padding::pad_to_standard(&packet))
            } else {
                packet
            };

            if packet.len() >= BATCH_SIZE_THRESHOLD {
                let batch = batcher.flush();
                if !batch.is_empty() {
                    send_rt(&conn_send, batch, &stats_send, &send_metrics)
                        .map_err(|e| -> anyhow::Error { e.into() })?;
                }

                match classify(&packet) {
                    Priority::Realtime => {
                        // Check space before sending to avoid evicting older datagrams
                        if conn_send.datagram_send_buffer_space() >= packet.len() {
                            send_rt(&conn_send, packet, &stats_send, &send_metrics)
                                .map_err(|e| -> anyhow::Error { e.into() })?;
                        } else {
                            // Buffer congested - drop realtime rather than evict
                            send_metrics.bp_rt_drops_congested.inc();
                            stats_send.record_blocked();
                        }
                    }
                    Priority::Bulk => {
                        send_bulk(&conn_send, packet, &stats_send, &send_metrics)
                            .await
                            .map_err(|e| -> anyhow::Error { e.into() })?;
                    }
                }
            } else {
                // Small packet - always realtime class, batch it
                // Batched sends use send_rt (instant, with space check for the batch)
                if let Some(batch) = batcher.add(packet) {
                    send_rt(&conn_send, batch, &stats_send, &send_metrics)
                        .map_err(|e| -> anyhow::Error { e.into() })?;
                }
            }
        }
    });

    let recv_metrics = state.metrics.clone();
    let dg2tun_result: anyhow::Result<()> = async {
        loop {
            tokio::select! {
                _ = cancel.cancelled() => {
                    return Ok(());
                }
                result = conn.read_datagram() => {
                    match result {
                        Ok(data) => {
                            if data.is_empty() {
                                continue;
                            }
                            let data_len = data.len();
                            stats.record_recv(data_len);
                            recv_metrics.datagrams_in.inc();
                            recv_metrics.bytes_in.inc_by(data_len as u64);

                            if padded {
                                let version_nibble = data[0] >> 4;
                                if version_nibble != 4 && version_nibble != 6 {
                                    continue;
                                }
                                let stripped = redpill_quic::padding::strip_padding(&data);
                                if !validate_source_ip(stripped, client_ip) {
                                    stats.record_spoofed();
                                    recv_metrics.spoofed.inc();
                                    continue;
                                }
                                if !state.shaper.check(stripped.len()) {
                                    recv_metrics.drops_rate_limit.inc();
                                    continue;
                                }
                                if write_to_tun(tun_fd, stripped).is_ok() {
                                    stats.tun_writes.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                                }
                            } else {
                                if !validate_source_ip(&data, client_ip) {
                                    stats.record_spoofed();
                                    recv_metrics.spoofed.inc();
                                    continue;
                                }
                                if !state.shaper.check(data_len) {
                                    recv_metrics.drops_rate_limit.inc();
                                    continue;
                                }
                                if write_to_tun(tun_fd, &data).is_ok() {
                                    stats.tun_writes.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                                }
                            }
                        }
                        Err(e) => {
                            return Err(e.into());
                        }
                    }
                }
            }
        }
    }
    .await;

    queue2dg_task.abort();
    stats_task.abort();
    rtt_task.abort();
    stats.report(conn);

    dg2tun_result
}

/// RAII guard to decrement connection count on drop.
struct ConnectionGuard<'a> {
    counter: &'a AtomicU32,
}

impl Drop for ConnectionGuard<'_> {
    fn drop(&mut self) {
        self.counter.fetch_sub(1, Ordering::Relaxed);
    }
}

/// RAII guard to decrement session metrics on drop (prevents stale counters on hard kill).
struct SessionGuard {
    metrics: Arc<crate::metrics::Metrics>,
    username: String,
}

impl Drop for SessionGuard {
    fn drop(&mut self) {
        self.metrics.active_sessions.dec();
        self.metrics
            .sessions_by_user
            .with_label_values(&[&self.username])
            .dec();
    }
}

/// Reload configuration from disk on SIGHUP.
///
/// Reloadable fields: max_connections, max_bandwidth_mbps, log_level, decoy page, PSK.
/// Not reloadable: listen addr, TUN config, certs (need endpoint rebuild).
fn reload_config(state: &ServerState) {
    info!(
        "SIGHUP received, reloading config from {}",
        state.config_path
    );

    let config = match ServerConfig::load(&state.config_path) {
        Ok(c) => c,
        Err(e) => {
            error!("Failed to reload config: {e}");
            return;
        }
    };

    let old_max = state.max_connections.load(Ordering::Relaxed);
    if config.max_connections != old_max {
        state
            .max_connections
            .store(config.max_connections, Ordering::Relaxed);
        info!("max_connections: {old_max} → {}", config.max_connections);
    }

    {
        let mut page = state.decoy_page.write();
        if *page != config.decoy.page {
            info!("decoy page: {} → {}", *page, config.decoy.page);
            *page = config.decoy.page.clone();
        }
    }

    if let Some(ref users_dir) = config.users_dir {
        let dir = std::path::Path::new(users_dir);
        match UserStore::load(dir) {
            Ok(store) => {
                let count = store.len();
                *state.auth.write() = AuthMode::MultiUser(store);
                info!("User store reloaded: {count} user(s) from {users_dir}");
            }
            Err(e) => {
                warn!("Failed to reload user store: {e}");
            }
        }
    } else {
        match load_psk(&config.psk_file) {
            Ok(new_psk) => {
                *state.auth.write() = AuthMode::SinglePsk(PskAuthenticator::new(new_psk));
                info!("PSK reloaded from {}", config.psk_file);
            }
            Err(e) => {
                warn!("Failed to reload PSK: {e}");
            }
        }
    }

    // Reload log level
    // Note: tracing-subscriber doesn't support dynamic level changes easily.
    // We log the configured level for awareness.
    info!(
        "Reload complete (log_level in config: {})",
        config.log_level
    );
}

/// Run TCP Reality VPN tunnel using the global TUN reader's ClientRouter.
///
/// Packets from the internet arrive via the global TUN reader → ClientRouter → queue.
/// We batch-drain the queue and flush to TLS in bulk for high throughput.
async fn run_tcp_reality_tunnel(
    stream: tokio_rustls::server::TlsStream<tokio::net::TcpStream>,
    tun_fd: i32,
    client_ip: std::net::Ipv4Addr,
    client_queue: Arc<PriorityQueue>,
    state: &ServerState,
) -> anyhow::Result<()> {
    use tokio::io::{AsyncReadExt, AsyncWriteExt, BufWriter};

    stream.get_ref().0.set_nodelay(true)?;

    let (tls_read, tls_write) = tokio::io::split(stream);
    // BufReader reduces tokio::io::split mutex acquisitions: one underlying
    // TLS read (64KB) serves ~53 packets from cache instead of locking per read_exact.
    let mut tls_read = tokio::io::BufReader::with_capacity(64 * 1024, tls_read);
    let cancel = state.cancel.clone();

    // Queue → TLS: write packets to BufWriter, let it auto-flush at 64KB.
    // For idle periods, a 1ms timeout triggers manual flush so data doesn't sit buffered.
    // At 85 Mbps (~8800 pps × 1200B), the 64KB buffer fills every ~6ms → auto-flush ~170×/sec.
    let queue2tls_task: tokio::task::JoinHandle<anyhow::Result<()>> = tokio::spawn(async move {
        let mut buf_writer = BufWriter::with_capacity(64 * 1024, tls_write);
        let mut frame_buf = Vec::with_capacity(2 + 1400);
        let flush_interval = std::time::Duration::from_millis(1);
        let mut needs_flush = false;

        loop {
            // Wait for packet or flush timeout (whichever comes first)
            let packet = if needs_flush {
                tokio::select! {
                    biased;
                    packet = client_queue.pop() => packet,
                    _ = tokio::time::sleep(flush_interval) => {
                        buf_writer.flush().await?;
                        needs_flush = false;
                        continue;
                    }
                }
            } else {
                client_queue.pop().await
            };

            frame_buf.clear();
            frame_buf.extend_from_slice(&(packet.len() as u16).to_be_bytes());
            frame_buf.extend_from_slice(&packet);
            buf_writer.write_all(&frame_buf).await?;
            needs_flush = true;

            while let Some(packet) = client_queue.try_pop() {
                frame_buf.clear();
                frame_buf.extend_from_slice(&(packet.len() as u16).to_be_bytes());
                frame_buf.extend_from_slice(&packet);
                buf_writer.write_all(&frame_buf).await?;
            }
            // No explicit flush - BufWriter auto-flushes at capacity.
            // Idle flush handled by the select! timeout above.
        }
    });

    // TLS → TUN: read length-framed packets, validate, write to TUN.
    // Uses BufReader implicitly via tokio's read buffering.
    let tls2tun_result: anyhow::Result<()> = async {
        let mut len_buf = [0u8; 2];
        let mut pkt_buf = vec![0u8; 1500];
        loop {
            tokio::select! {
                _ = cancel.cancelled() => return Ok(()),
                result = tls_read.read_exact(&mut len_buf) => {
                    result?;
                    let len = u16::from_be_bytes(len_buf) as usize;
                    if len == 0 || len > 65535 {
                        anyhow::bail!("invalid frame length: {len}");
                    }
                    if len > pkt_buf.len() {
                        pkt_buf.resize(len, 0);
                    }
                    tls_read.read_exact(&mut pkt_buf[..len]).await?;
                    if !validate_source_ip(&pkt_buf[..len], client_ip) {
                        continue;
                    }
                    if !state.shaper.check(len) {
                        continue;
                    }
                    let _ = write_to_tun(tun_fd, &pkt_buf[..len]);
                }
            }
        }
    }
    .await;

    queue2tls_task.abort();
    tls2tun_result
}

/// TCP Reality accept loop: listens for TCP connections, handles TLS, routes to VPN or proxy.
async fn run_tcp_reality_listener(
    addr: SocketAddr,
    tls_acceptor: tokio_rustls::TlsAcceptor,
    state: Arc<ServerState>,
    target: String,
    tun_fd: i32,
) {
    let listener = match tokio::net::TcpListener::bind(addr).await {
        Ok(l) => l,
        Err(e) => {
            error!("Failed to bind TCP Reality listener on {addr}: {e}");
            return;
        }
    };
    info!("TCP Reality listening on {addr} (target: {target})");

    loop {
        tokio::select! {
            _ = state.cancel.cancelled() => break,
            result = listener.accept() => {
                let (stream, remote) = match result {
                    Ok(s) => s,
                    Err(e) => {
                        error!("TCP accept error: {e}");
                        continue;
                    }
                };

                info!("[{remote}] TCP connection (Reality)");

                let tls_acceptor = tls_acceptor.clone();
                let state = state.clone();
                let target = target.clone();
                tokio::spawn(async move {
                    let auth_snapshot = state.auth.read().clone();
                    let auth_ref: &dyn redpill_quic::auth::Authenticator = match &auth_snapshot {
                        AuthMode::SinglePsk(a) => a,
                        AuthMode::MultiUser(s) => s,
                    };
                    let reality_config = redpill_quic::reality::RealityConnectionConfig {
                        tls_acceptor,
                        auth: auth_ref,
                        pool: &state.ip_pool,
                        server_ip: state.server_ip,
                        dns_ip: state.dns_ip,
                        mtu: state.mtu,
                        target: &target,
                    };
                    let result = redpill_quic::reality::handle_tcp_connection(
                        stream,
                        &reality_config,
                    )
                    .await;

                    match result {
                        redpill_quic::reality::RealityResult::Vpn { client_ip, username, stream } => {
                            state.active_connections.fetch_add(1, Ordering::Relaxed);
                            let _conn_guard = ConnectionGuard { counter: &state.active_connections };
                            state.metrics.active_sessions.inc();
                            state.metrics.sessions_by_user.with_label_values(&[&username]).inc();
                            let _session_guard = SessionGuard {
                                metrics: state.metrics.clone(),
                                username: username.clone(),
                            };

                            const TCP_CLIENT_CHANNEL_SIZE: usize = 4096;
                            let (_handle, client_queue) = state.router.register(client_ip, TCP_CLIENT_CHANNEL_SIZE);
                            info!("[{remote}] TCP Reality VPN tunnel started (IP: {client_ip}, user: {username})");

                            if let Err(e) = run_tcp_reality_tunnel(
                                *stream, tun_fd, client_ip, client_queue, &state,
                            ).await {
                                info!("[{remote}] TCP Reality tunnel ended: {e}");
                            }

                            state.ip_pool.lock().release(client_ip);
                            info!("[{remote}] TCP Reality disconnected ({username}), released IP {client_ip}");
                        }
                        redpill_quic::reality::RealityResult::Proxied => {
                            info!("[{remote}] TCP Reality: proxied to target");
                        }
                        redpill_quic::reality::RealityResult::Error(e) => {
                            warn!("[{remote}] TCP Reality error: {e}");
                        }
                    }
                });
            }
        }
    }
}

/// WebSocket accept loop: listens for WebSocket connections (behind CDN reverse proxy).
async fn run_ws_listener(addr: SocketAddr, state: Arc<ServerState>, tun_fd: i32) {
    let listener = match tokio::net::TcpListener::bind(addr).await {
        Ok(l) => l,
        Err(e) => {
            error!("Failed to bind WebSocket listener on {addr}: {e}");
            return;
        }
    };
    info!("WebSocket listener on {addr}");

    loop {
        tokio::select! {
            _ = state.cancel.cancelled() => break,
            result = listener.accept() => {
                let (stream, remote) = match result {
                    Ok(s) => s,
                    Err(e) => {
                        error!("WS accept error: {e}");
                        continue;
                    }
                };

                info!("[{remote}] WebSocket connection");
                let state = state.clone();
                tokio::spawn(async move {
                    handle_ws_connection(stream, remote, state, tun_fd).await;
                });
            }
        }
    }
}

/// Handle a single WebSocket VPN connection.
async fn handle_ws_connection(
    stream: tokio::net::TcpStream,
    remote: SocketAddr,
    state: Arc<ServerState>,
    tun_fd: i32,
) {
    use futures_util::{SinkExt, StreamExt};
    use tokio_tungstenite::tungstenite::Message;

    let mut ws = match tokio_tungstenite::accept_async(stream).await {
        Ok(ws) => ws,
        Err(e) => {
            warn!("[{remote}] WebSocket handshake failed: {e}");
            return;
        }
    };
    info!("[{remote}] WebSocket accepted");

    let auth_msg = match tokio::time::timeout(std::time::Duration::from_secs(5), ws.next()).await {
        Ok(Some(Ok(Message::Binary(data)))) => data,
        Ok(Some(Ok(_))) => {
            warn!("[{remote}] WS: expected binary auth message");
            return;
        }
        Ok(Some(Err(e))) => {
            warn!("[{remote}] WS: read error: {e}");
            return;
        }
        Ok(None) => {
            warn!("[{remote}] WS: closed before auth");
            return;
        }
        Err(_) => {
            warn!("[{remote}] WS: auth timeout");
            return;
        }
    };

    if auth_msg.len() < redpill_quic::control::CLIENT_AUTH_LEN {
        warn!("[{remote}] WS: auth message too short");
        return;
    }

    let client_auth = match redpill_quic::control::ClientAuth::decode(&auth_msg) {
        Some(auth) => auth,
        None => {
            warn!("[{remote}] WS: malformed auth");
            return;
        }
    };

    state.metrics.handshakes_total.inc();
    let username = match state
        .auth
        .read()
        .verify(&client_auth.nonce, &client_auth.mac)
    {
        Some(name) => name,
        None => {
            warn!("[{remote}] WS: auth failed");
            state.metrics.handshakes_failed.inc();
            return;
        }
    };

    info!(
        "[{remote}] WS: authenticated as '{username}' (version {})",
        client_auth.version
    );

    let client_ip = match state.ip_pool.lock().allocate() {
        Some(ip) => ip,
        None => {
            error!("[{remote}] WS: IP pool exhausted");
            return;
        }
    };

    let session_config = redpill_quic::control::SessionConfig {
        client_ip,
        server_ip: state.server_ip,
        dns_ip: state.dns_ip,
        mtu: state.mtu as u16,
        keepalive_secs: 10,
        flags: 0, // no batching over WS
    };
    if let Err(e) = ws
        .send(Message::Binary(session_config.encode().to_vec()))
        .await
    {
        error!("[{remote}] WS: failed to send session config: {e}");
        state.ip_pool.lock().release(client_ip);
        return;
    }

    state.active_connections.fetch_add(1, Ordering::Relaxed);
    let _conn_guard = ConnectionGuard {
        counter: &state.active_connections,
    };
    state.metrics.active_sessions.inc();
    state
        .metrics
        .sessions_by_user
        .with_label_values(&[&username])
        .inc();
    let _session_guard = SessionGuard {
        metrics: state.metrics.clone(),
        username: username.clone(),
    };
    info!("[{remote}] WS VPN tunnel started (IP: {client_ip}, user: {username})");

    if let Err(e) =
        redpill_quic::transport::websocket_cdn::run_ws_vpn_tunnel(ws, tun_fd, client_ip).await
    {
        info!("[{remote}] WS tunnel ended: {e}");
    }

    state.ip_pool.lock().release(client_ip);
    info!("[{remote}] WS disconnected ({username}), released IP {client_ip}");
}

/// Derive subnet base address from config (e.g. "10.0.1.1" → "10.0.1.0").
fn subnet_from_config(config: &ServerConfig) -> String {
    let ip: Ipv4Addr = config.tun_address.parse().unwrap();
    let octets = ip.octets();
    format!("{}.{}.{}.0", octets[0], octets[1], octets[2])
}
