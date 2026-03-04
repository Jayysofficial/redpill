use std::net::SocketAddr;
#[cfg(unix)]
use std::os::fd::AsRawFd;
use std::sync::Arc;
use std::time::Duration;

use bytes::Bytes;
use clap::Parser;
#[cfg(unix)]
use tokio::io::unix::AsyncFd;
use tracing::{error, info, warn};

use redpill_quic::auth::{parse_psk_hex, PskAuthenticator};
use redpill_quic::config::ClientTomlConfig;
#[cfg(unix)]
use redpill_quic::daemon;
#[cfg(unix)]
use redpill_quic::datagram::write_to_tun;
#[cfg(unix)]
use redpill_quic::ipc;
use redpill_quic::killswitch;
use redpill_quic::stats::Stats;
use redpill_quic::transport::health::{HealthMonitor, ReconnectReason};
use redpill_quic::transport::manager::{build_transport_manager, TransportBuildConfig};
use redpill_quic::transport::{SendResult, Transport, TransportMode};
use redpill_quic::{MAX_TUN_BATCH, QUIC_PORT, STATS_INTERVAL, TUN_MTU};
use redpill_tun::device::TunDevice;
use redpill_tun::route;

const RECONNECT_MIN_DELAY: Duration = Duration::from_secs(1);
const RECONNECT_MAX_DELAY: Duration = Duration::from_secs(30);

/// How the tunnel exited - determines reconnect behavior.
enum TunnelExit {
    /// Transport error (connection lost).
    Error(anyhow::Error),
    /// Health monitor triggered reconnection (degradation or upgrade).
    HealthReconnect(ReconnectReason),
}

#[derive(Parser)]
#[command(name = "redpill-client", about = "QUIC DATAGRAM VPN client")]
struct Cli {
    /// Server address (IP:port or IP, default port 443)
    #[arg(short, long, global = true)]
    server: Option<String>,

    /// Path to server's certificate PEM
    #[arg(short, long, global = true)]
    cert: Option<String>,

    /// PSK (64 hex chars)
    #[arg(long, global = true)]
    psk: Option<String>,

    /// Path to TOML config file (CLI args override config values)
    #[arg(long, global = true)]
    config: Option<String>,

    /// Test mode: don't set up routes or kill-switch
    #[arg(long, default_value_t = false, global = true)]
    test_mode: bool,

    /// Quiet mode: suppress periodic stats output
    #[arg(short, long, default_value_t = false, global = true)]
    quiet: bool,

    #[command(subcommand)]
    command: Option<ClientCommand>,
}

#[derive(clap::Subcommand)]
enum ClientCommand {
    /// Connect in foreground (default behavior)
    Connect,
    /// Start VPN as a background daemon
    Up,
    /// Stop the background daemon
    Down,
    /// Query daemon status
    Status,
}

fn main() -> anyhow::Result<()> {
    rustls::crypto::ring::default_provider()
        .install_default()
        .ok();

    let cli = Cli::parse();

    #[cfg(target_os = "windows")]
    match cli.command {
        Some(ClientCommand::Up) | Some(ClientCommand::Down) | Some(ClientCommand::Status) => {
            anyhow::bail!("Daemon mode (up/down/status) is not supported on Windows. Use 'connect' or run without a subcommand.");
        }
        _ => {}
    }
    #[cfg(unix)]
    match cli.command {
        Some(ClientCommand::Down) => {
            return daemon::stop_daemon();
        }
        Some(ClientCommand::Status) => {
            let sock = daemon::socket_path();
            match ipc::query_status(&sock) {
                Ok(status) => {
                    println!("Redpill VPN Client");
                    println!(
                        "  Status:    {}",
                        if status.connected {
                            "connected"
                        } else {
                            "connecting..."
                        }
                    );
                    println!("  Server:    {}", status.server);
                    println!("  Transport: {}", status.transport);
                    if let Some(ref ip) = status.client_ip {
                        println!("  Client IP: {ip}");
                    }
                    println!("  Uptime:    {}s", status.uptime_secs);
                    let tx_mb = status.bytes_sent as f64 / 1_000_000.0;
                    let rx_mb = status.bytes_recv as f64 / 1_000_000.0;
                    println!("  TX: {tx_mb:.1} MB ({} pkts)", status.datagrams_sent);
                    println!("  RX: {rx_mb:.1} MB ({} pkts)", status.datagrams_recv);
                }
                Err(e) => {
                    if let Some(pid) = daemon::is_running() {
                        println!("Daemon running (pid={pid}) but IPC unavailable: {e}");
                    } else {
                        println!("No daemon running.");
                    }
                }
            }
            return Ok(());
        }
        _ => {} // Connect, Up, or None (default = connect)
    }

    let daemon_mode = matches!(cli.command, Some(ClientCommand::Up));

    #[cfg(unix)]
    if daemon_mode {
        if let Some(pid) = daemon::is_running() {
            anyhow::bail!("Daemon already running (pid={pid}). Use 'down' first.");
        }
    }

    // Daemonize BEFORE creating tokio runtime (fork is unsafe in multi-threaded processes)
    #[cfg(unix)]
    if daemon_mode {
        let log = daemon::log_path();
        println!("Starting daemon (log: {})", log.display());
        daemon::daemonize(&log)?;
    }

    // Now create tokio runtime (after fork, in the daemon child process)
    tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()?
        .block_on(async {
            tracing_subscriber::fmt()
                .with_env_filter(
                    tracing_subscriber::EnvFilter::try_from_default_env()
                        .unwrap_or_else(|_| "info".into()),
                )
                .init();

            #[cfg(unix)]
            let pid_path = daemon::pid_path();
            #[cfg(unix)]
            if daemon_mode {
                daemon::write_pid(&pid_path)?;
            }

            let result = run_client(&cli, daemon_mode).await;

            #[cfg(unix)]
            if daemon_mode {
                daemon::remove_pid(&pid_path);
                let sock = daemon::socket_path();
                let _ = std::fs::remove_file(&sock);
            }

            result
        })
}

async fn run_client(cli: &Cli, daemon_mode: bool) -> anyhow::Result<()> {
    let toml_config = if let Some(ref config_path) = cli.config {
        info!("Loading config from {config_path}");
        ClientTomlConfig::load(config_path)?
    } else {
        ClientTomlConfig::default()
    };

    let server_str = cli
        .server
        .as_deref()
        .or(toml_config.server.address.as_deref())
        .ok_or_else(|| anyhow::anyhow!("--server or config [server].address is required"))?;
    let domain = toml_config.server.domain.clone();
    let cert_path = if domain.is_some() {
        // WebPKI mode - cert pinning not needed, use dummy path
        cli.cert
            .as_deref()
            .or(toml_config.server.cert.as_deref())
            .unwrap_or("")
            .to_string()
    } else {
        cli.cert
            .as_deref()
            .or(toml_config.server.cert.as_deref())
            .ok_or_else(|| {
                anyhow::anyhow!(
                    "--cert or config [server].cert is required (or set domain for WebPKI)"
                )
            })?
            .to_string()
    };
    let psk_hex = cli
        .psk
        .as_deref()
        .or(toml_config.server.psk.as_deref())
        .ok_or_else(|| anyhow::anyhow!("--psk or config [server].psk is required"))?;

    let psk = parse_psk_hex(psk_hex)?;
    let auth = PskAuthenticator::new(psk);

    let transport_mode = &toml_config.transport.mode;
    info!("Starting VPN client (transport mode: {transport_mode})");

    let server_addr: SocketAddr = if server_str.contains(':') {
        server_str.parse()?
    } else {
        format!("{server_str}:{QUIC_PORT}").parse()?
    };
    info!("Server: {server_addr}");

    if !cli.test_mode {
        killswitch::cleanup_stale();
        route::cleanup_stale_client();
    }

    let socket = std::net::UdpSocket::bind("0.0.0.0:0")?;
    let sock2 = socket2::Socket::from(socket);
    sock2.set_recv_buffer_size(4 * 1024 * 1024)?;
    sock2.set_send_buffer_size(4 * 1024 * 1024)?;
    let socket: std::net::UdpSocket = sock2.into();

    let endpoint = quinn::Endpoint::new(
        quinn::EndpointConfig::default(),
        None,
        socket,
        quinn::default_runtime().unwrap(),
    )?;

    if domain.is_some() {
        info!(
            "WebPKI verification mode (domain: {})",
            domain.as_deref().unwrap()
        );
    }
    let manager = build_transport_manager(TransportBuildConfig {
        mode: transport_mode,
        server_addr,
        cert_path: &cert_path,
        auth: &auth,
        camouflage_config: &toml_config.camouflage,
        reality_config: &toml_config.reality,
        ws_config: &toml_config.websocket,
        endpoint: endpoint.clone(),
        domain,
    });
    info!("Available transports: {:?}", manager.available_modes());

    #[cfg(target_os = "macos")]
    let tun = TunDevice::create("utun")?;
    #[cfg(target_os = "linux")]
    let tun = TunDevice::create("tun")?;
    #[cfg(target_os = "windows")]
    let tun = TunDevice::create("Redpill VPN")?;
    let tun_name = tun.name().to_string();
    info!("TUN device: {tun_name}");
    tun.set_mtu(TUN_MTU)?;
    #[cfg(target_os = "windows")]
    let tun = std::sync::Arc::new(tun);

    let shared_stats = Arc::new(Stats::new());
    let daemon_state = Arc::new(ipc::DaemonState {
        connected: std::sync::atomic::AtomicBool::new(false),
        server: server_addr.to_string(),
        transport: parking_lot::RwLock::new("connecting".to_string()),
        client_ip: parking_lot::RwLock::new(None),
        start: std::time::Instant::now(),
        stats: shared_stats.clone(),
    });

    let ipc_task = if daemon_mode {
        let sock_path = daemon::socket_path();
        match ipc::bind_ipc_socket(&sock_path) {
            Ok(listener) => {
                info!("IPC socket bound: {}", sock_path.display());
                Some(ipc::spawn_ipc_server(listener, daemon_state.clone()))
            }
            Err(e) => {
                warn!("Failed to bind IPC socket: {e}");
                None
            }
        }
    } else {
        None
    };

    let mut routes_configured = false;
    let mut saved_routes: Option<route::SavedRoutes> = None;
    let mut killswitch_enabled = false;

    let shutdown = Arc::new(tokio::sync::Notify::new());
    {
        let shutdown = shutdown.clone();
        tokio::spawn(async move {
            shutdown_signal().await;
            shutdown.notify_waiters();
        });
    }

    let mut attempt: u32 = 0;

    loop {
        let connect_result = tokio::select! {
            _ = shutdown.notified() => {
                info!("Shutdown signal received");
                break;
            }
            result = manager.probe_and_connect() => {
                match result {
                    Ok(result) => {
                        attempt = 0;

                        let client_ip = result.session_config.client_ip;
                        let server_tunnel_ip = result.session_config.server_ip;
                        let mtu = result.session_config.mtu as u32;

                        info!(
                            "Authenticated via {}. Assigned IP: {client_ip}, server: {server_tunnel_ip}, MTU: {mtu}",
                            result.mode
                        );

                        daemon_state.connected.store(true, std::sync::atomic::Ordering::Relaxed);
                        *daemon_state.transport.write() = format!("{}", result.mode);
                        *daemon_state.client_ip.write() = Some(client_ip.to_string());

                        route::configure_client_interface(
                            &tun_name, client_ip, server_tunnel_ip, mtu as u16,
                        )?;

                        if !cli.test_mode && !routes_configured {
                            let server_real_ip = server_addr.ip().to_string();
                            // Safety: refuse to set routes if server is loopback - would deadlock
                            if server_addr.ip().is_loopback() {
                                warn!("Server is loopback - skipping route setup (would deadlock)");
                            } else {
                            let gw = route::get_default_gateway()?;
                            info!("Default gateway: {gw}");
                            let saved = route::setup_client_routes(&server_real_ip, server_tunnel_ip, &gw)?;
                            route::setup_client_dns()?;
                            saved_routes = Some(saved);
                            routes_configured = true;
                            info!("Routes + DNS configured (full tunnel)");

                            killswitch::enable(&tun_name, &server_real_ip, server_addr.port())?;
                            killswitch_enabled = true;
                            info!("Kill-switch enabled");

                            if let Ok(out) = std::process::Command::new("ifconfig").arg(&tun_name).output() {
                                info!("ifconfig {}:\n{}", tun_name, String::from_utf8_lossy(&out.stdout));
                            }
                            if let Ok(out) = std::process::Command::new("netstat").args(["-rn", "-f", "inet"]).output() {
                                let routes: String = String::from_utf8_lossy(&out.stdout)
                                    .lines()
                                    .filter(|l| l.contains("utun") || l.contains("default") || l.contains("10.0.1"))
                                    .collect::<Vec<_>>().join("\n");
                                info!("Routes:\n{routes}");
                            }
                            } // else (not loopback)
                        }

                        result
                    }
                    Err(e) => {
                        daemon_state.connected.store(false, std::sync::atomic::Ordering::Relaxed);
                        attempt += 1;
                        let delay = reconnect_delay(attempt);
                        warn!("Connect failed (attempt {attempt}): {e}");
                        info!("Retrying in {delay:?}...");

                        tokio::select! {
                            _ = tokio::signal::ctrl_c() => {
                                info!("Shutdown signal received during backoff");
                                break;
                            }
                            _ = tokio::time::sleep(delay) => {
                                continue;
                            }
                        }
                    }
                }
            }
        };

        let transport = connect_result.transport;
        let quic_conn = connect_result.quic_conn;
        let session_flags = connect_result.session_config.flags;
        let control_recv = connect_result.control_recv;

        let tun_name_mtu = tun_name.clone();
        let mtu_task = control_recv.map(|recv| {
            tokio::spawn(async move {
                read_session_updates(recv, &tun_name_mtu).await;
            })
        });

        if let Some(ref conn) = quic_conn {
            info!("Connected! RTT: {:?}", conn.stats().path.rtt);
            if let Some(max_dg) = conn.max_datagram_size() {
                info!("max_datagram_size = {max_dg}");
            }
        } else {
            info!("Connected via {}", connect_result.mode);
        }

        let batching_enabled = session_flags & redpill_quic::batch::flags::BATCHING != 0;
        if batching_enabled {
            info!("Server supports datagram batching");
        }

        let tunnel_exit = tokio::select! {
            _ = shutdown.notified() => {
                info!("Shutdown signal received");
                if let Some(ref conn) = quic_conn {
                    conn.close(quinn::VarInt::from_u32(0), b"client shutdown");
                }
                break;
            }
            exit = run_tunnel(
                transport,
                quic_conn.as_ref(),
                connect_result.mode,
                server_addr,
                &tun,
                cli.quiet,
                batching_enabled,
            ) => exit,
        };

        daemon_state
            .connected
            .store(false, std::sync::atomic::Ordering::Relaxed);
        if let Some(t) = mtu_task {
            t.abort();
        }

        match tunnel_exit {
            TunnelExit::HealthReconnect(reason) => {
                info!("Health monitor: {reason} - reconnecting immediately");
                attempt = 0;
                continue;
            }
            TunnelExit::Error(e) => {
                attempt += 1;
                let delay = reconnect_delay(attempt);
                warn!("Tunnel lost: {e}");
                info!("Reconnecting in {delay:?}...");

                tokio::select! {
                    _ = shutdown.notified() => {
                        info!("Shutdown signal received during backoff");
                        break;
                    }
                    _ = tokio::time::sleep(delay) => {
                        continue;
                    }
                }
            }
        }
    }

    if let Some(t) = ipc_task {
        t.abort();
    }
    if killswitch_enabled {
        killswitch::disable();
        info!("Kill-switch disabled");
    }
    if let Some(saved) = &saved_routes {
        route::cleanup_client_dns();
        route::cleanup_client_routes(saved);
        info!("Routes + DNS cleaned up");
    }

    endpoint.close(quinn::VarInt::from_u32(0), b"done");
    Ok(())
}

/// Calculate reconnect delay with exponential backoff + jitter.
fn reconnect_delay(attempt: u32) -> Duration {
    let base = RECONNECT_MIN_DELAY.saturating_mul(2u32.saturating_pow(attempt.saturating_sub(1)));
    let capped = base.min(RECONNECT_MAX_DELAY);
    // Add ±20% jitter
    let millis = capped.as_millis() as u64;
    let jitter = (millis as f64 * 0.2) as u64;
    let actual = millis + rand::random::<u64>() % (jitter * 2 + 1) - jitter;
    Duration::from_millis(actual)
}

async fn run_tunnel(
    transport: Arc<dyn Transport>,
    quic_conn: Option<&quinn::Connection>,
    mode: TransportMode,
    server_addr: SocketAddr,
    tun: &TunDevice,
    quiet: bool,
    batching: bool,
) -> TunnelExit {
    let stats = Arc::new(Stats::new());

    let stats_task = if !quiet {
        let stats_report = stats.clone();
        if let Some(conn) = quic_conn {
            let conn_stats = conn.clone();
            Some(tokio::spawn(async move {
                let mut interval = tokio::time::interval(STATS_INTERVAL);
                loop {
                    interval.tick().await;
                    stats_report.report(&conn_stats);
                }
            }))
        } else {
            Some(tokio::spawn(async move {
                let mut interval = tokio::time::interval(STATS_INTERVAL);
                loop {
                    interval.tick().await;
                    stats_report.report_basic();
                }
            }))
        }
    } else {
        None
    };

    // No backpressure on upload -- inner TCP handles congestion
    let transport_send = transport.clone();
    let stats_send = stats.clone();

    #[cfg(unix)]
    let tun2dg_task: tokio::task::JoinHandle<anyhow::Result<()>> = {
        let tun_fd = tun.raw_fd();
        let owned_fd =
            match unsafe { std::os::fd::BorrowedFd::borrow_raw(tun_fd) }.try_clone_to_owned() {
                Ok(fd) => fd,
                Err(e) => return TunnelExit::Error(e.into()),
            };
        let async_fd = match AsyncFd::new(owned_fd) {
            Ok(fd) => fd,
            Err(e) => return TunnelExit::Error(e.into()),
        };

        // macOS utun prepends 4-byte AF header on read
        #[cfg(target_os = "macos")]
        const TUN_HDR: usize = 4;
        #[cfg(not(target_os = "macos"))]
        const TUN_HDR: usize = 0;

        let dup_fd = async_fd.as_raw_fd();
        info!("TUN reader: original_fd={tun_fd}, dup_fd={dup_fd}");
        tokio::spawn(async move {
            info!("tun2dg_task started, waiting for packets on fd={dup_fd}...");
            let mut tun_buf = vec![0u8; TUN_MTU as usize + 4];
            loop {
                let mut guard = async_fd.readable().await?;
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

                    stats_send
                        .tun_reads
                        .fetch_add(1, std::sync::atomic::Ordering::Relaxed);

                    let ip_pkt = &tun_buf[TUN_HDR..n];
                    let size = ip_pkt.len();
                    match transport_send.send(Bytes::copy_from_slice(ip_pkt)).await {
                        Ok(SendResult::Sent) => stats_send.record_send(size),
                        Ok(SendResult::TooLarge) => stats_send.record_too_large(),
                        Ok(SendResult::Blocked) => {
                            stats_send.record_blocked();
                        }
                        Err(e) => {
                            return Err(e.into());
                        }
                    }

                    batch += 1;
                    if batch >= MAX_TUN_BATCH {
                        break;
                    }
                }
                if batch > 0 {
                    if let Err(e) = transport_send.flush().await {
                        return Err(e.into());
                    }
                }
            }
        })
    };

    #[cfg(target_os = "windows")]
    let tun2dg_task: tokio::task::JoinHandle<anyhow::Result<()>> = {
        let (tx, mut rx) = tokio::sync::mpsc::channel::<Vec<u8>>(512);

        let tun_reader = tun.clone();
        std::thread::spawn(move || {
            let mut buf = vec![0u8; TUN_MTU as usize + 64];
            loop {
                match tun_reader.read_packet(&mut buf) {
                    Ok(n) if n > 0 => {
                        if tx.blocking_send(buf[..n].to_vec()).is_err() {
                            break; // channel closed
                        }
                    }
                    Ok(_) => continue,
                    Err(e) => {
                        tracing::error!("wintun read error: {e}");
                        break;
                    }
                }
            }
        });

        tokio::spawn(async move {
            while let Some(pkt) = rx.recv().await {
                stats_send
                    .tun_reads
                    .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                let size = pkt.len();
                match transport_send.send(Bytes::from(pkt)).await {
                    Ok(SendResult::Sent) => stats_send.record_send(size),
                    Ok(SendResult::TooLarge) => stats_send.record_too_large(),
                    Ok(SendResult::Blocked) => {
                        stats_send.record_blocked();
                    }
                    Err(e) => {
                        return Err(e.into());
                    }
                }
            }
            Ok(())
        })
    };

    let idle_task = if mode == TransportMode::QuicCamouflaged {
        let transport_idle = transport.clone();
        Some(tokio::spawn(async move {
            let padder = redpill_quic::padding::IdlePadder::new(500, 64, 256);
            let mut interval = tokio::time::interval(padder.interval());
            loop {
                interval.tick().await;
                let pkt = padder.generate();
                let _ = transport_idle.send(Bytes::from(pkt)).await;
            }
        }))
    } else {
        None
    };

    let health = HealthMonitor::new(quic_conn.cloned(), mode, Some(server_addr));

    #[cfg(unix)]
    let tun_fd = tun.raw_fd();

    let tunnel_exit = tokio::select! {
        reason = health.watch() => TunnelExit::HealthReconnect(reason),
        dg2tun_result = async {
            loop {
                match transport.recv().await {
                    Ok(data) => {
                        if data.is_empty() {
                            continue;
                        }
                        stats.record_recv(data.len());

                        if batching && is_batched_datagram(&data) {
                            let packets = redpill_quic::batch::batch_decode(&data);
                            for pkt in packets {
                                #[cfg(unix)]
                                let result = write_to_tun(tun_fd, &pkt);
                                #[cfg(target_os = "windows")]
                                let result = tun.write_packet(&pkt).map(|_| ()).map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e.to_string()));
                                match result {
                                    Ok(()) => { stats.tun_writes.fetch_add(1, std::sync::atomic::Ordering::Relaxed); }
                                    Err(e) => warn!("TUN write failed: {e}"),
                                }
                            }
                        } else {
                            #[cfg(unix)]
                            let result = write_to_tun(tun_fd, &data);
                            #[cfg(target_os = "windows")]
                            let result = tun.write_packet(&data).map(|_| ()).map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e.to_string()));
                            match result {
                                Ok(()) => { stats.tun_writes.fetch_add(1, std::sync::atomic::Ordering::Relaxed); }
                                Err(e) => warn!("TUN write failed: {e}"),
                            }
                        }
                    }
                    Err(e) => {
                        error!("Connection error: {e}");
                        return Err::<(), anyhow::Error>(e.into());
                    }
                }
            }
        } => TunnelExit::Error(dg2tun_result.unwrap_err()),
    };

    tun2dg_task.abort();
    if let Some(t) = idle_task {
        t.abort();
    }
    if let Some(t) = stats_task {
        t.abort();
    }
    if !quiet {
        if let Some(conn) = quic_conn {
            stats.report(conn);
        } else {
            stats.report_basic();
        }
    }

    tunnel_exit
}

/// Read SessionUpdate messages from the control stream (dynamic MTU).
/// Old servers call send.finish() → recv gets EOF → task exits cleanly.
async fn read_session_updates(mut recv: quinn::RecvStream, tun_name: &str) {
    use redpill_quic::control::{SessionUpdate, SESSION_UPDATE_LEN};

    let mut buf = [0u8; SESSION_UPDATE_LEN];
    loop {
        match recv.read_exact(&mut buf).await {
            Ok(()) => {
                if let Some(update) = SessionUpdate::decode(&buf) {
                    info!("Server PMTU update: new MTU = {}", update.mtu);
                    #[cfg(target_os = "linux")]
                    let output = std::process::Command::new("ip")
                        .args(["link", "set", tun_name, "mtu", &update.mtu.to_string()])
                        .output();
                    #[cfg(not(target_os = "linux"))]
                    let output = std::process::Command::new("ifconfig")
                        .args([tun_name, "mtu", &update.mtu.to_string()])
                        .output();
                    match output {
                        Ok(o) if o.status.success() => {
                            info!("TUN MTU updated to {}", update.mtu);
                        }
                        Ok(o) => {
                            warn!(
                                "Failed to update TUN MTU: {}",
                                String::from_utf8_lossy(&o.stderr)
                            );
                        }
                        Err(e) => {
                            warn!("Failed to run ifconfig: {e}");
                        }
                    }
                }
            }
            Err(_) => {
                // EOF or error - server closed stream (old server or disconnect)
                return;
            }
        }
    }
}

/// Heuristic: detect if a datagram is a batch (length-prefixed) vs a raw IP packet.
///
/// Raw IP packets start with version nibble 4 (IPv4) or 6 (IPv6).
/// Batched datagrams start with a 2-byte big-endian length, where the first byte
/// is very unlikely to have nibble 4 or 6 (since packets are <300B, the high byte
/// of the length is always 0x00 or 0x01).
fn is_batched_datagram(data: &[u8]) -> bool {
    if data.is_empty() {
        return false;
    }
    let version_nibble = data[0] >> 4;
    // IP packets have version 4 or 6. Batch length prefix has 0x00 or 0x01 as first byte.
    version_nibble != 4 && version_nibble != 6
}

/// Wait for any shutdown signal (SIGINT, SIGTERM, SIGHUP on Unix; Ctrl+C on Windows).
async fn shutdown_signal() {
    #[cfg(unix)]
    {
        use tokio::signal::unix::{signal, SignalKind};
        let mut sigterm = signal(SignalKind::terminate()).expect("SIGTERM handler");
        let mut sighup = signal(SignalKind::hangup()).expect("SIGHUP handler");
        tokio::select! {
            _ = tokio::signal::ctrl_c() => { info!("Received SIGINT"); }
            _ = sigterm.recv() => { info!("Received SIGTERM"); }
            _ = sighup.recv() => { info!("Received SIGHUP"); }
        }
    }
    #[cfg(not(unix))]
    {
        tokio::signal::ctrl_c().await.ok();
        info!("Received Ctrl+C");
    }
}
