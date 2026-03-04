//! Transport health monitor - background watchdog for connection quality.
//!
//! Monitors RTT for QUIC transports (degradation detection) and periodically
//! probes for QUIC availability when connected via fallback transports
//! (TCP Reality, WebSocket) to attempt upgrades.

use std::net::SocketAddr;
use std::time::Duration;

use tokio::time;
use tracing::{debug, info};

use super::TransportMode;

/// Why the health monitor is requesting a reconnection.
#[derive(Debug, Clone, Copy)]
pub enum ReconnectReason {
    /// RTT or loss degraded beyond threshold.
    Degraded,
    /// A higher-priority transport may now be available.
    Upgrade,
}

impl std::fmt::Display for ReconnectReason {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Degraded => write!(f, "quality degraded"),
            Self::Upgrade => write!(f, "upgrade available"),
        }
    }
}

/// Background health monitor for an active transport connection.
///
/// - **QUIC transports**: checks RTT every 30s. If RTT exceeds 3x the baseline
///   for 2 consecutive checks (60s sustained), returns `Degraded`.
/// - **Non-QUIC transports** (TCP/WS): every 5 minutes attempts a UDP probe to
///   the server port as a heuristic for QUIC reachability. If reachable, returns
///   `Upgrade`.
pub struct HealthMonitor {
    quic_conn: Option<quinn::Connection>,
    mode: TransportMode,
    server_addr: Option<SocketAddr>,
}

/// RTT check interval for QUIC transports.
const QUIC_CHECK_INTERVAL: Duration = Duration::from_secs(30);

/// Upgrade probe interval for non-QUIC transports.
const UPGRADE_PROBE_INTERVAL: Duration = Duration::from_secs(300);

/// RTT degradation multiplier (3x baseline = degraded).
const RTT_DEGRADATION_FACTOR: f64 = 3.0;

/// Number of consecutive degraded checks before triggering reconnect.
const DEGRADED_THRESHOLD: u32 = 2;

/// Timeout for the UDP reachability probe.
const PROBE_TIMEOUT: Duration = Duration::from_secs(3);

impl HealthMonitor {
    /// Create a new health monitor.
    ///
    /// - `quic_conn`: QUIC connection handle (for RTT stats). None for TCP/WS.
    /// - `mode`: the current transport mode.
    /// - `server_addr`: server's UDP address (used for upgrade probes from non-QUIC).
    pub fn new(
        quic_conn: Option<quinn::Connection>,
        mode: TransportMode,
        server_addr: Option<SocketAddr>,
    ) -> Self {
        Self {
            quic_conn,
            mode,
            server_addr,
        }
    }

    /// Run until reconnection is needed. Returns the reason.
    ///
    /// This future never returns unless a reconnection condition is met.
    pub async fn watch(&self) -> ReconnectReason {
        match (&self.quic_conn, self.mode) {
            (Some(conn), TransportMode::QuicRaw | TransportMode::QuicCamouflaged) => {
                self.watch_quic(conn).await
            }
            (None, TransportMode::TcpReality | TransportMode::WebSocketCdn) => {
                self.watch_fallback().await
            }
            _ => std::future::pending().await,
        }
    }

    /// Monitor QUIC connection RTT for degradation.
    async fn watch_quic(&self, conn: &quinn::Connection) -> ReconnectReason {
        let mut interval = time::interval(QUIC_CHECK_INTERVAL);
        interval.tick().await;
        let baseline_rtt = conn.stats().path.rtt;
        let baseline_ms = baseline_rtt.as_secs_f64() * 1000.0;
        debug!(
            "Health monitor: baseline RTT = {:.1}ms (threshold = {:.1}ms)",
            baseline_ms,
            baseline_ms * RTT_DEGRADATION_FACTOR
        );

        let mut consecutive_degraded: u32 = 0;

        loop {
            interval.tick().await;

            let current_rtt = conn.stats().path.rtt;
            let current_ms = current_rtt.as_secs_f64() * 1000.0;
            let threshold_ms = baseline_ms * RTT_DEGRADATION_FACTOR;

            if current_ms > threshold_ms {
                consecutive_degraded += 1;
                info!(
                    "Health: RTT degraded {:.1}ms > {:.1}ms threshold ({consecutive_degraded}/{DEGRADED_THRESHOLD})",
                    current_ms, threshold_ms
                );
                if consecutive_degraded >= DEGRADED_THRESHOLD {
                    info!("Health: sustained degradation detected, triggering reconnect");
                    return ReconnectReason::Degraded;
                }
            } else {
                if consecutive_degraded > 0 {
                    debug!(
                        "Health: RTT recovered {:.1}ms <= {:.1}ms",
                        current_ms, threshold_ms
                    );
                }
                consecutive_degraded = 0;
            }
        }
    }

    /// Monitor fallback transport for QUIC upgrade opportunity.
    async fn watch_fallback(&self) -> ReconnectReason {
        let server_addr = match self.server_addr {
            Some(addr) => addr,
            None => std::future::pending().await,
        };

        let mut interval = time::interval(UPGRADE_PROBE_INTERVAL);
        // Skip immediate tick - just connected, QUIC was unavailable
        interval.tick().await;

        loop {
            interval.tick().await;

            debug!("Health: probing QUIC availability at {server_addr}...");

            // Heuristic: try to reach the server's UDP port.
            // A successful socket connect + small send/timeout suggests UDP is not blocked.
            match probe_udp_reachable(server_addr).await {
                true => {
                    info!(
                        "Health: UDP port {} reachable - QUIC may be available, triggering upgrade",
                        server_addr.port()
                    );
                    return ReconnectReason::Upgrade;
                }
                false => {
                    debug!("Health: UDP probe failed, staying on {}", self.mode);
                }
            }
        }
    }
}

/// Heuristic UDP reachability probe.
///
/// Sends a small packet to the server's UDP port and waits briefly for any response
/// (or ICMP unreachable). This is a best-effort check - firewalls may silently drop.
///
/// Returns `true` if the send succeeds and no immediate error is reported.
async fn probe_udp_reachable(addr: SocketAddr) -> bool {
    let result: Result<bool, std::io::Error> = tokio::time::timeout(PROBE_TIMEOUT, async {
        let sock = tokio::net::UdpSocket::bind("0.0.0.0:0").await?;
        sock.connect(addr).await?;
        sock.send(&[0u8; 4]).await?;
        let mut buf = [0u8; 64];
        match tokio::time::timeout(Duration::from_secs(1), sock.recv(&mut buf)).await {
            Ok(Ok(_)) => Ok(true),
            Ok(Err(_)) => Ok(false), // ICMP unreachable
            Err(_) => Ok(true),      // no ICMP unreachable, assume open
        }
    })
    .await
    .unwrap_or(Ok(false));

    result.unwrap_or(false)
}
