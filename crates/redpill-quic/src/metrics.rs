//! Prometheus metrics: counters, histograms, and HTTP /metrics endpoint.

use std::net::SocketAddr;
use std::sync::Arc;

use prometheus::{
    Encoder, Histogram, HistogramOpts, IntCounter, IntGauge, IntGaugeVec, Opts, Registry,
    TextEncoder,
};
use tokio::net::TcpListener;
use tracing::{error, info};

/// All server metrics, registered with a Prometheus registry.
pub struct Metrics {
    pub registry: Registry,

    pub active_sessions: IntGauge,
    pub handshakes_total: IntCounter,
    pub handshakes_failed: IntCounter,

    pub bytes_in: IntCounter,
    pub bytes_out: IntCounter,
    pub datagrams_in: IntCounter,
    pub datagrams_out: IntCounter,

    pub drops_rate_limit: IntCounter,
    pub drops_backpressure: IntCounter,
    pub drops_stale: IntCounter,
    pub spoofed: IntCounter,

    pub bp_wait_count: IntCounter,
    pub bp_wait_timeouts: IntCounter,
    pub bp_rt_drops_congested: IntCounter,

    pub rtt_ms: Histogram,
    pub sessions_by_user: IntGaugeVec,
}

impl Default for Metrics {
    fn default() -> Self {
        Self::new()
    }
}

impl Metrics {
    pub fn new() -> Self {
        let registry = Registry::new();

        let active_sessions =
            IntGauge::new("redpill_active_sessions", "Active VPN sessions").unwrap();
        let handshakes_total =
            IntCounter::new("redpill_handshakes_total", "Total handshake attempts").unwrap();
        let handshakes_failed =
            IntCounter::new("redpill_handshakes_failed", "Failed handshakes").unwrap();

        let bytes_in = IntCounter::new("redpill_bytes_in", "Bytes received from clients").unwrap();
        let bytes_out = IntCounter::new("redpill_bytes_out", "Bytes sent to clients").unwrap();
        let datagrams_in =
            IntCounter::new("redpill_datagrams_in", "Datagrams received from clients").unwrap();
        let datagrams_out =
            IntCounter::new("redpill_datagrams_out", "Datagrams sent to clients").unwrap();

        let drops_rate_limit = IntCounter::new(
            "redpill_drops_rate_limit",
            "Packets dropped by rate limiter",
        )
        .unwrap();
        let drops_backpressure = IntCounter::new(
            "redpill_drops_backpressure",
            "Packets dropped by backpressure",
        )
        .unwrap();
        let drops_stale =
            IntCounter::new("redpill_drops_stale", "Stale realtime packets dropped").unwrap();
        let spoofed = IntCounter::new("redpill_spoofed", "Spoofed packets dropped").unwrap();

        let bp_wait_count = IntCounter::new(
            "redpill_bp_wait_count",
            "Bulk packets that entered send_datagram_wait",
        )
        .unwrap();
        let bp_wait_timeouts = IntCounter::new(
            "redpill_bp_wait_timeouts",
            "Bulk packets dropped by wait timeout",
        )
        .unwrap();
        let bp_rt_drops_congested = IntCounter::new(
            "redpill_bp_rt_drops_congested",
            "Realtime packets dropped due to congested buffer",
        )
        .unwrap();

        let rtt_opts = HistogramOpts::new("redpill_rtt_ms", "RTT in milliseconds")
            .buckets(vec![5.0, 10.0, 25.0, 50.0, 100.0, 250.0]);
        let rtt_ms = Histogram::with_opts(rtt_opts).unwrap();

        let sessions_by_user = IntGaugeVec::new(
            Opts::new("redpill_sessions_by_user", "Active sessions per user"),
            &["user"],
        )
        .unwrap();

        registry
            .register(Box::new(active_sessions.clone()))
            .unwrap();
        registry
            .register(Box::new(handshakes_total.clone()))
            .unwrap();
        registry
            .register(Box::new(handshakes_failed.clone()))
            .unwrap();
        registry.register(Box::new(bytes_in.clone())).unwrap();
        registry.register(Box::new(bytes_out.clone())).unwrap();
        registry.register(Box::new(datagrams_in.clone())).unwrap();
        registry.register(Box::new(datagrams_out.clone())).unwrap();
        registry
            .register(Box::new(drops_rate_limit.clone()))
            .unwrap();
        registry
            .register(Box::new(drops_backpressure.clone()))
            .unwrap();
        registry.register(Box::new(drops_stale.clone())).unwrap();
        registry.register(Box::new(spoofed.clone())).unwrap();
        registry.register(Box::new(bp_wait_count.clone())).unwrap();
        registry
            .register(Box::new(bp_wait_timeouts.clone()))
            .unwrap();
        registry
            .register(Box::new(bp_rt_drops_congested.clone()))
            .unwrap();
        registry.register(Box::new(rtt_ms.clone())).unwrap();
        registry
            .register(Box::new(sessions_by_user.clone()))
            .unwrap();

        Self {
            registry,
            active_sessions,
            handshakes_total,
            handshakes_failed,
            bytes_in,
            bytes_out,
            datagrams_in,
            datagrams_out,
            drops_rate_limit,
            drops_backpressure,
            drops_stale,
            spoofed,
            bp_wait_count,
            bp_wait_timeouts,
            bp_rt_drops_congested,
            rtt_ms,
            sessions_by_user,
        }
    }

    /// Render all metrics in Prometheus text format.
    pub fn render(&self) -> String {
        let encoder = TextEncoder::new();
        let metric_families = self.registry.gather();
        let mut buffer = Vec::new();
        encoder.encode(&metric_families, &mut buffer).unwrap();
        String::from_utf8(buffer).unwrap()
    }
}

/// Spawn the metrics HTTP server on the given address.
/// Returns a JoinHandle that can be aborted on shutdown.
pub fn spawn_metrics_server(
    addr: SocketAddr,
    metrics: Arc<Metrics>,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        let listener = match TcpListener::bind(addr).await {
            Ok(l) => l,
            Err(e) => {
                error!("Failed to bind metrics server on {addr}: {e}");
                return;
            }
        };
        info!("Metrics server listening on {addr}");

        loop {
            let (stream, _) = match listener.accept().await {
                Ok(s) => s,
                Err(e) => {
                    error!("Metrics accept error: {e}");
                    continue;
                }
            };

            let metrics = metrics.clone();
            tokio::spawn(async move {
                let io = hyper_util::rt::TokioIo::new(stream);
                let service = hyper::service::service_fn(
                    move |req: hyper::Request<hyper::body::Incoming>| {
                        let metrics = metrics.clone();
                        async move {
                            if req.uri().path() == "/metrics" {
                                let body = metrics.render();
                                Ok::<_, std::convert::Infallible>(hyper::Response::new(
                                    http_body_util::Full::new(bytes::Bytes::from(body)),
                                ))
                            } else {
                                Ok(hyper::Response::builder()
                                    .status(404)
                                    .body(http_body_util::Full::new(bytes::Bytes::from_static(
                                        b"Not Found",
                                    )))
                                    .unwrap())
                            }
                        }
                    },
                );

                if let Err(e) = hyper::server::conn::http1::Builder::new()
                    .serve_connection(io, service)
                    .await
                {
                    if !e.is_incomplete_message() {
                        error!("Metrics connection error: {e}");
                    }
                }
            });
        }
    })
}
