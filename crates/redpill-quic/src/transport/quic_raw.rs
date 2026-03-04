//! QuicRaw transport: direct QUIC DATAGRAM frames (no camouflage).
//!
//! Wraps `quinn::Connection` and provides the `Transport` trait implementation.
//! This is the default transport mode - identical behavior to the pre-abstraction code.

use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use bytes::Bytes;
use quinn::SendDatagramError;

use crate::noop_cc::NoopCcConfig;

use super::{SendResult, Transport, TransportError, TransportMode, TransportStats};

const MB: u64 = 1024 * 1024;

/// Build the production QUIC transport config (no-op CC, 16MB window).
///
/// No-op CC with 16 MB constant window - inner TCP handles congestion control.
/// Datagram send buffer: 2 MB (~3x BDP for 100 Mbps / 50 ms path).
pub fn build_transport_config() -> quinn::TransportConfig {
    let mut transport = quinn::TransportConfig::default();

    transport.congestion_controller_factory(Arc::new(NoopCcConfig::new(16 * MB)));
    transport.send_window(16 * MB);
    transport.datagram_receive_buffer_size(Some(16 * MB as usize));
    transport.datagram_send_buffer_size(2 * MB as usize);

    transport.initial_mtu(1400);
    transport.min_mtu(1280);
    transport.mtu_discovery_config(Some(quinn::MtuDiscoveryConfig::default()));

    transport.keep_alive_interval(Some(Duration::from_secs(10)));
    transport.max_idle_timeout(Some(Duration::from_secs(30).try_into().unwrap()));

    transport
}

/// QUIC raw transport - sends IP packets as QUIC DATAGRAM frames.
pub struct QuicRawTransport {
    conn: quinn::Connection,
}

impl QuicRawTransport {
    pub fn new(conn: quinn::Connection) -> Self {
        Self { conn }
    }

    /// Get a reference to the underlying quinn connection.
    ///
    /// Useful for accessing quinn-specific stats or features not exposed
    /// by the Transport trait.
    pub fn connection(&self) -> &quinn::Connection {
        &self.conn
    }
}

#[async_trait]
impl Transport for QuicRawTransport {
    async fn send(&self, data: Bytes) -> Result<SendResult, TransportError> {
        match self.conn.send_datagram(data) {
            Ok(()) => Ok(SendResult::Sent),
            Err(SendDatagramError::TooLarge) => Ok(SendResult::TooLarge),
            Err(SendDatagramError::ConnectionLost(e)) => {
                Err(TransportError::ConnectionLost(e.to_string()))
            }
            Err(_) => Ok(SendResult::Blocked),
        }
    }

    async fn recv(&self) -> Result<Bytes, TransportError> {
        self.conn
            .read_datagram()
            .await
            .map_err(|e| TransportError::ConnectionLost(e.to_string()))
    }

    fn mode(&self) -> TransportMode {
        TransportMode::QuicRaw
    }

    fn stats(&self) -> TransportStats {
        let s = self.conn.stats();
        TransportStats {
            rtt: Some(s.path.rtt),
            cwnd: Some(s.path.cwnd),
            lost_packets: Some(s.path.lost_packets),
            sent_packets: Some(s.path.sent_packets),
            max_datagram_size: self.conn.max_datagram_size(),
        }
    }

    fn max_datagram_size(&self) -> Option<usize> {
        self.conn.max_datagram_size()
    }
}
