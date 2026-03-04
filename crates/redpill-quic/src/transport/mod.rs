//! Transport abstraction layer.
//!
//! Provides a generic `Transport` trait for sending/receiving IP datagrams,
//! allowing the VPN to work over different underlying transports (QUIC, TCP+TLS, WebSocket).

pub mod health;
pub mod manager;
pub mod quic_camouflaged;
pub mod quic_raw;
pub mod tcp_reality;
pub mod websocket_cdn;

pub use quic_raw::{build_transport_config, QuicRawTransport};

use std::fmt;
use std::time::Duration;

use async_trait::async_trait;
use bytes::Bytes;

/// Transport mode identifier.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TransportMode {
    /// Direct QUIC with no camouflage.
    QuicRaw,
    /// QUIC with SNI camouflage + padding.
    QuicCamouflaged,
    /// TCP + TLS Reality (proxy-based).
    TcpReality,
    /// WebSocket through CDN.
    WebSocketCdn,
}

impl fmt::Display for TransportMode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::QuicRaw => write!(f, "QUIC"),
            Self::QuicCamouflaged => write!(f, "QUIC+Camo"),
            Self::TcpReality => write!(f, "TCP+Reality"),
            Self::WebSocketCdn => write!(f, "WS+CDN"),
        }
    }
}

/// Non-fatal outcome of a send operation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SendResult {
    /// Datagram was sent successfully.
    Sent,
    /// Datagram was too large for the transport.
    TooLarge,
    /// Send buffer is full; datagram was dropped.
    Blocked,
}

/// Fatal transport error - connection is lost or unusable.
#[derive(Debug, thiserror::Error)]
pub enum TransportError {
    #[error("connection lost: {0}")]
    ConnectionLost(String),
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
}

/// Transport statistics snapshot.
#[derive(Debug, Clone, Default)]
pub struct TransportStats {
    pub rtt: Option<Duration>,
    pub cwnd: Option<u64>,
    pub lost_packets: Option<u64>,
    pub sent_packets: Option<u64>,
    pub max_datagram_size: Option<usize>,
}

/// Abstraction over the VPN datagram transport.
///
/// Implementations wrap a specific transport mechanism (QUIC datagrams,
/// TCP+TLS length-framed, WebSocket binary frames) and provide a uniform
/// send/recv interface for IP packets.
#[async_trait]
pub trait Transport: Send + Sync {
    /// Send a datagram (IP packet) to the peer.
    ///
    /// Returns `SendResult::Sent` on success, or a non-fatal `SendResult`
    /// variant if the packet was dropped. Returns `TransportError` only
    /// for fatal errors (connection lost).
    async fn send(&self, data: Bytes) -> Result<SendResult, TransportError>;

    /// Receive the next datagram (IP packet) from the peer.
    ///
    /// Blocks until a datagram is available. Returns `TransportError` on
    /// fatal connection loss.
    async fn recv(&self) -> Result<Bytes, TransportError>;

    /// Get the transport mode.
    fn mode(&self) -> TransportMode;

    /// Get current transport statistics.
    fn stats(&self) -> TransportStats;

    /// Get the maximum datagram size supported by this transport.
    fn max_datagram_size(&self) -> Option<usize>;

    /// Flush buffered writes. No-op for transports without write buffering (QUIC).
    /// TCP-based transports should flush their BufWriter here.
    async fn flush(&self) -> Result<(), TransportError> {
        Ok(())
    }
}
