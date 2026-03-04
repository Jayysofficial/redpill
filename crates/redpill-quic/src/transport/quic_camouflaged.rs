//! QUIC Camouflaged transport: QUIC with fake SNI, cert pinning, and padding.
//!
//! Connects with h3 ALPN + rotated SNI + browser-like TLS fingerprint.
//! Cert pinning via SHA-256 fingerprint (SNI/cert mismatch hidden by TLS 1.3).

use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use bytes::Bytes;

use crate::browser_profile::BrowserProfile;
use crate::camouflage::{CamouflageCertVerifier, SniCamouflage};
use crate::cert::pem_to_cert_der;
use crate::config::ClientCamouflageSection;
use crate::fingerprint::build_camouflaged_rustls_config_with_profile;
use crate::padding;

use super::quic_raw::QuicRawTransport;
use super::{SendResult, Transport, TransportError, TransportMode, TransportStats};

/// Camouflaged QUIC transport - wraps QuicRawTransport with packet padding.
pub struct QuicCamouflagedTransport {
    inner: QuicRawTransport,
    padding_enabled: bool,
}

impl QuicCamouflagedTransport {
    pub fn new(inner: QuicRawTransport, padding_enabled: bool) -> Self {
        Self {
            inner,
            padding_enabled,
        }
    }
}

#[async_trait]
impl Transport for QuicCamouflagedTransport {
    async fn send(&self, data: Bytes) -> Result<SendResult, TransportError> {
        let data = if self.padding_enabled {
            Bytes::from(padding::pad_to_standard(&data))
        } else {
            data
        };
        self.inner.send(data).await
    }

    async fn recv(&self) -> Result<Bytes, TransportError> {
        let data = self.inner.recv().await?;
        if self.padding_enabled {
            let stripped = padding::strip_padding(&data);
            Ok(Bytes::copy_from_slice(stripped))
        } else {
            Ok(data)
        }
    }

    fn mode(&self) -> TransportMode {
        TransportMode::QuicCamouflaged
    }

    fn stats(&self) -> TransportStats {
        self.inner.stats()
    }

    fn max_datagram_size(&self) -> Option<usize> {
        self.inner.max_datagram_size()
    }
}

/// Builder for camouflaged QUIC connections.
///
/// Produces a `quinn::ClientConfig` with:
/// - Fake SNI from the configured pool (round-robin rotation)
/// - Certificate pinning (ignores SNI mismatch, verifies cert fingerprint)
/// - Chrome-like TLS fingerprint (cipher suites, key exchange groups)
/// - TLS 1.3 only (required for Certificate encryption)
pub struct QuicCamouflagedConnector {
    sni: SniCamouflage,
    cert_path: String,
    config: ClientCamouflageSection,
}

impl QuicCamouflagedConnector {
    pub fn new(cert_path: String, config: ClientCamouflageSection) -> Self {
        let sni = SniCamouflage::new(config.sni_pool.clone());
        Self {
            sni,
            cert_path,
            config,
        }
    }

    /// Whether padding is enabled for this connector.
    pub fn padding_enabled(&self) -> bool {
        self.config.padding
    }

    /// Build a quinn ClientConfig with camouflage settings.
    /// Returns (client_config, fake_sni) - the caller must use the fake SNI
    /// as the server_name when calling `endpoint.connect()`.
    pub fn build_client_config(&self) -> anyhow::Result<(quinn::ClientConfig, String)> {
        let cert_pem = std::fs::read_to_string(&self.cert_path)?;
        let cert_der = pem_to_cert_der(&cert_pem)?;

        let mut root_store = rustls::RootCertStore::empty();
        root_store.add(cert_der.clone())?;

        let verifier = Arc::new(CamouflageCertVerifier::new(&cert_der, Arc::new(root_store)));
        let profile = BrowserProfile::parse_profile(&self.config.browser_profile).resolve();

        let rustls_config = build_camouflaged_rustls_config_with_profile(
            verifier,
            profile,
            self.config.chrome_fingerprint,
        )?;

        let mut client_config = quinn::ClientConfig::new(Arc::new(
            quinn::crypto::rustls::QuicClientConfig::try_from(rustls_config)?,
        ));

        let transport = build_camouflaged_transport_config(profile);
        client_config.transport_config(Arc::new(transport));

        let fake_sni = self.sni.next_sni().to_string();

        Ok((client_config, fake_sni))
    }
}

/// Build QUIC transport config matching a real browser's transport parameters.
///
/// Overlays browser-specific values on top of our VPN transport config
/// (no-op CC, large windows). The visible QUIC transport parameters in the
/// Initial packet match the specified browser profile.
fn build_camouflaged_transport_config(profile: BrowserProfile) -> quinn::TransportConfig {
    use crate::noop_cc::NoopCcConfig;

    let params = profile.quic_transport_params();
    let mut transport = quinn::TransportConfig::default();

    const MB: u64 = 1024 * 1024;
    transport.congestion_controller_factory(Arc::new(NoopCcConfig::new(16 * MB)));
    transport.send_window(16 * MB);
    transport.datagram_receive_buffer_size(Some(16 * MB as usize));
    transport.datagram_send_buffer_size(2 * MB as usize);

    transport.receive_window(
        quinn::VarInt::from_u64(params.initial_max_data).unwrap_or(quinn::VarInt::MAX),
    );
    transport.stream_receive_window(
        quinn::VarInt::from_u64(params.initial_max_stream_data_bidi_local)
            .unwrap_or(quinn::VarInt::MAX),
    );
    transport.max_concurrent_bidi_streams(
        quinn::VarInt::from_u64(params.initial_max_streams_bidi).unwrap_or(quinn::VarInt::MAX),
    );
    transport.max_concurrent_uni_streams(
        quinn::VarInt::from_u64(params.initial_max_streams_uni).unwrap_or(quinn::VarInt::MAX),
    );

    transport.initial_mtu(params.max_udp_payload_size);
    transport.min_mtu(1280);
    transport.mtu_discovery_config(Some(quinn::MtuDiscoveryConfig::default()));

    transport.keep_alive_interval(Some(Duration::from_secs(10)));
    transport.max_idle_timeout(Some(params.max_idle_timeout.try_into().unwrap()));

    transport
}
