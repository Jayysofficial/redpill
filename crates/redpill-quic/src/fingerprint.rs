//! Browser-like TLS fingerprint for QUIC connections.
//!
//! Configures cipher suites and key exchange groups to match real browser
//! TLS 1.3 / QUIC fingerprints, reducing the chance of DPI flagging
//! the connection as non-browser traffic.
//!
//! Supports multiple browser profiles (Chrome, Firefox, Safari) via
//! `BrowserProfile`. The default (Chrome) matches the most common QUIC
//! client on the Internet.

use std::sync::Arc;

use crate::browser_profile::BrowserProfile;

/// Build a `rustls::CryptoProvider` matching Chrome's TLS 1.3 fingerprint.
pub fn chrome_crypto_provider() -> rustls::crypto::CryptoProvider {
    build_crypto_provider(BrowserProfile::Chrome)
}

/// Build a `rustls::CryptoProvider` matching the given browser profile.
pub fn build_crypto_provider(profile: BrowserProfile) -> rustls::crypto::CryptoProvider {
    let resolved = profile.resolve();

    let mut provider = rustls::crypto::ring::default_provider();
    provider.kx_groups = resolved.kx_groups();
    provider.cipher_suites = resolved.cipher_suites();

    provider
}

/// Build a rustls `ClientConfig` for camouflaged QUIC with browser-like fingerprint.
pub fn build_camouflaged_rustls_config(
    verifier: Arc<dyn rustls::client::danger::ServerCertVerifier>,
    chrome_fingerprint: bool,
) -> Result<rustls::ClientConfig, rustls::Error> {
    build_camouflaged_rustls_config_with_profile(
        verifier,
        BrowserProfile::Chrome,
        chrome_fingerprint,
    )
}

/// Build a rustls `ClientConfig` for camouflaged QUIC with a specific browser profile.
pub fn build_camouflaged_rustls_config_with_profile(
    verifier: Arc<dyn rustls::client::danger::ServerCertVerifier>,
    profile: BrowserProfile,
    enabled: bool,
) -> Result<rustls::ClientConfig, rustls::Error> {
    let provider = if enabled {
        build_crypto_provider(profile)
    } else {
        rustls::crypto::ring::default_provider()
    };

    let mut config = rustls::ClientConfig::builder_with_provider(Arc::new(provider))
        .with_protocol_versions(&[&rustls::version::TLS13])?
        .dangerous()
        .with_custom_certificate_verifier(verifier)
        .with_no_client_auth();

    // ALPN: h3 only - DPI sees a standard HTTP/3 ClientHello.
    // Server differentiates VPN clients from real HTTP/3 probes by whether
    // the client opens a bi-directional stream (VPN auth) or uni-directional (H3 settings).
    config.alpn_protocols = vec![crate::ALPN_H3.to_vec()];

    config.resumption = rustls::client::Resumption::in_memory_sessions(256);

    Ok(config)
}
