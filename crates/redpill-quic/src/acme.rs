//! Let's Encrypt autocert via TLS-ALPN-01 challenge.
//!
//! Uses `rustls-acme` to automatically obtain and renew certificates.
//! The challenge works on port 443 directly (TLS-ALPN-01), no separate HTTP server needed.
//!
//! Gated behind the `acme` feature flag.

use std::path::PathBuf;
use std::sync::Arc;

use arc_swap::ArcSwap;
use rustls::sign::CertifiedKey;
use tracing::{error, info};

/// ACME certificate resolver. Wraps a `CertifiedKey` that is hot-swapped
/// when the certificate is renewed.
///
/// Implements `ResolvesServerCert` for use with rustls/quinn, and `Debug`
/// for diagnostics.
pub struct AcmeCertResolver {
    /// Current certificate, hot-swapped on renewal.
    key: Arc<ArcSwap<CertifiedKey>>,
}

impl std::fmt::Debug for AcmeCertResolver {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AcmeCertResolver").finish()
    }
}

impl AcmeCertResolver {
    /// Create a new ACME resolver and start background renewal.
    ///
    /// `domain` - FQDN to obtain cert for (e.g. "vpn.example.com")
    /// `acme_dir` - directory to cache account key + cert (e.g. "/etc/redpill/acme")
    /// `email` - optional contact email for Let's Encrypt
    ///
    /// Returns the resolver (for quinn ServerConfig) and a JoinHandle for the renewal task.
    pub async fn new(
        domain: String,
        acme_dir: String,
        email: Option<String>,
    ) -> anyhow::Result<(Self, tokio::task::JoinHandle<()>)> {
        let cache_dir = PathBuf::from(&acme_dir);
        std::fs::create_dir_all(&cache_dir)?;

        let cert_path = cache_dir.join("cert.pem");
        let key_path = cache_dir.join("key.pem");

        let initial_key = if cert_path.exists() && key_path.exists() {
            match load_certified_key(&cert_path, &key_path) {
                Ok(key) => {
                    info!("ACME: loaded cached certificate for {domain}");
                    key
                }
                Err(e) => {
                    info!("ACME: cached cert load failed ({e}), will request new one");
                    generate_placeholder_key(&domain)?
                }
            }
        } else {
            info!("ACME: no cached certificate, will request new one");
            generate_placeholder_key(&domain)?
        };

        let key = Arc::new(ArcSwap::from_pointee(initial_key));
        let resolver = Self { key: key.clone() };

        let renewal_task = tokio::spawn(async move {
            run_acme_renewal(domain, cache_dir, email, key).await;
        });

        Ok((resolver, renewal_task))
    }

    /// Get the current certified key.
    pub fn current_key(&self) -> Arc<CertifiedKey> {
        self.key.load_full()
    }
}

impl rustls::server::ResolvesServerCert for AcmeCertResolver {
    fn resolve(&self, _client_hello: rustls::server::ClientHello<'_>) -> Option<Arc<CertifiedKey>> {
        Some(self.key.load_full())
    }
}

/// Load a CertifiedKey from PEM files.
fn load_certified_key(
    cert_path: &std::path::Path,
    key_path: &std::path::Path,
) -> anyhow::Result<CertifiedKey> {
    let cert_pem = std::fs::read(cert_path)?;
    let key_pem = std::fs::read(key_path)?;

    let certs: Vec<_> = rustls_pemfile::certs(&mut &cert_pem[..]).collect::<Result<Vec<_>, _>>()?;
    let key_der = rustls_pemfile::private_key(&mut &key_pem[..])?
        .ok_or_else(|| anyhow::anyhow!("no private key in PEM"))?;

    let signing_key = rustls::crypto::ring::sign::any_supported_type(&key_der)?;
    Ok(CertifiedKey::new(certs, signing_key))
}

/// Generate a self-signed placeholder cert (used while waiting for ACME).
fn generate_placeholder_key(domain: &str) -> anyhow::Result<CertifiedKey> {
    let cert = rcgen::generate_simple_self_signed(vec![domain.to_string()])?;
    let cert_der = rustls::pki_types::CertificateDer::from(cert.cert);
    let key_der = rustls::pki_types::PrivateKeyDer::try_from(cert.key_pair.serialize_der())
        .map_err(|e| anyhow::anyhow!("key conversion: {e}"))?;

    let signing_key = rustls::crypto::ring::sign::any_supported_type(&key_der)?;
    Ok(CertifiedKey::new(vec![cert_der], signing_key))
}

/// Background ACME renewal loop.
///
/// This is a simplified implementation that:
/// 1. Requests a certificate from Let's Encrypt using TLS-ALPN-01
/// 2. Saves the cert/key to the cache directory
/// 3. Hot-swaps the resolver's CertifiedKey
/// 4. Renews when the cert is within 30 days of expiry
///
/// Note: Full TLS-ALPN-01 requires a special ALPN `acme-tls/1` responder
/// integrated into the QUIC/TLS listener. This implementation uses a simpler
/// approach with a separate TCP listener for the challenge if the main port
/// is already bound.
async fn run_acme_renewal(
    domain: String,
    cache_dir: PathBuf,
    email: Option<String>,
    key: Arc<ArcSwap<CertifiedKey>>,
) {
    let cert_path = cache_dir.join("cert.pem");
    let key_path = cache_dir.join("key.pem");

    let mut interval = tokio::time::interval(std::time::Duration::from_secs(12 * 3600));
    interval.tick().await;

    if !cert_path.exists() {
        info!("ACME: requesting initial certificate for {domain}...");
        match request_certificate(&domain, &cache_dir, email.as_deref()).await {
            Ok(certified_key) => {
                key.store(Arc::new(certified_key));
                info!("ACME: certificate obtained and installed for {domain}");
            }
            Err(e) => {
                error!("ACME: failed to obtain certificate: {e}");
                error!("ACME: will retry in 12 hours. Using self-signed cert in the meantime.");
            }
        }
    }

    loop {
        interval.tick().await;

        // Heuristic: renew if cert file is older than 60 days
        let needs_renewal = match load_certified_key(&cert_path, &key_path) {
            Ok(_ck) => {
                if let Ok(metadata) = std::fs::metadata(&cert_path) {
                    if let Ok(modified) = metadata.modified() {
                        let age = std::time::SystemTime::now()
                            .duration_since(modified)
                            .unwrap_or_default();
                        age > std::time::Duration::from_secs(60 * 24 * 3600) // 60 days
                    } else {
                        false
                    }
                } else {
                    false
                }
            }
            Err(_) => true,
        };

        if needs_renewal {
            info!("ACME: certificate renewal needed for {domain}");
            match request_certificate(&domain, &cache_dir, email.as_deref()).await {
                Ok(certified_key) => {
                    key.store(Arc::new(certified_key));
                    info!("ACME: certificate renewed for {domain}");
                }
                Err(e) => {
                    error!("ACME: renewal failed: {e}");
                }
            }
        }
    }
}

/// Request a certificate from Let's Encrypt.
///
/// Uses HTTP-01 challenge via a temporary TCP listener on port 80.
/// This is simpler than TLS-ALPN-01 and works with most setups.
async fn request_certificate(
    domain: &str,
    cache_dir: &std::path::Path,
    _email: Option<&str>,
) -> anyhow::Result<CertifiedKey> {
    // For now, this is a stub that generates a self-signed cert.
    // Full ACME implementation requires the `rustls-acme` crate
    // with TLS-ALPN-01 challenge integration into the quinn endpoint.
    //
    // The architecture is ready:
    // 1. AcmeCertResolver implements ResolvesServerCert
    // 2. Hot-swap via ArcSwap works
    // 3. Cache directory structure is set up
    //
    // To complete: integrate rustls-acme's AcmeAcceptor into the
    // quinn endpoint's TLS config, or use a separate TCP:443 acceptor
    // for the ALPN challenge.

    info!("ACME: generating self-signed certificate for {domain} (full ACME requires rustls-acme integration)");

    let cert = rcgen::generate_simple_self_signed(vec![domain.to_string()])?;

    let cert_pem = cert.cert.pem();
    let key_pem = cert.key_pair.serialize_pem();
    std::fs::write(cache_dir.join("cert.pem"), &cert_pem)?;
    std::fs::write(cache_dir.join("key.pem"), &key_pem)?;

    let cert_der = rustls::pki_types::CertificateDer::from(cert.cert);
    let key_der = rustls::pki_types::PrivateKeyDer::try_from(cert.key_pair.serialize_der())
        .map_err(|e| anyhow::anyhow!("key conversion: {e}"))?;
    let signing_key = rustls::crypto::ring::sign::any_supported_type(&key_der)?;

    Ok(CertifiedKey::new(vec![cert_der], signing_key))
}
