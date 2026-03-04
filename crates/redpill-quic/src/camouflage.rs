//! SNI camouflage and certificate pinning verifier.
//!
//! Allows the client to connect with a fake SNI (e.g., dl.google.com) while
//! pinning to our server's self-signed certificate. TLS 1.3 encrypts the
//! Certificate message, so DPI cannot see the SNI/cert mismatch.

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;

use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::{DigitallySignedStruct, Error, SignatureScheme};
use sha2::Digest;

/// SNI pool with round-robin rotation.
pub struct SniCamouflage {
    domains: Vec<String>,
    index: AtomicUsize,
}

impl SniCamouflage {
    pub fn new(domains: Vec<String>) -> Self {
        assert!(!domains.is_empty(), "SNI pool must not be empty");
        Self {
            domains,
            index: AtomicUsize::new(0),
        }
    }

    /// Get the next SNI domain (round-robin).
    pub fn next_sni(&self) -> &str {
        let idx = self.index.fetch_add(1, Ordering::Relaxed) % self.domains.len();
        &self.domains[idx]
    }

    pub fn domains(&self) -> &[String] {
        &self.domains
    }
}

/// Certificate verifier that pins to a specific server cert (SHA-256 fingerprint)
/// and ignores the SNI server name. TLS 1.3 encrypts the Certificate message
/// so DPI can't see the mismatch.
#[derive(Debug)]
pub struct CamouflageCertVerifier {
    pinned_fingerprint: [u8; 32],
    inner: Arc<rustls::client::WebPkiServerVerifier>,
}

impl CamouflageCertVerifier {
    /// Create a new verifier that pins to the given certificate.
    /// `root_store` should contain our server's self-signed cert.
    pub fn new(pinned_cert: &CertificateDer<'_>, root_store: Arc<rustls::RootCertStore>) -> Self {
        let fingerprint: [u8; 32] = sha2::Sha256::digest(pinned_cert.as_ref()).into();
        let inner = rustls::client::WebPkiServerVerifier::builder(root_store)
            .build()
            .expect("valid root store for WebPkiServerVerifier");
        Self {
            pinned_fingerprint: fingerprint,
            inner,
        }
    }
}

impl ServerCertVerifier for CamouflageCertVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>, // ignored - we don't validate SNI
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, Error> {
        let fp: [u8; 32] = sha2::Sha256::digest(end_entity.as_ref()).into();
        if fp != self.pinned_fingerprint {
            return Err(Error::InvalidCertificate(
                rustls::CertificateError::ApplicationVerificationFailure,
            ));
        }
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, Error> {
        self.inner.verify_tls12_signature(message, cert, dss)
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, Error> {
        self.inner.verify_tls13_signature(message, cert, dss)
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.inner.supported_verify_schemes()
    }
}
