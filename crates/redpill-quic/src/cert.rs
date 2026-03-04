use std::path::Path;

use rcgen::{CertificateParams, KeyPair};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};

pub struct CertPair {
    pub cert_der: CertificateDer<'static>,
    pub key_der: PrivateKeyDer<'static>,
    pub cert_pem: String,
    pub key_pem: String,
}

/// Generate a self-signed certificate.
pub fn generate_self_signed() -> CertPair {
    let mut params = CertificateParams::new(vec!["redpill-quic".into()]).unwrap();
    params.distinguished_name.push(
        rcgen::DnType::CommonName,
        rcgen::DnValue::Utf8String("redpill-quic".into()),
    );

    let key_pair = KeyPair::generate().unwrap();
    let cert = params.self_signed(&key_pair).unwrap();

    let cert_pem = cert.pem();
    let key_pem = key_pair.serialize_pem();
    let cert_der = CertificateDer::from(cert.der().to_vec());
    let key_der = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(key_pair.serialize_der()));

    CertPair {
        cert_der,
        key_der,
        cert_pem,
        key_pem,
    }
}

/// Load cert+key from files, or generate and persist them.
pub fn load_or_generate(cert_path: &str, key_path: &str) -> anyhow::Result<CertPair> {
    if Path::new(cert_path).exists() && Path::new(key_path).exists() {
        load_from_files(cert_path, key_path)
    } else {
        let pair = generate_self_signed();
        if let Some(parent) = Path::new(cert_path).parent() {
            std::fs::create_dir_all(parent)?;
        }
        std::fs::write(cert_path, &pair.cert_pem)?;
        std::fs::write(key_path, &pair.key_pem)?;
        tracing::info!("Generated and saved cert to {cert_path}, key to {key_path}");
        Ok(pair)
    }
}

/// Load existing cert+key PEM files.
pub fn load_from_files(cert_path: &str, key_path: &str) -> anyhow::Result<CertPair> {
    let cert_pem = std::fs::read_to_string(cert_path)?;
    let key_pem = std::fs::read_to_string(key_path)?;

    let cert_der = pem_to_cert_der(&cert_pem)?;
    let key_der = pem_to_key_der(&key_pem)?;

    Ok(CertPair {
        cert_der,
        key_der,
        cert_pem,
        key_pem,
    })
}

/// Parse a PEM string into a DER certificate.
pub fn pem_to_cert_der(pem: &str) -> anyhow::Result<CertificateDer<'static>> {
    let mut reader = std::io::BufReader::new(pem.as_bytes());
    let certs = rustls_pemfile::certs(&mut reader).collect::<Result<Vec<_>, _>>()?;
    certs
        .into_iter()
        .next()
        .ok_or_else(|| anyhow::anyhow!("No certificate found in PEM"))
}

/// Parse a PEM string into a DER private key.
pub fn pem_to_key_der(pem: &str) -> anyhow::Result<PrivateKeyDer<'static>> {
    let mut reader = std::io::BufReader::new(pem.as_bytes());
    let key = rustls_pemfile::private_key(&mut reader)?
        .ok_or_else(|| anyhow::anyhow!("No private key found in PEM"))?;
    Ok(key)
}
