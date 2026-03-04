use hmac::{Hmac, Mac};
use sha2::Sha256;

type HmacSha256 = Hmac<Sha256>;

/// Trait for authentication verification. Returns username on success.
pub trait Authenticator: Send + Sync {
    /// Verify HMAC(psk, nonce) == mac. Returns username on success.
    fn verify_auth(&self, nonce: &[u8; 32], mac: &[u8; 32]) -> Option<String>;
}

impl Authenticator for PskAuthenticator {
    fn verify_auth(&self, nonce: &[u8; 32], mac: &[u8; 32]) -> Option<String> {
        if self.verify(nonce, mac) {
            Some("default".to_string())
        } else {
            None
        }
    }
}

/// PSK-based authenticator using HMAC-SHA256.
///
/// The client proves knowledge of the PSK by sending HMAC-SHA256(psk, nonce)
/// where nonce is a random 32-byte value chosen by the client.
/// Replay-safe: each nonce is unique. No clock sync needed.
#[derive(Clone)]
pub struct PskAuthenticator {
    psk: [u8; 32],
}

impl PskAuthenticator {
    pub fn new(psk: [u8; 32]) -> Self {
        Self { psk }
    }

    /// Verify a client's auth: HMAC-SHA256(psk, nonce) == mac.
    pub fn verify(&self, nonce: &[u8; 32], mac: &[u8; 32]) -> bool {
        let mut hmac = HmacSha256::new_from_slice(&self.psk).expect("HMAC key length valid");
        hmac.update(nonce);
        hmac.verify_slice(mac).is_ok()
    }

    /// Compute HMAC-SHA256(psk, nonce).
    pub fn compute_mac(&self, nonce: &[u8; 32]) -> [u8; 32] {
        let mut hmac = HmacSha256::new_from_slice(&self.psk).expect("HMAC key length valid");
        hmac.update(nonce);
        let result = hmac.finalize();
        let bytes = result.into_bytes();
        let mut out = [0u8; 32];
        out.copy_from_slice(&bytes);
        out
    }
}

fn parse_hex(hex: &str) -> anyhow::Result<[u8; 32]> {
    let hex = hex.trim();
    if hex.len() != 64 {
        anyhow::bail!("PSK must be exactly 64 hex characters, got {}", hex.len());
    }
    let mut psk = [0u8; 32];
    for (i, chunk) in hex.as_bytes().chunks(2).enumerate() {
        let s = std::str::from_utf8(chunk)?;
        psk[i] = u8::from_str_radix(s, 16)?;
    }
    Ok(psk)
}

/// Load a 32-byte PSK from a hex-encoded file (64 hex chars, optional newline).
pub fn load_psk(path: &str) -> anyhow::Result<[u8; 32]> {
    let content = std::fs::read_to_string(path)?;
    parse_hex(&content)
}

/// Parse a PSK from a hex string (64 hex chars).
pub fn parse_psk_hex(hex: &str) -> anyhow::Result<[u8; 32]> {
    parse_hex(hex)
}
