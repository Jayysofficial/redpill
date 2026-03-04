//! Browser TLS/QUIC fingerprint profiles for DPI evasion.
//!
//! Cipher suites, key exchange groups, and QUIC transport parameters
//! tuned to match real browsers (Chrome/Firefox/Safari).
//! Data from <https://tls.peet.ws/> and JA3/JA4 fingerprint dumps.

use std::time::Duration;

/// Browser profile for TLS/QUIC fingerprint mimicry.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BrowserProfile {
    /// Google Chrome 120+ (default - most common QUIC client)
    Chrome,
    /// Mozilla Firefox 120+
    Firefox,
    /// Apple Safari 17+
    Safari,
    /// Randomly select a profile per connection
    Random,
}

impl BrowserProfile {
    /// Parse from string (case-insensitive).
    pub fn parse_profile(s: &str) -> Self {
        match s.to_lowercase().as_str() {
            "chrome" => Self::Chrome,
            "firefox" => Self::Firefox,
            "safari" => Self::Safari,
            "random" => Self::Random,
            _ => Self::Chrome, // default
        }
    }

    /// Resolve `Random` to a concrete profile.
    pub fn resolve(self) -> Self {
        if self == Self::Random {
            let profiles = [Self::Chrome, Self::Firefox, Self::Safari];
            let idx = rand::random::<usize>() % profiles.len();
            profiles[idx]
        } else {
            self
        }
    }

    pub fn cipher_suites(&self) -> Vec<rustls::SupportedCipherSuite> {
        use rustls::crypto::ring::cipher_suite::*;
        match self {
            Self::Chrome => vec![
                TLS13_AES_128_GCM_SHA256,
                TLS13_AES_256_GCM_SHA384,
                TLS13_CHACHA20_POLY1305_SHA256,
            ],
            Self::Firefox => vec![
                TLS13_AES_128_GCM_SHA256,
                TLS13_CHACHA20_POLY1305_SHA256,
                TLS13_AES_256_GCM_SHA384,
            ],
            Self::Safari => vec![
                TLS13_AES_128_GCM_SHA256,
                TLS13_AES_256_GCM_SHA384,
                TLS13_CHACHA20_POLY1305_SHA256,
            ],
            Self::Random => self.resolve().cipher_suites(),
        }
    }

    pub fn kx_groups(&self) -> Vec<&'static dyn rustls::crypto::SupportedKxGroup> {
        use rustls::crypto::ring::kx_group::*;
        match self {
            Self::Chrome => vec![X25519, SECP256R1, SECP384R1],
            Self::Firefox => vec![X25519, SECP256R1, SECP384R1],
            // Safari: Apple CryptoKit optimized for P-256
            Self::Safari => vec![SECP256R1, X25519, SECP384R1],
            Self::Random => self.resolve().kx_groups(),
        }
    }

    /// Get QUIC transport parameters matching this browser's real values.
    pub fn quic_transport_params(&self) -> QuicTransportParams {
        match self {
            Self::Chrome => QuicTransportParams {
                initial_max_data: 10 * 1024 * 1024,                   // 10 MB
                initial_max_stream_data_bidi_local: 6 * 1024 * 1024,  // 6 MB
                initial_max_stream_data_bidi_remote: 6 * 1024 * 1024, // 6 MB
                initial_max_stream_data_uni: 6 * 1024 * 1024,         // 6 MB
                initial_max_streams_bidi: 100,
                initial_max_streams_uni: 100,
                max_idle_timeout: Duration::from_secs(30),
                max_udp_payload_size: 1350,
            },
            Self::Firefox => QuicTransportParams {
                initial_max_data: 16 * 1024 * 1024, // 16 MB
                initial_max_stream_data_bidi_local: 8 * 1024 * 1024,
                initial_max_stream_data_bidi_remote: 8 * 1024 * 1024,
                initial_max_stream_data_uni: 8 * 1024 * 1024,
                initial_max_streams_bidi: 128,
                initial_max_streams_uni: 128,
                max_idle_timeout: Duration::from_secs(30),
                max_udp_payload_size: 1472,
            },
            Self::Safari => QuicTransportParams {
                initial_max_data: 8 * 1024 * 1024,
                initial_max_stream_data_bidi_local: 4 * 1024 * 1024,
                initial_max_stream_data_bidi_remote: 4 * 1024 * 1024,
                initial_max_stream_data_uni: 4 * 1024 * 1024,
                initial_max_streams_bidi: 100,
                initial_max_streams_uni: 100,
                max_idle_timeout: Duration::from_secs(30),
                max_udp_payload_size: 1250,
            },
            Self::Random => self.resolve().quic_transport_params(),
        }
    }
}

/// QUIC transport parameters matching a real browser.
pub struct QuicTransportParams {
    pub initial_max_data: u64,
    pub initial_max_stream_data_bidi_local: u64,
    pub initial_max_stream_data_bidi_remote: u64,
    pub initial_max_stream_data_uni: u64,
    pub initial_max_streams_bidi: u64,
    pub initial_max_streams_uni: u64,
    pub max_idle_timeout: Duration,
    pub max_udp_payload_size: u16,
}

/// Generate a GREASE value (0x?A?A pattern).
///
/// Real browsers include random GREASE values; their absence is a strong
/// signal of non-browser clients.
pub fn grease_value() -> u16 {
    let idx = rand::random::<u8>() % 16;
    let nibble = idx as u16;
    (nibble << 12) | (0x0A << 8) | (nibble << 4) | 0x0A
}

/// Generate a GREASE cipher suite value (RFC 8701).
pub fn grease_cipher_suite() -> u16 {
    const GREASE_VALUES: [u16; 8] = [
        0x0A0A, 0x1A1A, 0x2A2A, 0x3A3A, 0x4A4A, 0x5A5A, 0x6A6A, 0x7A7A,
    ];
    GREASE_VALUES[rand::random::<usize>() % GREASE_VALUES.len()]
}
