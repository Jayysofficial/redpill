//! Control stream protocol: auth + session config.
//!
//! Wire format:
//!
//! ClientAuth (66 bytes):
//!   [0x01][32B nonce][32B HMAC-SHA256(psk, nonce)][1B version]
//!
//! SessionConfig (17 bytes):
//!   [0x02][4B client_ip][4B server_ip][4B dns_ip][2B mtu][1B keepalive_secs][1B flags]
//!   All multi-byte fields big-endian.
//!   Backward compat: old clients that read only 16 bytes get flags=0 implicitly.

use std::net::Ipv4Addr;

pub const MSG_CLIENT_AUTH: u8 = 0x01;
pub const MSG_SESSION_CONFIG: u8 = 0x02;
pub const MSG_SESSION_UPDATE: u8 = 0x03;

pub const CLIENT_AUTH_LEN: usize = 66; // 1 + 32 + 32 + 1
pub const SESSION_CONFIG_LEN: usize = 17; // 1 + 4 + 4 + 4 + 2 + 1 + 1
/// Legacy config length (without flags byte) for backward compat decoding.
pub const SESSION_CONFIG_LEN_V1: usize = 16;
pub const SESSION_UPDATE_LEN: usize = 3; // 1 + 2

/// Client → Server auth message.
#[derive(Debug, Clone)]
pub struct ClientAuth {
    pub nonce: [u8; 32],
    pub mac: [u8; 32],
    pub version: u8,
}

impl ClientAuth {
    /// Encode to wire format (66 bytes).
    pub fn encode(&self) -> [u8; CLIENT_AUTH_LEN] {
        let mut buf = [0u8; CLIENT_AUTH_LEN];
        buf[0] = MSG_CLIENT_AUTH;
        buf[1..33].copy_from_slice(&self.nonce);
        buf[33..65].copy_from_slice(&self.mac);
        buf[65] = self.version;
        buf
    }

    /// Decode from wire format.
    pub fn decode(data: &[u8]) -> Option<Self> {
        if data.len() < CLIENT_AUTH_LEN {
            return None;
        }
        if data[0] != MSG_CLIENT_AUTH {
            return None;
        }
        let mut nonce = [0u8; 32];
        nonce.copy_from_slice(&data[1..33]);
        let mut mac = [0u8; 32];
        mac.copy_from_slice(&data[33..65]);
        let version = data[65];
        Some(Self {
            nonce,
            mac,
            version,
        })
    }
}

/// Server → Client session configuration.
#[derive(Debug, Clone)]
pub struct SessionConfig {
    pub client_ip: Ipv4Addr,
    pub server_ip: Ipv4Addr,
    pub dns_ip: Ipv4Addr,
    pub mtu: u16,
    pub keepalive_secs: u8,
    /// Capability flags (bit 0 = batching supported). Default 0 for old clients.
    pub flags: u8,
}

impl SessionConfig {
    /// Encode to wire format (17 bytes).
    pub fn encode(&self) -> [u8; SESSION_CONFIG_LEN] {
        let mut buf = [0u8; SESSION_CONFIG_LEN];
        buf[0] = MSG_SESSION_CONFIG;
        buf[1..5].copy_from_slice(&self.client_ip.octets());
        buf[5..9].copy_from_slice(&self.server_ip.octets());
        buf[9..13].copy_from_slice(&self.dns_ip.octets());
        buf[13..15].copy_from_slice(&self.mtu.to_be_bytes());
        buf[15] = self.keepalive_secs;
        buf[16] = self.flags;
        buf
    }

    /// Decode from wire format. Accepts both 16-byte (v1) and 17-byte (v2) formats.
    pub fn decode(data: &[u8]) -> Option<Self> {
        if data.len() < SESSION_CONFIG_LEN_V1 {
            return None;
        }
        if data[0] != MSG_SESSION_CONFIG {
            return None;
        }
        let client_ip = Ipv4Addr::new(data[1], data[2], data[3], data[4]);
        let server_ip = Ipv4Addr::new(data[5], data[6], data[7], data[8]);
        let dns_ip = Ipv4Addr::new(data[9], data[10], data[11], data[12]);
        let mtu = u16::from_be_bytes([data[13], data[14]]);
        let keepalive_secs = data[15];
        let flags = if data.len() >= SESSION_CONFIG_LEN {
            data[16]
        } else {
            0 // v1 client → no flags
        };
        Some(Self {
            client_ip,
            server_ip,
            dns_ip,
            mtu,
            keepalive_secs,
            flags,
        })
    }
}

/// Server → Client session update (sent when PMTU changes).
///
/// Wire format (3 bytes): `[0x03][2B mtu BE]`
#[derive(Debug, Clone)]
pub struct SessionUpdate {
    pub mtu: u16,
}

impl SessionUpdate {
    pub fn encode(&self) -> [u8; SESSION_UPDATE_LEN] {
        let mut buf = [0u8; SESSION_UPDATE_LEN];
        buf[0] = MSG_SESSION_UPDATE;
        buf[1..3].copy_from_slice(&self.mtu.to_be_bytes());
        buf
    }

    pub fn decode(data: &[u8]) -> Option<Self> {
        if data.len() < SESSION_UPDATE_LEN {
            return None;
        }
        if data[0] != MSG_SESSION_UPDATE {
            return None;
        }
        let mtu = u16::from_be_bytes([data[1], data[2]]);
        Some(Self { mtu })
    }
}
