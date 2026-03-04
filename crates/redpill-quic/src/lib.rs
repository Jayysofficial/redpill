#[cfg(feature = "acme")]
pub mod acme;
pub mod auth;
pub mod batch;
pub mod browser_profile;
pub mod camouflage;
pub mod cert;
pub mod config;
pub mod control;
#[cfg(unix)]
pub mod daemon;
pub mod datagram;
pub mod decoy;
pub mod demux;
pub mod fingerprint;
pub mod ip_pool;
#[cfg(unix)]
pub mod ipc;
pub mod killswitch;
pub mod metrics;
pub mod noop_cc;
pub mod padding;
pub mod priority;
pub mod reality;
pub mod shaper;
pub mod stats;
pub mod transport;
pub mod users;
#[cfg(all(target_os = "linux", feature = "xdp"))]
pub mod xdp;

use std::time::Duration;

pub const TUN_MTU: u32 = 1200;
pub const QUIC_PORT: u16 = 443;
pub const STATS_INTERVAL: Duration = Duration::from_secs(5);
pub const PROTOCOL_VERSION: u8 = 1;
pub const MAX_TUN_BATCH: usize = 64;
pub const DATAGRAM_WAIT_TIMEOUT: Duration = Duration::from_millis(25);
pub const CLIENT_SEND_CHANNEL_SIZE: usize = 512;

pub const ALPN_VPN: &[u8] = b"redpill-vpn-1";
pub const ALPN_H3: &[u8] = b"h3";

pub const ERR_AUTH_FAILED: quinn::VarInt = quinn::VarInt::from_u32(0x01);
