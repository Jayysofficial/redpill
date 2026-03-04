//! TLS Reality: active probe deflection for TCP transport.
//!
//! TLS handshake → read first message → VPN ClientAuth? tunnel : proxy to target.
//! Non-VPN probes get transparently proxied to a real website (e.g. google.com),
//! so the server looks like a normal HTTPS reverse proxy to outside observers.

use std::net::Ipv4Addr;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio_rustls::TlsAcceptor;
use tracing::{error, info, warn};

use crate::auth::Authenticator;
use crate::control::{ClientAuth, SessionConfig, CLIENT_AUTH_LEN};
use crate::ip_pool::IpPool;

/// Configuration for handling a TCP Reality connection.
pub struct RealityConnectionConfig<'a> {
    pub tls_acceptor: TlsAcceptor,
    pub auth: &'a dyn Authenticator,
    pub pool: &'a parking_lot::Mutex<IpPool>,
    pub server_ip: Ipv4Addr,
    pub dns_ip: Ipv4Addr,
    pub mtu: u32,
    pub target: &'a str,
}

/// Result of handling a TCP Reality connection.
pub enum RealityResult {
    /// VPN client authenticated successfully.
    Vpn {
        client_ip: Ipv4Addr,
        username: String,
        stream: Box<tokio_rustls::server::TlsStream<TcpStream>>,
    },
    /// Connection was proxied to target (active probe or non-VPN).
    Proxied,
    /// Error during handling.
    Error(String),
}

/// Handle a new TCP connection using the Reality protocol.
///
/// 1. Accept TLS
/// 2. Read first bytes to check for VPN ClientAuth
/// 3. VPN → authenticate and return stream for VPN tunnel
/// 4. Not VPN → proxy bidirectionally to the target
pub async fn handle_tcp_connection(
    stream: TcpStream,
    config: &RealityConnectionConfig<'_>,
) -> RealityResult {
    let RealityConnectionConfig {
        ref tls_acceptor,
        auth,
        pool,
        server_ip,
        dns_ip,
        mtu,
        target,
    } = *config;
    let remote = stream
        .peer_addr()
        .map(|a| a.to_string())
        .unwrap_or_else(|_| "unknown".into());

    // Do NOT set SO_RCVBUF/SO_SNDBUF on Linux - it disables auto-tuning
    let _ = stream.set_nodelay(true);

    let mut tls_stream = match tls_acceptor.accept(stream).await {
        Ok(s) => s,
        Err(e) => {
            warn!("[{remote}] TLS handshake failed: {e}");
            return RealityResult::Error(format!("TLS handshake: {e}"));
        }
    };
    info!("[{remote}] TLS accepted (TCP Reality)");

    let mut auth_buf = vec![0u8; CLIENT_AUTH_LEN];
    match tokio::time::timeout(
        std::time::Duration::from_secs(5),
        tls_stream.read_exact(&mut auth_buf),
    )
    .await
    {
        Ok(Ok(_)) => {}
        Ok(Err(e)) => {
            warn!("[{remote}] Failed to read first message: {e}");
            // Not a VPN client - proxy to target
            return proxy_with_initial_data(&remote, tls_stream, &auth_buf[..0], target).await;
        }
        Err(_timeout) => {
            warn!("[{remote}] Timeout reading first message - proxying to target");
            return proxy_with_initial_data(&remote, tls_stream, &auth_buf[..0], target).await;
        }
    }

    let client_auth = match ClientAuth::decode(&auth_buf) {
        Some(auth) if auth_buf[0] == crate::control::MSG_CLIENT_AUTH => auth,
        _ => {
            info!("[{remote}] Not a VPN client, proxying to target");
            return proxy_with_initial_data(&remote, tls_stream, &auth_buf, target).await;
        }
    };

    let username = match auth.verify_auth(&client_auth.nonce, &client_auth.mac) {
        Some(name) => name,
        None => {
            // Auth failed - could be active probe. Proxy to avoid detection.
            warn!("[{remote}] TCP Reality: auth failed - proxying to target");
            return proxy_with_initial_data(&remote, tls_stream, &auth_buf, target).await;
        }
    };

    info!(
        "[{remote}] TCP Reality: authenticated as '{username}' (version {})",
        client_auth.version
    );

    let client_ip = match pool.lock().allocate() {
        Some(ip) => ip,
        None => {
            error!("[{remote}] IP pool exhausted");
            return RealityResult::Error("IP pool exhausted".into());
        }
    };

    let session_config = SessionConfig {
        client_ip,
        server_ip,
        dns_ip,
        mtu: mtu as u16,
        keepalive_secs: 10,
        flags: 0, // no batching over TCP
    };
    if let Err(e) = tls_stream.write_all(&session_config.encode()).await {
        error!("[{remote}] Failed to send session config: {e}");
        pool.lock().release(client_ip);
        return RealityResult::Error(format!("write session config: {e}"));
    }

    info!("[{remote}] TCP Reality: assigned IP {client_ip}");
    RealityResult::Vpn {
        client_ip,
        username,
        stream: Box::new(tls_stream),
    }
}

async fn proxy_with_initial_data(
    remote: &str,
    mut client_stream: tokio_rustls::server::TlsStream<TcpStream>,
    initial_data: &[u8],
    target: &str,
) -> RealityResult {
    let mut target_stream = match TcpStream::connect(target).await {
        Ok(s) => s,
        Err(e) => {
            warn!("[{remote}] Failed to connect to target {target}: {e}");
            return RealityResult::Error(format!("target connect: {e}"));
        }
    };

    if !initial_data.is_empty() {
        if let Err(e) = target_stream.write_all(initial_data).await {
            warn!("[{remote}] Failed to forward initial data to target: {e}");
            return RealityResult::Error(format!("target write: {e}"));
        }
    }

    proxy_bidirectional(&mut client_stream, &mut target_stream).await;
    info!("[{remote}] TCP Reality proxy session ended");
    RealityResult::Proxied
}

async fn proxy_bidirectional(
    client: &mut tokio_rustls::server::TlsStream<TcpStream>,
    target: &mut TcpStream,
) {
    let (mut client_read, mut client_write) = tokio::io::split(client);
    let (mut target_read, mut target_write) = tokio::io::split(target);

    let c2t = tokio::io::copy(&mut client_read, &mut target_write);
    let t2c = tokio::io::copy(&mut target_read, &mut client_write);

    tokio::select! {
        r = c2t => { if let Err(e) = r { tracing::debug!("c2t proxy ended: {e}"); } }
        r = t2c => { if let Err(e) = r { tracing::debug!("t2c proxy ended: {e}"); } }
    }
}
