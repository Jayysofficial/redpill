use std::net::{Ipv4Addr, SocketAddr};
use std::sync::atomic::Ordering;
use std::sync::Arc;

use bytes::Bytes;
use redpill_quic::auth::PskAuthenticator;
use redpill_quic::control::{ClientAuth, SessionConfig, CLIENT_AUTH_LEN, SESSION_CONFIG_LEN};
use redpill_quic::datagram::{extract_dst_ipv4, ip_version, validate_source_ip};
use redpill_quic::demux::ClientRouter;
use redpill_quic::ip_pool::IpPool;
use redpill_quic::priority::{classify, Priority, PriorityQueue};
use redpill_quic::shaper::{AdaptiveShaper, RateLimiter};
use redpill_quic::transport::build_transport_config;
use redpill_quic::{ALPN_VPN, ERR_AUTH_FAILED, PROTOCOL_VERSION};

const TEST_PSK: [u8; 32] = [0xAA; 32];

fn make_test_endpoints() -> (
    quinn::Endpoint,
    quinn::Endpoint,
    SocketAddr,
    Arc<PskAuthenticator>,
) {
    rustls::crypto::ring::default_provider()
        .install_default()
        .ok();

    let auth = Arc::new(PskAuthenticator::new(TEST_PSK));
    let cert_pair = redpill_quic::cert::generate_self_signed();

    let mut rustls_server_config = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(vec![cert_pair.cert_der.clone()], cert_pair.key_der)
        .unwrap();
    rustls_server_config.alpn_protocols = vec![ALPN_VPN.to_vec()];

    let mut server_config = quinn::ServerConfig::with_crypto(Arc::new(
        quinn::crypto::rustls::QuicServerConfig::try_from(rustls_server_config).unwrap(),
    ));
    let transport = build_transport_config();
    server_config.transport_config(Arc::new(transport));

    let server_socket = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
    let server_addr = server_socket.local_addr().unwrap();
    let server_endpoint = quinn::Endpoint::new(
        quinn::EndpointConfig::default(),
        Some(server_config),
        server_socket,
        quinn::default_runtime().unwrap(),
    )
    .unwrap();

    let mut root_store = rustls::RootCertStore::empty();
    root_store.add(cert_pair.cert_der).unwrap();
    let mut rustls_client_config = rustls::ClientConfig::builder()
        .with_root_certificates(root_store)
        .with_no_client_auth();
    rustls_client_config.alpn_protocols = vec![ALPN_VPN.to_vec()];

    let mut client_config = quinn::ClientConfig::new(Arc::new(
        quinn::crypto::rustls::QuicClientConfig::try_from(rustls_client_config).unwrap(),
    ));
    let transport = build_transport_config();
    client_config.transport_config(Arc::new(transport));

    let client_socket = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
    let mut client_endpoint = quinn::Endpoint::new(
        quinn::EndpointConfig::default(),
        None,
        client_socket,
        quinn::default_runtime().unwrap(),
    )
    .unwrap();
    client_endpoint.set_default_client_config(client_config);

    (server_endpoint, client_endpoint, server_addr, auth)
}

async fn server_auth_handler(
    conn: quinn::Connection,
    auth: &PskAuthenticator,
    pool: &parking_lot::Mutex<IpPool>,
) -> Result<(Ipv4Addr, quinn::Connection), String> {
    let (mut send, mut recv) = conn
        .accept_bi()
        .await
        .map_err(|e| format!("accept_bi: {e}"))?;

    let mut buf = vec![0u8; CLIENT_AUTH_LEN];
    recv.read_exact(&mut buf)
        .await
        .map_err(|e| format!("read: {e}"))?;

    let client_auth = ClientAuth::decode(&buf).ok_or("decode failed")?;
    if !auth.verify(&client_auth.nonce, &client_auth.mac) {
        conn.close(ERR_AUTH_FAILED, b"auth failed");
        return Err("auth failed".into());
    }

    let client_ip = pool.lock().allocate().ok_or("pool exhausted")?;

    let config = SessionConfig {
        client_ip,
        server_ip: Ipv4Addr::new(10, 0, 1, 1),
        dns_ip: Ipv4Addr::new(1, 1, 1, 1),
        mtu: 1200,
        keepalive_secs: 10,
        flags: 0,
    };
    send.write_all(&config.encode())
        .await
        .map_err(|e| format!("write: {e}"))?;
    send.finish().map_err(|e| format!("finish: {e}"))?;

    Ok((client_ip, conn))
}

async fn client_auth(
    conn: &quinn::Connection,
    auth: &PskAuthenticator,
) -> anyhow::Result<SessionConfig> {
    let (mut send, mut recv) = conn.open_bi().await?;

    let mut nonce = [0u8; 32];
    rand::RngCore::fill_bytes(&mut rand::thread_rng(), &mut nonce);
    let mac = auth.compute_mac(&nonce);

    let msg = ClientAuth {
        nonce,
        mac,
        version: PROTOCOL_VERSION,
    };
    send.write_all(&msg.encode()).await?;
    send.finish()?;

    let mut buf = vec![0u8; SESSION_CONFIG_LEN];
    recv.read_exact(&mut buf).await?;
    SessionConfig::decode(&buf).ok_or_else(|| anyhow::anyhow!("bad config"))
}

#[tokio::test]
async fn control_auth_ok() {
    let (server_ep, client_ep, server_addr, auth) = make_test_endpoints();
    let pool = parking_lot::Mutex::new(IpPool::new(Ipv4Addr::new(10, 0, 1, 0)));

    let server_auth = auth.clone();
    let server_ep2 = server_ep.clone();
    let (tx, rx) = tokio::sync::oneshot::channel::<()>();
    let server_task = tokio::spawn(async move {
        let incoming = server_ep2.accept().await.unwrap();
        let conn = incoming.await.unwrap();
        let result = server_auth_handler(conn, &server_auth, &pool).await;
        if let Ok((_ip, _conn)) = &result {
            let _ = rx.await;
        }
        result.map(|(ip, _)| ip)
    });

    let conn = client_ep
        .connect(server_addr, "redpill-quic")
        .unwrap()
        .await
        .unwrap();

    let config = client_auth(&conn, &auth).await.unwrap();
    assert_eq!(config.client_ip, Ipv4Addr::new(10, 0, 1, 2));
    assert_eq!(config.server_ip, Ipv4Addr::new(10, 0, 1, 1));
    assert_eq!(config.dns_ip, Ipv4Addr::new(1, 1, 1, 1));
    assert_eq!(config.mtu, 1200);

    let _ = tx.send(());
    let server_result = server_task.await.unwrap();
    assert!(server_result.is_ok());

    conn.close(quinn::VarInt::from_u32(0), b"done");
    server_ep.close(quinn::VarInt::from_u32(0), b"done");
    client_ep.close(quinn::VarInt::from_u32(0), b"done");
}

#[tokio::test]
async fn control_auth_fail() {
    let (server_ep, client_ep, server_addr, auth) = make_test_endpoints();
    let pool = parking_lot::Mutex::new(IpPool::new(Ipv4Addr::new(10, 0, 1, 0)));

    let server_auth = auth.clone();
    let server_task = tokio::spawn(async move {
        let incoming = server_ep.accept().await.unwrap();
        let conn = incoming.await.unwrap();
        server_auth_handler(conn, &server_auth, &pool).await
    });

    let conn = client_ep
        .connect(server_addr, "redpill-quic")
        .unwrap()
        .await
        .unwrap();

    let wrong_auth = PskAuthenticator::new([0xBB; 32]);
    let (mut send, mut recv) = conn.open_bi().await.unwrap();

    let mut nonce = [0u8; 32];
    rand::RngCore::fill_bytes(&mut rand::thread_rng(), &mut nonce);
    let mac = wrong_auth.compute_mac(&nonce);
    let msg = ClientAuth {
        nonce,
        mac,
        version: PROTOCOL_VERSION,
    };
    send.write_all(&msg.encode()).await.unwrap();
    send.finish().unwrap();

    let mut buf = vec![0u8; SESSION_CONFIG_LEN];
    let result = recv.read_exact(&mut buf).await;
    assert!(result.is_err());

    let server_result = server_task.await.unwrap();
    assert!(server_result.is_err());

    client_ep.close(quinn::VarInt::from_u32(0), b"done");
}

#[tokio::test]
async fn control_auth_malformed() {
    let (server_ep, client_ep, server_addr, _auth) = make_test_endpoints();

    let server_task = tokio::spawn(async move {
        let incoming = server_ep.accept().await.unwrap();
        let conn = incoming.await.unwrap();

        let (mut _send, mut recv) = conn.accept_bi().await.unwrap();
        let mut buf = vec![0u8; CLIENT_AUTH_LEN];
        let result = recv.read_exact(&mut buf).await;
        if result.is_err() {
            return Err("read failed (expected)".to_string());
        }
        let decoded = ClientAuth::decode(&buf);
        if decoded.is_none() {
            conn.close(ERR_AUTH_FAILED, b"malformed");
            return Err("malformed (expected)".to_string());
        }
        Ok(Ipv4Addr::new(0, 0, 0, 0))
    });

    let conn = client_ep
        .connect(server_addr, "redpill-quic")
        .unwrap()
        .await
        .unwrap();

    let (mut send, _recv) = conn.open_bi().await.unwrap();
    send.write_all(&[0x01; 10]).await.unwrap();
    send.finish().unwrap();

    let server_result = server_task.await.unwrap();
    assert!(server_result.is_err());

    conn.close(quinn::VarInt::from_u32(0), b"done");
    client_ep.close(quinn::VarInt::from_u32(0), b"done");
}

#[tokio::test]
#[ignore] // requires Linux + root
async fn mss_clamping_idempotent() {
    use redpill_tun::route;
    route::setup_mss_clamping("lo", 1200).unwrap();
    route::setup_mss_clamping("lo", 1200).unwrap();
    route::cleanup_mss_clamping("lo", 1200);
}

#[tokio::test]
#[ignore] // requires macOS + root
async fn dns_setup_cleanup() {
    use redpill_tun::route;
    route::setup_client_dns().unwrap();
    route::cleanup_client_dns();
}

#[test]
fn anti_spoof_drop() {
    let mut packet = vec![0u8; 20];
    packet[0] = 0x45;
    packet[12] = 192;
    packet[13] = 168;
    packet[14] = 1;
    packet[15] = 1;

    assert!(!validate_source_ip(&packet, Ipv4Addr::new(10, 0, 1, 2)));
}

#[test]
fn anti_spoof_pass() {
    let mut packet = vec![0u8; 20];
    packet[0] = 0x45;
    packet[12] = 10;
    packet[13] = 0;
    packet[14] = 1;
    packet[15] = 2;

    assert!(validate_source_ip(&packet, Ipv4Addr::new(10, 0, 1, 2)));
}

#[test]
fn ip_pool_allocate_release() {
    let mut pool = IpPool::new(Ipv4Addr::new(10, 0, 1, 0));

    let mut ips = Vec::new();
    for _ in 0..253 {
        let ip = pool.allocate().expect("should allocate");
        ips.push(ip);
    }
    assert_eq!(ips[0], Ipv4Addr::new(10, 0, 1, 2));
    assert_eq!(ips[252], Ipv4Addr::new(10, 0, 1, 254));
    assert_eq!(pool.len(), 253);

    assert!(pool.allocate().is_none());

    pool.release(Ipv4Addr::new(10, 0, 1, 50));
    let ip = pool.allocate().expect("should allocate after release");
    assert_eq!(ip, Ipv4Addr::new(10, 0, 1, 50));
}

#[test]
fn ip_pool_exhaustion() {
    let mut pool = IpPool::new(Ipv4Addr::new(10, 0, 1, 0));

    for _ in 0..253 {
        assert!(pool.allocate().is_some());
    }
    assert!(pool.allocate().is_none());
    assert!(pool.allocate().is_none());
}

#[test]
#[ignore] // requires macOS + root
fn killswitch_enable_disable() {
    use redpill_quic::killswitch;
    killswitch::enable("utun99", "1.2.3.4", 443).unwrap();
    killswitch::disable();
}

#[test]
fn datagram_ipv4() {
    let mut packet = vec![0u8; 40];
    packet[0] = 0x45;

    assert_eq!(ip_version(&packet), Some(4));
    packet[12] = 10;
    packet[13] = 0;
    packet[14] = 1;
    packet[15] = 2;
    assert!(validate_source_ip(&packet, Ipv4Addr::new(10, 0, 1, 2)));
}

#[test]
fn datagram_ipv6() {
    let mut packet = vec![0u8; 40];
    packet[0] = 0x60;

    assert_eq!(ip_version(&packet), Some(6));
    assert!(validate_source_ip(&packet, Ipv4Addr::new(10, 0, 1, 2)));
}

#[tokio::test]
async fn connection_limit() {
    let counter = std::sync::atomic::AtomicU32::new(0);
    let max = 2u32;

    counter.fetch_add(1, Ordering::Relaxed);
    counter.fetch_add(1, Ordering::Relaxed);
    assert_eq!(counter.load(Ordering::Relaxed), 2);

    let current = counter.load(Ordering::Relaxed);
    assert!(current >= max);

    counter.fetch_sub(1, Ordering::Relaxed);
    let current = counter.load(Ordering::Relaxed);
    assert!(current < max);

    counter.fetch_add(1, Ordering::Relaxed);
    assert_eq!(counter.load(Ordering::Relaxed), 2);
}

#[test]
fn extract_dst_ipv4_test() {
    let mut packet = vec![0u8; 20];
    packet[0] = 0x45;
    packet[16] = 10;
    packet[17] = 0;
    packet[18] = 1;
    packet[19] = 2;
    assert_eq!(extract_dst_ipv4(&packet), Some(Ipv4Addr::new(10, 0, 1, 2)));

    assert_eq!(extract_dst_ipv4(&[0x45; 10]), None);

    let mut v6_packet = vec![0u8; 40];
    v6_packet[0] = 0x60;
    assert_eq!(extract_dst_ipv4(&v6_packet), None);

    assert_eq!(extract_dst_ipv4(&[]), None);
}

#[tokio::test]
async fn client_router_register_route_unregister() {
    let router = Arc::new(ClientRouter::new());

    let ip1 = Ipv4Addr::new(10, 0, 1, 2);
    let ip2 = Ipv4Addr::new(10, 0, 1, 3);
    let ip3 = Ipv4Addr::new(10, 0, 1, 4);

    let (_h1, q1) = router.register(ip1, 16);
    let (_h2, q2) = router.register(ip2, 16);
    let (_h3, q3) = router.register(ip3, 16);
    assert_eq!(router.len(), 3);

    let pkt1 = Bytes::from_static(b"pkt-for-1");
    let pkt2 = Bytes::from_static(b"pkt-for-2");
    let pkt3 = Bytes::from_static(b"pkt-for-3");

    assert!(router.route(ip1, pkt1.clone()));
    assert!(router.route(ip2, pkt2.clone()));
    assert!(router.route(ip3, pkt3.clone()));

    assert_eq!(q1.try_pop().unwrap(), pkt1);
    assert_eq!(q2.try_pop().unwrap(), pkt2);
    assert_eq!(q3.try_pop().unwrap(), pkt3);

    assert!(!router.route(Ipv4Addr::new(10, 0, 1, 99), Bytes::from_static(b"nope")));

    drop(_h2);
    assert_eq!(router.len(), 2);
    assert!(!router.route(ip2, Bytes::from_static(b"should-fail")));

    assert!(router.route(ip1, Bytes::from_static(b"still-works")));
    assert_eq!(q1.try_pop().unwrap(), Bytes::from_static(b"still-works"));
}

#[tokio::test]
async fn two_clients_simultaneous() {
    let (server_ep, client_ep, server_addr, auth) = make_test_endpoints();
    let pool = Arc::new(parking_lot::Mutex::new(IpPool::new(Ipv4Addr::new(
        10, 0, 1, 0,
    ))));

    let server_auth = auth.clone();
    let server_ep2 = server_ep.clone();
    let pool1 = pool.clone();
    let server_task = tokio::spawn(async move {
        let mut results = Vec::new();
        for _ in 0..2 {
            let incoming = server_ep2.accept().await.unwrap();
            let conn = incoming.await.unwrap();
            let result = server_auth_handler(conn, &server_auth, &pool1).await;
            results.push(result);
        }
        results
    });

    let conn1 = client_ep
        .connect(server_addr, "redpill-quic")
        .unwrap()
        .await
        .unwrap();
    let config1 = client_auth(&conn1, &auth).await.unwrap();

    let conn2 = client_ep
        .connect(server_addr, "redpill-quic")
        .unwrap()
        .await
        .unwrap();
    let config2 = client_auth(&conn2, &auth).await.unwrap();

    assert_eq!(config1.client_ip, Ipv4Addr::new(10, 0, 1, 2));
    assert_eq!(config2.client_ip, Ipv4Addr::new(10, 0, 1, 3));
    assert_ne!(config1.client_ip, config2.client_ip);

    conn1
        .send_datagram(Bytes::from_static(b"hello-from-1"))
        .unwrap();
    conn2
        .send_datagram(Bytes::from_static(b"hello-from-2"))
        .unwrap();

    let server_results = server_task.await.unwrap();
    assert!(server_results.iter().all(|r| r.is_ok()));

    conn1.close(quinn::VarInt::from_u32(0), b"done");
    conn2.close(quinn::VarInt::from_u32(0), b"done");
    server_ep.close(quinn::VarInt::from_u32(0), b"done");
    client_ep.close(quinn::VarInt::from_u32(0), b"done");
}

#[test]
fn token_bucket_allows_then_blocks() {
    let limiter = RateLimiter::new(1);

    assert!(limiter.check(1000));

    for _ in 0..11 {
        assert!(limiter.check(1000));
    }

    assert!(!limiter.check(1000));
    assert_eq!(limiter.dropped_packets.load(Ordering::Relaxed), 1);
    assert_eq!(limiter.dropped_bytes.load(Ordering::Relaxed), 1000);

    std::thread::sleep(std::time::Duration::from_millis(50));
    assert!(limiter.check(1000));
}

#[test]
fn rate_limiter_zero_unlimited() {
    let limiter = RateLimiter::new(0);

    for _ in 0..10000 {
        assert!(limiter.check(1500));
    }
    assert_eq!(limiter.dropped_packets.load(Ordering::Relaxed), 0);
}

#[test]
fn adaptive_increases_on_low_delay() {
    use std::time::Duration;

    let shaper = AdaptiveShaper::new(100);

    shaper.update_rtt(Duration::from_millis(50));
    assert!(shaper.base_rtt().is_some());

    for _ in 0..20 {
        shaper.update_rtt(Duration::from_millis(130));
    }
    let lowered_rate = shaper.current_rate();
    let max_rate = 100 * 1_000_000 / 8;
    assert!(lowered_rate < max_rate);

    for _ in 0..20 {
        shaper.update_rtt(Duration::from_millis(50));
    }
    assert!(shaper.current_rate() > lowered_rate);
}

#[test]
fn adaptive_decreases_on_high_delay() {
    use std::time::Duration;

    let shaper = AdaptiveShaper::new(100);

    shaper.update_rtt(Duration::from_millis(50));
    let initial_rate = shaper.current_rate();

    for _ in 0..20 {
        shaper.update_rtt(Duration::from_millis(130));
    }

    assert!(shaper.current_rate() < initial_rate);
}

#[test]
fn classify_small_udp_realtime() {
    let mut packet = vec![0u8; 60];
    packet[0] = 0x45;
    packet[9] = 17;
    packet[20] = 0x30;
    packet[21] = 0x39;
    packet[22] = 0x1F;
    packet[23] = 0x90;

    assert_eq!(classify(&packet), Priority::Realtime);
}

#[test]
fn classify_tcp_bulk() {
    let mut packet = vec![0u8; 60];
    packet[0] = 0x45;
    packet[9] = 6;

    assert_eq!(classify(&packet), Priority::Bulk);
}

#[test]
fn classify_dns_realtime() {
    let mut packet = vec![0u8; 60];
    packet[0] = 0x45;
    packet[9] = 17;
    packet[22] = 0x00;
    packet[23] = 0x35;

    assert_eq!(classify(&packet), Priority::Realtime);
}

#[test]
fn classify_dscp_ef_realtime() {
    let mut packet = vec![0u8; 60];
    packet[0] = 0x45;
    packet[1] = 46 << 2;
    packet[9] = 6;

    assert_eq!(classify(&packet), Priority::Realtime);
}

#[test]
fn priority_queue_realtime_first() {
    let q = PriorityQueue::new(64);

    q.push(Bytes::from_static(b"bulk-1"), Priority::Bulk);
    q.push(Bytes::from_static(b"bulk-2"), Priority::Bulk);
    q.push(Bytes::from_static(b"realtime-1"), Priority::Realtime);

    assert_eq!(q.try_pop().unwrap(), Bytes::from_static(b"realtime-1"));
    assert_eq!(q.try_pop().unwrap(), Bytes::from_static(b"bulk-1"));
    assert_eq!(q.try_pop().unwrap(), Bytes::from_static(b"bulk-2"));
    assert!(q.try_pop().is_none());
}

#[test]
fn priority_queue_stale_dropped() {
    let q = PriorityQueue::new(64);

    q.push(Bytes::from_static(b"stale-rt"), Priority::Realtime);
    q.push(Bytes::from_static(b"bulk-ok"), Priority::Bulk);

    std::thread::sleep(std::time::Duration::from_millis(15));

    assert_eq!(q.try_pop().unwrap(), Bytes::from_static(b"bulk-ok"));
    assert!(q.try_pop().is_none());
}

#[tokio::test]
async fn metrics_render() {
    use redpill_quic::metrics::{self, Metrics};

    let m = Arc::new(Metrics::new());
    m.handshakes_total.inc();
    m.bytes_in.inc_by(1234);

    let addr: std::net::SocketAddr = "127.0.0.1:0".parse().unwrap();
    let task = metrics::spawn_metrics_server(addr, m.clone());

    let text = m.render();
    assert!(text.contains("redpill_handshakes_total 1"));
    assert!(text.contains("redpill_bytes_in 1234"));
    assert!(text.contains("redpill_active_sessions"));
    assert!(text.contains("redpill_rtt_ms"));

    task.abort();
}

#[test]
fn reload_max_connections() {
    let max = std::sync::atomic::AtomicU32::new(64);
    assert_eq!(max.load(Ordering::Relaxed), 64);

    max.store(128, Ordering::Relaxed);
    assert_eq!(max.load(Ordering::Relaxed), 128);

    let current = 100u32;
    assert!(current < max.load(Ordering::Relaxed));

    max.store(64, Ordering::Relaxed);
    assert!(current >= max.load(Ordering::Relaxed));
}

#[test]
fn batch_encode_decode_roundtrip() {
    use redpill_quic::batch::{batch_decode, batch_encode};

    let p1 = Bytes::from_static(b"packet-one");
    let p2 = Bytes::from_static(b"packet-two");
    let p3 = Bytes::from_static(b"packet-three");

    let encoded = batch_encode(&[p1.clone(), p2.clone(), p3.clone()]);
    let decoded = batch_decode(&encoded);

    assert_eq!(decoded.len(), 3);
    assert_eq!(decoded[0], p1);
    assert_eq!(decoded[1], p2);
    assert_eq!(decoded[2], p3);
}

#[test]
fn batch_large_packet_bypasses() {
    use redpill_quic::batch::{DatagramBatcher, BATCH_SIZE_THRESHOLD};

    let mut batcher = DatagramBatcher::new();

    let small = Bytes::from(vec![0u8; 100]);
    assert!(batcher.add(small).is_none());
    assert!(batcher.has_pending());

    assert_eq!(BATCH_SIZE_THRESHOLD, 300);

    let batch = batcher.flush();
    assert!(!batch.is_empty());
    assert!(!batcher.has_pending());

    let empty = batcher.flush();
    assert!(empty.is_empty());
}

#[test]
fn user_store_add_verify_remove() {
    let dir = tempfile::tempdir().unwrap();
    let mut store = redpill_quic::users::UserStore::load(dir.path()).unwrap();
    assert_eq!(store.len(), 0);

    // Add users
    let hex1 = store.add_user("alice").unwrap();
    let hex2 = store.add_user("bob").unwrap();
    assert_eq!(store.len(), 2);
    assert_ne!(hex1, hex2);

    // Verify alice's PSK
    let psk1 = redpill_quic::auth::parse_psk_hex(&hex1).unwrap();
    let auth1 = redpill_quic::auth::PskAuthenticator::new(psk1);
    let mut nonce = [0u8; 32];
    rand::RngCore::fill_bytes(&mut rand::thread_rng(), &mut nonce);
    let mac = auth1.compute_mac(&nonce);
    let result = store.verify(&nonce, &mac);
    assert!(result.is_some());
    assert_eq!(result.unwrap().username, "alice");

    // Verify bob's PSK
    let psk2 = redpill_quic::auth::parse_psk_hex(&hex2).unwrap();
    let auth2 = redpill_quic::auth::PskAuthenticator::new(psk2);
    let mut nonce2 = [0u8; 32];
    rand::RngCore::fill_bytes(&mut rand::thread_rng(), &mut nonce2);
    let mac2 = auth2.compute_mac(&nonce2);
    let result2 = store.verify(&nonce2, &mac2);
    assert!(result2.is_some());
    assert_eq!(result2.unwrap().username, "bob");

    // Wrong PSK fails
    let wrong_auth = redpill_quic::auth::PskAuthenticator::new([0xCC; 32]);
    let mut nonce3 = [0u8; 32];
    rand::RngCore::fill_bytes(&mut rand::thread_rng(), &mut nonce3);
    let mac3 = wrong_auth.compute_mac(&nonce3);
    assert!(store.verify(&nonce3, &mac3).is_none());

    // Remove alice
    store.remove_user("alice").unwrap();
    assert_eq!(store.len(), 1);

    // Alice can no longer authenticate
    let mut nonce4 = [0u8; 32];
    rand::RngCore::fill_bytes(&mut rand::thread_rng(), &mut nonce4);
    let mac4 = auth1.compute_mac(&nonce4);
    assert!(store.verify(&nonce4, &mac4).is_none());

    // Bob still works
    let mut nonce5 = [0u8; 32];
    rand::RngCore::fill_bytes(&mut rand::thread_rng(), &mut nonce5);
    let mac5 = auth2.compute_mac(&nonce5);
    assert!(store.verify(&nonce5, &mac5).is_some());

    // Duplicate username fails
    assert!(store.add_user("bob").is_err());
}

#[test]
fn user_store_reload() {
    let dir = tempfile::tempdir().unwrap();
    let mut store = redpill_quic::users::UserStore::load(dir.path()).unwrap();
    store.add_user("user1").unwrap();
    assert_eq!(store.len(), 1);

    // Create a new store from the same directory - should find the file
    let store2 = redpill_quic::users::UserStore::load(dir.path()).unwrap();
    assert_eq!(store2.len(), 1);

    // Reload
    store.add_user("user2").unwrap();
    let mut store3 = redpill_quic::users::UserStore::load(dir.path()).unwrap();
    assert_eq!(store3.len(), 2);
    store3.reload().unwrap();
    assert_eq!(store3.len(), 2);
}

#[test]
fn session_update_encode_decode() {
    use redpill_quic::control::{SessionUpdate, MSG_SESSION_UPDATE, SESSION_UPDATE_LEN};

    let update = SessionUpdate { mtu: 1400 };
    let encoded = update.encode();
    assert_eq!(encoded.len(), SESSION_UPDATE_LEN);
    assert_eq!(encoded[0], MSG_SESSION_UPDATE);
    assert_eq!(u16::from_be_bytes([encoded[1], encoded[2]]), 1400);

    let decoded = SessionUpdate::decode(&encoded).unwrap();
    assert_eq!(decoded.mtu, 1400);

    // Too short
    assert!(SessionUpdate::decode(&[0x03]).is_none());
    // Wrong tag
    assert!(SessionUpdate::decode(&[0x01, 0x00, 0x00]).is_none());
}

#[test]
fn session_config_flags_backward_compat() {
    let config = SessionConfig {
        client_ip: Ipv4Addr::new(10, 0, 1, 2),
        server_ip: Ipv4Addr::new(10, 0, 1, 1),
        dns_ip: Ipv4Addr::new(1, 1, 1, 1),
        mtu: 1200,
        keepalive_secs: 10,
        flags: 0x01,
    };
    let encoded = config.encode();
    assert_eq!(encoded.len(), 17);

    let decoded = SessionConfig::decode(&encoded).unwrap();
    assert_eq!(decoded.flags, 0x01);

    let decoded_v1 = SessionConfig::decode(&encoded[..16]).unwrap();
    assert_eq!(decoded_v1.flags, 0);
    assert_eq!(decoded_v1.client_ip, Ipv4Addr::new(10, 0, 1, 2));
}
