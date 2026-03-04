//! HTTP/3 decoy: serve a static HTML page to look like nginx.
//!
//! Connections with ALPN "h3" get a normal web page (active probe resistance).

use tracing::{info, warn};

const DEFAULT_HTML: &str = r#"<!DOCTYPE html>
<html>
<head><title>Welcome to nginx!</title>
<style>
body { width: 35em; margin: 0 auto; font-family: Tahoma, Verdana, Arial, sans-serif; }
</style>
</head>
<body>
<h1>Welcome to nginx!</h1>
<p>If you see this page, the nginx web server is successfully installed and working.</p>
<p><em>Thank you for using nginx.</em></p>
</body>
</html>"#;

/// Maximum idle time for a decoy connection before forced disconnect.
const DECOY_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(30);

/// Handle an HTTP/3 connection by serving a static page.
///
/// Times out after 30 seconds to prevent Slowloris-style resource exhaustion.
pub async fn handle_http3(conn: quinn::Connection, page_path: &str) {
    let remote = conn.remote_address();
    info!("[decoy] HTTP/3 request from {remote}");

    match tokio::time::timeout(DECOY_TIMEOUT, handle_http3_inner(&conn, page_path)).await {
        Ok(()) => {}
        Err(_) => {
            warn!(
                "[decoy] {remote} timed out after {}s",
                DECOY_TIMEOUT.as_secs()
            );
            conn.close(quinn::VarInt::from_u32(0), b"timeout");
        }
    }

    info!("[decoy] {remote} disconnected");
}

async fn handle_http3_inner(conn: &quinn::Connection, page_path: &str) {
    let remote = conn.remote_address();

    let html = match std::fs::read_to_string(page_path) {
        Ok(content) => content,
        Err(_) => DEFAULT_HTML.to_string(),
    };

    let h3_conn = h3_quinn::Connection::new(conn.clone());

    let mut h3 = match h3::server::builder().build(h3_conn).await {
        Ok(h3) => h3,
        Err(e) => {
            warn!("[decoy] H3 connection error from {remote}: {e}");
            return;
        }
    };

    loop {
        match h3.accept().await {
            Ok(Some(resolver)) => {
                let (req, mut stream) = match resolver.resolve_request().await {
                    Ok(pair) => pair,
                    Err(e) => {
                        warn!("[decoy] Resolve request error: {e}");
                        break;
                    }
                };
                info!("[decoy] {} {} from {remote}", req.method(), req.uri());

                let response = http::Response::builder()
                    .status(200)
                    .header("server", "nginx/1.24.0")
                    .header("content-type", "text/html")
                    .header("content-length", html.len().to_string())
                    .body(())
                    .unwrap();

                if let Err(e) = stream.send_response(response).await {
                    warn!("[decoy] Send response error: {e}");
                    break;
                }
                if let Err(e) = stream.send_data(bytes::Bytes::from(html.clone())).await {
                    warn!("[decoy] Send body error: {e}");
                    break;
                }
                if let Err(e) = stream.finish().await {
                    warn!("[decoy] Finish stream error: {e}");
                    break;
                }
            }
            Ok(None) => {
                break;
            }
            Err(e) => {
                warn!("[decoy] Accept error from {remote}: {e}");
                break;
            }
        }
    }
}
