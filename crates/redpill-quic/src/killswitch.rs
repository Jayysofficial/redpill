//! Kill-switch: prevent traffic leaks when VPN tunnel is down.
//!
//! macOS: uses pf (packet filter) with a namespaced anchor.
//! Linux: no-op (server doesn't need kill-switch).

/// Enable the kill-switch. Only VPN tunnel traffic and the connection
/// to the VPN server are allowed; everything else is blocked.
///
/// `extra_hosts` allows additional IPs through the firewall (e.g. CDN IPs
/// for WebSocket mode).
#[cfg(target_os = "macos")]
pub fn enable(tun_name: &str, server_ip: &str, port: u16) -> anyhow::Result<()> {
    enable_with_extras(tun_name, server_ip, port, &[])
}

/// Enable kill-switch with additional allowed hosts.
#[cfg(target_os = "macos")]
pub fn enable_with_extras(
    tun_name: &str,
    server_ip: &str,
    _port: u16,
    extra_hosts: &[String],
) -> anyhow::Result<()> {
    use std::io::Write;

    // Allow all traffic to the VPN server IP (any port/proto) - covers both
    // QUIC (:443) and TCP Reality (:8443/8444) without port mismatch bugs.
    let mut rules = format!(
        "pass out quick on {tun_name} all\n\
         pass out quick to {server_ip}\n\
         pass out quick on lo0 all\n"
    );
    for host in extra_hosts {
        rules.push_str(&format!("pass out quick to {host} port 443\n"));
    }
    rules.push_str("block drop out all\n");

    let path = format!("/tmp/redpill-pf-{}.conf", std::process::id());
    let mut f = std::fs::File::create(&path)?;
    f.write_all(rules.as_bytes())?;
    drop(f);

    let output = std::process::Command::new("pfctl")
        .args(["-a", "com.redpill", "-f", &path])
        .output()?;
    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        anyhow::bail!("pfctl load rules failed: {stderr}");
    }

    // Enable pf (idempotent - already enabled is not an error)
    let _ = std::process::Command::new("pfctl").arg("-E").output();

    let _ = std::fs::remove_file(&path);

    tracing::info!("Kill-switch enabled (pf anchor com.redpill)");
    Ok(())
}

/// Disable the kill-switch by flushing the anchor rules.
#[cfg(target_os = "macos")]
pub fn disable() {
    let _ = std::process::Command::new("pfctl")
        .args(["-a", "com.redpill", "-F", "all"])
        .output();
    tracing::info!("Kill-switch disabled (pf anchor flushed)");
}

/// Clean up stale kill-switch rules from a previous run (e.g. after SIGKILL).
#[cfg(target_os = "macos")]
pub fn cleanup_stale() {
    let _ = std::process::Command::new("pfctl")
        .args(["-a", "com.redpill", "-F", "all"])
        .output();
}

#[cfg(target_os = "linux")]
pub fn enable(_tun_name: &str, _server_ip: &str, _port: u16) -> anyhow::Result<()> {
    Ok(())
}

#[cfg(target_os = "linux")]
pub fn enable_with_extras(
    _tun_name: &str,
    _server_ip: &str,
    _port: u16,
    _extra_hosts: &[String],
) -> anyhow::Result<()> {
    Ok(())
}

#[cfg(target_os = "linux")]
pub fn disable() {}

#[cfg(target_os = "linux")]
pub fn cleanup_stale() {}

#[cfg(target_os = "windows")]
pub fn enable(tun_name: &str, server_ip: &str, _port: u16) -> anyhow::Result<()> {
    enable_with_extras(tun_name, server_ip, _port, &[])
}

#[cfg(target_os = "windows")]
pub fn enable_with_extras(
    _tun_name: &str,
    server_ip: &str,
    _port: u16,
    extra_hosts: &[String],
) -> anyhow::Result<()> {
    cleanup_stale();

    let _ = std::process::Command::new("netsh")
        .args([
            "advfirewall",
            "firewall",
            "add",
            "rule",
            "name=Redpill VPN Kill Switch - Block All",
            "dir=out",
            "action=block",
            "enable=yes",
            "profile=any",
        ])
        .output()?;

    let _ = std::process::Command::new("netsh")
        .args([
            "advfirewall",
            "firewall",
            "add",
            "rule",
            "name=Redpill VPN Kill Switch - Allow Server",
            "dir=out",
            "action=allow",
            &format!("remoteip={server_ip}"),
            "enable=yes",
            "profile=any",
        ])
        .output()?;

    let _ = std::process::Command::new("netsh")
        .args([
            "advfirewall",
            "firewall",
            "add",
            "rule",
            "name=Redpill VPN Kill Switch - Allow Loopback",
            "dir=out",
            "action=allow",
            "remoteip=127.0.0.0/8",
            "enable=yes",
            "profile=any",
        ])
        .output()?;

    for host in extra_hosts {
        let _ = std::process::Command::new("netsh")
            .args([
                "advfirewall",
                "firewall",
                "add",
                "rule",
                &format!("name=Redpill VPN Kill Switch - Allow {host}"),
                "dir=out",
                "action=allow",
                &format!("remoteip={host}"),
                "enable=yes",
                "profile=any",
            ])
            .output()?;
    }

    tracing::info!("Kill-switch enabled (Windows Firewall)");
    Ok(())
}

/// Disable kill-switch by removing all Redpill firewall rules.
#[cfg(target_os = "windows")]
pub fn disable() {
    let _ = std::process::Command::new("netsh")
        .args([
            "advfirewall",
            "firewall",
            "delete",
            "rule",
            "name=Redpill VPN Kill Switch - Block All",
        ])
        .output();
    let _ = std::process::Command::new("netsh")
        .args([
            "advfirewall",
            "firewall",
            "delete",
            "rule",
            "name=Redpill VPN Kill Switch - Allow Server",
        ])
        .output();
    let _ = std::process::Command::new("netsh")
        .args([
            "advfirewall",
            "firewall",
            "delete",
            "rule",
            "name=Redpill VPN Kill Switch - Allow Loopback",
        ])
        .output();
    tracing::info!("Kill-switch disabled (Windows Firewall rules removed)");
}

/// Clean up stale kill-switch rules from a previous run.
#[cfg(target_os = "windows")]
pub fn cleanup_stale() {
    for suffix in &["Block All", "Allow Server", "Allow Loopback"] {
        let _ = std::process::Command::new("netsh")
            .args([
                "advfirewall",
                "firewall",
                "delete",
                "rule",
                &format!("name=Redpill VPN Kill Switch - {suffix}"),
            ])
            .output();
    }
}
