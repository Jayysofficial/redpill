use std::net::Ipv4Addr;
use std::process::Command;

use thiserror::Error;

/// DNS servers used for VPN tunnel resolution.
const DNS_PRIMARY: &str = "1.1.1.1";
const DNS_SECONDARY: &str = "1.0.0.1";

#[derive(Debug, Error)]
pub enum RouteError {
    #[error("command failed: {cmd} - {stderr}")]
    CommandFailed { cmd: String, stderr: String },
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
    #[error("route configuration is only supported on Linux and macOS")]
    UnsupportedPlatform,
    #[error("could not determine default gateway")]
    NoDefaultGateway,
}

fn run_cmd(program: &str, args: &[&str]) -> Result<(), RouteError> {
    let output = Command::new(program).args(args).output()?;
    if !output.status.success() {
        return Err(RouteError::CommandFailed {
            cmd: format!("{} {}", program, args.join(" ")),
            stderr: String::from_utf8_lossy(&output.stderr).into_owned(),
        });
    }
    Ok(())
}

fn run_cmd_output(program: &str, args: &[&str]) -> Result<String, RouteError> {
    let output = Command::new(program).args(args).output()?;
    if !output.status.success() {
        return Err(RouteError::CommandFailed {
            cmd: format!("{} {}", program, args.join(" ")),
            stderr: String::from_utf8_lossy(&output.stderr).into_owned(),
        });
    }
    Ok(String::from_utf8_lossy(&output.stdout).into_owned())
}

/// Configure the TUN interface with an IP address and bring it up.
#[cfg(target_os = "linux")]
pub fn configure_interface(
    dev_name: &str,
    address: Ipv4Addr,
    prefix_len: u8,
) -> Result<(), RouteError> {
    let addr_cidr = format!("{}/{}", address, prefix_len);
    run_cmd("ip", &["addr", "add", &addr_cidr, "dev", dev_name])?;
    run_cmd("ip", &["link", "set", dev_name, "up"])?;

    Ok(())
}

#[cfg(not(target_os = "linux"))]
pub fn configure_interface(
    _dev_name: &str,
    _address: Ipv4Addr,
    _prefix_len: u8,
) -> Result<(), RouteError> {
    Err(RouteError::UnsupportedPlatform)
}

/// Enable IP forwarding.
#[cfg(target_os = "linux")]
pub fn enable_ip_forwarding() -> Result<(), RouteError> {
    std::fs::write("/proc/sys/net/ipv4/ip_forward", "1")?;
    Ok(())
}

#[cfg(not(target_os = "linux"))]
pub fn enable_ip_forwarding() -> Result<(), RouteError> {
    Err(RouteError::UnsupportedPlatform)
}

/// Remove ALL stale NAT masquerade and FORWARD rules for the given subnet/interface.
///
/// Uses `nft -a list chain` to enumerate rule handles, then deletes each
/// matching rule individually. Same approach as `flush_mss_rules_nft()`.
#[cfg(target_os = "linux")]
fn flush_nat_rules(tun_subnet: &str, wan_interface: &str) {
    if let Ok(output) = run_cmd_output("nft", &["-a", "list", "chain", "ip", "nat", "POSTROUTING"])
    {
        let handles: Vec<String> = output
            .lines()
            .filter(|line| line.contains(tun_subnet) && line.contains("masquerade"))
            .filter_map(|line| {
                let words: Vec<&str> = line.split_whitespace().collect();
                words
                    .iter()
                    .position(|&w| w == "handle")
                    .and_then(|i| words.get(i + 1))
                    .map(|s| s.to_string())
            })
            .collect();
        for handle in &handles {
            let _ = run_cmd(
                "nft",
                &[
                    "delete",
                    "rule",
                    "ip",
                    "nat",
                    "POSTROUTING",
                    "handle",
                    handle,
                ],
            );
        }
        if !handles.is_empty() {
            tracing::info!(
                "Flushed {} stale POSTROUTING masquerade rules for {}",
                handles.len(),
                tun_subnet
            );
        }
    }

    if let Ok(output) = run_cmd_output("nft", &["-a", "list", "chain", "ip", "filter", "FORWARD"]) {
        let handles: Vec<String> = output
            .lines()
            .filter(|line| {
                (line.contains("\"redpill+\"") || line.contains("\"redpill*\""))
                    && line.contains(&format!("\"{}\"", wan_interface))
                    && line.contains("accept")
            })
            .filter_map(|line| {
                let words: Vec<&str> = line.split_whitespace().collect();
                words
                    .iter()
                    .position(|&w| w == "handle")
                    .and_then(|i| words.get(i + 1))
                    .map(|s| s.to_string())
            })
            .collect();
        for handle in &handles {
            let _ = run_cmd(
                "nft",
                &[
                    "delete", "rule", "ip", "filter", "FORWARD", "handle", handle,
                ],
            );
        }
        if !handles.is_empty() {
            tracing::info!(
                "Flushed {} stale FORWARD rules for redpill+/{}",
                handles.len(),
                wan_interface
            );
        }
    }
}

/// Set up NAT masquerade for the VPN subnet.
///
/// Idempotent: flushes any existing rules for this subnet first so repeated
/// restarts don't accumulate duplicate rules.
#[cfg(target_os = "linux")]
pub fn setup_nat(tun_subnet: &str, wan_interface: &str) -> Result<(), RouteError> {
    flush_nat_rules(tun_subnet, wan_interface);

    run_cmd(
        "iptables",
        &[
            "-t",
            "nat",
            "-A",
            "POSTROUTING",
            "-s",
            tun_subnet,
            "-o",
            wan_interface,
            "-j",
            "MASQUERADE",
        ],
    )?;

    run_cmd(
        "iptables",
        &[
            "-A",
            "FORWARD",
            "-i",
            wan_interface,
            "-o",
            "redpill+",
            "-m",
            "state",
            "--state",
            "RELATED,ESTABLISHED",
            "-j",
            "ACCEPT",
        ],
    )?;

    run_cmd(
        "iptables",
        &[
            "-A",
            "FORWARD",
            "-i",
            "redpill+",
            "-o",
            wan_interface,
            "-j",
            "ACCEPT",
        ],
    )?;

    Ok(())
}

#[cfg(not(target_os = "linux"))]
pub fn setup_nat(_tun_subnet: &str, _wan_interface: &str) -> Result<(), RouteError> {
    Err(RouteError::UnsupportedPlatform)
}

/// Clean up NAT rules (call on shutdown).
///
/// Uses nftables handle-based flush (same as setup) to reliably remove
/// all rules regardless of iptables/nftables backend, plus iptables -D
/// as fallback for legacy rules.
#[cfg(target_os = "linux")]
pub fn cleanup_nat(tun_subnet: &str, wan_interface: &str) -> Result<(), RouteError> {
    flush_nat_rules(tun_subnet, wan_interface);
    let _ = run_cmd(
        "iptables",
        &[
            "-t",
            "nat",
            "-D",
            "POSTROUTING",
            "-s",
            tun_subnet,
            "-o",
            wan_interface,
            "-j",
            "MASQUERADE",
        ],
    );
    let _ = run_cmd(
        "iptables",
        &[
            "-D",
            "FORWARD",
            "-i",
            wan_interface,
            "-o",
            "redpill+",
            "-m",
            "state",
            "--state",
            "RELATED,ESTABLISHED",
            "-j",
            "ACCEPT",
        ],
    );
    let _ = run_cmd(
        "iptables",
        &[
            "-D",
            "FORWARD",
            "-i",
            "redpill+",
            "-o",
            wan_interface,
            "-j",
            "ACCEPT",
        ],
    );
    Ok(())
}

/// Remove ALL MSS clamping rules for `tun_dev` from the nft mangle table.
///
/// Uses `nft -a list chain` to enumerate rule handles, then deletes each
/// matching rule individually.  This handles stale rules from previous runs
/// that may have used a different MSS value (e.g. 1340, 1220, …).
#[cfg(target_os = "linux")]
fn flush_mss_rules_nft(tun_dev: &str) {
    for chain in &["FORWARD", "OUTPUT"] {
        let output = match run_cmd_output("nft", &["-a", "list", "chain", "ip", "mangle", chain]) {
            Ok(o) => o,
            Err(_) => continue,
        };

        let handles: Vec<String> = output
            .lines()
            .filter(|line| {
                (line.contains(&format!("oifname \"{}\"", tun_dev))
                    || line.contains(&format!("iifname \"{}\"", tun_dev)))
                    && line.contains("maxseg")
            })
            .filter_map(|line| {
                // Rule lines end with "# handle N"
                let words: Vec<&str> = line.split_whitespace().collect();
                words
                    .iter()
                    .position(|&w| w == "handle")
                    .and_then(|i| words.get(i + 1))
                    .map(|s| s.to_string())
            })
            .collect();

        for handle in handles {
            let _ = run_cmd(
                "nft",
                &["delete", "rule", "ip", "mangle", chain, "handle", &handle],
            );
        }
    }
}

/// Set up MSS clamping for a TUN device (Linux).
///
/// Without this, TCP connections through the VPN break: internet servers send
/// large TCP segments (MSS 1460) that exceed the TUN MTU, causing fragmentation
/// or PMTU black-hole (DF set, ICMP blocked → TCP stalls).
///
/// MSS = MTU - 60 bytes (IP header 20 + TCP header with options max 40).
///
/// Idempotent: flushes any existing rules for `tun_dev` first so repeated
/// restarts don't accumulate stale rules with wrong MSS values.
#[cfg(target_os = "linux")]
pub fn setup_mss_clamping(tun_dev: &str, tun_mtu: u32) -> Result<(), RouteError> {
    let mss = (tun_mtu as i32 - 60).max(512).to_string();

    // Uses -D in a loop until no more matches - handles multiple duplicates
    for chain_flag in &[("-o", "FORWARD"), ("-i", "FORWARD"), ("-o", "OUTPUT")] {
        let (dir, chain) = chain_flag;
        loop {
            let result = run_cmd(
                "iptables",
                &[
                    "-t",
                    "mangle",
                    "-D",
                    chain,
                    dir,
                    tun_dev,
                    "-p",
                    "tcp",
                    "--tcp-flags",
                    "SYN,RST",
                    "SYN",
                    "-j",
                    "TCPMSS",
                    "--set-mss",
                    &mss,
                ],
            );
            if result.is_err() {
                break;
            }
        }
    }

    flush_mss_rules_nft(tun_dev);

    // Outbound (internet → VPN tunnel): clamp replies from internet servers
    run_cmd(
        "iptables",
        &[
            "-t",
            "mangle",
            "-A",
            "FORWARD",
            "-o",
            tun_dev,
            "-p",
            "tcp",
            "--tcp-flags",
            "SYN,RST",
            "SYN",
            "-j",
            "TCPMSS",
            "--set-mss",
            &mss,
        ],
    )?;

    // Inbound (VPN tunnel → internet): clamp SYN from VPN clients
    run_cmd(
        "iptables",
        &[
            "-t",
            "mangle",
            "-A",
            "FORWARD",
            "-i",
            tun_dev,
            "-p",
            "tcp",
            "--tcp-flags",
            "SYN,RST",
            "SYN",
            "-j",
            "TCPMSS",
            "--set-mss",
            &mss,
        ],
    )?;

    // Locally-originated traffic (e.g. iperf3 to tunnel IP): uses OUTPUT chain, not FORWARD
    run_cmd(
        "iptables",
        &[
            "-t",
            "mangle",
            "-A",
            "OUTPUT",
            "-o",
            tun_dev,
            "-p",
            "tcp",
            "--tcp-flags",
            "SYN,RST",
            "SYN",
            "-j",
            "TCPMSS",
            "--set-mss",
            &mss,
        ],
    )?;

    Ok(())
}

#[cfg(not(target_os = "linux"))]
pub fn setup_mss_clamping(_tun_dev: &str, _tun_mtu: u32) -> Result<(), RouteError> {
    Ok(()) // no-op on non-Linux
}

/// Remove MSS clamping rules added by `setup_mss_clamping`.
///
/// Uses nftables handle-based flush (catches rules with any MSS value)
/// plus iptables -D as fallback.
#[cfg(target_os = "linux")]
pub fn cleanup_mss_clamping(tun_dev: &str, tun_mtu: u32) {
    flush_mss_rules_nft(tun_dev);

    let mss = (tun_mtu as i32 - 60).max(512).to_string();
    let _ = run_cmd(
        "iptables",
        &[
            "-t",
            "mangle",
            "-D",
            "FORWARD",
            "-o",
            tun_dev,
            "-p",
            "tcp",
            "--tcp-flags",
            "SYN,RST",
            "SYN",
            "-j",
            "TCPMSS",
            "--set-mss",
            &mss,
        ],
    );
    let _ = run_cmd(
        "iptables",
        &[
            "-t",
            "mangle",
            "-D",
            "FORWARD",
            "-i",
            tun_dev,
            "-p",
            "tcp",
            "--tcp-flags",
            "SYN,RST",
            "SYN",
            "-j",
            "TCPMSS",
            "--set-mss",
            &mss,
        ],
    );
    let _ = run_cmd(
        "iptables",
        &[
            "-t",
            "mangle",
            "-D",
            "OUTPUT",
            "-o",
            tun_dev,
            "-p",
            "tcp",
            "--tcp-flags",
            "SYN,RST",
            "SYN",
            "-j",
            "TCPMSS",
            "--set-mss",
            &mss,
        ],
    );
}

#[cfg(not(target_os = "linux"))]
pub fn cleanup_mss_clamping(_tun_dev: &str, _tun_mtu: u32) {}

/// Configure TUN device performance: txqueuelen + noqueue qdisc (Linux).
///
/// Matches v1 server tuning - eliminates per-packet fq scheduling overhead
/// and allows large queue depth for burst absorption.
#[cfg(target_os = "linux")]
pub fn configure_tun_performance(dev_name: &str, txqueuelen: u32) {
    let txq = txqueuelen.to_string();
    if let Err(e) = run_cmd("ip", &["link", "set", dev_name, "txqueuelen", &txq]) {
        tracing::warn!("Failed to set txqueuelen on {dev_name}: {e}");
    }
    if let Err(e) = run_cmd(
        "tc",
        &["qdisc", "replace", "dev", dev_name, "root", "noqueue"],
    ) {
        tracing::warn!("Failed to set noqueue qdisc on {dev_name}: {e}");
    }
    tracing::info!("TUN performance: {dev_name} txqueuelen={txq} qdisc=noqueue");
}

#[cfg(not(target_os = "linux"))]
pub fn configure_tun_performance(_dev_name: &str, _txqueuelen: u32) {}

#[cfg(not(target_os = "linux"))]
pub fn cleanup_nat(_tun_subnet: &str, _wan_interface: &str) -> Result<(), RouteError> {
    Ok(())
}

/// Saved route state for cleanup (Linux).
#[cfg(target_os = "linux")]
pub struct SavedRoutes {
    pub server_real_ip: String,
    pub gateway: String,
    pub server_tunnel_ip: String,
}

/// Configure a point-to-point TUN interface for the client (Linux).
#[cfg(target_os = "linux")]
pub fn configure_client_interface(
    dev_name: &str,
    client_ip: Ipv4Addr,
    server_tunnel_ip: Ipv4Addr,
    mtu: u16,
) -> Result<(), RouteError> {
    run_cmd(
        "ip",
        &[
            "addr",
            "add",
            &format!("{}/32", client_ip),
            "peer",
            &format!("{}/32", server_tunnel_ip),
            "dev",
            dev_name,
        ],
    )?;
    run_cmd(
        "ip",
        &["link", "set", dev_name, "mtu", &mtu.to_string(), "up"],
    )?;
    tracing::info!(
        "Configured {} : {} -> {} (mtu {})",
        dev_name,
        client_ip,
        server_tunnel_ip,
        mtu
    );
    Ok(())
}

/// Get default gateway (Linux).
#[cfg(target_os = "linux")]
pub fn get_default_gateway() -> Result<String, RouteError> {
    let output = run_cmd_output("ip", &["route", "show", "default"])?;
    for line in output.lines() {
        let parts: Vec<&str> = line.split_whitespace().collect();
        if parts.first() == Some(&"default") {
            if let Some(pos) = parts.iter().position(|&p| p == "via") {
                if let Some(&gw) = parts.get(pos + 1) {
                    return Ok(gw.to_string());
                }
            }
        }
    }
    Err(RouteError::NoDefaultGateway)
}

/// Route all traffic through VPN tunnel (Linux).
#[cfg(target_os = "linux")]
pub fn setup_client_routes(
    server_real_ip: &str,
    server_tunnel_ip: Ipv4Addr,
    gateway: &str,
) -> Result<SavedRoutes, RouteError> {
    let tunnel_ip = server_tunnel_ip.to_string();

    run_cmd("ip", &["route", "add", server_real_ip, "via", gateway])?;
    tracing::info!("Route: {} via {} (bypass)", server_real_ip, gateway);

    // Split into two /1 to override default without replacing it
    run_cmd("ip", &["route", "add", "0.0.0.0/1", "via", &tunnel_ip])?;
    run_cmd("ip", &["route", "add", "128.0.0.0/1", "via", &tunnel_ip])?;
    tracing::info!("Routes: 0/1 + 128/1 via {}", tunnel_ip);

    Ok(SavedRoutes {
        server_real_ip: server_real_ip.to_string(),
        gateway: gateway.to_string(),
        server_tunnel_ip: tunnel_ip,
    })
}

/// Remove VPN routes (Linux).
#[cfg(target_os = "linux")]
pub fn cleanup_client_routes(saved: &SavedRoutes) {
    let _ = run_cmd(
        "ip",
        &["route", "del", &saved.server_real_ip, "via", &saved.gateway],
    );
    let _ = run_cmd("ip", &["route", "del", "0.0.0.0/1"]);
    let _ = run_cmd("ip", &["route", "del", "128.0.0.0/1"]);
    tracing::info!("Client routes cleaned up");
}

/// Override DNS to use VPN-tunneled resolver (Linux).
#[cfg(target_os = "linux")]
pub fn setup_client_dns() -> Result<(), RouteError> {
    let orig = std::fs::read_to_string("/etc/resolv.conf").unwrap_or_default();
    let _ = std::fs::write("/etc/resolv.conf.redpill-bak", &orig);
    std::fs::write(
        "/etc/resolv.conf",
        format!("nameserver {DNS_PRIMARY}\nnameserver {DNS_SECONDARY}\n"),
    )
    .map_err(RouteError::Io)?;
    tracing::info!("DNS override: {DNS_PRIMARY} via tunnel");
    Ok(())
}

/// Restore original DNS (Linux).
#[cfg(target_os = "linux")]
pub fn cleanup_client_dns() {
    if let Ok(orig) = std::fs::read_to_string("/etc/resolv.conf.redpill-bak") {
        let _ = std::fs::write("/etc/resolv.conf", orig);
        let _ = std::fs::remove_file("/etc/resolv.conf.redpill-bak");
    }
    tracing::info!("DNS restored");
}

/// Saved route state for cleanup.
#[cfg(target_os = "macos")]
pub struct SavedRoutes {
    pub server_real_ip: String,
    pub gateway: String,
    pub server_tunnel_ip: String,
}

/// Configure a point-to-point utun interface for the client (macOS).
///
/// `ifconfig utunN inet <client_ip> <server_tunnel_ip> mtu <mtu> up`
#[cfg(target_os = "macos")]
pub fn configure_client_interface(
    dev_name: &str,
    client_ip: Ipv4Addr,
    server_tunnel_ip: Ipv4Addr,
    mtu: u16,
) -> Result<(), RouteError> {
    run_cmd(
        "ifconfig",
        &[
            dev_name,
            "inet",
            &client_ip.to_string(),
            &server_tunnel_ip.to_string(),
            "mtu",
            &mtu.to_string(),
            "up",
        ],
    )?;
    tracing::info!(
        "Configured {} : {} -> {} (mtu {})",
        dev_name,
        client_ip,
        server_tunnel_ip,
        mtu
    );
    Ok(())
}

/// Get the current default gateway IP (macOS).
///
/// Parses `route -n get default` output. If the default route goes through
/// a utun interface (another VPN is active), falls back to `netstat -rn` to
/// find a default route on a physical interface.
#[cfg(target_os = "macos")]
pub fn get_default_gateway() -> Result<String, RouteError> {
    let output = run_cmd_output("route", &["-n", "get", "default"])?;
    let mut gateway = None;
    let mut interface = None;
    for line in output.lines() {
        let trimmed = line.trim();
        if let Some(gw) = trimmed.strip_prefix("gateway:") {
            gateway = Some(gw.trim().to_string());
        }
        if let Some(iface) = trimmed.strip_prefix("interface:") {
            interface = Some(iface.trim().to_string());
        }
    }

    if let (Some(gw), Some(iface)) = (&gateway, &interface) {
        if !iface.starts_with("utun") {
            return Ok(gw.clone());
        }
        tracing::warn!(
            "Default route goes through {iface} (VPN active), looking for physical gateway..."
        );
    }

    let output = run_cmd_output("netstat", &["-rn", "-f", "inet"])?;
    for line in output.lines() {
        let parts: Vec<&str> = line.split_whitespace().collect();
        // Format: Destination  Gateway  Flags  Netif  [Expire]
        if parts.len() >= 4 && parts[0] == "default" && !parts[3].starts_with("utun") {
            return Ok(parts[1].to_string());
        }
    }

    gateway.ok_or(RouteError::NoDefaultGateway)
}

/// Set up split routes to send all traffic through the VPN tunnel (macOS).
///
/// 1. `route add -host <server_real_ip> <current_gateway>` - bypass VPN for server itself
/// 2. `route add -net 0.0.0.0/1 <server_tunnel_ip>` - first half of internet
/// 3. `route add -net 128.0.0.0/1 <server_tunnel_ip>` - second half of internet
///
/// Returns `SavedRoutes` for cleanup.
#[cfg(target_os = "macos")]
pub fn setup_client_routes(
    server_real_ip: &str,
    server_tunnel_ip: Ipv4Addr,
    gateway: &str,
) -> Result<SavedRoutes, RouteError> {
    let tunnel_ip = server_tunnel_ip.to_string();

    run_cmd("route", &["add", "-host", server_real_ip, gateway])?;
    tracing::info!("Route: {} via {} (bypass)", server_real_ip, gateway);

    run_cmd("route", &["add", "-net", "0.0.0.0/1", &tunnel_ip])?;
    tracing::info!("Route: 0.0.0.0/1 via {}", tunnel_ip);

    run_cmd("route", &["add", "-net", "128.0.0.0/1", &tunnel_ip])?;
    tracing::info!("Route: 128.0.0.0/1 via {}", tunnel_ip);

    Ok(SavedRoutes {
        server_real_ip: server_real_ip.to_string(),
        gateway: gateway.to_string(),
        server_tunnel_ip: tunnel_ip,
    })
}

/// Remove routes added by `setup_client_routes` (macOS).
///
/// Errors are logged but not propagated - best-effort cleanup.
#[cfg(target_os = "macos")]
pub fn cleanup_client_routes(saved: &SavedRoutes) {
    if let Err(e) = run_cmd(
        "route",
        &["delete", "-host", &saved.server_real_ip, &saved.gateway],
    ) {
        tracing::warn!("Failed to remove host route: {}", e);
    }
    if let Err(e) = run_cmd(
        "route",
        &["delete", "-net", "0.0.0.0/1", &saved.server_tunnel_ip],
    ) {
        tracing::warn!("Failed to remove 0/1 route: {}", e);
    }
    if let Err(e) = run_cmd(
        "route",
        &["delete", "-net", "128.0.0.0/1", &saved.server_tunnel_ip],
    ) {
        tracing::warn!("Failed to remove 128/1 route: {}", e);
    }
    tracing::info!("Client routes cleaned up");
}

/// Override system DNS to prevent leaks (macOS).
///
/// Creates a high-priority scutil DNS resolver pointing to public DNS servers
/// (1.1.1.1, 1.0.0.1) that route through the VPN tunnel (0.0.0.0/1 route).
/// `SupplementalMatchDomains` with empty string = default resolver (highest priority).
#[cfg(target_os = "macos")]
pub fn setup_client_dns() -> Result<(), RouteError> {
    let script = format!(
        "\
d.init\n\
d.add ServerAddresses * {DNS_PRIMARY} {DNS_SECONDARY}\n\
d.add SupplementalMatchDomains * \"\"\n\
d.add SupplementalMatchOrder # 1\n\
set State:/Network/Service/RedpillVPN/DNS\n\
quit\n"
    );

    let output = Command::new("scutil")
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .and_then(|mut child| {
            use std::io::Write;
            if let Some(mut stdin) = child.stdin.take() {
                stdin.write_all(script.as_bytes())?;
            }
            child.wait_with_output()
        })?;

    if !output.status.success() {
        return Err(RouteError::CommandFailed {
            cmd: "scutil (setup DNS)".into(),
            stderr: String::from_utf8_lossy(&output.stderr).into_owned(),
        });
    }

    tracing::info!("DNS override: {DNS_PRIMARY}, {DNS_SECONDARY} via VPN tunnel");
    Ok(())
}

/// Clean up stale routes from a previous client run that was killed without cleanup (macOS).
///
/// After SIGKILL the utun fd is closed (device destroyed), but routes persist.
/// The /1 split routes (0.0.0.0/1, 128.0.0.0/1) only exist because of redpill,
/// so it's always safe to remove them. Also cleans the stale host route to
/// 10.0.1.1 (server tunnel IP), the scutil DNS override, and brings down any
/// stale utun interfaces with 10.0.1.x addresses.
#[cfg(target_os = "macos")]
pub fn cleanup_stale_client() {
    let _ = run_cmd("route", &["delete", "-net", "0.0.0.0/1"]);
    let _ = run_cmd("route", &["delete", "-net", "128.0.0.0/1"]);

    // A stale host route (10.0.1.1 -> old utun) causes new /1 routes to
    // bind to the dead interface instead of our fresh utun device.
    let _ = run_cmd("route", &["delete", "-host", "10.0.1.1"]);

    let _ = run_cmd("route", &["delete", "-net", "10.0.1.0/24"]);

    // Stale utun devices persist if the owning process didn't close the fd,
    // holding the old host route and capturing our new routes.
    if let Ok(output) = std::process::Command::new("ifconfig").arg("-a").output() {
        let ifconfig = String::from_utf8_lossy(&output.stdout);
        let mut current_iface: Option<String> = None;
        for line in ifconfig.lines() {
            if !line.starts_with('\t') && !line.starts_with(' ') {
                current_iface = line.split(':').next().map(|s| s.to_string());
            } else if line.contains("10.0.1.") {
                if let Some(ref iface) = current_iface {
                    if iface.starts_with("utun") {
                        tracing::warn!(
                            "Bringing down stale interface {iface} (has 10.0.1.x address)"
                        );
                        let _ = run_cmd("ifconfig", &[iface, "down"]);
                        let _ = run_cmd("ifconfig", &[iface, "delete", "10.0.1.1"]);
                        let _ = run_cmd("route", &["delete", "-host", "10.0.1.1"]);
                    }
                }
            }
        }
    }

    cleanup_client_dns();

    tracing::info!("Cleaned up stale routes/DNS from previous run");
}

#[cfg(target_os = "linux")]
pub fn cleanup_stale_client() {
    let _ = run_cmd("ip", &["route", "del", "0.0.0.0/1"]);
    let _ = run_cmd("ip", &["route", "del", "128.0.0.0/1"]);
    cleanup_client_dns();
    tracing::info!("Cleaned up stale routes/DNS from previous run");
}

/// Restore original DNS settings by removing scutil override (macOS).
#[cfg(target_os = "macos")]
pub fn cleanup_client_dns() {
    let script = "remove State:/Network/Service/RedpillVPN/DNS\nquit\n";

    let result = Command::new("scutil")
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .and_then(|mut child| {
            use std::io::Write;
            if let Some(mut stdin) = child.stdin.take() {
                stdin.write_all(script.as_bytes())?;
            }
            child.wait_with_output()
        });

    if let Err(e) = result {
        tracing::warn!("Failed to restore DNS: {e}");
    } else {
        tracing::info!("DNS override removed");
    }
}

/// Saved route state for cleanup (Windows).
#[cfg(target_os = "windows")]
pub struct SavedRoutes {
    pub server_real_ip: String,
    pub gateway: String,
    pub server_tunnel_ip: String,
}

/// Configure the TUN interface with an IP address (Windows).
///
/// Uses `netsh interface ip set address` to assign IP to the wintun adapter.
#[cfg(target_os = "windows")]
pub fn configure_client_interface(
    dev_name: &str,
    client_ip: Ipv4Addr,
    server_tunnel_ip: Ipv4Addr,
    mtu: u16,
) -> Result<(), RouteError> {
    run_cmd(
        "netsh",
        &[
            "interface",
            "ip",
            "set",
            "address",
            dev_name,
            "static",
            &client_ip.to_string(),
            "255.255.255.0",
            &server_tunnel_ip.to_string(),
        ],
    )?;

    run_cmd(
        "netsh",
        &[
            "interface",
            "ipv4",
            "set",
            "subinterface",
            dev_name,
            &format!("mtu={mtu}"),
            "store=active",
        ],
    )?;

    tracing::info!(
        "Configured {} : {} -> {} (mtu {})",
        dev_name,
        client_ip,
        server_tunnel_ip,
        mtu
    );
    Ok(())
}

/// Get the current default gateway (Windows).
///
/// Parses `route print 0.0.0.0` output.
#[cfg(target_os = "windows")]
pub fn get_default_gateway() -> Result<String, RouteError> {
    let output = run_cmd_output("route", &["print", "0.0.0.0"])?;
    for line in output.lines() {
        let parts: Vec<&str> = line.split_whitespace().collect();
        if parts.len() >= 3 && parts[0] == "0.0.0.0" && parts[1] == "0.0.0.0" {
            return Ok(parts[2].to_string());
        }
    }
    Err(RouteError::NoDefaultGateway)
}

/// Route all traffic through VPN tunnel (Windows).
///
/// Uses `route add` with metric 1 to override default route.
#[cfg(target_os = "windows")]
pub fn setup_client_routes(
    server_real_ip: &str,
    server_tunnel_ip: Ipv4Addr,
    gateway: &str,
) -> Result<SavedRoutes, RouteError> {
    let tunnel_ip = server_tunnel_ip.to_string();

    run_cmd(
        "route",
        &[
            "add",
            server_real_ip,
            "mask",
            "255.255.255.255",
            gateway,
            "metric",
            "1",
        ],
    )?;
    tracing::info!("Route: {} via {} (bypass)", server_real_ip, gateway);

    run_cmd(
        "route",
        &[
            "add",
            "0.0.0.0",
            "mask",
            "128.0.0.0",
            &tunnel_ip,
            "metric",
            "1",
        ],
    )?;
    run_cmd(
        "route",
        &[
            "add",
            "128.0.0.0",
            "mask",
            "128.0.0.0",
            &tunnel_ip,
            "metric",
            "1",
        ],
    )?;
    tracing::info!("Routes: 0/1 + 128/1 via {}", tunnel_ip);

    Ok(SavedRoutes {
        server_real_ip: server_real_ip.to_string(),
        gateway: gateway.to_string(),
        server_tunnel_ip: tunnel_ip,
    })
}

/// Remove VPN routes (Windows).
#[cfg(target_os = "windows")]
pub fn cleanup_client_routes(saved: &SavedRoutes) {
    let _ = run_cmd("route", &["delete", &saved.server_real_ip]);
    let _ = run_cmd("route", &["delete", "0.0.0.0", "mask", "128.0.0.0"]);
    let _ = run_cmd("route", &["delete", "128.0.0.0", "mask", "128.0.0.0"]);
    tracing::info!("Client routes cleaned up");
}

/// Override DNS to use VPN-tunneled resolver (Windows).
///
/// Uses `netsh interface ip set dns` to set primary DNS.
#[cfg(target_os = "windows")]
pub fn setup_client_dns() -> Result<(), RouteError> {
    run_cmd(
        "netsh",
        &[
            "interface",
            "ip",
            "set",
            "dns",
            "Redpill VPN",
            "static",
            DNS_PRIMARY,
            "primary",
        ],
    )?;
    let _ = run_cmd(
        "netsh",
        &[
            "interface",
            "ip",
            "add",
            "dns",
            "Redpill VPN",
            DNS_SECONDARY,
            "index=2",
        ],
    );
    tracing::info!("DNS override: {DNS_PRIMARY} via tunnel");
    Ok(())
}

/// Restore DNS (Windows).
#[cfg(target_os = "windows")]
pub fn cleanup_client_dns() {
    let _ = run_cmd(
        "netsh",
        &["interface", "ip", "set", "dns", "Redpill VPN", "dhcp"],
    );
    tracing::info!("DNS restored");
}

/// Clean up stale state from a previous client run (Windows).
#[cfg(target_os = "windows")]
pub fn cleanup_stale_client() {
    let _ = run_cmd("route", &["delete", "0.0.0.0", "mask", "128.0.0.0"]);
    let _ = run_cmd("route", &["delete", "128.0.0.0", "mask", "128.0.0.0"]);
    cleanup_client_dns();
    tracing::info!("Cleaned up stale routes/DNS from previous run");
}
