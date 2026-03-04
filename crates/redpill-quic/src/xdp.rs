//! Conntrack bypass and socket tuning for high packet rates.
//!
//! Adds iptables raw/NOTRACK rules for UDP:443 to skip connection tracking,
//! tunes socket buffers (8MB), and disables UDP GRO.
//!
//! Gated behind `xdp` feature. Linux-only.

use std::os::fd::AsRawFd;

use tracing::{info, warn};

/// Set up conntrack bypass for UDP:443 via iptables NOTRACK.
///
/// Conntrack is the main bottleneck for high-rate UDP. NOTRACK skips it entirely.
pub fn attach_bpf_filter<S: AsRawFd>(socket: &S) -> anyhow::Result<bool> {
    let _fd = socket.as_raw_fd();

    if setup_notrack_iptables() {
        info!("XDP: conntrack bypass enabled (iptables raw/NOTRACK)");
        return Ok(true);
    }

    warn!("XDP: conntrack bypass not available (not critical - performance is still good)");
    Ok(false)
}

/// Set up NOTRACK rules in iptables raw table for UDP:443.
fn setup_notrack_iptables() -> bool {
    cleanup_notrack_iptables();

    let inbound = std::process::Command::new("iptables")
        .args([
            "-t",
            "raw",
            "-A",
            "PREROUTING",
            "-p",
            "udp",
            "--dport",
            "443",
            "-j",
            "NOTRACK",
        ])
        .output();

    let outbound = std::process::Command::new("iptables")
        .args([
            "-t", "raw", "-A", "OUTPUT", "-p", "udp", "--sport", "443", "-j", "NOTRACK",
        ])
        .output();

    let ok = inbound.map(|o| o.status.success()).unwrap_or(false)
        && outbound.map(|o| o.status.success()).unwrap_or(false);

    ok
}

/// Clean up all NOTRACK iptables rules (handles duplicates from previous runs).
pub fn cleanup_notrack_iptables() {
    for _ in 0..10 {
        let ok = std::process::Command::new("iptables")
            .args([
                "-t",
                "raw",
                "-D",
                "PREROUTING",
                "-p",
                "udp",
                "--dport",
                "443",
                "-j",
                "NOTRACK",
            ])
            .output()
            .map(|o| o.status.success())
            .unwrap_or(false);
        if !ok {
            break;
        }
    }
    for _ in 0..10 {
        let ok = std::process::Command::new("iptables")
            .args([
                "-t", "raw", "-D", "OUTPUT", "-p", "udp", "--sport", "443", "-j", "NOTRACK",
            ])
            .output()
            .map(|o| o.status.success())
            .unwrap_or(false);
        if !ok {
            break;
        }
    }
}

/// Tune socket: 8MB buffers + disable GRO (reduces latency variance).
pub fn tune_socket<S: AsRawFd>(socket: &S) -> anyhow::Result<()> {
    let fd = socket.as_raw_fd();

    let buf_size: i32 = 8 * 1024 * 1024;
    unsafe {
        libc::setsockopt(
            fd,
            libc::SOL_SOCKET,
            libc::SO_RCVBUF,
            &buf_size as *const i32 as *const libc::c_void,
            std::mem::size_of::<i32>() as libc::socklen_t,
        );
        libc::setsockopt(
            fd,
            libc::SOL_SOCKET,
            libc::SO_SNDBUF,
            &buf_size as *const i32 as *const libc::c_void,
            std::mem::size_of::<i32>() as libc::socklen_t,
        );
    }

    const UDP_GRO: i32 = 104;
    const SOL_UDP: i32 = 17;
    let val: i32 = 0;
    unsafe {
        libc::setsockopt(
            fd,
            SOL_UDP,
            UDP_GRO,
            &val as *const i32 as *const libc::c_void,
            std::mem::size_of::<i32>() as libc::socklen_t,
        );
    }

    info!("XDP: socket tuned (8MB buffers, GRO disabled)");
    Ok(())
}
