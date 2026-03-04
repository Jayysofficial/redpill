//! Datagram helpers: write IP packets to TUN, validate source IP.
//!
//! DATAGRAM frames carry raw IP packets (no type byte prefix).
//! IP version is detected from the first nibble (4 = IPv4, 6 = IPv6).

use std::net::Ipv4Addr;

/// Detect IP version from the first byte of a packet.
/// Returns 4, 6, or None if invalid.
pub fn ip_version(packet: &[u8]) -> Option<u8> {
    if packet.is_empty() {
        return None;
    }
    match packet[0] >> 4 {
        4 => Some(4),
        6 => Some(6),
        _ => None,
    }
}

/// Validate that the source IP of an IPv4 packet matches the expected IP.
/// For IPv6 packets, validation is skipped (returns true).
/// Returns false for invalid or spoofed packets.
pub fn validate_source_ip(packet: &[u8], expected_ip: Ipv4Addr) -> bool {
    match ip_version(packet) {
        Some(4) => {
            // IPv4: source IP is at bytes 12-15
            if packet.len() < 20 {
                return false;
            }
            let src = Ipv4Addr::new(packet[12], packet[13], packet[14], packet[15]);
            src == expected_ip
        }
        Some(6) => {
            // IPv6: source IP is at bytes 8-23
            // We don't validate IPv6 source addresses (no pool for them)
            true
        }
        _ => false,
    }
}

/// Extract the destination IPv4 address from a raw IP packet.
/// Returns None for non-IPv4 packets or packets shorter than 20 bytes.
pub fn extract_dst_ipv4(packet: &[u8]) -> Option<Ipv4Addr> {
    if packet.len() < 20 {
        return None;
    }
    if packet[0] >> 4 != 4 {
        return None;
    }
    Some(Ipv4Addr::new(
        packet[16], packet[17], packet[18], packet[19],
    ))
}

/// Write an IP packet to a TUN device (platform-specific).
///
/// - Linux: raw write (TUN is IFF_NO_PI, no header)
/// - macOS: writev with 4-byte big-endian AF header
pub fn write_to_tun(fd: i32, packet: &[u8]) -> std::io::Result<()> {
    if packet.is_empty() {
        return Ok(());
    }

    #[cfg(target_os = "linux")]
    {
        let ret = unsafe { libc::write(fd, packet.as_ptr() as *const libc::c_void, packet.len()) };
        if ret < 0 {
            return Err(std::io::Error::last_os_error());
        }
    }

    #[cfg(target_os = "macos")]
    {
        let af: u32 = if packet[0] >> 4 == 6 {
            libc::AF_INET6 as u32
        } else {
            libc::AF_INET as u32
        };
        let af_bytes = af.to_be_bytes();
        let iov = [
            libc::iovec {
                iov_base: af_bytes.as_ptr() as *mut libc::c_void,
                iov_len: 4,
            },
            libc::iovec {
                iov_base: packet.as_ptr() as *mut libc::c_void,
                iov_len: packet.len(),
            },
        ];
        let ret = unsafe { libc::writev(fd, iov.as_ptr(), 2) };
        if ret < 0 {
            return Err(std::io::Error::last_os_error());
        }
    }

    Ok(())
}
