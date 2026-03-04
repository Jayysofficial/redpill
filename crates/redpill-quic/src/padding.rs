//! Packet size normalization and idle padding.
//!
//! Pads outgoing IP packets to standard sizes common in HTTP/3 traffic,
//! making traffic analysis harder. Strips padding on receive using the
//! IP header's total_length field.

const STANDARD_SIZES: &[usize] = &[128, 256, 512, 1024, 1200, 1400];

/// Pad a packet to the next standard size boundary.
///
/// The receiver strips padding using `strip_padding()` which reads
/// the real length from the IP header.
pub fn pad_to_standard(data: &[u8]) -> Vec<u8> {
    let target = STANDARD_SIZES
        .iter()
        .find(|&&s| s >= data.len())
        .copied()
        .unwrap_or(data.len());

    let mut padded = Vec::with_capacity(target);
    padded.extend_from_slice(data);
    padded.resize(target, 0);
    padded
}

/// Strip padding from a received packet using the IP header's total_length.
///
/// - IPv4: bytes 2-3 = total length (header + payload)
/// - IPv6: bytes 4-5 = payload length (add 40 for fixed header)
/// - Non-IP data: returned unchanged
pub fn strip_padding(data: &[u8]) -> &[u8] {
    if data.is_empty() {
        return data;
    }

    let version = data[0] >> 4;
    let real_len = match version {
        4 if data.len() >= 4 => u16::from_be_bytes([data[2], data[3]]) as usize,
        6 if data.len() >= 6 => u16::from_be_bytes([data[4], data[5]]) as usize + 40,
        _ => return data,
    };

    if real_len > 0 && real_len <= data.len() {
        &data[..real_len]
    } else {
        data
    }
}

/// Idle padding generator - sends dummy packets during inactivity
/// to prevent traffic analysis based on idle patterns.
pub struct IdlePadder {
    interval: std::time::Duration,
    min_size: usize,
    max_size: usize,
}

impl IdlePadder {
    pub fn new(interval_ms: u64, min_size: usize, max_size: usize) -> Self {
        Self {
            interval: std::time::Duration::from_millis(interval_ms),
            min_size,
            max_size,
        }
    }

    pub fn interval(&self) -> std::time::Duration {
        self.interval
    }

    /// Generate a random-length padding packet.
    /// First nibble is 0 so it's not confused with a real IP packet.
    pub fn generate(&self) -> Vec<u8> {
        use rand::Rng;
        let mut rng = rand::thread_rng();
        let size = rng.gen_range(self.min_size..=self.max_size);
        let mut buf = vec![0u8; size];
        rng.fill(&mut buf[..]);
        buf[0] &= 0x0F; // version nibble 0 - not IP
        buf
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_pad_to_standard_sizes() {
        assert_eq!(pad_to_standard(&[1; 50]).len(), 128);
        assert_eq!(pad_to_standard(&[1; 128]).len(), 128);
        assert_eq!(pad_to_standard(&[1; 129]).len(), 256);
        assert_eq!(pad_to_standard(&[1; 500]).len(), 512);
        assert_eq!(pad_to_standard(&[1; 1000]).len(), 1024);
        assert_eq!(pad_to_standard(&[1; 1100]).len(), 1200);
        assert_eq!(pad_to_standard(&[1; 1300]).len(), 1400);
        assert_eq!(pad_to_standard(&[1; 1500]).len(), 1500);
    }

    #[test]
    fn test_strip_padding_ipv4() {
        let mut pkt = vec![0u8; 128];
        pkt[0] = 0x45;
        pkt[2] = 0;
        pkt[3] = 40;
        let stripped = strip_padding(&pkt);
        assert_eq!(stripped.len(), 40);
    }

    #[test]
    fn test_strip_padding_ipv6() {
        let mut pkt = vec![0u8; 128];
        pkt[0] = 0x60;
        pkt[4] = 0;
        pkt[5] = 20;
        let stripped = strip_padding(&pkt);
        assert_eq!(stripped.len(), 60);
    }

    #[test]
    fn test_strip_padding_non_ip() {
        let pkt = vec![0x00; 128];
        let stripped = strip_padding(&pkt);
        assert_eq!(stripped.len(), 128);
    }

    #[test]
    fn test_roundtrip() {
        let mut original = vec![0u8; 60];
        original[0] = 0x45;
        original[2] = 0;
        original[3] = 60;

        let padded = pad_to_standard(&original);
        assert_eq!(padded.len(), 128);

        let stripped = strip_padding(&padded);
        assert_eq!(stripped.len(), 60);
        assert_eq!(stripped, &original[..]);
    }

    #[test]
    fn test_idle_padder_generates_non_ip() {
        let padder = IdlePadder::new(100, 64, 256);
        let pkt = padder.generate();
        assert!(pkt.len() >= 64 && pkt.len() <= 256);
        // First nibble should be 0 (not 4 or 6)
        assert_eq!(pkt[0] >> 4, 0);
    }
}
