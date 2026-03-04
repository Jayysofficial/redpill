//! Datagram batching: combine small packets into a single DATAGRAM frame.
//!
//! Wire format: `[2B len BE][data][2B len BE][data]...`
//!
//! Only packets <300 bytes (DNS, ACKs) are batched. Larger packets are sent directly.
//! Batch is flushed when full or after a 1ms timeout.

use bytes::{BufMut, Bytes, BytesMut};

/// Maximum size of a single packet to batch (anything ≥ this is sent directly).
pub const BATCH_SIZE_THRESHOLD: usize = 300;

/// Maximum DATAGRAM payload size for a batch. Conservative to avoid hitting QUIC limits.
pub const MAX_BATCH_SIZE: usize = 1100;

/// Encode multiple packets into a single batched datagram.
///
/// Wire format: `[2B len BE][data][2B len BE][data]...`
/// All packets must be < BATCH_SIZE_THRESHOLD.
pub fn batch_encode(packets: &[Bytes]) -> Bytes {
    let total: usize = packets.iter().map(|p| 2 + p.len()).sum();
    let mut buf = BytesMut::with_capacity(total);
    for pkt in packets {
        buf.put_u16(pkt.len() as u16);
        buf.put_slice(pkt);
    }
    buf.freeze()
}

/// Decode a batched datagram into individual packets.
///
/// Returns the list of decoded packets. Invalid trailing bytes are ignored.
pub fn batch_decode(data: &[u8]) -> Vec<Bytes> {
    let mut packets = Vec::new();
    let mut pos = 0;
    while pos + 2 <= data.len() {
        let len = u16::from_be_bytes([data[pos], data[pos + 1]]) as usize;
        pos += 2;
        if pos + len > data.len() {
            break; // Truncated - ignore
        }
        packets.push(Bytes::copy_from_slice(&data[pos..pos + len]));
        pos += len;
    }
    packets
}

/// Accumulates small packets for batching, flushes when full.
pub struct DatagramBatcher {
    pending: Vec<Bytes>,
    pending_size: usize,
}

impl Default for DatagramBatcher {
    fn default() -> Self {
        Self::new()
    }
}

impl DatagramBatcher {
    pub fn new() -> Self {
        Self {
            pending: Vec::with_capacity(8),
            pending_size: 0,
        }
    }

    /// Add a packet to the batch.
    /// Returns `Some(batch)` if the batch is full and should be flushed.
    /// If the packet is too large for batching, returns None (caller should send directly).
    pub fn add(&mut self, packet: Bytes) -> Option<Bytes> {
        let entry_size = 2 + packet.len();
        if self.pending_size + entry_size > MAX_BATCH_SIZE && !self.pending.is_empty() {
            // Flush current batch, then add this packet to a new batch
            let batch = self.flush();
            self.pending.push(packet);
            self.pending_size = entry_size;
            Some(batch)
        } else {
            self.pending.push(packet);
            self.pending_size += entry_size;
            None
        }
    }

    /// Flush the current batch. Returns the encoded batch (or empty if nothing pending).
    pub fn flush(&mut self) -> Bytes {
        if self.pending.is_empty() {
            return Bytes::new();
        }
        let batch = batch_encode(&self.pending);
        self.pending.clear();
        self.pending_size = 0;
        batch
    }

    /// Check if there are pending packets.
    pub fn has_pending(&self) -> bool {
        !self.pending.is_empty()
    }
}

/// Session capability flags for SessionConfig.
pub mod flags {
    /// Bit 0: batching supported.
    pub const BATCHING: u8 = 0x01;
}
