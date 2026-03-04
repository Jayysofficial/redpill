use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Instant;

pub struct Stats {
    pub datagrams_sent: AtomicU64,
    pub datagrams_recv: AtomicU64,
    pub datagrams_blocked: AtomicU64,
    pub datagrams_too_large: AtomicU64,
    pub bytes_sent: AtomicU64,
    pub bytes_recv: AtomicU64,
    pub tun_reads: AtomicU64,
    pub tun_writes: AtomicU64,
    pub spoofed: AtomicU64,
    pub datagrams_wait_timeouts: AtomicU64,
    pub dg_size_min: AtomicU64,
    pub dg_size_max: AtomicU64,
    pub dg_size_sum: AtomicU64,
    pub start: Instant,
}

impl Default for Stats {
    fn default() -> Self {
        Self::new()
    }
}

impl Stats {
    pub fn new() -> Self {
        Self {
            datagrams_sent: AtomicU64::new(0),
            datagrams_recv: AtomicU64::new(0),
            datagrams_blocked: AtomicU64::new(0),
            datagrams_too_large: AtomicU64::new(0),
            bytes_sent: AtomicU64::new(0),
            bytes_recv: AtomicU64::new(0),
            tun_reads: AtomicU64::new(0),
            tun_writes: AtomicU64::new(0),
            spoofed: AtomicU64::new(0),
            datagrams_wait_timeouts: AtomicU64::new(0),
            dg_size_min: AtomicU64::new(u64::MAX),
            dg_size_max: AtomicU64::new(0),
            dg_size_sum: AtomicU64::new(0),
            start: Instant::now(),
        }
    }

    pub fn record_send(&self, size: usize) {
        self.datagrams_sent.fetch_add(1, Ordering::Relaxed);
        self.bytes_sent.fetch_add(size as u64, Ordering::Relaxed);
        self.update_dg_size(size);
    }

    pub fn record_recv(&self, size: usize) {
        self.datagrams_recv.fetch_add(1, Ordering::Relaxed);
        self.bytes_recv.fetch_add(size as u64, Ordering::Relaxed);
    }

    pub fn record_blocked(&self) {
        self.datagrams_blocked.fetch_add(1, Ordering::Relaxed);
    }

    pub fn record_too_large(&self) {
        self.datagrams_too_large.fetch_add(1, Ordering::Relaxed);
    }

    pub fn record_spoofed(&self) {
        self.spoofed.fetch_add(1, Ordering::Relaxed);
    }

    pub fn record_wait_timeout(&self) {
        self.datagrams_wait_timeouts.fetch_add(1, Ordering::Relaxed);
    }

    fn update_dg_size(&self, size: usize) {
        let size = size as u64;
        self.dg_size_sum.fetch_add(size, Ordering::Relaxed);
        let mut current = self.dg_size_min.load(Ordering::Relaxed);
        while size < current {
            match self.dg_size_min.compare_exchange_weak(
                current,
                size,
                Ordering::Relaxed,
                Ordering::Relaxed,
            ) {
                Ok(_) => break,
                Err(c) => current = c,
            }
        }
        current = self.dg_size_max.load(Ordering::Relaxed);
        while size > current {
            match self.dg_size_max.compare_exchange_weak(
                current,
                size,
                Ordering::Relaxed,
                Ordering::Relaxed,
            ) {
                Ok(_) => break,
                Err(c) => current = c,
            }
        }
    }

    /// Report stats without QUIC-specific path info (for TCP/WS transports).
    pub fn report_basic(&self) {
        let elapsed = self.start.elapsed().as_secs_f64();
        let sent = self.datagrams_sent.load(Ordering::Relaxed);
        let recv = self.datagrams_recv.load(Ordering::Relaxed);
        let blocked = self.datagrams_blocked.load(Ordering::Relaxed);
        let too_large = self.datagrams_too_large.load(Ordering::Relaxed);
        let bytes_tx = self.bytes_sent.load(Ordering::Relaxed);
        let bytes_rx = self.bytes_recv.load(Ordering::Relaxed);

        let total_attempted = sent + blocked;
        let blocked_pct = if total_attempted > 0 {
            blocked as f64 / total_attempted as f64 * 100.0
        } else {
            0.0
        };

        let tx_mbps = bytes_tx as f64 * 8.0 / elapsed / 1_000_000.0;
        let rx_mbps = bytes_rx as f64 * 8.0 / elapsed / 1_000_000.0;

        tracing::info!(
            "\n[{elapsed:.1}s] TX: {sent} pkts ({tx_mb:.1} MB) | RX: {recv} pkts ({rx_mb:.1} MB)\n\
             \x20       blocked: {blocked}/{total_attempted} ({blocked_pct:.2}%) | too_large: {too_large}\n\
             \x20       throughput: TX {tx_mbps:.1} Mbps | RX {rx_mbps:.1} Mbps",
            tx_mb = bytes_tx as f64 / 1_000_000.0,
            rx_mb = bytes_rx as f64 / 1_000_000.0,
        );
    }

    pub fn report(&self, conn: &quinn::Connection) {
        let elapsed = self.start.elapsed().as_secs_f64();
        let sent = self.datagrams_sent.load(Ordering::Relaxed);
        let recv = self.datagrams_recv.load(Ordering::Relaxed);
        let blocked = self.datagrams_blocked.load(Ordering::Relaxed);
        let too_large = self.datagrams_too_large.load(Ordering::Relaxed);
        let spoofed = self.spoofed.load(Ordering::Relaxed);
        let wait_timeouts = self.datagrams_wait_timeouts.load(Ordering::Relaxed);
        let bytes_tx = self.bytes_sent.load(Ordering::Relaxed);
        let bytes_rx = self.bytes_recv.load(Ordering::Relaxed);
        let dg_min = self.dg_size_min.load(Ordering::Relaxed);
        let dg_max = self.dg_size_max.load(Ordering::Relaxed);
        let dg_sum = self.dg_size_sum.load(Ordering::Relaxed);

        let total_attempted = sent + blocked;
        let blocked_pct = if total_attempted > 0 {
            blocked as f64 / total_attempted as f64 * 100.0
        } else {
            0.0
        };

        let tx_mbps = bytes_tx as f64 * 8.0 / elapsed / 1_000_000.0;
        let rx_mbps = bytes_rx as f64 * 8.0 / elapsed / 1_000_000.0;

        let dg_avg = if sent > 0 { dg_sum / sent } else { 0 };
        let dg_min_display = if dg_min == u64::MAX { 0 } else { dg_min };

        let stats = conn.stats();
        let rtt_ms = stats.path.rtt.as_secs_f64() * 1000.0;
        let cwnd = stats.path.cwnd;
        let lost = stats.path.lost_packets;
        let sent_pkts = stats.path.sent_packets;
        let lost_pct = if sent_pkts > 0 {
            lost as f64 / sent_pkts as f64 * 100.0
        } else {
            0.0
        };

        let max_dg = conn.max_datagram_size().unwrap_or(0);

        tracing::info!(
            "\n[{elapsed:.1}s] TX: {sent} pkts ({tx_mb:.1} MB) | RX: {recv} pkts ({rx_mb:.1} MB)\n\
             \x20       blocked: {blocked}/{total_attempted} ({blocked_pct:.2}%) | too_large: {too_large} | spoofed: {spoofed} | wait_timeouts: {wait_timeouts}\n\
             \x20       RTT: {rtt_ms:.1}ms | cwnd: {cwnd} | lost: {lost}/{sent_pkts} ({lost_pct:.2}%)\n\
             \x20       throughput: TX {tx_mbps:.1} Mbps | RX {rx_mbps:.1} Mbps\n\
             \x20       dg_size: min={dg_min_display} avg={dg_avg} max={dg_max} | max_datagram_size={max_dg}",
            tx_mb = bytes_tx as f64 / 1_000_000.0,
            rx_mb = bytes_rx as f64 / 1_000_000.0,
        );
    }
}
