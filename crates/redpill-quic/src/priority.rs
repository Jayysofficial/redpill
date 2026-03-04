//! Traffic prioritization: classify packets and provide priority queuing.
//!
//! Realtime traffic (small UDP, DNS, DSCP EF) is dequeued first.
//! Stale realtime packets (>10ms old) are dropped on pop.

use std::collections::VecDeque;
use std::time::{Duration, Instant};

use bytes::Bytes;
use parking_lot::Mutex;
use tokio::sync::Notify;

/// Maximum age for realtime packets before they're considered stale.
const REALTIME_MAX_AGE: Duration = Duration::from_millis(10);

/// Packet priority classification.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Priority {
    Realtime,
    Bulk,
}

/// Classify a raw IP packet into a priority level.
///
/// Realtime: DSCP EF (46), small UDP (<300B), DNS (UDP port 53).
/// Bulk: everything else.
pub fn classify(packet: &[u8]) -> Priority {
    if packet.len() < 20 {
        return Priority::Bulk;
    }

    // IPv4 only
    if packet[0] >> 4 != 4 {
        return Priority::Bulk;
    }

    let dscp = packet[1] >> 2;
    if dscp == 46 {
        return Priority::Realtime; // DSCP EF
    }

    let protocol = packet[9];
    if protocol != 17 {
        return Priority::Bulk; // not UDP
    }

    let ihl = (packet[0] & 0x0F) as usize * 4;
    if packet.len() < ihl + 4 {
        return Priority::Bulk;
    }

    let dst_port = u16::from_be_bytes([packet[ihl + 2], packet[ihl + 3]]);
    if dst_port == 53 {
        return Priority::Realtime;
    }

    if packet.len() < 300 {
        return Priority::Realtime;
    }

    Priority::Bulk
}

/// Priority queue with two lanes: realtime (timestamped) and bulk.
///
/// Dequeue always drains realtime first. Stale realtime packets are dropped.
pub struct PriorityQueue {
    realtime: Mutex<VecDeque<(Instant, Bytes)>>,
    bulk: Mutex<VecDeque<Bytes>>,
    notify: Notify,
    capacity: usize,
}

impl PriorityQueue {
    pub fn new(capacity: usize) -> Self {
        Self {
            realtime: Mutex::new(VecDeque::with_capacity(capacity / 4)),
            bulk: Mutex::new(VecDeque::with_capacity(capacity)),
            notify: Notify::new(),
            capacity,
        }
    }

    /// Push a packet into the appropriate queue.
    /// Returns false if the queue is full (backpressure).
    pub fn push(&self, packet: Bytes, priority: Priority) -> bool {
        match priority {
            Priority::Realtime => {
                let mut q = self.realtime.lock();
                if q.len() >= self.capacity / 4 {
                    return false;
                }
                q.push_back((Instant::now(), packet));
            }
            Priority::Bulk => {
                let mut q = self.bulk.lock();
                if q.len() >= self.capacity {
                    return false;
                }
                q.push_back(packet);
            }
        }
        self.notify.notify_one();
        true
    }

    /// Pop the highest-priority packet, dropping stale realtime packets.
    pub fn try_pop(&self) -> Option<Bytes> {
        {
            let mut q = self.realtime.lock();
            let now = Instant::now();
            while let Some((ts, pkt)) = q.pop_front() {
                if now.duration_since(ts) <= REALTIME_MAX_AGE {
                    return Some(pkt);
                }
            }
        }

        self.bulk.lock().pop_front()
    }

    /// Wait for a packet to become available, then pop it.
    pub async fn pop(&self) -> Bytes {
        loop {
            if let Some(pkt) = self.try_pop() {
                return pkt;
            }
            self.notify.notified().await;
        }
    }
}
