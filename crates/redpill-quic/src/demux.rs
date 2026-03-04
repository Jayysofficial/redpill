//! Multi-client demultiplexer: route TUN packets to the correct client.
//!
//! A single global TUN reader reads all packets, extracts the destination IP,
//! and dispatches to the correct client's priority queue via `ClientRouter`.
//! `ClientHandle` provides RAII unregistration on drop.

use std::net::Ipv4Addr;
use std::sync::Arc;

use bytes::Bytes;
use dashmap::DashMap;

use crate::priority::{classify, PriorityQueue};

/// Routes TUN-read packets to the correct client based on destination IP.
pub struct ClientRouter {
    routes: DashMap<Ipv4Addr, Arc<PriorityQueue>>,
}

impl Default for ClientRouter {
    fn default() -> Self {
        Self::new()
    }
}

impl ClientRouter {
    pub fn new() -> Self {
        Self {
            routes: DashMap::new(),
        }
    }

    /// Register a client and return a RAII handle that unregisters on drop.
    /// Also returns a reference to the client's priority queue.
    pub fn register(
        self: &Arc<Self>,
        client_ip: Ipv4Addr,
        buffer: usize,
    ) -> (ClientHandle, Arc<PriorityQueue>) {
        let queue = Arc::new(PriorityQueue::new(buffer));
        self.routes.insert(client_ip, Arc::clone(&queue));
        let handle = ClientHandle {
            router: Arc::clone(self),
            client_ip,
        };
        (handle, queue)
    }

    /// Try to send a packet to the client owning `dst_ip`.
    /// Classifies the packet and pushes to the appropriate priority lane.
    /// Returns false if no client is registered for that IP or the queue is full.
    pub fn route(&self, dst_ip: Ipv4Addr, packet: Bytes) -> bool {
        if let Some(queue) = self.routes.get(&dst_ip) {
            let priority = classify(&packet);
            queue.push(packet, priority)
        } else {
            false
        }
    }

    /// Number of registered clients.
    pub fn len(&self) -> usize {
        self.routes.len()
    }

    pub fn is_empty(&self) -> bool {
        self.routes.is_empty()
    }

    fn unregister(&self, ip: Ipv4Addr) {
        self.routes.remove(&ip);
    }
}

/// RAII guard that unregisters the client from the router on drop.
pub struct ClientHandle {
    router: Arc<ClientRouter>,
    client_ip: Ipv4Addr,
}

impl ClientHandle {
    pub fn client_ip(&self) -> Ipv4Addr {
        self.client_ip
    }
}

impl Drop for ClientHandle {
    fn drop(&mut self) {
        self.router.unregister(self.client_ip);
    }
}
