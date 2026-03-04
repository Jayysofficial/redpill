use std::collections::HashSet;
use std::net::Ipv4Addr;

/// IP address allocator for the VPN subnet.
///
/// Allocates from base+2 to base+254 (e.g. 10.0.1.2 - 10.0.1.254).
/// base+0 is the network address, base+1 is the server, base+255 is broadcast.
pub struct IpPool {
    base: [u8; 3], // first 3 octets
    allocated: HashSet<u8>,
}

impl IpPool {
    /// Create a new pool for the given /24 subnet.
    /// `base` should be the network address (e.g. 10.0.1.0).
    pub fn new(base: Ipv4Addr) -> Self {
        let octets = base.octets();
        Self {
            base: [octets[0], octets[1], octets[2]],
            allocated: HashSet::new(),
        }
    }

    /// Allocate the next available IP. Returns None if pool is exhausted.
    pub fn allocate(&mut self) -> Option<Ipv4Addr> {
        for host in 2..=254u8 {
            if !self.allocated.contains(&host) {
                self.allocated.insert(host);
                return Some(Ipv4Addr::new(
                    self.base[0],
                    self.base[1],
                    self.base[2],
                    host,
                ));
            }
        }
        None
    }

    /// Release an IP back to the pool.
    pub fn release(&mut self, ip: Ipv4Addr) {
        let octets = ip.octets();
        if octets[0] == self.base[0] && octets[1] == self.base[1] && octets[2] == self.base[2] {
            self.allocated.remove(&octets[3]);
        }
    }

    /// Check if an IP is currently allocated.
    pub fn is_allocated(&self, ip: Ipv4Addr) -> bool {
        let octets = ip.octets();
        if octets[0] == self.base[0] && octets[1] == self.base[1] && octets[2] == self.base[2] {
            self.allocated.contains(&octets[3])
        } else {
            false
        }
    }

    /// Number of currently allocated IPs.
    pub fn len(&self) -> usize {
        self.allocated.len()
    }

    pub fn is_empty(&self) -> bool {
        self.allocated.is_empty()
    }
}
