use anyhow::{Result, anyhow};
use ipnet::Ipv4Net;
use std::collections::VecDeque;
use std::net::Ipv4Addr;
use std::sync::Arc;
use tokio::sync::Mutex;

/// Simple sequential IPv4 address allocator backed by a CIDR block.
#[derive(Clone)]
pub struct IpAllocator {
    inner: Arc<Mutex<IpAllocatorState>>,
    prefix: u8,
}

struct IpAllocatorState {
    network: Ipv4Net,
    available: VecDeque<Ipv4Addr>,
}

impl IpAllocator {
    /// Create a new allocator from a CIDR string (e.g. "10.0.0.0/24").
    pub fn new(cidr: &str) -> Result<Self> {
        let net: Ipv4Net = cidr
            .parse()
            .map_err(|e| anyhow!("invalid server.virtual_ip_range {cidr}: {e}"))?;

        let mut available = VecDeque::new();
        for addr in net.hosts() {
            available.push_back(addr);
        }

        if available.is_empty() {
            return Err(anyhow!(
                "virtual IP range {cidr} contains no host addresses"
            ));
        }

        Ok(Self {
            inner: Arc::new(Mutex::new(IpAllocatorState {
                network: net,
                available,
            })),
            prefix: net.prefix_len(),
        })
    }

    pub fn prefix_len(&self) -> u8 {
        self.prefix
    }

    /// Attempt to allocate an address. Returns None if the pool is exhausted.
    pub async fn allocate(&self) -> Option<IpLease> {
        let mut guard = self.inner.lock().await;
        guard.available.pop_front().map(|addr| IpLease {
            allocator: self.clone(),
            addr,
        })
    }

    async fn release(&self, addr: Ipv4Addr) {
        let mut guard = self.inner.lock().await;
        if guard.network.contains(&addr) {
            guard.available.push_back(addr);
        } else {
            tracing::warn!(%addr, "attempted to release IP outside of pool");
        }
    }
}

/// Lease that automatically returns the IP to the allocator when dropped.
pub struct IpLease {
    allocator: IpAllocator,
    addr: Ipv4Addr,
}

impl IpLease {
    pub fn addr(&self) -> Ipv4Addr {
        self.addr
    }
}

impl Drop for IpLease {
    fn drop(&mut self) {
        let allocator = self.allocator.clone();
        let addr = self.addr;
        tokio::spawn(async move {
            allocator.release(addr).await;
        });
    }
}
