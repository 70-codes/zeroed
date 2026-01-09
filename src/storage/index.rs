//! Index module for fast lookups
//!
//! This module provides indexing functionality for efficient data retrieval
//! in the Zeroed storage system.

// Re-export bloom filter as the primary index structure
pub use super::bloom::{BloomFilter, BloomFilterStats, CountingBloomFilter, ScalableBloomFilter};

/// Index types supported
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IndexType {
    /// Bloom filter for probabilistic membership testing
    Bloom,
    /// Counting bloom filter with deletion support
    CountingBloom,
    /// Scalable bloom filter that grows automatically
    ScalableBloom,
    /// Hash index for exact lookups
    Hash,
}

/// Trait for indexable items
pub trait Indexable {
    /// Get the key for indexing
    fn index_key(&self) -> String;
}

impl Indexable for std::net::IpAddr {
    fn index_key(&self) -> String {
        self.to_string()
    }
}

impl Indexable for String {
    fn index_key(&self) -> String {
        self.clone()
    }
}

impl Indexable for &str {
    fn index_key(&self) -> String {
        self.to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{IpAddr, Ipv4Addr};

    #[test]
    fn test_ip_indexable() {
        let ip = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1));
        assert_eq!(ip.index_key(), "192.168.1.1");
    }
}
