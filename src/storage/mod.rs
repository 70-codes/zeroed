//! Storage module for the Zeroed DoS protection daemon
//!
//! This module provides an efficient, custom storage system designed for
//! high-performance logging and tracking of network events. Features include:
//!
//! - **Ring Buffer**: Fixed-size circular buffer for recent events with O(1) operations
//! - **Binary Format**: Custom compact binary format for minimal disk usage
//! - **Memory-Mapped Files**: Fast I/O using mmap for persistence
//! - **Sharded Storage**: Parallel write support through sharding
//! - **Bloom Filters**: Probabilistic data structure for quick IP lookups
//! - **Time-Series Bucketing**: Efficient time-based data organization
//!
//! # Storage Layout
//!
//! ```text
//! data/
//! ├── ring/                 # Ring buffer for recent events
//! │   ├── current.bin       # Current ring buffer (mmap'd)
//! │   └── overflow.bin      # Overflow buffer when ring is full
//! ├── archive/              # Archived historical data
//! │   ├── 2024-01-15/       # Date-based directories
//! │   │   ├── hour_00.zbin  # Hour-based binary files
//! │   │   └── hour_01.zbin
//! │   └── ...
//! ├── index/                # Indexes for fast lookups
//! │   ├── ip_bloom.bin      # Bloom filter for seen IPs
//! │   └── mac_bloom.bin     # Bloom filter for seen MACs
//! ├── state/                # Runtime state
//! │   ├── tracking.bin      # Current IP tracking data
//! │   └── blocked.bin       # Blocked IP list
//! └── wal/                  # Write-ahead log for durability
//!     ├── wal_001.bin
//!     └── wal_002.bin
//! ```

pub mod archive;
pub mod binary;
pub mod bloom;
pub mod index;
pub mod mmap;
pub mod mmap_ring;
pub mod ring;
pub mod ring_buffer;
pub mod shard;
pub mod wal;

use crate::core::config::StorageConfig;
use crate::core::error::{Result, StorageError, ZeroedError};
use crate::core::types::{ConnectionRecord, IpTrackingEntry, TrackingId};
use chrono::{DateTime, Utc};
use dashmap::DashMap;
use parking_lot::RwLock;
use serde::{Deserialize, Serialize};
use std::net::IpAddr;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use tracing::info;

// Re-export commonly used types
pub use bloom::BloomFilter;
pub use ring_buffer::RingBuffer;
pub use shard::ShardedStorage;
pub use wal::WriteAheadLog;

/// Storage file magic number for identification
pub const STORAGE_MAGIC: [u8; 4] = [0x5A, 0x45, 0x52, 0x4F]; // "ZERO"

/// Current storage format version
pub const STORAGE_VERSION: u8 = 1;

/// Default ring buffer capacity (number of records)
pub const DEFAULT_RING_CAPACITY: usize = 100_000;

/// Default shard count
pub const DEFAULT_SHARD_COUNT: usize = 16;

/// Storage statistics
#[derive(Debug, Default)]
pub struct StorageStats {
    /// Total records written
    pub records_written: AtomicU64,
    /// Total records read
    pub records_read: AtomicU64,
    /// Total bytes written
    pub bytes_written: AtomicU64,
    /// Total bytes read
    pub bytes_read: AtomicU64,
    /// Ring buffer overwrites
    pub ring_overwrites: AtomicU64,
    /// Bloom filter hits
    pub bloom_hits: AtomicU64,
    /// Bloom filter misses
    pub bloom_misses: AtomicU64,
    /// WAL entries written
    pub wal_entries: AtomicU64,
    /// Flush operations
    pub flush_count: AtomicU64,
}

impl StorageStats {
    pub fn snapshot(&self) -> StorageStatsSnapshot {
        StorageStatsSnapshot {
            records_written: self.records_written.load(Ordering::Relaxed),
            records_read: self.records_read.load(Ordering::Relaxed),
            bytes_written: self.bytes_written.load(Ordering::Relaxed),
            bytes_read: self.bytes_read.load(Ordering::Relaxed),
            ring_overwrites: self.ring_overwrites.load(Ordering::Relaxed),
            bloom_hits: self.bloom_hits.load(Ordering::Relaxed),
            bloom_misses: self.bloom_misses.load(Ordering::Relaxed),
            wal_entries: self.wal_entries.load(Ordering::Relaxed),
            flush_count: self.flush_count.load(Ordering::Relaxed),
        }
    }
}

/// Snapshot of storage statistics (non-atomic)
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct StorageStatsSnapshot {
    pub records_written: u64,
    pub records_read: u64,
    pub bytes_written: u64,
    pub bytes_read: u64,
    pub ring_overwrites: u64,
    pub bloom_hits: u64,
    pub bloom_misses: u64,
    pub wal_entries: u64,
    pub flush_count: u64,
}

/// Main storage engine for the Zeroed daemon
pub struct StorageEngine {
    /// Configuration
    config: StorageConfig,
    /// Base data directory
    data_dir: PathBuf,
    /// Ring buffer for recent connection records
    ring_buffer: Arc<RwLock<RingBuffer<StoredRecord>>>,
    /// Sharded writer for parallel writes
    sharded_writer: Arc<ShardedStorage>,
    /// Bloom filter for IP addresses
    ip_bloom: Arc<RwLock<BloomFilter>>,
    /// Bloom filter for MAC addresses
    mac_bloom: Arc<RwLock<BloomFilter>>,
    /// In-memory IP tracking cache
    ip_cache: Arc<DashMap<IpAddr, IpTrackingEntry>>,
    /// Write-ahead log for durability
    wal: Option<Arc<WriteAheadLog>>,
    /// Storage statistics
    stats: Arc<StorageStats>,
    /// Running flag
    is_running: std::sync::atomic::AtomicBool,
}

/// A stored record in the ring buffer
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StoredRecord {
    /// Record ID
    pub id: TrackingId,
    /// Timestamp
    pub timestamp: DateTime<Utc>,
    /// Source IP (as bytes for compact storage)
    pub src_ip: IpAddrBytes,
    /// Destination IP
    pub dst_ip: IpAddrBytes,
    /// Source port
    pub src_port: u16,
    /// Destination port
    pub dst_port: u16,
    /// Protocol (1 byte)
    pub protocol: u8,
    /// TCP flags (1 byte)
    pub tcp_flags: u8,
    /// Packet size
    pub packet_size: u32,
    /// Payload size
    pub payload_size: u32,
    /// Source MAC (6 bytes)
    pub src_mac: [u8; 6],
}

/// Compact IP address storage
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub enum IpAddrBytes {
    V4([u8; 4]),
    V6([u8; 16]),
}

impl From<IpAddr> for IpAddrBytes {
    fn from(ip: IpAddr) -> Self {
        match ip {
            IpAddr::V4(v4) => IpAddrBytes::V4(v4.octets()),
            IpAddr::V6(v6) => IpAddrBytes::V6(v6.octets()),
        }
    }
}

impl From<IpAddrBytes> for IpAddr {
    fn from(bytes: IpAddrBytes) -> Self {
        match bytes {
            IpAddrBytes::V4(b) => IpAddr::V4(b.into()),
            IpAddrBytes::V6(b) => IpAddr::V6(b.into()),
        }
    }
}

impl StoredRecord {
    /// Create from a ConnectionRecord
    pub fn from_connection(record: &ConnectionRecord) -> Self {
        let src_mac = record.src_mac.map(|m| m.0).unwrap_or([0u8; 6]);

        let tcp_flags = record.tcp_flags.map(|f| f.to_byte()).unwrap_or(0);

        Self {
            id: record.id,
            timestamp: record.timestamp,
            src_ip: record.src_ip.into(),
            dst_ip: record.dst_ip.into(),
            src_port: record.src_port.unwrap_or(0),
            dst_port: record.dst_port.unwrap_or(0),
            protocol: record.protocol.into(),
            tcp_flags,
            packet_size: record.packet_size,
            payload_size: record.payload_size,
            src_mac,
        }
    }

    /// Get source IP as IpAddr
    pub fn source_ip(&self) -> IpAddr {
        self.src_ip.into()
    }

    /// Get destination IP as IpAddr
    pub fn destination_ip(&self) -> IpAddr {
        self.dst_ip.into()
    }

    /// Binary size of this record
    pub const fn binary_size() -> usize {
        // id: 8 + timestamp: 8 + src_ip: 17 + dst_ip: 17 + ports: 4 + proto: 1 + flags: 1 + sizes: 8 + mac: 6
        8 + 8 + 17 + 17 + 4 + 1 + 1 + 8 + 6
    }
}

impl StorageEngine {
    /// Create a new storage engine
    pub async fn new(config: StorageConfig) -> Result<Self> {
        let data_dir = config.data_dir.clone();

        // Create directory structure
        Self::create_directories(&data_dir)?;

        // Initialize ring buffer
        let ring_buffer = Arc::new(RwLock::new(RingBuffer::new(config.ring_buffer_size)));

        // Initialize sharded storage
        let sharded_writer = Arc::new(ShardedStorage::new(
            data_dir.join("shards"),
            config.shard_count,
        )?);

        // Initialize bloom filters
        let ip_bloom = Arc::new(RwLock::new(BloomFilter::new(
            config.expected_unique_ips,
            config.bloom_fp_rate,
        )));

        let mac_bloom = Arc::new(RwLock::new(BloomFilter::new(
            config.expected_unique_ips / 10, // Fewer unique MACs expected
            config.bloom_fp_rate,
        )));

        // Initialize WAL if enabled
        let wal = if config.wal_enabled {
            Some(Arc::new(WriteAheadLog::new(data_dir.join("wal"))?))
        } else {
            None
        };

        // Load existing bloom filters if they exist
        let ip_bloom_path = data_dir.join("index").join("ip_bloom.bin");
        if ip_bloom_path.exists() {
            if let Ok(loaded) = BloomFilter::load(&ip_bloom_path) {
                *ip_bloom.write() = loaded;
                info!("Loaded existing IP bloom filter");
            }
        }

        let mac_bloom_path = data_dir.join("index").join("mac_bloom.bin");
        if mac_bloom_path.exists() {
            if let Ok(loaded) = BloomFilter::load(&mac_bloom_path) {
                *mac_bloom.write() = loaded;
                info!("Loaded existing MAC bloom filter");
            }
        }

        info!("Storage engine initialized at {:?}", data_dir);

        Ok(Self {
            config,
            data_dir,
            ring_buffer,
            sharded_writer,
            ip_bloom,
            mac_bloom,
            ip_cache: Arc::new(DashMap::new()),
            wal,
            stats: Arc::new(StorageStats::default()),
            is_running: std::sync::atomic::AtomicBool::new(true),
        })
    }

    /// Create required directory structure
    fn create_directories(base: &Path) -> Result<()> {
        let dirs = [
            base.to_path_buf(),
            base.join("ring"),
            base.join("archive"),
            base.join("index"),
            base.join("state"),
            base.join("wal"),
            base.join("shards"),
        ];

        for dir in &dirs {
            std::fs::create_dir_all(dir).map_err(|e| {
                ZeroedError::Storage(StorageError::InitializationError {
                    path: dir.clone(),
                    message: e.to_string(),
                })
            })?;
        }

        Ok(())
    }

    /// Store a connection record
    pub fn store(&self, record: &ConnectionRecord) -> Result<()> {
        let stored = StoredRecord::from_connection(record);

        // Add to ring buffer
        {
            let mut ring = self.ring_buffer.write();
            if ring.is_full() {
                self.stats.ring_overwrites.fetch_add(1, Ordering::Relaxed);
            }
            ring.push(stored.clone());
        }

        // Add to bloom filters
        {
            let mut ip_bloom = self.ip_bloom.write();
            ip_bloom.insert(&record.src_ip.to_string());
            ip_bloom.insert(&record.dst_ip.to_string());
        }

        if let Some(mac) = &record.src_mac {
            let mut mac_bloom = self.mac_bloom.write();
            mac_bloom.insert(&format!("{}", mac));
        }

        // Write to WAL if enabled
        if let Some(wal) = &self.wal {
            let serialized = bincode::serialize(&stored).map_err(|e| {
                ZeroedError::Storage(StorageError::SerializationError {
                    message: e.to_string(),
                })
            })?;
            wal.append(&serialized)?;
            self.stats.wal_entries.fetch_add(1, Ordering::Relaxed);
        }

        // Write to sharded storage
        self.sharded_writer.write(&stored)?;

        // Update statistics
        self.stats.records_written.fetch_add(1, Ordering::Relaxed);
        self.stats
            .bytes_written
            .fetch_add(StoredRecord::binary_size() as u64, Ordering::Relaxed);

        Ok(())
    }

    /// Check if an IP has been seen (using bloom filter)
    pub fn has_seen_ip(&self, ip: &IpAddr) -> bool {
        let ip_bloom = self.ip_bloom.read();
        let result = ip_bloom.contains(&ip.to_string());

        if result {
            self.stats.bloom_hits.fetch_add(1, Ordering::Relaxed);
        } else {
            self.stats.bloom_misses.fetch_add(1, Ordering::Relaxed);
        }

        result
    }

    /// Get recent records from ring buffer
    pub fn get_recent(&self, count: usize) -> Vec<StoredRecord> {
        let ring = self.ring_buffer.read();
        let records = ring.get_latest(count);
        self.stats
            .records_read
            .fetch_add(records.len() as u64, Ordering::Relaxed);
        records
    }

    /// Get records for a specific IP from ring buffer
    pub fn get_records_for_ip(&self, ip: &IpAddr) -> Vec<StoredRecord> {
        let ring = self.ring_buffer.read();
        ring.filter(|r| r.source_ip() == *ip || r.destination_ip() == *ip)
    }

    /// Update or insert IP tracking entry
    pub fn upsert_ip_tracking(&self, entry: IpTrackingEntry) {
        self.ip_cache.insert(entry.ip, entry);
    }

    /// Get IP tracking entry
    pub fn get_ip_tracking(&self, ip: &IpAddr) -> Option<IpTrackingEntry> {
        self.ip_cache.get(ip).map(|e| e.clone())
    }

    /// Get all tracked IPs
    pub fn get_all_tracked_ips(&self) -> Vec<IpAddr> {
        self.ip_cache.iter().map(|e| *e.key()).collect()
    }

    /// Get blocked IPs
    pub fn get_blocked_ips(&self) -> Vec<IpTrackingEntry> {
        self.ip_cache
            .iter()
            .filter(|e| e.is_blocked)
            .map(|e| e.clone())
            .collect()
    }

    /// Flush all buffers to disk
    pub async fn flush(&self) -> Result<()> {
        info!("Flushing storage buffers to disk");

        // Flush sharded storage
        self.sharded_writer.flush()?;

        // Save bloom filters
        {
            let ip_bloom = self.ip_bloom.read();
            ip_bloom.save(&self.data_dir.join("index").join("ip_bloom.bin"))?;
        }
        {
            let mac_bloom = self.mac_bloom.read();
            mac_bloom.save(&self.data_dir.join("index").join("mac_bloom.bin"))?;
        }

        // Flush WAL
        if let Some(wal) = &self.wal {
            wal.flush()?;
        }

        // Save IP tracking cache
        self.save_ip_cache()?;

        self.stats.flush_count.fetch_add(1, Ordering::Relaxed);
        info!("Storage flush complete");
        Ok(())
    }

    /// Save IP tracking cache to disk
    fn save_ip_cache(&self) -> Result<()> {
        let entries: Vec<IpTrackingEntry> = self.ip_cache.iter().map(|e| e.clone()).collect();
        let path = self.data_dir.join("state").join("tracking.bin");

        let serialized = bincode::serialize(&entries).map_err(|e| {
            ZeroedError::Storage(StorageError::SerializationError {
                message: e.to_string(),
            })
        })?;

        std::fs::write(&path, serialized).map_err(|e| {
            ZeroedError::Storage(StorageError::WriteError {
                message: e.to_string(),
            })
        })?;

        Ok(())
    }

    /// Load IP tracking cache from disk
    pub fn load_ip_cache(&self) -> Result<()> {
        let path = self.data_dir.join("state").join("tracking.bin");
        if !path.exists() {
            return Ok(());
        }

        let data = std::fs::read(&path).map_err(|e| {
            ZeroedError::Storage(StorageError::ReadError {
                message: e.to_string(),
            })
        })?;

        let entries: Vec<IpTrackingEntry> = bincode::deserialize(&data).map_err(|e| {
            ZeroedError::Storage(StorageError::DeserializationError {
                message: e.to_string(),
            })
        })?;

        for entry in entries {
            self.ip_cache.insert(entry.ip, entry);
        }

        info!("Loaded {} IP tracking entries", self.ip_cache.len());
        Ok(())
    }

    /// Get storage statistics
    pub fn stats(&self) -> StorageStatsSnapshot {
        self.stats.snapshot()
    }

    /// Get ring buffer size
    pub fn ring_buffer_size(&self) -> usize {
        self.ring_buffer.read().len()
    }

    /// Get IP cache size
    pub fn ip_cache_size(&self) -> usize {
        self.ip_cache.len()
    }

    /// Cleanup old data based on TTL
    pub async fn cleanup(&self) -> Result<usize> {
        let now = Utc::now();
        let ttl =
            chrono::Duration::from_std(self.config.record_ttl).unwrap_or(chrono::Duration::days(7));
        let cutoff = now - ttl;
        let mut removed = 0;

        // Clean up IP cache
        self.ip_cache.retain(|_, entry| {
            let keep = entry.last_seen > cutoff;
            if !keep {
                removed += 1;
            }
            keep
        });

        // TODO: Clean up archived data

        info!("Cleanup removed {} expired entries", removed);
        Ok(removed)
    }

    /// Shutdown the storage engine gracefully
    pub async fn shutdown(&self) -> Result<()> {
        info!("Shutting down storage engine");
        self.is_running
            .store(false, std::sync::atomic::Ordering::SeqCst);
        self.flush().await?;
        info!("Storage engine shutdown complete");
        Ok(())
    }

    /// Check if engine is running
    pub fn is_running(&self) -> bool {
        self.is_running.load(std::sync::atomic::Ordering::SeqCst)
    }

    /// Get the data directory path
    pub fn data_dir(&self) -> &Path {
        &self.data_dir
    }
}

/// Query options for searching records
#[derive(Debug, Clone, Default)]
pub struct QueryOptions {
    /// Filter by source IP
    pub src_ip: Option<IpAddr>,
    /// Filter by destination IP
    pub dst_ip: Option<IpAddr>,
    /// Filter by source port
    pub src_port: Option<u16>,
    /// Filter by destination port
    pub dst_port: Option<u16>,
    /// Filter by protocol
    pub protocol: Option<u8>,
    /// Start time
    pub start_time: Option<DateTime<Utc>>,
    /// End time
    pub end_time: Option<DateTime<Utc>>,
    /// Maximum results
    pub limit: Option<usize>,
    /// Offset for pagination
    pub offset: Option<usize>,
}

impl QueryOptions {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn with_src_ip(mut self, ip: IpAddr) -> Self {
        self.src_ip = Some(ip);
        self
    }

    pub fn with_dst_ip(mut self, ip: IpAddr) -> Self {
        self.dst_ip = Some(ip);
        self
    }

    pub fn with_limit(mut self, limit: usize) -> Self {
        self.limit = Some(limit);
        self
    }

    pub fn matches(&self, record: &StoredRecord) -> bool {
        if let Some(src_ip) = self.src_ip {
            if record.source_ip() != src_ip {
                return false;
            }
        }
        if let Some(dst_ip) = self.dst_ip {
            if record.destination_ip() != dst_ip {
                return false;
            }
        }
        if let Some(src_port) = self.src_port {
            if record.src_port != src_port {
                return false;
            }
        }
        if let Some(dst_port) = self.dst_port {
            if record.dst_port != dst_port {
                return false;
            }
        }
        if let Some(protocol) = self.protocol {
            if record.protocol != protocol {
                return false;
            }
        }
        if let Some(start) = self.start_time {
            if record.timestamp < start {
                return false;
            }
        }
        if let Some(end) = self.end_time {
            if record.timestamp > end {
                return false;
            }
        }
        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::net::Ipv4Addr;

    #[test]
    fn test_ip_addr_bytes_conversion() {
        let v4 = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1));
        let bytes: IpAddrBytes = v4.into();
        let back: IpAddr = bytes.into();
        assert_eq!(v4, back);
    }

    #[test]
    fn test_stored_record_size() {
        assert!(StoredRecord::binary_size() < 100); // Should be compact
    }

    #[test]
    fn test_query_options() {
        let query = QueryOptions::new()
            .with_src_ip(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1)))
            .with_limit(100);

        assert!(query.src_ip.is_some());
        assert_eq!(query.limit, Some(100));
    }
}
