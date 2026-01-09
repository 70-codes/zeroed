//! Sharded storage module for parallel writes
//!
//! This module provides a sharded storage system that distributes writes
//! across multiple files/buffers to reduce lock contention and improve
//! write throughput in high-traffic scenarios.
//!
//! ## Sharding Strategy
//!
//! Records are distributed across shards using consistent hashing based on
//! the source IP address. This ensures that records for the same IP always
//! go to the same shard, making queries more efficient.

use std::fs::{File, OpenOptions};
use std::io::{BufWriter, Write};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

use chrono::{DateTime, Utc};
use parking_lot::{Mutex, RwLock};
use serde::{Deserialize, Serialize};
use tracing::{debug, error, info, trace, warn};

use super::StoredRecord;
use crate::core::error::{Result, StorageError, ZeroedError};

// ─────────────────────────────────────────────────────────────────────────────
// Constants
// ─────────────────────────────────────────────────────────────────────────────

/// Default number of shards
pub const DEFAULT_SHARD_COUNT: usize = 16;

/// Default buffer size per shard (64 KB)
pub const DEFAULT_BUFFER_SIZE: usize = 64 * 1024;

/// Shard file extension
const SHARD_EXTENSION: &str = "shard";

/// Shard index file name
const SHARD_INDEX_FILE: &str = "shards.idx";

// ─────────────────────────────────────────────────────────────────────────────
// Shard Configuration
// ─────────────────────────────────────────────────────────────────────────────

/// Configuration for sharded storage
#[derive(Debug, Clone)]
pub struct ShardConfig {
    /// Number of shards
    pub shard_count: usize,
    /// Base directory for shard files
    pub base_dir: PathBuf,
    /// Buffer size per shard
    pub buffer_size: usize,
    /// Sync mode (sync on every write, periodic, or manual)
    pub sync_mode: SyncMode,
    /// Maximum shard file size in bytes (0 = unlimited)
    pub max_shard_size: u64,
    /// Enable compression
    pub compression: bool,
}

impl Default for ShardConfig {
    fn default() -> Self {
        Self {
            shard_count: DEFAULT_SHARD_COUNT,
            base_dir: PathBuf::from("/var/lib/zeroed/shards"),
            buffer_size: DEFAULT_BUFFER_SIZE,
            sync_mode: SyncMode::Periodic,
            max_shard_size: 100 * 1024 * 1024, // 100 MB
            compression: false,
        }
    }
}

/// Sync mode for shard writes
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SyncMode {
    /// Sync after every write (safest, slowest)
    Always,
    /// Sync periodically (balanced)
    Periodic,
    /// Manual sync only (fastest, least safe)
    Manual,
}

// ─────────────────────────────────────────────────────────────────────────────
// Individual Shard
// ─────────────────────────────────────────────────────────────────────────────

/// An individual storage shard
pub struct Shard {
    /// Shard ID
    id: usize,
    /// File path
    path: PathBuf,
    /// Buffered writer
    writer: Mutex<Option<BufWriter<File>>>,
    /// Records written to this shard
    records_written: AtomicU64,
    /// Bytes written to this shard
    bytes_written: AtomicU64,
    /// Current file size
    file_size: AtomicU64,
    /// Configuration
    config: ShardConfig,
    /// Last flush timestamp
    last_flush: RwLock<DateTime<Utc>>,
    /// Is shard open
    is_open: std::sync::atomic::AtomicBool,
}

impl Shard {
    /// Create a new shard
    pub fn new(id: usize, config: ShardConfig) -> Result<Self> {
        let path = config.base_dir.join(format!("shard_{:04}.{}", id, SHARD_EXTENSION));

        Ok(Self {
            id,
            path,
            writer: Mutex::new(None),
            records_written: AtomicU64::new(0),
            bytes_written: AtomicU64::new(0),
            file_size: AtomicU64::new(0),
            config,
            last_flush: RwLock::new(Utc::now()),
            is_open: std::sync::atomic::AtomicBool::new(false),
        })
    }

    /// Open the shard for writing
    pub fn open(&self) -> Result<()> {
        let file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(&self.path)
            .map_err(|e| {
                ZeroedError::Storage(StorageError::InitializationError {
                    path: self.path.clone(),
                    message: e.to_string(),
                })
            })?;

        // Get current file size
        let metadata = file.metadata().map_err(|e| {
            ZeroedError::Storage(StorageError::ReadError {
                message: e.to_string(),
            })
        })?;
        self.file_size.store(metadata.len(), Ordering::SeqCst);

        let writer = BufWriter::with_capacity(self.config.buffer_size, file);

        *self.writer.lock() = Some(writer);
        self.is_open.store(true, std::sync::atomic::Ordering::SeqCst);

        debug!("Opened shard {} at {:?}", self.id, self.path);
        Ok(())
    }

    /// Close the shard
    pub fn close(&self) -> Result<()> {
        self.flush()?;
        *self.writer.lock() = None;
        self.is_open.store(false, std::sync::atomic::Ordering::SeqCst);
        debug!("Closed shard {}", self.id);
        Ok(())
    }

    /// Write a record to the shard
    pub fn write(&self, data: &[u8]) -> Result<usize> {
        if !self.is_open.load(std::sync::atomic::Ordering::SeqCst) {
            self.open()?;
        }

        let mut writer_guard = self.writer.lock();
        let writer = writer_guard.as_mut().ok_or_else(|| {
            ZeroedError::Storage(StorageError::WriteError {
                message: "Shard not open".to_string(),
            })
        })?;

        // Write length prefix (4 bytes) + data
        let len = data.len() as u32;
        writer.write_all(&len.to_le_bytes()).map_err(|e| {
            ZeroedError::Storage(StorageError::WriteError {
                message: e.to_string(),
            })
        })?;

        writer.write_all(data).map_err(|e| {
            ZeroedError::Storage(StorageError::WriteError {
                message: e.to_string(),
            })
        })?;

        let total_bytes = 4 + data.len();
        self.records_written.fetch_add(1, Ordering::Relaxed);
        self.bytes_written.fetch_add(total_bytes as u64, Ordering::Relaxed);
        self.file_size.fetch_add(total_bytes as u64, Ordering::Relaxed);

        // Sync if configured
        if self.config.sync_mode == SyncMode::Always {
            writer.flush().map_err(|e| {
                ZeroedError::Storage(StorageError::WriteError {
                    message: e.to_string(),
                })
            })?;
        }

        trace!("Wrote {} bytes to shard {}", total_bytes, self.id);
        Ok(total_bytes)
    }

    /// Flush the shard buffer
    pub fn flush(&self) -> Result<()> {
        let mut writer_guard = self.writer.lock();
        if let Some(writer) = writer_guard.as_mut() {
            writer.flush().map_err(|e| {
                ZeroedError::Storage(StorageError::WriteError {
                    message: e.to_string(),
                })
            })?;
            *self.last_flush.write() = Utc::now();
        }
        Ok(())
    }

    /// Get shard statistics
    pub fn stats(&self) -> ShardStats {
        ShardStats {
            id: self.id,
            path: self.path.clone(),
            records_written: self.records_written.load(Ordering::Relaxed),
            bytes_written: self.bytes_written.load(Ordering::Relaxed),
            file_size: self.file_size.load(Ordering::Relaxed),
            last_flush: *self.last_flush.read(),
            is_open: self.is_open.load(std::sync::atomic::Ordering::SeqCst),
        }
    }

    /// Check if shard should rotate (file too large)
    pub fn should_rotate(&self) -> bool {
        if self.config.max_shard_size == 0 {
            return false;
        }
        self.file_size.load(Ordering::Relaxed) >= self.config.max_shard_size
    }

    /// Get shard ID
    pub fn id(&self) -> usize {
        self.id
    }

    /// Get shard path
    pub fn path(&self) -> &Path {
        &self.path
    }
}

impl Drop for Shard {
    fn drop(&mut self) {
        if let Err(e) = self.flush() {
            error!("Failed to flush shard {} on drop: {}", self.id, e);
        }
    }
}

/// Statistics for an individual shard
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ShardStats {
    pub id: usize,
    pub path: PathBuf,
    pub records_written: u64,
    pub bytes_written: u64,
    pub file_size: u64,
    pub last_flush: DateTime<Utc>,
    pub is_open: bool,
}

// ─────────────────────────────────────────────────────────────────────────────
// Sharded Storage
// ─────────────────────────────────────────────────────────────────────────────

/// Sharded storage system for high-throughput writes
pub struct ShardedStorage {
    /// Individual shards
    shards: Vec<Arc<Shard>>,
    /// Configuration
    config: ShardConfig,
    /// Total records written
    total_records: AtomicU64,
    /// Total bytes written
    total_bytes: AtomicU64,
    /// Round-robin counter for distribution
    round_robin: AtomicU64,
}

impl ShardedStorage {
    /// Create a new sharded storage
    pub fn new(base_dir: PathBuf, shard_count: usize) -> Result<Self> {
        let config = ShardConfig {
            shard_count,
            base_dir: base_dir.clone(),
            ..Default::default()
        };

        Self::with_config(config)
    }

    /// Create with custom configuration
    pub fn with_config(config: ShardConfig) -> Result<Self> {
        // Create base directory if it doesn't exist
        std::fs::create_dir_all(&config.base_dir).map_err(|e| {
            ZeroedError::Storage(StorageError::InitializationError {
                path: config.base_dir.clone(),
                message: e.to_string(),
            })
        })?;

        // Create shards
        let mut shards = Vec::with_capacity(config.shard_count);
        for i in 0..config.shard_count {
            let shard = Shard::new(i, config.clone())?;
            shards.push(Arc::new(shard));
        }

        info!(
            "Created sharded storage with {} shards at {:?}",
            config.shard_count, config.base_dir
        );

        Ok(Self {
            shards,
            config,
            total_records: AtomicU64::new(0),
            total_bytes: AtomicU64::new(0),
            round_robin: AtomicU64::new(0),
        })
    }

    /// Get shard for a given key (hash-based sharding)
    fn get_shard_for_key(&self, key: u64) -> &Arc<Shard> {
        let idx = (key as usize) % self.shards.len();
        &self.shards[idx]
    }

    /// Get shard using round-robin distribution
    fn get_shard_round_robin(&self) -> &Arc<Shard> {
        let idx = self.round_robin.fetch_add(1, Ordering::Relaxed) as usize % self.shards.len();
        &self.shards[idx]
    }

    /// Write a stored record using its source IP for sharding
    pub fn write(&self, record: &StoredRecord) -> Result<()> {
        // Use source IP as sharding key
        let key = Self::ip_to_hash(&record.src_ip);
        let shard = self.get_shard_for_key(key);

        // Serialize the record
        let data = bincode::serialize(record).map_err(|e| {
            ZeroedError::Storage(StorageError::SerializationError {
                message: e.to_string(),
            })
        })?;

        let bytes_written = shard.write(&data)?;

        self.total_records.fetch_add(1, Ordering::Relaxed);
        self.total_bytes.fetch_add(bytes_written as u64, Ordering::Relaxed);

        Ok(())
    }

    /// Write raw bytes to a specific shard
    pub fn write_to_shard(&self, shard_id: usize, data: &[u8]) -> Result<()> {
        if shard_id >= self.shards.len() {
            return Err(ZeroedError::Storage(StorageError::WriteError {
                message: format!("Invalid shard ID: {}", shard_id),
            }));
        }

        let bytes_written = self.shards[shard_id].write(data)?;

        self.total_records.fetch_add(1, Ordering::Relaxed);
        self.total_bytes.fetch_add(bytes_written as u64, Ordering::Relaxed);

        Ok(())
    }

    /// Write raw bytes using round-robin distribution
    pub fn write_round_robin(&self, data: &[u8]) -> Result<()> {
        let shard = self.get_shard_round_robin();
        let bytes_written = shard.write(data)?;

        self.total_records.fetch_add(1, Ordering::Relaxed);
        self.total_bytes.fetch_add(bytes_written as u64, Ordering::Relaxed);

        Ok(())
    }

    /// Convert IP address bytes to a hash for sharding
    fn ip_to_hash(ip: &super::IpAddrBytes) -> u64 {
        match ip {
            super::IpAddrBytes::V4(bytes) => {
                u32::from_be_bytes(*bytes) as u64
            }
            super::IpAddrBytes::V6(bytes) => {
                // Use first 8 bytes of IPv6 for hash
                u64::from_be_bytes([
                    bytes[0], bytes[1], bytes[2], bytes[3],
                    bytes[4], bytes[5], bytes[6], bytes[7],
                ])
            }
        }
    }

    /// Flush all shards
    pub fn flush(&self) -> Result<()> {
        for shard in &self.shards {
            shard.flush()?;
        }
        debug!("Flushed all {} shards", self.shards.len());
        Ok(())
    }

    /// Close all shards
    pub fn close(&self) -> Result<()> {
        for shard in &self.shards {
            shard.close()?;
        }
        info!("Closed all shards");
        Ok(())
    }

    /// Get statistics for all shards
    pub fn stats(&self) -> ShardedStorageStats {
        let shard_stats: Vec<ShardStats> = self.shards.iter().map(|s| s.stats()).collect();

        ShardedStorageStats {
            shard_count: self.shards.len(),
            total_records: self.total_records.load(Ordering::Relaxed),
            total_bytes: self.total_bytes.load(Ordering::Relaxed),
            shard_stats,
        }
    }

    /// Get number of shards
    pub fn shard_count(&self) -> usize {
        self.shards.len()
    }

    /// Get a specific shard
    pub fn get_shard(&self, id: usize) -> Option<Arc<Shard>> {
        self.shards.get(id).cloned()
    }

    /// Get base directory
    pub fn base_dir(&self) -> &Path {
        &self.config.base_dir
    }

    /// Check if any shard needs rotation
    pub fn needs_rotation(&self) -> Vec<usize> {
        self.shards
            .iter()
            .filter(|s| s.should_rotate())
            .map(|s| s.id())
            .collect()
    }
}

impl Drop for ShardedStorage {
    fn drop(&mut self) {
        if let Err(e) = self.flush() {
            error!("Failed to flush sharded storage on drop: {}", e);
        }
    }
}

/// Statistics for the sharded storage system
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ShardedStorageStats {
    pub shard_count: usize,
    pub total_records: u64,
    pub total_bytes: u64,
    pub shard_stats: Vec<ShardStats>,
}

impl ShardedStorageStats {
    /// Get distribution statistics (how evenly records are distributed)
    pub fn distribution(&self) -> ShardDistribution {
        if self.shard_stats.is_empty() {
            return ShardDistribution::default();
        }

        let records: Vec<u64> = self.shard_stats.iter().map(|s| s.records_written).collect();
        let total: u64 = records.iter().sum();
        let avg = total as f64 / records.len() as f64;

        let min = *records.iter().min().unwrap_or(&0);
        let max = *records.iter().max().unwrap_or(&0);

        // Calculate standard deviation
        let variance: f64 = records
            .iter()
            .map(|&r| {
                let diff = r as f64 - avg;
                diff * diff
            })
            .sum::<f64>()
            / records.len() as f64;
        let std_dev = variance.sqrt();

        // Coefficient of variation (lower is more even)
        let cv = if avg > 0.0 { std_dev / avg } else { 0.0 };

        ShardDistribution {
            min_records: min,
            max_records: max,
            avg_records: avg,
            std_dev,
            coefficient_of_variation: cv,
            is_balanced: cv < 0.1, // Less than 10% CV is considered balanced
        }
    }
}

/// Distribution statistics for shards
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ShardDistribution {
    pub min_records: u64,
    pub max_records: u64,
    pub avg_records: f64,
    pub std_dev: f64,
    pub coefficient_of_variation: f64,
    pub is_balanced: bool,
}

// ─────────────────────────────────────────────────────────────────────────────
// Sharded Writer (for parallel writes)
// ─────────────────────────────────────────────────────────────────────────────

/// A writer handle for a specific shard
pub struct ShardedWriter {
    storage: Arc<ShardedStorage>,
    preferred_shard: Option<usize>,
}

impl ShardedWriter {
    /// Create a new writer with access to all shards
    pub fn new(storage: Arc<ShardedStorage>) -> Self {
        Self {
            storage,
            preferred_shard: None,
        }
    }

    /// Create a writer that prefers a specific shard
    pub fn with_preferred_shard(storage: Arc<ShardedStorage>, shard_id: usize) -> Self {
        Self {
            storage,
            preferred_shard: Some(shard_id),
        }
    }

    /// Write a record
    pub fn write(&self, record: &StoredRecord) -> Result<()> {
        if let Some(shard_id) = self.preferred_shard {
            let data = bincode::serialize(record).map_err(|e| {
                ZeroedError::Storage(StorageError::SerializationError {
                    message: e.to_string(),
                })
            })?;
            self.storage.write_to_shard(shard_id, &data)
        } else {
            self.storage.write(record)
        }
    }

    /// Write raw bytes
    pub fn write_raw(&self, data: &[u8]) -> Result<()> {
        if let Some(shard_id) = self.preferred_shard {
            self.storage.write_to_shard(shard_id, data)
        } else {
            self.storage.write_round_robin(data)
        }
    }

    /// Flush the underlying storage
    pub fn flush(&self) -> Result<()> {
        self.storage.flush()
    }
}

impl Clone for ShardedWriter {
    fn clone(&self) -> Self {
        Self {
            storage: Arc::clone(&self.storage),
            preferred_shard: self.preferred_shard,
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Tests
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;
    use tempfile::TempDir;

    fn create_test_record(ip: Ipv4Addr) -> StoredRecord {
        StoredRecord {
            id: 1,
            timestamp: Utc::now(),
            src_ip: super::super::IpAddrBytes::V4(ip.octets()),
            dst_ip: super::super::IpAddrBytes::V4([10, 0, 0, 1]),
            src_port: 12345,
            dst_port: 80,
            protocol: 6,
            tcp_flags: 0x02,
            packet_size: 64,
            payload_size: 0,
            src_mac: [0; 6],
        }
    }

    #[test]
    fn test_shard_config_default() {
        let config = ShardConfig::default();
        assert_eq!(config.shard_count, DEFAULT_SHARD_COUNT);
        assert_eq!(config.buffer_size, DEFAULT_BUFFER_SIZE);
    }

    #[test]
    fn test_sharded_storage_creation() {
        let temp_dir = TempDir::new().unwrap();
        let storage = ShardedStorage::new(temp_dir.path().to_path_buf(), 4).unwrap();

        assert_eq!(storage.shard_count(), 4);
        assert_eq!(storage.stats().total_records, 0);
    }

    #[test]
    fn test_sharded_storage_write() {
        let temp_dir = TempDir::new().unwrap();
        let storage = ShardedStorage::new(temp_dir.path().to_path_buf(), 4).unwrap();

        let record = create_test_record(Ipv4Addr::new(192, 168, 1, 1));
        storage.write(&record).unwrap();

        assert_eq!(storage.stats().total_records, 1);
    }

    #[test]
    fn test_shard_distribution() {
        let temp_dir = TempDir::new().unwrap();
        let storage = ShardedStorage::new(temp_dir.path().to_path_buf(), 4).unwrap();

        // Write records with different IPs
        for i in 0..100 {
            let record = create_test_record(Ipv4Addr::new(192, 168, i / 25, i));
            storage.write(&record).unwrap();
        }

        let stats = storage.stats();
        let dist = stats.distribution();

        assert_eq!(stats.total_records, 100);
        assert!(dist.avg_records > 0.0);
    }

    #[test]
    fn test_sharded_writer() {
        let temp_dir = TempDir::new().unwrap();
        let storage = Arc::new(ShardedStorage::new(temp_dir.path().to_path_buf(), 4).unwrap());

        let writer = ShardedWriter::new(Arc::clone(&storage));
        let record = create_test_record(Ipv4Addr::new(192, 168, 1, 1));
        writer.write(&record).unwrap();

        assert_eq!(storage.stats().total_records, 1);
    }
}
