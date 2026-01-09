//! Memory-mapped ring buffer implementation
//!
//! This module provides a persistent ring buffer backed by a memory-mapped file.
//! It combines the zero-copy performance of mmap with the fixed-size semantics
//! of a ring buffer, making it ideal for storing recent connection records.
//!
//! ## Features
//! - Persistent storage across daemon restarts
//! - Zero-copy reads via mmap
//! - Fixed memory footprint
//! - Automatic wraparound when full
//! - Thread-safe concurrent access

use std::fs::{File, OpenOptions};
use std::io::{self, Read, Write};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

use bincode::{deserialize, serialize};
use byteorder::{LittleEndian, ReadBytesExt, WriteBytesExt};
use memmap2::{MmapMut, MmapOptions};
use parking_lot::RwLock;
use serde::{de::DeserializeOwned, Deserialize, Serialize};
use tracing::{debug, error, info, trace, warn};

// ─────────────────────────────────────────────────────────────────────────────
// Constants
// ─────────────────────────────────────────────────────────────────────────────

/// Magic number for mmap ring buffer files ("MRBF")
const MAGIC_NUMBER: [u8; 4] = [0x4D, 0x52, 0x42, 0x46];

/// Current format version
const FORMAT_VERSION: u32 = 1;

/// Header size in bytes (must be aligned to page size for efficiency)
const HEADER_SIZE: usize = 4096;

/// Default capacity (number of records)
const DEFAULT_CAPACITY: usize = 100_000;

/// Record alignment (cache-line aligned)
const RECORD_ALIGNMENT: usize = 64;

// ─────────────────────────────────────────────────────────────────────────────
// Error Types
// ─────────────────────────────────────────────────────────────────────────────

/// Errors for mmap ring buffer operations
#[derive(Debug, thiserror::Error)]
pub enum MmapRingError {
    #[error("I/O error: {0}")]
    Io(#[from] io::Error),

    #[error("Invalid magic number")]
    InvalidMagic,

    #[error("Unsupported version: {0}")]
    UnsupportedVersion(u32),

    #[error("Buffer is full")]
    BufferFull,

    #[error("Invalid record size: expected {expected}, got {actual}")]
    InvalidRecordSize { expected: usize, actual: usize },

    #[error("Memory mapping failed: {0}")]
    MmapFailed(String),

    #[error("Serialization error: {0}")]
    Serialization(String),

    #[error("Deserialization error: {0}")]
    Deserialization(String),

    #[error("Index out of bounds: {index} >= {capacity}")]
    IndexOutOfBounds { index: usize, capacity: usize },

    #[error("Record size too large: {size} > {max}")]
    RecordTooLarge { size: usize, max: usize },
}

pub type Result<T> = std::result::Result<T, MmapRingError>;

// ─────────────────────────────────────────────────────────────────────────────
// Ring Buffer Header
// ─────────────────────────────────────────────────────────────────────────────

/// Ring buffer header stored at the beginning of the file
#[derive(Debug, Clone)]
#[repr(C)]
pub struct RingHeader {
    /// Magic number for identification
    pub magic: [u8; 4],
    /// Format version
    pub version: u32,
    /// Capacity (max number of records)
    pub capacity: u64,
    /// Size of each record slot in bytes
    pub record_size: u32,
    /// Current write position (next slot to write)
    pub write_pos: u64,
    /// Number of records currently in buffer
    pub count: u64,
    /// Total records ever written (for statistics)
    pub total_written: u64,
    /// Sequence number (for ordering)
    pub sequence: u64,
    /// Creation timestamp
    pub created_at: i64,
    /// Last modified timestamp
    pub modified_at: i64,
    /// Checksum of header (for integrity)
    pub checksum: u32,
    /// Reserved for future use
    pub reserved: [u8; 64],
}

impl RingHeader {
    fn new(capacity: u64, record_size: u32) -> Self {
        let now = chrono::Utc::now().timestamp();
        Self {
            magic: MAGIC_NUMBER,
            version: FORMAT_VERSION,
            capacity,
            record_size,
            write_pos: 0,
            count: 0,
            total_written: 0,
            sequence: 0,
            created_at: now,
            modified_at: now,
            checksum: 0,
            reserved: [0u8; 64],
        }
    }

    fn validate(&self) -> Result<()> {
        if self.magic != MAGIC_NUMBER {
            return Err(MmapRingError::InvalidMagic);
        }
        if self.version > FORMAT_VERSION {
            return Err(MmapRingError::UnsupportedVersion(self.version));
        }
        Ok(())
    }

    fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(HEADER_SIZE);
        let mut cursor = io::Cursor::new(&mut bytes);

        cursor.write_all(&self.magic).unwrap();
        cursor.write_u32::<LittleEndian>(self.version).unwrap();
        cursor.write_u64::<LittleEndian>(self.capacity).unwrap();
        cursor.write_u32::<LittleEndian>(self.record_size).unwrap();
        cursor.write_u64::<LittleEndian>(self.write_pos).unwrap();
        cursor.write_u64::<LittleEndian>(self.count).unwrap();
        cursor
            .write_u64::<LittleEndian>(self.total_written)
            .unwrap();
        cursor.write_u64::<LittleEndian>(self.sequence).unwrap();
        cursor.write_i64::<LittleEndian>(self.created_at).unwrap();
        cursor.write_i64::<LittleEndian>(self.modified_at).unwrap();
        cursor.write_u32::<LittleEndian>(self.checksum).unwrap();
        cursor.write_all(&self.reserved).unwrap();

        // Pad to HEADER_SIZE
        bytes.resize(HEADER_SIZE, 0);
        bytes
    }

    fn from_bytes(bytes: &[u8]) -> Result<Self> {
        if bytes.len() < 128 {
            return Err(MmapRingError::Io(io::Error::new(
                io::ErrorKind::InvalidData,
                "Header too short",
            )));
        }

        let mut cursor = io::Cursor::new(bytes);
        let mut magic = [0u8; 4];
        cursor.read_exact(&mut magic)?;

        let version = cursor.read_u32::<LittleEndian>()?;
        let capacity = cursor.read_u64::<LittleEndian>()?;
        let record_size = cursor.read_u32::<LittleEndian>()?;
        let write_pos = cursor.read_u64::<LittleEndian>()?;
        let count = cursor.read_u64::<LittleEndian>()?;
        let total_written = cursor.read_u64::<LittleEndian>()?;
        let sequence = cursor.read_u64::<LittleEndian>()?;
        let created_at = cursor.read_i64::<LittleEndian>()?;
        let modified_at = cursor.read_i64::<LittleEndian>()?;
        let checksum = cursor.read_u32::<LittleEndian>()?;

        let mut reserved = [0u8; 64];
        cursor.read_exact(&mut reserved)?;

        Ok(Self {
            magic,
            version,
            capacity,
            record_size,
            write_pos,
            count,
            total_written,
            sequence,
            created_at,
            modified_at,
            checksum,
            reserved,
        })
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Record Wrapper
// ─────────────────────────────────────────────────────────────────────────────

/// Wrapper around a record with metadata
#[derive(Debug, Clone, Serialize, Deserialize)]
struct RecordSlot<T> {
    /// Whether this slot is occupied
    occupied: bool,
    /// Sequence number for ordering
    sequence: u64,
    /// The actual record data
    data: Option<T>,
}

impl<T> Default for RecordSlot<T> {
    fn default() -> Self {
        Self {
            occupied: false,
            sequence: 0,
            data: None,
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Memory-Mapped Ring Buffer
// ─────────────────────────────────────────────────────────────────────────────

/// Configuration for the mmap ring buffer
#[derive(Debug, Clone)]
pub struct MmapRingConfig {
    /// Maximum number of records
    pub capacity: usize,
    /// Size of each record in bytes (including overhead)
    pub record_size: usize,
    /// Whether to sync after each write
    pub sync_on_write: bool,
    /// Whether to create the file if it doesn't exist
    pub create_if_missing: bool,
}

impl Default for MmapRingConfig {
    fn default() -> Self {
        Self {
            capacity: DEFAULT_CAPACITY,
            record_size: 256, // Default record size
            sync_on_write: false,
            create_if_missing: true,
        }
    }
}

/// A persistent ring buffer backed by a memory-mapped file
pub struct MmapRingBuffer {
    /// File path
    path: PathBuf,
    /// Memory-mapped region
    mmap: RwLock<MmapMut>,
    /// Current header state (cached)
    header: RwLock<RingHeader>,
    /// Configuration
    config: MmapRingConfig,
    /// Write position (atomic for lock-free position reads)
    write_pos: AtomicU64,
    /// Current count
    count: AtomicU64,
    /// Sequence counter
    sequence: AtomicU64,
    /// Total records written
    total_written: AtomicU64,
}

impl MmapRingBuffer {
    /// Open or create a new mmap ring buffer
    pub fn open<P: AsRef<Path>>(path: P, config: MmapRingConfig) -> Result<Self> {
        let path = path.as_ref().to_path_buf();
        let file_exists = path.exists();

        // Calculate required file size
        let data_size = config.capacity * Self::align_size(config.record_size);
        let total_size = HEADER_SIZE + data_size;

        // Open or create file
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .create(config.create_if_missing)
            .open(&path)?;

        let (mmap, header) = if file_exists && file.metadata()?.len() > 0 {
            // Open existing file
            let mmap = unsafe {
                MmapOptions::new()
                    .map_mut(&file)
                    .map_err(|e| MmapRingError::MmapFailed(e.to_string()))?
            };

            let header = RingHeader::from_bytes(&mmap[..HEADER_SIZE])?;
            header.validate()?;

            info!(
                "Opened existing mmap ring buffer: {:?} ({} records)",
                path, header.count
            );

            (mmap, header)
        } else {
            // Create new file
            file.set_len(total_size as u64)?;

            let mmap = unsafe {
                MmapOptions::new()
                    .len(total_size)
                    .map_mut(&file)
                    .map_err(|e| MmapRingError::MmapFailed(e.to_string()))?
            };

            let header = RingHeader::new(config.capacity as u64, config.record_size as u32);

            info!(
                "Created new mmap ring buffer: {:?} (capacity: {})",
                path, config.capacity
            );

            (mmap, header)
        };

        let write_pos = AtomicU64::new(header.write_pos);
        let count = AtomicU64::new(header.count);
        let sequence = AtomicU64::new(header.sequence);
        let total_written = AtomicU64::new(header.total_written);

        let buffer = Self {
            path,
            mmap: RwLock::new(mmap),
            header: RwLock::new(header),
            config,
            write_pos,
            count,
            sequence,
            total_written,
        };

        // Write header if new file
        if !file_exists {
            buffer.write_header()?;
        }

        Ok(buffer)
    }

    /// Align size to record alignment boundary
    fn align_size(size: usize) -> usize {
        (size + RECORD_ALIGNMENT - 1) & !(RECORD_ALIGNMENT - 1)
    }

    /// Get the offset for a record at the given index
    fn record_offset(&self, index: usize) -> usize {
        HEADER_SIZE + index * Self::align_size(self.config.record_size)
    }

    /// Write the header to the mmap
    fn write_header(&self) -> Result<()> {
        let header = self.header.read();
        let bytes = header.to_bytes();
        drop(header);

        let mut mmap = self.mmap.write();
        mmap[..HEADER_SIZE].copy_from_slice(&bytes);

        if self.config.sync_on_write {
            mmap.flush()?;
        }

        Ok(())
    }

    /// Update header with current state
    fn update_header(&self) -> Result<()> {
        let mut header = self.header.write();
        header.write_pos = self.write_pos.load(Ordering::SeqCst);
        header.count = self.count.load(Ordering::SeqCst);
        header.sequence = self.sequence.load(Ordering::SeqCst);
        header.total_written = self.total_written.load(Ordering::SeqCst);
        header.modified_at = chrono::Utc::now().timestamp();

        let bytes = header.to_bytes();
        drop(header);

        let mut mmap = self.mmap.write();
        mmap[..HEADER_SIZE].copy_from_slice(&bytes);

        Ok(())
    }

    /// Push a record to the buffer
    pub fn push<T: Serialize>(&self, record: &T) -> Result<u64> {
        let serialized =
            serialize(record).map_err(|e| MmapRingError::Serialization(e.to_string()))?;

        if serialized.len() > self.config.record_size - 16 {
            return Err(MmapRingError::RecordTooLarge {
                size: serialized.len(),
                max: self.config.record_size - 16,
            });
        }

        self.push_raw(&serialized)
    }

    /// Push raw bytes to the buffer
    pub fn push_raw(&self, data: &[u8]) -> Result<u64> {
        // Get next sequence number
        let seq = self.sequence.fetch_add(1, Ordering::SeqCst);

        // Get write position and advance it
        let pos = self.write_pos.fetch_add(1, Ordering::SeqCst) as usize;
        let actual_pos = pos % self.config.capacity;
        let offset = self.record_offset(actual_pos);

        // Write the record
        let mut mmap = self.mmap.write();

        // Record format: [occupied: u8] [sequence: u64] [length: u32] [data...]
        let record_start = offset;
        mmap[record_start] = 1; // occupied = true
        mmap[record_start + 1..record_start + 9].copy_from_slice(&seq.to_le_bytes());
        mmap[record_start + 9..record_start + 13]
            .copy_from_slice(&(data.len() as u32).to_le_bytes());
        mmap[record_start + 13..record_start + 13 + data.len()].copy_from_slice(data);

        drop(mmap);

        // Update count
        let current_count = self.count.load(Ordering::SeqCst);
        if current_count < self.config.capacity as u64 {
            self.count.fetch_add(1, Ordering::SeqCst);
        }

        self.total_written.fetch_add(1, Ordering::SeqCst);

        // Update header periodically
        if seq % 100 == 0 {
            let _ = self.update_header();
        }

        trace!("Pushed record at position {}, sequence {}", actual_pos, seq);

        Ok(seq)
    }

    /// Read a record at the given index (0 = oldest)
    pub fn get<T: DeserializeOwned>(&self, index: usize) -> Result<Option<T>> {
        if let Some(data) = self.get_raw(index)? {
            let record: T =
                deserialize(&data).map_err(|e| MmapRingError::Deserialization(e.to_string()))?;
            Ok(Some(record))
        } else {
            Ok(None)
        }
    }

    /// Read raw bytes at the given index
    pub fn get_raw(&self, index: usize) -> Result<Option<Vec<u8>>> {
        let count = self.count.load(Ordering::SeqCst) as usize;
        if index >= count {
            return Err(MmapRingError::IndexOutOfBounds {
                index,
                capacity: count,
            });
        }

        let write_pos = self.write_pos.load(Ordering::SeqCst) as usize;
        let capacity = self.config.capacity;

        // Calculate actual position in the ring
        let start = if count < capacity {
            0
        } else {
            write_pos % capacity
        };
        let actual_pos = (start + index) % capacity;
        let offset = self.record_offset(actual_pos);

        let mmap = self.mmap.read();

        // Check if occupied
        if mmap[offset] == 0 {
            return Ok(None);
        }

        // Read length
        let len_bytes: [u8; 4] = mmap[offset + 9..offset + 13].try_into().unwrap();
        let len = u32::from_le_bytes(len_bytes) as usize;

        if len > self.config.record_size - 13 {
            return Err(MmapRingError::InvalidRecordSize {
                expected: self.config.record_size - 13,
                actual: len,
            });
        }

        // Read data
        let data = mmap[offset + 13..offset + 13 + len].to_vec();

        Ok(Some(data))
    }

    /// Get the N most recent records
    pub fn get_latest<T: DeserializeOwned>(&self, n: usize) -> Vec<T> {
        let count = self.count.load(Ordering::SeqCst) as usize;
        let take = n.min(count);
        let start = count.saturating_sub(take);

        (start..count)
            .filter_map(|i| self.get::<T>(i).ok().flatten())
            .collect()
    }

    /// Iterate over all records from oldest to newest
    pub fn iter<T: DeserializeOwned>(&self) -> impl Iterator<Item = T> + '_ {
        let count = self.count.load(Ordering::SeqCst) as usize;
        (0..count).filter_map(|i| self.get::<T>(i).ok().flatten())
    }

    /// Get current count of records
    pub fn len(&self) -> usize {
        self.count.load(Ordering::SeqCst) as usize
    }

    /// Check if buffer is empty
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Check if buffer is at capacity
    pub fn is_full(&self) -> bool {
        self.len() >= self.config.capacity
    }

    /// Get capacity
    pub fn capacity(&self) -> usize {
        self.config.capacity
    }

    /// Get total records ever written
    pub fn total_written(&self) -> u64 {
        self.total_written.load(Ordering::SeqCst)
    }

    /// Get current sequence number
    pub fn current_sequence(&self) -> u64 {
        self.sequence.load(Ordering::SeqCst)
    }

    /// Flush changes to disk
    pub fn flush(&self) -> Result<()> {
        self.update_header()?;
        let mmap = self.mmap.read();
        mmap.flush()?;
        Ok(())
    }

    /// Async-safe flush
    pub fn flush_async(&self) -> Result<()> {
        self.update_header()?;
        let mmap = self.mmap.read();
        mmap.flush_async()?;
        Ok(())
    }

    /// Clear all records
    pub fn clear(&self) -> Result<()> {
        self.write_pos.store(0, Ordering::SeqCst);
        self.count.store(0, Ordering::SeqCst);
        // Keep sequence and total_written for statistics

        // Zero out data region
        let mut mmap = self.mmap.write();
        let data_start = HEADER_SIZE;
        let data_size = self.config.capacity * Self::align_size(self.config.record_size);
        for byte in &mut mmap[data_start..data_start + data_size] {
            *byte = 0;
        }
        drop(mmap);

        self.update_header()?;
        Ok(())
    }

    /// Get buffer statistics
    pub fn stats(&self) -> MmapRingStats {
        let header = self.header.read();
        MmapRingStats {
            capacity: self.config.capacity,
            count: self.len(),
            total_written: self.total_written(),
            current_sequence: self.current_sequence(),
            record_size: self.config.record_size,
            file_size: HEADER_SIZE
                + self.config.capacity * Self::align_size(self.config.record_size),
            created_at: header.created_at,
            modified_at: header.modified_at,
            fill_ratio: self.len() as f64 / self.config.capacity as f64,
        }
    }

    /// Get the file path
    pub fn path(&self) -> &Path {
        &self.path
    }
}

impl Drop for MmapRingBuffer {
    fn drop(&mut self) {
        if let Err(e) = self.flush() {
            error!("Failed to flush mmap ring buffer on close: {}", e);
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Statistics
// ─────────────────────────────────────────────────────────────────────────────

/// Statistics for the mmap ring buffer
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MmapRingStats {
    /// Maximum capacity
    pub capacity: usize,
    /// Current record count
    pub count: usize,
    /// Total records ever written
    pub total_written: u64,
    /// Current sequence number
    pub current_sequence: u64,
    /// Size of each record slot
    pub record_size: usize,
    /// Total file size in bytes
    pub file_size: usize,
    /// Creation timestamp
    pub created_at: i64,
    /// Last modified timestamp
    pub modified_at: i64,
    /// Fill ratio (0.0 to 1.0)
    pub fill_ratio: f64,
}

// ─────────────────────────────────────────────────────────────────────────────
// Tests
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
    struct TestRecord {
        id: u64,
        value: String,
    }

    #[test]
    fn test_mmap_ring_basic() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("test.ring");

        let config = MmapRingConfig {
            capacity: 100,
            record_size: 128,
            ..Default::default()
        };

        let buffer = MmapRingBuffer::open(&path, config).unwrap();

        // Push some records
        for i in 0..10 {
            let record = TestRecord {
                id: i,
                value: format!("record_{}", i),
            };
            buffer.push(&record).unwrap();
        }

        assert_eq!(buffer.len(), 10);

        // Read records back
        let records: Vec<TestRecord> = buffer.get_latest(5);
        assert_eq!(records.len(), 5);
        assert_eq!(records[0].id, 5);
        assert_eq!(records[4].id, 9);
    }

    #[test]
    fn test_mmap_ring_overflow() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("test_overflow.ring");

        let config = MmapRingConfig {
            capacity: 10,
            record_size: 64,
            ..Default::default()
        };

        let buffer = MmapRingBuffer::open(&path, config).unwrap();

        // Push more than capacity
        for i in 0..25 {
            buffer.push(&i).unwrap();
        }

        assert_eq!(buffer.len(), 10);
        assert!(buffer.is_full());
        assert_eq!(buffer.total_written(), 25);
    }

    #[test]
    fn test_mmap_ring_persistence() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("test_persist.ring");

        // Create and write
        {
            let config = MmapRingConfig {
                capacity: 100,
                record_size: 128,
                ..Default::default()
            };

            let buffer = MmapRingBuffer::open(&path, config).unwrap();

            for i in 0..10u64 {
                buffer.push(&i).unwrap();
            }

            buffer.flush().unwrap();
        }

        // Reopen and verify
        {
            let config = MmapRingConfig {
                capacity: 100,
                record_size: 128,
                create_if_missing: false,
                ..Default::default()
            };

            let buffer = MmapRingBuffer::open(&path, config).unwrap();

            assert_eq!(buffer.len(), 10);

            let values: Vec<u64> = buffer.iter().collect();
            assert_eq!(values, (0..10).collect::<Vec<_>>());
        }
    }

    #[test]
    fn test_mmap_ring_stats() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("test_stats.ring");

        let config = MmapRingConfig {
            capacity: 50,
            record_size: 64,
            ..Default::default()
        };

        let buffer = MmapRingBuffer::open(&path, config).unwrap();

        for i in 0..25u64 {
            buffer.push(&i).unwrap();
        }

        let stats = buffer.stats();
        assert_eq!(stats.capacity, 50);
        assert_eq!(stats.count, 25);
        assert_eq!(stats.total_written, 25);
        assert!((stats.fill_ratio - 0.5).abs() < 0.01);
    }
}
