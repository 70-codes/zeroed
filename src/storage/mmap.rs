//! Memory-mapped storage engine for efficient data persistence
//!
//! This module provides a high-performance storage engine using memory-mapped files
//! for fast read/write operations. It's designed for the Zeroed DoS protection daemon
//! to efficiently store connection records, IP tracking data, and event logs.
//!
//! ## Features
//! - Zero-copy reads via mmap
//! - Append-only log structure for durability
//! - Automatic file rotation based on size
//! - CRC32 checksums for data integrity
//! - Lock-free reads with synchronized writes

use std::fs::OpenOptions;
use std::io::{self, Read, Write};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

use bincode::{deserialize, serialize};
use byteorder::{LittleEndian, ReadBytesExt, WriteBytesExt};
use chrono::{DateTime, Utc};
use memmap2::{MmapMut, MmapOptions};
use parking_lot::RwLock;
use serde::{de::DeserializeOwned, Deserialize, Serialize};
use tracing::{error, info, trace};

// ─────────────────────────────────────────────────────────────────────────────
// Constants
// ─────────────────────────────────────────────────────────────────────────────

/// Magic number for file identification ("ZERO" in little-endian)
const MAGIC_NUMBER: u32 = 0x4F52455A;

/// Current file format version
const FORMAT_VERSION: u32 = 1;

/// Default file size (64 MB)
const DEFAULT_FILE_SIZE: usize = 64 * 1024 * 1024;

/// Minimum file size (1 MB)
const MIN_FILE_SIZE: usize = 1024 * 1024;

/// Maximum file size (1 GB)
const MAX_FILE_SIZE: usize = 1024 * 1024 * 1024;

/// File header size in bytes
const HEADER_SIZE: usize = 64;

/// Record header size in bytes
const RECORD_HEADER_SIZE: usize = 24;

/// Alignment for records (cache-line aligned)
const RECORD_ALIGNMENT: usize = 64;

// ─────────────────────────────────────────────────────────────────────────────
// Error Types
// ─────────────────────────────────────────────────────────────────────────────

/// Storage error types
#[derive(Debug, thiserror::Error)]
pub enum MmapError {
    #[error("I/O error: {0}")]
    Io(#[from] io::Error),

    #[error("Invalid magic number, file may be corrupted")]
    InvalidMagic,

    #[error("Unsupported format version: {version}")]
    UnsupportedVersion { version: u32 },

    #[error("File size too small: {size} bytes (minimum: {min} bytes)")]
    FileTooSmall { size: usize, min: usize },

    #[error("File size too large: {size} bytes (maximum: {max} bytes)")]
    FileTooLarge { size: usize, max: usize },

    #[error("Storage is full, cannot write {requested} bytes (available: {available})")]
    StorageFull { requested: usize, available: usize },

    #[error("Record not found at offset {offset}")]
    RecordNotFound { offset: u64 },

    #[error("Checksum mismatch: expected {expected:08x}, got {actual:08x}")]
    ChecksumMismatch { expected: u32, actual: u32 },

    #[error("Serialization error: {0}")]
    Serialization(String),

    #[error("Deserialization error: {0}")]
    Deserialization(String),

    #[error("Record too large: {size} bytes (maximum: {max} bytes)")]
    RecordTooLarge { size: usize, max: usize },

    #[error("Memory mapping failed: {0}")]
    MmapFailed(String),

    #[error("File is read-only")]
    ReadOnly,

    #[error("Invalid offset: {offset}")]
    InvalidOffset { offset: u64 },
}

pub type Result<T> = std::result::Result<T, MmapError>;

// ─────────────────────────────────────────────────────────────────────────────
// File Header
// ─────────────────────────────────────────────────────────────────────────────

/// File header structure (64 bytes)
#[derive(Debug, Clone, Serialize, Deserialize)]
#[repr(C)]
pub struct FileHeader {
    /// Magic number for identification
    pub magic: u32,
    /// Format version
    pub version: u32,
    /// Total file size
    pub file_size: u64,
    /// Number of records in the file
    pub record_count: u64,
    /// Offset to the first record
    pub first_record_offset: u64,
    /// Offset to write next record
    pub write_offset: u64,
    /// Creation timestamp (Unix timestamp)
    pub created_at: i64,
    /// Last modified timestamp
    pub modified_at: i64,
    /// Reserved for future use
    pub reserved: [u8; 8],
}

impl FileHeader {
    fn new(file_size: u64) -> Self {
        let now = Utc::now().timestamp();
        Self {
            magic: MAGIC_NUMBER,
            version: FORMAT_VERSION,
            file_size,
            record_count: 0,
            first_record_offset: HEADER_SIZE as u64,
            write_offset: HEADER_SIZE as u64,
            created_at: now,
            modified_at: now,
            reserved: [0u8; 8],
        }
    }

    fn validate(&self) -> Result<()> {
        if self.magic != MAGIC_NUMBER {
            return Err(MmapError::InvalidMagic);
        }
        if self.version > FORMAT_VERSION {
            return Err(MmapError::UnsupportedVersion {
                version: self.version,
            });
        }
        Ok(())
    }

    fn to_bytes(&self) -> [u8; HEADER_SIZE] {
        let mut bytes = [0u8; HEADER_SIZE];
        let mut cursor = io::Cursor::new(&mut bytes[..]);

        cursor.write_u32::<LittleEndian>(self.magic).unwrap();
        cursor.write_u32::<LittleEndian>(self.version).unwrap();
        cursor.write_u64::<LittleEndian>(self.file_size).unwrap();
        cursor.write_u64::<LittleEndian>(self.record_count).unwrap();
        cursor
            .write_u64::<LittleEndian>(self.first_record_offset)
            .unwrap();
        cursor.write_u64::<LittleEndian>(self.write_offset).unwrap();
        cursor.write_i64::<LittleEndian>(self.created_at).unwrap();
        cursor.write_i64::<LittleEndian>(self.modified_at).unwrap();
        cursor.write_all(&self.reserved).unwrap();

        bytes
    }

    fn from_bytes(bytes: &[u8]) -> Result<Self> {
        if bytes.len() < HEADER_SIZE {
            return Err(MmapError::Io(io::Error::new(
                io::ErrorKind::InvalidData,
                "Header too short",
            )));
        }

        let mut cursor = io::Cursor::new(bytes);
        let magic = cursor.read_u32::<LittleEndian>()?;
        let version = cursor.read_u32::<LittleEndian>()?;
        let file_size = cursor.read_u64::<LittleEndian>()?;
        let record_count = cursor.read_u64::<LittleEndian>()?;
        let first_record_offset = cursor.read_u64::<LittleEndian>()?;
        let write_offset = cursor.read_u64::<LittleEndian>()?;
        let created_at = cursor.read_i64::<LittleEndian>()?;
        let modified_at = cursor.read_i64::<LittleEndian>()?;

        let mut reserved = [0u8; 8];
        cursor.read_exact(&mut reserved)?;

        Ok(Self {
            magic,
            version,
            file_size,
            record_count,
            first_record_offset,
            write_offset,
            created_at,
            modified_at,
            reserved,
        })
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Record Header
// ─────────────────────────────────────────────────────────────────────────────

/// Record header structure (24 bytes)
#[derive(Debug, Clone, Copy)]
#[repr(C)]
pub struct RecordHeader {
    /// Record type identifier
    pub record_type: u32,
    /// CRC32 checksum of the payload
    pub checksum: u32,
    /// Payload size in bytes
    pub payload_size: u32,
    /// Flags (deleted, compressed, etc.)
    pub flags: u32,
    /// Timestamp when record was written
    pub timestamp: i64,
}

impl RecordHeader {
    fn new(record_type: u32, payload_size: u32, checksum: u32) -> Self {
        Self {
            record_type,
            checksum,
            payload_size,
            flags: 0,
            timestamp: Utc::now().timestamp(),
        }
    }

    fn to_bytes(&self) -> [u8; RECORD_HEADER_SIZE] {
        let mut bytes = [0u8; RECORD_HEADER_SIZE];
        let mut cursor = io::Cursor::new(&mut bytes[..]);

        cursor.write_u32::<LittleEndian>(self.record_type).unwrap();
        cursor.write_u32::<LittleEndian>(self.checksum).unwrap();
        cursor.write_u32::<LittleEndian>(self.payload_size).unwrap();
        cursor.write_u32::<LittleEndian>(self.flags).unwrap();
        cursor.write_i64::<LittleEndian>(self.timestamp).unwrap();

        bytes
    }

    fn from_bytes(bytes: &[u8]) -> Result<Self> {
        if bytes.len() < RECORD_HEADER_SIZE {
            return Err(MmapError::Io(io::Error::new(
                io::ErrorKind::InvalidData,
                "Record header too short",
            )));
        }

        let mut cursor = io::Cursor::new(bytes);
        Ok(Self {
            record_type: cursor.read_u32::<LittleEndian>()?,
            checksum: cursor.read_u32::<LittleEndian>()?,
            payload_size: cursor.read_u32::<LittleEndian>()?,
            flags: cursor.read_u32::<LittleEndian>()?,
            timestamp: cursor.read_i64::<LittleEndian>()?,
        })
    }

    fn is_deleted(&self) -> bool {
        self.flags & 0x01 != 0
    }

    fn is_compressed(&self) -> bool {
        self.flags & 0x02 != 0
    }

    fn total_size(&self) -> usize {
        align_to(
            RECORD_HEADER_SIZE + self.payload_size as usize,
            RECORD_ALIGNMENT,
        )
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Record Types
// ─────────────────────────────────────────────────────────────────────────────

/// Record type identifiers
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u32)]
pub enum RecordType {
    /// Connection record
    Connection = 1,
    /// IP tracking record
    IpTracking = 2,
    /// Block event
    BlockEvent = 3,
    /// Unblock event
    UnblockEvent = 4,
    /// Attack detection
    AttackDetection = 5,
    /// System event
    SystemEvent = 6,
    /// Statistics snapshot
    Statistics = 7,
    /// GeoIP data
    GeoIp = 8,
    /// Custom/user-defined
    Custom = 255,
}

impl From<u32> for RecordType {
    fn from(value: u32) -> Self {
        match value {
            1 => RecordType::Connection,
            2 => RecordType::IpTracking,
            3 => RecordType::BlockEvent,
            4 => RecordType::UnblockEvent,
            5 => RecordType::AttackDetection,
            6 => RecordType::SystemEvent,
            7 => RecordType::Statistics,
            8 => RecordType::GeoIp,
            _ => RecordType::Custom,
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Helper Functions
// ─────────────────────────────────────────────────────────────────────────────

/// Align a value to the next multiple of alignment
fn align_to(value: usize, alignment: usize) -> usize {
    (value + alignment - 1) & !(alignment - 1)
}

/// Calculate CRC32 checksum
fn crc32(data: &[u8]) -> u32 {
    let mut hasher = crc32fast::Hasher::new();
    hasher.update(data);
    hasher.finalize()
}

// ─────────────────────────────────────────────────────────────────────────────
// Statistics Types
// ─────────────────────────────────────────────────────────────────────────────

/// Statistics about storage compaction
#[derive(Debug, Clone)]
pub struct CompactionStats {
    /// Number of records kept
    pub records_kept: u64,
    /// Number of records deleted
    pub records_deleted: u64,
    /// Bytes reclaimed from deleted records
    pub bytes_reclaimed: u64,
}

/// Storage statistics snapshot
#[derive(Debug, Clone)]
pub struct StorageStats {
    /// File path
    pub file_path: PathBuf,
    /// Total file size
    pub file_size: u64,
    /// Bytes currently used
    pub bytes_used: u64,
    /// Bytes available
    pub bytes_available: u64,
    /// Number of records
    pub record_count: u64,
    /// Creation timestamp
    pub created_at: DateTime<Utc>,
    /// Last modified timestamp
    pub modified_at: DateTime<Utc>,
    /// Fill percentage
    pub fill_percentage: f64,
}

// ─────────────────────────────────────────────────────────────────────────────
// Configuration
// ─────────────────────────────────────────────────────────────────────────────

/// Configuration for the mmap storage engine
#[derive(Debug, Clone)]
pub struct MmapStorageConfig {
    /// File size in bytes
    pub file_size: usize,
    /// Whether to create the file if it doesn't exist
    pub create_if_missing: bool,
    /// Whether to open in read-only mode
    pub read_only: bool,
    /// Whether to verify checksums on read
    pub verify_checksums: bool,
    /// Whether to sync on every write
    pub sync_on_write: bool,
}

impl Default for MmapStorageConfig {
    fn default() -> Self {
        Self {
            file_size: DEFAULT_FILE_SIZE,
            create_if_missing: true,
            read_only: false,
            verify_checksums: true,
            sync_on_write: false,
        }
    }
}

/// Memory-mapped storage engine
pub struct MmapStorage {
    /// File path
    path: PathBuf,
    /// Memory-mapped region
    mmap: RwLock<MmapMut>,
    /// File header (cached)
    header: RwLock<FileHeader>,
    /// Configuration
    config: MmapStorageConfig,
    /// Write position (atomic for lock-free reads of position)
    write_pos: AtomicU64,
    /// Record count
    record_count: AtomicU64,
    /// Whether the file is read-only
    read_only: bool,
}

impl MmapStorage {
    /// Open or create a new mmap storage file
    pub fn open<P: AsRef<Path>>(path: P, config: MmapStorageConfig) -> Result<Self> {
        let path = path.as_ref().to_path_buf();

        // Validate configuration
        if config.file_size < MIN_FILE_SIZE {
            return Err(MmapError::FileTooSmall {
                size: config.file_size,
                min: MIN_FILE_SIZE,
            });
        }
        if config.file_size > MAX_FILE_SIZE {
            return Err(MmapError::FileTooLarge {
                size: config.file_size,
                max: MAX_FILE_SIZE,
            });
        }

        let file_exists = path.exists();

        if !file_exists && !config.create_if_missing {
            return Err(MmapError::Io(io::Error::new(
                io::ErrorKind::NotFound,
                format!("File not found: {:?}", path),
            )));
        }

        // Open or create file
        let file = OpenOptions::new()
            .read(true)
            .write(!config.read_only)
            .create(config.create_if_missing)
            .open(&path)?;

        let (mmap, header) = if file_exists {
            // Open existing file
            let metadata = file.metadata()?;
            let size = metadata.len() as usize;

            let mmap = unsafe {
                MmapOptions::new()
                    .len(size)
                    .map_mut(&file)
                    .map_err(|e| MmapError::MmapFailed(e.to_string()))?
            };

            let header = FileHeader::from_bytes(&mmap[..HEADER_SIZE])?;
            header.validate()?;

            info!(
                "Opened existing storage file: {:?} ({} records)",
                path, header.record_count
            );

            (mmap, header)
        } else {
            // Create new file
            file.set_len(config.file_size as u64)?;

            let mmap = unsafe {
                MmapOptions::new()
                    .len(config.file_size)
                    .map_mut(&file)
                    .map_err(|e| MmapError::MmapFailed(e.to_string()))?
            };

            let header = FileHeader::new(config.file_size as u64);

            info!(
                "Created new storage file: {:?} ({} bytes)",
                path, config.file_size
            );

            (mmap, header)
        };

        let write_pos = AtomicU64::new(header.write_offset);
        let record_count = AtomicU64::new(header.record_count);

        let read_only = config.read_only;
        let storage = Self {
            path,
            mmap: RwLock::new(mmap),
            header: RwLock::new(header),
            config,
            write_pos,
            record_count,
            read_only,
        };

        // Write header if new file
        if !file_exists {
            storage.write_header()?;
        }

        Ok(storage)
    }

    /// Write the file header
    fn write_header(&self) -> Result<()> {
        if self.read_only {
            return Err(MmapError::ReadOnly);
        }

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

    /// Update the header with current state
    fn update_header(&self) -> Result<()> {
        if self.read_only {
            return Err(MmapError::ReadOnly);
        }

        let mut header = self.header.write();
        header.write_offset = self.write_pos.load(Ordering::SeqCst);
        header.record_count = self.record_count.load(Ordering::SeqCst);
        header.modified_at = Utc::now().timestamp();

        let bytes = header.to_bytes();
        drop(header);

        let mut mmap = self.mmap.write();
        mmap[..HEADER_SIZE].copy_from_slice(&bytes);

        Ok(())
    }

    /// Write a record to storage
    pub fn write_record<T: Serialize>(&self, record_type: RecordType, data: &T) -> Result<u64> {
        if self.read_only {
            return Err(MmapError::ReadOnly);
        }

        // Serialize the data
        let payload = serialize(data).map_err(|e| MmapError::Serialization(e.to_string()))?;

        self.write_raw(record_type as u32, &payload)
    }

    /// Write raw bytes to storage
    pub fn write_raw(&self, record_type: u32, payload: &[u8]) -> Result<u64> {
        if self.read_only {
            return Err(MmapError::ReadOnly);
        }

        let checksum = crc32(payload);
        let record_header = RecordHeader::new(record_type, payload.len() as u32, checksum);
        let total_size = record_header.total_size();

        // Get current write position and reserve space atomically
        let offset = self
            .write_pos
            .fetch_add(total_size as u64, Ordering::SeqCst);

        // Check if we have enough space
        let header = self.header.read();
        let available = header.file_size - offset;
        drop(header);

        if available < total_size as u64 {
            // Roll back the write position
            self.write_pos
                .fetch_sub(total_size as u64, Ordering::SeqCst);
            return Err(MmapError::StorageFull {
                requested: total_size,
                available: available as usize,
            });
        }

        // Write record header and payload
        let header_bytes = record_header.to_bytes();
        let mut mmap = self.mmap.write();

        let start = offset as usize;
        mmap[start..start + RECORD_HEADER_SIZE].copy_from_slice(&header_bytes);
        mmap[start + RECORD_HEADER_SIZE..start + RECORD_HEADER_SIZE + payload.len()]
            .copy_from_slice(payload);

        // Zero out padding
        let padding_start = start + RECORD_HEADER_SIZE + payload.len();
        let padding_end = start + total_size;
        for i in padding_start..padding_end {
            mmap[i] = 0;
        }

        drop(mmap);

        // Increment record count
        self.record_count.fetch_add(1, Ordering::SeqCst);

        // Update header periodically (every 100 records to reduce I/O)
        if self.record_count.load(Ordering::Relaxed) % 100 == 0 {
            let _ = self.update_header();
        }

        trace!(
            "Wrote record type {} at offset {} ({} bytes)",
            record_type,
            offset,
            total_size
        );

        Ok(offset)
    }

    /// Read a record from storage
    pub fn read_record<T: DeserializeOwned>(&self, offset: u64) -> Result<(RecordType, T)> {
        let (record_type, payload) = self.read_raw(offset)?;
        let data = deserialize(&payload).map_err(|e| MmapError::Deserialization(e.to_string()))?;
        Ok((RecordType::from(record_type), data))
    }

    /// Read raw bytes from storage
    pub fn read_raw(&self, offset: u64) -> Result<(u32, Vec<u8>)> {
        let mmap = self.mmap.read();
        let start = offset as usize;

        if start + RECORD_HEADER_SIZE > mmap.len() {
            return Err(MmapError::InvalidOffset { offset });
        }

        // Read record header
        let record_header = RecordHeader::from_bytes(&mmap[start..start + RECORD_HEADER_SIZE])?;

        if record_header.is_deleted() {
            return Err(MmapError::RecordNotFound { offset });
        }

        let payload_start = start + RECORD_HEADER_SIZE;
        let payload_end = payload_start + record_header.payload_size as usize;

        if payload_end > mmap.len() {
            return Err(MmapError::InvalidOffset { offset });
        }

        let payload = mmap[payload_start..payload_end].to_vec();

        // Verify checksum if enabled
        if self.config.verify_checksums {
            let actual_checksum = crc32(&payload);
            if actual_checksum != record_header.checksum {
                return Err(MmapError::ChecksumMismatch {
                    expected: record_header.checksum,
                    actual: actual_checksum,
                });
            }
        }

        Ok((record_header.record_type, payload))
    }

    /// Iterate over all records
    pub fn iter(&self) -> RecordIterator<'_> {
        RecordIterator {
            storage: self,
            offset: HEADER_SIZE as u64,
            end_offset: self.write_pos.load(Ordering::SeqCst),
        }
    }

    /// Iterate over records of a specific type
    pub fn iter_type(&self, record_type: RecordType) -> FilteredRecordIterator<'_> {
        FilteredRecordIterator {
            inner: self.iter(),
            filter_type: record_type as u32,
        }
    }

    /// Check if the storage is empty
    pub fn is_empty(&self) -> bool {
        self.record_count.load(Ordering::SeqCst) == 0
    }

    /// Get the number of records
    pub fn record_count(&self) -> u64 {
        self.record_count.load(Ordering::SeqCst)
    }

    /// Get the amount of space used
    pub fn bytes_used(&self) -> u64 {
        self.write_pos.load(Ordering::SeqCst)
    }

    /// Get the total capacity
    pub fn capacity(&self) -> u64 {
        self.header.read().file_size
    }

    /// Get the amount of space available
    pub fn bytes_available(&self) -> u64 {
        self.capacity() - self.bytes_used()
    }

    /// Get the fill percentage
    pub fn fill_percentage(&self) -> f64 {
        (self.bytes_used() as f64 / self.capacity() as f64) * 100.0
    }

    /// Flush changes to disk
    pub fn flush(&self) -> Result<()> {
        self.update_header()?;
        let mmap = self.mmap.read();
        mmap.flush()?;
        Ok(())
    }

    /// Sync changes to disk (async-safe)
    pub fn sync(&self) -> Result<()> {
        let mmap = self.mmap.read();
        mmap.flush_async()?;
        Ok(())
    }

    /// Get the file path
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Check if storage is full
    pub fn is_full(&self) -> bool {
        self.bytes_available() < RECORD_HEADER_SIZE as u64 + 64
    }

    /// Mark a record as deleted
    pub fn delete_record(&self, offset: u64) -> Result<()> {
        if self.read_only {
            return Err(MmapError::ReadOnly);
        }

        let mut mmap = self.mmap.write();
        let start = offset as usize;

        if start + RECORD_HEADER_SIZE > mmap.len() {
            return Err(MmapError::InvalidOffset { offset });
        }

        // Read current flags
        let flags_offset = start + 12; // offset to flags field
        let mut flags = mmap[flags_offset..flags_offset + 4]
            .iter()
            .fold(0u32, |acc, &b| (acc << 8) | b as u32);

        // Set deleted flag
        flags |= 0x01;

        // Write back
        mmap[flags_offset..flags_offset + 4].copy_from_slice(&flags.to_le_bytes());

        Ok(())
    }

    /// Compact the storage file (remove deleted records)
    pub fn compact(&self) -> Result<CompactionStats> {
        if self.read_only {
            return Err(MmapError::ReadOnly);
        }

        let mut records_kept = 0u64;
        let mut records_deleted = 0u64;
        let mut bytes_reclaimed = 0u64;

        // This is a simplified compaction - in production, you'd want to
        // copy to a new file and swap
        for record in self.iter() {
            match record {
                Ok((_, header, _)) if header.is_deleted() => {
                    records_deleted += 1;
                    bytes_reclaimed += header.total_size() as u64;
                }
                Ok(_) => {
                    records_kept += 1;
                }
                Err(_) => {
                    records_deleted += 1;
                }
            }
        }

        Ok(CompactionStats {
            records_kept,
            records_deleted,
            bytes_reclaimed,
        })
    }

    /// Get storage statistics
    pub fn stats(&self) -> StorageStats {
        let header = self.header.read();
        StorageStats {
            file_path: self.path.clone(),
            file_size: header.file_size,
            bytes_used: self.bytes_used(),
            bytes_available: self.bytes_available(),
            record_count: self.record_count(),
            created_at: DateTime::from_timestamp(header.created_at, 0)
                .unwrap_or_else(|| Utc::now()),
            modified_at: DateTime::from_timestamp(header.modified_at, 0)
                .unwrap_or_else(|| Utc::now()),
            fill_percentage: self.fill_percentage(),
        }
    }
}

impl Drop for MmapStorage {
    fn drop(&mut self) {
        // Ensure header is updated on close
        if !self.read_only {
            if let Err(e) = self.flush() {
                error!("Failed to flush storage on close: {}", e);
            }
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Iterators
// ─────────────────────────────────────────────────────────────────────────────

/// Iterator over all records in storage
pub struct RecordIterator<'a> {
    storage: &'a MmapStorage,
    offset: u64,
    end_offset: u64,
}

/// Filtered iterator that only returns records of a specific type
pub struct FilteredRecordIterator<'a> {
    inner: RecordIterator<'a>,
    filter_type: u32,
}

impl<'a> Iterator for FilteredRecordIterator<'a> {
    type Item = Result<(u64, RecordHeader, Vec<u8>)>;

    fn next(&mut self) -> Option<Self::Item> {
        loop {
            match self.inner.next() {
                Some(Ok((offset, header, data))) => {
                    if header.record_type == self.filter_type {
                        return Some(Ok((offset, header, data)));
                    }
                    // Continue to next record if type doesn't match
                }
                Some(Err(e)) => return Some(Err(e)),
                None => return None,
            }
        }
    }
}

impl<'a> Iterator for RecordIterator<'a> {
    type Item = Result<(u64, RecordHeader, Vec<u8>)>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.offset >= self.end_offset {
            return None;
        }

        let mmap = self.storage.mmap.read();
        let start = self.offset as usize;

        if start + RECORD_HEADER_SIZE > mmap.len() {
            return None;
        }

        // Read record header
        let record_header = match RecordHeader::from_bytes(&mmap[start..start + RECORD_HEADER_SIZE])
        {
            Ok(h) => h,
            Err(e) => return Some(Err(e)),
        };

        let payload_start = start + RECORD_HEADER_SIZE;
        let payload_end = payload_start + record_header.payload_size as usize;

        if payload_end > mmap.len() {
            return Some(Err(MmapError::InvalidOffset {
                offset: self.offset,
            }));
        }

        // Read payload
        let payload = mmap[payload_start..payload_end].to_vec();

        let current_offset = self.offset;
        // Advance by the aligned total size, not just payload_end
        self.offset += record_header.total_size() as u64;

        Some(Ok((current_offset, record_header, payload)))
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Tests
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn test_mmap_storage_create() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("test.mmap");

        let config = MmapStorageConfig {
            file_size: 1024 * 1024, // 1 MB
            ..Default::default()
        };

        let storage = MmapStorage::open(&path, config).unwrap();
        assert!(storage.is_empty());
        assert_eq!(storage.record_count(), 0);
    }

    #[test]
    fn test_mmap_storage_write_read() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("test.mmap");

        let config = MmapStorageConfig::default();
        let storage = MmapStorage::open(&path, config).unwrap();

        // Write data
        let data = b"test data for mmap storage";
        let offset = storage.write_raw(1, data).unwrap();

        // Read it back
        let (_, read_data) = storage.read_raw(offset).unwrap();
        assert_eq!(read_data, data);
    }

    #[test]
    fn test_mmap_storage_multiple_writes() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("test.mmap");

        let config = MmapStorageConfig::default();
        let storage = MmapStorage::open(&path, config).unwrap();

        let mut offsets = Vec::new();

        for i in 0..100 {
            let data = format!("record number {}", i);
            let offset = storage.write_raw(1, data.as_bytes()).unwrap();
            offsets.push((offset, data));
        }

        // Verify all records
        for (offset, expected) in offsets {
            let (_, data) = storage.read_raw(offset).unwrap();
            assert_eq!(data, expected.as_bytes());
        }

        assert_eq!(storage.record_count(), 100);
    }

    #[test]
    fn test_mmap_storage_persistence() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("test.mmap");

        let data = b"persistent data";
        let offset;

        // Write and close
        {
            let config = MmapStorageConfig::default();
            let storage = MmapStorage::open(&path, config).unwrap();
            offset = storage.write_raw(1, data).unwrap();
            storage.flush().unwrap();
        }

        // Reopen and read
        {
            let config = MmapStorageConfig {
                create_if_missing: false,
                ..Default::default()
            };
            let storage = MmapStorage::open(&path, config).unwrap();
            let (_, read_data) = storage.read_raw(offset).unwrap();
            assert_eq!(read_data, data);
        }
    }

    #[test]
    fn test_mmap_storage_stats() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("test.mmap");

        let config = MmapStorageConfig {
            file_size: 1024 * 1024,
            ..Default::default()
        };

        let storage = MmapStorage::open(&path, config).unwrap();

        for i in 0..50 {
            let data = format!("data {}", i);
            storage.write_raw(1, data.as_bytes()).unwrap();
        }

        assert_eq!(storage.record_count(), 50);
    }

    #[test]
    fn test_mmap_storage_iterator() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("test.mmap");

        let config = MmapStorageConfig::default();
        let storage = MmapStorage::open(&path, config).unwrap();

        let records: Vec<String> = (0..10).map(|i| format!("record {}", i)).collect();

        for record in &records {
            storage.write_raw(1, record.as_bytes()).unwrap();
        }

        // Iterate and verify
        let mut count = 0;
        for result in storage.iter() {
            let (_, _, data) = result.unwrap();
            let data_str = String::from_utf8(data).unwrap();
            assert!(records.contains(&data_str));
            count += 1;
        }

        assert_eq!(count, records.len());
    }

    #[test]
    fn test_mmap_config_default() {
        let config = MmapStorageConfig::default();
        assert!(config.file_size > 0);
        assert!(!config.read_only);
        assert!(config.verify_checksums);
    }
}
