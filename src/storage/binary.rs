//! Binary format module for compact data serialization
//!
//! This module provides a custom binary format for efficiently storing connection
//! records, IP tracking data, and other structures used by the Zeroed daemon.
//! The format is designed to be:
//! - Compact: Minimize storage space
//! - Fast: Quick serialization/deserialization
//! - Portable: Little-endian byte order
//! - Extensible: Version field for future changes

use byteorder::{LittleEndian, ReadBytesExt, WriteBytesExt};
use chrono::{DateTime, TimeZone, Utc};
use serde::{de::DeserializeOwned, Serialize};
use std::io::{self, Cursor, Read, Write};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use crate::core::types::{ConnectionRecord, MacAddress, Protocol, TcpFlags, ThreatLevel};

// ─────────────────────────────────────────────────────────────────────────────
// Constants
// ─────────────────────────────────────────────────────────────────────────────

/// Magic number for file identification ("ZERO" in ASCII)
pub const MAGIC_NUMBER: [u8; 4] = [0x5A, 0x45, 0x52, 0x4F];

/// Current binary format version
pub const VERSION: u8 = 1;

/// Record type identifiers
pub mod record_types {
    pub const CONNECTION: u8 = 1;
    pub const IP_TRACKING: u8 = 2;
    pub const BLOCK_EVENT: u8 = 3;
    pub const UNBLOCK_EVENT: u8 = 4;
    pub const ATTACK_DETECTION: u8 = 5;
    pub const STATISTICS: u8 = 6;
    pub const GEO_DATA: u8 = 7;
}

/// IP version identifiers
pub mod ip_version {
    pub const IPV4: u8 = 4;
    pub const IPV6: u8 = 6;
}

// ─────────────────────────────────────────────────────────────────────────────
// Error Types
// ─────────────────────────────────────────────────────────────────────────────

/// Binary format errors
#[derive(Debug, thiserror::Error)]
pub enum BinaryError {
    #[error("I/O error: {0}")]
    Io(#[from] io::Error),

    #[error("Invalid magic number")]
    InvalidMagic,

    #[error("Unsupported version: {0}")]
    UnsupportedVersion(u8),

    #[error("Invalid record type: {0}")]
    InvalidRecordType(u8),

    #[error("Invalid IP version: {0}")]
    InvalidIpVersion(u8),

    #[error("Invalid data length: expected {expected}, got {actual}")]
    InvalidLength { expected: usize, actual: usize },

    #[error("Checksum mismatch: expected {expected:08x}, got {actual:08x}")]
    ChecksumMismatch { expected: u32, actual: u32 },

    #[error("Buffer too small: need {needed} bytes, have {available}")]
    BufferTooSmall { needed: usize, available: usize },

    #[error("Invalid protocol: {0}")]
    InvalidProtocol(u8),

    #[error("Data corruption detected")]
    Corruption,
}

pub type Result<T> = std::result::Result<T, BinaryError>;

// ─────────────────────────────────────────────────────────────────────────────
// Record Header
// ─────────────────────────────────────────────────────────────────────────────

/// Binary record header (16 bytes)
///
/// Layout:
/// - record_type: u8 (1 byte)
/// - flags: u8 (1 byte)
/// - reserved: u16 (2 bytes)
/// - payload_size: u32 (4 bytes)
/// - checksum: u32 (4 bytes) - CRC32 of payload
/// - timestamp: u32 (4 bytes) - Unix timestamp (seconds)
#[derive(Debug, Clone, Copy)]
#[repr(C)]
pub struct RecordHeader {
    pub record_type: u8,
    pub flags: u8,
    pub reserved: u16,
    pub payload_size: u32,
    pub checksum: u32,
    pub timestamp: u32,
}

impl RecordHeader {
    pub const SIZE: usize = 16;

    /// Create a new record header
    pub fn new(record_type: u8, payload_size: u32, checksum: u32) -> Self {
        Self {
            record_type,
            flags: 0,
            reserved: 0,
            payload_size,
            checksum,
            timestamp: Utc::now().timestamp() as u32,
        }
    }

    /// Serialize to bytes
    pub fn to_bytes(&self) -> [u8; Self::SIZE] {
        let mut bytes = [0u8; Self::SIZE];
        let mut cursor = Cursor::new(&mut bytes[..]);

        cursor.write_u8(self.record_type).unwrap();
        cursor.write_u8(self.flags).unwrap();
        cursor.write_u16::<LittleEndian>(self.reserved).unwrap();
        cursor.write_u32::<LittleEndian>(self.payload_size).unwrap();
        cursor.write_u32::<LittleEndian>(self.checksum).unwrap();
        cursor.write_u32::<LittleEndian>(self.timestamp).unwrap();

        bytes
    }

    /// Deserialize from bytes
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        if bytes.len() < Self::SIZE {
            return Err(BinaryError::BufferTooSmall {
                needed: Self::SIZE,
                available: bytes.len(),
            });
        }

        let mut cursor = Cursor::new(bytes);

        Ok(Self {
            record_type: cursor.read_u8()?,
            flags: cursor.read_u8()?,
            reserved: cursor.read_u16::<LittleEndian>()?,
            payload_size: cursor.read_u32::<LittleEndian>()?,
            checksum: cursor.read_u32::<LittleEndian>()?,
            timestamp: cursor.read_u32::<LittleEndian>()?,
        })
    }

    /// Check if record is marked as deleted
    pub fn is_deleted(&self) -> bool {
        self.flags & 0x01 != 0
    }

    /// Check if record is compressed
    pub fn is_compressed(&self) -> bool {
        self.flags & 0x02 != 0
    }

    /// Get total size (header + payload)
    pub fn total_size(&self) -> usize {
        Self::SIZE + self.payload_size as usize
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Binary Writer
// ─────────────────────────────────────────────────────────────────────────────

/// Writer for binary serialization
pub struct BinaryWriter<W: Write> {
    writer: W,
    bytes_written: usize,
}

impl<W: Write> BinaryWriter<W> {
    /// Create a new binary writer
    pub fn new(writer: W) -> Self {
        Self {
            writer,
            bytes_written: 0,
        }
    }

    /// Get bytes written so far
    pub fn bytes_written(&self) -> usize {
        self.bytes_written
    }

    /// Write file header
    pub fn write_header(&mut self) -> Result<()> {
        self.writer.write_all(&MAGIC_NUMBER)?;
        self.writer.write_u8(VERSION)?;
        self.bytes_written += 5;
        Ok(())
    }

    /// Write a u8
    pub fn write_u8(&mut self, value: u8) -> Result<()> {
        self.writer.write_u8(value)?;
        self.bytes_written += 1;
        Ok(())
    }

    /// Write a u16
    pub fn write_u16(&mut self, value: u16) -> Result<()> {
        self.writer.write_u16::<LittleEndian>(value)?;
        self.bytes_written += 2;
        Ok(())
    }

    /// Write a u32
    pub fn write_u32(&mut self, value: u32) -> Result<()> {
        self.writer.write_u32::<LittleEndian>(value)?;
        self.bytes_written += 4;
        Ok(())
    }

    /// Write a u64
    pub fn write_u64(&mut self, value: u64) -> Result<()> {
        self.writer.write_u64::<LittleEndian>(value)?;
        self.bytes_written += 8;
        Ok(())
    }

    /// Write an i64
    pub fn write_i64(&mut self, value: i64) -> Result<()> {
        self.writer.write_i64::<LittleEndian>(value)?;
        self.bytes_written += 8;
        Ok(())
    }

    /// Write a f64
    pub fn write_f64(&mut self, value: f64) -> Result<()> {
        self.writer.write_f64::<LittleEndian>(value)?;
        self.bytes_written += 8;
        Ok(())
    }

    /// Write raw bytes
    pub fn write_bytes(&mut self, bytes: &[u8]) -> Result<()> {
        self.writer.write_all(bytes)?;
        self.bytes_written += bytes.len();
        Ok(())
    }

    /// Write a length-prefixed byte slice
    pub fn write_bytes_prefixed(&mut self, bytes: &[u8]) -> Result<()> {
        self.write_u32(bytes.len() as u32)?;
        self.write_bytes(bytes)?;
        Ok(())
    }

    /// Write an IP address
    pub fn write_ip(&mut self, ip: &IpAddr) -> Result<()> {
        match ip {
            IpAddr::V4(v4) => {
                self.write_u8(ip_version::IPV4)?;
                self.write_bytes(&v4.octets())?;
            }
            IpAddr::V6(v6) => {
                self.write_u8(ip_version::IPV6)?;
                self.write_bytes(&v6.octets())?;
            }
        }
        Ok(())
    }

    /// Write a MAC address
    pub fn write_mac(&mut self, mac: &MacAddress) -> Result<()> {
        self.write_bytes(&mac.0)?;
        Ok(())
    }

    /// Write an optional MAC address
    pub fn write_optional_mac(&mut self, mac: &Option<MacAddress>) -> Result<()> {
        match mac {
            Some(m) => {
                self.write_u8(1)?;
                self.write_mac(m)?;
            }
            None => {
                self.write_u8(0)?;
            }
        }
        Ok(())
    }

    /// Write a timestamp
    pub fn write_timestamp(&mut self, ts: &DateTime<Utc>) -> Result<()> {
        self.write_i64(ts.timestamp_millis())?;
        Ok(())
    }

    /// Write TCP flags
    pub fn write_tcp_flags(&mut self, flags: &Option<TcpFlags>) -> Result<()> {
        match flags {
            Some(f) => {
                self.write_u8(1)?;
                self.write_u8(f.to_byte())?;
            }
            None => {
                self.write_u8(0)?;
            }
        }
        Ok(())
    }

    /// Write a protocol
    pub fn write_protocol(&mut self, proto: Protocol) -> Result<()> {
        self.write_u8(proto.into())?;
        Ok(())
    }

    /// Write a connection record
    pub fn write_connection_record(&mut self, record: &ConnectionRecord) -> Result<usize> {
        let start = self.bytes_written;

        self.write_u64(record.id)?;
        self.write_timestamp(&record.timestamp)?;
        self.write_ip(&record.src_ip)?;
        self.write_ip(&record.dst_ip)?;
        self.write_u16(record.src_port.unwrap_or(0))?;
        self.write_u16(record.dst_port.unwrap_or(0))?;
        self.write_optional_mac(&record.src_mac)?;
        self.write_protocol(record.protocol)?;
        self.write_tcp_flags(&record.tcp_flags)?;
        self.write_u32(record.packet_size)?;
        self.write_u32(record.payload_size)?;

        Ok(self.bytes_written - start)
    }

    /// Flush the writer
    pub fn flush(&mut self) -> Result<()> {
        self.writer.flush()?;
        Ok(())
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Binary Reader
// ─────────────────────────────────────────────────────────────────────────────

/// Reader for binary deserialization
pub struct BinaryReader<R: Read> {
    reader: R,
    bytes_read: usize,
}

impl<R: Read> BinaryReader<R> {
    /// Create a new binary reader
    pub fn new(reader: R) -> Self {
        Self {
            reader,
            bytes_read: 0,
        }
    }

    /// Get bytes read so far
    pub fn bytes_read(&self) -> usize {
        self.bytes_read
    }

    /// Read and verify file header
    pub fn read_header(&mut self) -> Result<u8> {
        let mut magic = [0u8; 4];
        self.reader.read_exact(&mut magic)?;
        self.bytes_read += 4;

        if magic != MAGIC_NUMBER {
            return Err(BinaryError::InvalidMagic);
        }

        let version = self.read_u8()?;
        if version > VERSION {
            return Err(BinaryError::UnsupportedVersion(version));
        }

        Ok(version)
    }

    /// Read a u8
    pub fn read_u8(&mut self) -> Result<u8> {
        let value = self.reader.read_u8()?;
        self.bytes_read += 1;
        Ok(value)
    }

    /// Read a u16
    pub fn read_u16(&mut self) -> Result<u16> {
        let value = self.reader.read_u16::<LittleEndian>()?;
        self.bytes_read += 2;
        Ok(value)
    }

    /// Read a u32
    pub fn read_u32(&mut self) -> Result<u32> {
        let value = self.reader.read_u32::<LittleEndian>()?;
        self.bytes_read += 4;
        Ok(value)
    }

    /// Read a u64
    pub fn read_u64(&mut self) -> Result<u64> {
        let value = self.reader.read_u64::<LittleEndian>()?;
        self.bytes_read += 8;
        Ok(value)
    }

    /// Read an i64
    pub fn read_i64(&mut self) -> Result<i64> {
        let value = self.reader.read_i64::<LittleEndian>()?;
        self.bytes_read += 8;
        Ok(value)
    }

    /// Read a f64
    pub fn read_f64(&mut self) -> Result<f64> {
        let value = self.reader.read_f64::<LittleEndian>()?;
        self.bytes_read += 8;
        Ok(value)
    }

    /// Read exact bytes
    pub fn read_bytes(&mut self, len: usize) -> Result<Vec<u8>> {
        let mut buf = vec![0u8; len];
        self.reader.read_exact(&mut buf)?;
        self.bytes_read += len;
        Ok(buf)
    }

    /// Read a length-prefixed byte slice
    pub fn read_bytes_prefixed(&mut self) -> Result<Vec<u8>> {
        let len = self.read_u32()? as usize;
        self.read_bytes(len)
    }

    /// Read an IP address
    pub fn read_ip(&mut self) -> Result<IpAddr> {
        let version = self.read_u8()?;
        match version {
            ip_version::IPV4 => {
                let bytes = self.read_bytes(4)?;
                let octets: [u8; 4] = bytes.try_into().unwrap();
                Ok(IpAddr::V4(Ipv4Addr::from(octets)))
            }
            ip_version::IPV6 => {
                let bytes = self.read_bytes(16)?;
                let octets: [u8; 16] = bytes.try_into().unwrap();
                Ok(IpAddr::V6(Ipv6Addr::from(octets)))
            }
            _ => Err(BinaryError::InvalidIpVersion(version)),
        }
    }

    /// Read a MAC address
    pub fn read_mac(&mut self) -> Result<MacAddress> {
        let bytes = self.read_bytes(6)?;
        let octets: [u8; 6] = bytes.try_into().unwrap();
        Ok(MacAddress::new(octets))
    }

    /// Read an optional MAC address
    pub fn read_optional_mac(&mut self) -> Result<Option<MacAddress>> {
        let present = self.read_u8()?;
        if present == 1 {
            Ok(Some(self.read_mac()?))
        } else {
            Ok(None)
        }
    }

    /// Read a timestamp
    pub fn read_timestamp(&mut self) -> Result<DateTime<Utc>> {
        let millis = self.read_i64()?;
        Ok(Utc
            .timestamp_millis_opt(millis)
            .single()
            .unwrap_or_else(Utc::now))
    }

    /// Read TCP flags
    pub fn read_tcp_flags(&mut self) -> Result<Option<TcpFlags>> {
        let present = self.read_u8()?;
        if present == 1 {
            let byte = self.read_u8()?;
            Ok(Some(TcpFlags::from_byte(byte)))
        } else {
            Ok(None)
        }
    }

    /// Read a protocol
    pub fn read_protocol(&mut self) -> Result<Protocol> {
        let byte = self.read_u8()?;
        Ok(Protocol::from(byte))
    }

    /// Read a connection record
    pub fn read_connection_record(&mut self) -> Result<ConnectionRecord> {
        let id = self.read_u64()?;
        let timestamp = self.read_timestamp()?;
        let src_ip = self.read_ip()?;
        let dst_ip = self.read_ip()?;
        let src_port_raw = self.read_u16()?;
        let dst_port_raw = self.read_u16()?;
        let src_mac = self.read_optional_mac()?;
        let protocol = self.read_protocol()?;
        let tcp_flags = self.read_tcp_flags()?;
        let packet_size = self.read_u32()?;
        let payload_size = self.read_u32()?;

        let src_port = if src_port_raw == 0 {
            None
        } else {
            Some(src_port_raw)
        };
        let dst_port = if dst_port_raw == 0 {
            None
        } else {
            Some(dst_port_raw)
        };

        Ok(ConnectionRecord {
            id,
            timestamp,
            src_ip,
            dst_ip,
            src_port,
            dst_port,
            src_mac,
            protocol,
            tcp_flags,
            packet_size,
            payload_size,
        })
    }

    /// Read a record header
    pub fn read_record_header(&mut self) -> Result<RecordHeader> {
        let bytes = self.read_bytes(RecordHeader::SIZE)?;
        RecordHeader::from_bytes(&bytes)
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// CRC32 Checksum
// ─────────────────────────────────────────────────────────────────────────────

/// Calculate CRC32 checksum
pub fn crc32(data: &[u8]) -> u32 {
    let mut hasher = crc32fast::Hasher::new();
    hasher.update(data);
    hasher.finalize()
}

/// Verify CRC32 checksum
pub fn verify_crc32(data: &[u8], expected: u32) -> bool {
    crc32(data) == expected
}

// ─────────────────────────────────────────────────────────────────────────────
// Compact Serialization Helpers
// ─────────────────────────────────────────────────────────────────────────────

/// Encode a variable-length integer (up to 64 bits)
/// Uses 7 bits per byte, MSB indicates continuation
pub fn encode_varint(mut value: u64) -> Vec<u8> {
    let mut result = Vec::with_capacity(10);
    loop {
        let mut byte = (value & 0x7F) as u8;
        value >>= 7;
        if value != 0 {
            byte |= 0x80;
        }
        result.push(byte);
        if value == 0 {
            break;
        }
    }
    result
}

/// Decode a variable-length integer
pub fn decode_varint(bytes: &[u8]) -> Result<(u64, usize)> {
    let mut result: u64 = 0;
    let mut shift = 0;
    let mut bytes_read = 0;

    for &byte in bytes {
        bytes_read += 1;
        result |= ((byte & 0x7F) as u64) << shift;
        if byte & 0x80 == 0 {
            return Ok((result, bytes_read));
        }
        shift += 7;
        if shift >= 64 {
            return Err(BinaryError::Corruption);
        }
    }

    Err(BinaryError::Corruption)
}

/// Encode a signed integer using zigzag encoding
pub fn encode_zigzag(value: i64) -> u64 {
    ((value << 1) ^ (value >> 63)) as u64
}

/// Decode a zigzag-encoded integer
pub fn decode_zigzag(value: u64) -> i64 {
    ((value >> 1) as i64) ^ -((value & 1) as i64)
}

// ─────────────────────────────────────────────────────────────────────────────
// Compact Connection Record
// ─────────────────────────────────────────────────────────────────────────────

/// A compact binary representation of a connection record
/// Designed for minimal storage space
#[derive(Debug, Clone)]
pub struct CompactRecord {
    /// Record ID (delta-encoded in streams)
    pub id: u64,
    /// Timestamp (delta from base in seconds)
    pub timestamp_delta: i32,
    /// Source IP (compressed)
    pub src_ip: CompactIp,
    /// Destination IP (compressed)
    pub dst_ip: CompactIp,
    /// Source port
    pub src_port: u16,
    /// Destination port
    pub dst_port: u16,
    /// Protocol and flags packed into one byte
    pub proto_flags: u8,
    /// Packet size (varint encoded)
    pub packet_size: u32,
}

/// Compact IP representation
#[derive(Debug, Clone, Copy)]
pub enum CompactIp {
    V4([u8; 4]),
    V6([u8; 16]),
}

impl From<IpAddr> for CompactIp {
    fn from(ip: IpAddr) -> Self {
        match ip {
            IpAddr::V4(v4) => CompactIp::V4(v4.octets()),
            IpAddr::V6(v6) => CompactIp::V6(v6.octets()),
        }
    }
}

impl From<CompactIp> for IpAddr {
    fn from(ip: CompactIp) -> Self {
        match ip {
            CompactIp::V4(b) => IpAddr::V4(Ipv4Addr::from(b)),
            CompactIp::V6(b) => IpAddr::V6(Ipv6Addr::from(b)),
        }
    }
}

impl CompactRecord {
    /// Approximate binary size
    pub fn binary_size(&self) -> usize {
        let ip_size = match (&self.src_ip, &self.dst_ip) {
            (CompactIp::V4(_), CompactIp::V4(_)) => 8,
            (CompactIp::V6(_), CompactIp::V6(_)) => 32,
            _ => 20,
        };

        8 + // id
        4 + // timestamp_delta
        ip_size +
        4 + // ports
        1 + // proto_flags
        4 // packet_size (max varint size for u32)
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Tests
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_record_header() {
        let header = RecordHeader::new(record_types::CONNECTION, 128, 0xDEADBEEF);
        let bytes = header.to_bytes();
        let parsed = RecordHeader::from_bytes(&bytes).unwrap();

        assert_eq!(parsed.record_type, record_types::CONNECTION);
        assert_eq!(parsed.payload_size, 128);
        assert_eq!(parsed.checksum, 0xDEADBEEF);
    }

    #[test]
    fn test_ip_serialization() {
        let mut buf = Vec::new();
        let mut writer = BinaryWriter::new(&mut buf);

        let ipv4 = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1));
        writer.write_ip(&ipv4).unwrap();

        let mut reader = BinaryReader::new(buf.as_slice());
        let read_ip = reader.read_ip().unwrap();

        assert_eq!(ipv4, read_ip);
    }

    #[test]
    fn test_varint_encoding() {
        let values = [0u64, 1, 127, 128, 16383, 16384, u32::MAX as u64, u64::MAX];

        for &value in &values {
            let encoded = encode_varint(value);
            let (decoded, _) = decode_varint(&encoded).unwrap();
            assert_eq!(value, decoded);
        }
    }

    #[test]
    fn test_zigzag_encoding() {
        let values = [0i64, -1, 1, -2, 2, i32::MIN as i64, i32::MAX as i64];

        for &value in &values {
            let encoded = encode_zigzag(value);
            let decoded = decode_zigzag(encoded);
            assert_eq!(value, decoded);
        }
    }

    #[test]
    fn test_crc32() {
        let data = b"Hello, World!";
        let checksum = crc32(data);
        assert!(verify_crc32(data, checksum));
        assert!(!verify_crc32(data, checksum ^ 1));
    }

    #[test]
    fn test_connection_record_roundtrip() {
        use chrono::Utc;

        let record = ConnectionRecord {
            id: 12345,
            timestamp: Utc::now(),
            src_ip: IpAddr::V4(Ipv4Addr::new(192, 168, 1, 100)),
            dst_ip: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
            src_port: Some(54321),
            dst_port: Some(80),
            src_mac: Some(MacAddress::new([0x00, 0x11, 0x22, 0x33, 0x44, 0x55])),
            protocol: Protocol::Tcp,
            tcp_flags: Some(TcpFlags::from_byte(0x12)), // SYN-ACK
            packet_size: 1500,
            payload_size: 1460,
        };

        let mut buf = Vec::new();
        let mut writer = BinaryWriter::new(&mut buf);
        writer.write_connection_record(&record).unwrap();

        let mut reader = BinaryReader::new(buf.as_slice());
        let read_record = reader.read_connection_record().unwrap();

        assert_eq!(record.id, read_record.id);
        assert_eq!(record.src_ip, read_record.src_ip);
        assert_eq!(record.dst_ip, read_record.dst_ip);
        assert_eq!(record.src_port, read_record.src_port);
        assert_eq!(record.dst_port, read_record.dst_port);
        assert_eq!(record.protocol, read_record.protocol);
        assert_eq!(record.packet_size, read_record.packet_size);
    }
}
