//! Core type definitions for the Zeroed DoS protection daemon
//!
//! This module contains all fundamental data structures used throughout
//! the application for tracking connections, IP addresses, MAC addresses,
//! and threat assessment.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::VecDeque;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::time::{Duration, Instant};

/// Unique identifier for tracking entries
pub type TrackingId = u64;

/// MAC address representation (6 bytes)
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct MacAddress(pub [u8; 6]);

impl MacAddress {
    pub const ZERO: MacAddress = MacAddress([0u8; 6]);
    pub const BROADCAST: MacAddress = MacAddress([0xff; 6]);

    pub fn new(bytes: [u8; 6]) -> Self {
        Self(bytes)
    }

    pub fn from_slice(slice: &[u8]) -> Option<Self> {
        if slice.len() >= 6 {
            let mut bytes = [0u8; 6];
            bytes.copy_from_slice(&slice[..6]);
            Some(Self(bytes))
        } else {
            None
        }
    }

    pub fn is_unicast(&self) -> bool {
        (self.0[0] & 0x01) == 0
    }

    pub fn is_multicast(&self) -> bool {
        (self.0[0] & 0x01) == 1
    }

    pub fn is_local(&self) -> bool {
        (self.0[0] & 0x02) == 2
    }

    pub fn as_bytes(&self) -> &[u8; 6] {
        &self.0
    }
}

impl std::fmt::Display for MacAddress {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
            self.0[0], self.0[1], self.0[2], self.0[3], self.0[4], self.0[5]
        )
    }
}

impl Default for MacAddress {
    fn default() -> Self {
        Self::ZERO
    }
}

/// Protocol types we track
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[repr(u8)]
pub enum Protocol {
    Tcp = 6,
    Udp = 17,
    Icmp = 1,
    Icmpv6 = 58,
    Unknown(u8),
}

impl From<u8> for Protocol {
    fn from(value: u8) -> Self {
        match value {
            1 => Protocol::Icmp,
            6 => Protocol::Tcp,
            17 => Protocol::Udp,
            58 => Protocol::Icmpv6,
            other => Protocol::Unknown(other),
        }
    }
}

impl From<Protocol> for u8 {
    fn from(proto: Protocol) -> Self {
        match proto {
            Protocol::Icmp => 1,
            Protocol::Tcp => 6,
            Protocol::Udp => 17,
            Protocol::Icmpv6 => 58,
            Protocol::Unknown(v) => v,
        }
    }
}

/// TCP flags for connection analysis
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct TcpFlags {
    pub fin: bool,
    pub syn: bool,
    pub rst: bool,
    pub psh: bool,
    pub ack: bool,
    pub urg: bool,
    pub ece: bool,
    pub cwr: bool,
}

impl TcpFlags {
    pub fn from_byte(byte: u8) -> Self {
        Self {
            fin: (byte & 0x01) != 0,
            syn: (byte & 0x02) != 0,
            rst: (byte & 0x04) != 0,
            psh: (byte & 0x08) != 0,
            ack: (byte & 0x10) != 0,
            urg: (byte & 0x20) != 0,
            ece: (byte & 0x40) != 0,
            cwr: (byte & 0x80) != 0,
        }
    }

    pub fn to_byte(&self) -> u8 {
        let mut byte = 0u8;
        if self.fin {
            byte |= 0x01;
        }
        if self.syn {
            byte |= 0x02;
        }
        if self.rst {
            byte |= 0x04;
        }
        if self.psh {
            byte |= 0x08;
        }
        if self.ack {
            byte |= 0x10;
        }
        if self.urg {
            byte |= 0x20;
        }
        if self.ece {
            byte |= 0x40;
        }
        if self.cwr {
            byte |= 0x80;
        }
        byte
    }

    /// Check if this is a SYN flood indicator (SYN without ACK)
    pub fn is_syn_only(&self) -> bool {
        self.syn && !self.ack
    }
}

/// Threat level classification
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[repr(u8)]
pub enum ThreatLevel {
    /// Normal traffic
    None = 0,
    /// Slightly elevated activity
    Low = 1,
    /// Suspicious activity detected
    Medium = 2,
    /// High probability of attack
    High = 3,
    /// Confirmed attack in progress
    Critical = 4,
}

impl Default for ThreatLevel {
    fn default() -> Self {
        Self::None
    }
}

impl ThreatLevel {
    pub fn from_score(score: f64) -> Self {
        match score {
            s if s < 0.2 => ThreatLevel::None,
            s if s < 0.4 => ThreatLevel::Low,
            s if s < 0.6 => ThreatLevel::Medium,
            s if s < 0.8 => ThreatLevel::High,
            _ => ThreatLevel::Critical,
        }
    }
}

/// Attack type classification
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum AttackType {
    /// SYN flood attack
    SynFlood,
    /// UDP flood attack
    UdpFlood,
    /// ICMP flood (ping flood)
    IcmpFlood,
    /// HTTP flood (application layer)
    HttpFlood,
    /// Slowloris attack
    Slowloris,
    /// DNS amplification
    DnsAmplification,
    /// NTP amplification
    NtpAmplification,
    /// Generic volumetric attack
    Volumetric,
    /// Connection exhaustion
    ConnectionExhaustion,
    /// Unknown attack pattern
    Unknown,
}

/// Geographic region information
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct GeoLocation {
    /// ISO 3166-1 alpha-2 country code
    pub country_code: String,
    /// Country name
    pub country_name: String,
    /// Region/State
    pub region: Option<String>,
    /// City
    pub city: Option<String>,
    /// Latitude
    pub latitude: Option<f64>,
    /// Longitude
    pub longitude: Option<f64>,
    /// Autonomous System Number
    pub asn: Option<u32>,
    /// Organization name
    pub org: Option<String>,
}

impl Default for GeoLocation {
    fn default() -> Self {
        Self {
            country_code: "XX".to_string(),
            country_name: "Unknown".to_string(),
            region: None,
            city: None,
            latitude: None,
            longitude: None,
            asn: None,
            org: None,
        }
    }
}

/// Single connection/packet record
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConnectionRecord {
    /// Unique identifier
    pub id: TrackingId,
    /// Timestamp when the connection was observed
    pub timestamp: DateTime<Utc>,
    /// Source IP address
    pub src_ip: IpAddr,
    /// Destination IP address
    pub dst_ip: IpAddr,
    /// Source port (if applicable)
    pub src_port: Option<u16>,
    /// Destination port (if applicable)
    pub dst_port: Option<u16>,
    /// Source MAC address (if available from ARP/NDP)
    pub src_mac: Option<MacAddress>,
    /// Protocol type
    pub protocol: Protocol,
    /// TCP flags (if TCP)
    pub tcp_flags: Option<TcpFlags>,
    /// Packet size in bytes
    pub packet_size: u32,
    /// Payload size in bytes
    pub payload_size: u32,
}

/// Time-windowed statistics for an IP address
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IpStatistics {
    /// Total number of requests in the window
    pub request_count: u64,
    /// Total bytes transferred
    pub bytes_total: u64,
    /// Number of SYN packets (potential SYN flood indicator)
    pub syn_count: u64,
    /// Number of unique destination ports accessed
    pub unique_ports: u32,
    /// Number of failed connections (RST received)
    pub failed_connections: u64,
    /// Average packet size
    pub avg_packet_size: f64,
    /// Packets per second (calculated)
    pub packets_per_second: f64,
    /// Bytes per second (calculated)
    pub bytes_per_second: f64,
    /// Window start time
    pub window_start: DateTime<Utc>,
    /// Window duration in seconds
    pub window_duration_secs: u64,
}

impl Default for IpStatistics {
    fn default() -> Self {
        Self {
            request_count: 0,
            bytes_total: 0,
            syn_count: 0,
            unique_ports: 0,
            failed_connections: 0,
            avg_packet_size: 0.0,
            packets_per_second: 0.0,
            bytes_per_second: 0.0,
            window_start: Utc::now(),
            window_duration_secs: 60,
        }
    }
}

/// Sliding window for tracking request timestamps
#[derive(Debug, Clone)]
pub struct SlidingWindow {
    /// Timestamps of requests within the window
    timestamps: VecDeque<Instant>,
    /// Window duration
    window_size: Duration,
    /// Maximum capacity
    max_capacity: usize,
}

impl SlidingWindow {
    pub fn new(window_size: Duration, max_capacity: usize) -> Self {
        Self {
            timestamps: VecDeque::with_capacity(max_capacity),
            window_size,
            max_capacity,
        }
    }

    /// Add a new timestamp and clean old entries
    pub fn add(&mut self, timestamp: Instant) {
        self.clean_old_entries(timestamp);

        if self.timestamps.len() >= self.max_capacity {
            self.timestamps.pop_front();
        }
        self.timestamps.push_back(timestamp);
    }

    /// Get the count of entries in the current window
    pub fn count(&self) -> usize {
        self.timestamps.len()
    }

    /// Get the rate (requests per second)
    pub fn rate(&self) -> f64 {
        if self.timestamps.len() < 2 {
            return self.timestamps.len() as f64;
        }

        let duration = self.window_size.as_secs_f64();
        if duration > 0.0 {
            self.timestamps.len() as f64 / duration
        } else {
            0.0
        }
    }

    /// Clean entries older than the window
    fn clean_old_entries(&mut self, now: Instant) {
        while let Some(&front) = self.timestamps.front() {
            if now.duration_since(front) > self.window_size {
                self.timestamps.pop_front();
            } else {
                break;
            }
        }
    }

    /// Check if rate exceeds threshold
    pub fn exceeds_rate(&self, threshold: f64) -> bool {
        self.rate() > threshold
    }
}

/// IP tracking entry with all associated data
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IpTrackingEntry {
    /// The tracked IP address
    pub ip: IpAddr,
    /// Associated MAC address (if known)
    pub mac: Option<MacAddress>,
    /// Geographic location
    pub geo: Option<GeoLocation>,
    /// Current threat level
    pub threat_level: ThreatLevel,
    /// Threat score (0.0 - 1.0)
    pub threat_score: f64,
    /// Detected attack types
    pub attack_types: Vec<AttackType>,
    /// First seen timestamp
    pub first_seen: DateTime<Utc>,
    /// Last seen timestamp
    pub last_seen: DateTime<Utc>,
    /// Current statistics
    pub stats: IpStatistics,
    /// Whether this IP is currently blocked
    pub is_blocked: bool,
    /// Block expiration time (if blocked)
    pub block_expires: Option<DateTime<Utc>>,
    /// Number of times this IP has been blocked
    pub block_count: u32,
    /// Whitelisted status
    pub is_whitelisted: bool,
    /// Notes/comments
    pub notes: Option<String>,
}

impl IpTrackingEntry {
    pub fn new(ip: IpAddr) -> Self {
        let now = Utc::now();
        Self {
            ip,
            mac: None,
            geo: None,
            threat_level: ThreatLevel::None,
            threat_score: 0.0,
            attack_types: Vec::new(),
            first_seen: now,
            last_seen: now,
            stats: IpStatistics::default(),
            is_blocked: false,
            block_expires: None,
            block_count: 0,
            is_whitelisted: false,
            notes: None,
        }
    }

    pub fn update_last_seen(&mut self) {
        self.last_seen = Utc::now();
    }

    pub fn should_unblock(&self) -> bool {
        if let Some(expires) = self.block_expires {
            Utc::now() > expires
        } else {
            false
        }
    }
}

/// Action to take against a connection
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Action {
    /// Allow the connection
    Allow,
    /// Drop the packet silently
    Drop,
    /// Reject with RST/ICMP unreachable
    Reject,
    /// Rate limit the connection
    RateLimit,
    /// Tarpit (slow down responses)
    Tarpit,
    /// Challenge (e.g., SYN cookie)
    Challenge,
    /// Log only, no action
    LogOnly,
}

/// Rule matching criteria
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RuleCriteria {
    /// Source IP/CIDR to match
    pub src_ip: Option<String>,
    /// Destination IP/CIDR to match
    pub dst_ip: Option<String>,
    /// Source port range
    pub src_port_range: Option<(u16, u16)>,
    /// Destination port range
    pub dst_port_range: Option<(u16, u16)>,
    /// Protocol to match
    pub protocol: Option<Protocol>,
    /// Country codes to match
    pub countries: Option<Vec<String>>,
    /// Minimum threat level to match
    pub min_threat_level: Option<ThreatLevel>,
    /// Rate threshold (requests per second)
    pub rate_threshold: Option<f64>,
}

/// A protection rule
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Rule {
    /// Rule identifier
    pub id: u64,
    /// Rule name
    pub name: String,
    /// Rule description
    pub description: Option<String>,
    /// Matching criteria
    pub criteria: RuleCriteria,
    /// Action to take
    pub action: Action,
    /// Rule priority (higher = checked first)
    pub priority: i32,
    /// Whether the rule is enabled
    pub enabled: bool,
    /// Creation timestamp
    pub created_at: DateTime<Utc>,
    /// Last modified timestamp
    pub modified_at: DateTime<Utc>,
}

/// System-wide statistics
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct SystemStats {
    /// Total packets processed
    pub total_packets: u64,
    /// Total bytes processed
    pub total_bytes: u64,
    /// Packets dropped
    pub packets_dropped: u64,
    /// Packets allowed
    pub packets_allowed: u64,
    /// Currently tracked IPs
    pub tracked_ips: u64,
    /// Currently blocked IPs
    pub blocked_ips: u64,
    /// Active connections
    pub active_connections: u64,
    /// CPU usage percentage
    pub cpu_usage: f64,
    /// Memory usage in bytes
    pub memory_usage: u64,
    /// Uptime in seconds
    pub uptime_secs: u64,
    /// Last update timestamp
    pub last_update: Option<DateTime<Utc>>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_mac_address_display() {
        let mac = MacAddress::new([0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff]);
        assert_eq!(format!("{}", mac), "aa:bb:cc:dd:ee:ff");
    }

    #[test]
    fn test_tcp_flags() {
        let flags = TcpFlags::from_byte(0x02); // SYN only
        assert!(flags.syn);
        assert!(!flags.ack);
        assert!(flags.is_syn_only());
    }

    #[test]
    fn test_threat_level_from_score() {
        assert_eq!(ThreatLevel::from_score(0.1), ThreatLevel::None);
        assert_eq!(ThreatLevel::from_score(0.5), ThreatLevel::Medium);
        assert_eq!(ThreatLevel::from_score(0.9), ThreatLevel::Critical);
    }

    #[test]
    fn test_sliding_window() {
        let mut window = SlidingWindow::new(Duration::from_secs(60), 1000);
        let now = Instant::now();

        for _ in 0..100 {
            window.add(now);
        }

        assert_eq!(window.count(), 100);
    }
}
