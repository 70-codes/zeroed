//! Connection tracking module for monitoring TCP/UDP connections
//!
//! This module provides functionality for tracking the state of network connections,
//! monitoring connection patterns, and detecting potential DoS attack indicators
//! such as excessive connection attempts from a single source.

use crate::core::types::{ConnectionRecord, MacAddress, Protocol, SlidingWindow, TcpFlags};
use chrono::{DateTime, Duration as ChronoDuration, Utc};
use dashmap::DashMap;
use parking_lot::RwLock;
use std::collections::{HashMap, VecDeque};
use std::net::IpAddr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

/// TCP connection states based on the TCP state machine
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum TcpState {
    /// Initial state, waiting for SYN
    Listen,
    /// SYN sent, waiting for SYN-ACK
    SynSent,
    /// SYN received, SYN-ACK sent, waiting for ACK
    SynReceived,
    /// Connection established
    Established,
    /// FIN sent, waiting for ACK
    FinWait1,
    /// FIN sent, ACK received, waiting for FIN from remote
    FinWait2,
    /// Close requested, waiting for FIN
    CloseWait,
    /// FIN sent after receiving FIN
    LastAck,
    /// Both FINs exchanged, waiting for timeout
    TimeWait,
    /// Connection closed
    Closed,
}

impl Default for TcpState {
    fn default() -> Self {
        TcpState::Listen
    }
}

impl TcpState {
    /// Check if the connection is in a half-open state (potential SYN flood)
    pub fn is_half_open(&self) -> bool {
        matches!(self, TcpState::SynReceived | TcpState::SynSent)
    }

    /// Check if the connection is fully established
    pub fn is_established(&self) -> bool {
        matches!(self, TcpState::Established)
    }

    /// Check if the connection is closing
    pub fn is_closing(&self) -> bool {
        matches!(
            self,
            TcpState::FinWait1
                | TcpState::FinWait2
                | TcpState::CloseWait
                | TcpState::LastAck
                | TcpState::TimeWait
        )
    }

    /// Check if the connection is closed
    pub fn is_closed(&self) -> bool {
        matches!(self, TcpState::Closed)
    }

    /// Transition to next state based on TCP flags
    pub fn transition(&self, flags: &TcpFlags, is_incoming: bool) -> Self {
        match self {
            TcpState::Listen => {
                if flags.syn && !flags.ack {
                    TcpState::SynReceived
                } else {
                    TcpState::Listen
                }
            }
            TcpState::SynSent => {
                if flags.syn && flags.ack {
                    TcpState::Established
                } else if flags.rst {
                    TcpState::Closed
                } else {
                    TcpState::SynSent
                }
            }
            TcpState::SynReceived => {
                if flags.ack && !flags.syn {
                    TcpState::Established
                } else if flags.rst {
                    TcpState::Closed
                } else {
                    TcpState::SynReceived
                }
            }
            TcpState::Established => {
                if flags.fin {
                    if is_incoming {
                        TcpState::CloseWait
                    } else {
                        TcpState::FinWait1
                    }
                } else if flags.rst {
                    TcpState::Closed
                } else {
                    TcpState::Established
                }
            }
            TcpState::FinWait1 => {
                if flags.fin && flags.ack {
                    TcpState::TimeWait
                } else if flags.fin {
                    TcpState::TimeWait
                } else if flags.ack {
                    TcpState::FinWait2
                } else if flags.rst {
                    TcpState::Closed
                } else {
                    TcpState::FinWait1
                }
            }
            TcpState::FinWait2 => {
                if flags.fin {
                    TcpState::TimeWait
                } else if flags.rst {
                    TcpState::Closed
                } else {
                    TcpState::FinWait2
                }
            }
            TcpState::CloseWait => {
                if flags.fin && !is_incoming {
                    TcpState::LastAck
                } else if flags.rst {
                    TcpState::Closed
                } else {
                    TcpState::CloseWait
                }
            }
            TcpState::LastAck => {
                if flags.ack {
                    TcpState::Closed
                } else if flags.rst {
                    TcpState::Closed
                } else {
                    TcpState::LastAck
                }
            }
            TcpState::TimeWait => {
                // TimeWait typically has a timeout, but for tracking we can transition to Closed
                TcpState::Closed
            }
            TcpState::Closed => TcpState::Closed,
        }
    }
}

/// Connection state for UDP (simplified, as UDP is connectionless)
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum UdpState {
    /// New UDP flow detected
    New,
    /// Active UDP flow (packets seen recently)
    Active,
    /// Stale UDP flow (no packets for a while)
    Stale,
    /// Closed (expired)
    Closed,
}

impl Default for UdpState {
    fn default() -> Self {
        UdpState::New
    }
}

/// Generic connection state enum
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConnectionState {
    Tcp(TcpState),
    Udp(UdpState),
    Icmp,
    Other,
}

impl ConnectionState {
    pub fn is_active(&self) -> bool {
        match self {
            ConnectionState::Tcp(state) => state.is_established(),
            ConnectionState::Udp(state) => matches!(state, UdpState::Active | UdpState::New),
            ConnectionState::Icmp => true,
            ConnectionState::Other => true,
        }
    }
}

/// Connection key for tracking (normalized 5-tuple)
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct ConnectionKey {
    /// Lower IP address (for normalization)
    pub ip_low: IpAddr,
    /// Higher IP address
    pub ip_high: IpAddr,
    /// Port for lower IP
    pub port_low: u16,
    /// Port for higher IP
    pub port_high: u16,
    /// Protocol
    pub protocol: Protocol,
}

impl ConnectionKey {
    /// Create a new normalized connection key
    pub fn new(
        src_ip: IpAddr,
        dst_ip: IpAddr,
        src_port: u16,
        dst_port: u16,
        protocol: Protocol,
    ) -> Self {
        if src_ip < dst_ip || (src_ip == dst_ip && src_port <= dst_port) {
            Self {
                ip_low: src_ip,
                ip_high: dst_ip,
                port_low: src_port,
                port_high: dst_port,
                protocol,
            }
        } else {
            Self {
                ip_low: dst_ip,
                ip_high: src_ip,
                port_low: dst_port,
                port_high: src_port,
                protocol,
            }
        }
    }

    /// Check if a packet belongs to this connection
    pub fn matches(&self, record: &ConnectionRecord) -> bool {
        let key = Self::new(
            record.src_ip,
            record.dst_ip,
            record.src_port.unwrap_or(0),
            record.dst_port.unwrap_or(0),
            record.protocol,
        );
        self == &key
    }
}

/// Tracked connection information
#[derive(Debug, Clone)]
pub struct TrackedConnection {
    /// Connection key
    pub key: ConnectionKey,
    /// Current state
    pub state: ConnectionState,
    /// First seen timestamp
    pub first_seen: DateTime<Utc>,
    /// Last seen timestamp
    pub last_seen: DateTime<Utc>,
    /// Total packets in this connection
    pub packet_count: u64,
    /// Total bytes transferred
    pub byte_count: u64,
    /// Original source IP (before normalization)
    pub original_src_ip: IpAddr,
    /// Original destination IP
    pub original_dst_ip: IpAddr,
    /// Source MAC address
    pub src_mac: Option<MacAddress>,
    /// Destination MAC address
    pub dst_mac: Option<MacAddress>,
    /// Number of retransmissions detected (TCP)
    pub retransmissions: u32,
    /// SYN count for SYN flood detection
    pub syn_count: u32,
    /// RST count for connection quality assessment
    pub rst_count: u32,
    /// Packets from the original source
    pub packets_from_src: u64,
    /// Packets to the original source
    pub packets_to_src: u64,
}

impl TrackedConnection {
    /// Create a new tracked connection
    pub fn new(record: &ConnectionRecord) -> Self {
        let key = ConnectionKey::new(
            record.src_ip,
            record.dst_ip,
            record.src_port.unwrap_or(0),
            record.dst_port.unwrap_or(0),
            record.protocol,
        );

        let state = match record.protocol {
            Protocol::Tcp => {
                if let Some(flags) = &record.tcp_flags {
                    if flags.syn && !flags.ack {
                        ConnectionState::Tcp(TcpState::SynReceived)
                    } else {
                        ConnectionState::Tcp(TcpState::Listen)
                    }
                } else {
                    ConnectionState::Tcp(TcpState::Listen)
                }
            }
            Protocol::Udp => ConnectionState::Udp(UdpState::New),
            Protocol::Icmp | Protocol::Icmpv6 => ConnectionState::Icmp,
            _ => ConnectionState::Other,
        };

        let now = Utc::now();
        let mut conn = Self {
            key,
            state,
            first_seen: now,
            last_seen: now,
            packet_count: 1,
            byte_count: record.packet_size as u64,
            original_src_ip: record.src_ip,
            original_dst_ip: record.dst_ip,
            src_mac: record.src_mac,
            dst_mac: None,
            retransmissions: 0,
            syn_count: 0,
            rst_count: 0,
            packets_from_src: 1,
            packets_to_src: 0,
        };

        // Update SYN/RST counts
        if let Some(flags) = &record.tcp_flags {
            if flags.syn {
                conn.syn_count += 1;
            }
            if flags.rst {
                conn.rst_count += 1;
            }
        }

        conn
    }

    /// Update connection with new packet
    pub fn update(&mut self, record: &ConnectionRecord) {
        self.last_seen = Utc::now();
        self.packet_count += 1;
        self.byte_count += record.packet_size as u64;

        // Track direction
        if record.src_ip == self.original_src_ip {
            self.packets_from_src += 1;
        } else {
            self.packets_to_src += 1;
        }

        // Update TCP state
        if let (ConnectionState::Tcp(tcp_state), Some(flags)) = (&self.state, &record.tcp_flags) {
            let is_incoming = record.src_ip != self.original_src_ip;
            let new_state = tcp_state.transition(flags, is_incoming);
            self.state = ConnectionState::Tcp(new_state);

            if flags.syn {
                self.syn_count += 1;
            }
            if flags.rst {
                self.rst_count += 1;
            }
        }

        // Update UDP state
        if let ConnectionState::Udp(udp_state) = &self.state {
            if *udp_state == UdpState::New || *udp_state == UdpState::Stale {
                self.state = ConnectionState::Udp(UdpState::Active);
            }
        }
    }

    /// Get connection duration
    pub fn duration(&self) -> ChronoDuration {
        self.last_seen - self.first_seen
    }

    /// Check if connection appears to be under attack (many SYNs, few established)
    pub fn is_syn_heavy(&self) -> bool {
        self.syn_count > 10
            && matches!(
                self.state,
                ConnectionState::Tcp(TcpState::SynReceived)
                    | ConnectionState::Tcp(TcpState::Listen)
            )
    }

    /// Calculate connection symmetry (balanced = bidirectional traffic)
    pub fn symmetry_ratio(&self) -> f64 {
        if self.packets_from_src == 0 && self.packets_to_src == 0 {
            return 0.0;
        }
        let min = self.packets_from_src.min(self.packets_to_src) as f64;
        let max = self.packets_from_src.max(self.packets_to_src) as f64;
        if max == 0.0 {
            0.0
        } else {
            min / max
        }
    }
}

/// Per-IP connection statistics
#[derive(Debug, Clone)]
pub struct IpConnectionStats {
    /// IP address
    pub ip: IpAddr,
    /// Total connection count
    pub total_connections: u64,
    /// Active connection count
    pub active_connections: u64,
    /// Half-open connections (SYN received but not established)
    pub half_open_connections: u64,
    /// Failed connections (RST received)
    pub failed_connections: u64,
    /// Total SYN packets sent
    pub syn_packets: u64,
    /// Unique destination IPs contacted
    pub unique_destinations: u64,
    /// Unique destination ports contacted
    pub unique_ports: u64,
    /// First seen
    pub first_seen: DateTime<Utc>,
    /// Last seen
    pub last_seen: DateTime<Utc>,
    /// Request timestamps for rate calculation
    timestamps: VecDeque<Instant>,
}

impl IpConnectionStats {
    pub fn new(ip: IpAddr) -> Self {
        let now = Utc::now();
        Self {
            ip,
            total_connections: 0,
            active_connections: 0,
            half_open_connections: 0,
            failed_connections: 0,
            syn_packets: 0,
            unique_destinations: 0,
            unique_ports: 0,
            first_seen: now,
            last_seen: now,
            timestamps: VecDeque::with_capacity(1000),
        }
    }

    /// Record a new request/packet
    pub fn record_request(&mut self) {
        let now = Instant::now();
        self.last_seen = Utc::now();

        // Clean old timestamps (older than 60 seconds)
        while let Some(&front) = self.timestamps.front() {
            if now.duration_since(front) > Duration::from_secs(60) {
                self.timestamps.pop_front();
            } else {
                break;
            }
        }

        // Add new timestamp
        if self.timestamps.len() < 1000 {
            self.timestamps.push_back(now);
        }
    }

    /// Get requests per second (over the last minute)
    pub fn requests_per_second(&self) -> f64 {
        if self.timestamps.is_empty() {
            return 0.0;
        }
        self.timestamps.len() as f64 / 60.0
    }

    /// Get connection rate (connections per second)
    pub fn connection_rate(&self) -> f64 {
        let duration = (self.last_seen - self.first_seen).num_seconds() as f64;
        if duration > 0.0 {
            self.total_connections as f64 / duration
        } else {
            self.total_connections as f64
        }
    }
}

/// Connection tracker for monitoring all connections
pub struct ConnectionTracker {
    /// Active connections by key
    connections: DashMap<ConnectionKey, TrackedConnection>,
    /// Per-IP statistics
    ip_stats: DashMap<IpAddr, IpConnectionStats>,
    /// Global statistics
    stats: ConnectionTrackerStats,
    /// Configuration
    config: ConnectionTrackerConfig,
    /// Destination tracking per source IP
    destinations: DashMap<IpAddr, DashMap<IpAddr, ()>>,
    /// Port tracking per source IP
    ports: DashMap<IpAddr, DashMap<u16, ()>>,
}

/// Configuration for connection tracker
#[derive(Debug, Clone)]
pub struct ConnectionTrackerConfig {
    /// Connection timeout for TCP established connections
    pub tcp_established_timeout: Duration,
    /// Connection timeout for TCP half-open connections
    pub tcp_half_open_timeout: Duration,
    /// Connection timeout for UDP flows
    pub udp_timeout: Duration,
    /// Maximum connections to track
    pub max_connections: usize,
    /// Maximum connections per IP
    pub max_connections_per_ip: usize,
    /// Enable half-open connection tracking
    pub track_half_open: bool,
}

impl Default for ConnectionTrackerConfig {
    fn default() -> Self {
        Self {
            tcp_established_timeout: Duration::from_secs(3600), // 1 hour
            tcp_half_open_timeout: Duration::from_secs(30),     // 30 seconds
            udp_timeout: Duration::from_secs(300),              // 5 minutes
            max_connections: 1_000_000,
            max_connections_per_ip: 10_000,
            track_half_open: true,
        }
    }
}

/// Global statistics for the connection tracker
#[derive(Debug, Default)]
pub struct ConnectionTrackerStats {
    /// Total connections tracked
    pub total_connections: AtomicU64,
    /// Active connections
    pub active_connections: AtomicU64,
    /// Half-open connections
    pub half_open_connections: AtomicU64,
    /// Connections dropped due to limits
    pub dropped_connections: AtomicU64,
    /// Total packets processed
    pub packets_processed: AtomicU64,
    /// Connection evictions due to timeout
    pub evictions: AtomicU64,
}

impl ConnectionTracker {
    /// Create a new connection tracker
    pub fn new() -> Self {
        Self::with_config(ConnectionTrackerConfig::default())
    }

    /// Create with custom configuration
    pub fn with_config(config: ConnectionTrackerConfig) -> Self {
        Self {
            connections: DashMap::new(),
            ip_stats: DashMap::new(),
            stats: ConnectionTrackerStats::default(),
            config,
            destinations: DashMap::new(),
            ports: DashMap::new(),
        }
    }

    /// Update connection state with a new packet
    pub fn update(&self, record: &ConnectionRecord) {
        self.stats.packets_processed.fetch_add(1, Ordering::Relaxed);

        // Create connection key
        let key = ConnectionKey::new(
            record.src_ip,
            record.dst_ip,
            record.src_port.unwrap_or(0),
            record.dst_port.unwrap_or(0),
            record.protocol,
        );

        // Update or create connection
        self.connections
            .entry(key)
            .and_modify(|conn| {
                conn.update(record);
            })
            .or_insert_with(|| {
                self.stats.total_connections.fetch_add(1, Ordering::Relaxed);
                TrackedConnection::new(record)
            });

        // Update per-IP statistics
        self.update_ip_stats(record);

        // Track destinations and ports
        self.track_destinations(record);
    }

    /// Update per-IP statistics
    fn update_ip_stats(&self, record: &ConnectionRecord) {
        self.ip_stats
            .entry(record.src_ip)
            .and_modify(|stats| {
                stats.record_request();
                if let Some(flags) = &record.tcp_flags {
                    if flags.syn && !flags.ack {
                        stats.syn_packets += 1;
                    }
                }
            })
            .or_insert_with(|| {
                let mut stats = IpConnectionStats::new(record.src_ip);
                stats.record_request();
                stats
            });
    }

    /// Track destination IPs and ports per source
    fn track_destinations(&self, record: &ConnectionRecord) {
        // Track destination IPs
        self.destinations
            .entry(record.src_ip)
            .or_default()
            .insert(record.dst_ip, ());

        // Track destination ports
        if let Some(port) = record.dst_port {
            self.ports
                .entry(record.src_ip)
                .or_default()
                .insert(port, ());
        }
    }

    /// Get connection by key
    pub fn get_connection(&self, key: &ConnectionKey) -> Option<TrackedConnection> {
        self.connections.get(key).map(|c| c.clone())
    }

    /// Get all connections for an IP
    pub fn get_connections_for_ip(&self, ip: IpAddr) -> Vec<TrackedConnection> {
        self.connections
            .iter()
            .filter(|entry| entry.key.ip_low == ip || entry.key.ip_high == ip)
            .map(|entry| entry.value().clone())
            .collect()
    }

    /// Get statistics for an IP
    pub fn get_ip_stats(&self, ip: IpAddr) -> Option<IpConnectionStats> {
        self.ip_stats.get(&ip).map(|s| s.clone())
    }

    /// Get number of unique destinations for an IP
    pub fn get_unique_destinations(&self, ip: IpAddr) -> usize {
        self.destinations.get(&ip).map(|d| d.len()).unwrap_or(0)
    }

    /// Get number of unique ports for an IP
    pub fn get_unique_ports(&self, ip: IpAddr) -> usize {
        self.ports.get(&ip).map(|p| p.len()).unwrap_or(0)
    }

    /// Get half-open connections for an IP (potential SYN flood)
    pub fn get_half_open_count(&self, ip: IpAddr) -> usize {
        self.connections
            .iter()
            .filter(|entry| {
                (entry.key.ip_low == ip || entry.key.ip_high == ip)
                    && matches!(
                        entry.state,
                        ConnectionState::Tcp(TcpState::SynReceived)
                            | ConnectionState::Tcp(TcpState::SynSent)
                    )
            })
            .count()
    }

    /// Get total connection count
    pub fn connection_count(&self) -> usize {
        self.connections.len()
    }

    /// Get active connection count
    pub fn active_connection_count(&self) -> usize {
        self.connections
            .iter()
            .filter(|entry| entry.state.is_active())
            .count()
    }

    /// Clean up expired connections
    pub fn cleanup_expired(&self) -> usize {
        let now = Utc::now();
        let mut removed = 0;

        self.connections.retain(|_key, conn| {
            let age = now - conn.last_seen;

            let timeout = match &conn.state {
                ConnectionState::Tcp(tcp_state) => {
                    if tcp_state.is_half_open() {
                        self.config.tcp_half_open_timeout
                    } else if tcp_state.is_closed() {
                        Duration::from_secs(5) // Quick cleanup for closed connections
                    } else {
                        self.config.tcp_established_timeout
                    }
                }
                ConnectionState::Udp(_) => self.config.udp_timeout,
                _ => self.config.udp_timeout,
            };

            let keep = age < ChronoDuration::from_std(timeout).unwrap_or(ChronoDuration::hours(1));

            if !keep {
                removed += 1;
            }
            keep
        });

        self.stats
            .evictions
            .fetch_add(removed as u64, Ordering::Relaxed);
        removed
    }

    /// Get global statistics snapshot
    pub fn get_stats(&self) -> ConnectionTrackerStatsSnapshot {
        ConnectionTrackerStatsSnapshot {
            total_connections: self.stats.total_connections.load(Ordering::Relaxed),
            active_connections: self.active_connection_count() as u64,
            half_open_connections: self
                .connections
                .iter()
                .filter(|e| matches!(e.state, ConnectionState::Tcp(s) if s.is_half_open()))
                .count() as u64,
            dropped_connections: self.stats.dropped_connections.load(Ordering::Relaxed),
            packets_processed: self.stats.packets_processed.load(Ordering::Relaxed),
            evictions: self.stats.evictions.load(Ordering::Relaxed),
            unique_ips: self.ip_stats.len() as u64,
        }
    }

    /// Get top IPs by connection count
    pub fn get_top_ips(&self, limit: usize) -> Vec<(IpAddr, u64)> {
        let mut ip_counts: HashMap<IpAddr, u64> = HashMap::new();

        for entry in self.connections.iter() {
            *ip_counts.entry(entry.original_src_ip).or_insert(0) += 1;
        }

        let mut sorted: Vec<_> = ip_counts.into_iter().collect();
        sorted.sort_by(|a, b| b.1.cmp(&a.1));
        sorted.truncate(limit);
        sorted
    }

    /// Check if an IP has suspicious connection patterns
    pub fn is_suspicious(&self, ip: IpAddr) -> bool {
        let half_open = self.get_half_open_count(ip);
        let unique_ports = self.get_unique_ports(ip);
        let unique_dests = self.get_unique_destinations(ip);

        // Heuristics for suspicious behavior
        half_open > 100 || unique_ports > 1000 || unique_dests > 500
    }
}

impl Default for ConnectionTracker {
    fn default() -> Self {
        Self::new()
    }
}

/// Snapshot of connection tracker statistics
#[derive(Debug, Clone)]
pub struct ConnectionTrackerStatsSnapshot {
    pub total_connections: u64,
    pub active_connections: u64,
    pub half_open_connections: u64,
    pub dropped_connections: u64,
    pub packets_processed: u64,
    pub evictions: u64,
    pub unique_ips: u64,
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    fn create_test_record(
        src_ip: Ipv4Addr,
        dst_ip: Ipv4Addr,
        src_port: u16,
        dst_port: u16,
        flags: Option<TcpFlags>,
    ) -> ConnectionRecord {
        ConnectionRecord {
            id: 1,
            timestamp: Utc::now(),
            src_ip: IpAddr::V4(src_ip),
            dst_ip: IpAddr::V4(dst_ip),
            src_port: Some(src_port),
            dst_port: Some(dst_port),
            src_mac: None,
            protocol: Protocol::Tcp,
            tcp_flags: flags,
            packet_size: 64,
            payload_size: 0,
        }
    }

    #[test]
    fn test_tcp_state_transitions() {
        // SYN
        let syn_flags = TcpFlags::from_byte(0x02);
        let state = TcpState::Listen.transition(&syn_flags, true);
        assert_eq!(state, TcpState::SynReceived);

        // ACK
        let ack_flags = TcpFlags::from_byte(0x10);
        let state = TcpState::SynReceived.transition(&ack_flags, true);
        assert_eq!(state, TcpState::Established);

        // FIN
        let fin_flags = TcpFlags::from_byte(0x01);
        let state = TcpState::Established.transition(&fin_flags, true);
        assert_eq!(state, TcpState::CloseWait);
    }

    #[test]
    fn test_connection_key_normalization() {
        let key1 = ConnectionKey::new(
            IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1)),
            IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
            12345,
            80,
            Protocol::Tcp,
        );

        let key2 = ConnectionKey::new(
            IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
            IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1)),
            80,
            12345,
            Protocol::Tcp,
        );

        assert_eq!(key1, key2);
    }

    #[test]
    fn test_connection_tracker() {
        let tracker = ConnectionTracker::new();

        // Create a SYN packet
        let syn_flags = TcpFlags::from_byte(0x02);
        let record = create_test_record(
            Ipv4Addr::new(192, 168, 1, 1),
            Ipv4Addr::new(10, 0, 0, 1),
            12345,
            80,
            Some(syn_flags),
        );

        tracker.update(&record);
        assert_eq!(tracker.connection_count(), 1);

        // Create a SYN-ACK response
        let syn_ack_flags = TcpFlags::from_byte(0x12);
        let response = create_test_record(
            Ipv4Addr::new(10, 0, 0, 1),
            Ipv4Addr::new(192, 168, 1, 1),
            80,
            12345,
            Some(syn_ack_flags),
        );

        tracker.update(&response);
        assert_eq!(tracker.connection_count(), 1); // Same connection

        // Check stats
        let stats = tracker.get_stats();
        assert_eq!(stats.packets_processed, 2);
    }

    #[test]
    fn test_ip_connection_stats() {
        use std::net::Ipv4Addr;

        let mut stats = IpConnectionStats::new(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1)));

        // Record some requests
        stats.record_request();
        stats.record_request();
        stats.record_request();

        assert!(stats.requests_per_second() >= 0.0);
    }

    #[test]
    fn test_tracked_connection_symmetry() {
        use std::net::Ipv4Addr;

        let record = create_test_record(
            Ipv4Addr::new(192, 168, 1, 1),
            Ipv4Addr::new(10, 0, 0, 1),
            12345,
            80,
            None,
        );

        let mut conn = TrackedConnection::new(&record);

        // Initially asymmetric (only packets from source)
        assert_eq!(conn.packets_from_src, 1);
        assert_eq!(conn.packets_to_src, 0);

        // Symmetry should be 0 when unidirectional
        assert_eq!(conn.symmetry_ratio(), 0.0);
    }

    #[test]
    fn test_connection_state_is_active() {
        let tcp_established = ConnectionState::Tcp(TcpState::Established);
        assert!(tcp_established.is_active());

        let tcp_closed = ConnectionState::Tcp(TcpState::Closed);
        assert!(!tcp_closed.is_active());

        let udp_active = ConnectionState::Udp(UdpState::Active);
        assert!(udp_active.is_active());

        let udp_closed = ConnectionState::Udp(UdpState::Closed);
        assert!(!udp_closed.is_active());
    }

    #[test]
    fn test_cleanup_expired() {
        let config = ConnectionTrackerConfig {
            tcp_established_timeout: std::time::Duration::from_millis(1),
            tcp_half_open_timeout: std::time::Duration::from_millis(1),
            udp_timeout: std::time::Duration::from_millis(1),
            ..Default::default()
        };

        let tracker = ConnectionTracker::with_config(config);

        let record = create_test_record(
            Ipv4Addr::new(192, 168, 1, 1),
            Ipv4Addr::new(10, 0, 0, 1),
            12345,
            80,
            None,
        );

        tracker.update(&record);
        assert_eq!(tracker.connection_count(), 1);

        // Wait for timeout
        std::thread::sleep(std::time::Duration::from_millis(10));

        // Cleanup should remove the expired connection
        let removed = tracker.cleanup_expired();
        assert_eq!(removed, 1);
        assert_eq!(tracker.connection_count(), 0);
    }
}
