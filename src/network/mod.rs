//! Network module for packet capture, connection tracking, and network analysis
//!
//! This module provides the core networking functionality for the Zeroed daemon,
//! including:
//! - Raw packet capture using libpcap
//! - Connection tracking and state management
//! - IP and MAC address monitoring
//! - Protocol analysis (TCP, UDP, ICMP)
//! - Network interface management

pub mod capture;
pub mod connection;
pub mod interface;
pub mod packet;
pub mod parser;

use crate::core::{ConnectionRecord, MacAddress, Protocol, Result, TrackingId};
use dashmap::DashMap;
use std::net::IpAddr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use tokio::sync::broadcast;

// Re-export commonly used types
pub use capture::CaptureEngine;
pub use connection::ConnectionTracker;
pub use parser::ParsedPacket;

/// Network event types for broadcasting to other components
#[derive(Debug, Clone)]
pub enum NetworkEvent {
    /// New packet captured
    PacketCaptured(Arc<ParsedPacket>),
    /// New connection detected
    NewConnection {
        src_ip: IpAddr,
        dst_ip: IpAddr,
        src_port: u16,
        dst_port: u16,
        protocol: Protocol,
    },
    /// Connection closed
    ConnectionClosed {
        src_ip: IpAddr,
        dst_ip: IpAddr,
        src_port: u16,
        dst_port: u16,
    },
    /// SYN flood indicator detected
    SynFloodDetected { src_ip: IpAddr, rate: f64 },
    /// Interface state changed
    InterfaceStateChanged { name: String, is_up: bool },
    /// Capture error occurred
    CaptureError { message: String },
}

/// Network manager coordinating all network operations
pub struct NetworkManager {
    /// Active packet captures by interface name
    captures: DashMap<String, Arc<CaptureEngine>>,
    /// Connection tracker
    connection_tracker: Arc<ConnectionTracker>,
    /// Event broadcaster
    event_tx: broadcast::Sender<NetworkEvent>,
    /// Packet counter for generating unique IDs
    packet_counter: AtomicU64,
    /// Running status
    is_running: std::sync::atomic::AtomicBool,
}

impl NetworkManager {
    /// Create a new network manager
    pub fn new(channel_capacity: usize) -> Self {
        let (event_tx, _) = broadcast::channel(channel_capacity);

        Self {
            captures: DashMap::new(),
            connection_tracker: Arc::new(ConnectionTracker::new()),
            event_tx,
            packet_counter: AtomicU64::new(0),
            is_running: std::sync::atomic::AtomicBool::new(false),
        }
    }

    /// Subscribe to network events
    pub fn subscribe(&self) -> broadcast::Receiver<NetworkEvent> {
        self.event_tx.subscribe()
    }

    /// Get the event sender for external use
    pub fn event_sender(&self) -> broadcast::Sender<NetworkEvent> {
        self.event_tx.clone()
    }

    /// Get reference to connection tracker
    pub fn connection_tracker(&self) -> Arc<ConnectionTracker> {
        Arc::clone(&self.connection_tracker)
    }

    /// Start capturing on a specific interface
    pub async fn start_capture(
        &self,
        interface: &str,
        config: crate::core::config::NetworkConfig,
    ) -> Result<()> {
        if self.captures.contains_key(interface) {
            return Ok(());
        }

        let capture = CaptureEngine::new(config);
        self.captures
            .insert(interface.to_string(), Arc::new(capture));
        self.is_running
            .store(true, std::sync::atomic::Ordering::SeqCst);

        Ok(())
    }

    /// Stop capturing on a specific interface
    pub async fn stop_capture(&self, interface: &str) -> Result<()> {
        if let Some((_, capture)) = self.captures.remove(interface) {
            capture.stop();
        }
        Ok(())
    }

    /// Stop all captures
    pub async fn stop_all(&self) {
        self.is_running
            .store(false, std::sync::atomic::Ordering::SeqCst);
        self.captures.clear();
    }

    /// Generate a unique tracking ID
    pub fn next_tracking_id(&self) -> TrackingId {
        self.packet_counter.fetch_add(1, Ordering::SeqCst)
    }

    /// Process a captured packet
    pub fn process_packet(&self, packet: ParsedPacket) -> Result<ConnectionRecord> {
        let _id = self.next_tracking_id();

        // Use the connection record from the parsed packet
        let record = packet.record.clone();

        // Update connection tracker
        self.connection_tracker.update(&record);

        // Broadcast event
        let _ = self
            .event_tx
            .send(NetworkEvent::PacketCaptured(Arc::new(packet)));

        Ok(record)
    }

    /// Get statistics for all interfaces
    pub fn get_interface_stats(&self) -> Vec<InterfaceStats> {
        self.captures
            .iter()
            .map(|entry| {
                let stats = entry.value().stats();
                let snapshot = stats.snapshot();
                InterfaceStats {
                    name: entry.key().clone(),
                    packets_captured: snapshot.packets_captured,
                    bytes_captured: snapshot.bytes_captured,
                    packets_dropped: snapshot.packets_dropped,
                }
            })
            .collect()
    }

    /// Check if manager is running
    pub fn is_running(&self) -> bool {
        self.is_running.load(std::sync::atomic::Ordering::SeqCst)
    }

    /// Get list of monitored interfaces
    pub fn monitored_interfaces(&self) -> Vec<String> {
        self.captures.iter().map(|e| e.key().clone()).collect()
    }
}

impl Default for NetworkManager {
    fn default() -> Self {
        Self::new(10_000)
    }
}

/// Statistics for a network interface
#[derive(Debug, Clone)]
pub struct InterfaceStats {
    pub name: String,
    pub packets_captured: u64,
    pub bytes_captured: u64,
    pub packets_dropped: u64,
}

/// Five-tuple connection identifier
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct FiveTuple {
    pub src_ip: IpAddr,
    pub dst_ip: IpAddr,
    pub src_port: u16,
    pub dst_port: u16,
    pub protocol: Protocol,
}

impl FiveTuple {
    pub fn new(
        src_ip: IpAddr,
        dst_ip: IpAddr,
        src_port: u16,
        dst_port: u16,
        protocol: Protocol,
    ) -> Self {
        Self {
            src_ip,
            dst_ip,
            src_port,
            dst_port,
            protocol,
        }
    }

    /// Create the reverse tuple (for bidirectional tracking)
    pub fn reverse(&self) -> Self {
        Self {
            src_ip: self.dst_ip,
            dst_ip: self.src_ip,
            src_port: self.dst_port,
            dst_port: self.src_port,
            protocol: self.protocol,
        }
    }

    /// Normalize tuple for consistent hashing (lower IP first)
    pub fn normalize(&self) -> Self {
        if self.src_ip < self.dst_ip
            || (self.src_ip == self.dst_ip && self.src_port <= self.dst_port)
        {
            *self
        } else {
            self.reverse()
        }
    }
}

/// Utility functions for network operations
pub mod utils {
    use super::*;
    use std::net::{Ipv4Addr, Ipv6Addr};

    /// Check if an IP address is private/internal
    pub fn is_private_ip(ip: &IpAddr) -> bool {
        match ip {
            IpAddr::V4(ipv4) => {
                ipv4.is_private() || ipv4.is_loopback() || ipv4.is_link_local() || is_cgnat(ipv4)
            }
            IpAddr::V6(ipv6) => ipv6.is_loopback() || is_ula(ipv6) || is_link_local_v6(ipv6),
        }
    }

    /// Check if IPv4 is in CGNAT range (100.64.0.0/10)
    fn is_cgnat(ip: &Ipv4Addr) -> bool {
        let octets = ip.octets();
        octets[0] == 100 && (octets[1] & 0xC0) == 64
    }

    /// Check if IPv6 is Unique Local Address (ULA)
    fn is_ula(ip: &Ipv6Addr) -> bool {
        let segments = ip.segments();
        (segments[0] & 0xFE00) == 0xFC00
    }

    /// Check if IPv6 is link-local
    fn is_link_local_v6(ip: &Ipv6Addr) -> bool {
        let segments = ip.segments();
        (segments[0] & 0xFFC0) == 0xFE80
    }

    /// Check if an IP is a broadcast address
    pub fn is_broadcast(ip: &IpAddr) -> bool {
        match ip {
            IpAddr::V4(ipv4) => ipv4.is_broadcast(),
            IpAddr::V6(_) => false, // IPv6 doesn't have broadcast
        }
    }

    /// Check if an IP is multicast
    pub fn is_multicast(ip: &IpAddr) -> bool {
        match ip {
            IpAddr::V4(ipv4) => ipv4.is_multicast(),
            IpAddr::V6(ipv6) => ipv6.is_multicast(),
        }
    }

    /// Extract MAC vendor prefix (OUI)
    pub fn get_mac_oui(mac: &MacAddress) -> [u8; 3] {
        [mac.0[0], mac.0[1], mac.0[2]]
    }

    /// Check if MAC is a virtual/hypervisor MAC
    pub fn is_virtual_mac(mac: &MacAddress) -> bool {
        let oui = get_mac_oui(mac);
        matches!(
            oui,
            [0x00, 0x0C, 0x29]  // VMware
            | [0x00, 0x50, 0x56] // VMware
            | [0x00, 0x1C, 0x42] // Parallels
            | [0x00, 0x16, 0x3E] // Xen
            | [0x08, 0x00, 0x27] // VirtualBox
            | [0x52, 0x54, 0x00] // QEMU/KVM
            | [0x00, 0x15, 0x5D] // Hyper-V
        )
    }

    /// Calculate the entropy of a byte slice (useful for detecting encrypted/compressed data)
    pub fn calculate_entropy(data: &[u8]) -> f64 {
        if data.is_empty() {
            return 0.0;
        }

        let mut freq = [0u64; 256];
        for &byte in data {
            freq[byte as usize] += 1;
        }

        let len = data.len() as f64;
        freq.iter()
            .filter(|&&count| count > 0)
            .map(|&count| {
                let p = count as f64 / len;
                -p * p.log2()
            })
            .sum()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{IpAddr, Ipv4Addr};

    #[test]
    fn test_five_tuple_normalize() {
        let tuple1 = FiveTuple::new(
            IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1)),
            IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
            12345,
            80,
            Protocol::Tcp,
        );

        let tuple2 = FiveTuple::new(
            IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
            IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1)),
            80,
            12345,
            Protocol::Tcp,
        );

        assert_eq!(tuple1.normalize(), tuple2.normalize());
    }

    #[test]
    fn test_is_private_ip() {
        assert!(utils::is_private_ip(&IpAddr::V4(Ipv4Addr::new(
            192, 168, 1, 1
        ))));
        assert!(utils::is_private_ip(&IpAddr::V4(Ipv4Addr::new(
            10, 0, 0, 1
        ))));
        assert!(utils::is_private_ip(&IpAddr::V4(Ipv4Addr::new(
            127, 0, 0, 1
        ))));
        assert!(!utils::is_private_ip(&IpAddr::V4(Ipv4Addr::new(
            8, 8, 8, 8
        ))));
    }

    #[test]
    fn test_entropy_calculation() {
        // Uniform distribution has max entropy
        let uniform: Vec<u8> = (0..=255).collect();
        let entropy = utils::calculate_entropy(&uniform);
        assert!(entropy > 7.9 && entropy <= 8.0);

        // Constant data has zero entropy
        let constant = vec![0u8; 256];
        let entropy = utils::calculate_entropy(&constant);
        assert!(entropy < 0.01);
    }

    #[test]
    fn test_virtual_mac_detection() {
        // VMware MAC
        let vmware_mac = MacAddress::new([0x00, 0x0C, 0x29, 0x12, 0x34, 0x56]);
        assert!(utils::is_virtual_mac(&vmware_mac));

        // Regular MAC
        let regular_mac = MacAddress::new([0xDE, 0xAD, 0xBE, 0xEF, 0x12, 0x34]);
        assert!(!utils::is_virtual_mac(&regular_mac));
    }
}
