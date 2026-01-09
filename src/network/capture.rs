//! Packet capture engine using libpcap
//!
//! This module provides the core packet capture functionality for the Zeroed daemon,
//! using libpcap to capture network traffic from specified interfaces.

use crate::core::{
    config::NetworkConfig,
    error::{NetworkError, Result, ZeroedError},
    types::{ConnectionRecord, MacAddress, Protocol, TcpFlags, TrackingId},
};

use chrono::Utc;
use pcap::{Active, Capture, Device, Linktype, Packet};
use pnet::packet::{
    ethernet::{EtherTypes, EthernetPacket},
    ipv4::Ipv4Packet,
    ipv6::Ipv6Packet,
    tcp::TcpPacket,
    udp::UdpPacket,
    Packet as PnetPacket,
};
use std::net::IpAddr;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use tokio::sync::mpsc;
use tracing::{error, info, trace, warn};

/// Statistics for the capture engine
#[derive(Debug, Default)]
pub struct CaptureStats {
    /// Total packets captured
    pub packets_captured: AtomicU64,
    /// Total packets dropped by kernel
    pub packets_dropped: AtomicU64,
    /// Total bytes captured
    pub bytes_captured: AtomicU64,
    /// Parse errors encountered
    pub parse_errors: AtomicU64,
    /// IPv4 packets
    pub ipv4_packets: AtomicU64,
    /// IPv6 packets
    pub ipv6_packets: AtomicU64,
    /// TCP packets
    pub tcp_packets: AtomicU64,
    /// UDP packets
    pub udp_packets: AtomicU64,
    /// ICMP packets
    pub icmp_packets: AtomicU64,
}

impl CaptureStats {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn increment_captured(&self) {
        self.packets_captured.fetch_add(1, Ordering::Relaxed);
    }

    pub fn add_bytes(&self, bytes: u64) {
        self.bytes_captured.fetch_add(bytes, Ordering::Relaxed);
    }

    pub fn increment_dropped(&self) {
        self.packets_dropped.fetch_add(1, Ordering::Relaxed);
    }

    pub fn increment_parse_errors(&self) {
        self.parse_errors.fetch_add(1, Ordering::Relaxed);
    }

    pub fn increment_protocol(&self, protocol: Protocol) {
        match protocol {
            Protocol::Tcp => self.tcp_packets.fetch_add(1, Ordering::Relaxed),
            Protocol::Udp => self.udp_packets.fetch_add(1, Ordering::Relaxed),
            Protocol::Icmp | Protocol::Icmpv6 => self.icmp_packets.fetch_add(1, Ordering::Relaxed),
            _ => 0,
        };
    }

    pub fn increment_ip_version(&self, is_ipv6: bool) {
        if is_ipv6 {
            self.ipv6_packets.fetch_add(1, Ordering::Relaxed);
        } else {
            self.ipv4_packets.fetch_add(1, Ordering::Relaxed);
        }
    }

    /// Get a snapshot of current statistics
    pub fn snapshot(&self) -> CaptureStatsSnapshot {
        CaptureStatsSnapshot {
            packets_captured: self.packets_captured.load(Ordering::Relaxed),
            packets_dropped: self.packets_dropped.load(Ordering::Relaxed),
            bytes_captured: self.bytes_captured.load(Ordering::Relaxed),
            parse_errors: self.parse_errors.load(Ordering::Relaxed),
            ipv4_packets: self.ipv4_packets.load(Ordering::Relaxed),
            ipv6_packets: self.ipv6_packets.load(Ordering::Relaxed),
            tcp_packets: self.tcp_packets.load(Ordering::Relaxed),
            udp_packets: self.udp_packets.load(Ordering::Relaxed),
            icmp_packets: self.icmp_packets.load(Ordering::Relaxed),
        }
    }
}

/// Snapshot of capture statistics (non-atomic for easy use)
#[derive(Debug, Clone, Default)]
pub struct CaptureStatsSnapshot {
    pub packets_captured: u64,
    pub packets_dropped: u64,
    pub bytes_captured: u64,
    pub parse_errors: u64,
    pub ipv4_packets: u64,
    pub ipv6_packets: u64,
    pub tcp_packets: u64,
    pub udp_packets: u64,
    pub icmp_packets: u64,
}

/// Parsed packet information
#[derive(Debug, Clone)]
pub struct ParsedPacket {
    /// Source MAC address
    pub src_mac: MacAddress,
    /// Destination MAC address
    pub dst_mac: MacAddress,
    /// Source IP address
    pub src_ip: IpAddr,
    /// Destination IP address
    pub dst_ip: IpAddr,
    /// Source port (TCP/UDP)
    pub src_port: Option<u16>,
    /// Destination port (TCP/UDP)
    pub dst_port: Option<u16>,
    /// Protocol
    pub protocol: Protocol,
    /// TCP flags (if applicable)
    pub tcp_flags: Option<TcpFlags>,
    /// Total packet length
    pub packet_len: u32,
    /// Payload length
    pub payload_len: u32,
    /// TTL/Hop limit
    pub ttl: u8,
    /// IP fragment indicator
    pub is_fragment: bool,
    /// Raw packet data (optional, for deep inspection)
    pub raw_data: Option<Vec<u8>>,
}

impl ParsedPacket {
    /// Convert to a connection record
    pub fn to_connection_record(&self, id: TrackingId) -> ConnectionRecord {
        ConnectionRecord {
            id,
            timestamp: Utc::now(),
            src_ip: self.src_ip,
            dst_ip: self.dst_ip,
            src_port: self.src_port,
            dst_port: self.dst_port,
            src_mac: Some(self.src_mac),
            protocol: self.protocol,
            tcp_flags: self.tcp_flags,
            packet_size: self.packet_len,
            payload_size: self.payload_len,
        }
    }

    /// Check if this is a SYN packet (potential SYN flood)
    pub fn is_syn_packet(&self) -> bool {
        matches!(self.tcp_flags, Some(flags) if flags.is_syn_only())
    }

    /// Check if this is a SYN-ACK packet
    pub fn is_syn_ack_packet(&self) -> bool {
        matches!(self.tcp_flags, Some(flags) if flags.syn && flags.ack)
    }
}

/// Packet capture engine
pub struct CaptureEngine {
    /// Network configuration
    config: NetworkConfig,
    /// Running flag
    running: Arc<AtomicBool>,
    /// Capture statistics
    stats: Arc<CaptureStats>,
    /// Next tracking ID
    next_id: AtomicU64,
}

impl CaptureEngine {
    /// Create a new capture engine with the given configuration
    pub fn new(config: NetworkConfig) -> Self {
        Self {
            config,
            running: Arc::new(AtomicBool::new(false)),
            stats: Arc::new(CaptureStats::new()),
            next_id: AtomicU64::new(1),
        }
    }

    /// Get available network interfaces
    pub fn list_interfaces() -> Result<Vec<InterfaceInfo>> {
        let devices = Device::list().map_err(|e| {
            ZeroedError::Network(NetworkError::InterfaceOpenError {
                interface: "all".to_string(),
                message: e.to_string(),
            })
        })?;

        Ok(devices
            .into_iter()
            .map(|d| InterfaceInfo {
                name: d.name.clone(),
                description: d.desc.unwrap_or_default(),
                addresses: d.addresses.iter().map(|a| a.addr.to_string()).collect(),
                is_loopback: d.name.starts_with("lo"),
                is_up: true, // pcap doesn't provide this directly
            })
            .collect())
    }

    /// Get the default interface
    pub fn default_interface() -> Result<String> {
        Device::lookup()
            .map_err(|_| {
                ZeroedError::Network(NetworkError::InterfaceNotFound {
                    interface: "default".to_string(),
                })
            })?
            .map(|d| d.name)
            .ok_or_else(|| {
                ZeroedError::Network(NetworkError::InterfaceNotFound {
                    interface: "default".to_string(),
                })
            })
    }

    /// Get capture statistics
    pub fn stats(&self) -> Arc<CaptureStats> {
        Arc::clone(&self.stats)
    }

    /// Check if the engine is running
    pub fn is_running(&self) -> bool {
        self.running.load(Ordering::Relaxed)
    }

    /// Stop the capture engine
    pub fn stop(&self) {
        self.running.store(false, Ordering::SeqCst);
        info!("Capture engine stop requested");
    }

    /// Generate next tracking ID
    fn next_tracking_id(&self) -> TrackingId {
        self.next_id.fetch_add(1, Ordering::Relaxed)
    }

    /// Open a capture handle for the specified interface
    fn open_capture(&self, interface: &str) -> Result<Capture<Active>> {
        let mut cap = Capture::from_device(interface)
            .map_err(|e| {
                ZeroedError::Network(NetworkError::InterfaceOpenError {
                    interface: interface.to_string(),
                    message: e.to_string(),
                })
            })?
            .promisc(self.config.promiscuous)
            .snaplen(self.config.snap_len)
            .timeout(self.config.capture_timeout_ms)
            .buffer_size(self.config.capture_buffer_mb as i32 * 1024 * 1024)
            .open()
            .map_err(|e| {
                ZeroedError::Network(NetworkError::InterfaceOpenError {
                    interface: interface.to_string(),
                    message: e.to_string(),
                })
            })?;

        // Apply BPF filter if configured
        if let Some(ref filter) = self.config.bpf_filter {
            cap.filter(filter, true).map_err(|e| {
                ZeroedError::Network(NetworkError::BpfFilterError {
                    message: e.to_string(),
                })
            })?;
            info!("Applied BPF filter: {}", filter);
        }

        Ok(cap)
    }

    /// Start capturing packets and send them to the provided channel
    pub async fn start(&self, tx: mpsc::Sender<ParsedPacket>) -> Result<()> {
        self.running.store(true, Ordering::SeqCst);

        // Determine which interfaces to capture from
        let interfaces = if self.config.interfaces.is_empty() {
            vec![Self::default_interface()?]
        } else {
            self.config.interfaces.clone()
        };

        info!("Starting capture on interfaces: {:?}", interfaces);

        // For simplicity, we'll capture on the first interface
        // In production, you'd spawn multiple tasks for each interface
        let interface = &interfaces[0];
        let mut cap = self.open_capture(interface)?;

        // Check link type
        let linktype = cap.get_datalink();
        if linktype != Linktype::ETHERNET {
            warn!(
                "Non-Ethernet link type detected: {:?}. Some features may not work.",
                linktype
            );
        }

        info!("Capture started on interface: {}", interface);

        // Main capture loop
        while self.running.load(Ordering::Relaxed) {
            match cap.next_packet() {
                Ok(packet) => {
                    self.stats.increment_captured();
                    self.stats.add_bytes(packet.data.len() as u64);

                    match self.parse_packet(&packet) {
                        Ok(parsed) => {
                            self.stats.increment_protocol(parsed.protocol);
                            self.stats
                                .increment_ip_version(matches!(parsed.src_ip, IpAddr::V6(_)));

                            trace!(
                                "Captured: {} -> {} ({:?})",
                                parsed.src_ip,
                                parsed.dst_ip,
                                parsed.protocol
                            );

                            // Send to processing channel
                            if tx.send(parsed).await.is_err() {
                                warn!("Packet channel closed, stopping capture");
                                break;
                            }
                        }
                        Err(e) => {
                            self.stats.increment_parse_errors();
                            trace!("Packet parse error: {}", e);
                        }
                    }
                }
                Err(pcap::Error::TimeoutExpired) => {
                    // Normal timeout, continue
                    continue;
                }
                Err(e) => {
                    error!("Capture error: {}", e);
                    self.stats.increment_dropped();
                }
            }

            // Yield to allow other tasks to run
            tokio::task::yield_now().await;
        }

        self.running.store(false, Ordering::SeqCst);
        info!("Capture stopped");

        Ok(())
    }

    /// Parse a raw packet into structured data
    fn parse_packet(&self, packet: &Packet) -> Result<ParsedPacket> {
        let data = packet.data;

        // Parse Ethernet frame
        let ethernet = EthernetPacket::new(data).ok_or_else(|| {
            ZeroedError::Network(NetworkError::PacketParseError {
                message: "Failed to parse Ethernet frame".to_string(),
            })
        })?;

        let src_mac =
            MacAddress::from_slice(&ethernet.get_source().octets()).unwrap_or(MacAddress::ZERO);
        let dst_mac = MacAddress::from_slice(&ethernet.get_destination().octets())
            .unwrap_or(MacAddress::ZERO);

        // Parse IP layer based on EtherType
        match ethernet.get_ethertype() {
            EtherTypes::Ipv4 => self.parse_ipv4_packet(ethernet.payload(), src_mac, dst_mac),
            EtherTypes::Ipv6 => self.parse_ipv6_packet(ethernet.payload(), src_mac, dst_mac),
            _ => Err(ZeroedError::Network(NetworkError::PacketParseError {
                message: format!("Unsupported EtherType: {:?}", ethernet.get_ethertype()),
            })),
        }
    }

    /// Parse IPv4 packet
    fn parse_ipv4_packet(
        &self,
        data: &[u8],
        src_mac: MacAddress,
        dst_mac: MacAddress,
    ) -> Result<ParsedPacket> {
        let ipv4 = Ipv4Packet::new(data).ok_or_else(|| {
            ZeroedError::Network(NetworkError::PacketParseError {
                message: "Failed to parse IPv4 packet".to_string(),
            })
        })?;

        let src_ip = IpAddr::V4(ipv4.get_source());
        let dst_ip = IpAddr::V4(ipv4.get_destination());
        let protocol = Protocol::from(ipv4.get_next_level_protocol().0);
        let ttl = ipv4.get_ttl();
        let is_fragment = ipv4.get_fragment_offset() > 0 || ipv4.get_flags() & 0x1 != 0;
        let total_len = ipv4.get_total_length() as u32;

        // Parse transport layer
        let (src_port, dst_port, tcp_flags, payload_len) =
            self.parse_transport_layer(protocol, ipv4.payload())?;

        Ok(ParsedPacket {
            src_mac,
            dst_mac,
            src_ip,
            dst_ip,
            src_port,
            dst_port,
            protocol,
            tcp_flags,
            packet_len: total_len,
            payload_len,
            ttl,
            is_fragment,
            raw_data: None,
        })
    }

    /// Parse IPv6 packet
    fn parse_ipv6_packet(
        &self,
        data: &[u8],
        src_mac: MacAddress,
        dst_mac: MacAddress,
    ) -> Result<ParsedPacket> {
        let ipv6 = Ipv6Packet::new(data).ok_or_else(|| {
            ZeroedError::Network(NetworkError::PacketParseError {
                message: "Failed to parse IPv6 packet".to_string(),
            })
        })?;

        let src_ip = IpAddr::V6(ipv6.get_source());
        let dst_ip = IpAddr::V6(ipv6.get_destination());
        let protocol = Protocol::from(ipv6.get_next_header().0);
        let ttl = ipv6.get_hop_limit();
        let total_len = ipv6.get_payload_length() as u32 + 40; // IPv6 header is 40 bytes

        // Parse transport layer
        let (src_port, dst_port, tcp_flags, payload_len) =
            self.parse_transport_layer(protocol, ipv6.payload())?;

        Ok(ParsedPacket {
            src_mac,
            dst_mac,
            src_ip,
            dst_ip,
            src_port,
            dst_port,
            protocol,
            tcp_flags,
            packet_len: total_len,
            payload_len,
            ttl,
            is_fragment: false, // Simplified, would need extension header parsing
            raw_data: None,
        })
    }

    /// Parse transport layer (TCP/UDP/ICMP)
    fn parse_transport_layer(
        &self,
        protocol: Protocol,
        data: &[u8],
    ) -> Result<(Option<u16>, Option<u16>, Option<TcpFlags>, u32)> {
        match protocol {
            Protocol::Tcp => {
                let tcp = TcpPacket::new(data).ok_or_else(|| {
                    ZeroedError::Network(NetworkError::PacketParseError {
                        message: "Failed to parse TCP packet".to_string(),
                    })
                })?;

                let flags = TcpFlags::from_byte(tcp.get_flags());
                let payload_len = tcp.payload().len() as u32;

                Ok((
                    Some(tcp.get_source()),
                    Some(tcp.get_destination()),
                    Some(flags),
                    payload_len,
                ))
            }
            Protocol::Udp => {
                let udp = UdpPacket::new(data).ok_or_else(|| {
                    ZeroedError::Network(NetworkError::PacketParseError {
                        message: "Failed to parse UDP packet".to_string(),
                    })
                })?;

                let payload_len = udp.payload().len() as u32;

                Ok((
                    Some(udp.get_source()),
                    Some(udp.get_destination()),
                    None,
                    payload_len,
                ))
            }
            Protocol::Icmp | Protocol::Icmpv6 => {
                // ICMP doesn't have ports, but we can extract type/code
                let payload_len = data.len().saturating_sub(8) as u32;
                Ok((None, None, None, payload_len))
            }
            _ => Ok((None, None, None, data.len() as u32)),
        }
    }
}

/// Information about a network interface
#[derive(Debug, Clone)]
pub struct InterfaceInfo {
    pub name: String,
    pub description: String,
    pub addresses: Vec<String>,
    pub is_loopback: bool,
    pub is_up: bool,
}

/// Builder for creating capture configurations
pub struct CaptureBuilder {
    config: NetworkConfig,
}

impl CaptureBuilder {
    pub fn new() -> Self {
        Self {
            config: NetworkConfig::default(),
        }
    }

    pub fn interface(mut self, interface: impl Into<String>) -> Self {
        self.config.interfaces = vec![interface.into()];
        self
    }

    pub fn interfaces(mut self, interfaces: Vec<String>) -> Self {
        self.config.interfaces = interfaces;
        self
    }

    pub fn promiscuous(mut self, enabled: bool) -> Self {
        self.config.promiscuous = enabled;
        self
    }

    pub fn buffer_size_mb(mut self, size: usize) -> Self {
        self.config.capture_buffer_mb = size;
        self
    }

    pub fn bpf_filter(mut self, filter: impl Into<String>) -> Self {
        self.config.bpf_filter = Some(filter.into());
        self
    }

    pub fn snap_len(mut self, len: i32) -> Self {
        self.config.snap_len = len;
        self
    }

    pub fn timeout_ms(mut self, ms: i32) -> Self {
        self.config.capture_timeout_ms = ms;
        self
    }

    pub fn build(self) -> CaptureEngine {
        CaptureEngine::new(self.config)
    }
}

impl Default for CaptureBuilder {
    fn default() -> Self {
        Self::new()
    }
}

/// Generate a BPF filter for common DoS protection scenarios
pub fn generate_bpf_filter(ports: &[u16], protocols: &[Protocol]) -> String {
    let mut parts = Vec::new();

    // Add port filters
    if !ports.is_empty() {
        let port_filter = ports
            .iter()
            .map(|p| format!("port {}", p))
            .collect::<Vec<_>>()
            .join(" or ");
        parts.push(format!("({})", port_filter));
    }

    // Add protocol filters
    for proto in protocols {
        match proto {
            Protocol::Tcp => parts.push("tcp".to_string()),
            Protocol::Udp => parts.push("udp".to_string()),
            Protocol::Icmp => parts.push("icmp".to_string()),
            Protocol::Icmpv6 => parts.push("icmp6".to_string()),
            _ => {}
        }
    }

    if parts.is_empty() {
        // Capture all IP traffic by default
        "ip or ip6".to_string()
    } else {
        parts.join(" or ")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_capture_builder() {
        let engine = CaptureBuilder::new()
            .interface("eth0")
            .promiscuous(true)
            .buffer_size_mb(64)
            .build();

        assert!(!engine.is_running());
    }

    #[test]
    fn test_bpf_filter_generation() {
        let filter = generate_bpf_filter(&[80, 443], &[Protocol::Tcp]);
        assert!(filter.contains("port 80"));
        assert!(filter.contains("port 443"));
        assert!(filter.contains("tcp"));
    }

    #[test]
    fn test_tcp_flags() {
        // SYN only
        let syn = TcpFlags::from_byte(0x02);
        assert!(syn.syn);
        assert!(!syn.ack);
        assert!(syn.is_syn_only());

        // SYN-ACK
        let syn_ack = TcpFlags::from_byte(0x12);
        assert!(syn_ack.syn);
        assert!(syn_ack.ack);
        assert!(!syn_ack.is_syn_only());
    }

    #[test]
    fn test_mac_address_display() {
        let mac = MacAddress::new([0x00, 0x11, 0x22, 0x33, 0x44, 0x55]);
        assert_eq!(format!("{}", mac), "00:11:22:33:44:55");
    }

    #[test]
    fn test_capture_stats() {
        let stats = CaptureStats::new();
        stats.increment_captured();
        stats.increment_captured();
        stats.add_bytes(100);

        let snapshot = stats.snapshot();
        assert_eq!(snapshot.packets_captured, 2);
        assert_eq!(snapshot.bytes_captured, 100);
    }
}
