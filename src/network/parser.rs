//! Packet parser module for extracting network information
//!
//! This module provides functionality for parsing raw network packets
//! and extracting relevant information like IP addresses, MAC addresses,
//! ports, and protocol-specific data.

use crate::core::error::{NetworkError, Result};
use crate::core::types::{ConnectionRecord, MacAddress, Protocol, TcpFlags, TrackingId};
use chrono::Utc;
use pnet::packet::{
    arp::ArpPacket,
    ethernet::{EtherTypes, EthernetPacket},
    icmp::IcmpPacket,
    icmpv6::Icmpv6Packet,
    ip::IpNextHeaderProtocols,
    ipv4::Ipv4Packet,
    ipv6::Ipv6Packet,
    tcp::TcpPacket,
    udp::UdpPacket,
    Packet,
};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::sync::atomic::{AtomicU64, Ordering};

/// Global counter for generating unique tracking IDs
static TRACKING_ID_COUNTER: AtomicU64 = AtomicU64::new(1);

/// Generate a new unique tracking ID
fn next_tracking_id() -> TrackingId {
    TRACKING_ID_COUNTER.fetch_add(1, Ordering::SeqCst)
}

/// Parsed packet information
#[derive(Debug, Clone)]
pub struct ParsedPacket {
    /// Connection record with all extracted information
    pub record: ConnectionRecord,
    /// Raw ethernet frame info
    pub ethernet_info: Option<EthernetInfo>,
    /// Additional protocol-specific info
    pub proto_info: Option<ProtocolInfo>,
    /// Whether the packet is fragmented
    pub is_fragmented: bool,
    /// TTL/Hop Limit
    pub ttl: u8,
}

/// Ethernet frame information
#[derive(Debug, Clone)]
pub struct EthernetInfo {
    pub src_mac: MacAddress,
    pub dst_mac: MacAddress,
    pub ethertype: u16,
}

/// Protocol-specific information
#[derive(Debug, Clone)]
pub enum ProtocolInfo {
    Tcp(TcpInfo),
    Udp(UdpInfo),
    Icmp(IcmpInfo),
    Icmpv6(Icmpv6Info),
    Arp(ArpInfo),
}

/// TCP-specific information
#[derive(Debug, Clone)]
pub struct TcpInfo {
    pub seq_num: u32,
    pub ack_num: u32,
    pub window_size: u16,
    pub urgent_ptr: u16,
    pub options_len: usize,
}

/// UDP-specific information
#[derive(Debug, Clone)]
pub struct UdpInfo {
    pub length: u16,
    pub checksum: u16,
}

/// ICMP-specific information
#[derive(Debug, Clone)]
pub struct IcmpInfo {
    pub icmp_type: u8,
    pub icmp_code: u8,
    pub identifier: Option<u16>,
    pub sequence: Option<u16>,
}

/// ICMPv6-specific information
#[derive(Debug, Clone)]
pub struct Icmpv6Info {
    pub icmp_type: u8,
    pub icmp_code: u8,
}

/// ARP-specific information
#[derive(Debug, Clone)]
pub struct ArpInfo {
    pub operation: u16,
    pub sender_hw_addr: MacAddress,
    pub sender_proto_addr: Ipv4Addr,
    pub target_hw_addr: MacAddress,
    pub target_proto_addr: Ipv4Addr,
}

/// Packet parser for network traffic analysis
pub struct PacketParser {
    /// Track localhost IPs to filter internal traffic
    localhost_ips: Vec<IpAddr>,
}

impl PacketParser {
    /// Create a new packet parser
    pub fn new() -> Self {
        Self {
            localhost_ips: vec![
                IpAddr::V4(Ipv4Addr::LOCALHOST),
                IpAddr::V6(Ipv6Addr::LOCALHOST),
            ],
        }
    }

    /// Create a packet parser with custom localhost IPs
    pub fn with_localhost_ips(localhost_ips: Vec<IpAddr>) -> Self {
        Self { localhost_ips }
    }

    /// Parse a raw ethernet frame
    pub fn parse_ethernet(&self, data: &[u8]) -> Result<ParsedPacket> {
        let ethernet = EthernetPacket::new(data).ok_or_else(|| NetworkError::PacketParseError {
            message: "Failed to parse ethernet frame".to_string(),
        })?;

        let src_mac =
            MacAddress::from_slice(&ethernet.get_source().octets()).unwrap_or(MacAddress::ZERO);
        let dst_mac = MacAddress::from_slice(&ethernet.get_destination().octets())
            .unwrap_or(MacAddress::ZERO);

        let ethernet_info = EthernetInfo {
            src_mac,
            dst_mac,
            ethertype: ethernet.get_ethertype().0,
        };

        match ethernet.get_ethertype() {
            EtherTypes::Ipv4 => self.parse_ipv4(ethernet.payload(), Some(ethernet_info)),
            EtherTypes::Ipv6 => self.parse_ipv6(ethernet.payload(), Some(ethernet_info)),
            EtherTypes::Arp => self.parse_arp(ethernet.payload(), ethernet_info),
            _ => Err(NetworkError::PacketParseError {
                message: format!("Unsupported ethertype: {:?}", ethernet.get_ethertype()),
            }
            .into()),
        }
    }

    /// Parse an IPv4 packet
    pub fn parse_ipv4(
        &self,
        data: &[u8],
        ethernet_info: Option<EthernetInfo>,
    ) -> Result<ParsedPacket> {
        let ipv4 = Ipv4Packet::new(data).ok_or_else(|| NetworkError::PacketParseError {
            message: "Failed to parse IPv4 packet".to_string(),
        })?;

        let src_ip = IpAddr::V4(ipv4.get_source());
        let dst_ip = IpAddr::V4(ipv4.get_destination());
        let ttl = ipv4.get_ttl();
        let is_fragmented = ipv4.get_fragment_offset() != 0 || ipv4.get_flags() & 0x1 != 0;
        let total_len = ipv4.get_total_length() as u32;
        let header_len = (ipv4.get_header_length() as u32) * 4;

        // Parse transport layer
        let (src_port, dst_port, tcp_flags, proto_info, payload_size) =
            self.parse_transport_ipv4(&ipv4)?;

        let record = ConnectionRecord {
            id: next_tracking_id(),
            timestamp: Utc::now(),
            src_ip,
            dst_ip,
            src_port,
            dst_port,
            src_mac: ethernet_info.as_ref().map(|e| e.src_mac),
            protocol: Protocol::from(ipv4.get_next_level_protocol().0),
            tcp_flags,
            packet_size: total_len,
            payload_size: payload_size.unwrap_or(total_len.saturating_sub(header_len)),
        };

        Ok(ParsedPacket {
            record,
            ethernet_info,
            proto_info,
            is_fragmented,
            ttl,
        })
    }

    /// Parse an IPv6 packet
    pub fn parse_ipv6(
        &self,
        data: &[u8],
        ethernet_info: Option<EthernetInfo>,
    ) -> Result<ParsedPacket> {
        let ipv6 = Ipv6Packet::new(data).ok_or_else(|| NetworkError::PacketParseError {
            message: "Failed to parse IPv6 packet".to_string(),
        })?;

        let src_ip = IpAddr::V6(ipv6.get_source());
        let dst_ip = IpAddr::V6(ipv6.get_destination());
        let ttl = ipv6.get_hop_limit();
        let payload_len = ipv6.get_payload_length() as u32;

        // Parse transport layer
        let (src_port, dst_port, tcp_flags, proto_info, payload_size) =
            self.parse_transport_ipv6(&ipv6)?;

        let record = ConnectionRecord {
            id: next_tracking_id(),
            timestamp: Utc::now(),
            src_ip,
            dst_ip,
            src_port,
            dst_port,
            src_mac: ethernet_info.as_ref().map(|e| e.src_mac),
            protocol: Protocol::from(ipv6.get_next_header().0),
            tcp_flags,
            packet_size: 40 + payload_len, // IPv6 header is always 40 bytes
            payload_size: payload_size.unwrap_or(payload_len),
        };

        Ok(ParsedPacket {
            record,
            ethernet_info,
            proto_info,
            is_fragmented: false, // Simplified; real implementation should check extension headers
            ttl,
        })
    }

    /// Parse transport layer for IPv4
    fn parse_transport_ipv4(
        &self,
        ipv4: &Ipv4Packet,
    ) -> Result<(
        Option<u16>,
        Option<u16>,
        Option<TcpFlags>,
        Option<ProtocolInfo>,
        Option<u32>,
    )> {
        match ipv4.get_next_level_protocol() {
            IpNextHeaderProtocols::Tcp => {
                if let Some(tcp) = TcpPacket::new(ipv4.payload()) {
                    let flags = TcpFlags::from_byte(tcp.get_flags());
                    let info = TcpInfo {
                        seq_num: tcp.get_sequence(),
                        ack_num: tcp.get_acknowledgement(),
                        window_size: tcp.get_window(),
                        urgent_ptr: tcp.get_urgent_ptr(),
                        options_len: tcp.get_options_raw().len(),
                    };
                    let payload_size = tcp.payload().len() as u32;
                    Ok((
                        Some(tcp.get_source()),
                        Some(tcp.get_destination()),
                        Some(flags),
                        Some(ProtocolInfo::Tcp(info)),
                        Some(payload_size),
                    ))
                } else {
                    Ok((None, None, None, None, None))
                }
            }
            IpNextHeaderProtocols::Udp => {
                if let Some(udp) = UdpPacket::new(ipv4.payload()) {
                    let info = UdpInfo {
                        length: udp.get_length(),
                        checksum: udp.get_checksum(),
                    };
                    let payload_size = udp.payload().len() as u32;
                    Ok((
                        Some(udp.get_source()),
                        Some(udp.get_destination()),
                        None,
                        Some(ProtocolInfo::Udp(info)),
                        Some(payload_size),
                    ))
                } else {
                    Ok((None, None, None, None, None))
                }
            }
            IpNextHeaderProtocols::Icmp => {
                if let Some(icmp) = IcmpPacket::new(ipv4.payload()) {
                    let (identifier, sequence) = self.parse_icmp_echo(&icmp);
                    let info = IcmpInfo {
                        icmp_type: icmp.get_icmp_type().0,
                        icmp_code: icmp.get_icmp_code().0,
                        identifier,
                        sequence,
                    };
                    Ok((None, None, None, Some(ProtocolInfo::Icmp(info)), None))
                } else {
                    Ok((None, None, None, None, None))
                }
            }
            _ => Ok((None, None, None, None, None)),
        }
    }

    /// Parse transport layer for IPv6
    fn parse_transport_ipv6(
        &self,
        ipv6: &Ipv6Packet,
    ) -> Result<(
        Option<u16>,
        Option<u16>,
        Option<TcpFlags>,
        Option<ProtocolInfo>,
        Option<u32>,
    )> {
        match ipv6.get_next_header() {
            IpNextHeaderProtocols::Tcp => {
                if let Some(tcp) = TcpPacket::new(ipv6.payload()) {
                    let flags = TcpFlags::from_byte(tcp.get_flags());
                    let info = TcpInfo {
                        seq_num: tcp.get_sequence(),
                        ack_num: tcp.get_acknowledgement(),
                        window_size: tcp.get_window(),
                        urgent_ptr: tcp.get_urgent_ptr(),
                        options_len: tcp.get_options_raw().len(),
                    };
                    let payload_size = tcp.payload().len() as u32;
                    Ok((
                        Some(tcp.get_source()),
                        Some(tcp.get_destination()),
                        Some(flags),
                        Some(ProtocolInfo::Tcp(info)),
                        Some(payload_size),
                    ))
                } else {
                    Ok((None, None, None, None, None))
                }
            }
            IpNextHeaderProtocols::Udp => {
                if let Some(udp) = UdpPacket::new(ipv6.payload()) {
                    let info = UdpInfo {
                        length: udp.get_length(),
                        checksum: udp.get_checksum(),
                    };
                    let payload_size = udp.payload().len() as u32;
                    Ok((
                        Some(udp.get_source()),
                        Some(udp.get_destination()),
                        None,
                        Some(ProtocolInfo::Udp(info)),
                        Some(payload_size),
                    ))
                } else {
                    Ok((None, None, None, None, None))
                }
            }
            IpNextHeaderProtocols::Icmpv6 => {
                if let Some(icmpv6) = Icmpv6Packet::new(ipv6.payload()) {
                    let info = Icmpv6Info {
                        icmp_type: icmpv6.get_icmpv6_type().0,
                        icmp_code: icmpv6.get_icmpv6_code().0,
                    };
                    Ok((None, None, None, Some(ProtocolInfo::Icmpv6(info)), None))
                } else {
                    Ok((None, None, None, None, None))
                }
            }
            _ => Ok((None, None, None, None, None)),
        }
    }

    /// Parse ARP packet
    fn parse_arp(&self, data: &[u8], ethernet_info: EthernetInfo) -> Result<ParsedPacket> {
        let arp = ArpPacket::new(data).ok_or_else(|| NetworkError::PacketParseError {
            message: "Failed to parse ARP packet".to_string(),
        })?;

        // Get hardware addresses - pnet MacAddr has octets() method
        let sender_hw_mac = arp.get_sender_hw_addr();
        let sender_hw = MacAddress::new(sender_hw_mac.octets());

        let target_hw_mac = arp.get_target_hw_addr();
        let target_hw = MacAddress::new(target_hw_mac.octets());

        // Get protocol addresses - pnet returns Ipv4Addr directly
        let sender_ip = arp.get_sender_proto_addr();
        let target_ip = arp.get_target_proto_addr();

        let arp_info = ArpInfo {
            operation: arp.get_operation().0,
            sender_hw_addr: sender_hw,
            sender_proto_addr: sender_ip,
            target_hw_addr: target_hw,
            target_proto_addr: target_ip,
        };

        let record = ConnectionRecord {
            id: next_tracking_id(),
            timestamp: Utc::now(),
            src_ip: IpAddr::V4(sender_ip),
            dst_ip: IpAddr::V4(target_ip),
            src_port: None,
            dst_port: None,
            src_mac: Some(sender_hw),
            protocol: Protocol::Unknown(0), // ARP is not an IP protocol
            tcp_flags: None,
            packet_size: data.len() as u32,
            payload_size: 0,
        };

        Ok(ParsedPacket {
            record,
            ethernet_info: Some(ethernet_info),
            proto_info: Some(ProtocolInfo::Arp(arp_info)),
            is_fragmented: false,
            ttl: 0,
        })
    }

    /// Parse ICMP echo request/reply to extract identifier and sequence
    fn parse_icmp_echo(&self, icmp: &IcmpPacket) -> (Option<u16>, Option<u16>) {
        let payload = icmp.payload();
        if payload.len() >= 4 {
            let identifier = u16::from_be_bytes([payload[0], payload[1]]);
            let sequence = u16::from_be_bytes([payload[2], payload[3]]);
            (Some(identifier), Some(sequence))
        } else {
            (None, None)
        }
    }

    /// Check if an IP address is localhost
    pub fn is_localhost(&self, ip: &IpAddr) -> bool {
        self.localhost_ips.contains(ip)
            || match ip {
                IpAddr::V4(v4) => v4.is_loopback(),
                IpAddr::V6(v6) => v6.is_loopback(),
            }
    }

    /// Check if traffic is internal (both src and dst are localhost)
    pub fn is_internal_traffic(&self, packet: &ParsedPacket) -> bool {
        self.is_localhost(&packet.record.src_ip) && self.is_localhost(&packet.record.dst_ip)
    }

    /// Extract flow identifier (5-tuple) from a packet
    pub fn extract_flow_id(&self, packet: &ParsedPacket) -> FlowId {
        FlowId {
            src_ip: packet.record.src_ip,
            dst_ip: packet.record.dst_ip,
            src_port: packet.record.src_port.unwrap_or(0),
            dst_port: packet.record.dst_port.unwrap_or(0),
            protocol: packet.record.protocol,
        }
    }
}

impl Default for PacketParser {
    fn default() -> Self {
        Self::new()
    }
}

/// Flow identifier (5-tuple)
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct FlowId {
    pub src_ip: IpAddr,
    pub dst_ip: IpAddr,
    pub src_port: u16,
    pub dst_port: u16,
    pub protocol: Protocol,
}

impl FlowId {
    /// Get the reverse flow (swap src and dst)
    pub fn reverse(&self) -> Self {
        Self {
            src_ip: self.dst_ip,
            dst_ip: self.src_ip,
            src_port: self.dst_port,
            dst_port: self.src_port,
            protocol: self.protocol,
        }
    }

    /// Get a canonical form (smaller IP first) for bidirectional flow matching
    pub fn canonical(&self) -> Self {
        if self.src_ip < self.dst_ip {
            *self
        } else if self.src_ip > self.dst_ip {
            self.reverse()
        } else if self.src_port <= self.dst_port {
            *self
        } else {
            self.reverse()
        }
    }
}

/// Quick packet classification for filtering
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PacketClass {
    /// TCP SYN (connection initiation)
    TcpSyn,
    /// TCP SYN-ACK
    TcpSynAck,
    /// TCP ACK
    TcpAck,
    /// TCP FIN
    TcpFin,
    /// TCP RST
    TcpRst,
    /// TCP data packet
    TcpData,
    /// UDP packet
    Udp,
    /// ICMP Echo Request (ping)
    IcmpEchoRequest,
    /// ICMP Echo Reply
    IcmpEchoReply,
    /// Other ICMP
    IcmpOther,
    /// ARP
    Arp,
    /// Unknown/Other
    Other,
}

impl ParsedPacket {
    /// Classify the packet type for quick filtering
    pub fn classify(&self) -> PacketClass {
        match &self.proto_info {
            Some(ProtocolInfo::Tcp(tcp_info)) => {
                if let Some(flags) = &self.record.tcp_flags {
                    if flags.syn && !flags.ack {
                        PacketClass::TcpSyn
                    } else if flags.syn && flags.ack {
                        PacketClass::TcpSynAck
                    } else if flags.fin {
                        PacketClass::TcpFin
                    } else if flags.rst {
                        PacketClass::TcpRst
                    } else if flags.ack && self.record.payload_size == 0 {
                        PacketClass::TcpAck
                    } else {
                        PacketClass::TcpData
                    }
                } else {
                    PacketClass::TcpData
                }
            }
            Some(ProtocolInfo::Udp(_)) => PacketClass::Udp,
            Some(ProtocolInfo::Icmp(icmp)) => {
                match icmp.icmp_type {
                    8 => PacketClass::IcmpEchoRequest, // Echo Request
                    0 => PacketClass::IcmpEchoReply,   // Echo Reply
                    _ => PacketClass::IcmpOther,
                }
            }
            Some(ProtocolInfo::Icmpv6(icmpv6)) => {
                match icmpv6.icmp_type {
                    128 => PacketClass::IcmpEchoRequest, // Echo Request
                    129 => PacketClass::IcmpEchoReply,   // Echo Reply
                    _ => PacketClass::IcmpOther,
                }
            }
            Some(ProtocolInfo::Arp(_)) => PacketClass::Arp,
            None => PacketClass::Other,
        }
    }

    /// Check if this is a connection initiation packet
    pub fn is_connection_start(&self) -> bool {
        matches!(self.classify(), PacketClass::TcpSyn)
    }

    /// Check if this is a potential flood packet
    pub fn is_potential_flood(&self) -> bool {
        matches!(
            self.classify(),
            PacketClass::TcpSyn | PacketClass::Udp | PacketClass::IcmpEchoRequest
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_flow_id_canonical() {
        let flow1 = FlowId {
            src_ip: IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1)),
            dst_ip: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
            src_port: 12345,
            dst_port: 80,
            protocol: Protocol::Tcp,
        };

        let flow2 = flow1.reverse();
        assert_eq!(flow1.canonical(), flow2.canonical());
    }

    #[test]
    fn test_tcp_flags_parsing() {
        let syn_only = TcpFlags::from_byte(0x02);
        assert!(syn_only.syn);
        assert!(!syn_only.ack);
        assert!(syn_only.is_syn_only());

        let syn_ack = TcpFlags::from_byte(0x12);
        assert!(syn_ack.syn);
        assert!(syn_ack.ack);
        assert!(!syn_ack.is_syn_only());
    }

    #[test]
    fn test_packet_parser_localhost() {
        let parser = PacketParser::new();
        assert!(parser.is_localhost(&IpAddr::V4(Ipv4Addr::LOCALHOST)));
        assert!(parser.is_localhost(&IpAddr::V6(Ipv6Addr::LOCALHOST)));
        assert!(!parser.is_localhost(&IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8))));
    }
}
