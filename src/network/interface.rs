//! Network interface management module
//!
//! This module provides functionality for discovering, monitoring, and managing
//! network interfaces for the Zeroed DoS protection daemon.

use crate::core::error::{NetworkError, Result, ZeroedError};
use pnet::datalink::{self, Channel, DataLinkReceiver, DataLinkSender, NetworkInterface};
use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::sync::Arc;
use tokio::sync::RwLock;
use tracing::info;

/// Network interface information
#[derive(Debug, Clone)]
pub struct InterfaceInfo {
    /// Interface name (e.g., "eth0", "ens33")
    pub name: String,
    /// Interface description
    pub description: Option<String>,
    /// Interface index
    pub index: u32,
    /// MAC address
    pub mac: Option<[u8; 6]>,
    /// IPv4 addresses assigned to this interface
    pub ipv4_addrs: Vec<Ipv4Addr>,
    /// IPv6 addresses assigned to this interface
    pub ipv6_addrs: Vec<Ipv6Addr>,
    /// Interface flags
    pub flags: InterfaceFlags,
    /// MTU (Maximum Transmission Unit)
    pub mtu: Option<u32>,
    /// Interface statistics
    pub stats: InterfaceStats,
}

/// Interface flags indicating state and capabilities
#[derive(Debug, Clone, Copy, Default)]
pub struct InterfaceFlags {
    /// Interface is up
    pub is_up: bool,
    /// Interface is a loopback
    pub is_loopback: bool,
    /// Interface supports broadcast
    pub is_broadcast: bool,
    /// Interface supports multicast
    pub is_multicast: bool,
    /// Interface is point-to-point
    pub is_point_to_point: bool,
    /// Interface is running (carrier present)
    pub is_running: bool,
}

impl From<u32> for InterfaceFlags {
    fn from(flags: u32) -> Self {
        // Standard Linux interface flags
        const IFF_UP: u32 = 0x1;
        const IFF_BROADCAST: u32 = 0x2;
        const IFF_LOOPBACK: u32 = 0x8;
        const IFF_POINTOPOINT: u32 = 0x10;
        const IFF_RUNNING: u32 = 0x40;
        const IFF_MULTICAST: u32 = 0x1000;

        Self {
            is_up: (flags & IFF_UP) != 0,
            is_broadcast: (flags & IFF_BROADCAST) != 0,
            is_loopback: (flags & IFF_LOOPBACK) != 0,
            is_point_to_point: (flags & IFF_POINTOPOINT) != 0,
            is_running: (flags & IFF_RUNNING) != 0,
            is_multicast: (flags & IFF_MULTICAST) != 0,
        }
    }
}

/// Interface traffic statistics
#[derive(Debug, Clone, Default)]
pub struct InterfaceStats {
    /// Bytes received
    pub rx_bytes: u64,
    /// Bytes transmitted
    pub tx_bytes: u64,
    /// Packets received
    pub rx_packets: u64,
    /// Packets transmitted
    pub tx_packets: u64,
    /// Receive errors
    pub rx_errors: u64,
    /// Transmit errors
    pub tx_errors: u64,
    /// Dropped packets (receive)
    pub rx_dropped: u64,
    /// Dropped packets (transmit)
    pub tx_dropped: u64,
}

/// Network interface manager
pub struct InterfaceManager {
    /// Cached interface information
    interfaces: Arc<RwLock<HashMap<String, InterfaceInfo>>>,
    /// Selected interfaces for monitoring
    monitored: Arc<RwLock<Vec<String>>>,
}

impl InterfaceManager {
    /// Create a new interface manager
    pub fn new() -> Self {
        Self {
            interfaces: Arc::new(RwLock::new(HashMap::new())),
            monitored: Arc::new(RwLock::new(Vec::new())),
        }
    }

    /// Discover all network interfaces on the system
    pub async fn discover(&self) -> Result<Vec<InterfaceInfo>> {
        let interfaces = datalink::interfaces();
        let mut result = Vec::new();
        let mut cache = self.interfaces.write().await;

        for iface in interfaces {
            let info = self.interface_to_info(&iface);
            cache.insert(info.name.clone(), info.clone());
            result.push(info);
        }

        info!("Discovered {} network interfaces", result.len());
        Ok(result)
    }

    /// Convert pnet interface to our InterfaceInfo
    fn interface_to_info(&self, iface: &NetworkInterface) -> InterfaceInfo {
        let mut ipv4_addrs = Vec::new();
        let mut ipv6_addrs = Vec::new();

        for ip in &iface.ips {
            match ip.ip() {
                IpAddr::V4(v4) => ipv4_addrs.push(v4),
                IpAddr::V6(v6) => ipv6_addrs.push(v6),
            }
        }

        InterfaceInfo {
            name: iface.name.clone(),
            description: {
                let desc = iface.description.clone();
                if desc.is_empty() {
                    None
                } else {
                    Some(desc)
                }
            },
            index: iface.index,
            mac: iface.mac.map(|m| m.octets()),
            ipv4_addrs,
            ipv6_addrs,
            flags: InterfaceFlags {
                is_up: iface.is_up(),
                is_loopback: iface.is_loopback(),
                is_broadcast: iface.is_broadcast(),
                is_multicast: iface.is_multicast(),
                is_point_to_point: iface.is_point_to_point(),
                is_running: iface.is_running(),
            },
            mtu: None, // Would need additional system calls
            stats: InterfaceStats::default(),
        }
    }

    /// Get a specific interface by name
    pub async fn get_interface(&self, name: &str) -> Option<InterfaceInfo> {
        let cache = self.interfaces.read().await;
        cache.get(name).cloned()
    }

    /// Get all cached interfaces
    pub async fn get_all_interfaces(&self) -> Vec<InterfaceInfo> {
        let cache = self.interfaces.read().await;
        cache.values().cloned().collect()
    }

    /// Get interfaces suitable for monitoring (non-loopback, up)
    pub async fn get_monitorable_interfaces(&self) -> Vec<InterfaceInfo> {
        let cache = self.interfaces.read().await;
        cache
            .values()
            .filter(|i| i.flags.is_up && !i.flags.is_loopback)
            .cloned()
            .collect()
    }

    /// Set interfaces to monitor
    pub async fn set_monitored(&self, interfaces: Vec<String>) -> Result<()> {
        let cache = self.interfaces.read().await;

        // Verify all interfaces exist
        for name in &interfaces {
            if !cache.contains_key(name) {
                return Err(ZeroedError::Network(NetworkError::InterfaceNotFound {
                    interface: name.clone(),
                }));
            }
        }

        let mut monitored = self.monitored.write().await;
        *monitored = interfaces;
        Ok(())
    }

    /// Get currently monitored interfaces
    pub async fn get_monitored(&self) -> Vec<String> {
        self.monitored.read().await.clone()
    }

    /// Get the default interface (first non-loopback interface that is up)
    pub async fn get_default_interface(&self) -> Option<InterfaceInfo> {
        let interfaces = self.get_monitorable_interfaces().await;
        interfaces.into_iter().next()
    }

    /// Check if an interface exists and is usable
    pub async fn is_interface_usable(&self, name: &str) -> bool {
        if let Some(info) = self.get_interface(name).await {
            info.flags.is_up && info.flags.is_running
        } else {
            false
        }
    }

    /// Get interface by IP address
    pub async fn get_interface_by_ip(&self, ip: &IpAddr) -> Option<InterfaceInfo> {
        let cache = self.interfaces.read().await;
        cache
            .values()
            .find(|i| match ip {
                IpAddr::V4(v4) => i.ipv4_addrs.contains(v4),
                IpAddr::V6(v6) => i.ipv6_addrs.contains(v6),
            })
            .cloned()
    }

    /// Refresh interface statistics from /proc/net/dev (Linux-specific)
    #[cfg(target_os = "linux")]
    pub async fn refresh_stats(&self) -> Result<()> {
        use std::fs;

        let content = fs::read_to_string("/proc/net/dev").map_err(|e| {
            ZeroedError::Io(std::io::Error::new(
                std::io::ErrorKind::Other,
                format!("Failed to read /proc/net/dev: {}", e),
            ))
        })?;

        let mut cache = self.interfaces.write().await;

        for line in content.lines().skip(2) {
            // Skip header lines
            let parts: Vec<&str> = line.split_whitespace().collect();
            if parts.len() < 17 {
                continue;
            }

            let name = parts[0].trim_end_matches(':');
            if let Some(info) = cache.get_mut(name) {
                info.stats = InterfaceStats {
                    rx_bytes: parts[1].parse().unwrap_or(0),
                    rx_packets: parts[2].parse().unwrap_or(0),
                    rx_errors: parts[3].parse().unwrap_or(0),
                    rx_dropped: parts[4].parse().unwrap_or(0),
                    tx_bytes: parts[9].parse().unwrap_or(0),
                    tx_packets: parts[10].parse().unwrap_or(0),
                    tx_errors: parts[11].parse().unwrap_or(0),
                    tx_dropped: parts[12].parse().unwrap_or(0),
                };
            }
        }

        Ok(())
    }

    /// No-op for non-Linux systems
    #[cfg(not(target_os = "linux"))]
    pub async fn refresh_stats(&self) -> Result<()> {
        warn!("Interface statistics refresh not supported on this platform");
        Ok(())
    }

    /// Watch for interface state changes
    pub async fn watch_changes(&self) -> InterfaceWatcher {
        InterfaceWatcher::new(Arc::clone(&self.interfaces))
    }
}

impl Default for InterfaceManager {
    fn default() -> Self {
        Self::new()
    }
}

/// Watches for interface state changes
pub struct InterfaceWatcher {
    interfaces: Arc<RwLock<HashMap<String, InterfaceInfo>>>,
    last_state: HashMap<String, bool>,
}

impl InterfaceWatcher {
    fn new(interfaces: Arc<RwLock<HashMap<String, InterfaceInfo>>>) -> Self {
        Self {
            interfaces,
            last_state: HashMap::new(),
        }
    }

    /// Check for state changes and return them
    pub async fn check_changes(&mut self) -> Vec<InterfaceChange> {
        let cache = self.interfaces.read().await;
        let mut changes = Vec::new();

        for (name, info) in cache.iter() {
            let is_up = info.flags.is_up && info.flags.is_running;
            match self.last_state.get(name) {
                Some(&was_up) if was_up != is_up => {
                    changes.push(InterfaceChange {
                        name: name.clone(),
                        change_type: if is_up {
                            ChangeType::BecameUp
                        } else {
                            ChangeType::BecameDown
                        },
                    });
                }
                None => {
                    changes.push(InterfaceChange {
                        name: name.clone(),
                        change_type: ChangeType::Discovered,
                    });
                }
                _ => {}
            }
            self.last_state.insert(name.clone(), is_up);
        }

        // Check for removed interfaces
        let current_names: std::collections::HashSet<_> = cache.keys().cloned().collect();
        let removed: Vec<_> = self
            .last_state
            .keys()
            .filter(|k| !current_names.contains(*k))
            .cloned()
            .collect();

        for name in removed {
            self.last_state.remove(&name);
            changes.push(InterfaceChange {
                name,
                change_type: ChangeType::Removed,
            });
        }

        changes
    }
}

/// Represents a change in interface state
#[derive(Debug, Clone)]
pub struct InterfaceChange {
    pub name: String,
    pub change_type: ChangeType,
}

/// Type of interface change
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ChangeType {
    /// Interface was discovered (first seen)
    Discovered,
    /// Interface came up
    BecameUp,
    /// Interface went down
    BecameDown,
    /// Interface was removed
    Removed,
}

/// Helper to open a raw socket for an interface
pub fn open_raw_channel(
    interface_name: &str,
) -> Result<(Box<dyn DataLinkSender>, Box<dyn DataLinkReceiver>)> {
    let interfaces = datalink::interfaces();
    let interface = interfaces
        .into_iter()
        .find(|i| i.name == interface_name)
        .ok_or_else(|| {
            ZeroedError::Network(NetworkError::InterfaceNotFound {
                interface: interface_name.to_string(),
            })
        })?;

    let config = datalink::Config {
        write_buffer_size: 65536,
        read_buffer_size: 65536,
        read_timeout: Some(std::time::Duration::from_millis(100)),
        write_timeout: None,
        channel_type: datalink::ChannelType::Layer2,
        bpf_fd_attempts: 1000,
        linux_fanout: None,
        promiscuous: true,
    };

    match datalink::channel(&interface, config) {
        Ok(Channel::Ethernet(tx, rx)) => Ok((tx, rx)),
        Ok(_) => Err(ZeroedError::Network(NetworkError::InterfaceOpenError {
            interface: interface_name.to_string(),
            message: "Unknown channel type".to_string(),
        })),
        Err(e) => Err(ZeroedError::Network(NetworkError::InterfaceOpenError {
            interface: interface_name.to_string(),
            message: e.to_string(),
        })),
    }
}

/// Utility: Format MAC address as string
pub fn format_mac(mac: &[u8; 6]) -> String {
    format!(
        "{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
        mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]
    )
}

/// Utility: Parse MAC address from string
pub fn parse_mac(s: &str) -> Option<[u8; 6]> {
    let parts: Vec<&str> = s.split(':').collect();
    if parts.len() != 6 {
        return None;
    }

    let mut mac = [0u8; 6];
    for (i, part) in parts.iter().enumerate() {
        mac[i] = u8::from_str_radix(part, 16).ok()?;
    }
    Some(mac)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_format_mac() {
        let mac = [0x00, 0x11, 0x22, 0x33, 0x44, 0x55];
        assert_eq!(format_mac(&mac), "00:11:22:33:44:55");
    }

    #[test]
    fn test_parse_mac() {
        let mac = parse_mac("00:11:22:33:44:55");
        assert_eq!(mac, Some([0x00, 0x11, 0x22, 0x33, 0x44, 0x55]));

        let invalid = parse_mac("invalid");
        assert_eq!(invalid, None);
    }

    #[test]
    fn test_interface_flags() {
        let flags = InterfaceFlags::from(0x1043); // UP | BROADCAST | RUNNING | MULTICAST
        assert!(flags.is_up);
        assert!(flags.is_broadcast);
        assert!(flags.is_running);
        assert!(flags.is_multicast);
        assert!(!flags.is_loopback);
    }

    #[tokio::test]
    async fn test_interface_manager() {
        let manager = InterfaceManager::new();
        let interfaces = manager.discover().await.unwrap();

        // Should find at least loopback
        assert!(!interfaces.is_empty());

        // Check we can find loopback
        let lo = interfaces.iter().find(|i| i.flags.is_loopback);
        assert!(lo.is_some());
    }
}
