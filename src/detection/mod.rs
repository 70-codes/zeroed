//! Detection module for DoS/DDoS attack identification
//!
//! This module provides the core attack detection algorithms and rate limiting
//! functionality for the Zeroed daemon. It analyzes network traffic patterns
//! and identifies potential attacks based on configurable thresholds.
//!
//! ## Detection Capabilities
//!
//! - **Rate Limiting**: Token bucket and sliding window algorithms
//! - **SYN Flood Detection**: Monitors half-open TCP connections
//! - **UDP Flood Detection**: Tracks UDP packet rates per source
//! - **ICMP Flood Detection**: Monitors ping flood patterns
//! - **Slowloris Detection**: Identifies slow HTTP attacks
//! - **Connection Exhaustion**: Tracks concurrent connections per IP
//! - **Anomaly Detection**: Statistical analysis of traffic patterns

pub mod analyzer;
pub mod rate_limiter;
pub mod rules;
pub mod threshold;

use crate::core::config::DetectionConfig;
use crate::core::types::{
    Action, AttackType, ConnectionRecord, IpTrackingEntry, Protocol, ThreatLevel,
};
use chrono::{DateTime, Duration, Utc};
use dashmap::DashMap;
use parking_lot::RwLock;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

// Re-exports
pub use analyzer::TrafficAnalyzer;
pub use rate_limiter::{RateLimiter, TokenBucket};
pub use threshold::ThresholdManager;

/// Detection engine result
#[derive(Debug, Clone)]
pub struct DetectionResult {
    /// Source IP that was analyzed
    pub source_ip: IpAddr,
    /// Detected threat level
    pub threat_level: ThreatLevel,
    /// Threat score (0.0 - 1.0)
    pub threat_score: f64,
    /// Detected attack types (if any)
    pub attack_types: Vec<AttackType>,
    /// Recommended action
    pub action: Action,
    /// Reason for the detection
    pub reason: String,
    /// Timestamp of detection
    pub timestamp: DateTime<Utc>,
    /// Additional metadata
    pub metadata: HashMap<String, String>,
}

impl DetectionResult {
    /// Create a new detection result indicating no threat
    pub fn no_threat(source_ip: IpAddr) -> Self {
        Self {
            source_ip,
            threat_level: ThreatLevel::None,
            threat_score: 0.0,
            attack_types: Vec::new(),
            action: Action::Allow,
            reason: String::new(),
            timestamp: Utc::now(),
            metadata: HashMap::new(),
        }
    }

    /// Create a detection result for a detected attack
    pub fn attack_detected(
        source_ip: IpAddr,
        attack_type: AttackType,
        threat_level: ThreatLevel,
        threat_score: f64,
        reason: String,
    ) -> Self {
        let action = match threat_level {
            ThreatLevel::None => Action::Allow,
            ThreatLevel::Low => Action::LogOnly,
            ThreatLevel::Medium => Action::RateLimit,
            ThreatLevel::High => Action::Drop,
            ThreatLevel::Critical => Action::Reject,
        };

        Self {
            source_ip,
            threat_level,
            threat_score,
            attack_types: vec![attack_type],
            action,
            reason,
            timestamp: Utc::now(),
            metadata: HashMap::new(),
        }
    }

    /// Check if this result indicates a threat
    pub fn is_threat(&self) -> bool {
        self.threat_level > ThreatLevel::None
    }

    /// Check if this result should trigger a block
    pub fn should_block(&self) -> bool {
        matches!(self.action, Action::Drop | Action::Reject)
    }
}

/// Per-IP tracking data for detection
#[derive(Debug, Clone)]
pub struct IpDetectionState {
    /// IP address
    pub ip: IpAddr,
    /// Request count in current window
    pub request_count: u64,
    /// SYN packet count
    pub syn_count: u64,
    /// UDP packet count in current window
    pub udp_count: u64,
    /// ICMP packet count in current window
    pub icmp_count: u64,
    /// Connection count (fed from ConnectionTracker)
    pub connection_count: u64,
    /// Bytes transferred
    pub bytes_total: u64,
    /// Unique destination ports accessed
    pub unique_ports: u32,
    /// Current threat score
    pub threat_score: f64,
    /// Detection history
    pub detection_history: Vec<DetectionResult>,
    /// First seen timestamp
    pub first_seen: DateTime<Utc>,
    /// Last seen timestamp
    pub last_seen: DateTime<Utc>,
    /// Window start time
    pub window_start: DateTime<Utc>,
}

impl IpDetectionState {
    pub fn new(ip: IpAddr) -> Self {
        let now = Utc::now();
        Self {
            ip,
            request_count: 0,
            syn_count: 0,
            udp_count: 0,
            icmp_count: 0,
            connection_count: 0,
            bytes_total: 0,
            unique_ports: 0,
            threat_score: 0.0,
            detection_history: Vec::new(),
            first_seen: now,
            last_seen: now,
            window_start: now,
        }
    }

    /// Calculate requests per second
    pub fn requests_per_second(&self) -> f64 {
        let duration = (self.last_seen - self.window_start).num_seconds() as f64;
        if duration > 0.0 {
            self.request_count as f64 / duration
        } else {
            self.request_count as f64
        }
    }

    /// Calculate the duration of the current window in seconds (floored to 0)
    pub fn window_duration_secs(&self) -> f64 {
        let d = (self.last_seen - self.window_start).num_seconds() as f64;
        if d > 0.0 { d } else { 0.0 }
    }

    /// Reset window counters
    pub fn reset_window(&mut self) {
        self.request_count = 0;
        self.syn_count = 0;
        self.udp_count = 0;
        self.icmp_count = 0;
        self.bytes_total = 0;
        self.window_start = Utc::now();
    }
}

/// Main detection engine
pub struct DetectionEngine {
    /// Configuration
    config: DetectionConfig,
    /// Per-IP detection state
    ip_states: DashMap<IpAddr, IpDetectionState>,
    /// Rate limiter
    rate_limiter: Arc<RateLimiter>,
    /// Threshold manager
    threshold_manager: Arc<ThresholdManager>,
    /// Global statistics
    stats: DetectionStats,
}

impl DetectionEngine {
    /// Create a new detection engine
    pub fn new(config: DetectionConfig) -> Self {
        let rate_limiter = Arc::new(RateLimiter::new(
            config.rps_threshold as f64,
            config.rps_block_threshold as f64,
        ));

        let threshold_manager = Arc::new(ThresholdManager::new(&config));

        Self {
            config,
            ip_states: DashMap::new(),
            rate_limiter,
            threshold_manager,
            stats: DetectionStats::default(),
        }
    }

    /// Analyze a connection record and return detection result
    pub fn analyze(&self, record: &ConnectionRecord) -> DetectionResult {
        self.stats.packets_analyzed.fetch_add(1, Ordering::Relaxed);

        let src_ip = record.src_ip;

        // Check whitelist first
        if self.is_whitelisted(&src_ip) {
            return DetectionResult::no_threat(src_ip);
        }

        // Check blacklist
        if self.is_blacklisted(&src_ip) {
            self.stats.attacks_detected.fetch_add(1, Ordering::Relaxed);
            return DetectionResult::attack_detected(
                src_ip,
                AttackType::Unknown,
                ThreatLevel::Critical,
                1.0,
                "IP is blacklisted".to_string(),
            );
        }

        // Update IP state
        let mut state = self.ip_states
            .entry(src_ip)
            .or_insert_with(|| IpDetectionState::new(src_ip));

        state.request_count += 1;
        state.bytes_total += record.packet_size as u64;
        state.last_seen = Utc::now();

        // Track per-protocol counters
        match record.protocol {
            Protocol::Tcp => {
                if let Some(flags) = &record.tcp_flags {
                    if flags.is_syn_only() {
                        state.syn_count += 1;
                    }
                }
            }
            Protocol::Udp => {
                state.udp_count += 1;
            }
            Protocol::Icmp | Protocol::Icmpv6 => {
                state.icmp_count += 1;
            }
            _ => {}
        }

        // Run detection checks
        let mut results = Vec::new();

        // Rate limit check
        if let Some(result) = self.check_rate_limit(&state) {
            results.push(result);
        }

        // SYN flood check
        if let Some(result) = self.check_syn_flood(&state) {
            results.push(result);
        }

        // UDP flood check
        if let Some(result) = self.check_udp_flood(&state) {
            results.push(result);
        }

        // ICMP flood check
        if let Some(result) = self.check_icmp_flood(&state) {
            results.push(result);
        }

        // Connection exhaustion check
        if let Some(result) = self.check_connection_exhaustion(&state) {
            results.push(result);
        }

        drop(state);

        // Return the highest severity result
        if results.is_empty() {
            DetectionResult::no_threat(src_ip)
        } else {
            // Find highest threat level
            results
                .into_iter()
                .max_by(|a, b| a.threat_level.cmp(&b.threat_level))
                .unwrap()
        }
    }

    /// Check rate limiting
    fn check_rate_limit(&self, state: &IpDetectionState) -> Option<DetectionResult> {
        let rps = state.requests_per_second();

        if rps > self.config.rps_block_threshold as f64 {
            self.stats.attacks_detected.fetch_add(1, Ordering::Relaxed);
            Some(DetectionResult::attack_detected(
                state.ip,
                AttackType::Volumetric,
                ThreatLevel::Critical,
                1.0,
                format!("Rate limit exceeded: {:.2} RPS (threshold: {})", rps, self.config.rps_block_threshold),
            ))
        } else if rps > self.config.rps_threshold as f64 {
            Some(DetectionResult::attack_detected(
                state.ip,
                AttackType::Volumetric,
                ThreatLevel::Medium,
                rps / self.config.rps_block_threshold as f64,
                format!("Elevated request rate: {:.2} RPS", rps),
            ))
        } else {
            None
        }
    }

    /// Check for SYN flood
    fn check_syn_flood(&self, state: &IpDetectionState) -> Option<DetectionResult> {
        let duration = (state.last_seen - state.window_start).num_seconds() as f64;
        if duration <= 0.0 {
            return None;
        }

        let syn_rate = state.syn_count as f64 / duration;

        if syn_rate > self.config.syn_flood_threshold as f64 {
            self.stats.attacks_detected.fetch_add(1, Ordering::Relaxed);
            Some(DetectionResult::attack_detected(
                state.ip,
                AttackType::SynFlood,
                ThreatLevel::Critical,
                1.0,
                format!("SYN flood detected: {:.2} SYN/s", syn_rate),
            ))
        } else if syn_rate > (self.config.syn_flood_threshold / 2) as f64 {
            Some(DetectionResult::attack_detected(
                state.ip,
                AttackType::SynFlood,
                ThreatLevel::High,
                syn_rate / self.config.syn_flood_threshold as f64,
                format!("Elevated SYN rate: {:.2} SYN/s", syn_rate),
            ))
        } else {
            None
        }
    }

    /// Check for UDP flood
    fn check_udp_flood(&self, state: &IpDetectionState) -> Option<DetectionResult> {
        let duration = state.window_duration_secs();
        if duration <= 0.0 {
            return None;
        }

        let udp_rate = state.udp_count as f64 / duration;

        if udp_rate > self.config.udp_flood_threshold as f64 {
            self.stats.attacks_detected.fetch_add(1, Ordering::Relaxed);
            Some(DetectionResult::attack_detected(
                state.ip,
                AttackType::UdpFlood,
                ThreatLevel::Critical,
                1.0,
                format!("UDP flood detected: {:.2} UDP/s (threshold: {})", udp_rate, self.config.udp_flood_threshold),
            ))
        } else if udp_rate > (self.config.udp_flood_threshold / 2) as f64 {
            Some(DetectionResult::attack_detected(
                state.ip,
                AttackType::UdpFlood,
                ThreatLevel::High,
                udp_rate / self.config.udp_flood_threshold as f64,
                format!("Elevated UDP rate: {:.2} UDP/s", udp_rate),
            ))
        } else {
            None
        }
    }

    /// Check for ICMP flood (ping flood)
    fn check_icmp_flood(&self, state: &IpDetectionState) -> Option<DetectionResult> {
        let duration = state.window_duration_secs();
        if duration <= 0.0 {
            return None;
        }

        let icmp_rate = state.icmp_count as f64 / duration;

        if icmp_rate > self.config.icmp_flood_threshold as f64 {
            self.stats.attacks_detected.fetch_add(1, Ordering::Relaxed);
            Some(DetectionResult::attack_detected(
                state.ip,
                AttackType::IcmpFlood,
                ThreatLevel::Critical,
                1.0,
                format!("ICMP flood detected: {:.2} ICMP/s (threshold: {})", icmp_rate, self.config.icmp_flood_threshold),
            ))
        } else if icmp_rate > (self.config.icmp_flood_threshold / 2) as f64 {
            Some(DetectionResult::attack_detected(
                state.ip,
                AttackType::IcmpFlood,
                ThreatLevel::High,
                icmp_rate / self.config.icmp_flood_threshold as f64,
                format!("Elevated ICMP rate: {:.2} ICMP/s", icmp_rate),
            ))
        } else {
            None
        }
    }

    /// Check for connection exhaustion
    fn check_connection_exhaustion(&self, state: &IpDetectionState) -> Option<DetectionResult> {
        if state.connection_count > self.config.max_connections_per_ip as u64 {
            self.stats.attacks_detected.fetch_add(1, Ordering::Relaxed);
            Some(DetectionResult::attack_detected(
                state.ip,
                AttackType::ConnectionExhaustion,
                ThreatLevel::High,
                state.connection_count as f64 / self.config.max_connections_per_ip as f64,
                format!(
                    "Connection limit exceeded: {} connections",
                    state.connection_count
                ),
            ))
        } else {
            None
        }
    }

    /// Check if IP is whitelisted
    pub fn is_whitelisted(&self, ip: &IpAddr) -> bool {
        let ip_str = ip.to_string();
        self.config.whitelist_ips.contains(&ip_str)
    }

    /// Check if IP is blacklisted
    pub fn is_blacklisted(&self, ip: &IpAddr) -> bool {
        let ip_str = ip.to_string();
        self.config.blacklist_ips.contains(&ip_str)
    }

    /// Get detection statistics
    pub fn stats(&self) -> DetectionStatsSnapshot {
        DetectionStatsSnapshot {
            packets_analyzed: self.stats.packets_analyzed.load(Ordering::Relaxed),
            attacks_detected: self.stats.attacks_detected.load(Ordering::Relaxed),
            ips_blocked: self.stats.ips_blocked.load(Ordering::Relaxed),
            false_positives: self.stats.false_positives.load(Ordering::Relaxed),
            tracked_ips: self.ip_states.len(),
        }
    }

    /// Clear state for an IP
    pub fn clear_ip_state(&self, ip: &IpAddr) {
        self.ip_states.remove(ip);
    }

    /// Get all tracked IPs
    pub fn tracked_ips(&self) -> Vec<IpAddr> {
        self.ip_states.iter().map(|entry| *entry.key()).collect()
    }

    /// Update the connection count for an IP from an external source
    /// (e.g., the ConnectionTracker). This allows the detection engine
    /// to check connection exhaustion using live connection data.
    pub fn update_connection_count(&self, ip: IpAddr, connection_count: u64) {
        if let Some(mut state) = self.ip_states.get_mut(&ip) {
            state.connection_count = connection_count;
        }
    }

    /// Reset detection windows for IPs whose window has expired.
    ///
    /// This should be called periodically (e.g., every `rate_window` seconds)
    /// to ensure that old packet counts don't accumulate forever, which would
    /// cause the requests-per-second calculation to trend toward zero instead
    /// of reflecting the current traffic rate.
    ///
    /// Returns the number of IP states that had their windows reset.
    pub fn reset_stale_windows(&self) -> usize {
        let now = Utc::now();
        let window = Duration::from_std(self.config.rate_window).unwrap_or(Duration::seconds(60));
        let mut reset_count = 0;

        for mut entry in self.ip_states.iter_mut() {
            let elapsed = now - entry.window_start;
            if elapsed > window {
                entry.reset_window();
                reset_count += 1;
            }
        }

        if reset_count > 0 {
            tracing::debug!("Reset detection windows for {} IPs", reset_count);
        }

        reset_count
    }

    /// Get the detection configuration (read-only).
    pub fn config(&self) -> &DetectionConfig {
        &self.config
    }

    /// Cleanup old entries
    pub fn cleanup(&self, max_age: Duration) -> usize {
        let cutoff = Utc::now() - max_age;
        let mut removed = 0;

        self.ip_states.retain(|_, state| {
            let keep = state.last_seen > cutoff;
            if !keep {
                removed += 1;
            }
            keep
        });

        removed
    }
}

/// Detection statistics (atomic)
#[derive(Debug, Default)]
pub struct DetectionStats {
    pub packets_analyzed: AtomicU64,
    pub attacks_detected: AtomicU64,
    pub ips_blocked: AtomicU64,
    pub false_positives: AtomicU64,
}

/// Detection statistics snapshot
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DetectionStatsSnapshot {
    pub packets_analyzed: u64,
    pub attacks_detected: u64,
    pub ips_blocked: u64,
    pub false_positives: u64,
    pub tracked_ips: usize,
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashSet;

    fn create_test_config() -> DetectionConfig {
        DetectionConfig {
            rps_threshold: 100,
            rps_block_threshold: 500,
            rate_window: std::time::Duration::from_secs(60),
            connection_window: std::time::Duration::from_secs(300),
            max_connections_per_ip: 100,
            syn_flood_threshold: 1000,
            udp_flood_threshold: 5000,
            icmp_flood_threshold: 500,
            slowloris_min_rate: 100,
            track_mac_addresses: true,
            whitelist_ips: HashSet::new(),
            whitelist_cidrs: vec!["127.0.0.0/8".to_string()],
            blacklist_ips: HashSet::new(),
            blacklist_cidrs: vec![],
            block_duration: std::time::Duration::from_secs(3600),
            adaptive_thresholds: false,
            sensitivity: 5,
        }
    }

    fn create_tcp_syn_record(src_ip: IpAddr, dst_ip: IpAddr) -> ConnectionRecord {
        use crate::core::types::TcpFlags;
        ConnectionRecord {
            id: 1,
            timestamp: Utc::now(),
            src_ip,
            dst_ip,
            src_port: Some(12345),
            dst_port: Some(80),
            src_mac: None,
            protocol: Protocol::Tcp,
            tcp_flags: Some(TcpFlags { syn: true, ..Default::default() }),
            packet_size: 64,
            payload_size: 0,
        }
    }

    fn create_udp_record(src_ip: IpAddr, dst_ip: IpAddr) -> ConnectionRecord {
        ConnectionRecord {
            id: 1,
            timestamp: Utc::now(),
            src_ip,
            dst_ip,
            src_port: Some(54321),
            dst_port: Some(53),
            src_mac: None,
            protocol: Protocol::Udp,
            tcp_flags: None,
            packet_size: 128,
            payload_size: 64,
        }
    }

    fn create_icmp_record(src_ip: IpAddr, dst_ip: IpAddr) -> ConnectionRecord {
        ConnectionRecord {
            id: 1,
            timestamp: Utc::now(),
            src_ip,
            dst_ip,
            src_port: None,
            dst_port: None,
            src_mac: None,
            protocol: Protocol::Icmp,
            tcp_flags: None,
            packet_size: 64,
            payload_size: 32,
        }
    }

    fn create_tcp_data_record(src_ip: IpAddr, dst_ip: IpAddr) -> ConnectionRecord {
        use crate::core::types::TcpFlags;
        ConnectionRecord {
            id: 1,
            timestamp: Utc::now(),
            src_ip,
            dst_ip,
            src_port: Some(12345),
            dst_port: Some(80),
            src_mac: None,
            protocol: Protocol::Tcp,
            tcp_flags: Some(TcpFlags { ack: true, psh: true, ..Default::default() }),
            packet_size: 1400,
            payload_size: 1360,
        }
    }

    #[test]
    fn test_detection_result_no_threat() {
        use std::net::Ipv4Addr;

        let result = DetectionResult::no_threat(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1)));
        assert!(!result.is_threat());
        assert!(!result.should_block());
        assert_eq!(result.threat_level, ThreatLevel::None);
    }

    #[test]
    fn test_detection_result_attack() {
        use std::net::Ipv4Addr;

        let result = DetectionResult::attack_detected(
            IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1)),
            AttackType::SynFlood,
            ThreatLevel::Critical,
            1.0,
            "Test attack".to_string(),
        );

        assert!(result.is_threat());
        assert!(result.should_block());
        assert_eq!(result.threat_level, ThreatLevel::Critical);
    }

    #[test]
    fn test_ip_detection_state() {
        use std::net::Ipv4Addr;

        let mut state = IpDetectionState::new(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)));
        state.request_count = 100;

        assert!(state.requests_per_second() >= 0.0);

        state.reset_window();
        assert_eq!(state.request_count, 0);
        assert_eq!(state.syn_count, 0);
        assert_eq!(state.udp_count, 0);
        assert_eq!(state.icmp_count, 0);
        assert_eq!(state.bytes_total, 0);
    }

    #[test]
    fn test_detection_engine_analyze_normal_traffic() {
        use std::net::Ipv4Addr;

        let config = create_test_config();
        let engine = DetectionEngine::new(config);
        let src = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
        let dst = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1));

        // A few packets should not trigger anything
        for _ in 0..5 {
            let record = create_tcp_data_record(src, dst);
            let result = engine.analyze(&record);
            assert!(!result.should_block());
            assert_eq!(result.threat_level, ThreatLevel::None);
        }

        let stats = engine.stats();
        assert_eq!(stats.packets_analyzed, 5);
        assert_eq!(stats.attacks_detected, 0);
        assert_eq!(stats.tracked_ips, 1);
    }

    #[test]
    fn test_detection_engine_syn_counter() {
        use std::net::Ipv4Addr;

        let config = create_test_config();
        let engine = DetectionEngine::new(config);
        let src = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 50));
        let dst = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1));

        // Send SYN packets
        for _ in 0..10 {
            let record = create_tcp_syn_record(src, dst);
            engine.analyze(&record);
        }

        let state = engine.ip_states.get(&src).unwrap();
        assert_eq!(state.syn_count, 10);
        assert_eq!(state.request_count, 10);
    }

    #[test]
    fn test_detection_engine_udp_counter() {
        use std::net::Ipv4Addr;

        let config = create_test_config();
        let engine = DetectionEngine::new(config);
        let src = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 60));
        let dst = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1));

        for _ in 0..20 {
            let record = create_udp_record(src, dst);
            engine.analyze(&record);
        }

        let state = engine.ip_states.get(&src).unwrap();
        assert_eq!(state.udp_count, 20);
        assert_eq!(state.syn_count, 0);
        assert_eq!(state.icmp_count, 0);
    }

    #[test]
    fn test_detection_engine_icmp_counter() {
        use std::net::Ipv4Addr;

        let config = create_test_config();
        let engine = DetectionEngine::new(config);
        let src = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 70));
        let dst = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1));

        for _ in 0..15 {
            let record = create_icmp_record(src, dst);
            engine.analyze(&record);
        }

        let state = engine.ip_states.get(&src).unwrap();
        assert_eq!(state.icmp_count, 15);
        assert_eq!(state.udp_count, 0);
        assert_eq!(state.syn_count, 0);
    }

    #[test]
    fn test_detection_engine_whitelist() {
        use std::net::Ipv4Addr;

        let mut config = create_test_config();
        config.whitelist_ips.insert("10.0.0.99".to_string());

        let engine = DetectionEngine::new(config);
        let src = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 99));
        let dst = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1));

        // Even a huge burst should be allowed for whitelisted IPs
        for _ in 0..10_000 {
            let record = create_tcp_syn_record(src, dst);
            let result = engine.analyze(&record);
            assert_eq!(result.threat_level, ThreatLevel::None);
            assert!(!result.should_block());
        }

        // Whitelisted IPs should not appear in ip_states at all
        assert!(engine.ip_states.get(&src).is_none());
    }

    #[test]
    fn test_detection_engine_blacklist() {
        use std::net::Ipv4Addr;

        let mut config = create_test_config();
        config.blacklist_ips.insert("10.0.0.66".to_string());

        let engine = DetectionEngine::new(config);
        let src = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 66));
        let dst = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1));

        let record = create_tcp_data_record(src, dst);
        let result = engine.analyze(&record);

        assert!(result.is_threat());
        assert!(result.should_block());
        assert_eq!(result.threat_level, ThreatLevel::Critical);
        assert_eq!(result.reason, "IP is blacklisted");
    }

    #[test]
    fn test_detection_engine_connection_exhaustion() {
        use std::net::Ipv4Addr;

        let mut config = create_test_config();
        config.max_connections_per_ip = 10;

        let engine = DetectionEngine::new(config);
        let src = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 80));
        let dst = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1));

        // First send a packet so the IP state exists
        let record = create_tcp_data_record(src, dst);
        engine.analyze(&record);

        // Inject a high connection count via the public method
        engine.update_connection_count(src, 50);

        // Now analyze another packet — should trigger connection exhaustion
        let record = create_tcp_data_record(src, dst);
        let result = engine.analyze(&record);

        assert!(result.is_threat());
        assert_eq!(result.attack_types, vec![AttackType::ConnectionExhaustion]);
        assert!(result.threat_level >= ThreatLevel::High);
    }

    #[test]
    fn test_detection_engine_update_connection_count() {
        use std::net::Ipv4Addr;

        let config = create_test_config();
        let engine = DetectionEngine::new(config);
        let ip = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 90));

        // Before the IP is tracked, update should be a no-op
        engine.update_connection_count(ip, 100);
        assert!(engine.ip_states.get(&ip).is_none());

        // Create the state by analyzing a packet
        let record = create_tcp_data_record(ip, IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1)));
        engine.analyze(&record);

        // Now update should work
        engine.update_connection_count(ip, 42);
        let state = engine.ip_states.get(&ip).unwrap();
        assert_eq!(state.connection_count, 42);
    }

    #[test]
    fn test_detection_engine_reset_stale_windows() {
        use std::net::Ipv4Addr;

        // Use a very short window so we can test staleness
        let mut config = create_test_config();
        config.rate_window = std::time::Duration::from_millis(1);

        let engine = DetectionEngine::new(config);
        let src = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 100));
        let dst = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1));

        // Send some packets to create state
        for _ in 0..50 {
            let record = create_tcp_data_record(src, dst);
            engine.analyze(&record);
        }

        assert_eq!(engine.ip_states.get(&src).unwrap().request_count, 50);

        // Wait long enough for the window to be stale
        std::thread::sleep(std::time::Duration::from_millis(5));

        let reset = engine.reset_stale_windows();
        assert_eq!(reset, 1);
        assert_eq!(engine.ip_states.get(&src).unwrap().request_count, 0);
    }

    #[test]
    fn test_detection_engine_cleanup() {
        use std::net::Ipv4Addr;

        let config = create_test_config();
        let engine = DetectionEngine::new(config);

        // Create some IP states
        for i in 1..=5 {
            let src = IpAddr::V4(Ipv4Addr::new(10, 0, 0, i));
            let dst = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1));
            let record = create_tcp_data_record(src, dst);
            engine.analyze(&record);
        }

        assert_eq!(engine.ip_states.len(), 5);

        // Cleanup with zero max_age should remove everything
        let removed = engine.cleanup(Duration::seconds(0));
        assert_eq!(removed, 5);
        assert_eq!(engine.ip_states.len(), 0);
    }

    #[test]
    fn test_detection_engine_cleanup_preserves_recent() {
        use std::net::Ipv4Addr;

        let config = create_test_config();
        let engine = DetectionEngine::new(config);

        for i in 1..=3 {
            let src = IpAddr::V4(Ipv4Addr::new(10, 0, 0, i));
            let dst = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1));
            let record = create_tcp_data_record(src, dst);
            engine.analyze(&record);
        }

        // Cleanup with a generous max_age should keep everything
        let removed = engine.cleanup(Duration::hours(1));
        assert_eq!(removed, 0);
        assert_eq!(engine.ip_states.len(), 3);
    }

    #[test]
    fn test_detection_engine_stats() {
        use std::net::Ipv4Addr;

        let config = create_test_config();
        let engine = DetectionEngine::new(config);

        let stats = engine.stats();
        assert_eq!(stats.packets_analyzed, 0);
        assert_eq!(stats.attacks_detected, 0);
        assert_eq!(stats.tracked_ips, 0);

        let src = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
        let dst = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1));
        for _ in 0..10 {
            let record = create_tcp_data_record(src, dst);
            engine.analyze(&record);
        }

        let stats = engine.stats();
        assert_eq!(stats.packets_analyzed, 10);
        assert_eq!(stats.tracked_ips, 1);
    }

    #[test]
    fn test_detection_engine_config_accessor() {
        let config = create_test_config();
        let engine = DetectionEngine::new(config);
        assert_eq!(engine.config().rps_threshold, 100);
        assert_eq!(engine.config().rps_block_threshold, 500);
        assert_eq!(engine.config().syn_flood_threshold, 1000);
        assert_eq!(engine.config().udp_flood_threshold, 5000);
        assert_eq!(engine.config().icmp_flood_threshold, 500);
    }

    #[test]
    fn test_detection_engine_multiple_ips() {
        use std::net::Ipv4Addr;

        let config = create_test_config();
        let engine = DetectionEngine::new(config);
        let dst = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1));

        // Three different source IPs
        for i in 1..=3 {
            let src = IpAddr::V4(Ipv4Addr::new(10, 0, 0, i));
            for _ in 0..5 {
                let record = create_tcp_data_record(src, dst);
                engine.analyze(&record);
            }
        }

        assert_eq!(engine.ip_states.len(), 3);
        assert_eq!(engine.stats().packets_analyzed, 15);

        let tracked = engine.tracked_ips();
        assert_eq!(tracked.len(), 3);
    }

    #[test]
    fn test_detection_engine_clear_ip_state() {
        use std::net::Ipv4Addr;

        let config = create_test_config();
        let engine = DetectionEngine::new(config);

        let src = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
        let dst = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1));
        let record = create_tcp_data_record(src, dst);
        engine.analyze(&record);

        assert_eq!(engine.ip_states.len(), 1);

        engine.clear_ip_state(&src);
        assert_eq!(engine.ip_states.len(), 0);
    }

    #[test]
    fn test_ip_detection_state_window_duration() {
        use std::net::Ipv4Addr;

        let mut state = IpDetectionState::new(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)));

        // When window_start == last_seen, duration is 0
        assert_eq!(state.window_duration_secs(), 0.0);

        // Simulate time passing
        state.last_seen = state.window_start + Duration::seconds(30);
        assert!((state.window_duration_secs() - 30.0).abs() < 0.01);
    }
}
