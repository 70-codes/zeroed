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
    Action, AttackType, ConnectionRecord, IpTrackingEntry, ThreatLevel,
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
    /// Connection count
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

    /// Reset window counters
    pub fn reset_window(&mut self) {
        self.request_count = 0;
        self.syn_count = 0;
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

        // Check for SYN flag
        if let Some(flags) = &record.tcp_flags {
            if flags.is_syn_only() {
                state.syn_count += 1;
            }
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
    }
}
