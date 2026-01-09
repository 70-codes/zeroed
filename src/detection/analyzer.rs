//! Traffic analyzer module for pattern detection
//!
//! This module provides traffic pattern analysis functionality
//! for detecting potential DoS/DDoS attacks.

use crate::core::types::{AttackType, ConnectionRecord, ThreatLevel};
use chrono::{DateTime, Utc};
use std::collections::HashMap;
use std::net::IpAddr;

/// Traffic analyzer for detecting attack patterns
pub struct TrafficAnalyzer {
    /// Analysis window in seconds
    window_secs: u64,
    /// Minimum samples required for analysis
    min_samples: usize,
}

impl TrafficAnalyzer {
    /// Create a new traffic analyzer
    pub fn new(window_secs: u64, min_samples: usize) -> Self {
        Self {
            window_secs,
            min_samples,
        }
    }

    /// Analyze traffic patterns for a given IP
    pub fn analyze_patterns(&self, records: &[ConnectionRecord]) -> AnalysisResult {
        if records.len() < self.min_samples {
            return AnalysisResult::insufficient_data();
        }

        let mut result = AnalysisResult::default();

        // Analyze request rate
        result.request_rate = self.calculate_request_rate(records);

        // Analyze port distribution
        result.port_entropy = self.calculate_port_entropy(records);

        // Analyze packet sizes
        result.avg_packet_size = self.calculate_avg_packet_size(records);

        // Detect specific patterns
        result.patterns = self.detect_patterns(records);

        result
    }

    /// Calculate request rate (requests per second)
    fn calculate_request_rate(&self, records: &[ConnectionRecord]) -> f64 {
        if records.len() < 2 {
            return records.len() as f64;
        }

        let first = records.first().map(|r| r.timestamp).unwrap();
        let last = records.last().map(|r| r.timestamp).unwrap();
        let duration = (last - first).num_seconds() as f64;

        if duration > 0.0 {
            records.len() as f64 / duration
        } else {
            records.len() as f64
        }
    }

    /// Calculate entropy of destination port distribution
    fn calculate_port_entropy(&self, records: &[ConnectionRecord]) -> f64 {
        let mut port_counts: HashMap<u16, usize> = HashMap::new();

        for record in records {
            if let Some(port) = record.dst_port {
                *port_counts.entry(port).or_insert(0) += 1;
            }
        }

        if port_counts.is_empty() {
            return 0.0;
        }

        let total = records.len() as f64;
        let mut entropy = 0.0;

        for count in port_counts.values() {
            let p = *count as f64 / total;
            if p > 0.0 {
                entropy -= p * p.log2();
            }
        }

        entropy
    }

    /// Calculate average packet size
    fn calculate_avg_packet_size(&self, records: &[ConnectionRecord]) -> f64 {
        if records.is_empty() {
            return 0.0;
        }

        let total: u64 = records.iter().map(|r| r.packet_size as u64).sum();
        total as f64 / records.len() as f64
    }

    /// Detect specific attack patterns
    fn detect_patterns(&self, records: &[ConnectionRecord]) -> Vec<DetectedPattern> {
        let mut patterns = Vec::new();

        // Check for SYN flood pattern
        let syn_count = records
            .iter()
            .filter(|r| r.tcp_flags.map(|f| f.is_syn_only()).unwrap_or(false))
            .count();

        if syn_count as f64 / records.len() as f64 > 0.8 {
            patterns.push(DetectedPattern {
                pattern_type: AttackType::SynFlood,
                confidence: syn_count as f64 / records.len() as f64,
                description: "High ratio of SYN-only packets".to_string(),
            });
        }

        // Check for port scan pattern (high port entropy)
        let port_entropy = self.calculate_port_entropy(records);
        if port_entropy > 4.0 {
            patterns.push(DetectedPattern {
                pattern_type: AttackType::Unknown,
                confidence: (port_entropy / 8.0).min(1.0),
                description: "Possible port scan detected".to_string(),
            });
        }

        patterns
    }
}

impl Default for TrafficAnalyzer {
    fn default() -> Self {
        Self::new(60, 10)
    }
}

/// Result of traffic analysis
#[derive(Debug, Clone, Default)]
pub struct AnalysisResult {
    /// Request rate (requests per second)
    pub request_rate: f64,
    /// Port distribution entropy
    pub port_entropy: f64,
    /// Average packet size
    pub avg_packet_size: f64,
    /// Detected patterns
    pub patterns: Vec<DetectedPattern>,
    /// Whether there was sufficient data
    pub sufficient_data: bool,
}

impl AnalysisResult {
    /// Create result indicating insufficient data
    pub fn insufficient_data() -> Self {
        Self {
            sufficient_data: false,
            ..Default::default()
        }
    }
}

/// A detected attack pattern
#[derive(Debug, Clone)]
pub struct DetectedPattern {
    /// Type of attack pattern
    pub pattern_type: AttackType,
    /// Confidence score (0.0 - 1.0)
    pub confidence: f64,
    /// Human-readable description
    pub description: String,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_traffic_analyzer_creation() {
        let analyzer = TrafficAnalyzer::new(60, 10);
        assert_eq!(analyzer.window_secs, 60);
        assert_eq!(analyzer.min_samples, 10);
    }

    #[test]
    fn test_insufficient_data() {
        let analyzer = TrafficAnalyzer::new(60, 10);
        let records: Vec<ConnectionRecord> = vec![];
        let result = analyzer.analyze_patterns(&records);
        assert!(!result.sufficient_data);
    }
}
