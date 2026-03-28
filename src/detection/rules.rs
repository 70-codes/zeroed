//! Detection rules module
//!
//! This module defines the rule-based detection system for the Zeroed daemon.
//! Rules can be configured to match specific traffic patterns and trigger actions.

use crate::core::types::{Action, Protocol, ThreatLevel};
use ipnetwork::IpNetwork;
use serde::{Deserialize, Serialize};
use std::net::IpAddr;

/// A detection rule that matches traffic and triggers an action
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DetectionRule {
    /// Unique rule identifier
    pub id: u64,
    /// Rule name
    pub name: String,
    /// Rule description
    pub description: Option<String>,
    /// Whether the rule is enabled
    pub enabled: bool,
    /// Priority (higher = checked first)
    pub priority: i32,
    /// Matching criteria
    pub criteria: RuleCriteria,
    /// Action to take when rule matches
    pub action: Action,
    /// Threat level to assign when rule matches
    pub threat_level: ThreatLevel,
}

/// Criteria for matching traffic
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct RuleCriteria {
    /// Source IP or CIDR to match
    pub src_ip: Option<String>,
    /// Destination IP or CIDR to match
    pub dst_ip: Option<String>,
    /// Source port or range (min, max)
    pub src_port: Option<(u16, u16)>,
    /// Destination port or range (min, max)
    pub dst_port: Option<(u16, u16)>,
    /// Protocol to match
    pub protocol: Option<Protocol>,
    /// Minimum packets per second to trigger
    pub min_pps: Option<u32>,
    /// Minimum bytes per second to trigger
    pub min_bps: Option<u64>,
    /// Minimum connections to trigger
    pub min_connections: Option<u32>,
    /// Country codes to match
    pub countries: Option<Vec<String>>,
    /// Time range (start_hour, end_hour) in UTC
    pub time_range: Option<(u8, u8)>,
}

impl RuleCriteria {
    /// Check if the criteria matches an IP address.
    ///
    /// Supports both exact IP matching (`"1.2.3.4"`) and CIDR subnet
    /// matching (`"10.0.0.0/8"`, `"192.168.1.0/24"`, etc.).
    /// Uses the `ipnetwork` crate for proper subnet containment checks.
    pub fn matches_ip(&self, ip: &IpAddr) -> bool {
        if let Some(ref src) = self.src_ip {
            if !ip_matches_pattern(ip, src) {
                return false;
            }
        }
        true
    }

    /// Check if the criteria matches a port
    pub fn matches_port(&self, port: u16, is_source: bool) -> bool {
        let range = if is_source {
            &self.src_port
        } else {
            &self.dst_port
        };

        if let Some((min, max)) = range {
            if port < *min || port > *max {
                return false;
            }
        }
        true
    }

    /// Check if the criteria matches a protocol
    pub fn matches_protocol(&self, proto: Protocol) -> bool {
        if let Some(ref required) = self.protocol {
            if *required != proto {
                return false;
            }
        }
        true
    }
}

/// Rule engine for managing and evaluating detection rules
pub struct RuleEngine {
    /// List of rules sorted by priority
    rules: Vec<DetectionRule>,
}

impl RuleEngine {
    /// Create a new rule engine
    pub fn new() -> Self {
        Self { rules: Vec::new() }
    }

    /// Add a rule to the engine
    pub fn add_rule(&mut self, rule: DetectionRule) {
        self.rules.push(rule);
        self.rules.sort_by(|a, b| b.priority.cmp(&a.priority));
    }

    /// Remove a rule by ID
    pub fn remove_rule(&mut self, id: u64) -> Option<DetectionRule> {
        if let Some(pos) = self.rules.iter().position(|r| r.id == id) {
            Some(self.rules.remove(pos))
        } else {
            None
        }
    }

    /// Get all rules
    pub fn rules(&self) -> &[DetectionRule] {
        &self.rules
    }

    /// Enable a rule
    pub fn enable_rule(&mut self, id: u64) -> bool {
        if let Some(rule) = self.rules.iter_mut().find(|r| r.id == id) {
            rule.enabled = true;
            true
        } else {
            false
        }
    }

    /// Disable a rule
    pub fn disable_rule(&mut self, id: u64) -> bool {
        if let Some(rule) = self.rules.iter_mut().find(|r| r.id == id) {
            rule.enabled = false;
            true
        } else {
            false
        }
    }

    /// Evaluate rules against traffic data and return the first matching action
    pub fn evaluate(&self, src_ip: &IpAddr, protocol: Protocol) -> Option<&DetectionRule> {
        for rule in &self.rules {
            if !rule.enabled {
                continue;
            }

            if rule.criteria.matches_ip(src_ip) && rule.criteria.matches_protocol(protocol) {
                return Some(rule);
            }
        }
        None
    }
}

impl Default for RuleEngine {
    fn default() -> Self {
        Self::new()
    }
}

/// Check whether an IP address matches a pattern string.
///
/// The pattern can be:
/// - An exact IP address: `"1.2.3.4"` or `"::1"`
/// - A CIDR subnet: `"10.0.0.0/8"`, `"192.168.0.0/16"`, `"fe80::/10"`
///
/// Returns `true` if the IP is contained within the pattern.
fn ip_matches_pattern(ip: &IpAddr, pattern: &str) -> bool {
    // Try parsing as a CIDR network first (e.g. "10.0.0.0/8")
    if let Ok(network) = pattern.parse::<IpNetwork>() {
        return network.contains(*ip);
    }

    // Fall back to exact IP comparison (e.g. "1.2.3.4")
    if let Ok(pattern_ip) = pattern.parse::<IpAddr>() {
        return *ip == pattern_ip;
    }

    // If it can't be parsed as either, no match
    false
}

/// Check whether an IP address matches any pattern in a list.
///
/// Each entry in the list can be an exact IP or a CIDR subnet.
pub fn ip_matches_any(ip: &IpAddr, patterns: &[String]) -> bool {
    patterns.iter().any(|pattern| ip_matches_pattern(ip, pattern))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_rule_criteria_port_matching() {
        let criteria = RuleCriteria {
            dst_port: Some((80, 443)),
            ..Default::default()
        };

        assert!(criteria.matches_port(80, false));
        assert!(criteria.matches_port(443, false));
        assert!(criteria.matches_port(100, false));
        assert!(!criteria.matches_port(22, false));
    }

    #[test]
    fn test_rule_engine() {
        let mut engine = RuleEngine::new();

        let rule = DetectionRule {
            id: 1,
            name: "Test Rule".to_string(),
            description: None,
            enabled: true,
            priority: 100,
            criteria: RuleCriteria::default(),
            action: Action::Drop,
            threat_level: ThreatLevel::High,
        };

        engine.add_rule(rule);
        assert_eq!(engine.rules().len(), 1);

        engine.disable_rule(1);
        assert!(!engine.rules()[0].enabled);

        engine.remove_rule(1);
        assert!(engine.rules().is_empty());
    }

    // ── CIDR Matching Tests ────────────────────────────────────────────

    #[test]
    fn test_ip_matches_pattern_exact_ipv4() {
        let ip: IpAddr = "192.168.1.100".parse().unwrap();
        assert!(ip_matches_pattern(&ip, "192.168.1.100"));
        assert!(!ip_matches_pattern(&ip, "192.168.1.101"));
    }

    #[test]
    fn test_ip_matches_pattern_exact_ipv6() {
        let ip: IpAddr = "::1".parse().unwrap();
        assert!(ip_matches_pattern(&ip, "::1"));
        assert!(!ip_matches_pattern(&ip, "::2"));
    }

    #[test]
    fn test_ip_matches_pattern_cidr_ipv4() {
        let ip: IpAddr = "10.0.0.50".parse().unwrap();
        assert!(ip_matches_pattern(&ip, "10.0.0.0/8"));
        assert!(ip_matches_pattern(&ip, "10.0.0.0/24"));
        assert!(!ip_matches_pattern(&ip, "192.168.0.0/16"));
    }

    #[test]
    fn test_ip_matches_pattern_cidr_ipv4_slash16() {
        let ip: IpAddr = "172.16.5.10".parse().unwrap();
        assert!(ip_matches_pattern(&ip, "172.16.0.0/12"));
        assert!(ip_matches_pattern(&ip, "172.16.0.0/16"));
        assert!(!ip_matches_pattern(&ip, "172.16.6.0/24"));
    }

    #[test]
    fn test_ip_matches_pattern_cidr_ipv6() {
        let ip: IpAddr = "fe80::1".parse().unwrap();
        assert!(ip_matches_pattern(&ip, "fe80::/10"));
        assert!(!ip_matches_pattern(&ip, "2001:db8::/32"));
    }

    #[test]
    fn test_ip_matches_pattern_single_host_cidr() {
        let ip: IpAddr = "1.2.3.4".parse().unwrap();
        assert!(ip_matches_pattern(&ip, "1.2.3.4/32"));
        assert!(!ip_matches_pattern(&ip, "1.2.3.5/32"));
    }

    #[test]
    fn test_ip_matches_pattern_invalid_pattern() {
        let ip: IpAddr = "10.0.0.1".parse().unwrap();
        assert!(!ip_matches_pattern(&ip, "not-an-ip"));
        assert!(!ip_matches_pattern(&ip, ""));
        assert!(!ip_matches_pattern(&ip, "10.0.0.0/99"));
    }

    #[test]
    fn test_ip_matches_any() {
        let ip: IpAddr = "192.168.1.50".parse().unwrap();
        let patterns = vec![
            "10.0.0.0/8".to_string(),
            "172.16.0.0/12".to_string(),
            "192.168.0.0/16".to_string(),
        ];
        assert!(ip_matches_any(&ip, &patterns));

        let public_ip: IpAddr = "8.8.8.8".parse().unwrap();
        assert!(!ip_matches_any(&public_ip, &patterns));
    }

    #[test]
    fn test_ip_matches_any_empty_list() {
        let ip: IpAddr = "10.0.0.1".parse().unwrap();
        let empty: Vec<String> = vec![];
        assert!(!ip_matches_any(&ip, &empty));
    }

    #[test]
    fn test_ip_matches_any_mixed() {
        let ip: IpAddr = "1.2.3.4".parse().unwrap();
        let patterns = vec![
            "10.0.0.0/8".to_string(),
            "1.2.3.4".to_string(), // exact match
        ];
        assert!(ip_matches_any(&ip, &patterns));
    }

    #[test]
    fn test_rule_criteria_matches_ip_exact() {
        let criteria = RuleCriteria {
            src_ip: Some("1.2.3.4".to_string()),
            ..Default::default()
        };
        let ip: IpAddr = "1.2.3.4".parse().unwrap();
        assert!(criteria.matches_ip(&ip));

        let other: IpAddr = "5.6.7.8".parse().unwrap();
        assert!(!criteria.matches_ip(&other));
    }

    #[test]
    fn test_rule_criteria_matches_ip_cidr() {
        let criteria = RuleCriteria {
            src_ip: Some("10.0.0.0/8".to_string()),
            ..Default::default()
        };
        let inside: IpAddr = "10.255.0.1".parse().unwrap();
        assert!(criteria.matches_ip(&inside));

        let outside: IpAddr = "192.168.1.1".parse().unwrap();
        assert!(!criteria.matches_ip(&outside));
    }

    #[test]
    fn test_rule_criteria_matches_ip_none() {
        // No src_ip set — should match everything
        let criteria = RuleCriteria::default();
        let any_ip: IpAddr = "8.8.8.8".parse().unwrap();
        assert!(criteria.matches_ip(&any_ip));
    }

    #[test]
    fn test_rule_criteria_matches_ip_private_cidrs() {
        let criteria_a = RuleCriteria {
            src_ip: Some("10.0.0.0/8".to_string()),
            ..Default::default()
        };
        let criteria_b = RuleCriteria {
            src_ip: Some("172.16.0.0/12".to_string()),
            ..Default::default()
        };
        let criteria_c = RuleCriteria {
            src_ip: Some("192.168.0.0/16".to_string()),
            ..Default::default()
        };

        let ip_a: IpAddr = "10.1.2.3".parse().unwrap();
        let ip_b: IpAddr = "172.20.5.10".parse().unwrap();
        let ip_c: IpAddr = "192.168.100.1".parse().unwrap();
        let ip_public: IpAddr = "8.8.4.4".parse().unwrap();

        assert!(criteria_a.matches_ip(&ip_a));
        assert!(!criteria_a.matches_ip(&ip_b));

        assert!(criteria_b.matches_ip(&ip_b));
        assert!(!criteria_b.matches_ip(&ip_c));

        assert!(criteria_c.matches_ip(&ip_c));
        assert!(!criteria_c.matches_ip(&ip_public));
    }
}
