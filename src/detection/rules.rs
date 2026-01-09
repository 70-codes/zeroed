//! Detection rules module
//!
//! This module defines the rule-based detection system for the Zeroed daemon.
//! Rules can be configured to match specific traffic patterns and trigger actions.

use crate::core::types::{Action, Protocol, ThreatLevel};
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
    /// Check if the criteria matches an IP address
    pub fn matches_ip(&self, ip: &IpAddr) -> bool {
        // TODO: Implement CIDR matching
        if let Some(ref src) = self.src_ip {
            if src != &ip.to_string() {
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
}
