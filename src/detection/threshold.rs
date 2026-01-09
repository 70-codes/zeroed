//! Threshold management for detection rules
//!
//! This module provides adaptive and static threshold management for
//! the detection engine. It supports both fixed thresholds and adaptive
//! thresholds that learn from historical traffic patterns.

use crate::core::config::DetectionConfig;
use chrono::{DateTime, Utc};
use parking_lot::RwLock;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::hash::Hash;

/// Threshold types
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum ThresholdType {
    /// Requests per second
    RequestsPerSecond,
    /// SYN packets per second
    SynRate,
    /// UDP packets per second
    UdpRate,
    /// ICMP packets per second
    IcmpRate,
    /// Concurrent connections
    Connections,
    /// Bytes per second
    Bandwidth,
    /// Unique ports accessed
    PortScan,
}

/// A threshold value with optional adaptivity
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Threshold {
    /// Threshold type
    pub threshold_type: ThresholdType,
    /// Base/static threshold value
    pub base_value: f64,
    /// Current adaptive threshold (if enabled)
    pub adaptive_value: Option<f64>,
    /// Warning threshold (percentage of block threshold)
    pub warning_ratio: f64,
    /// Whether adaptive thresholds are enabled
    pub adaptive_enabled: bool,
    /// Minimum allowed threshold
    pub min_value: f64,
    /// Maximum allowed threshold
    pub max_value: f64,
}

impl Threshold {
    /// Create a new threshold
    pub fn new(threshold_type: ThresholdType, base_value: f64) -> Self {
        Self {
            threshold_type,
            base_value,
            adaptive_value: None,
            warning_ratio: 0.5,
            adaptive_enabled: false,
            min_value: base_value * 0.1,
            max_value: base_value * 10.0,
        }
    }

    /// Create an adaptive threshold
    pub fn adaptive(threshold_type: ThresholdType, base_value: f64) -> Self {
        Self {
            threshold_type,
            base_value,
            adaptive_value: Some(base_value),
            warning_ratio: 0.5,
            adaptive_enabled: true,
            min_value: base_value * 0.1,
            max_value: base_value * 10.0,
        }
    }

    /// Get the current effective threshold
    pub fn effective_value(&self) -> f64 {
        self.adaptive_value.unwrap_or(self.base_value)
    }

    /// Get the warning threshold
    pub fn warning_value(&self) -> f64 {
        self.effective_value() * self.warning_ratio
    }

    /// Check if a value exceeds the threshold
    pub fn exceeds(&self, value: f64) -> bool {
        value > self.effective_value()
    }

    /// Check if a value exceeds the warning threshold
    pub fn exceeds_warning(&self, value: f64) -> bool {
        value > self.warning_value()
    }

    /// Update adaptive threshold based on observed value
    pub fn update_adaptive(&mut self, observed: f64, learning_rate: f64) {
        if !self.adaptive_enabled {
            return;
        }

        let current = self.adaptive_value.unwrap_or(self.base_value);

        // Exponential moving average
        let new_value = current * (1.0 - learning_rate) + observed * learning_rate;

        // Clamp to min/max
        let clamped = new_value.clamp(self.min_value, self.max_value);

        self.adaptive_value = Some(clamped);
    }

    /// Reset adaptive threshold to base value
    pub fn reset_adaptive(&mut self) {
        if self.adaptive_enabled {
            self.adaptive_value = Some(self.base_value);
        }
    }
}

/// Threshold manager that handles all detection thresholds
pub struct ThresholdManager {
    /// All thresholds
    thresholds: RwLock<HashMap<ThresholdType, Threshold>>,
    /// Historical statistics for adaptive learning
    history: RwLock<ThresholdHistory>,
    /// Whether adaptive mode is enabled globally
    adaptive_enabled: bool,
    /// Sensitivity level (1-10)
    sensitivity: u8,
}

impl ThresholdManager {
    /// Create a new threshold manager from config
    pub fn new(config: &DetectionConfig) -> Self {
        let mut thresholds = HashMap::new();

        // Create thresholds from config
        let rps = if config.adaptive_thresholds {
            Threshold::adaptive(
                ThresholdType::RequestsPerSecond,
                config.rps_block_threshold as f64,
            )
        } else {
            Threshold::new(
                ThresholdType::RequestsPerSecond,
                config.rps_block_threshold as f64,
            )
        };
        thresholds.insert(ThresholdType::RequestsPerSecond, rps);

        let syn = if config.adaptive_thresholds {
            Threshold::adaptive(ThresholdType::SynRate, config.syn_flood_threshold as f64)
        } else {
            Threshold::new(ThresholdType::SynRate, config.syn_flood_threshold as f64)
        };
        thresholds.insert(ThresholdType::SynRate, syn);

        let udp = if config.adaptive_thresholds {
            Threshold::adaptive(ThresholdType::UdpRate, config.udp_flood_threshold as f64)
        } else {
            Threshold::new(ThresholdType::UdpRate, config.udp_flood_threshold as f64)
        };
        thresholds.insert(ThresholdType::UdpRate, udp);

        let icmp = if config.adaptive_thresholds {
            Threshold::adaptive(ThresholdType::IcmpRate, config.icmp_flood_threshold as f64)
        } else {
            Threshold::new(ThresholdType::IcmpRate, config.icmp_flood_threshold as f64)
        };
        thresholds.insert(ThresholdType::IcmpRate, icmp);

        let conn = Threshold::new(
            ThresholdType::Connections,
            config.max_connections_per_ip as f64,
        );
        thresholds.insert(ThresholdType::Connections, conn);

        Self {
            thresholds: RwLock::new(thresholds),
            history: RwLock::new(ThresholdHistory::default()),
            adaptive_enabled: config.adaptive_thresholds,
            sensitivity: config.sensitivity,
        }
    }

    /// Get a threshold by type
    pub fn get(&self, threshold_type: ThresholdType) -> Option<Threshold> {
        self.thresholds.read().get(&threshold_type).cloned()
    }

    /// Get effective threshold value
    pub fn get_value(&self, threshold_type: ThresholdType) -> f64 {
        self.thresholds
            .read()
            .get(&threshold_type)
            .map(|t| t.effective_value())
            .unwrap_or(f64::MAX)
    }

    /// Check if a value exceeds threshold
    pub fn check(&self, threshold_type: ThresholdType, value: f64) -> ThresholdResult {
        let thresholds = self.thresholds.read();

        if let Some(threshold) = thresholds.get(&threshold_type) {
            if threshold.exceeds(value) {
                ThresholdResult::Exceeded {
                    value,
                    threshold: threshold.effective_value(),
                    ratio: value / threshold.effective_value(),
                }
            } else if threshold.exceeds_warning(value) {
                ThresholdResult::Warning {
                    value,
                    threshold: threshold.effective_value(),
                    ratio: value / threshold.effective_value(),
                }
            } else {
                ThresholdResult::Normal {
                    value,
                    threshold: threshold.effective_value(),
                    ratio: value / threshold.effective_value(),
                }
            }
        } else {
            ThresholdResult::Unknown
        }
    }

    /// Update threshold with observed value (for adaptive learning)
    pub fn observe(&self, threshold_type: ThresholdType, value: f64) {
        if !self.adaptive_enabled {
            return;
        }

        // Update history
        {
            let mut history = self.history.write();
            history.record(threshold_type, value);
        }

        // Update adaptive threshold
        let learning_rate = 0.01 / self.sensitivity as f64; // Lower sensitivity = faster learning

        let mut thresholds = self.thresholds.write();
        if let Some(threshold) = thresholds.get_mut(&threshold_type) {
            threshold.update_adaptive(value, learning_rate);
        }
    }

    /// Apply sensitivity modifier to a threshold
    pub fn apply_sensitivity(&self, base_threshold: f64) -> f64 {
        // Sensitivity 1 = 2x threshold (less sensitive)
        // Sensitivity 5 = 1x threshold (default)
        // Sensitivity 10 = 0.5x threshold (more sensitive)
        let modifier = 2.0 - (self.sensitivity as f64 - 1.0) * (1.5 / 9.0);
        base_threshold * modifier
    }

    /// Reset all adaptive thresholds
    pub fn reset_adaptive(&self) {
        let mut thresholds = self.thresholds.write();
        for threshold in thresholds.values_mut() {
            threshold.reset_adaptive();
        }
    }

    /// Get all thresholds as a snapshot
    pub fn snapshot(&self) -> HashMap<ThresholdType, Threshold> {
        self.thresholds.read().clone()
    }
}

/// Result of a threshold check
#[derive(Debug, Clone)]
pub enum ThresholdResult {
    /// Value is within normal range
    Normal {
        value: f64,
        threshold: f64,
        ratio: f64,
    },
    /// Value exceeds warning threshold but not block threshold
    Warning {
        value: f64,
        threshold: f64,
        ratio: f64,
    },
    /// Value exceeds block threshold
    Exceeded {
        value: f64,
        threshold: f64,
        ratio: f64,
    },
    /// Threshold type not found
    Unknown,
}

impl ThresholdResult {
    /// Check if threshold was exceeded
    pub fn is_exceeded(&self) -> bool {
        matches!(self, ThresholdResult::Exceeded { .. })
    }

    /// Check if warning threshold was exceeded
    pub fn is_warning(&self) -> bool {
        matches!(
            self,
            ThresholdResult::Warning { .. } | ThresholdResult::Exceeded { .. }
        )
    }

    /// Get the ratio of value to threshold
    pub fn ratio(&self) -> f64 {
        match self {
            ThresholdResult::Normal { ratio, .. } => *ratio,
            ThresholdResult::Warning { ratio, .. } => *ratio,
            ThresholdResult::Exceeded { ratio, .. } => *ratio,
            ThresholdResult::Unknown => 0.0,
        }
    }
}

/// Historical threshold data for adaptive learning
#[derive(Debug, Default)]
struct ThresholdHistory {
    /// Recent observations per threshold type
    observations: HashMap<ThresholdType, Vec<ObservationPoint>>,
    /// Maximum observations to keep
    max_observations: usize,
}

impl ThresholdHistory {
    fn record(&mut self, threshold_type: ThresholdType, value: f64) {
        let observations = self.observations.entry(threshold_type).or_default();

        observations.push(ObservationPoint {
            value,
            timestamp: Utc::now(),
        });

        // Keep only recent observations
        let max = if self.max_observations > 0 {
            self.max_observations
        } else {
            1000
        };

        if observations.len() > max {
            observations.remove(0);
        }
    }
}

/// A single observation point
#[derive(Debug, Clone)]
struct ObservationPoint {
    value: f64,
    timestamp: DateTime<Utc>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_threshold_basic() {
        let threshold = Threshold::new(ThresholdType::RequestsPerSecond, 100.0);

        assert!(!threshold.exceeds(50.0));
        assert!(threshold.exceeds(150.0));
        assert!(threshold.exceeds_warning(60.0)); // 60 > 100 * 0.5
    }

    #[test]
    fn test_threshold_adaptive() {
        let mut threshold = Threshold::adaptive(ThresholdType::RequestsPerSecond, 100.0);

        // Update with higher values
        for _ in 0..10 {
            threshold.update_adaptive(150.0, 0.1);
        }

        // Adaptive value should have increased
        assert!(threshold.effective_value() > 100.0);
    }

    #[test]
    fn test_threshold_result() {
        let result = ThresholdResult::Exceeded {
            value: 150.0,
            threshold: 100.0,
            ratio: 1.5,
        };

        assert!(result.is_exceeded());
        assert!(result.is_warning());
        assert_eq!(result.ratio(), 1.5);
    }
}
