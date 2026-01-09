//! API and Control Interface module for the Zeroed daemon
//!
//! This module provides various interfaces for controlling and monitoring
//! the Zeroed DoS protection daemon:
//!
//! - Unix socket interface for local control (zeroctl)
//! - HTTP REST API for remote management
//! - Prometheus metrics endpoint
//!
//! ## Architecture
//!
//! ```text
//! ┌─────────────────────────────────────────────────────────────────┐
//! │                        API Module                                │
//! ├─────────────────┬─────────────────────┬─────────────────────────┤
//! │  Unix Socket    │    HTTP REST API    │   Prometheus Metrics    │
//! │  (zeroctl)      │    (optional)       │   (optional)            │
//! ├─────────────────┴─────────────────────┴─────────────────────────┤
//! │                    Command Handler                               │
//! ├─────────────────────────────────────────────────────────────────┤
//! │                    Daemon Core                                   │
//! └─────────────────────────────────────────────────────────────────┘
//! ```

// Sub-modules (to be implemented)
// pub mod commands;
// pub mod http;
// pub mod metrics;
// pub mod socket;

use serde::{Deserialize, Serialize};

/// API request types
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "command", content = "params")]
pub enum ApiRequest {
    /// Get daemon status
    Status,
    /// Get statistics
    Stats,
    /// List blocked IPs
    ListBlocked { limit: Option<usize> },
    /// List tracked IPs
    ListTracked { limit: Option<usize> },
    /// Block an IP manually
    BlockIp { ip: String, duration: Option<u64> },
    /// Unblock an IP
    UnblockIp { ip: String },
    /// Add IP to whitelist
    WhitelistAdd { ip: String },
    /// Remove IP from whitelist
    WhitelistRemove { ip: String },
    /// Get configuration
    GetConfig,
    /// Reload configuration
    ReloadConfig,
    /// Flush storage
    FlushStorage,
    /// Get recent events
    RecentEvents { count: Option<usize> },
    /// Shutdown daemon
    Shutdown,
}

/// API response types
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "status")]
pub enum ApiResponse {
    /// Successful response with data
    Success { data: serde_json::Value },
    /// Error response
    Error { code: u32, message: String },
}

impl ApiResponse {
    /// Create a success response
    pub fn success<T: Serialize>(data: T) -> Self {
        ApiResponse::Success {
            data: serde_json::to_value(data).unwrap_or(serde_json::Value::Null),
        }
    }

    /// Create an error response
    pub fn error(code: u32, message: impl Into<String>) -> Self {
        ApiResponse::Error {
            code,
            message: message.into(),
        }
    }
}

/// Status information returned by the daemon
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DaemonStatus {
    /// Daemon version
    pub version: String,
    /// Uptime in seconds
    pub uptime_secs: u64,
    /// Number of tracked IPs
    pub tracked_ips: u64,
    /// Number of blocked IPs
    pub blocked_ips: u64,
    /// Total packets processed
    pub packets_processed: u64,
    /// Total bytes processed
    pub bytes_processed: u64,
    /// Current packets per second
    pub packets_per_second: f64,
    /// Memory usage in bytes
    pub memory_usage: u64,
    /// Monitored interfaces
    pub interfaces: Vec<String>,
    /// Whether firewall is enabled
    pub firewall_enabled: bool,
    /// Storage stats
    pub storage_records: u64,
}

/// Error codes for API responses
pub mod error_codes {
    pub const INVALID_REQUEST: u32 = 400;
    pub const UNAUTHORIZED: u32 = 401;
    pub const FORBIDDEN: u32 = 403;
    pub const NOT_FOUND: u32 = 404;
    pub const INTERNAL_ERROR: u32 = 500;
    pub const SERVICE_UNAVAILABLE: u32 = 503;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_api_response_success() {
        let response = ApiResponse::success("test data");
        match response {
            ApiResponse::Success { data } => {
                assert_eq!(data.as_str(), Some("test data"));
            }
            _ => panic!("Expected success response"),
        }
    }

    #[test]
    fn test_api_response_error() {
        let response = ApiResponse::error(400, "Bad request");
        match response {
            ApiResponse::Error { code, message } => {
                assert_eq!(code, 400);
                assert_eq!(message, "Bad request");
            }
            _ => panic!("Expected error response"),
        }
    }
}
