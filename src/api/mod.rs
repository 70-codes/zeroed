//! API and Control Interface module for the Zeroed daemon
//!
//! This module provides the Unix socket interface for controlling and monitoring
//! the Zeroed DoS protection daemon via the `zeroctl` command-line tool.
//!
//! ## Architecture
//!
//! ```text
//! ┌─────────────────────────────────────────────────────────────────┐
//! │                        API Module                               │
//! ├─────────────────┬───────────────────────────────────────────────┤
//! │  Unix Socket    │    Command Handler                            │
//! │  (zeroctl)      │    (dispatches to subsystems)                 │
//! ├─────────────────┴───────────────────────────────────────────────┤
//! │                    Daemon Core                                   │
//! │  StorageEngine · DetectionEngine · FirewallManager · NetworkMgr │
//! └─────────────────────────────────────────────────────────────────┘
//! ```
//!
//! ## Wire Protocol
//!
//! The protocol between `zeroctl` and the daemon is:
//!
//! 1. Client connects to the Unix socket
//! 2. Client writes one JSON line (newline-terminated `ApiRequest`)
//! 3. Server reads the line, dispatches to the handler, produces an `ApiResponse`
//! 4. Server writes the full JSON response and closes the connection
//!
//! Each connection handles exactly one request-response pair.

pub mod handler;
pub mod socket;

use serde::{Deserialize, Serialize};

// ─────────────────────────────────────────────────────────────────────────────
// API Request — matches the zeroctl client-side enum exactly
// ─────────────────────────────────────────────────────────────────────────────

/// Request sent from `zeroctl` to the daemon over the Unix socket.
///
/// This enum MUST match the `ApiRequest` enum in `src/bin/zeroctl.rs` exactly,
/// because both sides use `serde_json` with `#[serde(tag = "command", content = "params")]`
/// for serialization.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "command", content = "params")]
pub enum ApiRequest {
    /// Get daemon status (uptime, tracked IPs, blocked IPs, etc.)
    Status,

    /// Get detailed statistics
    Stats {
        detailed: bool,
    },

    /// List currently blocked IPs
    ListBlocked {
        limit: usize,
    },

    /// List tracked IPs (IPs the detection engine is monitoring)
    ListTracked {
        limit: usize,
        sort: String,
    },

    /// List whitelisted IPs
    ListWhitelist,

    /// List blacklisted IPs
    ListBlacklist,

    /// List monitored network interfaces
    ListInterfaces,

    /// List detection rules
    ListRules,

    /// Manually block an IP
    Block {
        ip: String,
        duration: u64,
        reason: Option<String>,
    },

    /// Unblock a currently blocked IP
    Unblock {
        ip: String,
    },

    /// Add an IP to the whitelist
    WhitelistAdd {
        ip: String,
        comment: Option<String>,
    },

    /// Remove an IP from the whitelist
    WhitelistRemove {
        ip: String,
    },

    /// Add an IP to the blacklist
    BlacklistAdd {
        ip: String,
        comment: Option<String>,
    },

    /// Remove an IP from the blacklist
    BlacklistRemove {
        ip: String,
    },

    /// Get recent events/detections
    Events {
        count: usize,
        filter: Option<String>,
    },

    /// Lookup information about a specific IP
    Lookup {
        ip: String,
    },

    /// Flush all blocked IPs (unblock all)
    FlushBlocked,

    /// Flush tracking data
    FlushTracking,

    /// Flush caches
    FlushCache,

    /// Flush everything (blocked + tracking + cache)
    FlushAll,

    /// Reload configuration from disk
    Reload,

    /// Shut down the daemon
    Shutdown {
        force: bool,
    },

    /// Get daemon version
    Version,

    /// Ping the daemon (connectivity check)
    Ping,

    /// Export data (blocked, tracked, config, etc.)
    Export {
        what: String,
    },

    /// Import data
    Import {
        what: String,
        data: String,
    },

    // ─────────────────────────────────────────────────────────────────────
    // Deploy Management Commands
    // ─────────────────────────────────────────────────────────────────────

    /// Create and register a new application
    CreateApp {
        name: String,
        repo_url: String,
        app_type: String,
        port: u16,
        branch: Option<String>,
        ssh_key_id: Option<String>,
        domain: Option<String>,
        build_cmd: Option<String>,
        start_cmd: Option<String>,
        build_dir: Option<String>,
        spa: bool,
    },

    /// Deploy (or redeploy) an application
    DeployApp {
        name: String,
        branch: Option<String>,
        force: bool,
        skip_deps: bool,
        skip_build: bool,
        skip_health_check: bool,
    },

    /// Stop a running application's service
    StopApp {
        name: String,
    },

    /// Start a stopped application's service
    StartApp {
        name: String,
    },

    /// Restart an application's service
    RestartApp {
        name: String,
    },

    /// Delete an application entirely
    DeleteApp {
        name: String,
        force: bool,
    },

    /// Get detailed info about an application
    AppInfo {
        name: String,
    },

    /// List all managed applications
    ListApps,

    /// Get application logs from journalctl
    AppLogs {
        name: String,
        lines: usize,
        since: Option<String>,
    },

    /// Rollback an application to a previous release
    RollbackApp {
        name: String,
        target_id: Option<String>,
    },

    /// List an application's deployment history / releases
    AppReleases {
        name: String,
    },

    /// Change an application's port
    AppSetPort {
        name: String,
        port: u16,
    },

    /// Set or change an application's domain
    AppSetDomain {
        name: String,
        domain: String,
    },

    /// Enable SSL for an application (requires a domain)
    AppEnableSsl {
        name: String,
    },

    /// Disable SSL for an application
    AppDisableSsl {
        name: String,
    },

    /// Show the generated nginx config for an application
    AppNginxShow {
        name: String,
    },

    /// Set an environment variable for an application
    AppEnvSet {
        name: String,
        key: String,
        value: String,
    },

    /// Unset an environment variable for an application
    AppEnvUnset {
        name: String,
        key: String,
    },

    /// List environment variables for an application
    AppEnvList {
        name: String,
    },

    // ─────────────────────────────────────────────────────────────────────
    // SSH Key Management Commands
    // ─────────────────────────────────────────────────────────────────────

    /// Generate a new SSH key
    SshKeyGenerate {
        name: String,
        key_type: Option<String>,
    },

    /// List all managed SSH keys
    SshKeyList,

    /// Delete an SSH key
    SshKeyDelete {
        id: String,
    },

    /// Show the public key for copying to GitHub
    SshKeyShowPublic {
        id: String,
    },

    /// Test SSH connectivity to GitHub with a key
    SshKeyTest {
        id: String,
    },

    // ─────────────────────────────────────────────────────────────────────
    // Port & SSL Commands
    // ─────────────────────────────────────────────────────────────────────

    /// List all allocated ports
    PortsList,

    /// Check if a port is available
    PortCheck {
        port: u16,
    },

    /// List all managed SSL certificates
    SslList,

    /// Check all certificates for expiry
    SslCheck,

    /// Manually renew a certificate
    SslRenew {
        domain: String,
    },
}

// ─────────────────────────────────────────────────────────────────────────────
// API Response
// ─────────────────────────────────────────────────────────────────────────────

/// Response sent from the daemon back to `zeroctl`.
///
/// Uses the same `#[serde(tag = "status")]` discriminant as the client-side enum.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "status")]
pub enum ApiResponse {
    /// Successful response with a JSON payload
    Success { data: serde_json::Value },
    /// Error response with a numeric code and message
    Error { code: u32, message: String },
}

impl ApiResponse {
    /// Create a success response, serializing the given data to JSON.
    pub fn success<T: Serialize>(data: T) -> Self {
        ApiResponse::Success {
            data: serde_json::to_value(data).unwrap_or(serde_json::Value::Null),
        }
    }

    /// Create a success response from a raw `serde_json::Value`.
    pub fn success_raw(data: serde_json::Value) -> Self {
        ApiResponse::Success { data }
    }

    /// Create an error response.
    pub fn error(code: u32, message: impl Into<String>) -> Self {
        ApiResponse::Error {
            code,
            message: message.into(),
        }
    }

    /// Create a "not implemented" error for commands that aren't handled yet.
    pub fn not_implemented(command: &str) -> Self {
        ApiResponse::Error {
            code: error_codes::NOT_IMPLEMENTED,
            message: format!("Command '{}' is not yet implemented", command),
        }
    }

    /// Create an internal server error.
    pub fn internal_error(message: impl Into<String>) -> Self {
        ApiResponse::Error {
            code: error_codes::INTERNAL_ERROR,
            message: message.into(),
        }
    }

    /// Check whether this response indicates success.
    pub fn is_success(&self) -> bool {
        matches!(self, ApiResponse::Success { .. })
    }

    /// Check whether this response indicates an error.
    pub fn is_error(&self) -> bool {
        matches!(self, ApiResponse::Error { .. })
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Status payload returned by the Status command
// ─────────────────────────────────────────────────────────────────────────────

/// Status information returned by the `Status` command.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DaemonStatus {
    /// Daemon version string
    pub version: String,
    /// Uptime in seconds since the daemon started
    pub uptime_secs: u64,
    /// Number of IPs currently tracked by the detection engine
    pub tracked_ips: u64,
    /// Number of IPs currently blocked by the firewall
    pub blocked_ips: u64,
    /// Total number of packets processed since startup
    pub packets_processed: u64,
    /// Total number of attacks detected since startup
    pub attacks_detected: u64,
    /// Memory usage in bytes (from sysinfo)
    pub memory_usage: u64,
    /// List of monitored network interfaces
    pub interfaces: Vec<String>,
    /// Whether the firewall is enabled
    pub firewall_enabled: bool,
    /// Whether the firewall is in dry-run mode
    pub firewall_dry_run: bool,
    /// Total storage records written
    pub storage_records: u64,
}

/// Statistics payload returned by the `Stats` command.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DaemonStats {
    /// Detection engine stats
    pub detection: DetectionStatsPayload,
    /// Firewall stats
    pub firewall: FirewallStatsPayload,
    /// Storage stats
    pub storage: StorageStatsPayload,
    /// Connection tracker stats
    pub connections: ConnectionStatsPayload,
}

/// Detection engine statistics for API response.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DetectionStatsPayload {
    pub packets_analyzed: u64,
    pub attacks_detected: u64,
    pub ips_blocked: u64,
    pub tracked_ips: usize,
}

/// Firewall statistics for API response.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FirewallStatsPayload {
    pub currently_blocked: usize,
    pub total_blocks: u64,
    pub total_unblocks: u64,
    pub total_expired_cleanups: u64,
    pub dry_run: bool,
    pub enabled: bool,
    pub chain_name: String,
}

/// Storage statistics for API response.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StorageStatsPayload {
    pub records_written: u64,
    pub ring_buffer_size: usize,
    pub ip_cache_size: usize,
}

/// Connection tracker statistics for API response.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConnectionStatsPayload {
    pub active_connections: usize,
    pub monitored_interfaces: Vec<String>,
}

/// Blocked IP entry for API response.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BlockedIpInfo {
    pub ip: String,
    pub blocked_at: String,
    pub expires_at: Option<String>,
    pub reason: String,
    pub block_count: u32,
}

/// Tracked IP entry for API response.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TrackedIpInfo {
    pub ip: String,
    pub threat_level: String,
    pub threat_score: f64,
    pub is_blocked: bool,
    pub first_seen: String,
    pub last_seen: String,
    pub request_count: u64,
    pub attack_types: Vec<String>,
}

// ─────────────────────────────────────────────────────────────────────────────
// Error Codes
// ─────────────────────────────────────────────────────────────────────────────

/// Numeric error codes used in `ApiResponse::Error`.
pub mod error_codes {
    /// The request was malformed or invalid
    pub const INVALID_REQUEST: u32 = 400;
    /// Authentication failed
    pub const UNAUTHORIZED: u32 = 401;
    /// The requested resource was not found
    pub const NOT_FOUND: u32 = 404;
    /// The command is not yet implemented
    pub const NOT_IMPLEMENTED: u32 = 501;
    /// An internal server error occurred
    pub const INTERNAL_ERROR: u32 = 500;
    /// The service is temporarily unavailable
    pub const SERVICE_UNAVAILABLE: u32 = 503;
}

// ─────────────────────────────────────────────────────────────────────────────
// Tests
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_api_response_success() {
        let response = ApiResponse::success("test data");
        assert!(response.is_success());
        assert!(!response.is_error());
        match response {
            ApiResponse::Success { data } => {
                assert_eq!(data.as_str(), Some("test data"));
            }
            _ => panic!("Expected success response"),
        }
    }

    #[test]
    fn test_api_response_success_struct() {
        let status = DaemonStatus {
            version: "0.1.0".to_string(),
            uptime_secs: 100,
            tracked_ips: 5,
            blocked_ips: 2,
            packets_processed: 10000,
            attacks_detected: 3,
            memory_usage: 1024 * 1024 * 50,
            interfaces: vec!["eth0".to_string()],
            firewall_enabled: true,
            firewall_dry_run: false,
            storage_records: 5000,
        };

        let response = ApiResponse::success(&status);
        match response {
            ApiResponse::Success { data } => {
                assert_eq!(data["version"], "0.1.0");
                assert_eq!(data["uptime_secs"], 100);
                assert_eq!(data["blocked_ips"], 2);
            }
            _ => panic!("Expected success response"),
        }
    }

    #[test]
    fn test_api_response_error() {
        let response = ApiResponse::error(400, "Bad request");
        assert!(!response.is_success());
        assert!(response.is_error());
        match response {
            ApiResponse::Error { code, message } => {
                assert_eq!(code, 400);
                assert_eq!(message, "Bad request");
            }
            _ => panic!("Expected error response"),
        }
    }

    #[test]
    fn test_api_response_not_implemented() {
        let response = ApiResponse::not_implemented("FancyCommand");
        match response {
            ApiResponse::Error { code, message } => {
                assert_eq!(code, error_codes::NOT_IMPLEMENTED);
                assert!(message.contains("FancyCommand"));
            }
            _ => panic!("Expected error response"),
        }
    }

    #[test]
    fn test_api_response_internal_error() {
        let response = ApiResponse::internal_error("something broke");
        match response {
            ApiResponse::Error { code, message } => {
                assert_eq!(code, error_codes::INTERNAL_ERROR);
                assert_eq!(message, "something broke");
            }
            _ => panic!("Expected error response"),
        }
    }

    #[test]
    fn test_api_request_serialization_roundtrip() {
        let request = ApiRequest::Block {
            ip: "1.2.3.4".to_string(),
            duration: 3600,
            reason: Some("Manual block".to_string()),
        };

        let json = serde_json::to_string(&request).unwrap();
        let deserialized: ApiRequest = serde_json::from_str(&json).unwrap();

        match deserialized {
            ApiRequest::Block { ip, duration, reason } => {
                assert_eq!(ip, "1.2.3.4");
                assert_eq!(duration, 3600);
                assert_eq!(reason, Some("Manual block".to_string()));
            }
            _ => panic!("Expected Block request"),
        }
    }

    #[test]
    fn test_api_request_status_serialization() {
        let request = ApiRequest::Status;
        let json = serde_json::to_string(&request).unwrap();
        assert!(json.contains("Status"));

        let deserialized: ApiRequest = serde_json::from_str(&json).unwrap();
        assert!(matches!(deserialized, ApiRequest::Status));
    }

    #[test]
    fn test_api_request_ping_serialization() {
        let request = ApiRequest::Ping;
        let json = serde_json::to_string(&request).unwrap();
        let deserialized: ApiRequest = serde_json::from_str(&json).unwrap();
        assert!(matches!(deserialized, ApiRequest::Ping));
    }

    #[test]
    fn test_api_request_shutdown_serialization() {
        let request = ApiRequest::Shutdown { force: true };
        let json = serde_json::to_string(&request).unwrap();
        let deserialized: ApiRequest = serde_json::from_str(&json).unwrap();
        match deserialized {
            ApiRequest::Shutdown { force } => assert!(force),
            _ => panic!("Expected Shutdown"),
        }
    }

    #[test]
    fn test_api_request_list_blocked_serialization() {
        let request = ApiRequest::ListBlocked { limit: 50 };
        let json = serde_json::to_string(&request).unwrap();
        let deserialized: ApiRequest = serde_json::from_str(&json).unwrap();
        match deserialized {
            ApiRequest::ListBlocked { limit } => assert_eq!(limit, 50),
            _ => panic!("Expected ListBlocked"),
        }
    }

    #[test]
    fn test_api_request_unblock_serialization() {
        let request = ApiRequest::Unblock {
            ip: "10.0.0.1".to_string(),
        };
        let json = serde_json::to_string(&request).unwrap();
        let deserialized: ApiRequest = serde_json::from_str(&json).unwrap();
        match deserialized {
            ApiRequest::Unblock { ip } => assert_eq!(ip, "10.0.0.1"),
            _ => panic!("Expected Unblock"),
        }
    }

    #[test]
    fn test_api_response_serialization_roundtrip() {
        let response = ApiResponse::success("hello");
        let json = serde_json::to_string(&response).unwrap();
        let deserialized: ApiResponse = serde_json::from_str(&json).unwrap();
        assert!(deserialized.is_success());
    }

    #[test]
    fn test_api_response_error_serialization_roundtrip() {
        let response = ApiResponse::error(404, "Not found");
        let json = serde_json::to_string(&response).unwrap();
        let deserialized: ApiResponse = serde_json::from_str(&json).unwrap();
        match deserialized {
            ApiResponse::Error { code, message } => {
                assert_eq!(code, 404);
                assert_eq!(message, "Not found");
            }
            _ => panic!("Expected error"),
        }
    }

    #[test]
    fn test_daemon_status_serialization() {
        let status = DaemonStatus {
            version: "0.1.0".to_string(),
            uptime_secs: 3600,
            tracked_ips: 100,
            blocked_ips: 5,
            packets_processed: 1_000_000,
            attacks_detected: 42,
            memory_usage: 1024 * 1024 * 128,
            interfaces: vec!["eth0".to_string(), "wlan0".to_string()],
            firewall_enabled: true,
            firewall_dry_run: false,
            storage_records: 500_000,
        };

        let json = serde_json::to_string(&status).unwrap();
        let deserialized: DaemonStatus = serde_json::from_str(&json).unwrap();

        assert_eq!(deserialized.version, "0.1.0");
        assert_eq!(deserialized.uptime_secs, 3600);
        assert_eq!(deserialized.packets_processed, 1_000_000);
        assert_eq!(deserialized.interfaces.len(), 2);
    }

    #[test]
    fn test_blocked_ip_info_serialization() {
        let info = BlockedIpInfo {
            ip: "1.2.3.4".to_string(),
            blocked_at: "2025-01-15T12:00:00Z".to_string(),
            expires_at: Some("2025-01-15T13:00:00Z".to_string()),
            reason: "SYN flood detected".to_string(),
            block_count: 3,
        };

        let json = serde_json::to_string(&info).unwrap();
        let deserialized: BlockedIpInfo = serde_json::from_str(&json).unwrap();

        assert_eq!(deserialized.ip, "1.2.3.4");
        assert_eq!(deserialized.block_count, 3);
        assert!(deserialized.expires_at.is_some());
    }

    #[test]
    fn test_tracked_ip_info_serialization() {
        let info = TrackedIpInfo {
            ip: "10.0.0.1".to_string(),
            threat_level: "High".to_string(),
            threat_score: 0.85,
            is_blocked: true,
            first_seen: "2025-01-15T10:00:00Z".to_string(),
            last_seen: "2025-01-15T12:00:00Z".to_string(),
            request_count: 50000,
            attack_types: vec!["SynFlood".to_string(), "Volumetric".to_string()],
        };

        let json = serde_json::to_string(&info).unwrap();
        let deserialized: TrackedIpInfo = serde_json::from_str(&json).unwrap();

        assert_eq!(deserialized.ip, "10.0.0.1");
        assert_eq!(deserialized.threat_score, 0.85);
        assert_eq!(deserialized.attack_types.len(), 2);
    }

    #[test]
    fn test_daemon_stats_serialization() {
        let stats = DaemonStats {
            detection: DetectionStatsPayload {
                packets_analyzed: 1_000_000,
                attacks_detected: 42,
                ips_blocked: 5,
                tracked_ips: 100,
            },
            firewall: FirewallStatsPayload {
                currently_blocked: 5,
                total_blocks: 20,
                total_unblocks: 15,
                total_expired_cleanups: 10,
                dry_run: false,
                enabled: true,
                chain_name: "ZEROED".to_string(),
            },
            storage: StorageStatsPayload {
                records_written: 500_000,
                ring_buffer_size: 10_000,
                ip_cache_size: 100,
            },
            connections: ConnectionStatsPayload {
                active_connections: 250,
                monitored_interfaces: vec!["eth0".to_string()],
            },
        };

        let json = serde_json::to_string(&stats).unwrap();
        let deserialized: DaemonStats = serde_json::from_str(&json).unwrap();

        assert_eq!(deserialized.detection.packets_analyzed, 1_000_000);
        assert_eq!(deserialized.firewall.currently_blocked, 5);
        assert_eq!(deserialized.storage.records_written, 500_000);
        assert_eq!(deserialized.connections.active_connections, 250);
    }
}
