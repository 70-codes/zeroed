//! Configuration module for the Zeroed daemon
//!
//! This module defines all configuration structures used throughout the application.
//! Configuration can be loaded from TOML files and supports hot-reloading.

use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use std::net::IpAddr;
use std::path::PathBuf;
use std::time::Duration;

/// Main configuration structure for the Zeroed daemon
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ZeroedConfig {
    /// General daemon settings
    #[serde(default)]
    pub daemon: DaemonConfig,

    /// Network monitoring configuration
    #[serde(default)]
    pub network: NetworkConfig,

    /// Detection and rate limiting settings
    #[serde(default)]
    pub detection: DetectionConfig,

    /// Storage configuration for the custom file system
    #[serde(default)]
    pub storage: StorageConfig,

    /// GeoIP lookup configuration
    #[serde(default)]
    pub geoip: GeoIpConfig,

    /// Firewall integration settings
    #[serde(default)]
    pub firewall: FirewallConfig,

    /// Logging configuration
    #[serde(default)]
    pub logging: LoggingConfig,

    /// API and control interface settings
    #[serde(default)]
    pub api: ApiConfig,

    /// Metrics and monitoring
    #[serde(default)]
    pub metrics: MetricsConfig,

    /// Application deployment management
    #[serde(default)]
    pub deploy: DeployConfig,
}

impl Default for ZeroedConfig {
    fn default() -> Self {
        Self {
            daemon: DaemonConfig::default(),
            network: NetworkConfig::default(),
            detection: DetectionConfig::default(),
            storage: StorageConfig::default(),
            geoip: GeoIpConfig::default(),
            firewall: FirewallConfig::default(),
            logging: LoggingConfig::default(),
            api: ApiConfig::default(),
            metrics: MetricsConfig::default(),
            deploy: DeployConfig::default(),
        }
    }
}

/// Daemon process settings
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DaemonConfig {
    /// Path to PID file
    pub pid_file: PathBuf,

    /// User to run as after dropping privileges
    pub user: Option<String>,

    /// Group to run as after dropping privileges
    pub group: Option<String>,

    /// Working directory for the daemon
    pub working_dir: PathBuf,

    /// Enable daemon mode (background process)
    pub daemonize: bool,

    /// Number of worker threads (0 = auto-detect based on CPU cores)
    pub worker_threads: usize,

    /// Maximum memory usage in MB (0 = unlimited)
    pub max_memory_mb: usize,
}

impl Default for DaemonConfig {
    fn default() -> Self {
        Self {
            pid_file: PathBuf::from("/var/run/zeroed/zeroed.pid"),
            user: Some("zeroed".to_string()),
            group: Some("zeroed".to_string()),
            working_dir: PathBuf::from("/var/lib/zeroed"),
            daemonize: true,
            worker_threads: 0, // Auto-detect
            max_memory_mb: 512,
        }
    }
}

/// Network monitoring configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkConfig {
    /// Network interfaces to monitor (empty = all interfaces)
    pub interfaces: Vec<String>,

    /// Enable promiscuous mode for packet capture
    pub promiscuous: bool,

    /// Packet capture buffer size in MB
    pub capture_buffer_mb: usize,

    /// BPF filter expression for packet capture
    pub bpf_filter: Option<String>,

    /// Ports to monitor (empty = all ports)
    pub monitored_ports: Vec<u16>,

    /// Enable IPv6 monitoring
    pub enable_ipv6: bool,

    /// Snapshot length for packet capture
    pub snap_len: i32,

    /// Packet capture timeout in milliseconds
    pub capture_timeout_ms: i32,
}

impl Default for NetworkConfig {
    fn default() -> Self {
        Self {
            interfaces: vec![],
            promiscuous: true,
            capture_buffer_mb: 64,
            bpf_filter: None,
            monitored_ports: vec![80, 443, 22, 53, 25, 3306, 5432],
            enable_ipv6: true,
            snap_len: 65535,
            capture_timeout_ms: 1000,
        }
    }
}

/// Detection and rate limiting configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DetectionConfig {
    /// Requests per second threshold per IP (triggers alert)
    pub rps_threshold: u32,

    /// Requests per second threshold per IP (triggers block)
    pub rps_block_threshold: u32,

    /// Time window for rate calculation in seconds
    #[serde(with = "humantime_serde")]
    pub rate_window: Duration,

    /// Connection tracking window
    #[serde(with = "humantime_serde")]
    pub connection_window: Duration,

    /// Maximum concurrent connections per IP
    pub max_connections_per_ip: u32,

    /// SYN flood detection threshold (SYN packets per second)
    pub syn_flood_threshold: u32,

    /// UDP flood detection threshold (packets per second)
    pub udp_flood_threshold: u32,

    /// ICMP flood detection threshold (packets per second)
    pub icmp_flood_threshold: u32,

    /// Slowloris detection: minimum data rate in bytes/sec
    pub slowloris_min_rate: u32,

    /// Enable MAC address tracking
    pub track_mac_addresses: bool,

    /// Whitelisted IP addresses (never blocked)
    pub whitelist_ips: HashSet<String>,

    /// Whitelisted CIDR ranges
    pub whitelist_cidrs: Vec<String>,

    /// Blacklisted IP addresses (always blocked)
    pub blacklist_ips: HashSet<String>,

    /// Blacklisted CIDR ranges
    pub blacklist_cidrs: Vec<String>,

    /// Auto-block duration for detected attackers
    #[serde(with = "humantime_serde")]
    pub block_duration: Duration,

    /// Enable adaptive thresholds based on historical data
    pub adaptive_thresholds: bool,

    /// Sensitivity level: 1 (low) to 10 (high)
    pub sensitivity: u8,
}

impl Default for DetectionConfig {
    fn default() -> Self {
        Self {
            rps_threshold: 100,
            rps_block_threshold: 500,
            rate_window: Duration::from_secs(60),
            connection_window: Duration::from_secs(300),
            max_connections_per_ip: 100,
            syn_flood_threshold: 1000,
            udp_flood_threshold: 5000,
            icmp_flood_threshold: 500,
            slowloris_min_rate: 100,
            track_mac_addresses: true,
            whitelist_ips: HashSet::new(),
            whitelist_cidrs: vec!["127.0.0.0/8".to_string(), "10.0.0.0/8".to_string()],
            blacklist_ips: HashSet::new(),
            blacklist_cidrs: vec![],
            block_duration: Duration::from_secs(3600), // 1 hour
            adaptive_thresholds: true,
            sensitivity: 5,
        }
    }
}

/// Custom storage file system configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StorageConfig {
    /// Base directory for data storage
    pub data_dir: PathBuf,

    /// Storage format: "binary" (default), "mmap", "ringbuffer"
    pub format: StorageFormat,

    /// Maximum storage size in MB (0 = unlimited)
    pub max_size_mb: usize,

    /// Enable data compression
    pub compression: bool,

    /// Compression level (1-9, higher = more compression)
    pub compression_level: u8,

    /// Time-to-live for stored records
    #[serde(with = "humantime_serde")]
    pub record_ttl: Duration,

    /// Flush interval for in-memory data
    #[serde(with = "humantime_serde")]
    pub flush_interval: Duration,

    /// Number of shards for parallel writes
    pub shard_count: usize,

    /// Enable write-ahead logging for durability
    pub wal_enabled: bool,

    /// Ring buffer size for recent events (number of events)
    pub ring_buffer_size: usize,

    /// Bloom filter false positive rate (0.0 to 1.0)
    pub bloom_fp_rate: f64,

    /// Expected number of unique IPs for bloom filter sizing
    pub expected_unique_ips: usize,
}

impl Default for StorageConfig {
    fn default() -> Self {
        Self {
            data_dir: PathBuf::from("/var/lib/zeroed/data"),
            format: StorageFormat::Binary,
            max_size_mb: 1024, // 1 GB
            compression: true,
            compression_level: 6,
            record_ttl: Duration::from_secs(86400 * 7), // 7 days
            flush_interval: Duration::from_secs(30),
            shard_count: 16,
            wal_enabled: true,
            ring_buffer_size: 100_000,
            bloom_fp_rate: 0.01,
            expected_unique_ips: 1_000_000,
        }
    }
}

/// Storage format options
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum StorageFormat {
    /// Custom binary format (most efficient)
    Binary,
    /// Memory-mapped files (fastest reads)
    Mmap,
    /// Ring buffer (fixed size, oldest data evicted)
    RingBuffer,
}

/// GeoIP lookup configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GeoIpConfig {
    /// Enable GeoIP lookups
    pub enabled: bool,

    /// Path to MaxMind GeoLite2 database
    pub database_path: PathBuf,

    /// Auto-update GeoIP database
    pub auto_update: bool,

    /// Update check interval
    #[serde(with = "humantime_serde")]
    pub update_interval: Duration,

    /// MaxMind license key for updates (optional)
    pub license_key: Option<String>,

    /// Cache size for GeoIP lookups
    pub cache_size: usize,

    /// Blocked countries (ISO 3166-1 alpha-2 codes)
    pub blocked_countries: HashSet<String>,

    /// Allowed countries (if set, only these are allowed)
    pub allowed_countries: HashSet<String>,

    /// Suspicious regions requiring extra scrutiny
    pub suspicious_regions: HashSet<String>,
}

impl Default for GeoIpConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            database_path: PathBuf::from("/var/lib/zeroed/GeoLite2-City.mmdb"),
            auto_update: false,
            update_interval: Duration::from_secs(86400 * 7), // Weekly
            license_key: None,
            cache_size: 10_000,
            blocked_countries: HashSet::new(),
            allowed_countries: HashSet::new(),
            suspicious_regions: HashSet::new(),
        }
    }
}

/// Firewall integration configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FirewallConfig {
    /// Enable automatic firewall rule management
    pub enabled: bool,

    /// Firewall backend: "iptables", "nftables", "ipset"
    pub backend: FirewallBackend,

    /// Chain name for zeroed rules
    pub chain_name: String,

    /// Table name for zeroed rules
    pub table_name: String,

    /// IPSet name for blocked IPs (when using ipset)
    pub ipset_name: String,

    /// Use ipset for efficient large blocklists
    pub use_ipset: bool,

    /// Maximum number of firewall rules
    pub max_rules: usize,

    /// Dry run mode (log but don't apply rules)
    pub dry_run: bool,
}

impl Default for FirewallConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            backend: FirewallBackend::Iptables,
            chain_name: "ZEROED".to_string(),
            table_name: "filter".to_string(),
            ipset_name: "zeroed_blocklist".to_string(),
            use_ipset: true,
            max_rules: 10_000,
            dry_run: false,
        }
    }
}

/// Firewall backend options
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum FirewallBackend {
    Iptables,
    Nftables,
    Ipset,
}

/// Logging configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LoggingConfig {
    /// Log level: "trace", "debug", "info", "warn", "error"
    pub level: String,

    /// Log output: "stdout", "stderr", "file", "syslog"
    pub output: LogOutput,

    /// Log file path (when output = "file")
    pub file_path: PathBuf,

    /// Enable JSON formatted logs
    pub json_format: bool,

    /// Maximum log file size in MB before rotation
    pub max_file_size_mb: usize,

    /// Number of rotated log files to keep
    pub max_files: usize,

    /// Include source location in logs
    pub include_location: bool,

    /// Log security events to separate file
    pub security_log_path: Option<PathBuf>,
}

impl Default for LoggingConfig {
    fn default() -> Self {
        Self {
            level: "info".to_string(),
            output: LogOutput::File,
            file_path: PathBuf::from("/var/log/zeroed/zeroed.log"),
            json_format: false,
            max_file_size_mb: 100,
            max_files: 10,
            include_location: false,
            security_log_path: Some(PathBuf::from("/var/log/zeroed/security.log")),
        }
    }
}

/// Log output options
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum LogOutput {
    Stdout,
    Stderr,
    File,
    Syslog,
}

/// API and control interface configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApiConfig {
    /// Enable control API
    pub enabled: bool,

    /// Unix socket path for local control
    pub socket_path: PathBuf,

    /// Enable HTTP REST API
    pub http_enabled: bool,

    /// HTTP API bind address
    pub http_bind: String,

    /// HTTP API port
    pub http_port: u16,

    /// Enable TLS for HTTP API
    pub tls_enabled: bool,

    /// TLS certificate path
    pub tls_cert_path: Option<PathBuf>,

    /// TLS key path
    pub tls_key_path: Option<PathBuf>,

    /// API authentication token (required for HTTP)
    pub auth_token: Option<String>,

    /// Allowed client IPs for API access
    pub allowed_clients: Vec<String>,
}

impl Default for ApiConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            socket_path: PathBuf::from("/var/run/zeroed/zeroed.sock"),
            http_enabled: false,
            http_bind: "127.0.0.1".to_string(),
            http_port: 8080,
            tls_enabled: false,
            tls_cert_path: None,
            tls_key_path: None,
            auth_token: None,
            allowed_clients: vec!["127.0.0.1".to_string()],
        }
    }
}

/// Metrics and monitoring configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MetricsConfig {
    /// Enable metrics collection
    pub enabled: bool,

    /// Enable Prometheus exporter
    pub prometheus_enabled: bool,

    /// Prometheus exporter bind address
    pub prometheus_bind: String,

    /// Prometheus exporter port
    pub prometheus_port: u16,

    /// Metrics collection interval
    #[serde(with = "humantime_serde")]
    pub collection_interval: Duration,

    /// Enable internal statistics
    pub internal_stats: bool,
}

impl Default for MetricsConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            prometheus_enabled: true,
            prometheus_bind: "0.0.0.0".to_string(),
            prometheus_port: 9090,
            collection_interval: Duration::from_secs(10),
            internal_stats: true,
        }
    }
}

/// Helper module for duration serialization
mod humantime_serde {
    use serde::{Deserialize, Deserializer, Serializer};
    use std::time::Duration;

    pub fn serialize<S>(duration: &Duration, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_u64(duration.as_secs())
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<Duration, D::Error>
    where
        D: Deserializer<'de>,
    {
        let secs = u64::deserialize(deserializer)?;
        Ok(Duration::from_secs(secs))
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Deployment Management Configuration
// ─────────────────────────────────────────────────────────────────────────────

/// Configuration for the application deployment management subsystem.
///
/// This is included in the main `zeroed.toml` under the `[deploy]` section.
/// The deploy subsystem is optional — the daemon's core DoS protection
/// functions work without it.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeployConfig {
    /// Whether the deployment subsystem is enabled
    #[serde(default = "default_true")]
    pub enabled: bool,

    /// Base directory for all managed applications
    #[serde(default = "default_apps_dir")]
    pub apps_dir: PathBuf,

    /// Directory for storing SSH keys
    #[serde(default = "default_ssh_keys_dir")]
    pub ssh_keys_dir: PathBuf,

    /// Nginx sites-available directory
    #[serde(default = "default_nginx_sites_dir")]
    pub nginx_sites_dir: PathBuf,

    /// Nginx sites-enabled directory
    #[serde(default = "default_nginx_enabled_dir")]
    pub nginx_enabled_dir: PathBuf,

    /// Directory for systemd unit files
    #[serde(default = "default_systemd_units_dir")]
    pub systemd_units_dir: PathBuf,

    /// Directory where SSL certificates are stored (e.g. /etc/letsencrypt/live)
    #[serde(default = "default_ssl_certs_dir")]
    pub ssl_certs_dir: PathBuf,

    /// Email address for ACME / Let's Encrypt account registration
    #[serde(default)]
    pub acme_email: String,

    /// Start of the port range available for application allocation
    #[serde(default = "default_port_range_start")]
    pub default_port_range_start: u16,

    /// End of the port range available for application allocation
    #[serde(default = "default_port_range_end")]
    pub default_port_range_end: u16,

    /// Maximum number of managed applications
    #[serde(default = "default_max_apps")]
    pub max_apps: usize,

    /// Maximum number of deploy history records to keep per app
    #[serde(default = "default_max_deploy_history")]
    pub max_deploy_history: usize,

    /// Timeout in seconds for build steps
    #[serde(default = "default_build_timeout_secs")]
    pub build_timeout_secs: u64,

    /// Timeout in seconds for health check probes after deploy
    #[serde(default = "default_health_check_timeout_secs")]
    pub health_check_timeout_secs: u64,

    /// Number of health check retries before marking a deploy as failed
    #[serde(default = "default_health_check_retries")]
    pub health_check_retries: u32,

    /// Path to the application registry file
    #[serde(default = "default_registry_path")]
    pub registry_path: PathBuf,
}

impl Default for DeployConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            apps_dir: PathBuf::from("/var/lib/zeroed/apps"),
            ssh_keys_dir: PathBuf::from("/var/lib/zeroed/ssh/keys"),
            nginx_sites_dir: PathBuf::from("/etc/nginx/sites-available"),
            nginx_enabled_dir: PathBuf::from("/etc/nginx/sites-enabled"),
            systemd_units_dir: PathBuf::from("/etc/systemd/system"),
            ssl_certs_dir: PathBuf::from("/etc/letsencrypt/live"),
            acme_email: String::new(),
            default_port_range_start: 3000,
            default_port_range_end: 9999,
            max_apps: 100,
            max_deploy_history: 10,
            build_timeout_secs: 600,
            health_check_timeout_secs: 30,
            health_check_retries: 5,
            registry_path: PathBuf::from("/var/lib/zeroed/deploy/registry.toml"),
        }
    }
}

// Serde default value helper functions for DeployConfig
fn default_true() -> bool { true }
fn default_apps_dir() -> PathBuf { PathBuf::from("/var/lib/zeroed/apps") }
fn default_ssh_keys_dir() -> PathBuf { PathBuf::from("/var/lib/zeroed/ssh/keys") }
fn default_nginx_sites_dir() -> PathBuf { PathBuf::from("/etc/nginx/sites-available") }
fn default_nginx_enabled_dir() -> PathBuf { PathBuf::from("/etc/nginx/sites-enabled") }
fn default_systemd_units_dir() -> PathBuf { PathBuf::from("/etc/systemd/system") }
fn default_ssl_certs_dir() -> PathBuf { PathBuf::from("/etc/letsencrypt/live") }
fn default_port_range_start() -> u16 { 3000 }
fn default_port_range_end() -> u16 { 9999 }
fn default_max_apps() -> usize { 100 }
fn default_max_deploy_history() -> usize { 10 }
fn default_build_timeout_secs() -> u64 { 600 }
fn default_health_check_timeout_secs() -> u64 { 30 }
fn default_health_check_retries() -> u32 { 5 }
fn default_registry_path() -> PathBuf { PathBuf::from("/var/lib/zeroed/deploy/registry.toml") }

impl ZeroedConfig {
    /// Load configuration from a TOML file
    pub fn from_file(path: &PathBuf) -> Result<Self, ConfigError> {
        let content =
            std::fs::read_to_string(path).map_err(|e| ConfigError::IoError(e.to_string()))?;

        let config: ZeroedConfig =
            toml::from_str(&content).map_err(|e| ConfigError::ParseError(e.to_string()))?;

        config.validate()?;
        Ok(config)
    }

    /// Load configuration from a string
    pub fn from_str(content: &str) -> Result<Self, ConfigError> {
        let config: ZeroedConfig =
            toml::from_str(content).map_err(|e| ConfigError::ParseError(e.to_string()))?;

        config.validate()?;
        Ok(config)
    }

    /// Validate configuration values
    pub fn validate(&self) -> Result<(), ConfigError> {
        // Validate detection thresholds
        if self.detection.rps_threshold >= self.detection.rps_block_threshold {
            return Err(ConfigError::ValidationError(
                "rps_threshold must be less than rps_block_threshold".to_string(),
            ));
        }

        // Validate sensitivity
        if self.detection.sensitivity < 1 || self.detection.sensitivity > 10 {
            return Err(ConfigError::ValidationError(
                "sensitivity must be between 1 and 10".to_string(),
            ));
        }

        // Validate storage settings
        if self.storage.bloom_fp_rate <= 0.0 || self.storage.bloom_fp_rate >= 1.0 {
            return Err(ConfigError::ValidationError(
                "bloom_fp_rate must be between 0.0 and 1.0".to_string(),
            ));
        }

        // Validate compression level
        if self.storage.compression && self.storage.compression_level > 9 {
            return Err(ConfigError::ValidationError(
                "compression_level must be between 1 and 9".to_string(),
            ));
        }

        Ok(())
    }

    /// Save configuration to a TOML file
    pub fn save(&self, path: &PathBuf) -> Result<(), ConfigError> {
        let content =
            toml::to_string_pretty(self).map_err(|e| ConfigError::SerializeError(e.to_string()))?;

        std::fs::write(path, content).map_err(|e| ConfigError::IoError(e.to_string()))?;

        Ok(())
    }

    /// Create default configuration file
    pub fn create_default_file(path: &PathBuf) -> Result<(), ConfigError> {
        let config = Self::default();
        config.save(path)
    }
}

/// Configuration errors
#[derive(Debug, thiserror::Error)]
pub enum ConfigError {
    #[error("IO error: {0}")]
    IoError(String),

    #[error("Parse error: {0}")]
    ParseError(String),

    #[error("Validation error: {0}")]
    ValidationError(String),

    #[error("Serialization error: {0}")]
    SerializeError(String),
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_config() {
        let config = ZeroedConfig::default();
        assert!(config.validate().is_ok());
    }

    #[test]
    fn test_config_serialization() {
        let config = ZeroedConfig::default();
        let toml_str = toml::to_string_pretty(&config).unwrap();
        let parsed: ZeroedConfig = toml::from_str(&toml_str).unwrap();
        assert!(parsed.validate().is_ok());
    }

    #[test]
    fn test_invalid_thresholds() {
        let mut config = ZeroedConfig::default();
        config.detection.rps_threshold = 1000;
        config.detection.rps_block_threshold = 100;
        assert!(config.validate().is_err());
    }
}
