//! Custom error types for the Zeroed daemon
//!
//! This module defines all error types used throughout the application,
//! providing structured error handling with detailed context for debugging.

use std::net::IpAddr;
use std::path::PathBuf;
use thiserror::Error;

/// Main result type used throughout the Zeroed daemon
pub type Result<T> = std::result::Result<T, ZeroedError>;

/// Primary error type for the Zeroed daemon
#[derive(Error, Debug)]
pub enum ZeroedError {
    // ─────────────────────────────────────────────────────────────────────────
    // Configuration Errors
    // ─────────────────────────────────────────────────────────────────────────
    #[error("Configuration error: {0}")]
    Config(#[from] ConfigError),

    // ─────────────────────────────────────────────────────────────────────────
    // Network Errors
    // ─────────────────────────────────────────────────────────────────────────
    #[error("Network error: {0}")]
    Network(#[from] NetworkError),

    // ─────────────────────────────────────────────────────────────────────────
    // Storage Errors
    // ─────────────────────────────────────────────────────────────────────────
    #[error("Storage error: {0}")]
    Storage(#[from] StorageError),

    // ─────────────────────────────────────────────────────────────────────────
    // Detection Errors
    // ─────────────────────────────────────────────────────────────────────────
    #[error("Detection error: {0}")]
    Detection(#[from] DetectionError),

    // ─────────────────────────────────────────────────────────────────────────
    // GeoIP Errors
    // ─────────────────────────────────────────────────────────────────────────
    #[error("GeoIP error: {0}")]
    GeoIP(#[from] GeoIPError),

    // ─────────────────────────────────────────────────────────────────────────
    // Daemon Errors
    // ─────────────────────────────────────────────────────────────────────────
    #[error("Daemon error: {0}")]
    Daemon(#[from] DaemonError),

    // ─────────────────────────────────────────────────────────────────────────
    // Firewall Errors
    // ─────────────────────────────────────────────────────────────────────────
    #[error("Firewall error: {0}")]
    Firewall(#[from] FirewallError),

    // ─────────────────────────────────────────────────────────────────────────
    // API Errors
    // ─────────────────────────────────────────────────────────────────────────
    #[error("API error: {0}")]
    Api(#[from] ApiError),

    // ─────────────────────────────────────────────────────────────────────────
    // Generic Errors
    // ─────────────────────────────────────────────────────────────────────────
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),

    #[error("Internal error: {message}")]
    Internal { message: String },

    #[error("Operation timed out after {duration_ms}ms")]
    Timeout { duration_ms: u64 },

    #[error("Permission denied: {operation}")]
    PermissionDenied { operation: String },

    #[error("Resource exhausted: {resource}")]
    ResourceExhausted { resource: String },
}

/// Configuration-related errors
#[derive(Error, Debug)]
pub enum ConfigError {
    #[error("Configuration file not found: {path}")]
    FileNotFound { path: PathBuf },

    #[error("Failed to parse configuration: {message}")]
    ParseError { message: String },

    #[error("Invalid configuration value for '{key}': {message}")]
    InvalidValue { key: String, message: String },

    #[error("Missing required configuration key: {key}")]
    MissingKey { key: String },

    #[error("Configuration validation failed: {message}")]
    ValidationError { message: String },

    #[error("TOML parsing error: {0}")]
    TomlError(#[from] toml::de::Error),

    #[error("JSON parsing error: {0}")]
    JsonError(#[from] serde_json::Error),
}

/// Network and packet capture errors
#[derive(Error, Debug)]
pub enum NetworkError {
    #[error("Failed to open network interface '{interface}': {message}")]
    InterfaceOpenError { interface: String, message: String },

    #[error("Network interface '{interface}' not found")]
    InterfaceNotFound { interface: String },

    #[error("Packet capture error: {message}")]
    CaptureError { message: String },

    #[error("Failed to parse packet: {message}")]
    PacketParseError { message: String },

    #[error("Invalid MAC address format: {address}")]
    InvalidMacAddress { address: String },

    #[error("Invalid IP address format: {address}")]
    InvalidIpAddress { address: String },

    #[error("Connection tracking error: {message}")]
    ConnectionTrackingError { message: String },

    #[error("Socket error: {message}")]
    SocketError { message: String },

    #[error("Netlink communication error: {message}")]
    NetlinkError { message: String },

    #[error("BPF filter compilation error: {message}")]
    BpfFilterError { message: String },

    #[error("libpcap error: {0}")]
    PcapError(String),
}

/// Storage and file system errors
#[derive(Error, Debug)]
pub enum StorageError {
    #[error("Failed to initialize storage at '{path}': {message}")]
    InitializationError { path: PathBuf, message: String },

    #[error("Storage file corrupted: {path}")]
    CorruptedFile { path: PathBuf },

    #[error("Failed to write record: {message}")]
    WriteError { message: String },

    #[error("Failed to read record: {message}")]
    ReadError { message: String },

    #[error("Memory mapping error: {message}")]
    MmapError { message: String },

    #[error("Index out of bounds: requested {requested}, available {available}")]
    IndexOutOfBounds { requested: usize, available: usize },

    #[error("Storage capacity exceeded: {current}/{max} bytes")]
    CapacityExceeded { current: u64, max: u64 },

    #[error("Failed to rotate log file: {message}")]
    RotationError { message: String },

    #[error("Serialization error: {message}")]
    SerializationError { message: String },

    #[error("Deserialization error: {message}")]
    DeserializationError { message: String },

    #[error("Failed to acquire lock on storage: {message}")]
    LockError { message: String },

    #[error("Checksum mismatch: expected {expected}, got {actual}")]
    ChecksumMismatch { expected: u32, actual: u32 },

    #[error("Write-ahead log error: {message}")]
    WalError { message: String },
}

impl From<crate::storage::wal::WalError> for StorageError {
    fn from(err: crate::storage::wal::WalError) -> Self {
        StorageError::WalError {
            message: err.to_string(),
        }
    }
}

impl From<crate::storage::wal::WalError> for ZeroedError {
    fn from(err: crate::storage::wal::WalError) -> Self {
        ZeroedError::Storage(StorageError::WalError {
            message: err.to_string(),
        })
    }
}

impl From<crate::storage::bloom::BloomFilterError> for StorageError {
    fn from(err: crate::storage::bloom::BloomFilterError) -> Self {
        StorageError::WriteError {
            message: err.to_string(),
        }
    }
}

impl From<crate::storage::bloom::BloomFilterError> for ZeroedError {
    fn from(err: crate::storage::bloom::BloomFilterError) -> Self {
        ZeroedError::Storage(StorageError::WriteError {
            message: err.to_string(),
        })
    }
}

/// Detection and analysis errors
#[derive(Error, Debug)]
pub enum DetectionError {
    #[error("Rate limiter error: {message}")]
    RateLimiterError { message: String },

    #[error("Pattern analysis failed: {message}")]
    PatternAnalysisError { message: String },

    #[error("Bloom filter error: {message}")]
    BloomFilterError { message: String },

    #[error("Threshold configuration error: {message}")]
    ThresholdError { message: String },

    #[error("Anomaly detection failed: {message}")]
    AnomalyDetectionError { message: String },

    #[error("Fingerprint computation error: {message}")]
    FingerprintError { message: String },
}

/// GeoIP lookup errors
#[derive(Error, Debug)]
pub enum GeoIPError {
    #[error("GeoIP database not found at '{path}'")]
    DatabaseNotFound { path: PathBuf },

    #[error("Failed to load GeoIP database: {message}")]
    DatabaseLoadError { message: String },

    #[error("GeoIP lookup failed for IP {ip}: {message}")]
    LookupError { ip: IpAddr, message: String },

    #[error("GeoIP database outdated, last update: {last_update}")]
    DatabaseOutdated { last_update: String },

    #[error("Invalid country code: {code}")]
    InvalidCountryCode { code: String },

    #[error("MaxMind database error: {0}")]
    MaxMindError(#[from] maxminddb::MaxMindDBError),
}

/// Daemon lifecycle errors
#[derive(Error, Debug)]
pub enum DaemonError {
    #[error("Failed to daemonize process: {message}")]
    DaemonizeError { message: String },

    #[error("PID file error at '{path}': {message}")]
    PidFileError { path: PathBuf, message: String },

    #[error("Daemon already running with PID {pid}")]
    AlreadyRunning { pid: u32 },

    #[error("Failed to drop privileges to user '{user}': {message}")]
    PrivilegeDropError { user: String, message: String },

    #[error("Signal handling error: {message}")]
    SignalError { message: String },

    #[error("Failed to create working directory '{path}': {message}")]
    WorkingDirectoryError { path: PathBuf, message: String },

    #[error("Shutdown error: {message}")]
    ShutdownError { message: String },

    #[error("Health check failed: {message}")]
    HealthCheckError { message: String },

    #[error("Resource limit error: {message}")]
    ResourceLimitError { message: String },
}

/// Firewall integration errors
#[derive(Error, Debug)]
pub enum FirewallError {
    #[error("Failed to execute iptables command: {message}")]
    IptablesError { message: String },

    #[error("Failed to execute nftables command: {message}")]
    NftablesError { message: String },

    #[error("Failed to block IP {ip}: {message}")]
    BlockError { ip: IpAddr, message: String },

    #[error("Failed to unblock IP {ip}: {message}")]
    UnblockError { ip: IpAddr, message: String },

    #[error("Failed to create firewall chain '{chain}': {message}")]
    ChainCreationError { chain: String, message: String },

    #[error("Firewall rule conflict: {message}")]
    RuleConflict { message: String },

    #[error("Firewall not available: {message}")]
    NotAvailable { message: String },
}

/// API and control interface errors
#[derive(Error, Debug)]
pub enum ApiError {
    #[error("Failed to bind to socket '{path}': {message}")]
    BindError { path: PathBuf, message: String },

    #[error("Invalid command: {command}")]
    InvalidCommand { command: String },

    #[error("Authentication failed: {message}")]
    AuthenticationError { message: String },

    #[error("Rate limit exceeded for client")]
    RateLimitExceeded,

    #[error("Invalid request format: {message}")]
    InvalidRequest { message: String },

    #[error("Response serialization error: {message}")]
    ResponseError { message: String },

    #[error("Connection closed unexpectedly")]
    ConnectionClosed,
}

// ─────────────────────────────────────────────────────────────────────────────
// Error conversion implementations
// ─────────────────────────────────────────────────────────────────────────────

impl From<bincode::Error> for StorageError {
    fn from(err: bincode::Error) -> Self {
        StorageError::SerializationError {
            message: err.to_string(),
        }
    }
}

impl From<bincode::Error> for ZeroedError {
    fn from(err: bincode::Error) -> Self {
        ZeroedError::Storage(StorageError::from(err))
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Error context extension trait
// ─────────────────────────────────────────────────────────────────────────────

/// Extension trait for adding context to errors
pub trait ErrorContext<T> {
    /// Add context to an error
    fn context(self, message: impl Into<String>) -> Result<T>;

    /// Add context with a closure (lazy evaluation)
    fn with_context<F, M>(self, f: F) -> Result<T>
    where
        F: FnOnce() -> M,
        M: Into<String>;
}

impl<T, E: Into<ZeroedError>> ErrorContext<T> for std::result::Result<T, E> {
    fn context(self, message: impl Into<String>) -> Result<T> {
        self.map_err(|e| {
            let base_error = e.into();
            ZeroedError::Internal {
                message: format!("{}: {}", message.into(), base_error),
            }
        })
    }

    fn with_context<F, M>(self, f: F) -> Result<T>
    where
        F: FnOnce() -> M,
        M: Into<String>,
    {
        self.map_err(|e| {
            let base_error = e.into();
            ZeroedError::Internal {
                message: format!("{}: {}", f().into(), base_error),
            }
        })
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Error severity levels for logging and alerting
// ─────────────────────────────────────────────────────────────────────────────

/// Severity level of an error for alerting purposes
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum ErrorSeverity {
    /// Informational, no action needed
    Info,
    /// Warning, should be monitored
    Warning,
    /// Error, requires attention
    Error,
    /// Critical, immediate action required
    Critical,
}

impl ZeroedError {
    /// Get the severity level of this error
    pub fn severity(&self) -> ErrorSeverity {
        match self {
            ZeroedError::Config(_) => ErrorSeverity::Critical,
            ZeroedError::Network(e) => match e {
                NetworkError::InterfaceNotFound { .. } => ErrorSeverity::Critical,
                NetworkError::PacketParseError { .. } => ErrorSeverity::Warning,
                _ => ErrorSeverity::Error,
            },
            ZeroedError::Storage(e) => match e {
                StorageError::CorruptedFile { .. } => ErrorSeverity::Critical,
                StorageError::CapacityExceeded { .. } => ErrorSeverity::Warning,
                _ => ErrorSeverity::Error,
            },
            ZeroedError::Detection(_) => ErrorSeverity::Warning,
            ZeroedError::GeoIP(_) => ErrorSeverity::Warning,
            ZeroedError::Daemon(e) => match e {
                DaemonError::AlreadyRunning { .. } => ErrorSeverity::Critical,
                DaemonError::PrivilegeDropError { .. } => ErrorSeverity::Critical,
                _ => ErrorSeverity::Error,
            },
            ZeroedError::Firewall(_) => ErrorSeverity::Error,
            ZeroedError::Api(_) => ErrorSeverity::Warning,
            ZeroedError::Io(_) => ErrorSeverity::Error,
            ZeroedError::Internal { .. } => ErrorSeverity::Error,
            ZeroedError::Timeout { .. } => ErrorSeverity::Warning,
            ZeroedError::PermissionDenied { .. } => ErrorSeverity::Critical,
            ZeroedError::ResourceExhausted { .. } => ErrorSeverity::Critical,
        }
    }

    /// Check if this error is recoverable
    pub fn is_recoverable(&self) -> bool {
        match self.severity() {
            ErrorSeverity::Info | ErrorSeverity::Warning => true,
            ErrorSeverity::Error => {
                // Some errors are recoverable even at Error level
                matches!(
                    self,
                    ZeroedError::Network(NetworkError::PacketParseError { .. })
                        | ZeroedError::Detection(_)
                        | ZeroedError::Api(_)
                )
            }
            ErrorSeverity::Critical => false,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_error_severity() {
        let err = ZeroedError::Config(ConfigError::FileNotFound {
            path: PathBuf::from("/etc/zeroed/config.toml"),
        });
        assert_eq!(err.severity(), ErrorSeverity::Critical);
        assert!(!err.is_recoverable());
    }

    #[test]
    fn test_error_display() {
        let err = NetworkError::InterfaceNotFound {
            interface: "eth0".to_string(),
        };
        assert!(err.to_string().contains("eth0"));
    }

    #[test]
    fn test_error_conversion() {
        let io_err = std::io::Error::new(std::io::ErrorKind::NotFound, "file not found");
        let zeroed_err: ZeroedError = io_err.into();
        assert!(matches!(zeroed_err, ZeroedError::Io(_)));
    }
}
