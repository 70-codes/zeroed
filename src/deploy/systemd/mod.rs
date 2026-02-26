//! Systemd Service & Journalctl Log Management Module
//!
//! This module provides functionality for generating systemd unit files,
//! managing service lifecycles (start/stop/restart/enable/disable), and
//! reading application logs via journalctl.
//!
//! ## Responsibilities
//!
//! - Generate `.service` unit files for backend and hybrid applications
//! - Install unit files to `/etc/systemd/system/` with proper naming
//! - Run `systemctl daemon-reload` after unit file changes
//! - Start, stop, restart, enable, and disable services
//! - Query service status via `systemctl`
//! - Read and stream logs via `journalctl`
//! - Manage environment files for services
//!
//! ## Unit File Naming Convention
//!
//! All generated unit files follow the pattern: `zeroed-app-<name>.service`
//! The syslog identifier is set to `zeroed-app-<name>` for easy log filtering.
//!
//! ## Security
//!
//! Generated unit files include systemd security hardening directives:
//! - `NoNewPrivileges=yes`
//! - `ProtectSystem=strict`
//! - `ProtectHome=yes`
//! - `PrivateTmp=yes`
//! - Resource limits via `MemoryMax` and `CPUQuota`

use crate::deploy::app::{AppType, Application};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fmt;
use std::fs;
use std::io;
use std::path::{Path, PathBuf};
use std::process::Command;
use thiserror::Error;
use tracing::{debug, error, info, warn};

// ─────────────────────────────────────────────────────────────────────────────
// Error Types
// ─────────────────────────────────────────────────────────────────────────────

/// Errors specific to systemd management operations.
#[derive(Debug, Error)]
pub enum SystemdError {
    #[error("IO error: {0}")]
    Io(#[from] io::Error),

    #[error("systemctl is not available on this system")]
    SystemctlNotAvailable,

    #[error("Service '{name}' not found")]
    ServiceNotFound { name: String },

    #[error("Failed to start service '{name}': {message}")]
    StartFailed { name: String, message: String },

    #[error("Failed to stop service '{name}': {message}")]
    StopFailed { name: String, message: String },

    #[error("Failed to restart service '{name}': {message}")]
    RestartFailed { name: String, message: String },

    #[error("Failed to enable service '{name}': {message}")]
    EnableFailed { name: String, message: String },

    #[error("Failed to disable service '{name}': {message}")]
    DisableFailed { name: String, message: String },

    #[error("daemon-reload failed: {message}")]
    DaemonReloadFailed { message: String },

    #[error("Unit file generation error: {message}")]
    UnitFileError { message: String },

    #[error("journalctl error: {message}")]
    JournalError { message: String },

    #[error("Unit file already exists for '{name}' at {path}")]
    UnitFileExists { name: String, path: String },

    #[error("Application '{name}' does not require a systemd service (type: {app_type})")]
    ServiceNotRequired { name: String, app_type: String },
}

/// Result alias for systemd operations.
pub type Result<T> = std::result::Result<T, SystemdError>;

// ─────────────────────────────────────────────────────────────────────────────
// Service Status
// ─────────────────────────────────────────────────────────────────────────────

/// Current status of a systemd service as reported by `systemctl`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum ServiceStatus {
    /// Service is running (active)
    Active,
    /// Service is not running (inactive)
    Inactive,
    /// Service failed to start or crashed
    Failed,
    /// Service is in the process of starting
    Activating,
    /// Service is in the process of stopping
    Deactivating,
    /// Service unit file is not installed
    NotFound,
    /// Status could not be determined
    Unknown,
}

impl ServiceStatus {
    /// Whether the service is considered running/healthy.
    pub fn is_running(&self) -> bool {
        matches!(self, ServiceStatus::Active)
    }

    /// Whether the service is in a failed state.
    pub fn is_failed(&self) -> bool {
        matches!(self, ServiceStatus::Failed)
    }

    /// Whether the service is stopped (but the unit file exists).
    pub fn is_stopped(&self) -> bool {
        matches!(self, ServiceStatus::Inactive)
    }

    /// Whether the unit file exists on the system.
    pub fn is_installed(&self) -> bool {
        !matches!(self, ServiceStatus::NotFound)
    }
}

impl Default for ServiceStatus {
    fn default() -> Self {
        ServiceStatus::Unknown
    }
}

impl fmt::Display for ServiceStatus {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ServiceStatus::Active => write!(f, "active"),
            ServiceStatus::Inactive => write!(f, "inactive"),
            ServiceStatus::Failed => write!(f, "failed"),
            ServiceStatus::Activating => write!(f, "activating"),
            ServiceStatus::Deactivating => write!(f, "deactivating"),
            ServiceStatus::NotFound => write!(f, "not-found"),
            ServiceStatus::Unknown => write!(f, "unknown"),
        }
    }
}

impl From<&str> for ServiceStatus {
    fn from(s: &str) -> Self {
        match s.trim() {
            "active" => ServiceStatus::Active,
            "inactive" => ServiceStatus::Inactive,
            "failed" => ServiceStatus::Failed,
            "activating" => ServiceStatus::Activating,
            "deactivating" => ServiceStatus::Deactivating,
            _ => ServiceStatus::Unknown,
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Service Info (extended status)
// ─────────────────────────────────────────────────────────────────────────────

/// Detailed information about a systemd service, parsed from `systemctl show`.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ServiceInfo {
    /// The unit name (e.g. "zeroed-app-my-api.service")
    pub unit_name: String,
    /// The current active state
    pub status: ServiceStatus,
    /// Whether the unit is enabled (starts on boot)
    pub enabled: bool,
    /// The main PID of the running process (0 if not running)
    pub main_pid: u32,
    /// Memory usage in bytes
    pub memory_bytes: Option<u64>,
    /// CPU usage time in microseconds
    pub cpu_usage_usec: Option<u64>,
    /// Number of restarts triggered by the restart policy
    pub restart_count: u32,
    /// Timestamp when the service last entered active state
    pub active_enter_timestamp: Option<String>,
    /// Timestamp when the service last exited
    pub inactive_enter_timestamp: Option<String>,
    /// The sub-state (e.g. "running", "dead", "exited")
    pub sub_state: String,
    /// Description from the unit file
    pub description: String,
    /// The ExecStart command
    pub exec_start: String,
}

// ─────────────────────────────────────────────────────────────────────────────
// Log Types
// ─────────────────────────────────────────────────────────────────────────────

/// Syslog priority levels.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[repr(u8)]
pub enum LogPriority {
    Emergency = 0,
    Alert = 1,
    Critical = 2,
    Error = 3,
    Warning = 4,
    Notice = 5,
    Info = 6,
    Debug = 7,
}

impl Default for LogPriority {
    fn default() -> Self {
        LogPriority::Info
    }
}

impl fmt::Display for LogPriority {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            LogPriority::Emergency => write!(f, "emerg"),
            LogPriority::Alert => write!(f, "alert"),
            LogPriority::Critical => write!(f, "crit"),
            LogPriority::Error => write!(f, "err"),
            LogPriority::Warning => write!(f, "warning"),
            LogPriority::Notice => write!(f, "notice"),
            LogPriority::Info => write!(f, "info"),
            LogPriority::Debug => write!(f, "debug"),
        }
    }
}

impl From<u8> for LogPriority {
    fn from(value: u8) -> Self {
        match value {
            0 => LogPriority::Emergency,
            1 => LogPriority::Alert,
            2 => LogPriority::Critical,
            3 => LogPriority::Error,
            4 => LogPriority::Warning,
            5 => LogPriority::Notice,
            6 => LogPriority::Info,
            7 => LogPriority::Debug,
            _ => LogPriority::Info,
        }
    }
}

/// A single log line parsed from journalctl output.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LogLine {
    /// Timestamp of the log entry
    pub timestamp: String,
    /// The log message content
    pub message: String,
    /// Syslog priority level
    pub priority: LogPriority,
    /// Hostname
    pub hostname: Option<String>,
    /// Process ID
    pub pid: Option<u32>,
    /// The syslog identifier
    pub syslog_identifier: Option<String>,
}

/// Options for querying logs.
#[derive(Debug, Clone, Default)]
pub struct LogQuery {
    /// Maximum number of lines to return
    pub lines: Option<usize>,
    /// Only return entries since this time (journalctl --since format)
    pub since: Option<String>,
    /// Only return entries until this time (journalctl --until format)
    pub until: Option<String>,
    /// Filter by minimum priority level
    pub priority: Option<LogPriority>,
    /// Grep pattern to filter messages
    pub grep: Option<String>,
    /// Whether to return entries in reverse order (newest first)
    pub reverse: bool,
    /// Output format: "short", "json", "cat"
    pub output_format: Option<String>,
}

// ─────────────────────────────────────────────────────────────────────────────
// Systemd Manager
// ─────────────────────────────────────────────────────────────────────────────

/// Manages systemd service unit files and provides journalctl log access
/// for deployed applications.
///
/// Handles generating unit files, installing them, starting/stopping services,
/// querying status, and reading logs.
pub struct SystemdManager {
    /// Directory where unit files are installed (typically /etc/systemd/system)
    units_dir: PathBuf,

    /// Whether systemctl is available on this system
    systemctl_available: bool,
}

impl SystemdManager {
    /// Create a new systemd manager.
    ///
    /// Checks whether `systemctl` is available on the system.
    pub fn new(units_dir: PathBuf) -> Result<Self> {
        let systemctl_available = Command::new("which")
            .arg("systemctl")
            .output()
            .map(|o| o.status.success())
            .unwrap_or(false);

        if systemctl_available {
            info!(
                "Systemd manager initialized (units dir: {:?})",
                units_dir
            );
        } else {
            warn!("systemctl not found — systemd operations will not work");
        }

        Ok(Self {
            units_dir,
            systemctl_available,
        })
    }

    // ─────────────────────────────────────────────────────────────────────
    // Unit File Generation
    // ─────────────────────────────────────────────────────────────────────

    /// Generate a systemd unit file for the given application.
    ///
    /// Only backend and hybrid applications get a unit file. Static sites
    /// are served directly by Nginx and don't need a systemd service.
    pub fn generate_unit_file(&self, app: &Application) -> Result<String> {
        if !app.app_type.needs_service() {
            return Err(SystemdError::ServiceNotRequired {
                name: app.name.clone(),
                app_type: app.app_type.to_string(),
            });
        }

        let start_command = app.start_command.as_deref().unwrap_or_else(|| {
            warn!(
                "Application '{}' has no start_command — unit file will have a placeholder",
                app.name
            );
            "/bin/false # FIXME: set start_command for this application"
        });

        let memory_limit = app
            .memory_limit_mb
            .map(|mb| format!("{}M", mb))
            .unwrap_or_else(|| "512M".to_string());

        let cpu_quota = app
            .cpu_quota_percent
            .map(|p| format!("{}%", p))
            .unwrap_or_else(|| "100%".to_string());

        let working_dir = app.current_link();
        let env_file_path = app.env_file_path();
        let deploy_dir_str = app.deploy_dir.to_string_lossy();

        let mut env_lines = String::new();
        env_lines.push_str(&format!("Environment=PORT={}\n", app.port));
        env_lines.push_str("Environment=NODE_ENV=production\n");
        for (key, value) in &app.env_vars {
            env_lines.push_str(&format!("Environment={}={}\n", key, value));
        }

        let unit = format!(
            r#"# Generated by zeroed — do not edit manually
# App: {app_name}
# Generated at: {timestamp}

[Unit]
Description=Zeroed Managed App: {display_name}
After=network.target
Wants=network-online.target
StartLimitIntervalSec=60
StartLimitBurst=5

[Service]
Type=simple
User=zeroed
Group=zeroed
WorkingDirectory={working_dir}
ExecStart={start_command}
Restart=on-failure
RestartSec=5

# Environment
{env_lines}EnvironmentFile=-{env_file}

# Security hardening
NoNewPrivileges=yes
PrivateTmp=yes
ProtectSystem=strict
ProtectHome=yes
ProtectKernelTunables=yes
ProtectKernelModules=yes
ProtectControlGroups=yes
RestrictNamespaces=yes
RestrictRealtime=yes
RestrictSUIDSGID=yes
ReadWritePaths={deploy_dir}

# Logging (accessible via journalctl)
StandardOutput=journal
StandardError=journal
SyslogIdentifier={syslog_id}

# Resource limits
LimitNOFILE=65536
MemoryMax={memory_limit}
CPUQuota={cpu_quota}

[Install]
WantedBy=multi-user.target
"#,
            app_name = app.name,
            timestamp = chrono::Utc::now().to_rfc3339(),
            display_name = app.display_name,
            working_dir = working_dir.display(),
            start_command = start_command,
            env_lines = env_lines,
            env_file = env_file_path.display(),
            deploy_dir = deploy_dir_str,
            syslog_id = app.syslog_identifier(),
            memory_limit = memory_limit,
            cpu_quota = cpu_quota,
        );

        Ok(unit)
    }

    // ─────────────────────────────────────────────────────────────────────
    // Unit File Installation
    // ─────────────────────────────────────────────────────────────────────

    /// Install the systemd unit file for the given application.
    ///
    /// Writes the unit file to the units directory and runs `daemon-reload`.
    /// If the service was already running, it is restarted.
    pub fn install_service(&self, app: &Application) -> Result<()> {
        self.require_systemctl()?;

        let unit_content = self.generate_unit_file(app)?;
        let unit_path = self.unit_file_path(&app.service_name());

        // Back up existing unit file if present
        if unit_path.exists() {
            let backup_path = unit_path.with_extension("service.bak");
            fs::copy(&unit_path, &backup_path)?;
            debug!("Backed up existing unit file to {:?}", backup_path);
        }

        // Write the unit file
        fs::write(&unit_path, &unit_content)?;
        info!(
            "Unit file written: {:?} ({} bytes)",
            unit_path,
            unit_content.len()
        );

        // Reload systemd to pick up the new file
        self.daemon_reload()?;

        // Enable the service (start on boot)
        self.enable(&app.service_name())?;

        info!("Service installed: {}", app.service_name());
        Ok(())
    }

    /// Remove the systemd unit file for the given application.
    ///
    /// Stops the service, disables it, removes the unit file, and reloads.
    pub fn remove_service(&self, service_name: &str) -> Result<()> {
        self.require_systemctl()?;

        // Stop the service if running
        let status = self.status(service_name)?;
        if status.is_running() {
            let _ = self.stop(service_name);
        }

        // Disable the service
        let _ = self.disable(service_name);

        // Remove the unit file
        let unit_path = self.unit_file_path(service_name);
        if unit_path.exists() {
            fs::remove_file(&unit_path)?;
            debug!("Removed unit file: {:?}", unit_path);
        }

        // Remove backup if present
        let backup_path = unit_path.with_extension("service.bak");
        if backup_path.exists() {
            let _ = fs::remove_file(&backup_path);
        }

        // Reload systemd
        self.daemon_reload()?;

        info!("Service removed: {}", service_name);
        Ok(())
    }

    /// Update the systemd unit file for an application and restart it.
    pub fn update_service(&self, app: &Application) -> Result<()> {
        self.install_service(app)?;
        self.restart(&app.service_name())?;
        Ok(())
    }

    // ─────────────────────────────────────────────────────────────────────
    // Service Lifecycle
    // ─────────────────────────────────────────────────────────────────────

    /// Start a service.
    pub fn start(&self, service_name: &str) -> Result<()> {
        self.require_systemctl()?;
        self.run_systemctl(&["start", &self.full_unit_name(service_name)], || {
            SystemdError::StartFailed {
                name: service_name.to_string(),
                message: String::new(),
            }
        })
    }

    /// Stop a service.
    pub fn stop(&self, service_name: &str) -> Result<()> {
        self.require_systemctl()?;
        self.run_systemctl(&["stop", &self.full_unit_name(service_name)], || {
            SystemdError::StopFailed {
                name: service_name.to_string(),
                message: String::new(),
            }
        })
    }

    /// Restart a service.
    pub fn restart(&self, service_name: &str) -> Result<()> {
        self.require_systemctl()?;
        self.run_systemctl(&["restart", &self.full_unit_name(service_name)], || {
            SystemdError::RestartFailed {
                name: service_name.to_string(),
                message: String::new(),
            }
        })
    }

    /// Enable a service to start on boot.
    pub fn enable(&self, service_name: &str) -> Result<()> {
        self.require_systemctl()?;
        self.run_systemctl(&["enable", &self.full_unit_name(service_name)], || {
            SystemdError::EnableFailed {
                name: service_name.to_string(),
                message: String::new(),
            }
        })
    }

    /// Disable a service from starting on boot.
    pub fn disable(&self, service_name: &str) -> Result<()> {
        self.require_systemctl()?;
        self.run_systemctl(&["disable", &self.full_unit_name(service_name)], || {
            SystemdError::DisableFailed {
                name: service_name.to_string(),
                message: String::new(),
            }
        })
    }

    /// Run `systemctl daemon-reload` to pick up unit file changes.
    pub fn daemon_reload(&self) -> Result<()> {
        self.require_systemctl()?;
        self.run_systemctl(&["daemon-reload"], || SystemdError::DaemonReloadFailed {
            message: String::new(),
        })
    }

    // ─────────────────────────────────────────────────────────────────────
    // Status Queries
    // ─────────────────────────────────────────────────────────────────────

    /// Get the current status of a service.
    pub fn status(&self, service_name: &str) -> Result<ServiceStatus> {
        self.require_systemctl()?;

        let output = Command::new("systemctl")
            .arg("is-active")
            .arg(&self.full_unit_name(service_name))
            .output()
            .map_err(|e| SystemdError::Io(e))?;

        let status_str = String::from_utf8_lossy(&output.stdout);
        Ok(ServiceStatus::from(status_str.as_ref()))
    }

    /// Check whether a service is currently active (running).
    pub fn is_active(&self, service_name: &str) -> bool {
        self.status(service_name)
            .map(|s| s.is_running())
            .unwrap_or(false)
    }

    /// Check whether a service is enabled (starts on boot).
    pub fn is_enabled(&self, service_name: &str) -> bool {
        if !self.systemctl_available {
            return false;
        }

        Command::new("systemctl")
            .arg("is-enabled")
            .arg(&self.full_unit_name(service_name))
            .output()
            .map(|o| {
                let s = String::from_utf8_lossy(&o.stdout);
                s.trim() == "enabled"
            })
            .unwrap_or(false)
    }

    /// Get detailed service information by parsing `systemctl show`.
    pub fn service_info(&self, service_name: &str) -> Result<ServiceInfo> {
        self.require_systemctl()?;

        let output = Command::new("systemctl")
            .arg("show")
            .arg("--no-pager")
            .arg(&self.full_unit_name(service_name))
            .output()
            .map_err(|e| SystemdError::Io(e))?;

        let stdout = String::from_utf8_lossy(&output.stdout);
        let mut props: HashMap<String, String> = HashMap::new();

        for line in stdout.lines() {
            if let Some((key, value)) = line.split_once('=') {
                props.insert(key.to_string(), value.to_string());
            }
        }

        let active_state = props.get("ActiveState").map(|s| s.as_str()).unwrap_or("unknown");
        let enabled = props
            .get("UnitFileState")
            .map(|s| s == "enabled")
            .unwrap_or(false);

        Ok(ServiceInfo {
            unit_name: self.full_unit_name(service_name),
            status: ServiceStatus::from(active_state),
            enabled,
            main_pid: props
                .get("MainPID")
                .and_then(|s| s.parse().ok())
                .unwrap_or(0),
            memory_bytes: props
                .get("MemoryCurrent")
                .and_then(|s| s.parse().ok()),
            cpu_usage_usec: props
                .get("CPUUsageNSec")
                .and_then(|s| s.parse::<u64>().ok())
                .map(|ns| ns / 1000),
            restart_count: props
                .get("NRestarts")
                .and_then(|s| s.parse().ok())
                .unwrap_or(0),
            active_enter_timestamp: props.get("ActiveEnterTimestamp").cloned(),
            inactive_enter_timestamp: props.get("InactiveEnterTimestamp").cloned(),
            sub_state: props
                .get("SubState")
                .cloned()
                .unwrap_or_else(|| "unknown".to_string()),
            description: props
                .get("Description")
                .cloned()
                .unwrap_or_default(),
            exec_start: props
                .get("ExecStart")
                .cloned()
                .unwrap_or_default(),
        })
    }

    /// Check if a unit file exists for the given service.
    pub fn unit_file_exists(&self, service_name: &str) -> bool {
        self.unit_file_path(service_name).exists()
    }

    /// Get the content of the installed unit file for a service.
    pub fn get_unit_file(&self, service_name: &str) -> Result<String> {
        let path = self.unit_file_path(service_name);
        if !path.exists() {
            return Err(SystemdError::ServiceNotFound {
                name: service_name.to_string(),
            });
        }
        Ok(fs::read_to_string(&path)?)
    }

    /// List all Zeroed-managed service unit files.
    pub fn list_managed_services(&self) -> Result<Vec<String>> {
        let mut services = Vec::new();

        if !self.units_dir.exists() {
            return Ok(services);
        }

        for entry in fs::read_dir(&self.units_dir)? {
            let entry = entry?;
            if let Some(name) = entry.file_name().to_str() {
                if name.starts_with("zeroed-app-") && name.ends_with(".service") {
                    // Strip the .service suffix to return the logical name
                    let logical_name = name.strip_suffix(".service").unwrap_or(name);
                    services.push(logical_name.to_string());
                }
            }
        }

        services.sort();
        Ok(services)
    }

    // ─────────────────────────────────────────────────────────────────────
    // Journalctl Log Access
    // ─────────────────────────────────────────────────────────────────────

    /// Get logs for a service using journalctl.
    ///
    /// Returns parsed log lines filtered by the given query options.
    pub fn get_logs(&self, service_name: &str, query: &LogQuery) -> Result<Vec<LogLine>> {
        let unit = self.full_unit_name(service_name);
        let mut cmd = Command::new("journalctl");

        cmd.arg("-u").arg(&unit);
        cmd.arg("--no-pager");
        cmd.arg("--output").arg("json");

        if let Some(n) = query.lines {
            cmd.arg("-n").arg(n.to_string());
        }

        if let Some(ref since) = query.since {
            cmd.arg("--since").arg(since);
        }

        if let Some(ref until) = query.until {
            cmd.arg("--until").arg(until);
        }

        if let Some(ref priority) = query.priority {
            cmd.arg("-p").arg(format!("{}", *priority as u8));
        }

        if let Some(ref grep) = query.grep {
            cmd.arg("--grep").arg(grep);
        }

        if query.reverse {
            cmd.arg("--reverse");
        }

        let output = cmd.output().map_err(|e| SystemdError::JournalError {
            message: format!("Failed to execute journalctl: {}", e),
        })?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            // journalctl exits with non-zero if there are no entries — that's OK
            if stderr.contains("No entries") || stderr.contains("no entries") {
                return Ok(Vec::new());
            }
            return Err(SystemdError::JournalError {
                message: stderr.trim().to_string(),
            });
        }

        let stdout = String::from_utf8_lossy(&output.stdout);
        let mut lines = Vec::new();

        for json_line in stdout.lines() {
            if json_line.trim().is_empty() {
                continue;
            }
            match serde_json::from_str::<serde_json::Value>(json_line) {
                Ok(entry) => {
                    let log_line = LogLine {
                        timestamp: entry
                            .get("__REALTIME_TIMESTAMP")
                            .or_else(|| entry.get("_SOURCE_REALTIME_TIMESTAMP"))
                            .and_then(|v| v.as_str())
                            .unwrap_or("")
                            .to_string(),
                        message: entry
                            .get("MESSAGE")
                            .and_then(|v| v.as_str())
                            .unwrap_or("")
                            .to_string(),
                        priority: entry
                            .get("PRIORITY")
                            .and_then(|v| v.as_str())
                            .and_then(|s| s.parse::<u8>().ok())
                            .map(LogPriority::from)
                            .unwrap_or(LogPriority::Info),
                        hostname: entry
                            .get("_HOSTNAME")
                            .and_then(|v| v.as_str())
                            .map(String::from),
                        pid: entry
                            .get("_PID")
                            .and_then(|v| v.as_str())
                            .and_then(|s| s.parse().ok()),
                        syslog_identifier: entry
                            .get("SYSLOG_IDENTIFIER")
                            .and_then(|v| v.as_str())
                            .map(String::from),
                    };
                    lines.push(log_line);
                }
                Err(e) => {
                    debug!("Failed to parse journalctl JSON line: {}", e);
                }
            }
        }

        Ok(lines)
    }

    /// Get the last N log lines for a service.
    pub fn tail_logs(&self, service_name: &str, lines: usize) -> Result<Vec<LogLine>> {
        self.get_logs(
            service_name,
            &LogQuery {
                lines: Some(lines),
                reverse: false,
                ..Default::default()
            },
        )
    }

    /// Get logs as plain text (for simpler display or export).
    pub fn get_logs_text(
        &self,
        service_name: &str,
        lines: Option<usize>,
        since: Option<&str>,
    ) -> Result<String> {
        let unit = self.full_unit_name(service_name);
        let mut cmd = Command::new("journalctl");

        cmd.arg("-u").arg(&unit);
        cmd.arg("--no-pager");
        cmd.arg("--output").arg("short-iso");

        if let Some(n) = lines {
            cmd.arg("-n").arg(n.to_string());
        }

        if let Some(s) = since {
            cmd.arg("--since").arg(s);
        }

        let output = cmd.output().map_err(|e| SystemdError::JournalError {
            message: format!("Failed to execute journalctl: {}", e),
        })?;

        Ok(String::from_utf8_lossy(&output.stdout).to_string())
    }

    /// Get the disk usage of logs for a service.
    pub fn log_disk_usage(&self, service_name: &str) -> Result<String> {
        let unit = self.full_unit_name(service_name);

        let output = Command::new("journalctl")
            .arg("-u")
            .arg(&unit)
            .arg("--disk-usage")
            .output()
            .map_err(|e| SystemdError::JournalError {
                message: format!("Failed to execute journalctl: {}", e),
            })?;

        Ok(String::from_utf8_lossy(&output.stdout).trim().to_string())
    }

    // ─────────────────────────────────────────────────────────────────────
    // Environment File Management
    // ─────────────────────────────────────────────────────────────────────

    /// Read environment variables from an application's .env file.
    pub fn read_env_file(path: &Path) -> Result<HashMap<String, String>> {
        let mut env = HashMap::new();

        if !path.exists() {
            return Ok(env);
        }

        let content = fs::read_to_string(path)?;

        for line in content.lines() {
            let trimmed = line.trim();

            // Skip empty lines and comments
            if trimmed.is_empty() || trimmed.starts_with('#') {
                continue;
            }

            if let Some((key, value)) = trimmed.split_once('=') {
                let key = key.trim().to_string();
                let value = value.trim().to_string();
                // Strip surrounding quotes if present
                let value = value
                    .strip_prefix('"')
                    .and_then(|v| v.strip_suffix('"'))
                    .unwrap_or(&value)
                    .to_string();
                let value = value
                    .strip_prefix('\'')
                    .and_then(|v| v.strip_suffix('\''))
                    .unwrap_or(&value)
                    .to_string();
                env.insert(key, value);
            }
        }

        Ok(env)
    }

    /// Write environment variables to an application's .env file.
    pub fn write_env_file(path: &Path, env: &HashMap<String, String>) -> Result<()> {
        // Ensure parent directory exists
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)?;
        }

        let mut content = String::new();
        content.push_str("# Generated by zeroed — environment variables\n");
        content.push_str(&format!(
            "# Last updated: {}\n\n",
            chrono::Utc::now().to_rfc3339()
        ));

        // Sort keys for consistent output
        let mut keys: Vec<&String> = env.keys().collect();
        keys.sort();

        for key in keys {
            if let Some(value) = env.get(key) {
                // Quote values that contain spaces or special characters
                if value.contains(' ')
                    || value.contains('=')
                    || value.contains('#')
                    || value.contains('\'')
                {
                    content.push_str(&format!("{}=\"{}\"\n", key, value.replace('"', "\\\"")));
                } else {
                    content.push_str(&format!("{}={}\n", key, value));
                }
            }
        }

        // Atomic write
        let tmp_path = path.with_extension("env.tmp");
        fs::write(&tmp_path, &content)?;
        fs::rename(&tmp_path, path)?;

        // Set permissions to owner-only read/write
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let _ = fs::set_permissions(path, fs::Permissions::from_mode(0o600));
        }

        debug!("Environment file written: {:?}", path);
        Ok(())
    }

    /// Set a single environment variable in an app's .env file.
    pub fn set_env_var(env_file: &Path, key: &str, value: &str) -> Result<()> {
        let mut env = Self::read_env_file(env_file)?;
        env.insert(key.to_string(), value.to_string());
        Self::write_env_file(env_file, &env)
    }

    /// Remove a single environment variable from an app's .env file.
    pub fn unset_env_var(env_file: &Path, key: &str) -> Result<()> {
        let mut env = Self::read_env_file(env_file)?;
        env.remove(key);
        Self::write_env_file(env_file, &env)
    }

    // ─────────────────────────────────────────────────────────────────────
    // Internal Helpers
    // ─────────────────────────────────────────────────────────────────────

    /// Ensure systemctl is available, returning an error if not.
    fn require_systemctl(&self) -> Result<()> {
        if self.systemctl_available {
            Ok(())
        } else {
            Err(SystemdError::SystemctlNotAvailable)
        }
    }

    /// Get the full unit file path for a service name.
    fn unit_file_path(&self, service_name: &str) -> PathBuf {
        let filename = if service_name.ends_with(".service") {
            service_name.to_string()
        } else {
            format!("{}.service", service_name)
        };
        self.units_dir.join(filename)
    }

    /// Get the full unit name (with .service suffix).
    fn full_unit_name(&self, service_name: &str) -> String {
        if service_name.ends_with(".service") {
            service_name.to_string()
        } else {
            format!("{}.service", service_name)
        }
    }

    /// Run a systemctl command and return Ok(()) on success, or an error.
    fn run_systemctl<F>(&self, args: &[&str], make_error: F) -> Result<()>
    where
        F: FnOnce() -> SystemdError,
    {
        let output = Command::new("systemctl")
            .args(args)
            .output()
            .map_err(|e| SystemdError::Io(e))?;

        if output.status.success() {
            debug!("systemctl {} succeeded", args.join(" "));
            Ok(())
        } else {
            let stderr = String::from_utf8_lossy(&output.stderr).trim().to_string();
            let mut err = make_error();
            // Patch the message into the error variant
            match &mut err {
                SystemdError::StartFailed { message, .. }
                | SystemdError::StopFailed { message, .. }
                | SystemdError::RestartFailed { message, .. }
                | SystemdError::EnableFailed { message, .. }
                | SystemdError::DisableFailed { message, .. }
                | SystemdError::DaemonReloadFailed { message, .. } => {
                    *message = stderr;
                }
                _ => {}
            }
            Err(err)
        }
    }

    /// Get the units directory path.
    pub fn units_dir(&self) -> &Path {
        &self.units_dir
    }

    /// Check whether systemctl is available.
    pub fn is_available(&self) -> bool {
        self.systemctl_available
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Tests
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::deploy::app::{AppStatus, AppType, Application};
    use tempfile::TempDir;

    fn test_app(name: &str, port: u16, apps_dir: &Path) -> Application {
        let mut app = Application::new(
            name.to_string(),
            format!("Test App: {}", name),
            AppType::Backend,
            "git@github.com:user/repo.git".to_string(),
            port,
            apps_dir,
        )
        .unwrap();
        app.start_command = Some("node server.js".to_string());
        app
    }

    fn test_manager(tmp: &TempDir) -> SystemdManager {
        let units_dir = tmp.path().join("systemd-units");
        fs::create_dir_all(&units_dir).unwrap();

        SystemdManager {
            units_dir,
            systemctl_available: false, // Tests run without systemctl
        }
    }

    // ── ServiceStatus Tests ────────────────────────────────────────────

    #[test]
    fn test_service_status_from_str() {
        assert_eq!(ServiceStatus::from("active"), ServiceStatus::Active);
        assert_eq!(ServiceStatus::from("inactive"), ServiceStatus::Inactive);
        assert_eq!(ServiceStatus::from("failed"), ServiceStatus::Failed);
        assert_eq!(ServiceStatus::from("activating"), ServiceStatus::Activating);
        assert_eq!(
            ServiceStatus::from("deactivating"),
            ServiceStatus::Deactivating
        );
        assert_eq!(ServiceStatus::from("garbage"), ServiceStatus::Unknown);
    }

    #[test]
    fn test_service_status_display() {
        assert_eq!(format!("{}", ServiceStatus::Active), "active");
        assert_eq!(format!("{}", ServiceStatus::Inactive), "inactive");
        assert_eq!(format!("{}", ServiceStatus::Failed), "failed");
        assert_eq!(format!("{}", ServiceStatus::NotFound), "not-found");
    }

    #[test]
    fn test_service_status_predicates() {
        assert!(ServiceStatus::Active.is_running());
        assert!(!ServiceStatus::Inactive.is_running());

        assert!(ServiceStatus::Failed.is_failed());
        assert!(!ServiceStatus::Active.is_failed());

        assert!(ServiceStatus::Inactive.is_stopped());

        assert!(ServiceStatus::Active.is_installed());
        assert!(!ServiceStatus::NotFound.is_installed());
    }

    // ── LogPriority Tests ──────────────────────────────────────────────

    #[test]
    fn test_log_priority_display() {
        assert_eq!(format!("{}", LogPriority::Emergency), "emerg");
        assert_eq!(format!("{}", LogPriority::Error), "err");
        assert_eq!(format!("{}", LogPriority::Warning), "warning");
        assert_eq!(format!("{}", LogPriority::Info), "info");
        assert_eq!(format!("{}", LogPriority::Debug), "debug");
    }

    #[test]
    fn test_log_priority_from_u8() {
        assert_eq!(LogPriority::from(0), LogPriority::Emergency);
        assert_eq!(LogPriority::from(3), LogPriority::Error);
        assert_eq!(LogPriority::from(6), LogPriority::Info);
        assert_eq!(LogPriority::from(7), LogPriority::Debug);
        assert_eq!(LogPriority::from(255), LogPriority::Info); // unknown defaults to info
    }

    // ── Unit File Generation Tests ─────────────────────────────────────

    #[test]
    fn test_generate_unit_file_backend() {
        let tmp = TempDir::new().unwrap();
        let manager = test_manager(&tmp);
        let apps_dir = tmp.path().join("apps");

        let app = test_app("my-api", 3000, &apps_dir);
        let unit = manager.generate_unit_file(&app).unwrap();

        assert!(unit.contains("Description=Zeroed Managed App: Test App: my-api"));
        assert!(unit.contains("ExecStart=node server.js"));
        assert!(unit.contains("Environment=PORT=3000"));
        assert!(unit.contains("Environment=NODE_ENV=production"));
        assert!(unit.contains("SyslogIdentifier=zeroed-app-my-api"));
        assert!(unit.contains("NoNewPrivileges=yes"));
        assert!(unit.contains("ProtectSystem=strict"));
        assert!(unit.contains("MemoryMax=512M"));
        assert!(unit.contains("Restart=on-failure"));
        assert!(unit.contains("WantedBy=multi-user.target"));
    }

    #[test]
    fn test_generate_unit_file_with_env_vars() {
        let tmp = TempDir::new().unwrap();
        let manager = test_manager(&tmp);
        let apps_dir = tmp.path().join("apps");

        let mut app = test_app("my-api", 3000, &apps_dir);
        app.env_vars
            .insert("DATABASE_URL".to_string(), "postgres://localhost/mydb".to_string());
        app.env_vars
            .insert("REDIS_URL".to_string(), "redis://localhost".to_string());

        let unit = manager.generate_unit_file(&app).unwrap();
        assert!(unit.contains("Environment=DATABASE_URL=postgres://localhost/mydb"));
        assert!(unit.contains("Environment=REDIS_URL=redis://localhost"));
    }

    #[test]
    fn test_generate_unit_file_with_resource_limits() {
        let tmp = TempDir::new().unwrap();
        let manager = test_manager(&tmp);
        let apps_dir = tmp.path().join("apps");

        let mut app = test_app("heavy-api", 4000, &apps_dir);
        app.memory_limit_mb = Some(2048);
        app.cpu_quota_percent = Some(200);

        let unit = manager.generate_unit_file(&app).unwrap();
        assert!(unit.contains("MemoryMax=2048M"));
        assert!(unit.contains("CPUQuota=200%"));
    }

    #[test]
    fn test_generate_unit_file_static_site_rejected() {
        let tmp = TempDir::new().unwrap();
        let manager = test_manager(&tmp);
        let apps_dir = tmp.path().join("apps");

        let app = Application::new(
            "frontend".to_string(),
            "Frontend".to_string(),
            AppType::StaticSite,
            "git@github.com:user/repo.git".to_string(),
            0,
            &apps_dir,
        )
        .unwrap();

        let result = manager.generate_unit_file(&app);
        assert!(matches!(
            result,
            Err(SystemdError::ServiceNotRequired { .. })
        ));
    }

    #[test]
    fn test_generate_unit_file_no_start_command() {
        let tmp = TempDir::new().unwrap();
        let manager = test_manager(&tmp);
        let apps_dir = tmp.path().join("apps");

        let mut app = Application::new(
            "bare-api".to_string(),
            "Bare API".to_string(),
            AppType::Backend,
            "git@github.com:user/repo.git".to_string(),
            5000,
            &apps_dir,
        )
        .unwrap();
        app.start_command = None;

        let unit = manager.generate_unit_file(&app).unwrap();
        assert!(unit.contains("/bin/false"));
        assert!(unit.contains("FIXME"));
    }

    // ── Unit File Path Tests ───────────────────────────────────────────

    #[test]
    fn test_unit_file_path() {
        let tmp = TempDir::new().unwrap();
        let manager = test_manager(&tmp);

        let path = manager.unit_file_path("zeroed-app-my-api");
        assert!(path
            .to_string_lossy()
            .ends_with("zeroed-app-my-api.service"));

        let path = manager.unit_file_path("zeroed-app-my-api.service");
        assert!(path
            .to_string_lossy()
            .ends_with("zeroed-app-my-api.service"));
        assert!(!path
            .to_string_lossy()
            .ends_with(".service.service"));
    }

    #[test]
    fn test_full_unit_name() {
        let tmp = TempDir::new().unwrap();
        let manager = test_manager(&tmp);

        assert_eq!(
            manager.full_unit_name("zeroed-app-api"),
            "zeroed-app-api.service"
        );
        assert_eq!(
            manager.full_unit_name("zeroed-app-api.service"),
            "zeroed-app-api.service"
        );
    }

    // ── Environment File Tests ─────────────────────────────────────────

    #[test]
    fn test_env_file_roundtrip() {
        let tmp = TempDir::new().unwrap();
        let env_path = tmp.path().join(".env");

        let mut env = HashMap::new();
        env.insert("DATABASE_URL".to_string(), "postgres://localhost/mydb".to_string());
        env.insert("SECRET_KEY".to_string(), "super-secret-123".to_string());
        env.insert("DEBUG".to_string(), "false".to_string());

        SystemdManager::write_env_file(&env_path, &env).unwrap();
        assert!(env_path.exists());

        let loaded = SystemdManager::read_env_file(&env_path).unwrap();
        assert_eq!(loaded.get("DATABASE_URL").unwrap(), "postgres://localhost/mydb");
        assert_eq!(loaded.get("SECRET_KEY").unwrap(), "super-secret-123");
        assert_eq!(loaded.get("DEBUG").unwrap(), "false");
    }

    #[test]
    fn test_env_file_with_quotes() {
        let tmp = TempDir::new().unwrap();
        let env_path = tmp.path().join(".env");

        let mut env = HashMap::new();
        env.insert("MSG".to_string(), "hello world".to_string());

        SystemdManager::write_env_file(&env_path, &env).unwrap();
        let loaded = SystemdManager::read_env_file(&env_path).unwrap();
        assert_eq!(loaded.get("MSG").unwrap(), "hello world");
    }

    #[test]
    fn test_env_file_with_comments() {
        let tmp = TempDir::new().unwrap();
        let env_path = tmp.path().join(".env");

        let content = "# This is a comment\nKEY=value\n\n# Another comment\nFOO=bar\n";
        fs::write(&env_path, content).unwrap();

        let env = SystemdManager::read_env_file(&env_path).unwrap();
        assert_eq!(env.len(), 2);
        assert_eq!(env.get("KEY").unwrap(), "value");
        assert_eq!(env.get("FOO").unwrap(), "bar");
    }

    #[test]
    fn test_env_file_nonexistent() {
        let tmp = TempDir::new().unwrap();
        let env_path = tmp.path().join("nonexistent.env");

        let env = SystemdManager::read_env_file(&env_path).unwrap();
        assert!(env.is_empty());
    }

    #[test]
    fn test_set_env_var() {
        let tmp = TempDir::new().unwrap();
        let env_path = tmp.path().join(".env");

        SystemdManager::set_env_var(&env_path, "KEY1", "value1").unwrap();
        SystemdManager::set_env_var(&env_path, "KEY2", "value2").unwrap();

        let env = SystemdManager::read_env_file(&env_path).unwrap();
        assert_eq!(env.get("KEY1").unwrap(), "value1");
        assert_eq!(env.get("KEY2").unwrap(), "value2");
    }

    #[test]
    fn test_unset_env_var() {
        let tmp = TempDir::new().unwrap();
        let env_path = tmp.path().join(".env");

        let mut env = HashMap::new();
        env.insert("KEEP".to_string(), "yes".to_string());
        env.insert("REMOVE".to_string(), "no".to_string());
        SystemdManager::write_env_file(&env_path, &env).unwrap();

        SystemdManager::unset_env_var(&env_path, "REMOVE").unwrap();

        let loaded = SystemdManager::read_env_file(&env_path).unwrap();
        assert_eq!(loaded.len(), 1);
        assert!(loaded.contains_key("KEEP"));
        assert!(!loaded.contains_key("REMOVE"));
    }

    // ── List Managed Services Test ─────────────────────────────────────

    #[test]
    fn test_list_managed_services() {
        let tmp = TempDir::new().unwrap();
        let manager = test_manager(&tmp);

        fs::write(
            manager.units_dir.join("zeroed-app-api.service"),
            "# api",
        )
        .unwrap();
        fs::write(
            manager.units_dir.join("zeroed-app-web.service"),
            "# web",
        )
        .unwrap();
        fs::write(
            manager.units_dir.join("nginx.service"),
            "# not managed by zeroed",
        )
        .unwrap();

        let services = manager.list_managed_services().unwrap();
        assert_eq!(services.len(), 2);
        assert!(services.contains(&"zeroed-app-api".to_string()));
        assert!(services.contains(&"zeroed-app-web".to_string()));
    }

    #[test]
    fn test_unit_file_exists() {
        let tmp = TempDir::new().unwrap();
        let manager = test_manager(&tmp);

        assert!(!manager.unit_file_exists("zeroed-app-my-api"));

        fs::write(
            manager.units_dir.join("zeroed-app-my-api.service"),
            "# test",
        )
        .unwrap();

        assert!(manager.unit_file_exists("zeroed-app-my-api"));
    }

    #[test]
    fn test_get_unit_file() {
        let tmp = TempDir::new().unwrap();
        let manager = test_manager(&tmp);

        let content = "[Unit]\nDescription=Test\n[Service]\nExecStart=/bin/true\n";
        fs::write(
            manager.units_dir.join("zeroed-app-test.service"),
            content,
        )
        .unwrap();

        let loaded = manager.get_unit_file("zeroed-app-test").unwrap();
        assert_eq!(loaded, content);
    }

    #[test]
    fn test_get_unit_file_not_found() {
        let tmp = TempDir::new().unwrap();
        let manager = test_manager(&tmp);

        let result = manager.get_unit_file("zeroed-app-nonexistent");
        assert!(matches!(result, Err(SystemdError::ServiceNotFound { .. })));
    }

    // ── LogQuery Tests ─────────────────────────────────────────────────

    #[test]
    fn test_log_query_default() {
        let query = LogQuery::default();
        assert!(query.lines.is_none());
        assert!(query.since.is_none());
        assert!(query.until.is_none());
        assert!(query.priority.is_none());
        assert!(query.grep.is_none());
        assert!(!query.reverse);
    }

    // ── LogLine Serialization ──────────────────────────────────────────

    #[test]
    fn test_log_line_serialization() {
        let line = LogLine {
            timestamp: "1704067200000000".to_string(),
            message: "Server started on port 3000".to_string(),
            priority: LogPriority::Info,
            hostname: Some("myserver".to_string()),
            pid: Some(1234),
            syslog_identifier: Some("zeroed-app-my-api".to_string()),
        };

        let json = serde_json::to_string(&line).unwrap();
        let deserialized: LogLine = serde_json::from_str(&json).unwrap();

        assert_eq!(deserialized.message, "Server started on port 3000");
        assert_eq!(deserialized.priority, LogPriority::Info);
        assert_eq!(deserialized.pid, Some(1234));
    }

    // ── ServiceInfo Serialization ──────────────────────────────────────

    #[test]
    fn test_service_info_default() {
        let info = ServiceInfo::default();
        assert_eq!(info.status, ServiceStatus::Unknown);
        assert!(!info.enabled);
        assert_eq!(info.main_pid, 0);
        assert_eq!(info.restart_count, 0);
    }
}
