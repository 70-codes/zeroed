//! Deployment Management Module for the Zeroed Daemon
//!
//! This module provides a complete application deployment and management subsystem
//! that integrates with Nginx, systemd/journalctl, SSL/TLS automation, and GitHub
//! via SSH key management.
//!
//! ## Architecture
//!
//! ```text
//! ┌─────────────────────────────────────────────────────────────────────┐
//! │                        UI / Control Interface                       │
//! │               (zeroctl CLI  ·  HTTP API  ·  Web Dashboard)          │
//! ├──────────┬──────────┬──────────┬──────────┬──────────┬──────────────┤
//! │  SSH Key │  App     │  Nginx   │ Systemd  │  SSL     │  Port        │
//! │  Manager │  Manager │  Engine  │ Engine   │ Manager  │  Allocator   │
//! ├──────────┴──────────┴──────────┴──────────┴──────────┴──────────────┤
//! │                      Deployment Pipeline                            │
//! │        (git clone → build → install → configure → start)            │
//! ├─────────────────────────────────────────────────────────────────────┤
//! │                      Storage & State                                │
//! │            (app registry, deploy history, SSH vault)                 │
//! └─────────────────────────────────────────────────────────────────────┘
//! ```
//!
//! ## Sub-modules
//!
//! - [`ssh`] — SSH key generation, import, storage, and GitHub connectivity
//! - [`app`] — Application model, registry, and lifecycle management
//! - [`nginx`] — Nginx config generation, installation, testing, and reload
//! - [`systemd`] — Systemd unit file generation, service control, and journalctl log access
//! - [`ssl`] — SSL/TLS certificate automation via ACME / Let's Encrypt / certbot
//! - [`ports`] — Port allocation, conflict detection, and reservation
//! - [`pipeline`] — Orchestrated deployment pipeline (clone → build → install → activate)
//!
//! ## Feature Highlights
//!
//! - **Backend apps**: Long-running processes (Node.js, Python, Go, Rust, etc.) managed as
//!   systemd services and reverse-proxied through Nginx.
//! - **Static sites**: Built frontend assets (React, Vue, Angular, Svelte, etc.) served
//!   directly by Nginx with SPA fallback (`try_files $uri $uri/ /index.html`).
//! - **Hybrid apps**: Applications with both a backend service and static frontend assets
//!   (e.g. Next.js with SSR), routed via path-based Nginx configuration.
//! - **SSL automation**: One-command domain + SSL setup with automatic certificate renewal.
//! - **Multi-key SSH**: Multiple SSH keys for different GitHub accounts/orgs, selectable
//!   per-application from the UI/CLI.
//! - **Zero-downtime deploys**: Atomic symlink swap with automatic rollback on health check failure.

pub mod app;
pub mod nginx;
pub mod pipeline;
pub mod ports;
pub mod ssh;
pub mod ssl;
pub mod systemd;

use crate::core::error::{Result, ZeroedError};
use serde::{Deserialize, Serialize};
use std::path::PathBuf;

// ─────────────────────────────────────────────────────────────────────────────
// Re-exports for convenience
// ─────────────────────────────────────────────────────────────────────────────

pub use app::{AppRegistry, AppStatus, AppType, Application};
pub use nginx::NginxManager;
pub use pipeline::DeploymentPipeline;
pub use ports::PortAllocator;
pub use ssh::SshKeyManager;
pub use ssl::SslManager;
pub use systemd::SystemdManager;

// ─────────────────────────────────────────────────────────────────────────────
// Deploy Configuration
// ─────────────────────────────────────────────────────────────────────────────

/// Top-level deployment configuration, included in the main `zeroed.toml`
/// under the `[deploy]` section.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeployConfig {
    /// Whether the deployment subsystem is enabled
    pub enabled: bool,

    /// Base directory for all managed applications
    pub apps_dir: PathBuf,

    /// Directory for storing SSH keys
    pub ssh_keys_dir: PathBuf,

    /// Nginx sites-available directory
    pub nginx_sites_dir: PathBuf,

    /// Nginx sites-enabled directory
    pub nginx_enabled_dir: PathBuf,

    /// Directory for systemd unit files
    pub systemd_units_dir: PathBuf,

    /// Directory where SSL certificates are stored (e.g. /etc/letsencrypt/live)
    pub ssl_certs_dir: PathBuf,

    /// Email address for ACME / Let's Encrypt account registration
    pub acme_email: String,

    /// Start of the port range available for application allocation
    pub default_port_range_start: u16,

    /// End of the port range available for application allocation
    pub default_port_range_end: u16,

    /// Maximum number of managed applications
    pub max_apps: usize,

    /// Maximum number of deploy history records to keep per app
    pub max_deploy_history: usize,

    /// Timeout in seconds for build steps
    pub build_timeout_secs: u64,

    /// Timeout in seconds for health check probes after deploy
    pub health_check_timeout_secs: u64,

    /// Number of health check retries before marking a deploy as failed
    pub health_check_retries: u32,

    /// Path to the application registry file
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

impl DeployConfig {
    /// Validate the deploy configuration, returning errors for any invalid values.
    pub fn validate(&self) -> Result<()> {
        if self.acme_email.is_empty() {
            tracing::warn!(
                "deploy.acme_email is empty — SSL certificate requests will fail without it"
            );
        }

        if self.default_port_range_start >= self.default_port_range_end {
            return Err(ZeroedError::Config(
                crate::core::error::ConfigError::ValidationError {
                    message: format!(
                        "deploy.default_port_range_start ({}) must be less than default_port_range_end ({})",
                        self.default_port_range_start, self.default_port_range_end
                    ),
                },
            ));
        }

        if self.default_port_range_start < 1024 {
            return Err(ZeroedError::Config(
                crate::core::error::ConfigError::ValidationError {
                    message: format!(
                        "deploy.default_port_range_start ({}) must be >= 1024 to avoid privileged ports",
                        self.default_port_range_start
                    ),
                },
            ));
        }

        if self.max_apps == 0 {
            return Err(ZeroedError::Config(
                crate::core::error::ConfigError::ValidationError {
                    message: "deploy.max_apps must be greater than 0".to_string(),
                },
            ));
        }

        if self.build_timeout_secs == 0 {
            return Err(ZeroedError::Config(
                crate::core::error::ConfigError::ValidationError {
                    message: "deploy.build_timeout_secs must be greater than 0".to_string(),
                },
            ));
        }

        Ok(())
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Deploy Manager (top-level coordinator)
// ─────────────────────────────────────────────────────────────────────────────

/// The top-level deployment manager that coordinates all sub-managers.
///
/// This is the primary entry point for all deployment operations. It owns
/// the individual managers and provides high-level methods that orchestrate
/// multi-step workflows (e.g. "deploy app" involves git, build, nginx,
/// systemd, health check).
pub struct DeployManager {
    /// Configuration
    config: DeployConfig,

    /// SSH key manager
    pub ssh_keys: SshKeyManager,

    /// Application registry
    pub apps: AppRegistry,

    /// Nginx configuration manager
    pub nginx: NginxManager,

    /// Systemd service manager
    pub systemd: SystemdManager,

    /// SSL certificate manager
    pub ssl: SslManager,

    /// Port allocator
    pub ports: PortAllocator,

    /// Deployment pipeline
    pub pipeline: DeploymentPipeline,
}

impl DeployManager {
    /// Create a new deploy manager from configuration.
    ///
    /// This initializes all sub-managers and creates required directories.
    pub fn new(config: DeployConfig) -> Result<Self> {
        config.validate()?;

        // Ensure base directories exist
        Self::ensure_directories(&config)?;

        let ssh_keys = SshKeyManager::new(config.ssh_keys_dir.clone())?;
        let apps = AppRegistry::new(config.registry_path.clone())?;
        let nginx = NginxManager::new(
            config.nginx_sites_dir.clone(),
            config.nginx_enabled_dir.clone(),
        )?;
        let systemd = SystemdManager::new(config.systemd_units_dir.clone())?;
        let ssl = SslManager::new(config.ssl_certs_dir.clone(), config.acme_email.clone())?;
        let ports = PortAllocator::new(
            config.default_port_range_start,
            config.default_port_range_end,
        )?;
        let pipeline = DeploymentPipeline::new(config.clone())?;

        tracing::info!("Deployment manager initialized");

        Ok(Self {
            config,
            ssh_keys,
            apps,
            nginx,
            systemd,
            ssl,
            ports,
            pipeline,
        })
    }

    /// Ensure all required directories exist with correct permissions.
    fn ensure_directories(config: &DeployConfig) -> Result<()> {
        let dirs = [
            &config.apps_dir,
            &config.ssh_keys_dir,
        ];

        for dir in &dirs {
            if !dir.exists() {
                std::fs::create_dir_all(dir).map_err(|e| ZeroedError::Internal {
                    message: format!("Failed to create directory {:?}: {}", dir, e),
                })?;
                tracing::debug!("Created directory: {:?}", dir);
            }
        }

        // Ensure registry parent directory exists
        if let Some(parent) = config.registry_path.parent() {
            if !parent.exists() {
                std::fs::create_dir_all(parent).map_err(|e| ZeroedError::Internal {
                    message: format!("Failed to create registry directory {:?}: {}", parent, e),
                })?;
            }
        }

        // Set restrictive permissions on SSH keys directory
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let perms = std::fs::Permissions::from_mode(0o700);
            if config.ssh_keys_dir.exists() {
                std::fs::set_permissions(&config.ssh_keys_dir, perms).map_err(|e| {
                    ZeroedError::Internal {
                        message: format!(
                            "Failed to set permissions on {:?}: {}",
                            config.ssh_keys_dir, e
                        ),
                    }
                })?;
            }
        }

        Ok(())
    }

    /// Run preflight checks to verify the system is ready for deployments.
    ///
    /// Returns a list of warnings and errors. Errors are fatal (deployments
    /// will fail), warnings are informational.
    pub fn preflight_check(&self) -> PreflightResult {
        let mut result = PreflightResult::default();

        // Check Nginx is installed
        match std::process::Command::new("which").arg("nginx").output() {
            Ok(output) if output.status.success() => {
                result.add_ok("Nginx is installed");
            }
            _ => {
                result.add_error("Nginx is not installed. Install with: apt install nginx");
            }
        }

        // Check systemctl is available
        match std::process::Command::new("which").arg("systemctl").output() {
            Ok(output) if output.status.success() => {
                result.add_ok("systemd is available");
            }
            _ => {
                result.add_error("systemctl not found — systemd is required");
            }
        }

        // Check git is installed
        match std::process::Command::new("which").arg("git").output() {
            Ok(output) if output.status.success() => {
                result.add_ok("git is installed");
            }
            _ => {
                result.add_error("git is not installed. Install with: apt install git");
            }
        }

        // Check certbot for SSL (warn, not error)
        match std::process::Command::new("which").arg("certbot").output() {
            Ok(output) if output.status.success() => {
                result.add_ok("certbot is installed (SSL available)");
            }
            _ => {
                result.add_warning(
                    "certbot is not installed — SSL automation will not work. \
                     Install with: apt install certbot python3-certbot-nginx",
                );
            }
        }

        // Check ACME email is configured
        if self.config.acme_email.is_empty() {
            result.add_warning(
                "deploy.acme_email is not set — required for SSL certificate requests",
            );
        }

        // Check Nginx config directories are writable
        if self.config.nginx_sites_dir.exists() {
            match std::fs::metadata(&self.config.nginx_sites_dir) {
                Ok(meta) if meta.is_dir() => {
                    result.add_ok("Nginx sites-available directory exists");
                }
                _ => {
                    result.add_error(&format!(
                        "Nginx sites directory {:?} is not accessible",
                        self.config.nginx_sites_dir
                    ));
                }
            }
        } else {
            result.add_warning(&format!(
                "Nginx sites directory {:?} does not exist — will be created on first deploy",
                self.config.nginx_sites_dir
            ));
        }

        // Check systemd units directory
        if !self.config.systemd_units_dir.exists() {
            result.add_error(&format!(
                "systemd units directory {:?} does not exist",
                self.config.systemd_units_dir
            ));
        }

        result
    }

    /// Get the deploy configuration.
    pub fn config(&self) -> &DeployConfig {
        &self.config
    }

    /// Check whether the deployment subsystem is enabled.
    pub fn is_enabled(&self) -> bool {
        self.config.enabled
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Preflight Check Result
// ─────────────────────────────────────────────────────────────────────────────

/// Severity level for a preflight check item.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum CheckSeverity {
    Ok,
    Warning,
    Error,
}

/// A single item from a preflight check.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CheckItem {
    pub severity: CheckSeverity,
    pub message: String,
}

/// Result of running preflight checks.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct PreflightResult {
    pub items: Vec<CheckItem>,
}

impl PreflightResult {
    pub fn add_ok(&mut self, message: &str) {
        self.items.push(CheckItem {
            severity: CheckSeverity::Ok,
            message: message.to_string(),
        });
    }

    pub fn add_warning(&mut self, message: &str) {
        self.items.push(CheckItem {
            severity: CheckSeverity::Warning,
            message: message.to_string(),
        });
    }

    pub fn add_error(&mut self, message: &str) {
        self.items.push(CheckItem {
            severity: CheckSeverity::Error,
            message: message.to_string(),
        });
    }

    /// Returns true if there are no errors (warnings are acceptable).
    pub fn is_ok(&self) -> bool {
        !self.items.iter().any(|i| i.severity == CheckSeverity::Error)
    }

    /// Returns only the error items.
    pub fn errors(&self) -> Vec<&CheckItem> {
        self.items
            .iter()
            .filter(|i| i.severity == CheckSeverity::Error)
            .collect()
    }

    /// Returns only the warning items.
    pub fn warnings(&self) -> Vec<&CheckItem> {
        self.items
            .iter()
            .filter(|i| i.severity == CheckSeverity::Warning)
            .collect()
    }
}

impl std::fmt::Display for PreflightResult {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        for item in &self.items {
            let prefix = match item.severity {
                CheckSeverity::Ok => "  ✓",
                CheckSeverity::Warning => "  ⚠",
                CheckSeverity::Error => "  ✗",
            };
            writeln!(f, "{} {}", prefix, item.message)?;
        }

        if self.is_ok() {
            writeln!(f, "\nPreflight checks passed.")
        } else {
            writeln!(
                f,
                "\nPreflight checks FAILED with {} error(s).",
                self.errors().len()
            )
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_deploy_config() {
        let config = DeployConfig::default();
        assert!(config.enabled);
        assert_eq!(config.default_port_range_start, 3000);
        assert_eq!(config.default_port_range_end, 9999);
        assert_eq!(config.max_apps, 100);
        assert_eq!(config.max_deploy_history, 10);
    }

    #[test]
    fn test_deploy_config_validation_port_range() {
        let mut config = DeployConfig::default();
        config.default_port_range_start = 9999;
        config.default_port_range_end = 3000;
        assert!(config.validate().is_err());
    }

    #[test]
    fn test_deploy_config_validation_privileged_port() {
        let mut config = DeployConfig::default();
        config.default_port_range_start = 80;
        assert!(config.validate().is_err());
    }

    #[test]
    fn test_deploy_config_validation_max_apps_zero() {
        let mut config = DeployConfig::default();
        config.max_apps = 0;
        assert!(config.validate().is_err());
    }

    #[test]
    fn test_deploy_config_validation_valid() {
        let config = DeployConfig::default();
        // Will warn about empty acme_email but should not error
        assert!(config.validate().is_ok());
    }

    #[test]
    fn test_preflight_result() {
        let mut result = PreflightResult::default();
        result.add_ok("all good");
        result.add_warning("heads up");
        assert!(result.is_ok());

        result.add_error("something broke");
        assert!(!result.is_ok());
        assert_eq!(result.errors().len(), 1);
        assert_eq!(result.warnings().len(), 1);
    }

    #[test]
    fn test_preflight_result_display() {
        let mut result = PreflightResult::default();
        result.add_ok("Nginx is installed");
        result.add_warning("certbot missing");
        let output = format!("{}", result);
        assert!(output.contains("✓"));
        assert!(output.contains("⚠"));
        assert!(output.contains("passed"));
    }
}
