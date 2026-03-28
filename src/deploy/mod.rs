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

// Re-export DeployConfig from core::config so downstream code can use
// `crate::deploy::DeployConfig` as before
pub use crate::core::config::DeployConfig as DeployConfig;
pub use app::{AppRegistry, AppStatus, AppType, Application};
pub use nginx::NginxManager;
pub use pipeline::DeploymentPipeline;
pub use ports::PortAllocator;
pub use ssh::SshKeyManager;
pub use ssl::SslManager;
pub use systemd::SystemdManager;

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
        // Basic validation
        if config.default_port_range_start >= config.default_port_range_end {
            return Err(ZeroedError::Config(
                crate::core::error::ConfigError::ValidationError {
                    message: format!(
                        "deploy.default_port_range_start ({}) must be less than default_port_range_end ({})",
                        config.default_port_range_start, config.default_port_range_end
                    ),
                },
            ));
        }

        if config.default_port_range_start < 1024 {
            return Err(ZeroedError::Config(
                crate::core::error::ConfigError::ValidationError {
                    message: format!(
                        "deploy.default_port_range_start ({}) must be >= 1024 to avoid privileged ports",
                        config.default_port_range_start
                    ),
                },
            ));
        }

        if config.max_apps == 0 {
            return Err(ZeroedError::Config(
                crate::core::error::ConfigError::ValidationError {
                    message: "deploy.max_apps must be greater than 0".to_string(),
                },
            ));
        }

        if config.build_timeout_secs == 0 {
            return Err(ZeroedError::Config(
                crate::core::error::ConfigError::ValidationError {
                    message: "deploy.build_timeout_secs must be greater than 0".to_string(),
                },
            ));
        }

        if config.acme_email.is_empty() {
            tracing::warn!(
                "deploy.acme_email is empty — SSL certificate requests will fail without it"
            );
        }

        // Ensure base directories exist
        Self::ensure_directories(&config)?;

        let ssh_keys = SshKeyManager::new(config.ssh_keys_dir.clone())
            .map_err(|e| ZeroedError::Internal {
                message: format!("Failed to initialize SSH key manager: {}", e),
            })?;
        let apps = AppRegistry::new(config.registry_path.clone())
            .map_err(|e| ZeroedError::Internal {
                message: format!("Failed to initialize app registry: {}", e),
            })?;
        let nginx = NginxManager::new(
            config.nginx_sites_dir.clone(),
            config.nginx_enabled_dir.clone(),
        )
        .map_err(|e| ZeroedError::Internal {
            message: format!("Failed to initialize Nginx manager: {}", e),
        })?;
        let systemd = SystemdManager::new(config.systemd_units_dir.clone())
            .map_err(|e| ZeroedError::Internal {
                message: format!("Failed to initialize systemd manager: {}", e),
            })?;
        let ssl = SslManager::new(config.ssl_certs_dir.clone(), config.acme_email.clone())
            .map_err(|e| ZeroedError::Internal {
                message: format!("Failed to initialize SSL manager: {}", e),
            })?;
        let ports = PortAllocator::new(
            config.default_port_range_start,
            config.default_port_range_end,
        )
        .map_err(|e| ZeroedError::Internal {
            message: format!("Failed to initialize port allocator: {}", e),
        })?;
        let pipeline = DeploymentPipeline::new(config.clone())
            .map_err(|e| ZeroedError::Internal {
                message: format!("Failed to initialize deployment pipeline: {}", e),
            })?;

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

    // ─────────────────────────────────────────────────────────────────────
    // High-Level Application Operations
    // ─────────────────────────────────────────────────────────────────────

    /// Deploy an application by name.
    ///
    /// Looks up the application in the registry, runs the full deployment
    /// pipeline, and updates the registry with the result.
    pub fn deploy_app(
        &mut self,
        name: &str,
        options: &crate::deploy::pipeline::DeployOptions,
    ) -> Result<crate::deploy::pipeline::DeployResult> {
        let mut app = self
            .apps
            .get(name)
            .ok_or_else(|| ZeroedError::Internal {
                message: format!("Application '{}' not found", name),
            })?
            .clone();

        if !app.status.can_deploy() {
            return Err(ZeroedError::Internal {
                message: format!(
                    "Application '{}' is currently {} and cannot be deployed",
                    name, app.status
                ),
            });
        }

        let result = self
            .pipeline
            .deploy(
                &mut app,
                &self.ssh_keys,
                &self.nginx,
                &self.systemd,
                options,
            )
            .map_err(|e| ZeroedError::Internal {
                message: format!("Deploy pipeline failed: {}", e),
            })?;

        // Persist the updated app state back to the registry
        let _ = self.apps.update(name, |a| {
            a.status = app.status;
            a.current_deploy_id = app.current_deploy_id.clone();
            a.current_commit = app.current_commit.clone();
            a.last_deployed_at = app.last_deployed_at;
            a.updated_at = app.updated_at;
            a.build_command = app.build_command.clone();
            a.build_output_dir = app.build_output_dir.clone();
            a.start_command = app.start_command.clone();
        });

        Ok(result)
    }

    /// Rollback an application to a previous release.
    ///
    /// If `target_deploy_id` is `None`, rolls back to the most recent
    /// successful deployment before the current one.
    pub fn rollback_app(
        &mut self,
        name: &str,
        target_deploy_id: Option<&str>,
    ) -> Result<crate::deploy::pipeline::DeployResult> {
        let mut app = self
            .apps
            .get(name)
            .ok_or_else(|| ZeroedError::Internal {
                message: format!("Application '{}' not found", name),
            })?
            .clone();

        let result = self
            .pipeline
            .rollback(&mut app, &self.nginx, &self.systemd, target_deploy_id)
            .map_err(|e| ZeroedError::Internal {
                message: format!("Rollback failed: {}", e),
            })?;

        // Persist the updated app state
        let _ = self.apps.update(name, |a| {
            a.status = app.status;
            a.current_deploy_id = app.current_deploy_id.clone();
            a.current_commit = app.current_commit.clone();
            a.last_deployed_at = app.last_deployed_at;
            a.updated_at = app.updated_at;
        });

        Ok(result)
    }

    /// Stop a running application's systemd service.
    pub fn stop_app(&mut self, name: &str) -> Result<()> {
        let app = self
            .apps
            .get(name)
            .ok_or_else(|| ZeroedError::Internal {
                message: format!("Application '{}' not found", name),
            })?;

        if !app.app_type.needs_service() {
            return Err(ZeroedError::Internal {
                message: format!(
                    "Application '{}' is a {} and has no service to stop",
                    name, app.app_type
                ),
            });
        }

        let svc_name = app.service_name();
        self.systemd.stop(&svc_name).map_err(|e| ZeroedError::Internal {
            message: format!("Failed to stop service '{}': {}", svc_name, e),
        })?;

        self.apps
            .set_status(name, AppStatus::Stopped)
            .map_err(|e| ZeroedError::Internal {
                message: format!("Failed to update status: {}", e),
            })?;

        tracing::info!("Application '{}' stopped", name);
        Ok(())
    }

    /// Start a stopped application's systemd service.
    pub fn start_app(&mut self, name: &str) -> Result<()> {
        let app = self
            .apps
            .get(name)
            .ok_or_else(|| ZeroedError::Internal {
                message: format!("Application '{}' not found", name),
            })?;

        if !app.app_type.needs_service() {
            return Err(ZeroedError::Internal {
                message: format!(
                    "Application '{}' is a {} and has no service to start",
                    name, app.app_type
                ),
            });
        }

        if !app.has_been_deployed() {
            return Err(ZeroedError::Internal {
                message: format!(
                    "Application '{}' has never been deployed — deploy it first",
                    name
                ),
            });
        }

        let svc_name = app.service_name();
        self.systemd.start(&svc_name).map_err(|e| ZeroedError::Internal {
            message: format!("Failed to start service '{}': {}", svc_name, e),
        })?;

        self.apps
            .set_status(name, AppStatus::Running)
            .map_err(|e| ZeroedError::Internal {
                message: format!("Failed to update status: {}", e),
            })?;

        tracing::info!("Application '{}' started", name);
        Ok(())
    }

    /// Restart a running application's systemd service.
    pub fn restart_app(&mut self, name: &str) -> Result<()> {
        let app = self
            .apps
            .get(name)
            .ok_or_else(|| ZeroedError::Internal {
                message: format!("Application '{}' not found", name),
            })?;

        if !app.app_type.needs_service() {
            return Err(ZeroedError::Internal {
                message: format!(
                    "Application '{}' is a {} and has no service to restart",
                    name, app.app_type
                ),
            });
        }

        let svc_name = app.service_name();
        self.systemd.restart(&svc_name).map_err(|e| ZeroedError::Internal {
            message: format!("Failed to restart service '{}': {}", svc_name, e),
        })?;

        self.apps
            .set_status(name, AppStatus::Running)
            .map_err(|e| ZeroedError::Internal {
                message: format!("Failed to update status: {}", e),
            })?;

        tracing::info!("Application '{}' restarted", name);
        Ok(())
    }

    /// Delete an application entirely.
    ///
    /// This performs a full teardown:
    /// 1. Stop the systemd service (if running)
    /// 2. Remove the systemd unit file
    /// 3. Remove the nginx config and reload
    /// 4. Release the port allocation
    /// 5. Unregister from the app registry
    /// 6. Optionally delete all files on disk
    pub fn delete_app(&mut self, name: &str, delete_files: bool) -> Result<()> {
        let app = self
            .apps
            .get(name)
            .ok_or_else(|| ZeroedError::Internal {
                message: format!("Application '{}' not found", name),
            })?
            .clone();

        tracing::info!("Deleting application '{}' (delete_files: {})", name, delete_files);

        // 1. Stop the service if it's a backend/hybrid app
        if app.app_type.needs_service() {
            let svc_name = app.service_name();
            if let Err(e) = self.systemd.stop(&svc_name) {
                tracing::warn!("Could not stop service '{}' during delete: {}", svc_name, e);
            }

            // 2. Remove the systemd unit file
            if let Err(e) = self.systemd.remove_service(&svc_name) {
                tracing::warn!("Could not remove service '{}' during delete: {}", svc_name, e);
            }
        }

        // 3. Remove nginx config and reload
        if let Err(e) = self.nginx.remove_config(name) {
            tracing::warn!("Could not remove nginx config for '{}': {}", name, e);
        }
        let _ = self.nginx.reload();

        // 4. Release the port
        if app.app_type.needs_port() && app.port > 0 {
            let _ = self.ports.release(app.port);
        }

        // 5. Remove SSH key association
        if let Some(ref key_id) = app.ssh_key_id {
            if let Some(key) = self.ssh_keys.get_key_mut(key_id) {
                key.remove_app(&app.id);
            }
            let _ = self.ssh_keys.save();
        }

        // 6. Unregister from the app registry
        self.apps.unregister(name).map_err(|e| ZeroedError::Internal {
            message: format!("Failed to unregister app '{}': {}", name, e),
        })?;

        // 7. Optionally delete files on disk
        if delete_files {
            if app.deploy_dir.exists() {
                if let Err(e) = std::fs::remove_dir_all(&app.deploy_dir) {
                    tracing::warn!(
                        "Could not delete app directory {:?}: {}",
                        app.deploy_dir, e
                    );
                } else {
                    tracing::info!("Deleted app directory: {:?}", app.deploy_dir);
                }
            }
        }

        tracing::info!("Application '{}' deleted successfully", name);
        Ok(())
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
