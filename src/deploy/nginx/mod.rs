//! Nginx Configuration Management Module
//!
//! This module provides functionality for generating, installing, testing, and
//! managing Nginx server block configurations for deployed applications.
//!
//! ## Responsibilities
//!
//! - Generate Nginx server block configs for backend (reverse proxy), static site,
//!   and hybrid applications
//! - Install configs to `sites-available/` and symlink to `sites-enabled/`
//! - Test configs with `nginx -t` before reloading
//! - Reload/restart Nginx via systemctl
//! - Handle SSL server blocks with HTTP→HTTPS redirect
//! - Manage static asset caching, gzip compression, and security headers
//! - Support SPA mode (`try_files $uri $uri/ /index.html`) for frontend apps
//! - Detect and adapt to `sites-available/sites-enabled` vs `conf.d/` patterns
//!
//! ## Config Naming Convention
//!
//! All generated configs follow the pattern: `zeroed-app-<name>.conf`
//! This makes it easy to identify Zeroed-managed configs and avoid conflicts.

use crate::deploy::app::{AppType, Application};
use serde::{Deserialize, Serialize};
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

/// Errors specific to Nginx management operations.
#[derive(Debug, Error)]
pub enum NginxError {
    #[error("IO error: {0}")]
    Io(#[from] io::Error),

    #[error("Nginx is not installed or not found in PATH")]
    NotInstalled,

    #[error("Nginx configuration test failed: {output}")]
    ConfigTestFailed { output: String },

    #[error("Nginx reload failed: {message}")]
    ReloadFailed { message: String },

    #[error("Nginx restart failed: {message}")]
    RestartFailed { message: String },

    #[error("Config file already exists for app '{app}' and force=false")]
    ConfigExists { app: String },

    #[error("Config file not found for app '{app}'")]
    ConfigNotFound { app: String },

    #[error("Sites directory not found: {path}")]
    SitesDirectoryNotFound { path: String },

    #[error("Server name conflict: '{domain}' is already configured in {existing_config}")]
    ServerNameConflict {
        domain: String,
        existing_config: String,
    },

    #[error("Nginx status check failed: {message}")]
    StatusCheckFailed { message: String },

    #[error("Template rendering error: {message}")]
    TemplateError { message: String },
}

/// Result alias for Nginx operations.
pub type Result<T> = std::result::Result<T, NginxError>;

// ─────────────────────────────────────────────────────────────────────────────
// Nginx Status
// ─────────────────────────────────────────────────────────────────────────────

/// Current status of the Nginx service.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum NginxStatus {
    /// Nginx is running normally
    Running,
    /// Nginx is stopped
    Stopped,
    /// Nginx is not installed
    NotInstalled,
    /// Nginx status could not be determined
    Unknown,
}

impl fmt::Display for NginxStatus {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            NginxStatus::Running => write!(f, "running"),
            NginxStatus::Stopped => write!(f, "stopped"),
            NginxStatus::NotInstalled => write!(f, "not_installed"),
            NginxStatus::Unknown => write!(f, "unknown"),
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Site Layout Style
// ─────────────────────────────────────────────────────────────────────────────

/// The Nginx site configuration layout style detected on the system.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SiteLayoutStyle {
    /// Debian/Ubuntu style: sites-available/ + sites-enabled/ (symlinks)
    SitesAvailableEnabled,
    /// RHEL/Fedora style: conf.d/ (direct files)
    ConfD,
}

// ─────────────────────────────────────────────────────────────────────────────
// Config Test Result
// ─────────────────────────────────────────────────────────────────────────────

/// Result of running `nginx -t` to test the configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConfigTestResult {
    /// Whether the test passed
    pub success: bool,
    /// Raw stdout output from nginx -t
    pub stdout: String,
    /// Raw stderr output from nginx -t (nginx writes status here)
    pub stderr: String,
    /// Parsed error messages (if any)
    pub errors: Vec<String>,
}

// ─────────────────────────────────────────────────────────────────────────────
// Generated Config
// ─────────────────────────────────────────────────────────────────────────────

/// A generated Nginx configuration file and its metadata.
#[derive(Debug, Clone)]
pub struct GeneratedConfig {
    /// The application this config is for
    pub app_name: String,
    /// The generated config content
    pub content: String,
    /// The target filename (e.g. "zeroed-app-my-api.conf")
    pub filename: String,
}

// ─────────────────────────────────────────────────────────────────────────────
// Nginx Manager
// ─────────────────────────────────────────────────────────────────────────────

/// Manages Nginx configuration files for deployed applications.
///
/// Handles generating, installing, testing, and reloading Nginx configs.
/// Supports both reverse proxy (backend) and static file (frontend) configurations,
/// as well as SSL termination with HTTP→HTTPS redirects.
pub struct NginxManager {
    /// Path to the sites-available directory (or conf.d)
    sites_available_dir: PathBuf,

    /// Path to the sites-enabled directory (if using symlink style)
    sites_enabled_dir: PathBuf,

    /// Detected site layout style
    layout_style: SiteLayoutStyle,

    /// Path to the nginx binary
    nginx_bin: Option<PathBuf>,
}

impl NginxManager {
    /// Create a new Nginx manager.
    ///
    /// Detects the Nginx installation and site layout style.
    pub fn new(sites_available_dir: PathBuf, sites_enabled_dir: PathBuf) -> Result<Self> {
        let nginx_bin = Self::find_nginx_binary();
        let layout_style = if sites_enabled_dir.exists() {
            SiteLayoutStyle::SitesAvailableEnabled
        } else if sites_available_dir.exists() {
            SiteLayoutStyle::ConfD
        } else {
            // Default to Debian-style
            SiteLayoutStyle::SitesAvailableEnabled
        };

        if nginx_bin.is_some() {
            info!(
                "Nginx manager initialized (layout: {:?}, sites: {:?})",
                layout_style, sites_available_dir
            );
        } else {
            warn!("Nginx binary not found — Nginx operations will fail until it is installed");
        }

        Ok(Self {
            sites_available_dir,
            sites_enabled_dir,
            layout_style,
            nginx_bin,
        })
    }

    // ─────────────────────────────────────────────────────────────────────
    // Config Generation
    // ─────────────────────────────────────────────────────────────────────

    /// Generate an Nginx configuration for the given application.
    ///
    /// The configuration is generated based on the application type:
    /// - `Backend`: reverse proxy upstream block + proxy_pass
    /// - `StaticSite`: root + index + try_files (with optional SPA fallback)
    /// - `Hybrid`: static file serving + API path reverse proxy
    ///
    /// If SSL is enabled, an HTTPS server block and HTTP→HTTPS redirect are included.
    pub fn generate_config(&self, app: &Application) -> Result<GeneratedConfig> {
        let content = match app.app_type {
            AppType::Backend => self.generate_backend_config(app)?,
            AppType::StaticSite => self.generate_static_config(app)?,
            AppType::Hybrid => self.generate_hybrid_config(app)?,
        };

        Ok(GeneratedConfig {
            app_name: app.name.clone(),
            content,
            filename: app.nginx_config_name(),
        })
    }

    /// Generate Nginx config for a backend (reverse proxy) application.
    fn generate_backend_config(&self, app: &Application) -> Result<String> {
        let server_name = app
            .domain
            .as_deref()
            .unwrap_or("_");

        let upstream_name = format!("{}_backend", app.name.replace('-', "_"));

        let mut config = String::new();

        // Header comment
        config.push_str(&format!(
            "# Generated by zeroed — do not edit manually\n\
             # App: {} | Type: backend | Port: {}\n\
             # Generated at: {}\n\n",
            app.name,
            app.port,
            chrono::Utc::now().to_rfc3339()
        ));

        // Upstream block
        config.push_str(&format!(
            "upstream {} {{\n\
             \x20   server 127.0.0.1:{};\n\
             \x20   keepalive 64;\n\
             }}\n\n",
            upstream_name, app.port
        ));

        // SSL server block (if enabled)
        if app.ssl_enabled {
            if let (Some(ref cert_path), Some(ref key_path)) =
                (&app.ssl_cert_path, &app.ssl_key_path)
            {
                config.push_str(&self.render_ssl_server_block(
                    server_name,
                    cert_path,
                    key_path,
                    &self.render_proxy_location(&upstream_name),
                    &app.name,
                ));
                config.push('\n');

                // HTTP → HTTPS redirect
                config.push_str(&self.render_http_redirect(server_name));
            } else {
                warn!(
                    "SSL enabled for '{}' but cert/key paths not set — generating HTTP-only config",
                    app.name
                );
                config.push_str(&self.render_http_server_block(
                    server_name,
                    &self.render_proxy_location(&upstream_name),
                    &app.name,
                ));
            }
        } else {
            config.push_str(&self.render_http_server_block(
                server_name,
                &self.render_proxy_location(&upstream_name),
                &app.name,
            ));
        }

        Ok(config)
    }

    /// Generate Nginx config for a static site application.
    fn generate_static_config(&self, app: &Application) -> Result<String> {
        let server_name = app
            .domain
            .as_deref()
            .unwrap_or("_");

        let static_root = app.static_root();
        let root_str = static_root.to_string_lossy();

        let mut config = String::new();

        // Header comment
        config.push_str(&format!(
            "# Generated by zeroed — do not edit manually\n\
             # App: {} | Type: static_site | SPA: {}\n\
             # Root: {}\n\
             # Generated at: {}\n\n",
            app.name,
            app.spa_mode,
            root_str,
            chrono::Utc::now().to_rfc3339()
        ));

        let location_block = self.render_static_location(
            &root_str,
            &app.index_file,
            app.spa_mode,
            app.base_path.as_deref(),
        );

        if app.ssl_enabled {
            if let (Some(ref cert_path), Some(ref key_path)) =
                (&app.ssl_cert_path, &app.ssl_key_path)
            {
                config.push_str(&self.render_ssl_server_block(
                    server_name,
                    cert_path,
                    key_path,
                    &location_block,
                    &app.name,
                ));
                config.push('\n');
                config.push_str(&self.render_http_redirect(server_name));
            } else {
                warn!(
                    "SSL enabled for '{}' but cert/key paths not set — generating HTTP-only config",
                    app.name
                );
                config.push_str(&self.render_http_server_block(
                    server_name,
                    &location_block,
                    &app.name,
                ));
            }
        } else {
            config.push_str(&self.render_http_server_block(
                server_name,
                &location_block,
                &app.name,
            ));
        }

        Ok(config)
    }

    /// Generate Nginx config for a hybrid (backend + static) application.
    fn generate_hybrid_config(&self, app: &Application) -> Result<String> {
        let server_name = app
            .domain
            .as_deref()
            .unwrap_or("_");

        let upstream_name = format!("{}_backend", app.name.replace('-', "_"));
        let api_prefix = app
            .api_path_prefix
            .as_deref()
            .unwrap_or("/api");

        let static_root = app.static_root();
        let root_str = static_root.to_string_lossy();

        let mut config = String::new();

        // Header comment
        config.push_str(&format!(
            "# Generated by zeroed — do not edit manually\n\
             # App: {} | Type: hybrid | Port: {} | API prefix: {}\n\
             # Static root: {}\n\
             # Generated at: {}\n\n",
            app.name,
            app.port,
            api_prefix,
            root_str,
            chrono::Utc::now().to_rfc3339()
        ));

        // Upstream block
        config.push_str(&format!(
            "upstream {} {{\n\
             \x20   server 127.0.0.1:{};\n\
             \x20   keepalive 64;\n\
             }}\n\n",
            upstream_name, app.port
        ));

        // Combined location blocks: static root + API proxy
        let mut location_block = String::new();

        // Static file serving with SPA fallback
        location_block.push_str(&self.render_static_location(
            &root_str,
            &app.index_file,
            app.spa_mode,
            None, // base_path handled at server level for hybrid
        ));
        location_block.push('\n');

        // API reverse proxy
        location_block.push_str(&format!(
            "    location {} {{\n\
             \x20       proxy_pass http://{};\n\
             \x20       proxy_http_version 1.1;\n\
             \x20       proxy_set_header Upgrade $http_upgrade;\n\
             \x20       proxy_set_header Connection \"upgrade\";\n\
             \x20       proxy_set_header Host $host;\n\
             \x20       proxy_set_header X-Real-IP $remote_addr;\n\
             \x20       proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;\n\
             \x20       proxy_set_header X-Forwarded-Proto $scheme;\n\
             \x20       proxy_cache_bypass $http_upgrade;\n\
             \x20       proxy_read_timeout 86400;\n\
             \x20   }}\n",
            api_prefix, upstream_name
        ));

        if app.ssl_enabled {
            if let (Some(ref cert_path), Some(ref key_path)) =
                (&app.ssl_cert_path, &app.ssl_key_path)
            {
                config.push_str(&self.render_ssl_server_block(
                    server_name,
                    cert_path,
                    key_path,
                    &location_block,
                    &app.name,
                ));
                config.push('\n');
                config.push_str(&self.render_http_redirect(server_name));
            } else {
                warn!(
                    "SSL enabled for '{}' but cert/key paths not set — generating HTTP-only config",
                    app.name
                );
                config.push_str(&self.render_http_server_block(
                    server_name,
                    &location_block,
                    &app.name,
                ));
            }
        } else {
            config.push_str(&self.render_http_server_block(
                server_name,
                &location_block,
                &app.name,
            ));
        }

        Ok(config)
    }

    // ─────────────────────────────────────────────────────────────────────
    // Template Rendering Helpers
    // ─────────────────────────────────────────────────────────────────────

    /// Render a reverse proxy location block.
    fn render_proxy_location(&self, upstream_name: &str) -> String {
        format!(
            "    location / {{\n\
             \x20       proxy_pass http://{};\n\
             \x20       proxy_http_version 1.1;\n\
             \x20       proxy_set_header Upgrade $http_upgrade;\n\
             \x20       proxy_set_header Connection \"upgrade\";\n\
             \x20       proxy_set_header Host $host;\n\
             \x20       proxy_set_header X-Real-IP $remote_addr;\n\
             \x20       proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;\n\
             \x20       proxy_set_header X-Forwarded-Proto $scheme;\n\
             \x20       proxy_cache_bypass $http_upgrade;\n\
             \x20       proxy_read_timeout 86400;\n\
             \x20   }}\n",
            upstream_name
        )
    }

    /// Render a static file serving location block with optional SPA fallback.
    fn render_static_location(
        &self,
        root: &str,
        index_file: &str,
        spa_mode: bool,
        base_path: Option<&str>,
    ) -> String {
        let location_path = base_path.unwrap_or("/");
        let try_files = if spa_mode {
            format!("$uri $uri/ /{}", index_file)
        } else {
            "$uri $uri/ =404".to_string()
        };

        let mut block = String::new();

        // Root and index (placed inside location for static-only, or at server level)
        block.push_str(&format!(
            "    root {};\n\
             \x20   index {};\n\n",
            root, index_file
        ));

        // Main location
        block.push_str(&format!(
            "    location {} {{\n\
             \x20       try_files {};\n\
             \x20   }}\n\n",
            location_path, try_files
        ));

        // Static asset caching
        block.push_str(
            "    # Cache static assets aggressively\n\
             \x20   location ~* \\.(js|css|png|jpg|jpeg|gif|ico|svg|woff|woff2|ttf|eot|map)$ {\n\
             \x20       expires 1y;\n\
             \x20       add_header Cache-Control \"public, immutable\";\n\
             \x20       access_log off;\n\
             \x20   }\n",
        );

        block
    }

    /// Render a full HTTP (port 80) server block wrapping the given location content.
    fn render_http_server_block(
        &self,
        server_name: &str,
        location_content: &str,
        app_name: &str,
    ) -> String {
        format!(
            "server {{\n\
             \x20   listen 80;\n\
             \x20   listen [::]:80;\n\
             \x20   server_name {};\n\n\
             \x20   # Logging\n\
             \x20   access_log /var/log/nginx/{}_access.log;\n\
             \x20   error_log  /var/log/nginx/{}_error.log;\n\n\
             \x20   # Security headers\n\
             \x20   add_header X-Frame-Options \"SAMEORIGIN\" always;\n\
             \x20   add_header X-Content-Type-Options \"nosniff\" always;\n\
             \x20   add_header Referrer-Policy \"strict-origin-when-cross-origin\" always;\n\n\
             \x20   # Gzip compression\n\
             \x20   gzip on;\n\
             \x20   gzip_types text/plain text/css application/json application/javascript text/xml application/xml application/xml+rss text/javascript image/svg+xml;\n\
             \x20   gzip_vary on;\n\
             \x20   gzip_min_length 256;\n\n\
             \x20   # Block common exploit paths\n\
             \x20   location ~ /\\.git {{ deny all; return 404; }}\n\
             \x20   location ~ /\\.env {{ deny all; return 404; }}\n\n\
             {}\n\
             }}\n",
            server_name, app_name, app_name, location_content
        )
    }

    /// Render a full HTTPS (port 443) server block with SSL configuration.
    fn render_ssl_server_block(
        &self,
        server_name: &str,
        cert_path: &Path,
        key_path: &Path,
        location_content: &str,
        app_name: &str,
    ) -> String {
        format!(
            "server {{\n\
             \x20   listen 443 ssl http2;\n\
             \x20   listen [::]:443 ssl http2;\n\
             \x20   server_name {};\n\n\
             \x20   # SSL configuration\n\
             \x20   ssl_certificate     {};\n\
             \x20   ssl_certificate_key {};\n\
             \x20   ssl_protocols       TLSv1.2 TLSv1.3;\n\
             \x20   ssl_ciphers         HIGH:!aNULL:!MD5;\n\
             \x20   ssl_prefer_server_ciphers on;\n\
             \x20   ssl_session_cache   shared:SSL:10m;\n\
             \x20   ssl_session_timeout 10m;\n\n\
             \x20   # HSTS\n\
             \x20   add_header Strict-Transport-Security \"max-age=63072000; includeSubDomains; preload\" always;\n\n\
             \x20   # Logging\n\
             \x20   access_log /var/log/nginx/{}_access.log;\n\
             \x20   error_log  /var/log/nginx/{}_error.log;\n\n\
             \x20   # Security headers\n\
             \x20   add_header X-Frame-Options \"SAMEORIGIN\" always;\n\
             \x20   add_header X-Content-Type-Options \"nosniff\" always;\n\
             \x20   add_header Referrer-Policy \"strict-origin-when-cross-origin\" always;\n\n\
             \x20   # Gzip compression\n\
             \x20   gzip on;\n\
             \x20   gzip_types text/plain text/css application/json application/javascript text/xml application/xml application/xml+rss text/javascript image/svg+xml;\n\
             \x20   gzip_vary on;\n\
             \x20   gzip_min_length 256;\n\n\
             \x20   # Block common exploit paths\n\
             \x20   location ~ /\\.git {{ deny all; return 404; }}\n\
             \x20   location ~ /\\.env {{ deny all; return 404; }}\n\n\
             {}\n\
             }}\n",
            server_name,
            cert_path.display(),
            key_path.display(),
            app_name,
            app_name,
            location_content
        )
    }

    /// Render an HTTP→HTTPS redirect server block.
    fn render_http_redirect(&self, server_name: &str) -> String {
        format!(
            "# HTTP -> HTTPS redirect\n\
             server {{\n\
             \x20   listen 80;\n\
             \x20   listen [::]:80;\n\
             \x20   server_name {};\n\
             \x20   return 301 https://$host$request_uri;\n\
             }}\n",
            server_name
        )
    }

    // ─────────────────────────────────────────────────────────────────────
    // Config Installation
    // ─────────────────────────────────────────────────────────────────────

    /// Install a generated config to the Nginx sites directory.
    ///
    /// This writes the config to `sites-available/` and creates a symlink in
    /// `sites-enabled/`. If a config for this app already exists, it is backed
    /// up before being overwritten.
    ///
    /// After installation, the config is tested with `nginx -t`. If the test
    /// fails, the old config is restored and an error is returned.
    pub fn install_config(&self, config: &GeneratedConfig) -> Result<()> {
        let available_path = self.sites_available_dir.join(&config.filename);
        let enabled_path = self.sites_enabled_dir.join(&config.filename);

        // Ensure directories exist
        if !self.sites_available_dir.exists() {
            fs::create_dir_all(&self.sites_available_dir)?;
        }

        // Back up existing config
        let backup_path = available_path.with_extension("conf.bak");
        if available_path.exists() {
            fs::copy(&available_path, &backup_path)?;
            debug!(
                "Backed up existing config to {:?}",
                backup_path
            );
        }

        // Write the new config
        fs::write(&available_path, &config.content)?;
        info!(
            "Nginx config written: {:?} ({} bytes)",
            available_path,
            config.content.len()
        );

        // Create symlink in sites-enabled (if using that layout)
        if self.layout_style == SiteLayoutStyle::SitesAvailableEnabled {
            if !self.sites_enabled_dir.exists() {
                fs::create_dir_all(&self.sites_enabled_dir)?;
            }

            // Remove existing symlink if present
            if enabled_path.exists() || enabled_path.is_symlink() {
                fs::remove_file(&enabled_path)?;
            }

            #[cfg(unix)]
            {
                std::os::unix::fs::symlink(&available_path, &enabled_path)?;
                debug!("Symlink created: {:?} -> {:?}", enabled_path, available_path);
            }

            #[cfg(not(unix))]
            {
                fs::copy(&available_path, &enabled_path)?;
                debug!("Config copied to enabled dir (non-Unix): {:?}", enabled_path);
            }
        }

        // Test the configuration
        match self.test_config() {
            Ok(result) if result.success => {
                info!(
                    "Nginx config test passed for app '{}'",
                    config.app_name
                );
                // Remove backup since new config is valid
                if backup_path.exists() {
                    let _ = fs::remove_file(&backup_path);
                }
                Ok(())
            }
            Ok(result) => {
                error!(
                    "Nginx config test FAILED for app '{}': {:?}",
                    config.app_name, result.errors
                );

                // Restore backup
                if backup_path.exists() {
                    fs::copy(&backup_path, &available_path)?;
                    let _ = fs::remove_file(&backup_path);
                    warn!("Restored previous Nginx config from backup");
                } else {
                    // No backup — remove the broken config
                    let _ = fs::remove_file(&available_path);
                    if enabled_path.exists() || enabled_path.is_symlink() {
                        let _ = fs::remove_file(&enabled_path);
                    }
                    warn!("Removed broken Nginx config (no backup available)");
                }

                Err(NginxError::ConfigTestFailed {
                    output: result.errors.join("; "),
                })
            }
            Err(e) => {
                warn!("Could not run nginx -t: {} — config installed but untested", e);
                Ok(())
            }
        }
    }

    /// Remove the Nginx config for a given application.
    ///
    /// Removes both the sites-available file and the sites-enabled symlink.
    pub fn remove_config(&self, app_name: &str) -> Result<()> {
        let filename = format!("zeroed-app-{}.conf", app_name);
        let available_path = self.sites_available_dir.join(&filename);
        let enabled_path = self.sites_enabled_dir.join(&filename);
        let backup_path = available_path.with_extension("conf.bak");

        // Remove symlink / enabled config
        if enabled_path.exists() || enabled_path.is_symlink() {
            fs::remove_file(&enabled_path)?;
            debug!("Removed Nginx enabled config: {:?}", enabled_path);
        }

        // Remove available config
        if available_path.exists() {
            fs::remove_file(&available_path)?;
            debug!("Removed Nginx available config: {:?}", available_path);
        }

        // Remove backup if present
        if backup_path.exists() {
            let _ = fs::remove_file(&backup_path);
        }

        info!("Nginx config removed for app '{}'", app_name);
        Ok(())
    }

    // ─────────────────────────────────────────────────────────────────────
    // Config Testing & Reloading
    // ─────────────────────────────────────────────────────────────────────

    /// Test the current Nginx configuration by running `nginx -t`.
    pub fn test_config(&self) -> Result<ConfigTestResult> {
        let nginx_bin = self.require_nginx()?;

        let output = Command::new(&nginx_bin)
            .arg("-t")
            .output()
            .map_err(|e| NginxError::ConfigTestFailed {
                output: format!("Failed to execute nginx -t: {}", e),
            })?;

        let stdout = String::from_utf8_lossy(&output.stdout).to_string();
        let stderr = String::from_utf8_lossy(&output.stderr).to_string();

        let errors: Vec<String> = stderr
            .lines()
            .filter(|line| {
                line.contains("[emerg]") || line.contains("[error]") || line.contains("failed")
            })
            .map(String::from)
            .collect();

        Ok(ConfigTestResult {
            success: output.status.success(),
            stdout,
            stderr,
            errors,
        })
    }

    /// Reload Nginx to apply configuration changes.
    ///
    /// Uses `systemctl reload nginx`. Always tests the config first.
    pub fn reload(&self) -> Result<()> {
        // Always test before reloading
        let test_result = self.test_config()?;
        if !test_result.success {
            return Err(NginxError::ConfigTestFailed {
                output: test_result.errors.join("; "),
            });
        }

        let output = Command::new("systemctl")
            .arg("reload")
            .arg("nginx")
            .output()
            .map_err(|e| NginxError::ReloadFailed {
                message: format!("Failed to execute systemctl reload: {}", e),
            })?;

        if output.status.success() {
            info!("Nginx reloaded successfully");
            Ok(())
        } else {
            let stderr = String::from_utf8_lossy(&output.stderr);
            Err(NginxError::ReloadFailed {
                message: stderr.trim().to_string(),
            })
        }
    }

    /// Restart Nginx completely (use reload instead when possible).
    pub fn restart(&self) -> Result<()> {
        let output = Command::new("systemctl")
            .arg("restart")
            .arg("nginx")
            .output()
            .map_err(|e| NginxError::RestartFailed {
                message: format!("Failed to execute systemctl restart: {}", e),
            })?;

        if output.status.success() {
            info!("Nginx restarted successfully");
            Ok(())
        } else {
            let stderr = String::from_utf8_lossy(&output.stderr);
            Err(NginxError::RestartFailed {
                message: stderr.trim().to_string(),
            })
        }
    }

    // ─────────────────────────────────────────────────────────────────────
    // Status & Info
    // ─────────────────────────────────────────────────────────────────────

    /// Check the current status of the Nginx service.
    pub fn status(&self) -> NginxStatus {
        if self.nginx_bin.is_none() {
            return NginxStatus::NotInstalled;
        }

        match Command::new("systemctl")
            .arg("is-active")
            .arg("nginx")
            .output()
        {
            Ok(output) => {
                let status_str = String::from_utf8_lossy(&output.stdout);
                if status_str.trim() == "active" {
                    NginxStatus::Running
                } else {
                    NginxStatus::Stopped
                }
            }
            Err(_) => NginxStatus::Unknown,
        }
    }

    /// Get the content of the installed config for a specific application.
    pub fn get_config(&self, app_name: &str) -> Result<String> {
        let filename = format!("zeroed-app-{}.conf", app_name);
        let path = self.sites_available_dir.join(&filename);

        if !path.exists() {
            return Err(NginxError::ConfigNotFound {
                app: app_name.to_string(),
            });
        }

        Ok(fs::read_to_string(&path)?)
    }

    /// Check whether a config file exists for the given application.
    pub fn config_exists(&self, app_name: &str) -> bool {
        let filename = format!("zeroed-app-{}.conf", app_name);
        self.sites_available_dir.join(&filename).exists()
    }

    /// List all Zeroed-managed Nginx config filenames.
    pub fn list_managed_configs(&self) -> Result<Vec<String>> {
        let mut configs = Vec::new();

        if !self.sites_available_dir.exists() {
            return Ok(configs);
        }

        for entry in fs::read_dir(&self.sites_available_dir)? {
            let entry = entry?;
            if let Some(name) = entry.file_name().to_str() {
                if name.starts_with("zeroed-app-") && name.ends_with(".conf") {
                    configs.push(name.to_string());
                }
            }
        }

        configs.sort();
        Ok(configs)
    }

    /// Get the sites-available directory path.
    pub fn sites_available_dir(&self) -> &Path {
        &self.sites_available_dir
    }

    /// Get the sites-enabled directory path.
    pub fn sites_enabled_dir(&self) -> &Path {
        &self.sites_enabled_dir
    }

    /// Get the detected layout style.
    pub fn layout_style(&self) -> SiteLayoutStyle {
        self.layout_style
    }

    // ─────────────────────────────────────────────────────────────────────
    // Internal Helpers
    // ─────────────────────────────────────────────────────────────────────

    /// Find the nginx binary on the system.
    fn find_nginx_binary() -> Option<PathBuf> {
        match Command::new("which").arg("nginx").output() {
            Ok(output) if output.status.success() => {
                let path = String::from_utf8_lossy(&output.stdout).trim().to_string();
                if path.is_empty() {
                    None
                } else {
                    Some(PathBuf::from(path))
                }
            }
            _ => None,
        }
    }

    /// Require that nginx is installed, returning the binary path or an error.
    fn require_nginx(&self) -> Result<&PathBuf> {
        self.nginx_bin
            .as_ref()
            .ok_or(NginxError::NotInstalled)
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Tests
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::deploy::app::{AppStatus, Application};
    use tempfile::TempDir;

    fn test_app(
        name: &str,
        app_type: AppType,
        port: u16,
        apps_dir: &Path,
    ) -> Application {
        Application::new(
            name.to_string(),
            name.to_string(),
            app_type,
            "git@github.com:user/repo.git".to_string(),
            port,
            apps_dir,
        )
        .unwrap()
    }

    fn test_manager(tmp: &TempDir) -> NginxManager {
        let sites_available = tmp.path().join("sites-available");
        let sites_enabled = tmp.path().join("sites-enabled");
        fs::create_dir_all(&sites_available).unwrap();
        fs::create_dir_all(&sites_enabled).unwrap();

        NginxManager {
            sites_available_dir: sites_available,
            sites_enabled_dir: sites_enabled,
            layout_style: SiteLayoutStyle::SitesAvailableEnabled,
            nginx_bin: None, // Tests don't require nginx binary
        }
    }

    #[test]
    fn test_nginx_status_display() {
        assert_eq!(format!("{}", NginxStatus::Running), "running");
        assert_eq!(format!("{}", NginxStatus::Stopped), "stopped");
        assert_eq!(format!("{}", NginxStatus::NotInstalled), "not_installed");
        assert_eq!(format!("{}", NginxStatus::Unknown), "unknown");
    }

    #[test]
    fn test_generate_backend_config() {
        let tmp = TempDir::new().unwrap();
        let manager = test_manager(&tmp);
        let apps_dir = tmp.path().join("apps");

        let app = test_app("my-api", AppType::Backend, 3000, &apps_dir);
        let config = manager.generate_config(&app).unwrap();

        assert_eq!(config.filename, "zeroed-app-my-api.conf");
        assert!(config.content.contains("upstream my_api_backend"));
        assert!(config.content.contains("server 127.0.0.1:3000"));
        assert!(config.content.contains("proxy_pass http://my_api_backend"));
        assert!(config.content.contains("listen 80"));
        assert!(config.content.contains("server_name _"));
        assert!(config.content.contains("gzip on"));
        assert!(config.content.contains("X-Frame-Options"));
        assert!(!config.content.contains("listen 443"));
    }

    #[test]
    fn test_generate_backend_config_with_domain() {
        let tmp = TempDir::new().unwrap();
        let manager = test_manager(&tmp);
        let apps_dir = tmp.path().join("apps");

        let mut app = test_app("my-api", AppType::Backend, 3000, &apps_dir);
        app.domain = Some("api.example.com".to_string());

        let config = manager.generate_config(&app).unwrap();
        assert!(config.content.contains("server_name api.example.com"));
    }

    #[test]
    fn test_generate_backend_config_with_ssl() {
        let tmp = TempDir::new().unwrap();
        let manager = test_manager(&tmp);
        let apps_dir = tmp.path().join("apps");

        let mut app = test_app("my-api", AppType::Backend, 3000, &apps_dir);
        app.domain = Some("api.example.com".to_string());
        app.ssl_enabled = true;
        app.ssl_cert_path = Some(PathBuf::from("/etc/letsencrypt/live/api.example.com/fullchain.pem"));
        app.ssl_key_path = Some(PathBuf::from("/etc/letsencrypt/live/api.example.com/privkey.pem"));

        let config = manager.generate_config(&app).unwrap();
        assert!(config.content.contains("listen 443 ssl http2"));
        assert!(config.content.contains("ssl_certificate"));
        assert!(config.content.contains("ssl_certificate_key"));
        assert!(config.content.contains("Strict-Transport-Security"));
        assert!(config.content.contains("return 301 https://"));
    }

    #[test]
    fn test_generate_static_config() {
        let tmp = TempDir::new().unwrap();
        let manager = test_manager(&tmp);
        let apps_dir = tmp.path().join("apps");

        let mut app = test_app("frontend", AppType::StaticSite, 0, &apps_dir);
        app.build_output_dir = Some("dist".to_string());
        app.index_file = "index.html".to_string();
        app.spa_mode = true;

        let config = manager.generate_config(&app).unwrap();
        assert_eq!(config.filename, "zeroed-app-frontend.conf");
        assert!(config.content.contains("index index.html"));
        assert!(config.content.contains("try_files $uri $uri/ /index.html"));
        assert!(config.content.contains("expires 1y"));
        assert!(config.content.contains("Cache-Control"));
        assert!(!config.content.contains("proxy_pass"));
    }

    #[test]
    fn test_generate_static_config_no_spa() {
        let tmp = TempDir::new().unwrap();
        let manager = test_manager(&tmp);
        let apps_dir = tmp.path().join("apps");

        let mut app = test_app("docs-site", AppType::StaticSite, 0, &apps_dir);
        app.build_output_dir = Some("public".to_string());
        app.spa_mode = false;

        let config = manager.generate_config(&app).unwrap();
        assert!(config.content.contains("try_files $uri $uri/ =404"));
        assert!(!config.content.contains("/index.html"));
    }

    #[test]
    fn test_generate_hybrid_config() {
        let tmp = TempDir::new().unwrap();
        let manager = test_manager(&tmp);
        let apps_dir = tmp.path().join("apps");

        let mut app = test_app("fullstack", AppType::Hybrid, 4000, &apps_dir);
        app.build_output_dir = Some("build".to_string());
        app.api_path_prefix = Some("/api".to_string());
        app.spa_mode = true;

        let config = manager.generate_config(&app).unwrap();
        assert!(config.content.contains("upstream fullstack_backend"));
        assert!(config.content.contains("server 127.0.0.1:4000"));
        assert!(config.content.contains("try_files $uri $uri/ /index.html"));
        assert!(config.content.contains("location /api"));
        assert!(config.content.contains("proxy_pass http://fullstack_backend"));
    }

    #[test]
    fn test_install_and_remove_config() {
        let tmp = TempDir::new().unwrap();
        let manager = test_manager(&tmp);

        let config = GeneratedConfig {
            app_name: "test-app".to_string(),
            content: "# test config\nserver { listen 80; }".to_string(),
            filename: "zeroed-app-test-app.conf".to_string(),
        };

        // We can't fully test install_config because it calls nginx -t,
        // but we can test the file writing portion by checking paths
        let available_path = manager.sites_available_dir.join(&config.filename);
        let enabled_path = manager.sites_enabled_dir.join(&config.filename);

        // Manually write to simulate install (without nginx -t)
        fs::write(&available_path, &config.content).unwrap();
        assert!(available_path.exists());

        // Remove
        manager.remove_config("test-app").unwrap();
        assert!(!available_path.exists());
    }

    #[test]
    fn test_config_exists() {
        let tmp = TempDir::new().unwrap();
        let manager = test_manager(&tmp);

        assert!(!manager.config_exists("my-app"));

        let path = manager
            .sites_available_dir
            .join("zeroed-app-my-app.conf");
        fs::write(&path, "# test").unwrap();

        assert!(manager.config_exists("my-app"));
    }

    #[test]
    fn test_list_managed_configs() {
        let tmp = TempDir::new().unwrap();
        let manager = test_manager(&tmp);

        fs::write(
            manager.sites_available_dir.join("zeroed-app-api.conf"),
            "# api",
        )
        .unwrap();
        fs::write(
            manager.sites_available_dir.join("zeroed-app-web.conf"),
            "# web",
        )
        .unwrap();
        fs::write(
            manager.sites_available_dir.join("default"),
            "# default — not managed by zeroed",
        )
        .unwrap();

        let configs = manager.list_managed_configs().unwrap();
        assert_eq!(configs.len(), 2);
        assert!(configs.contains(&"zeroed-app-api.conf".to_string()));
        assert!(configs.contains(&"zeroed-app-web.conf".to_string()));
    }

    #[test]
    fn test_get_config() {
        let tmp = TempDir::new().unwrap();
        let manager = test_manager(&tmp);

        let content = "server { listen 80; server_name example.com; }";
        fs::write(
            manager.sites_available_dir.join("zeroed-app-my-app.conf"),
            content,
        )
        .unwrap();

        let loaded = manager.get_config("my-app").unwrap();
        assert_eq!(loaded, content);
    }

    #[test]
    fn test_get_config_not_found() {
        let tmp = TempDir::new().unwrap();
        let manager = test_manager(&tmp);

        let result = manager.get_config("nonexistent");
        assert!(matches!(result, Err(NginxError::ConfigNotFound { .. })));
    }

    #[test]
    fn test_status_without_nginx() {
        let tmp = TempDir::new().unwrap();
        let manager = NginxManager {
            sites_available_dir: tmp.path().join("sites-available"),
            sites_enabled_dir: tmp.path().join("sites-enabled"),
            layout_style: SiteLayoutStyle::SitesAvailableEnabled,
            nginx_bin: None,
        };

        assert_eq!(manager.status(), NginxStatus::NotInstalled);
    }

    #[test]
    fn test_render_http_redirect() {
        let tmp = TempDir::new().unwrap();
        let manager = test_manager(&tmp);

        let redirect = manager.render_http_redirect("example.com");
        assert!(redirect.contains("listen 80"));
        assert!(redirect.contains("server_name example.com"));
        assert!(redirect.contains("return 301 https://"));
    }

    #[test]
    fn test_block_exploit_paths_in_config() {
        let tmp = TempDir::new().unwrap();
        let manager = test_manager(&tmp);
        let apps_dir = tmp.path().join("apps");

        let app = test_app("my-api", AppType::Backend, 3000, &apps_dir);
        let config = manager.generate_config(&app).unwrap();

        assert!(config.content.contains(".git"));
        assert!(config.content.contains(".env"));
        assert!(config.content.contains("deny all"));
    }
}
