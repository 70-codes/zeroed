//! Application Registry and Lifecycle Management
//!
//! This module defines the core `Application` model, the `AppRegistry` for
//! persisting application metadata, and the `AppType`/`AppStatus` enums that
//! drive the deployment pipeline.
//!
//! ## Overview
//!
//! Every deployed application is represented by an [`Application`] struct that
//! captures everything needed to clone, build, configure, and run it:
//!
//! - Git repository URL and branch
//! - SSH key reference for private repos
//! - Runtime type (backend service, static site, or hybrid)
//! - Port assignment and optional custom domain
//! - Build and start commands
//! - Environment variables
//! - SSL and Nginx configuration state
//! - Deployment history and rollback support
//!
//! The [`AppRegistry`] is responsible for persisting all application metadata
//! to a TOML file on disk, providing CRUD operations, and ensuring uniqueness
//! of application names and port assignments.

pub mod history;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fmt;
use std::path::{Path, PathBuf};
use thiserror::Error;
use tracing::{debug, error, info, warn};

// ─────────────────────────────────────────────────────────────────────────────
// Error Types
// ─────────────────────────────────────────────────────────────────────────────

/// Errors specific to application registry operations.
#[derive(Debug, Error)]
pub enum AppError {
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),

    #[error("Application not found: {name}")]
    NotFound { name: String },

    #[error("Application with name '{name}' already exists")]
    DuplicateName { name: String },

    #[error("Invalid application name '{name}': {reason}")]
    InvalidName { name: String, reason: String },

    #[error("Port {port} is already assigned to application '{app}'")]
    PortConflict { port: u16, app: String },

    #[error("Application '{name}' is currently {status} and cannot perform this action")]
    InvalidState { name: String, status: String },

    #[error("Registry serialization error: {0}")]
    Serialization(String),

    #[error("Registry deserialization error: {0}")]
    Deserialization(String),

    #[error("Validation error: {0}")]
    Validation(String),

    #[error("Maximum number of applications ({max}) reached")]
    MaxAppsReached { max: usize },
}

/// Result alias for app operations.
pub type Result<T> = std::result::Result<T, AppError>;

// ─────────────────────────────────────────────────────────────────────────────
// Application Type
// ─────────────────────────────────────────────────────────────────────────────

/// The kind of application being deployed.
///
/// This determines how Nginx is configured and whether a systemd service
/// is created.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AppType {
    /// A long-running backend process (Node.js, Python, Go, Rust, Java, etc.)
    /// that listens on a port and is reverse-proxied by Nginx.
    /// A systemd service unit is created for process management.
    Backend,

    /// Pre-built static files (React, Vue, Angular, Svelte, Hugo, etc.)
    /// served directly by Nginx. No systemd service is needed.
    /// Nginx is configured with `root`, `index`, and `try_files`.
    StaticSite,

    /// An application that has both a backend service AND static frontend
    /// assets. Nginx routes API paths to the backend upstream and serves
    /// static files for everything else (e.g. Next.js with SSR, or a
    /// monorepo with separate frontend/backend builds).
    Hybrid,
}

impl AppType {
    /// Whether this app type requires a systemd service.
    pub fn needs_service(&self) -> bool {
        matches!(self, AppType::Backend | AppType::Hybrid)
    }

    /// Whether this app type has static files served by Nginx.
    pub fn has_static_files(&self) -> bool {
        matches!(self, AppType::StaticSite | AppType::Hybrid)
    }

    /// Whether this app type requires a port for a backend process.
    pub fn needs_port(&self) -> bool {
        matches!(self, AppType::Backend | AppType::Hybrid)
    }
}

impl Default for AppType {
    fn default() -> Self {
        AppType::Backend
    }
}

impl fmt::Display for AppType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            AppType::Backend => write!(f, "backend"),
            AppType::StaticSite => write!(f, "static_site"),
            AppType::Hybrid => write!(f, "hybrid"),
        }
    }
}

impl std::str::FromStr for AppType {
    type Err = AppError;

    fn from_str(s: &str) -> Result<Self> {
        match s.to_lowercase().as_str() {
            "backend" | "service" | "server" => Ok(AppType::Backend),
            "static" | "static_site" | "staticsite" | "spa" | "frontend" => Ok(AppType::StaticSite),
            "hybrid" | "fullstack" | "full_stack" => Ok(AppType::Hybrid),
            other => Err(AppError::Validation(format!(
                "Unknown app type '{}'. Expected: backend, static_site, or hybrid",
                other
            ))),
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Application Status
// ─────────────────────────────────────────────────────────────────────────────

/// Current runtime status of an application.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AppStatus {
    /// The application service is not running.
    Stopped,
    /// The application service is running and healthy.
    Running,
    /// A deployment is currently in progress.
    Deploying,
    /// The application failed to start or the last deploy failed.
    Failed,
    /// The application has been created but never deployed.
    Created,
    /// The status could not be determined (e.g. systemd query failed).
    Unknown,
}

impl AppStatus {
    /// Whether the application is in a state where a new deploy is allowed.
    pub fn can_deploy(&self) -> bool {
        matches!(
            self,
            AppStatus::Stopped
                | AppStatus::Running
                | AppStatus::Failed
                | AppStatus::Created
                | AppStatus::Unknown
        )
    }

    /// Whether the application is in a state where it can be started.
    pub fn can_start(&self) -> bool {
        matches!(
            self,
            AppStatus::Stopped | AppStatus::Failed | AppStatus::Unknown
        )
    }

    /// Whether the application is in a state where it can be stopped.
    pub fn can_stop(&self) -> bool {
        matches!(self, AppStatus::Running | AppStatus::Unknown)
    }

    /// Whether the application is considered healthy.
    pub fn is_healthy(&self) -> bool {
        matches!(self, AppStatus::Running)
    }
}

impl Default for AppStatus {
    fn default() -> Self {
        AppStatus::Created
    }
}

impl fmt::Display for AppStatus {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            AppStatus::Stopped => write!(f, "stopped"),
            AppStatus::Running => write!(f, "running"),
            AppStatus::Deploying => write!(f, "deploying"),
            AppStatus::Failed => write!(f, "failed"),
            AppStatus::Created => write!(f, "created"),
            AppStatus::Unknown => write!(f, "unknown"),
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Application Model
// ─────────────────────────────────────────────────────────────────────────────

/// Full configuration and state for a managed application.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Application {
    /// Unique identifier (UUID hex string)
    pub id: String,

    /// Unique slug-style name (e.g. "my-api", "frontend-app")
    /// Used in systemd unit names, Nginx config filenames, directory names, etc.
    pub name: String,

    /// Human-friendly display name
    pub display_name: String,

    /// The kind of application
    pub app_type: AppType,

    // ── Git Configuration ──────────────────────────────────────────────

    /// Git repository URL (SSH or HTTPS)
    pub repo_url: String,

    /// Git branch to deploy from
    pub branch: String,

    /// ID of the SSH key to use for private repos (None for public repos)
    pub ssh_key_id: Option<String>,

    // ── Runtime Configuration ──────────────────────────────────────────

    /// Port the application listens on (backend/hybrid) or internal port
    pub port: u16,

    /// Optional custom domain name (e.g. "api.example.com")
    pub domain: Option<String>,

    /// Whether SSL is enabled for this application
    pub ssl_enabled: bool,

    /// Path to the SSL certificate (populated after SSL provisioning)
    pub ssl_cert_path: Option<PathBuf>,

    /// Path to the SSL private key (populated after SSL provisioning)
    pub ssl_key_path: Option<PathBuf>,

    // ── Static Site Configuration ──────────────────────────────────────

    /// Build command (e.g. "npm run build", "cargo build --release")
    pub build_command: Option<String>,

    /// Output directory of the build, relative to repo root (e.g. "dist", "build", "out")
    pub build_output_dir: Option<String>,

    /// The index file for static sites (default: "index.html")
    pub index_file: String,

    /// Whether to enable SPA mode (try_files fallback to index.html)
    pub spa_mode: bool,

    /// Optional base path for sub-path deployments (e.g. "/dashboard")
    pub base_path: Option<String>,

    // ── Backend Service Configuration ──────────────────────────────────

    /// Command to start the application (e.g. "node server.js", "python app.py")
    pub start_command: Option<String>,

    /// Path to a .env file (relative to deploy dir)
    pub env_file: Option<String>,

    /// Environment variables set directly (in addition to env_file)
    pub env_vars: HashMap<String, String>,

    /// Health check URL (e.g. "http://localhost:PORT/health")
    pub health_check_url: Option<String>,

    /// Maximum memory in megabytes for the service (systemd MemoryMax)
    pub memory_limit_mb: Option<u64>,

    /// CPU quota percentage for the service (systemd CPUQuota, e.g. 200 = 2 cores)
    pub cpu_quota_percent: Option<u32>,

    // ── Hybrid-Specific Configuration ──────────────────────────────────

    /// URL path prefix that routes to the backend (e.g. "/api")
    /// All other paths serve static files. Only used for AppType::Hybrid.
    pub api_path_prefix: Option<String>,

    // ── Deployment State ───────────────────────────────────────────────

    /// Current runtime status
    pub status: AppStatus,

    /// ID of the current active deployment (if any)
    pub current_deploy_id: Option<String>,

    /// Current active commit hash
    pub current_commit: Option<String>,

    /// Base directory for this application's files
    pub deploy_dir: PathBuf,

    // ── Metadata ───────────────────────────────────────────────────────

    /// When the application was first registered
    pub created_at: DateTime<Utc>,

    /// When the application configuration was last updated
    pub updated_at: DateTime<Utc>,

    /// When the application was last successfully deployed
    pub last_deployed_at: Option<DateTime<Utc>>,

    /// Free-form notes/description
    pub notes: Option<String>,

    /// Tags for grouping/filtering
    pub tags: Vec<String>,
}

impl Application {
    /// Create a new application with minimal required fields.
    /// All optional fields are set to sensible defaults.
    pub fn new(
        name: String,
        display_name: String,
        app_type: AppType,
        repo_url: String,
        port: u16,
        apps_dir: &Path,
    ) -> Result<Self> {
        validate_app_name(&name)?;

        let now = Utc::now();
        let deploy_dir = apps_dir.join(&name);

        Ok(Self {
            id: generate_app_id(),
            name,
            display_name,
            app_type,
            repo_url,
            branch: "main".to_string(),
            ssh_key_id: None,
            port,
            domain: None,
            ssl_enabled: false,
            ssl_cert_path: None,
            ssl_key_path: None,
            build_command: None,
            build_output_dir: None,
            index_file: "index.html".to_string(),
            spa_mode: true,
            base_path: None,
            start_command: None,
            env_file: None,
            env_vars: HashMap::new(),
            health_check_url: None,
            memory_limit_mb: Some(512),
            cpu_quota_percent: None,
            api_path_prefix: None,
            status: AppStatus::Created,
            current_deploy_id: None,
            current_commit: None,
            deploy_dir,
            created_at: now,
            updated_at: now,
            last_deployed_at: None,
            notes: None,
            tags: Vec::new(),
        })
    }

    /// Get the path to the persistent git checkout for this application.
    pub fn repo_dir(&self) -> PathBuf {
        self.deploy_dir.join("repo")
    }

    /// Get the path to the releases directory.
    pub fn releases_dir(&self) -> PathBuf {
        self.deploy_dir.join("releases")
    }

    /// Get the path to the `current` symlink (points to the active release).
    pub fn current_link(&self) -> PathBuf {
        self.deploy_dir.join("current")
    }

    /// Get the path to the shared directory (persistent across releases).
    pub fn shared_dir(&self) -> PathBuf {
        self.deploy_dir.join("shared")
    }

    /// Get the path to the deploy history directory.
    pub fn deploys_dir(&self) -> PathBuf {
        self.deploy_dir.join("deploys")
    }

    /// Get the path to the environment file.
    pub fn env_file_path(&self) -> PathBuf {
        self.deploy_dir.join(".env")
    }

    /// The systemd service unit name for this application.
    pub fn service_name(&self) -> String {
        format!("zeroed-app-{}", self.name)
    }

    /// The Nginx config filename for this application.
    pub fn nginx_config_name(&self) -> String {
        format!("zeroed-app-{}.conf", self.name)
    }

    /// The syslog identifier used in journalctl.
    pub fn syslog_identifier(&self) -> String {
        format!("zeroed-app-{}", self.name)
    }

    /// Build the resolved root directory for static file serving.
    /// This is `current/<build_output_dir>` or just `current/` if no build dir is set.
    pub fn static_root(&self) -> PathBuf {
        let base = self.current_link();
        match &self.build_output_dir {
            Some(dir) => base.join(dir),
            None => base,
        }
    }

    /// Whether this application has been deployed at least once.
    pub fn has_been_deployed(&self) -> bool {
        self.current_deploy_id.is_some()
    }

    /// Whether this application has a custom domain configured.
    pub fn has_domain(&self) -> bool {
        self.domain.is_some()
    }

    /// Whether this application needs a systemd service.
    pub fn needs_service(&self) -> bool {
        self.app_type.needs_service()
    }

    /// Touch the `updated_at` timestamp.
    pub fn touch(&mut self) {
        self.updated_at = Utc::now();
    }

    /// Validate the application configuration for completeness and correctness.
    pub fn validate(&self) -> Result<()> {
        validate_app_name(&self.name)?;

        if self.repo_url.is_empty() {
            return Err(AppError::Validation(
                "repo_url cannot be empty".to_string(),
            ));
        }

        if self.branch.is_empty() {
            return Err(AppError::Validation("branch cannot be empty".to_string()));
        }

        // Backend and hybrid apps need a start command or a way to detect one
        if self.app_type.needs_service() && self.start_command.is_none() && self.has_been_deployed()
        {
            warn!(
                "Application '{}' is a {} app but has no start_command set",
                self.name, self.app_type
            );
        }

        // Static sites should have an index file
        if self.app_type.has_static_files() && self.index_file.is_empty() {
            return Err(AppError::Validation(
                "index_file cannot be empty for static sites".to_string(),
            ));
        }

        // Validate port range
        if self.app_type.needs_port() && self.port == 0 {
            return Err(AppError::Validation(
                "port must be set for backend/hybrid apps".to_string(),
            ));
        }

        // Validate domain format if set
        if let Some(ref domain) = self.domain {
            if domain.is_empty() {
                return Err(AppError::Validation(
                    "domain cannot be an empty string (use None instead)".to_string(),
                ));
            }
            if domain.contains(' ') || domain.starts_with('.') || domain.ends_with('.') {
                return Err(AppError::Validation(format!(
                    "Invalid domain format: '{}'",
                    domain
                )));
            }
        }

        // SSL requires a domain
        if self.ssl_enabled && self.domain.is_none() {
            return Err(AppError::Validation(
                "SSL cannot be enabled without a domain".to_string(),
            ));
        }

        // Hybrid apps should have an api_path_prefix
        if self.app_type == AppType::Hybrid && self.api_path_prefix.is_none() {
            warn!(
                "Hybrid application '{}' has no api_path_prefix set — defaulting to /api",
                self.name
            );
        }

        Ok(())
    }
}

impl fmt::Display for Application {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{} ({}) [{}] port={} status={}",
            self.name, self.app_type, self.id, self.port, self.status
        )
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Application Registry (On-Disk Persistence)
// ─────────────────────────────────────────────────────────────────────────────

/// Serializable registry that holds all managed applications.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
struct RegistryData {
    /// Map from app name to Application
    apps: HashMap<String, Application>,
}

/// The application registry — responsible for CRUD operations on applications
/// and persisting state to a TOML file on disk.
pub struct AppRegistry {
    /// Path to the registry file
    path: PathBuf,

    /// In-memory registry data
    data: RegistryData,
}

impl AppRegistry {
    /// Create a new app registry, loading existing data from disk if present.
    pub fn new(path: PathBuf) -> Result<Self> {
        let data = if path.exists() {
            let content = std::fs::read_to_string(&path).map_err(AppError::Io)?;
            toml::from_str(&content).map_err(|e| AppError::Deserialization(e.to_string()))?
        } else {
            RegistryData::default()
        };

        info!(
            "Application registry loaded: {} apps from {:?}",
            data.apps.len(),
            path
        );

        Ok(Self { path, data })
    }

    /// Persist the registry to disk.
    fn save(&self) -> Result<()> {
        if let Some(parent) = self.path.parent() {
            std::fs::create_dir_all(parent).map_err(AppError::Io)?;
        }

        let content =
            toml::to_string_pretty(&self.data).map_err(|e| AppError::Serialization(e.to_string()))?;

        // Atomic write: temp file → rename
        let tmp_path = self.path.with_extension("toml.tmp");
        std::fs::write(&tmp_path, &content).map_err(AppError::Io)?;
        std::fs::rename(&tmp_path, &self.path).map_err(AppError::Io)?;

        debug!("Application registry saved to {:?}", self.path);
        Ok(())
    }

    // ── CRUD Operations ────────────────────────────────────────────────

    /// Register a new application.
    pub fn register(&mut self, app: Application) -> Result<Application> {
        // Check name uniqueness
        if self.data.apps.contains_key(&app.name) {
            return Err(AppError::DuplicateName {
                name: app.name.clone(),
            });
        }

        // Validate
        app.validate()?;

        // Check port conflict (only for apps that need a port)
        if app.app_type.needs_port() {
            if let Some(conflict) = self.find_app_by_port(app.port) {
                return Err(AppError::PortConflict {
                    port: app.port,
                    app: conflict.name.clone(),
                });
            }
        }

        info!("Registering application: {}", app);
        self.data.apps.insert(app.name.clone(), app.clone());
        self.save()?;

        Ok(app)
    }

    /// Update an existing application's configuration.
    pub fn update(&mut self, name: &str, updater: impl FnOnce(&mut Application)) -> Result<Application> {
        let app = self
            .data
            .apps
            .get_mut(name)
            .ok_or_else(|| AppError::NotFound {
                name: name.to_string(),
            })?;

        updater(app);
        app.touch();
        app.validate()?;

        let updated = app.clone();
        self.save()?;

        info!("Updated application: {}", updated.name);
        Ok(updated)
    }

    /// Unregister (delete) an application from the registry.
    ///
    /// This only removes the registry entry. It does NOT delete files on disk,
    /// stop services, or remove Nginx configs. The caller is responsible for
    /// orchestrating the full teardown.
    pub fn unregister(&mut self, name: &str) -> Result<Application> {
        let app = self
            .data
            .apps
            .remove(name)
            .ok_or_else(|| AppError::NotFound {
                name: name.to_string(),
            })?;

        self.save()?;
        info!("Unregistered application: {}", app.name);
        Ok(app)
    }

    /// Get an application by name.
    pub fn get(&self, name: &str) -> Option<&Application> {
        self.data.apps.get(name)
    }

    /// Get a mutable reference to an application by name.
    pub fn get_mut(&mut self, name: &str) -> Option<&mut Application> {
        self.data.apps.get_mut(name)
    }

    /// Get an application by its ID.
    pub fn get_by_id(&self, id: &str) -> Option<&Application> {
        self.data.apps.values().find(|a| a.id == id)
    }

    /// List all applications, sorted by name.
    pub fn list(&self) -> Vec<&Application> {
        let mut apps: Vec<&Application> = self.data.apps.values().collect();
        apps.sort_by(|a, b| a.name.cmp(&b.name));
        apps
    }

    /// List applications filtered by status.
    pub fn list_by_status(&self, status: AppStatus) -> Vec<&Application> {
        self.data
            .apps
            .values()
            .filter(|a| a.status == status)
            .collect()
    }

    /// List applications filtered by type.
    pub fn list_by_type(&self, app_type: AppType) -> Vec<&Application> {
        self.data
            .apps
            .values()
            .filter(|a| a.app_type == app_type)
            .collect()
    }

    /// Find an application that is using a specific port.
    pub fn find_app_by_port(&self, port: u16) -> Option<&Application> {
        self.data
            .apps
            .values()
            .find(|a| a.app_type.needs_port() && a.port == port)
    }

    /// Find an application by domain name.
    pub fn find_app_by_domain(&self, domain: &str) -> Option<&Application> {
        self.data
            .apps
            .values()
            .find(|a| a.domain.as_deref() == Some(domain))
    }

    /// Total number of registered applications.
    pub fn count(&self) -> usize {
        self.data.apps.len()
    }

    /// Check if an application with the given name exists.
    pub fn exists(&self, name: &str) -> bool {
        self.data.apps.contains_key(name)
    }

    // ── Status Updates ─────────────────────────────────────────────────

    /// Update the status of an application and persist.
    pub fn set_status(&mut self, name: &str, status: AppStatus) -> Result<()> {
        let app = self
            .data
            .apps
            .get_mut(name)
            .ok_or_else(|| AppError::NotFound {
                name: name.to_string(),
            })?;

        let old_status = app.status;
        app.status = status;
        app.touch();
        self.save()?;

        debug!(
            "Application '{}' status changed: {} -> {}",
            name, old_status, status
        );
        Ok(())
    }

    /// Record a successful deployment.
    pub fn record_deploy(
        &mut self,
        name: &str,
        deploy_id: &str,
        commit_hash: &str,
    ) -> Result<()> {
        let app = self
            .data
            .apps
            .get_mut(name)
            .ok_or_else(|| AppError::NotFound {
                name: name.to_string(),
            })?;

        app.current_deploy_id = Some(deploy_id.to_string());
        app.current_commit = Some(commit_hash.to_string());
        app.last_deployed_at = Some(Utc::now());
        app.status = AppStatus::Running;
        app.touch();
        self.save()?;

        info!(
            "Deployment recorded for '{}': deploy={}, commit={}",
            name, deploy_id, commit_hash
        );
        Ok(())
    }

    // ── Bulk Operations ────────────────────────────────────────────────

    /// Get all port numbers currently in use.
    pub fn allocated_ports(&self) -> Vec<(u16, String)> {
        self.data
            .apps
            .values()
            .filter(|a| a.app_type.needs_port())
            .map(|a| (a.port, a.name.clone()))
            .collect()
    }

    /// Get all domains currently in use.
    pub fn allocated_domains(&self) -> Vec<(String, String)> {
        self.data
            .apps
            .values()
            .filter_map(|a| a.domain.as_ref().map(|d| (d.clone(), a.name.clone())))
            .collect()
    }

    /// Reload the registry from disk.
    pub fn reload(&mut self) -> Result<()> {
        if self.path.exists() {
            let content = std::fs::read_to_string(&self.path).map_err(AppError::Io)?;
            self.data =
                toml::from_str(&content).map_err(|e| AppError::Deserialization(e.to_string()))?;
            info!(
                "Application registry reloaded: {} apps",
                self.data.apps.len()
            );
        }
        Ok(())
    }

    /// Get a summary of all applications for display.
    pub fn summary(&self) -> RegistrySummary {
        let apps: Vec<&Application> = self.data.apps.values().collect();

        RegistrySummary {
            total: apps.len(),
            running: apps.iter().filter(|a| a.status == AppStatus::Running).count(),
            stopped: apps.iter().filter(|a| a.status == AppStatus::Stopped).count(),
            failed: apps.iter().filter(|a| a.status == AppStatus::Failed).count(),
            deploying: apps.iter().filter(|a| a.status == AppStatus::Deploying).count(),
            created: apps.iter().filter(|a| a.status == AppStatus::Created).count(),
            backends: apps.iter().filter(|a| a.app_type == AppType::Backend).count(),
            static_sites: apps.iter().filter(|a| a.app_type == AppType::StaticSite).count(),
            hybrids: apps.iter().filter(|a| a.app_type == AppType::Hybrid).count(),
            with_ssl: apps.iter().filter(|a| a.ssl_enabled).count(),
            with_domain: apps.iter().filter(|a| a.domain.is_some()).count(),
        }
    }
}

/// Summary statistics about the application registry.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RegistrySummary {
    pub total: usize,
    pub running: usize,
    pub stopped: usize,
    pub failed: usize,
    pub deploying: usize,
    pub created: usize,
    pub backends: usize,
    pub static_sites: usize,
    pub hybrids: usize,
    pub with_ssl: usize,
    pub with_domain: usize,
}

// ─────────────────────────────────────────────────────────────────────────────
// Validation Helpers
// ─────────────────────────────────────────────────────────────────────────────

/// Validate that an application name is a valid slug.
///
/// Rules:
/// - Only lowercase alphanumeric characters and hyphens
/// - Must start and end with an alphanumeric character
/// - Must be between 1 and 63 characters (DNS label compatible)
/// - Cannot be a reserved name
fn validate_app_name(name: &str) -> Result<()> {
    if name.is_empty() {
        return Err(AppError::InvalidName {
            name: name.to_string(),
            reason: "name cannot be empty".to_string(),
        });
    }

    if name.len() > 63 {
        return Err(AppError::InvalidName {
            name: name.to_string(),
            reason: "name must be 63 characters or fewer".to_string(),
        });
    }

    if !name
        .chars()
        .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-')
    {
        return Err(AppError::InvalidName {
            name: name.to_string(),
            reason: "name must contain only lowercase letters, digits, and hyphens".to_string(),
        });
    }

    if name.starts_with('-') || name.ends_with('-') {
        return Err(AppError::InvalidName {
            name: name.to_string(),
            reason: "name must start and end with a letter or digit".to_string(),
        });
    }

    if name.contains("--") {
        return Err(AppError::InvalidName {
            name: name.to_string(),
            reason: "name cannot contain consecutive hyphens".to_string(),
        });
    }

    // Reserved names that could conflict with system resources
    const RESERVED: &[&str] = &[
        "default",
        "nginx",
        "zeroed",
        "system",
        "root",
        "admin",
        "localhost",
        "test",
    ];

    if RESERVED.contains(&name) {
        return Err(AppError::InvalidName {
            name: name.to_string(),
            reason: format!("'{}' is a reserved name", name),
        });
    }

    Ok(())
}

/// Generate a unique application ID.
fn generate_app_id() -> String {
    use std::time::{SystemTime, UNIX_EPOCH};

    let timestamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos();

    let mut h: u64 = 0x517c_c1b7_2722_0a95;
    for byte in timestamp.to_le_bytes() {
        h ^= byte as u64;
        h = h.wrapping_mul(0x0100_0000_01b3);
    }
    h ^= std::process::id() as u64;
    h = h.wrapping_mul(0x0100_0000_01b3);

    format!("app-{:016x}", h)
}

// ─────────────────────────────────────────────────────────────────────────────
// Tests
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    fn test_apps_dir() -> TempDir {
        TempDir::new().unwrap()
    }

    #[test]
    fn test_app_type_properties() {
        assert!(AppType::Backend.needs_service());
        assert!(AppType::Backend.needs_port());
        assert!(!AppType::Backend.has_static_files());

        assert!(!AppType::StaticSite.needs_service());
        assert!(!AppType::StaticSite.needs_port());
        assert!(AppType::StaticSite.has_static_files());

        assert!(AppType::Hybrid.needs_service());
        assert!(AppType::Hybrid.needs_port());
        assert!(AppType::Hybrid.has_static_files());
    }

    #[test]
    fn test_app_type_from_str() {
        assert_eq!("backend".parse::<AppType>().unwrap(), AppType::Backend);
        assert_eq!("static".parse::<AppType>().unwrap(), AppType::StaticSite);
        assert_eq!("static_site".parse::<AppType>().unwrap(), AppType::StaticSite);
        assert_eq!("spa".parse::<AppType>().unwrap(), AppType::StaticSite);
        assert_eq!("hybrid".parse::<AppType>().unwrap(), AppType::Hybrid);
        assert_eq!("fullstack".parse::<AppType>().unwrap(), AppType::Hybrid);
        assert!("invalid".parse::<AppType>().is_err());
    }

    #[test]
    fn test_app_status_transitions() {
        assert!(AppStatus::Created.can_deploy());
        assert!(AppStatus::Running.can_deploy());
        assert!(AppStatus::Stopped.can_deploy());
        assert!(AppStatus::Failed.can_deploy());
        assert!(!AppStatus::Deploying.can_deploy());

        assert!(AppStatus::Stopped.can_start());
        assert!(!AppStatus::Running.can_start());

        assert!(AppStatus::Running.can_stop());
        assert!(!AppStatus::Stopped.can_stop());

        assert!(AppStatus::Running.is_healthy());
        assert!(!AppStatus::Failed.is_healthy());
    }

    #[test]
    fn test_validate_app_name_valid() {
        assert!(validate_app_name("my-app").is_ok());
        assert!(validate_app_name("frontend").is_ok());
        assert!(validate_app_name("api-v2").is_ok());
        assert!(validate_app_name("a").is_ok());
        assert!(validate_app_name("app123").is_ok());
    }

    #[test]
    fn test_validate_app_name_invalid() {
        assert!(validate_app_name("").is_err());
        assert!(validate_app_name("-start-with-hyphen").is_err());
        assert!(validate_app_name("end-with-hyphen-").is_err());
        assert!(validate_app_name("UPPERCASE").is_err());
        assert!(validate_app_name("has space").is_err());
        assert!(validate_app_name("has.dot").is_err());
        assert!(validate_app_name("double--hyphen").is_err());
        assert!(validate_app_name("has_underscore").is_err());
    }

    #[test]
    fn test_validate_app_name_reserved() {
        assert!(validate_app_name("nginx").is_err());
        assert!(validate_app_name("zeroed").is_err());
        assert!(validate_app_name("root").is_err());
        assert!(validate_app_name("default").is_err());
    }

    #[test]
    fn test_application_new() {
        let tmp = test_apps_dir();
        let app = Application::new(
            "my-api".to_string(),
            "My API".to_string(),
            AppType::Backend,
            "git@github.com:user/repo.git".to_string(),
            3000,
            tmp.path(),
        )
        .unwrap();

        assert_eq!(app.name, "my-api");
        assert_eq!(app.display_name, "My API");
        assert_eq!(app.app_type, AppType::Backend);
        assert_eq!(app.port, 3000);
        assert_eq!(app.branch, "main");
        assert_eq!(app.status, AppStatus::Created);
        assert_eq!(app.index_file, "index.html");
        assert!(app.spa_mode);
        assert!(!app.ssl_enabled);
        assert!(!app.has_been_deployed());
        assert!(!app.has_domain());
        assert!(app.needs_service());
    }

    #[test]
    fn test_application_paths() {
        let tmp = test_apps_dir();
        let app = Application::new(
            "my-api".to_string(),
            "My API".to_string(),
            AppType::Backend,
            "git@github.com:user/repo.git".to_string(),
            3000,
            tmp.path(),
        )
        .unwrap();

        assert!(app.repo_dir().ends_with("my-api/repo"));
        assert!(app.releases_dir().ends_with("my-api/releases"));
        assert!(app.current_link().ends_with("my-api/current"));
        assert!(app.shared_dir().ends_with("my-api/shared"));
        assert!(app.deploys_dir().ends_with("my-api/deploys"));
        assert!(app.env_file_path().ends_with("my-api/.env"));
        assert_eq!(app.service_name(), "zeroed-app-my-api");
        assert_eq!(app.nginx_config_name(), "zeroed-app-my-api.conf");
        assert_eq!(app.syslog_identifier(), "zeroed-app-my-api");
    }

    #[test]
    fn test_application_static_root() {
        let tmp = test_apps_dir();

        let mut app = Application::new(
            "frontend".to_string(),
            "Frontend".to_string(),
            AppType::StaticSite,
            "https://github.com/user/repo.git".to_string(),
            0,
            tmp.path(),
        )
        .unwrap();

        // Without build_output_dir
        assert!(app.static_root().ends_with("frontend/current"));

        // With build_output_dir
        app.build_output_dir = Some("dist".to_string());
        assert!(app.static_root().ends_with("frontend/current/dist"));
    }

    #[test]
    fn test_application_validation() {
        let tmp = test_apps_dir();

        // Valid app
        let app = Application::new(
            "valid-app".to_string(),
            "Valid App".to_string(),
            AppType::Backend,
            "git@github.com:user/repo.git".to_string(),
            3000,
            tmp.path(),
        )
        .unwrap();
        assert!(app.validate().is_ok());

        // Empty repo URL
        let mut bad_app = app.clone();
        bad_app.repo_url = String::new();
        assert!(bad_app.validate().is_err());

        // SSL without domain
        let mut bad_app = app.clone();
        bad_app.ssl_enabled = true;
        bad_app.domain = None;
        assert!(bad_app.validate().is_err());

        // Invalid domain
        let mut bad_app = app.clone();
        bad_app.domain = Some(".bad.domain".to_string());
        assert!(bad_app.validate().is_err());
    }

    #[test]
    fn test_app_registry_crud() {
        let tmp = test_apps_dir();
        let registry_path = tmp.path().join("registry.toml");
        let mut registry = AppRegistry::new(registry_path).unwrap();

        assert_eq!(registry.count(), 0);

        // Register
        let app = Application::new(
            "my-app".to_string(),
            "My App".to_string(),
            AppType::Backend,
            "git@github.com:user/repo.git".to_string(),
            3000,
            tmp.path(),
        )
        .unwrap();

        let registered = registry.register(app).unwrap();
        assert_eq!(registry.count(), 1);

        // Get
        let fetched = registry.get("my-app").unwrap();
        assert_eq!(fetched.name, "my-app");
        assert_eq!(fetched.id, registered.id);

        // Update
        let updated = registry
            .update("my-app", |app| {
                app.port = 4000;
            })
            .unwrap();
        assert_eq!(updated.port, 4000);
        assert_eq!(registry.get("my-app").unwrap().port, 4000);

        // Unregister
        let removed = registry.unregister("my-app").unwrap();
        assert_eq!(removed.name, "my-app");
        assert_eq!(registry.count(), 0);
    }

    #[test]
    fn test_app_registry_duplicate_name() {
        let tmp = test_apps_dir();
        let registry_path = tmp.path().join("registry.toml");
        let mut registry = AppRegistry::new(registry_path).unwrap();

        let app = Application::new(
            "my-app".to_string(),
            "My App".to_string(),
            AppType::Backend,
            "git@github.com:user/repo.git".to_string(),
            3000,
            tmp.path(),
        )
        .unwrap();

        registry.register(app.clone()).unwrap();

        // Second registration with same name should fail
        let result = registry.register(app);
        assert!(matches!(result, Err(AppError::DuplicateName { .. })));
    }

    #[test]
    fn test_app_registry_port_conflict() {
        let tmp = test_apps_dir();
        let registry_path = tmp.path().join("registry.toml");
        let mut registry = AppRegistry::new(registry_path).unwrap();

        let app1 = Application::new(
            "app-one".to_string(),
            "App One".to_string(),
            AppType::Backend,
            "git@github.com:user/repo1.git".to_string(),
            3000,
            tmp.path(),
        )
        .unwrap();

        registry.register(app1).unwrap();

        let app2 = Application::new(
            "app-two".to_string(),
            "App Two".to_string(),
            AppType::Backend,
            "git@github.com:user/repo2.git".to_string(),
            3000, // same port!
            tmp.path(),
        )
        .unwrap();

        let result = registry.register(app2);
        assert!(matches!(result, Err(AppError::PortConflict { .. })));
    }

    #[test]
    fn test_app_registry_no_port_conflict_for_static_sites() {
        let tmp = test_apps_dir();
        let registry_path = tmp.path().join("registry.toml");
        let mut registry = AppRegistry::new(registry_path).unwrap();

        // Static sites don't need ports, so port 0 shouldn't conflict
        let app1 = Application::new(
            "site-one".to_string(),
            "Site One".to_string(),
            AppType::StaticSite,
            "git@github.com:user/repo1.git".to_string(),
            0,
            tmp.path(),
        )
        .unwrap();

        let app2 = Application::new(
            "site-two".to_string(),
            "Site Two".to_string(),
            AppType::StaticSite,
            "git@github.com:user/repo2.git".to_string(),
            0,
            tmp.path(),
        )
        .unwrap();

        registry.register(app1).unwrap();
        registry.register(app2).unwrap();
        assert_eq!(registry.count(), 2);
    }

    #[test]
    fn test_app_registry_persistence() {
        let tmp = test_apps_dir();
        let registry_path = tmp.path().join("registry.toml");

        // Create and populate registry
        {
            let mut registry = AppRegistry::new(registry_path.clone()).unwrap();
            let app = Application::new(
                "persistent-app".to_string(),
                "Persistent App".to_string(),
                AppType::Backend,
                "git@github.com:user/repo.git".to_string(),
                3000,
                tmp.path(),
            )
            .unwrap();
            registry.register(app).unwrap();
        }

        // Load from disk and verify
        {
            let registry = AppRegistry::new(registry_path).unwrap();
            assert_eq!(registry.count(), 1);
            let app = registry.get("persistent-app").unwrap();
            assert_eq!(app.port, 3000);
        }
    }

    #[test]
    fn test_app_registry_status_update() {
        let tmp = test_apps_dir();
        let registry_path = tmp.path().join("registry.toml");
        let mut registry = AppRegistry::new(registry_path).unwrap();

        let app = Application::new(
            "my-app".to_string(),
            "My App".to_string(),
            AppType::Backend,
            "git@github.com:user/repo.git".to_string(),
            3000,
            tmp.path(),
        )
        .unwrap();
        registry.register(app).unwrap();

        assert_eq!(registry.get("my-app").unwrap().status, AppStatus::Created);

        registry.set_status("my-app", AppStatus::Running).unwrap();
        assert_eq!(registry.get("my-app").unwrap().status, AppStatus::Running);
    }

    #[test]
    fn test_app_registry_summary() {
        let tmp = test_apps_dir();
        let registry_path = tmp.path().join("registry.toml");
        let mut registry = AppRegistry::new(registry_path).unwrap();

        let app1 = Application::new(
            "backend-app".to_string(),
            "Backend".to_string(),
            AppType::Backend,
            "git@github.com:user/repo1.git".to_string(),
            3000,
            tmp.path(),
        )
        .unwrap();

        let app2 = Application::new(
            "frontend-app".to_string(),
            "Frontend".to_string(),
            AppType::StaticSite,
            "git@github.com:user/repo2.git".to_string(),
            0,
            tmp.path(),
        )
        .unwrap();

        registry.register(app1).unwrap();
        registry.register(app2).unwrap();

        let summary = registry.summary();
        assert_eq!(summary.total, 2);
        assert_eq!(summary.created, 2);
        assert_eq!(summary.backends, 1);
        assert_eq!(summary.static_sites, 1);
    }

    #[test]
    fn test_generate_app_id() {
        let id = generate_app_id();
        assert!(id.starts_with("app-"));
        assert!(id.len() > 4);
    }
}
