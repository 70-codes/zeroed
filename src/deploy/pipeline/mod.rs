//! Deployment Pipeline Module
//!
//! This module orchestrates the full deployment workflow for applications,
//! coordinating git operations, build steps, release management, service
//! configuration, and health checks into an ordered pipeline.
//!
//! ## Pipeline Steps
//!
//! A full deployment executes the following steps in order:
//!
//! 1. **PRE_DEPLOY** — Validate configuration, check prerequisites, acquire locks
//! 2. **GIT_CLONE/GIT_PULL** — Clone the repository (first deploy) or pull latest changes
//! 3. **DETECT** — Auto-detect project type, build system, and runtime if not specified
//! 4. **INSTALL_DEPS** — Install dependencies (npm ci, pip install, cargo fetch, etc.)
//! 5. **BUILD** — Run the build command (npm run build, cargo build --release, etc.)
//! 6. **VERIFY_BUILD** — Check that the build output directory exists and is non-empty
//! 7. **INSTALL** — Copy build artifacts to a new release directory
//! 8. **CONFIGURE** — Generate Nginx config and systemd unit file
//! 9. **ACTIVATE** — Swap the `current` symlink, start/restart services, reload Nginx
//! 10. **HEALTH_CHECK** — Verify the application is responding correctly
//! 11. **POST_DEPLOY** — Clean up old releases, update registry, log success
//!
//! ## Failure Handling
//!
//! If any step fails, the pipeline:
//! - Logs the error with full context
//! - Attempts automatic rollback to the previous release (if one exists)
//! - Marks the deployment as `Failed` with the error details
//! - Does NOT leave the application in a broken state if a previous version existed
//!
//! ## Dry Run Mode
//!
//! The pipeline supports a dry-run mode that logs what each step would do
//! without actually making any changes. This is useful for validating
//! configuration before committing to a deployment.
//!
//! ## Concurrency
//!
//! Only one deployment per application can run at a time. The pipeline
//! acquires a per-app lock before starting and releases it on completion
//! (or failure). Attempting to deploy an app that is already deploying
//! returns an error immediately.

use crate::deploy::app::history::{
    DeployHistory, DeployLogWriter, DeployRecord, DeployStatus, DeployTrigger, PipelineStep,
    StepRecord,
};
use crate::deploy::app::{AppStatus, AppType, Application};
use crate::deploy::nginx::NginxManager;
use crate::deploy::ports::PortAllocator;
use crate::deploy::ssh::SshKeyManager;
use crate::deploy::ssl::SslManager;
use crate::deploy::systemd::SystemdManager;
use crate::deploy::DeployConfig;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use std::fmt;
use std::fs;
use std::io;
use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};
use std::sync::{Arc, Mutex};
use std::time::Duration;
use thiserror::Error;
use tracing::{debug, error, info, warn};

// ─────────────────────────────────────────────────────────────────────────────
// Error Types
// ─────────────────────────────────────────────────────────────────────────────

/// Errors that can occur during the deployment pipeline.
#[derive(Debug, Error)]
pub enum PipelineError {
    #[error("IO error: {0}")]
    Io(#[from] io::Error),

    #[error("Pipeline step '{step}' failed: {message}")]
    StepFailed { step: String, message: String },

    #[error("Application '{app}' is already being deployed")]
    DeploymentInProgress { app: String },

    #[error("Application '{app}' has never been deployed — cannot rollback")]
    NoPreviousRelease { app: String },

    #[error("Rollback failed for '{app}': {message}")]
    RollbackFailed { app: String, message: String },

    #[error("Health check failed for '{app}': {message}")]
    HealthCheckFailed { app: String, message: String },

    #[error("Build timeout exceeded ({timeout_secs}s) for '{app}'")]
    BuildTimeout { app: String, timeout_secs: u64 },

    #[error("Git operation failed: {message}")]
    GitError { message: String },

    #[error("Build failed: {message}")]
    BuildError { message: String },

    #[error("Project detection failed: {message}")]
    DetectionError { message: String },

    #[error("Configuration error: {message}")]
    ConfigError { message: String },

    #[error("Prerequisite check failed: {message}")]
    PrerequisiteFailed { message: String },

    #[error("Lock acquisition failed for app '{app}'")]
    LockFailed { app: String },

    #[error("SSH key error: {0}")]
    SshKeyError(String),

    #[error("Nginx error: {0}")]
    NginxError(String),

    #[error("Systemd error: {0}")]
    SystemdError(String),

    #[error("SSL error: {0}")]
    SslError(String),

    #[error("Port error: {0}")]
    PortError(String),
}

/// Result alias for pipeline operations.
pub type Result<T> = std::result::Result<T, PipelineError>;

// ─────────────────────────────────────────────────────────────────────────────
// Detected Project Type
// ─────────────────────────────────────────────────────────────────────────────

/// The detected project framework/toolchain, used to infer build commands
/// and output directories when the user hasn't specified them explicitly.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DetectedProject {
    /// React (Create React App) — build dir: `build/`
    ReactCra,
    /// Vite-based project (React, Vue, Svelte, etc.) — build dir: `dist/`
    Vite,
    /// Next.js — build dir: `.next/` (SSR) or `out/` (static export)
    NextJs,
    /// Nuxt.js — build dir: `.output/public/` or `dist/`
    NuxtJs,
    /// Angular CLI — build dir: `dist/<project-name>/`
    Angular,
    /// SvelteKit — build dir: `build/`
    SvelteKit,
    /// Gatsby — build dir: `public/`
    Gatsby,
    /// Hugo — build dir: `public/`
    Hugo,
    /// Jekyll — build dir: `_site/`
    Jekyll,
    /// Plain static site (index.html at root, no build needed)
    PlainStatic,
    /// Node.js backend (has package.json with a start script)
    NodeBackend,
    /// Python backend (has requirements.txt or setup.py or pyproject.toml)
    PythonBackend,
    /// Rust backend (has Cargo.toml)
    RustBackend,
    /// Go backend (has go.mod)
    GoBackend,
    /// Java / Spring Boot (has pom.xml or build.gradle)
    JavaBackend,
    /// Unknown project type — user must specify commands manually
    Unknown,
}

impl DetectedProject {
    /// The default build command for this project type (if applicable).
    pub fn default_build_command(&self) -> Option<&'static str> {
        match self {
            DetectedProject::ReactCra => Some("npm run build"),
            DetectedProject::Vite => Some("npm run build"),
            DetectedProject::NextJs => Some("npm run build"),
            DetectedProject::NuxtJs => Some("npm run build"),
            DetectedProject::Angular => Some("npm run build"),
            DetectedProject::SvelteKit => Some("npm run build"),
            DetectedProject::Gatsby => Some("npm run build"),
            DetectedProject::Hugo => Some("hugo --minify"),
            DetectedProject::Jekyll => Some("bundle exec jekyll build"),
            DetectedProject::PlainStatic => None,
            DetectedProject::NodeBackend => None,
            DetectedProject::PythonBackend => None,
            DetectedProject::RustBackend => Some("cargo build --release"),
            DetectedProject::GoBackend => Some("go build -o app ."),
            DetectedProject::JavaBackend => Some("./mvnw package -DskipTests"),
            DetectedProject::Unknown => None,
        }
    }

    /// The default build output directory for this project type (if applicable).
    pub fn default_build_output_dir(&self) -> Option<&'static str> {
        match self {
            DetectedProject::ReactCra => Some("build"),
            DetectedProject::Vite => Some("dist"),
            DetectedProject::NextJs => Some("out"),
            DetectedProject::NuxtJs => Some("dist"),
            DetectedProject::Angular => Some("dist"),
            DetectedProject::SvelteKit => Some("build"),
            DetectedProject::Gatsby => Some("public"),
            DetectedProject::Hugo => Some("public"),
            DetectedProject::Jekyll => Some("_site"),
            DetectedProject::PlainStatic => None,
            _ => None,
        }
    }

    /// The default start command for backend project types.
    pub fn default_start_command(&self) -> Option<&'static str> {
        match self {
            DetectedProject::NodeBackend => Some("node server.js"),
            DetectedProject::PythonBackend => Some("python app.py"),
            DetectedProject::RustBackend => Some("./target/release/app"),
            DetectedProject::GoBackend => Some("./app"),
            DetectedProject::JavaBackend => Some("java -jar target/*.jar"),
            DetectedProject::NextJs => Some("npm start"),
            _ => None,
        }
    }

    /// The default dependency install command for this project type.
    pub fn default_install_deps_command(&self) -> Option<&'static str> {
        match self {
            DetectedProject::ReactCra
            | DetectedProject::Vite
            | DetectedProject::NextJs
            | DetectedProject::NuxtJs
            | DetectedProject::Angular
            | DetectedProject::SvelteKit
            | DetectedProject::Gatsby
            | DetectedProject::NodeBackend => Some("npm ci"),
            DetectedProject::PythonBackend => Some("pip install -r requirements.txt"),
            DetectedProject::RustBackend => Some("cargo fetch"),
            DetectedProject::GoBackend => Some("go mod download"),
            DetectedProject::JavaBackend => Some("./mvnw dependency:resolve"),
            DetectedProject::Jekyll => Some("bundle install"),
            _ => None,
        }
    }

    /// Whether this project type should default to SPA mode in Nginx.
    pub fn default_spa_mode(&self) -> bool {
        matches!(
            self,
            DetectedProject::ReactCra
                | DetectedProject::Vite
                | DetectedProject::NextJs
                | DetectedProject::Angular
                | DetectedProject::SvelteKit
        )
    }

    /// Whether this project type is a static site (no backend service needed).
    pub fn is_static(&self) -> bool {
        matches!(
            self,
            DetectedProject::ReactCra
                | DetectedProject::Vite
                | DetectedProject::Angular
                | DetectedProject::SvelteKit
                | DetectedProject::Gatsby
                | DetectedProject::Hugo
                | DetectedProject::Jekyll
                | DetectedProject::PlainStatic
        )
    }

    /// Whether this project type is a backend service.
    pub fn is_backend(&self) -> bool {
        matches!(
            self,
            DetectedProject::NodeBackend
                | DetectedProject::PythonBackend
                | DetectedProject::RustBackend
                | DetectedProject::GoBackend
                | DetectedProject::JavaBackend
        )
    }

    /// Whether this project type is a hybrid (backend + static).
    pub fn is_hybrid(&self) -> bool {
        matches!(self, DetectedProject::NextJs | DetectedProject::NuxtJs)
    }
}

impl Default for DetectedProject {
    fn default() -> Self {
        DetectedProject::Unknown
    }
}

impl fmt::Display for DetectedProject {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            DetectedProject::ReactCra => write!(f, "React (CRA)"),
            DetectedProject::Vite => write!(f, "Vite"),
            DetectedProject::NextJs => write!(f, "Next.js"),
            DetectedProject::NuxtJs => write!(f, "Nuxt.js"),
            DetectedProject::Angular => write!(f, "Angular"),
            DetectedProject::SvelteKit => write!(f, "SvelteKit"),
            DetectedProject::Gatsby => write!(f, "Gatsby"),
            DetectedProject::Hugo => write!(f, "Hugo"),
            DetectedProject::Jekyll => write!(f, "Jekyll"),
            DetectedProject::PlainStatic => write!(f, "Plain Static"),
            DetectedProject::NodeBackend => write!(f, "Node.js Backend"),
            DetectedProject::PythonBackend => write!(f, "Python Backend"),
            DetectedProject::RustBackend => write!(f, "Rust Backend"),
            DetectedProject::GoBackend => write!(f, "Go Backend"),
            DetectedProject::JavaBackend => write!(f, "Java Backend"),
            DetectedProject::Unknown => write!(f, "Unknown"),
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Package Manager Detection
// ─────────────────────────────────────────────────────────────────────────────

/// Detected JavaScript/Node.js package manager.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PackageManager {
    Npm,
    Yarn,
    Pnpm,
    Bun,
}

impl PackageManager {
    /// The install command for this package manager (CI/frozen lockfile mode).
    pub fn install_command(&self) -> &'static str {
        match self {
            PackageManager::Npm => "npm ci",
            PackageManager::Yarn => "yarn install --frozen-lockfile",
            PackageManager::Pnpm => "pnpm install --frozen-lockfile",
            PackageManager::Bun => "bun install --frozen-lockfile",
        }
    }

    /// The build command prefix for this package manager.
    pub fn run_command(&self) -> &'static str {
        match self {
            PackageManager::Npm => "npm run",
            PackageManager::Yarn => "yarn",
            PackageManager::Pnpm => "pnpm run",
            PackageManager::Bun => "bun run",
        }
    }

    /// The lockfile name for this package manager.
    pub fn lockfile(&self) -> &'static str {
        match self {
            PackageManager::Npm => "package-lock.json",
            PackageManager::Yarn => "yarn.lock",
            PackageManager::Pnpm => "pnpm-lock.yaml",
            PackageManager::Bun => "bun.lockb",
        }
    }
}

impl Default for PackageManager {
    fn default() -> Self {
        PackageManager::Npm
    }
}

impl fmt::Display for PackageManager {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            PackageManager::Npm => write!(f, "npm"),
            PackageManager::Yarn => write!(f, "yarn"),
            PackageManager::Pnpm => write!(f, "pnpm"),
            PackageManager::Bun => write!(f, "bun"),
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Deploy Options
// ─────────────────────────────────────────────────────────────────────────────

/// Options that control how a deployment is executed.
///
/// These are provided by the user (via CLI flags or API parameters) and
/// override the application's stored configuration for this single deploy.
#[derive(Debug, Clone, Default)]
pub struct DeployOptions {
    /// Override the git branch to deploy (default: app's configured branch)
    pub branch: Option<String>,

    /// Deploy a specific git tag instead of a branch
    pub tag: Option<String>,

    /// Deploy a specific git commit hash
    pub commit: Option<String>,

    /// What triggered this deployment
    pub trigger: DeployTrigger,

    /// Run in dry-run mode (log actions but don't execute them)
    pub dry_run: bool,

    /// Skip the dependency installation step
    pub skip_deps: bool,

    /// Skip the build step (use existing build artifacts)
    pub skip_build: bool,

    /// Skip the health check step
    pub skip_health_check: bool,

    /// Force deploy even if there are no new commits
    pub force: bool,

    /// Custom environment variables for this deploy only
    pub env_overrides: HashMap<String, String>,

    /// Optional timeout override for the build step (in seconds)
    pub build_timeout_secs: Option<u64>,

    /// Free-form metadata to attach to the deploy record
    pub metadata: HashMap<String, String>,
}

impl DeployOptions {
    /// Create default options for a CLI-triggered deployment.
    pub fn cli() -> Self {
        Self {
            trigger: DeployTrigger::Cli,
            ..Default::default()
        }
    }

    /// Create default options for an API-triggered deployment.
    pub fn api() -> Self {
        Self {
            trigger: DeployTrigger::Api,
            ..Default::default()
        }
    }

    /// Create default options for a webhook-triggered deployment.
    pub fn webhook() -> Self {
        Self {
            trigger: DeployTrigger::Webhook,
            ..Default::default()
        }
    }

    /// Get the effective branch (override or app default).
    pub fn effective_branch(&self, app_branch: &str) -> String {
        self.branch
            .clone()
            .unwrap_or_else(|| app_branch.to_string())
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Deploy Result
// ─────────────────────────────────────────────────────────────────────────────

/// The outcome of a deployment attempt, returned to the caller after the
/// pipeline completes (or fails).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeployResult {
    /// Whether the deployment succeeded
    pub success: bool,

    /// The deploy record ID
    pub deploy_id: String,

    /// The application name
    pub app_name: String,

    /// The git commit hash that was deployed
    pub commit_hash: String,

    /// The git branch that was deployed
    pub branch: String,

    /// Final deployment status
    pub status: DeployStatus,

    /// Total duration of the deployment in seconds
    pub duration_secs: u64,

    /// Error message if the deployment failed
    pub error: Option<String>,

    /// The pipeline step that failed (if any)
    pub failed_step: Option<String>,

    /// Whether a rollback was performed
    pub rolled_back: bool,

    /// Path to the deployment log file
    pub log_path: Option<String>,

    /// The detected project type
    pub detected_project: Option<DetectedProject>,

    /// Warnings generated during the deployment
    pub warnings: Vec<String>,
}

impl DeployResult {
    /// Create a successful deploy result.
    pub fn success(
        deploy_id: String,
        app_name: String,
        commit_hash: String,
        branch: String,
        duration_secs: u64,
    ) -> Self {
        Self {
            success: true,
            deploy_id,
            app_name,
            commit_hash,
            branch,
            status: DeployStatus::Success,
            duration_secs,
            error: None,
            failed_step: None,
            rolled_back: false,
            log_path: None,
            detected_project: None,
            warnings: Vec::new(),
        }
    }

    /// Create a failed deploy result.
    pub fn failure(
        deploy_id: String,
        app_name: String,
        branch: String,
        duration_secs: u64,
        error: String,
        failed_step: Option<String>,
        rolled_back: bool,
    ) -> Self {
        Self {
            success: false,
            deploy_id,
            app_name,
            commit_hash: String::new(),
            branch,
            status: DeployStatus::Failed,
            duration_secs,
            error: Some(error),
            failed_step,
            rolled_back,
            log_path: None,
            detected_project: None,
            warnings: Vec::new(),
        }
    }
}

impl fmt::Display for DeployResult {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.success {
            write!(
                f,
                "✓ Deploy {} succeeded for '{}' (branch={}, commit={}, {}s)",
                self.deploy_id,
                self.app_name,
                self.branch,
                if self.commit_hash.len() >= 7 {
                    &self.commit_hash[..7]
                } else {
                    &self.commit_hash
                },
                self.duration_secs
            )
        } else {
            write!(
                f,
                "✗ Deploy {} FAILED for '{}': {}{}",
                self.deploy_id,
                self.app_name,
                self.error.as_deref().unwrap_or("unknown error"),
                if self.rolled_back {
                    " (rolled back)"
                } else {
                    ""
                }
            )
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Deployment Pipeline
// ─────────────────────────────────────────────────────────────────────────────

/// The main deployment pipeline that orchestrates the full deploy workflow.
///
/// Each invocation of `deploy()` runs the complete pipeline for a single
/// application. The pipeline is sequential and synchronous — steps run one
/// after another. Concurrency is managed at the application level via
/// per-app deploy locks.
///
/// ## Usage
///
/// ```ignore
/// let pipeline = DeploymentPipeline::new(config)?;
/// let result = pipeline.deploy(&mut app, &ssh_keys, &options).await;
/// ```
pub struct DeploymentPipeline {
    /// Global deployment configuration
    config: DeployConfig,

    /// Set of app names currently being deployed (concurrency lock)
    active_deploys: Arc<Mutex<HashSet<String>>>,
}

impl DeploymentPipeline {
    /// Create a new deployment pipeline with the given configuration.
    pub fn new(config: DeployConfig) -> Result<Self> {
        info!("Deployment pipeline initialized");

        Ok(Self {
            config,
            active_deploys: Arc::new(Mutex::new(HashSet::new())),
        })
    }

    // ─────────────────────────────────────────────────────────────────────
    // Project Detection
    // ─────────────────────────────────────────────────────────────────────

    /// Auto-detect the project type by examining the contents of a directory.
    ///
    /// Checks for framework-specific files (package.json dependencies,
    /// Cargo.toml, go.mod, etc.) and returns the best match.
    pub fn detect_project_type(repo_dir: &Path) -> DetectedProject {
        // Check for package.json (Node.js ecosystem)
        let package_json_path = repo_dir.join("package.json");
        if package_json_path.exists() {
            if let Ok(content) = fs::read_to_string(&package_json_path) {
                return Self::detect_node_project(&content);
            }
        }

        // Check for Cargo.toml (Rust)
        if repo_dir.join("Cargo.toml").exists() {
            return DetectedProject::RustBackend;
        }

        // Check for go.mod (Go)
        if repo_dir.join("go.mod").exists() {
            return DetectedProject::GoBackend;
        }

        // Check for Python indicators
        if repo_dir.join("requirements.txt").exists()
            || repo_dir.join("setup.py").exists()
            || repo_dir.join("pyproject.toml").exists()
            || repo_dir.join("Pipfile").exists()
        {
            return DetectedProject::PythonBackend;
        }

        // Check for Java / Spring Boot
        if repo_dir.join("pom.xml").exists() || repo_dir.join("build.gradle").exists() {
            return DetectedProject::JavaBackend;
        }

        // Check for Hugo
        if repo_dir.join("hugo.toml").exists()
            || repo_dir.join("hugo.yaml").exists()
            || (repo_dir.join("config.toml").exists() && repo_dir.join("content").is_dir())
        {
            return DetectedProject::Hugo;
        }

        // Check for Jekyll
        if repo_dir.join("_config.yml").exists() && repo_dir.join("_layouts").is_dir() {
            return DetectedProject::Jekyll;
        }

        // Check for plain static site (index.html at root)
        if repo_dir.join("index.html").exists() {
            return DetectedProject::PlainStatic;
        }

        DetectedProject::Unknown
    }

    /// Detect the specific Node.js project type from package.json content.
    fn detect_node_project(package_json_content: &str) -> DetectedProject {
        let content = package_json_content.to_lowercase();

        // Check dependencies and devDependencies for framework indicators
        if content.contains("\"next\"") || content.contains("'next'") {
            return DetectedProject::NextJs;
        }

        if content.contains("\"nuxt\"") || content.contains("'nuxt'") {
            return DetectedProject::NuxtJs;
        }

        if content.contains("\"react-scripts\"") {
            return DetectedProject::ReactCra;
        }

        if content.contains("\"@angular/cli\"") || content.contains("\"@angular/core\"") {
            return DetectedProject::Angular;
        }

        if content.contains("\"@sveltejs/kit\"") {
            return DetectedProject::SvelteKit;
        }

        if content.contains("\"gatsby\"") {
            return DetectedProject::Gatsby;
        }

        if content.contains("\"vite\"") {
            return DetectedProject::Vite;
        }

        // If it has a "start" script, it's likely a backend
        if content.contains("\"start\"") {
            // But also check for common frontend build indicators
            if content.contains("\"build\"")
                && (content.contains("\"react\"")
                    || content.contains("\"vue\"")
                    || content.contains("\"svelte\""))
            {
                return DetectedProject::Vite; // Default SPA framework
            }
            return DetectedProject::NodeBackend;
        }

        // If it has a "build" script but no "start", likely a static site build
        if content.contains("\"build\"") {
            return DetectedProject::Vite;
        }

        DetectedProject::NodeBackend
    }

    /// Detect the package manager from lockfile presence.
    pub fn detect_package_manager(repo_dir: &Path) -> PackageManager {
        if repo_dir.join("bun.lockb").exists() {
            PackageManager::Bun
        } else if repo_dir.join("pnpm-lock.yaml").exists() {
            PackageManager::Pnpm
        } else if repo_dir.join("yarn.lock").exists() {
            PackageManager::Yarn
        } else {
            PackageManager::Npm
        }
    }

    // ─────────────────────────────────────────────────────────────────────
    // Git Operations
    // ─────────────────────────────────────────────────────────────────────

    /// Clone a git repository into the given destination directory.
    ///
    /// If an SSH key ID is provided, it is used via GIT_SSH_COMMAND to
    /// authenticate with the remote host.
    pub fn git_clone(
        repo_url: &str,
        dest: &Path,
        branch: &str,
        ssh_command: Option<&str>,
    ) -> Result<Output> {
        let mut cmd = Command::new("git");
        cmd.arg("clone")
            .arg("--branch")
            .arg(branch)
            .arg("--depth")
            .arg("1")
            .arg("--single-branch")
            .arg(repo_url)
            .arg(dest);

        if let Some(ssh_cmd) = ssh_command {
            cmd.env("GIT_SSH_COMMAND", ssh_cmd);
        }

        info!("Cloning {} (branch: {}) into {:?}", repo_url, branch, dest);

        let output = cmd.output().map_err(|e| PipelineError::GitError {
            message: format!("Failed to execute git clone: {}", e),
        })?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            return Err(PipelineError::GitError {
                message: format!("git clone failed: {}", stderr.trim()),
            });
        }

        Ok(output)
    }

    /// Pull the latest changes in an existing git checkout.
    pub fn git_pull(
        repo_dir: &Path,
        branch: &str,
        ssh_command: Option<&str>,
    ) -> Result<Output> {
        // Fetch
        let mut fetch_cmd = Command::new("git");
        fetch_cmd
            .current_dir(repo_dir)
            .arg("fetch")
            .arg("origin")
            .arg(branch);

        if let Some(ssh_cmd) = ssh_command {
            fetch_cmd.env("GIT_SSH_COMMAND", ssh_cmd);
        }

        let fetch_output = fetch_cmd.output().map_err(|e| PipelineError::GitError {
            message: format!("Failed to execute git fetch: {}", e),
        })?;

        if !fetch_output.status.success() {
            let stderr = String::from_utf8_lossy(&fetch_output.stderr);
            return Err(PipelineError::GitError {
                message: format!("git fetch failed: {}", stderr.trim()),
            });
        }

        // Reset to the fetched branch
        let mut reset_cmd = Command::new("git");
        reset_cmd
            .current_dir(repo_dir)
            .arg("reset")
            .arg("--hard")
            .arg(&format!("origin/{}", branch));

        let reset_output = reset_cmd.output().map_err(|e| PipelineError::GitError {
            message: format!("Failed to execute git reset: {}", e),
        })?;

        if !reset_output.status.success() {
            let stderr = String::from_utf8_lossy(&reset_output.stderr);
            return Err(PipelineError::GitError {
                message: format!("git reset failed: {}", stderr.trim()),
            });
        }

        info!("Git pull completed for branch '{}' in {:?}", branch, repo_dir);
        Ok(reset_output)
    }

    /// Get the current HEAD commit hash in a git repository.
    pub fn git_current_commit(repo_dir: &Path) -> Result<String> {
        let output = Command::new("git")
            .current_dir(repo_dir)
            .arg("rev-parse")
            .arg("HEAD")
            .output()
            .map_err(|e| PipelineError::GitError {
                message: format!("Failed to get current commit: {}", e),
            })?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            return Err(PipelineError::GitError {
                message: format!("git rev-parse failed: {}", stderr.trim()),
            });
        }

        Ok(String::from_utf8_lossy(&output.stdout).trim().to_string())
    }

    /// Get the current HEAD commit message (first line).
    pub fn git_current_commit_message(repo_dir: &Path) -> Result<String> {
        let output = Command::new("git")
            .current_dir(repo_dir)
            .arg("log")
            .arg("-1")
            .arg("--format=%s")
            .output()
            .map_err(|e| PipelineError::GitError {
                message: format!("Failed to get commit message: {}", e),
            })?;

        if !output.status.success() {
            return Ok(String::new());
        }

        Ok(String::from_utf8_lossy(&output.stdout).trim().to_string())
    }

    // ─────────────────────────────────────────────────────────────────────
    // Build Operations
    // ─────────────────────────────────────────────────────────────────────

    /// Run a shell command in a given working directory, capturing output.
    ///
    /// Returns the combined stdout+stderr output and the exit status.
    pub fn run_command(
        command: &str,
        working_dir: &Path,
        env_vars: &HashMap<String, String>,
        timeout_secs: Option<u64>,
    ) -> Result<CommandResult> {
        info!("Running command: '{}' in {:?}", command, working_dir);

        let mut cmd = Command::new("sh");
        cmd.arg("-c")
            .arg(command)
            .current_dir(working_dir)
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());

        // Set environment variables
        for (key, value) in env_vars {
            cmd.env(key, value);
        }

        let child = cmd.spawn().map_err(|e| PipelineError::BuildError {
            message: format!("Failed to spawn command '{}': {}", command, e),
        })?;

        let output = child.wait_with_output().map_err(|e| PipelineError::BuildError {
            message: format!("Command '{}' failed: {}", command, e),
        })?;

        let stdout = String::from_utf8_lossy(&output.stdout).to_string();
        let stderr = String::from_utf8_lossy(&output.stderr).to_string();

        let result = CommandResult {
            success: output.status.success(),
            exit_code: output.status.code(),
            stdout,
            stderr,
            command: command.to_string(),
        };

        if result.success {
            debug!("Command '{}' completed successfully", command);
        } else {
            warn!(
                "Command '{}' failed with exit code {:?}",
                command, result.exit_code
            );
        }

        Ok(result)
    }

    // ─────────────────────────────────────────────────────────────────────
    // Release Management
    // ─────────────────────────────────────────────────────────────────────

    /// Create a new release directory from the repo checkout.
    ///
    /// Copies the relevant files from the repo into a timestamped release
    /// directory under `releases/`.
    pub fn create_release(
        repo_dir: &Path,
        releases_dir: &Path,
        deploy_id: &str,
    ) -> Result<PathBuf> {
        // Ensure releases directory exists
        fs::create_dir_all(releases_dir).map_err(PipelineError::Io)?;

        let release_dir = releases_dir.join(deploy_id);

        if release_dir.exists() {
            warn!("Release directory already exists, removing: {:?}", release_dir);
            fs::remove_dir_all(&release_dir).map_err(PipelineError::Io)?;
        }

        // Copy the repo contents to the release directory
        // We use a recursive copy that excludes .git to save space
        Self::copy_dir_recursive(repo_dir, &release_dir, &[".git"])?;

        info!("Release created: {:?}", release_dir);
        Ok(release_dir)
    }

    /// Atomically activate a release by swapping the `current` symlink.
    ///
    /// This is the core of zero-downtime deployment: the symlink swap is
    /// an atomic filesystem operation, so the transition from old to new
    /// release is instantaneous.
    #[cfg(unix)]
    pub fn activate_release(
        release_dir: &Path,
        current_link: &Path,
    ) -> Result<Option<PathBuf>> {
        // Read the old target (if any) for rollback info
        let old_target = if current_link.is_symlink() {
            fs::read_link(current_link).ok()
        } else {
            None
        };

        // Atomic symlink swap: create a temp symlink, then rename it over the current one
        let tmp_link = current_link.with_extension("new");

        // Remove temp link if it exists from a previous failed attempt
        if tmp_link.exists() || tmp_link.is_symlink() {
            let _ = fs::remove_file(&tmp_link);
        }

        // Create the new symlink
        std::os::unix::fs::symlink(release_dir, &tmp_link).map_err(|e| {
            PipelineError::StepFailed {
                step: "activate".to_string(),
                message: format!("Failed to create symlink: {}", e),
            }
        })?;

        // Atomically rename the temp symlink over the current one
        fs::rename(&tmp_link, current_link).map_err(|e| PipelineError::StepFailed {
            step: "activate".to_string(),
            message: format!("Failed to swap symlink: {}", e),
        })?;

        info!(
            "Release activated: {:?} → {:?}",
            current_link, release_dir
        );

        Ok(old_target)
    }

    /// Non-Unix fallback: copy instead of symlink.
    #[cfg(not(unix))]
    pub fn activate_release(
        release_dir: &Path,
        current_link: &Path,
    ) -> Result<Option<PathBuf>> {
        let old_target = if current_link.exists() {
            // Back up old current
            let backup = current_link.with_extension("old");
            if backup.exists() {
                let _ = fs::remove_dir_all(&backup);
            }
            fs::rename(current_link, &backup).ok();
            Some(backup)
        } else {
            None
        };

        Self::copy_dir_recursive(release_dir, current_link, &[])?;

        info!(
            "Release activated (copy): {:?} → {:?}",
            release_dir, current_link
        );

        Ok(old_target)
    }

    /// Clean up old releases, keeping the N most recent ones.
    ///
    /// Returns the number of releases that were removed.
    pub fn cleanup_old_releases(releases_dir: &Path, keep: usize) -> Result<usize> {
        if !releases_dir.exists() {
            return Ok(0);
        }

        let mut entries: Vec<(String, PathBuf)> = Vec::new();

        for entry in fs::read_dir(releases_dir).map_err(PipelineError::Io)? {
            let entry = entry.map_err(PipelineError::Io)?;
            if entry.file_type().map(|t| t.is_dir()).unwrap_or(false) {
                if let Some(name) = entry.file_name().to_str() {
                    entries.push((name.to_string(), entry.path()));
                }
            }
        }

        // Sort by name (which includes timestamp, so alphabetical = chronological)
        entries.sort_by(|a, b| b.0.cmp(&a.0)); // newest first

        let mut removed = 0;

        for (_name, path) in entries.iter().skip(keep) {
            match fs::remove_dir_all(path) {
                Ok(()) => {
                    debug!("Removed old release: {:?}", path);
                    removed += 1;
                }
                Err(e) => {
                    warn!("Failed to remove old release {:?}: {}", path, e);
                }
            }
        }

        if removed > 0 {
            info!(
                "Cleaned up {} old release(s) from {:?} (kept {})",
                removed, releases_dir, keep
            );
        }

        Ok(removed)
    }

    // ─────────────────────────────────────────────────────────────────────
    // Health Checking
    // ─────────────────────────────────────────────────────────────────────

    /// Perform a health check on an application after deployment.
    ///
    /// For backend apps, sends an HTTP GET to the health check URL.
    /// For static sites, checks that the index file exists and Nginx is serving.
    ///
    /// Retries up to `max_retries` times with `retry_interval` between attempts.
    pub fn health_check(
        url: &str,
        max_retries: u32,
        retry_interval: Duration,
    ) -> Result<HealthCheckResult> {
        info!("Running health check: {} (max retries: {})", url, max_retries);

        for attempt in 0..=max_retries {
            if attempt > 0 {
                debug!(
                    "Health check retry {}/{} for {}",
                    attempt, max_retries, url
                );
                std::thread::sleep(retry_interval);
            }

            // Use curl for HTTP health check (avoids adding an HTTP client dependency)
            let output = Command::new("curl")
                .arg("-s")
                .arg("-o")
                .arg("/dev/null")
                .arg("-w")
                .arg("%{http_code}")
                .arg("--max-time")
                .arg("5")
                .arg("--connect-timeout")
                .arg("3")
                .arg(url)
                .output();

            match output {
                Ok(o) if o.status.success() => {
                    let status_code = String::from_utf8_lossy(&o.stdout)
                        .trim()
                        .parse::<u16>()
                        .unwrap_or(0);

                    if (200..400).contains(&status_code) {
                        info!(
                            "Health check passed: {} (HTTP {})",
                            url, status_code
                        );
                        return Ok(HealthCheckResult {
                            success: true,
                            url: url.to_string(),
                            status_code: Some(status_code),
                            attempts: attempt + 1,
                            error: None,
                        });
                    }

                    debug!(
                        "Health check got HTTP {} (attempt {})",
                        status_code,
                        attempt + 1
                    );
                }
                Ok(o) => {
                    let stderr = String::from_utf8_lossy(&o.stderr);
                    debug!(
                        "Health check failed (attempt {}): {}",
                        attempt + 1,
                        stderr.trim()
                    );
                }
                Err(e) => {
                    debug!(
                        "Health check error (attempt {}): {}",
                        attempt + 1,
                        e
                    );
                }
            }
        }

        let msg = format!(
            "Health check failed after {} attempts for {}",
            max_retries + 1,
            url
        );
        warn!("{}", msg);

        Ok(HealthCheckResult {
            success: false,
            url: url.to_string(),
            status_code: None,
            attempts: max_retries + 1,
            error: Some(msg),
        })
    }

    /// Perform a simple file-existence health check for static sites.
    pub fn health_check_static(static_root: &Path, index_file: &str) -> HealthCheckResult {
        let index_path = static_root.join(index_file);

        if index_path.exists() {
            info!(
                "Static site health check passed: {:?} exists",
                index_path
            );
            HealthCheckResult {
                success: true,
                url: index_path.to_string_lossy().to_string(),
                status_code: None,
                attempts: 1,
                error: None,
            }
        } else {
            let msg = format!(
                "Static site health check failed: {:?} not found",
                index_path
            );
            warn!("{}", msg);
            HealthCheckResult {
                success: false,
                url: index_path.to_string_lossy().to_string(),
                status_code: None,
                attempts: 1,
                error: Some(msg),
            }
        }
    }

    // ─────────────────────────────────────────────────────────────────────
    // Deploy Lock Management
    // ─────────────────────────────────────────────────────────────────────

    /// Acquire a deploy lock for the given application.
    ///
    /// Returns an error if the application is already being deployed.
    pub fn acquire_lock(&self, app_name: &str) -> Result<DeployLock> {
        let mut active = self.active_deploys.lock().map_err(|_| {
            PipelineError::LockFailed {
                app: app_name.to_string(),
            }
        })?;

        if active.contains(app_name) {
            return Err(PipelineError::DeploymentInProgress {
                app: app_name.to_string(),
            });
        }

        active.insert(app_name.to_string());
        debug!("Deploy lock acquired for '{}'", app_name);

        Ok(DeployLock {
            app_name: app_name.to_string(),
            active_deploys: Arc::clone(&self.active_deploys),
        })
    }

    /// Check whether an application is currently being deployed.
    pub fn is_deploying(&self, app_name: &str) -> bool {
        self.active_deploys
            .lock()
            .map(|active| active.contains(app_name))
            .unwrap_or(false)
    }

    /// Get the list of applications currently being deployed.
    pub fn active_deployments(&self) -> Vec<String> {
        self.active_deploys
            .lock()
            .map(|active| active.iter().cloned().collect())
            .unwrap_or_default()
    }

    // ─────────────────────────────────────────────────────────────────────
    // Utility Functions
    // ─────────────────────────────────────────────────────────────────────

    /// Recursively copy a directory, excluding specified directory names.
    pub fn copy_dir_recursive(
        src: &Path,
        dest: &Path,
        exclude: &[&str],
    ) -> Result<()> {
        fs::create_dir_all(dest).map_err(PipelineError::Io)?;

        for entry in fs::read_dir(src).map_err(PipelineError::Io)? {
            let entry = entry.map_err(PipelineError::Io)?;
            let entry_name = entry.file_name();
            let entry_name_str = entry_name.to_string_lossy();

            // Skip excluded directories
            if exclude.iter().any(|e| *e == entry_name_str.as_ref()) {
                continue;
            }

            let src_path = entry.path();
            let dest_path = dest.join(&entry_name);

            let file_type = entry.file_type().map_err(PipelineError::Io)?;

            if file_type.is_dir() {
                Self::copy_dir_recursive(&src_path, &dest_path, exclude)?;
            } else if file_type.is_file() {
                fs::copy(&src_path, &dest_path).map_err(PipelineError::Io)?;
            } else if file_type.is_symlink() {
                // Preserve symlinks
                #[cfg(unix)]
                {
                    let target = fs::read_link(&src_path).map_err(PipelineError::Io)?;
                    let _ = std::os::unix::fs::symlink(&target, &dest_path);
                }
                #[cfg(not(unix))]
                {
                    // On non-Unix, copy the target instead
                    if src_path.is_file() {
                        fs::copy(&src_path, &dest_path).map_err(PipelineError::Io)?;
                    }
                }
            }
        }

        Ok(())
    }

    /// Get the pipeline configuration.
    pub fn config(&self) -> &DeployConfig {
        &self.config
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Deploy Lock (RAII guard)
// ─────────────────────────────────────────────────────────────────────────────

/// An RAII guard that releases the per-app deploy lock when dropped.
///
/// This ensures the lock is released even if the pipeline panics or
/// returns an error early.
pub struct DeployLock {
    app_name: String,
    active_deploys: Arc<Mutex<HashSet<String>>>,
}

impl Drop for DeployLock {
    fn drop(&mut self) {
        if let Ok(mut active) = self.active_deploys.lock() {
            active.remove(&self.app_name);
            debug!("Deploy lock released for '{}'", self.app_name);
        } else {
            error!(
                "Failed to release deploy lock for '{}' — mutex poisoned",
                self.app_name
            );
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Command Result
// ─────────────────────────────────────────────────────────────────────────────

/// Result of running a shell command.
#[derive(Debug, Clone)]
pub struct CommandResult {
    /// Whether the command exited with code 0
    pub success: bool,
    /// The exit code (None if terminated by signal)
    pub exit_code: Option<i32>,
    /// Standard output
    pub stdout: String,
    /// Standard error
    pub stderr: String,
    /// The command that was run
    pub command: String,
}

impl CommandResult {
    /// Get the combined stdout + stderr output.
    pub fn combined_output(&self) -> String {
        if self.stderr.is_empty() {
            self.stdout.clone()
        } else if self.stdout.is_empty() {
            self.stderr.clone()
        } else {
            format!("{}\n{}", self.stdout, self.stderr)
        }
    }

    /// Get a short error summary (first line of stderr, or exit code).
    pub fn error_summary(&self) -> String {
        if !self.stderr.is_empty() {
            self.stderr
                .lines()
                .find(|l| !l.trim().is_empty())
                .unwrap_or("unknown error")
                .to_string()
        } else {
            format!(
                "Command '{}' exited with code {:?}",
                self.command, self.exit_code
            )
        }
    }
}

impl fmt::Display for CommandResult {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.success {
            write!(f, "✓ '{}' succeeded", self.command)
        } else {
            write!(
                f,
                "✗ '{}' failed (exit code {:?}): {}",
                self.command,
                self.exit_code,
                self.error_summary()
            )
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Health Check Result
// ─────────────────────────────────────────────────────────────────────────────

/// Result of a post-deployment health check.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HealthCheckResult {
    /// Whether the health check passed
    pub success: bool,
    /// The URL that was checked
    pub url: String,
    /// HTTP status code (if an HTTP check was performed)
    pub status_code: Option<u16>,
    /// Number of attempts made
    pub attempts: u32,
    /// Error message if the check failed
    pub error: Option<String>,
}

impl fmt::Display for HealthCheckResult {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.success {
            let status = self
                .status_code
                .map(|c| format!(" (HTTP {})", c))
                .unwrap_or_default();
            write!(
                f,
                "✓ Health check passed for {}{} ({} attempt(s))",
                self.url, status, self.attempts
            )
        } else {
            write!(
                f,
                "✗ Health check FAILED for {}: {} ({} attempt(s))",
                self.url,
                self.error.as_deref().unwrap_or("unknown error"),
                self.attempts
            )
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Tests
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    fn test_config() -> DeployConfig {
        DeployConfig {
            enabled: true,
            apps_dir: PathBuf::from("/tmp/zeroed-test/apps"),
            ssh_keys_dir: PathBuf::from("/tmp/zeroed-test/ssh"),
            nginx_sites_dir: PathBuf::from("/tmp/zeroed-test/nginx/sites-available"),
            nginx_enabled_dir: PathBuf::from("/tmp/zeroed-test/nginx/sites-enabled"),
            systemd_units_dir: PathBuf::from("/tmp/zeroed-test/systemd"),
            ssl_certs_dir: PathBuf::from("/tmp/zeroed-test/ssl"),
            acme_email: "test@example.com".to_string(),
            default_port_range_start: 3000,
            default_port_range_end: 9999,
            max_apps: 100,
            max_deploy_history: 10,
            build_timeout_secs: 300,
            health_check_timeout_secs: 30,
            health_check_retries: 3,
            registry_path: PathBuf::from("/tmp/zeroed-test/registry.toml"),
        }
    }

    // ── DetectedProject Tests ──────────────────────────────────────────

    #[test]
    fn test_detected_project_display() {
        assert_eq!(format!("{}", DetectedProject::ReactCra), "React (CRA)");
        assert_eq!(format!("{}", DetectedProject::Vite), "Vite");
        assert_eq!(format!("{}", DetectedProject::NextJs), "Next.js");
        assert_eq!(format!("{}", DetectedProject::NodeBackend), "Node.js Backend");
        assert_eq!(format!("{}", DetectedProject::RustBackend), "Rust Backend");
        assert_eq!(format!("{}", DetectedProject::PlainStatic), "Plain Static");
        assert_eq!(format!("{}", DetectedProject::Unknown), "Unknown");
    }

    #[test]
    fn test_detected_project_default_commands() {
        assert_eq!(
            DetectedProject::ReactCra.default_build_command(),
            Some("npm run build")
        );
        assert_eq!(
            DetectedProject::ReactCra.default_build_output_dir(),
            Some("build")
        );
        assert_eq!(
            DetectedProject::Vite.default_build_output_dir(),
            Some("dist")
        );
        assert_eq!(
            DetectedProject::Hugo.default_build_command(),
            Some("hugo --minify")
        );
        assert_eq!(
            DetectedProject::Hugo.default_build_output_dir(),
            Some("public")
        );
        assert!(DetectedProject::PlainStatic.default_build_command().is_none());
        assert!(DetectedProject::PlainStatic.default_build_output_dir().is_none());
    }

    #[test]
    fn test_detected_project_start_commands() {
        assert_eq!(
            DetectedProject::NodeBackend.default_start_command(),
            Some("node server.js")
        );
        assert_eq!(
            DetectedProject::RustBackend.default_start_command(),
            Some("./target/release/app")
        );
        assert_eq!(
            DetectedProject::GoBackend.default_start_command(),
            Some("./app")
        );
        assert!(DetectedProject::ReactCra.default_start_command().is_none());
    }

    #[test]
    fn test_detected_project_install_deps_commands() {
        assert_eq!(
            DetectedProject::ReactCra.default_install_deps_command(),
            Some("npm ci")
        );
        assert_eq!(
            DetectedProject::PythonBackend.default_install_deps_command(),
            Some("pip install -r requirements.txt")
        );
        assert_eq!(
            DetectedProject::RustBackend.default_install_deps_command(),
            Some("cargo fetch")
        );
        assert!(DetectedProject::PlainStatic.default_install_deps_command().is_none());
    }

    #[test]
    fn test_detected_project_spa_mode() {
        assert!(DetectedProject::ReactCra.default_spa_mode());
        assert!(DetectedProject::Vite.default_spa_mode());
        assert!(DetectedProject::Angular.default_spa_mode());
        assert!(!DetectedProject::Hugo.default_spa_mode());
        assert!(!DetectedProject::NodeBackend.default_spa_mode());
        assert!(!DetectedProject::PlainStatic.default_spa_mode());
    }

    #[test]
    fn test_detected_project_type_classification() {
        assert!(DetectedProject::ReactCra.is_static());
        assert!(DetectedProject::Vite.is_static());
        assert!(DetectedProject::Hugo.is_static());
        assert!(DetectedProject::PlainStatic.is_static());
        assert!(!DetectedProject::NodeBackend.is_static());

        assert!(DetectedProject::NodeBackend.is_backend());
        assert!(DetectedProject::RustBackend.is_backend());
        assert!(DetectedProject::GoBackend.is_backend());
        assert!(!DetectedProject::ReactCra.is_backend());

        assert!(DetectedProject::NextJs.is_hybrid());
        assert!(DetectedProject::NuxtJs.is_hybrid());
        assert!(!DetectedProject::ReactCra.is_hybrid());
        assert!(!DetectedProject::NodeBackend.is_hybrid());
    }

    // ── Project Detection Tests ────────────────────────────────────────

    #[test]
    fn test_detect_react_cra() {
        let tmp = TempDir::new().unwrap();
        let package_json = r#"{"dependencies": {"react": "^18.0", "react-scripts": "5.0"}}"#;
        fs::write(tmp.path().join("package.json"), package_json).unwrap();

        let detected = DeploymentPipeline::detect_project_type(tmp.path());
        assert_eq!(detected, DetectedProject::ReactCra);
    }

    #[test]
    fn test_detect_vite() {
        let tmp = TempDir::new().unwrap();
        let package_json = r#"{"devDependencies": {"vite": "^5.0", "react": "^18.0"}}"#;
        fs::write(tmp.path().join("package.json"), package_json).unwrap();

        let detected = DeploymentPipeline::detect_project_type(tmp.path());
        assert_eq!(detected, DetectedProject::Vite);
    }

    #[test]
    fn test_detect_nextjs() {
        let tmp = TempDir::new().unwrap();
        let package_json = r#"{"dependencies": {"next": "^14.0", "react": "^18.0"}}"#;
        fs::write(tmp.path().join("package.json"), package_json).unwrap();

        let detected = DeploymentPipeline::detect_project_type(tmp.path());
        assert_eq!(detected, DetectedProject::NextJs);
    }

    #[test]
    fn test_detect_angular() {
        let tmp = TempDir::new().unwrap();
        let package_json =
            r#"{"dependencies": {"@angular/core": "^17.0"}, "devDependencies": {"@angular/cli": "^17.0"}}"#;
        fs::write(tmp.path().join("package.json"), package_json).unwrap();

        let detected = DeploymentPipeline::detect_project_type(tmp.path());
        assert_eq!(detected, DetectedProject::Angular);
    }

    #[test]
    fn test_detect_sveltekit() {
        let tmp = TempDir::new().unwrap();
        let package_json = r#"{"devDependencies": {"@sveltejs/kit": "^2.0"}}"#;
        fs::write(tmp.path().join("package.json"), package_json).unwrap();

        let detected = DeploymentPipeline::detect_project_type(tmp.path());
        assert_eq!(detected, DetectedProject::SvelteKit);
    }

    #[test]
    fn test_detect_gatsby() {
        let tmp = TempDir::new().unwrap();
        let package_json = r#"{"dependencies": {"gatsby": "^5.0"}}"#;
        fs::write(tmp.path().join("package.json"), package_json).unwrap();

        let detected = DeploymentPipeline::detect_project_type(tmp.path());
        assert_eq!(detected, DetectedProject::Gatsby);
    }

    #[test]
    fn test_detect_nuxtjs() {
        let tmp = TempDir::new().unwrap();
        let package_json = r#"{"dependencies": {"nuxt": "^3.0"}}"#;
        fs::write(tmp.path().join("package.json"), package_json).unwrap();

        let detected = DeploymentPipeline::detect_project_type(tmp.path());
        assert_eq!(detected, DetectedProject::NuxtJs);
    }

    #[test]
    fn test_detect_node_backend() {
        let tmp = TempDir::new().unwrap();
        let package_json = r#"{"name": "my-api", "scripts": {"start": "node server.js"}, "dependencies": {"express": "^4.0"}}"#;
        fs::write(tmp.path().join("package.json"), package_json).unwrap();

        let detected = DeploymentPipeline::detect_project_type(tmp.path());
        assert_eq!(detected, DetectedProject::NodeBackend);
    }

    #[test]
    fn test_detect_rust() {
        let tmp = TempDir::new().unwrap();
        fs::write(
            tmp.path().join("Cargo.toml"),
            "[package]\nname = \"my-app\"\nversion = \"0.1.0\"",
        )
        .unwrap();

        let detected = DeploymentPipeline::detect_project_type(tmp.path());
        assert_eq!(detected, DetectedProject::RustBackend);
    }

    #[test]
    fn test_detect_go() {
        let tmp = TempDir::new().unwrap();
        fs::write(tmp.path().join("go.mod"), "module example.com/myapp\ngo 1.21").unwrap();

        let detected = DeploymentPipeline::detect_project_type(tmp.path());
        assert_eq!(detected, DetectedProject::GoBackend);
    }

    #[test]
    fn test_detect_python() {
        let tmp = TempDir::new().unwrap();
        fs::write(tmp.path().join("requirements.txt"), "flask==3.0\n").unwrap();

        let detected = DeploymentPipeline::detect_project_type(tmp.path());
        assert_eq!(detected, DetectedProject::PythonBackend);
    }

    #[test]
    fn test_detect_java() {
        let tmp = TempDir::new().unwrap();
        fs::write(tmp.path().join("pom.xml"), "<project></project>").unwrap();

        let detected = DeploymentPipeline::detect_project_type(tmp.path());
        assert_eq!(detected, DetectedProject::JavaBackend);
    }

    #[test]
    fn test_detect_hugo() {
        let tmp = TempDir::new().unwrap();
        fs::write(tmp.path().join("hugo.toml"), "baseURL = 'https://example.com'").unwrap();

        let detected = DeploymentPipeline::detect_project_type(tmp.path());
        assert_eq!(detected, DetectedProject::Hugo);
    }

    #[test]
    fn test_detect_jekyll() {
        let tmp = TempDir::new().unwrap();
        fs::write(tmp.path().join("_config.yml"), "title: My Site").unwrap();
        fs::create_dir(tmp.path().join("_layouts")).unwrap();

        let detected = DeploymentPipeline::detect_project_type(tmp.path());
        assert_eq!(detected, DetectedProject::Jekyll);
    }

    #[test]
    fn test_detect_plain_static() {
        let tmp = TempDir::new().unwrap();
        fs::write(tmp.path().join("index.html"), "<html>Hello</html>").unwrap();

        let detected = DeploymentPipeline::detect_project_type(tmp.path());
        assert_eq!(detected, DetectedProject::PlainStatic);
    }

    #[test]
    fn test_detect_unknown() {
        let tmp = TempDir::new().unwrap();
        fs::write(tmp.path().join("README.md"), "# My Project").unwrap();

        let detected = DeploymentPipeline::detect_project_type(tmp.path());
        assert_eq!(detected, DetectedProject::Unknown);
    }

    // ── Package Manager Detection Tests ────────────────────────────────

    #[test]
    fn test_detect_package_manager_npm() {
        let tmp = TempDir::new().unwrap();
        fs::write(tmp.path().join("package-lock.json"), "{}").unwrap();

        let pm = DeploymentPipeline::detect_package_manager(tmp.path());
        assert_eq!(pm, PackageManager::Npm);
    }

    #[test]
    fn test_detect_package_manager_yarn() {
        let tmp = TempDir::new().unwrap();
        fs::write(tmp.path().join("yarn.lock"), "# yarn lockfile").unwrap();

        let pm = DeploymentPipeline::detect_package_manager(tmp.path());
        assert_eq!(pm, PackageManager::Yarn);
    }

    #[test]
    fn test_detect_package_manager_pnpm() {
        let tmp = TempDir::new().unwrap();
        fs::write(tmp.path().join("pnpm-lock.yaml"), "lockfileVersion: 9").unwrap();

        let pm = DeploymentPipeline::detect_package_manager(tmp.path());
        assert_eq!(pm, PackageManager::Pnpm);
    }

    #[test]
    fn test_detect_package_manager_bun() {
        let tmp = TempDir::new().unwrap();
        fs::write(tmp.path().join("bun.lockb"), "binary").unwrap();

        let pm = DeploymentPipeline::detect_package_manager(tmp.path());
        assert_eq!(pm, PackageManager::Bun);
    }

    #[test]
    fn test_detect_package_manager_default() {
        let tmp = TempDir::new().unwrap();

        let pm = DeploymentPipeline::detect_package_manager(tmp.path());
        assert_eq!(pm, PackageManager::Npm);
    }

    // ── PackageManager Properties Tests ────────────────────────────────

    #[test]
    fn test_package_manager_install_commands() {
        assert_eq!(PackageManager::Npm.install_command(), "npm ci");
        assert_eq!(
            PackageManager::Yarn.install_command(),
            "yarn install --frozen-lockfile"
        );
        assert_eq!(
            PackageManager::Pnpm.install_command(),
            "pnpm install --frozen-lockfile"
        );
        assert_eq!(
            PackageManager::Bun.install_command(),
            "bun install --frozen-lockfile"
        );
    }

    #[test]
    fn test_package_manager_run_commands() {
        assert_eq!(PackageManager::Npm.run_command(), "npm run");
        assert_eq!(PackageManager::Yarn.run_command(), "yarn");
        assert_eq!(PackageManager::Pnpm.run_command(), "pnpm run");
        assert_eq!(PackageManager::Bun.run_command(), "bun run");
    }

    #[test]
    fn test_package_manager_lockfiles() {
        assert_eq!(PackageManager::Npm.lockfile(), "package-lock.json");
        assert_eq!(PackageManager::Yarn.lockfile(), "yarn.lock");
        assert_eq!(PackageManager::Pnpm.lockfile(), "pnpm-lock.yaml");
        assert_eq!(PackageManager::Bun.lockfile(), "bun.lockb");
    }

    #[test]
    fn test_package_manager_display() {
        assert_eq!(format!("{}", PackageManager::Npm), "npm");
        assert_eq!(format!("{}", PackageManager::Yarn), "yarn");
        assert_eq!(format!("{}", PackageManager::Pnpm), "pnpm");
        assert_eq!(format!("{}", PackageManager::Bun), "bun");
    }

    // ── DeployOptions Tests ────────────────────────────────────────────

    #[test]
    fn test_deploy_options_defaults() {
        let opts = DeployOptions::default();
        assert!(opts.branch.is_none());
        assert!(opts.tag.is_none());
        assert!(opts.commit.is_none());
        assert!(!opts.dry_run);
        assert!(!opts.skip_deps);
        assert!(!opts.skip_build);
        assert!(!opts.skip_health_check);
        assert!(!opts.force);
        assert!(opts.env_overrides.is_empty());
        assert!(opts.metadata.is_empty());
    }

    #[test]
    fn test_deploy_options_cli() {
        let opts = DeployOptions::cli();
        assert_eq!(opts.trigger, DeployTrigger::Cli);
    }

    #[test]
    fn test_deploy_options_api() {
        let opts = DeployOptions::api();
        assert_eq!(opts.trigger, DeployTrigger::Api);
    }

    #[test]
    fn test_deploy_options_effective_branch() {
        let mut opts = DeployOptions::default();

        // Without override, use app's branch
        assert_eq!(opts.effective_branch("main"), "main");

        // With override, use the override
        opts.branch = Some("feature/new".to_string());
        assert_eq!(opts.effective_branch("main"), "feature/new");
    }

    // ── DeployResult Tests ─────────────────────────────────────────────

    #[test]
    fn test_deploy_result_success() {
        let result = DeployResult::success(
            "20250115-120000-abc".to_string(),
            "my-api".to_string(),
            "abc123def456789".to_string(),
            "main".to_string(),
            42,
        );

        assert!(result.success);
        assert_eq!(result.status, DeployStatus::Success);
        assert_eq!(result.deploy_id, "20250115-120000-abc");
        assert_eq!(result.app_name, "my-api");
        assert_eq!(result.duration_secs, 42);
        assert!(result.error.is_none());
        assert!(result.failed_step.is_none());
        assert!(!result.rolled_back);

        let display = format!("{}", result);
        assert!(display.contains("✓"));
        assert!(display.contains("my-api"));
        assert!(display.contains("abc123d"));
        assert!(display.contains("42s"));
    }

    #[test]
    fn test_deploy_result_failure() {
        let result = DeployResult::failure(
            "20250115-120000-abc".to_string(),
            "my-api".to_string(),
            "main".to_string(),
            15,
            "Build failed: exit code 1".to_string(),
            Some("build".to_string()),
            true,
        );

        assert!(!result.success);
        assert_eq!(result.status, DeployStatus::Failed);
        assert_eq!(result.error.as_deref(), Some("Build failed: exit code 1"));
        assert_eq!(result.failed_step.as_deref(), Some("build"));
        assert!(result.rolled_back);

        let display = format!("{}", result);
        assert!(display.contains("✗"));
        assert!(display.contains("FAILED"));
        assert!(display.contains("rolled back"));
    }

    // ── Release Management Tests ───────────────────────────────────────

    #[test]
    fn test_create_release() {
        let tmp = TempDir::new().unwrap();
        let repo_dir = tmp.path().join("repo");
        let releases_dir = tmp.path().join("releases");

        // Create a mock repo with some files
        fs::create_dir_all(&repo_dir).unwrap();
        fs::write(repo_dir.join("server.js"), "console.log('hello');").unwrap();
        fs::create_dir(repo_dir.join("src")).unwrap();
        fs::write(repo_dir.join("src/app.js"), "export default {};").unwrap();
        fs::create_dir(repo_dir.join(".git")).unwrap();
        fs::write(repo_dir.join(".git/HEAD"), "ref: refs/heads/main").unwrap();

        let release_dir =
            DeploymentPipeline::create_release(&repo_dir, &releases_dir, "test-release")
                .unwrap();

        assert!(release_dir.exists());
        assert!(release_dir.join("server.js").exists());
        assert!(release_dir.join("src/app.js").exists());
        // .git should be excluded
        assert!(!release_dir.join(".git").exists());
    }

    #[test]
    fn test_cleanup_old_releases() {
        let tmp = TempDir::new().unwrap();
        let releases_dir = tmp.path().join("releases");
        fs::create_dir_all(&releases_dir).unwrap();

        // Create 5 mock releases
        for i in 0..5 {
            let name = format!("20250101-{:06}-abc", i);
            fs::create_dir(releases_dir.join(&name)).unwrap();
            fs::write(
                releases_dir.join(&name).join("marker.txt"),
                format!("release {}", i),
            )
            .unwrap();
        }

        // Keep only 2
        let removed = DeploymentPipeline::cleanup_old_releases(&releases_dir, 2).unwrap();
        assert_eq!(removed, 3);

        // Verify only 2 remain
        let remaining: Vec<_> = fs::read_dir(&releases_dir)
            .unwrap()
            .filter_map(|e| e.ok())
            .filter(|e| e.file_type().map(|t| t.is_dir()).unwrap_or(false))
            .collect();
        assert_eq!(remaining.len(), 2);
    }

    #[test]
    fn test_cleanup_old_releases_nothing_to_remove() {
        let tmp = TempDir::new().unwrap();
        let releases_dir = tmp.path().join("releases");
        fs::create_dir_all(&releases_dir).unwrap();

        for i in 0..3 {
            fs::create_dir(releases_dir.join(format!("release-{}", i))).unwrap();
        }

        let removed = DeploymentPipeline::cleanup_old_releases(&releases_dir, 5).unwrap();
        assert_eq!(removed, 0);
    }

    #[test]
    fn test_cleanup_nonexistent_dir() {
        let result =
            DeploymentPipeline::cleanup_old_releases(Path::new("/nonexistent/releases"), 5);
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), 0);
    }

    // ── Symlink Activation Tests ───────────────────────────────────────

    #[cfg(unix)]
    #[test]
    fn test_activate_release() {
        let tmp = TempDir::new().unwrap();
        let release_dir = tmp.path().join("releases/release-1");
        let current_link = tmp.path().join("current");

        fs::create_dir_all(&release_dir).unwrap();
        fs::write(release_dir.join("app.js"), "console.log('v1');").unwrap();

        let old = DeploymentPipeline::activate_release(&release_dir, &current_link).unwrap();
        assert!(old.is_none()); // No previous release

        assert!(current_link.is_symlink());
        assert!(current_link.join("app.js").exists());

        // Activate a second release
        let release_dir_2 = tmp.path().join("releases/release-2");
        fs::create_dir_all(&release_dir_2).unwrap();
        fs::write(release_dir_2.join("app.js"), "console.log('v2');").unwrap();

        let old =
            DeploymentPipeline::activate_release(&release_dir_2, &current_link).unwrap();
        assert!(old.is_some());

        // current should now point to release-2
        let content = fs::read_to_string(current_link.join("app.js")).unwrap();
        assert!(content.contains("v2"));
    }

    // ── Copy Dir Recursive Tests ───────────────────────────────────────

    #[test]
    fn test_copy_dir_recursive() {
        let tmp = TempDir::new().unwrap();
        let src = tmp.path().join("src");
        let dest = tmp.path().join("dest");

        // Create a directory structure
        fs::create_dir_all(src.join("subdir")).unwrap();
        fs::write(src.join("file1.txt"), "hello").unwrap();
        fs::write(src.join("subdir/file2.txt"), "world").unwrap();
        fs::create_dir(src.join(".git")).unwrap();
        fs::write(src.join(".git/config"), "git stuff").unwrap();
        fs::create_dir(src.join("node_modules")).unwrap();
        fs::write(src.join("node_modules/dep.js"), "dep").unwrap();

        // Copy excluding .git
        DeploymentPipeline::copy_dir_recursive(&src, &dest, &[".git"]).unwrap();

        assert!(dest.join("file1.txt").exists());
        assert!(dest.join("subdir/file2.txt").exists());
        assert!(!dest.join(".git").exists()); // excluded
        assert!(dest.join("node_modules/dep.js").exists()); // not excluded

        assert_eq!(
            fs::read_to_string(dest.join("file1.txt")).unwrap(),
            "hello"
        );
    }

    #[test]
    fn test_copy_dir_recursive_multiple_excludes() {
        let tmp = TempDir::new().unwrap();
        let src = tmp.path().join("src");
        let dest = tmp.path().join("dest");

        fs::create_dir_all(src.join(".git")).unwrap();
        fs::create_dir_all(src.join("node_modules")).unwrap();
        fs::create_dir_all(src.join("src")).unwrap();
        fs::write(src.join(".git/config"), "git").unwrap();
        fs::write(src.join("node_modules/dep.js"), "dep").unwrap();
        fs::write(src.join("src/app.js"), "app").unwrap();
        fs::write(src.join("README.md"), "readme").unwrap();

        DeploymentPipeline::copy_dir_recursive(&src, &dest, &[".git", "node_modules"]).unwrap();

        assert!(!dest.join(".git").exists());
        assert!(!dest.join("node_modules").exists());
        assert!(dest.join("src/app.js").exists());
        assert!(dest.join("README.md").exists());
    }

    // ── Health Check Static Tests ──────────────────────────────────────

    #[test]
    fn test_health_check_static_success() {
        let tmp = TempDir::new().unwrap();
        fs::write(tmp.path().join("index.html"), "<html>OK</html>").unwrap();

        let result =
            DeploymentPipeline::health_check_static(tmp.path(), "index.html");
        assert!(result.success);
        assert_eq!(result.attempts, 1);
        assert!(result.error.is_none());
    }

    #[test]
    fn test_health_check_static_failure() {
        let tmp = TempDir::new().unwrap();

        let result =
            DeploymentPipeline::health_check_static(tmp.path(), "index.html");
        assert!(!result.success);
        assert!(result.error.is_some());
    }

    // ── HealthCheckResult Tests ────────────────────────────────────────

    #[test]
    fn test_health_check_result_display() {
        let success = HealthCheckResult {
            success: true,
            url: "http://localhost:3000/health".to_string(),
            status_code: Some(200),
            attempts: 1,
            error: None,
        };
        let display = format!("{}", success);
        assert!(display.contains("✓"));
        assert!(display.contains("200"));
        assert!(display.contains("1 attempt"));

        let failure = HealthCheckResult {
            success: false,
            url: "http://localhost:3000/health".to_string(),
            status_code: None,
            attempts: 3,
            error: Some("Connection refused".to_string()),
        };
        let display = format!("{}", failure);
        assert!(display.contains("✗"));
        assert!(display.contains("Connection refused"));
        assert!(display.contains("3 attempt"));
    }

    // ── CommandResult Tests ────────────────────────────────────────────

    #[test]
    fn test_command_result_combined_output() {
        let result = CommandResult {
            success: true,
            exit_code: Some(0),
            stdout: "output".to_string(),
            stderr: "warning".to_string(),
            command: "test".to_string(),
        };
        assert!(result.combined_output().contains("output"));
        assert!(result.combined_output().contains("warning"));

        let stdout_only = CommandResult {
            success: true,
            exit_code: Some(0),
            stdout: "output".to_string(),
            stderr: String::new(),
            command: "test".to_string(),
        };
        assert_eq!(stdout_only.combined_output(), "output");
    }

    #[test]
    fn test_command_result_error_summary() {
        let result = CommandResult {
            success: false,
            exit_code: Some(1),
            stdout: String::new(),
            stderr: "Error: file not found\nDetails: /tmp/missing".to_string(),
            command: "cat /tmp/missing".to_string(),
        };
        assert_eq!(result.error_summary(), "Error: file not found");
    }

    #[test]
    fn test_command_result_display() {
        let success = CommandResult {
            success: true,
            exit_code: Some(0),
            stdout: "ok".to_string(),
            stderr: String::new(),
            command: "echo ok".to_string(),
        };
        assert!(format!("{}", success).contains("✓"));

        let failure = CommandResult {
            success: false,
            exit_code: Some(1),
            stdout: String::new(),
            stderr: "bad stuff".to_string(),
            command: "false".to_string(),
        };
        assert!(format!("{}", failure).contains("✗"));
    }

    // ── Deploy Lock Tests ──────────────────────────────────────────────

    #[test]
    fn test_deploy_lock_acquire_release() {
        let config = test_config();
        let pipeline = DeploymentPipeline::new(config).unwrap();

        assert!(!pipeline.is_deploying("my-app"));
        assert!(pipeline.active_deployments().is_empty());

        {
            let _lock = pipeline.acquire_lock("my-app").unwrap();
            assert!(pipeline.is_deploying("my-app"));
            assert_eq!(pipeline.active_deployments(), vec!["my-app".to_string()]);

            // Trying to acquire again should fail
            let result = pipeline.acquire_lock("my-app");
            assert!(matches!(
                result,
                Err(PipelineError::DeploymentInProgress { .. })
            ));

            // Different app should work
            let _lock2 = pipeline.acquire_lock("other-app").unwrap();
            assert!(pipeline.is_deploying("other-app"));
            assert_eq!(pipeline.active_deployments().len(), 2);
        }
        // Locks dropped here

        assert!(!pipeline.is_deploying("my-app"));
        assert!(!pipeline.is_deploying("other-app"));
        assert!(pipeline.active_deployments().is_empty());
    }

    #[test]
    fn test_deploy_lock_raii() {
        let config = test_config();
        let pipeline = DeploymentPipeline::new(config).unwrap();

        // Acquire and immediately drop
        let lock = pipeline.acquire_lock("test-app").unwrap();
        assert!(pipeline.is_deploying("test-app"));
        drop(lock);
        assert!(!pipeline.is_deploying("test-app"));
    }

    // ── Run Command Tests ──────────────────────────────────────────────

    #[test]
    fn test_run_command_success() {
        let tmp = TempDir::new().unwrap();
        let env = HashMap::new();

        let result =
            DeploymentPipeline::run_command("echo hello world", tmp.path(), &env, None)
                .unwrap();

        assert!(result.success);
        assert_eq!(result.exit_code, Some(0));
        assert!(result.stdout.trim().contains("hello world"));
    }

    #[test]
    fn test_run_command_failure() {
        let tmp = TempDir::new().unwrap();
        let env = HashMap::new();

        let result =
            DeploymentPipeline::run_command("exit 42", tmp.path(), &env, None).unwrap();

        assert!(!result.success);
        assert_eq!(result.exit_code, Some(42));
    }

    #[test]
    fn test_run_command_with_env() {
        let tmp = TempDir::new().unwrap();
        let mut env = HashMap::new();
        env.insert("MY_VAR".to_string(), "my_value".to_string());

        let result = DeploymentPipeline::run_command(
            "echo $MY_VAR",
            tmp.path(),
            &env,
            None,
        )
        .unwrap();

        assert!(result.success);
        assert!(result.stdout.trim().contains("my_value"));
    }

    #[test]
    fn test_run_command_in_working_dir() {
        let tmp = TempDir::new().unwrap();
        fs::write(tmp.path().join("test.txt"), "content").unwrap();
        let env = HashMap::new();

        let result =
            DeploymentPipeline::run_command("ls test.txt", tmp.path(), &env, None).unwrap();

        assert!(result.success);
        assert!(result.stdout.contains("test.txt"));
    }

    // ── Git Operations Tests (basic, non-network) ──────────────────────

    #[test]
    fn test_git_current_commit_in_non_repo() {
        let tmp = TempDir::new().unwrap();
        let result = DeploymentPipeline::git_current_commit(tmp.path());
        assert!(result.is_err());
    }

    // ── Pipeline Construction Test ─────────────────────────────────────

    #[test]
    fn test_pipeline_new() {
        let config = test_config();
        let pipeline = DeploymentPipeline::new(config);
        assert!(pipeline.is_ok());

        let pipeline = pipeline.unwrap();
        assert_eq!(pipeline.config().max_apps, 100);
        assert_eq!(pipeline.config().build_timeout_secs, 300);
        assert!(pipeline.active_deployments().is_empty());
    }

    // ── Serialization Tests ────────────────────────────────────────────

    #[test]
    fn test_detected_project_serialization() {
        let project = DetectedProject::ReactCra;
        let json = serde_json::to_string(&project).unwrap();
        let deserialized: DetectedProject = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized, DetectedProject::ReactCra);
    }

    #[test]
    fn test_package_manager_serialization() {
        let pm = PackageManager::Yarn;
        let json = serde_json::to_string(&pm).unwrap();
        let deserialized: PackageManager = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized, PackageManager::Yarn);
    }

    #[test]
    fn test_deploy_result_serialization() {
        let result = DeployResult::success(
            "deploy-1".to_string(),
            "my-app".to_string(),
            "abc123".to_string(),
            "main".to_string(),
            30,
        );

        let json = serde_json::to_string(&result).unwrap();
        let deserialized: DeployResult = serde_json::from_str(&json).unwrap();

        assert!(deserialized.success);
        assert_eq!(deserialized.deploy_id, "deploy-1");
        assert_eq!(deserialized.app_name, "my-app");
        assert_eq!(deserialized.commit_hash, "abc123");
    }

    #[test]
    fn test_health_check_result_serialization() {
        let result = HealthCheckResult {
            success: true,
            url: "http://localhost:3000".to_string(),
            status_code: Some(200),
            attempts: 1,
            error: None,
        };

        let json = serde_json::to_string(&result).unwrap();
        let deserialized: HealthCheckResult = serde_json::from_str(&json).unwrap();

        assert!(deserialized.success);
        assert_eq!(deserialized.status_code, Some(200));
    }
}
