//! Deployment History Module
//!
//! This module tracks the history of deployments for each application,
//! enabling rollback, audit trails, and deployment analytics.
//!
//! ## Storage
//!
//! Each application maintains its own deploy history directory at:
//! `<app_deploy_dir>/deploys/`
//!
//! Each deployment produces two files:
//! - `<deploy_id>.json` — structured metadata (DeployRecord)
//! - `<deploy_id>.log` — raw build/deploy output log
//!
//! ## Retention
//!
//! The number of retained deploy records is configurable (default: 10).
//! When the limit is exceeded, the oldest records (and their associated
//! release directories) are pruned automatically.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::fmt;
use std::fs;
use std::io::{self, BufWriter, Write};
use std::path::{Path, PathBuf};
use thiserror::Error;
use tracing::{debug, error, info, warn};

// ─────────────────────────────────────────────────────────────────────────────
// Error Types
// ─────────────────────────────────────────────────────────────────────────────

/// Errors specific to deploy history operations.
#[derive(Debug, Error)]
pub enum HistoryError {
    #[error("IO error: {0}")]
    Io(#[from] io::Error),

    #[error("Deploy record not found: {id}")]
    NotFound { id: String },

    #[error("No previous deployment to rollback to for app '{app}'")]
    NoPreviousDeploy { app: String },

    #[error("Serialization error: {0}")]
    Serialization(String),

    #[error("Deserialization error: {0}")]
    Deserialization(String),

    #[error("Deploy log not found for deploy '{id}'")]
    LogNotFound { id: String },

    #[error("Deploy directory does not exist: {path}")]
    DirectoryMissing { path: String },
}

/// Result alias for history operations.
pub type Result<T> = std::result::Result<T, HistoryError>;

// ─────────────────────────────────────────────────────────────────────────────
// Deploy Status
// ─────────────────────────────────────────────────────────────────────────────

/// The final outcome of a deployment attempt.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DeployStatus {
    /// The deployment completed successfully and the app is running.
    Success,
    /// The deployment failed at some step.
    Failed,
    /// The deployment succeeded but was later rolled back.
    RolledBack,
    /// The deployment is currently in progress.
    InProgress,
    /// The deployment was cancelled before completion.
    Cancelled,
}

impl DeployStatus {
    /// Whether this status represents a terminal (finished) state.
    pub fn is_terminal(&self) -> bool {
        matches!(
            self,
            DeployStatus::Success
                | DeployStatus::Failed
                | DeployStatus::RolledBack
                | DeployStatus::Cancelled
        )
    }

    /// Whether this status represents a successful outcome.
    pub fn is_success(&self) -> bool {
        matches!(self, DeployStatus::Success)
    }
}

impl Default for DeployStatus {
    fn default() -> Self {
        DeployStatus::InProgress
    }
}

impl fmt::Display for DeployStatus {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            DeployStatus::Success => write!(f, "success"),
            DeployStatus::Failed => write!(f, "failed"),
            DeployStatus::RolledBack => write!(f, "rolled_back"),
            DeployStatus::InProgress => write!(f, "in_progress"),
            DeployStatus::Cancelled => write!(f, "cancelled"),
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Deploy Trigger
// ─────────────────────────────────────────────────────────────────────────────

/// What triggered the deployment.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DeployTrigger {
    /// Manually triggered via CLI
    Cli,
    /// Triggered via HTTP API call
    Api,
    /// Triggered by a GitHub webhook (push event)
    Webhook,
    /// Triggered by the auto-deploy/watcher system
    Auto,
    /// Triggered by a rollback operation
    Rollback,
    /// Triggered by a scheduled job
    Scheduled,
}

impl Default for DeployTrigger {
    fn default() -> Self {
        DeployTrigger::Cli
    }
}

impl fmt::Display for DeployTrigger {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            DeployTrigger::Cli => write!(f, "cli"),
            DeployTrigger::Api => write!(f, "api"),
            DeployTrigger::Webhook => write!(f, "webhook"),
            DeployTrigger::Auto => write!(f, "auto"),
            DeployTrigger::Rollback => write!(f, "rollback"),
            DeployTrigger::Scheduled => write!(f, "scheduled"),
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Pipeline Step Record
// ─────────────────────────────────────────────────────────────────────────────

/// The name of a step in the deployment pipeline.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PipelineStep {
    PreDeploy,
    GitClone,
    GitPull,
    Detect,
    InstallDeps,
    Build,
    VerifyBuild,
    Install,
    Configure,
    Activate,
    HealthCheck,
    PostDeploy,
}

impl fmt::Display for PipelineStep {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            PipelineStep::PreDeploy => write!(f, "pre_deploy"),
            PipelineStep::GitClone => write!(f, "git_clone"),
            PipelineStep::GitPull => write!(f, "git_pull"),
            PipelineStep::Detect => write!(f, "detect"),
            PipelineStep::InstallDeps => write!(f, "install_deps"),
            PipelineStep::Build => write!(f, "build"),
            PipelineStep::VerifyBuild => write!(f, "verify_build"),
            PipelineStep::Install => write!(f, "install"),
            PipelineStep::Configure => write!(f, "configure"),
            PipelineStep::Activate => write!(f, "activate"),
            PipelineStep::HealthCheck => write!(f, "health_check"),
            PipelineStep::PostDeploy => write!(f, "post_deploy"),
        }
    }
}

/// Record of a single pipeline step's execution.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StepRecord {
    /// Which step this is
    pub step: PipelineStep,

    /// Whether the step succeeded
    pub success: bool,

    /// When the step started
    pub started_at: DateTime<Utc>,

    /// When the step finished
    pub finished_at: Option<DateTime<Utc>>,

    /// Duration of the step in milliseconds
    pub duration_ms: Option<u64>,

    /// Error message if the step failed
    pub error: Option<String>,

    /// Optional output/notes from the step
    pub output: Option<String>,
}

impl StepRecord {
    /// Create a new step record marking the start of a step.
    pub fn start(step: PipelineStep) -> Self {
        Self {
            step,
            success: false,
            started_at: Utc::now(),
            finished_at: None,
            duration_ms: None,
            error: None,
            output: None,
        }
    }

    /// Mark the step as completed successfully.
    pub fn finish_success(&mut self) {
        let now = Utc::now();
        self.success = true;
        self.finished_at = Some(now);
        self.duration_ms = Some(
            (now - self.started_at)
                .num_milliseconds()
                .max(0) as u64,
        );
    }

    /// Mark the step as completed with success and attach output.
    pub fn finish_success_with_output(&mut self, output: String) {
        self.finish_success();
        self.output = Some(output);
    }

    /// Mark the step as failed with an error message.
    pub fn finish_failure(&mut self, error: String) {
        let now = Utc::now();
        self.success = false;
        self.finished_at = Some(now);
        self.duration_ms = Some(
            (now - self.started_at)
                .num_milliseconds()
                .max(0) as u64,
        );
        self.error = Some(error);
    }

    /// Whether this step has completed (success or failure).
    pub fn is_finished(&self) -> bool {
        self.finished_at.is_some()
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Deploy Record
// ─────────────────────────────────────────────────────────────────────────────

/// Complete record of a single deployment attempt.
///
/// One of these is created for every `deploy` or `rollback` operation.
/// They are persisted as JSON files in the app's `deploys/` directory.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeployRecord {
    /// Unique deployment identifier (e.g. "20250115-143022-abc1234")
    pub id: String,

    /// The application ID this deploy belongs to
    pub app_id: String,

    /// The application name (denormalized for convenience)
    pub app_name: String,

    /// Git commit hash at the time of deployment
    pub commit_hash: String,

    /// Git commit message (first line)
    pub commit_message: Option<String>,

    /// Git branch that was deployed
    pub branch: String,

    /// Git tag (if deploying a specific tag)
    pub tag: Option<String>,

    /// What triggered this deployment
    pub trigger: DeployTrigger,

    /// Final status of the deployment
    pub status: DeployStatus,

    /// When the deployment started
    pub started_at: DateTime<Utc>,

    /// When the deployment finished (success or failure)
    pub finished_at: Option<DateTime<Utc>>,

    /// Total duration of the deployment in seconds
    pub duration_secs: Option<u64>,

    /// Ordered list of pipeline step records
    pub steps: Vec<StepRecord>,

    /// Path to the release directory on disk (for rollback)
    pub release_path: Option<PathBuf>,

    /// Path to the build/deploy log file
    pub log_path: Option<PathBuf>,

    /// Error message if the deployment failed
    pub error_message: Option<String>,

    /// The deploy ID that was active before this deploy started
    /// (used to know what to rollback to)
    pub previous_deploy_id: Option<String>,

    /// Whether this deploy was itself a rollback operation
    pub is_rollback: bool,

    /// If this was a rollback, the deploy ID it rolled back to
    pub rollback_target_id: Option<String>,

    /// Free-form metadata (e.g. CI job URL, user notes)
    pub metadata: std::collections::HashMap<String, String>,
}

impl DeployRecord {
    /// Create a new deploy record for a fresh deployment.
    pub fn new(
        app_id: String,
        app_name: String,
        branch: String,
        trigger: DeployTrigger,
    ) -> Self {
        let now = Utc::now();
        let id = generate_deploy_id(&now);

        Self {
            id,
            app_id,
            app_name,
            commit_hash: String::new(),
            commit_message: None,
            branch,
            tag: None,
            trigger,
            status: DeployStatus::InProgress,
            started_at: now,
            finished_at: None,
            duration_secs: None,
            steps: Vec::new(),
            release_path: None,
            log_path: None,
            error_message: None,
            previous_deploy_id: None,
            is_rollback: false,
            rollback_target_id: None,
            metadata: std::collections::HashMap::new(),
        }
    }

    /// Create a new deploy record for a rollback operation.
    pub fn new_rollback(
        app_id: String,
        app_name: String,
        branch: String,
        target_deploy_id: String,
    ) -> Self {
        let mut record = Self::new(app_id, app_name, branch, DeployTrigger::Rollback);
        record.is_rollback = true;
        record.rollback_target_id = Some(target_deploy_id);
        record
    }

    /// Record a pipeline step result.
    pub fn add_step(&mut self, step: StepRecord) {
        self.steps.push(step);
    }

    /// Start a new pipeline step and return a mutable reference to it.
    pub fn start_step(&mut self, step: PipelineStep) -> &mut StepRecord {
        self.steps.push(StepRecord::start(step));
        self.steps.last_mut().unwrap()
    }

    /// Set the commit hash (populated after git clone/pull).
    pub fn set_commit(&mut self, hash: String, message: Option<String>) {
        self.commit_hash = hash;
        self.commit_message = message;
    }

    /// Mark the deployment as successfully completed.
    pub fn finish_success(&mut self) {
        let now = Utc::now();
        self.status = DeployStatus::Success;
        self.finished_at = Some(now);
        self.duration_secs = Some(
            (now - self.started_at)
                .num_seconds()
                .max(0) as u64,
        );
    }

    /// Mark the deployment as failed.
    pub fn finish_failure(&mut self, error: String) {
        let now = Utc::now();
        self.status = DeployStatus::Failed;
        self.finished_at = Some(now);
        self.duration_secs = Some(
            (now - self.started_at)
                .num_seconds()
                .max(0) as u64,
        );
        self.error_message = Some(error);
    }

    /// Mark the deployment as cancelled.
    pub fn cancel(&mut self) {
        let now = Utc::now();
        self.status = DeployStatus::Cancelled;
        self.finished_at = Some(now);
        self.duration_secs = Some(
            (now - self.started_at)
                .num_seconds()
                .max(0) as u64,
        );
    }

    /// Mark this deploy as rolled back (after a newer deploy triggered a rollback).
    pub fn mark_rolled_back(&mut self) {
        self.status = DeployStatus::RolledBack;
    }

    /// Whether the deployment is still in progress.
    pub fn is_in_progress(&self) -> bool {
        self.status == DeployStatus::InProgress
    }

    /// Whether the deployment completed successfully.
    pub fn is_success(&self) -> bool {
        self.status == DeployStatus::Success
    }

    /// Whether the deployment failed.
    pub fn is_failed(&self) -> bool {
        self.status == DeployStatus::Failed
    }

    /// Get the step that failed (if any).
    pub fn failed_step(&self) -> Option<&StepRecord> {
        self.steps.iter().find(|s| s.is_finished() && !s.success)
    }

    /// Get a human-friendly one-line summary of this deployment.
    pub fn summary(&self) -> String {
        let commit_short = if self.commit_hash.len() >= 7 {
            &self.commit_hash[..7]
        } else {
            &self.commit_hash
        };

        let duration = self
            .duration_secs
            .map(|d| format!(" ({}s)", d))
            .unwrap_or_default();

        format!(
            "[{}] {} {} branch={} commit={} trigger={}{}",
            self.id, self.status, self.app_name, self.branch, commit_short, self.trigger, duration
        )
    }
}

impl fmt::Display for DeployRecord {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.summary())
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Deploy History Manager
// ─────────────────────────────────────────────────────────────────────────────

/// Manages the deployment history for a single application.
///
/// Each application has its own `DeployHistory` instance that reads from and
/// writes to the app's `deploys/` directory.
pub struct DeployHistory {
    /// Path to the deploys directory for this app
    deploys_dir: PathBuf,

    /// Maximum number of deploy records to retain
    max_records: usize,
}

impl DeployHistory {
    /// Create a new deploy history manager for the given deploys directory.
    ///
    /// Creates the directory if it doesn't exist.
    pub fn new(deploys_dir: PathBuf, max_records: usize) -> Result<Self> {
        if !deploys_dir.exists() {
            fs::create_dir_all(&deploys_dir)?;
        }

        Ok(Self {
            deploys_dir,
            max_records,
        })
    }

    /// Save a deploy record to disk.
    pub fn save_record(&self, record: &DeployRecord) -> Result<()> {
        let path = self.record_path(&record.id);

        let content = serde_json::to_string_pretty(record)
            .map_err(|e| HistoryError::Serialization(e.to_string()))?;

        // Atomic write
        let tmp_path = path.with_extension("json.tmp");
        fs::write(&tmp_path, &content)?;
        fs::rename(&tmp_path, &path)?;

        debug!("Deploy record saved: {}", record.id);
        Ok(())
    }

    /// Load a deploy record by ID.
    pub fn load_record(&self, id: &str) -> Result<DeployRecord> {
        let path = self.record_path(id);

        if !path.exists() {
            return Err(HistoryError::NotFound { id: id.to_string() });
        }

        let content = fs::read_to_string(&path)?;
        let record: DeployRecord = serde_json::from_str(&content)
            .map_err(|e| HistoryError::Deserialization(e.to_string()))?;

        Ok(record)
    }

    /// Delete a deploy record by ID.
    pub fn delete_record(&self, id: &str) -> Result<()> {
        let record_path = self.record_path(id);
        let log_path = self.log_path(id);

        if record_path.exists() {
            fs::remove_file(&record_path)?;
        }

        if log_path.exists() {
            fs::remove_file(&log_path)?;
        }

        debug!("Deploy record deleted: {}", id);
        Ok(())
    }

    /// List all deploy records, sorted by timestamp (newest first).
    pub fn list(&self) -> Result<Vec<DeployRecord>> {
        let mut records = Vec::new();

        if !self.deploys_dir.exists() {
            return Ok(records);
        }

        for entry in fs::read_dir(&self.deploys_dir)? {
            let entry = entry?;
            let path = entry.path();

            if path.extension().and_then(|e| e.to_str()) == Some("json") {
                match fs::read_to_string(&path) {
                    Ok(content) => {
                        match serde_json::from_str::<DeployRecord>(&content) {
                            Ok(record) => records.push(record),
                            Err(e) => {
                                warn!(
                                    "Failed to parse deploy record {:?}: {}",
                                    path, e
                                );
                            }
                        }
                    }
                    Err(e) => {
                        warn!("Failed to read deploy record {:?}: {}", path, e);
                    }
                }
            }
        }

        // Sort newest first
        records.sort_by(|a, b| b.started_at.cmp(&a.started_at));

        Ok(records)
    }

    /// Get the most recent successful deployment.
    pub fn last_successful(&self) -> Result<Option<DeployRecord>> {
        let records = self.list()?;
        Ok(records.into_iter().find(|r| r.is_success()))
    }

    /// Get the most recent deployment (regardless of status).
    pub fn last(&self) -> Result<Option<DeployRecord>> {
        let records = self.list()?;
        Ok(records.into_iter().next())
    }

    /// Get the deployment before the given deploy ID (for rollback).
    pub fn previous_successful(&self, current_id: &str) -> Result<Option<DeployRecord>> {
        let records = self.list()?;
        let mut found_current = false;

        for record in records {
            if record.id == current_id {
                found_current = true;
                continue;
            }
            if found_current && record.is_success() {
                return Ok(Some(record));
            }
        }

        Ok(None)
    }

    /// Get the Nth most recent successful deployment (0 = most recent).
    pub fn nth_successful(&self, n: usize) -> Result<Option<DeployRecord>> {
        let records = self.list()?;
        Ok(records
            .into_iter()
            .filter(|r| r.is_success())
            .nth(n))
    }

    /// Get the total number of deploy records.
    pub fn count(&self) -> Result<usize> {
        Ok(self.list()?.len())
    }

    /// Get the number of successful deployments.
    pub fn success_count(&self) -> Result<usize> {
        Ok(self.list()?.iter().filter(|r| r.is_success()).count())
    }

    // ── Log File Management ────────────────────────────────────────────

    /// Create a new log file writer for a deployment.
    ///
    /// Returns a buffered writer that the pipeline can write build/deploy
    /// output to.
    pub fn create_log_writer(&self, deploy_id: &str) -> Result<DeployLogWriter> {
        let path = self.log_path(deploy_id);
        let file = fs::File::create(&path)?;
        let writer = BufWriter::new(file);

        Ok(DeployLogWriter {
            writer,
            path,
            bytes_written: 0,
        })
    }

    /// Read the log file for a given deploy.
    pub fn read_log(&self, deploy_id: &str) -> Result<String> {
        let path = self.log_path(deploy_id);

        if !path.exists() {
            return Err(HistoryError::LogNotFound {
                id: deploy_id.to_string(),
            });
        }

        Ok(fs::read_to_string(&path)?)
    }

    /// Read the last N lines of a deploy log.
    pub fn tail_log(&self, deploy_id: &str, lines: usize) -> Result<Vec<String>> {
        let content = self.read_log(deploy_id)?;
        let all_lines: Vec<String> = content.lines().map(String::from).collect();
        let start = all_lines.len().saturating_sub(lines);
        Ok(all_lines[start..].to_vec())
    }

    /// Get the size of a deploy log file in bytes.
    pub fn log_size(&self, deploy_id: &str) -> Result<u64> {
        let path = self.log_path(deploy_id);

        if !path.exists() {
            return Ok(0);
        }

        let metadata = fs::metadata(&path)?;
        Ok(metadata.len())
    }

    // ── Cleanup & Pruning ──────────────────────────────────────────────

    /// Prune old deploy records, keeping only the most recent `max_records`.
    ///
    /// Returns the IDs of the pruned records.
    pub fn prune(&self) -> Result<Vec<String>> {
        let records = self.list()?;
        let mut pruned = Vec::new();

        if records.len() <= self.max_records {
            return Ok(pruned);
        }

        // Records are sorted newest-first, so skip the ones we want to keep
        for record in records.iter().skip(self.max_records) {
            // Never prune in-progress deployments
            if record.is_in_progress() {
                continue;
            }

            match self.delete_record(&record.id) {
                Ok(()) => {
                    pruned.push(record.id.clone());
                    info!("Pruned old deploy record: {}", record.id);
                }
                Err(e) => {
                    warn!("Failed to prune deploy record {}: {}", record.id, e);
                }
            }
        }

        Ok(pruned)
    }

    /// Remove all deploy records and logs for this application.
    pub fn clear(&self) -> Result<usize> {
        let records = self.list()?;
        let count = records.len();

        for record in &records {
            let _ = self.delete_record(&record.id);
        }

        info!("Cleared {} deploy records", count);
        Ok(count)
    }

    // ── Statistics ─────────────────────────────────────────────────────

    /// Get deploy history statistics.
    pub fn stats(&self) -> Result<DeployHistoryStats> {
        let records = self.list()?;

        let total = records.len();
        let successful = records.iter().filter(|r| r.is_success()).count();
        let failed = records.iter().filter(|r| r.is_failed()).count();
        let rolled_back = records
            .iter()
            .filter(|r| r.status == DeployStatus::RolledBack)
            .count();

        let avg_duration = if successful > 0 {
            let total_duration: u64 = records
                .iter()
                .filter(|r| r.is_success())
                .filter_map(|r| r.duration_secs)
                .sum();
            Some(total_duration as f64 / successful as f64)
        } else {
            None
        };

        let last_deploy = records.first().map(|r| r.started_at);
        let last_success = records
            .iter()
            .find(|r| r.is_success())
            .map(|r| r.started_at);

        let success_rate = if total > 0 {
            successful as f64 / total as f64
        } else {
            0.0
        };

        Ok(DeployHistoryStats {
            total_deploys: total,
            successful,
            failed,
            rolled_back,
            success_rate,
            avg_duration_secs: avg_duration,
            last_deploy_at: last_deploy,
            last_success_at: last_success,
        })
    }

    // ── Path Helpers ───────────────────────────────────────────────────

    /// Get the file path for a deploy record JSON file.
    fn record_path(&self, deploy_id: &str) -> PathBuf {
        self.deploys_dir.join(format!("{}.json", deploy_id))
    }

    /// Get the file path for a deploy log file.
    fn log_path(&self, deploy_id: &str) -> PathBuf {
        self.deploys_dir.join(format!("{}.log", deploy_id))
    }

    /// Get the deploys directory path.
    pub fn dir(&self) -> &Path {
        &self.deploys_dir
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Deploy Log Writer
// ─────────────────────────────────────────────────────────────────────────────

/// A buffered writer for capturing deployment output to a log file.
///
/// Wraps a `BufWriter<File>` with convenience methods for writing
/// structured log entries with timestamps.
pub struct DeployLogWriter {
    writer: BufWriter<fs::File>,
    path: PathBuf,
    bytes_written: u64,
}

impl DeployLogWriter {
    /// Write a line to the log with a timestamp prefix.
    pub fn log(&mut self, message: &str) -> Result<()> {
        let timestamp = Utc::now().format("%Y-%m-%d %H:%M:%S%.3f UTC");
        let line = format!("[{}] {}\n", timestamp, message);
        let bytes = line.as_bytes();
        self.writer.write_all(bytes)?;
        self.bytes_written += bytes.len() as u64;
        Ok(())
    }

    /// Write a step header to the log.
    pub fn log_step_start(&mut self, step: &PipelineStep) -> Result<()> {
        self.log(&format!("═══ Step: {} ═══════════════════════════════", step))
    }

    /// Write a step completion to the log.
    pub fn log_step_end(&mut self, step: &PipelineStep, success: bool) -> Result<()> {
        let status = if success { "✓ PASSED" } else { "✗ FAILED" };
        self.log(&format!("═══ {} {} ═══════════════════════════════", step, status))
    }

    /// Write raw output (e.g. from a build command) without timestamp prefix.
    pub fn write_raw(&mut self, data: &[u8]) -> Result<()> {
        self.writer.write_all(data)?;
        self.bytes_written += data.len() as u64;
        Ok(())
    }

    /// Write a separator line.
    pub fn separator(&mut self) -> Result<()> {
        let line = "────────────────────────────────────────────────────────────\n";
        self.writer.write_all(line.as_bytes())?;
        self.bytes_written += line.len() as u64;
        Ok(())
    }

    /// Write an error message prominently.
    pub fn log_error(&mut self, message: &str) -> Result<()> {
        self.log(&format!("ERROR: {}", message))
    }

    /// Flush the writer to ensure all data is written to disk.
    pub fn flush(&mut self) -> Result<()> {
        self.writer.flush()?;
        Ok(())
    }

    /// Get the path to the log file.
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Get the total number of bytes written.
    pub fn bytes_written(&self) -> u64 {
        self.bytes_written
    }

    /// Finalize the log writer, flushing and returning the path.
    pub fn finalize(mut self) -> Result<PathBuf> {
        self.flush()?;
        Ok(self.path)
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Deploy History Stats
// ─────────────────────────────────────────────────────────────────────────────

/// Aggregate statistics about an application's deployment history.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeployHistoryStats {
    /// Total number of deployment attempts
    pub total_deploys: usize,

    /// Number of successful deployments
    pub successful: usize,

    /// Number of failed deployments
    pub failed: usize,

    /// Number of deployments that were rolled back
    pub rolled_back: usize,

    /// Success rate (0.0 to 1.0)
    pub success_rate: f64,

    /// Average deployment duration in seconds (successful deploys only)
    pub avg_duration_secs: Option<f64>,

    /// Timestamp of the most recent deployment attempt
    pub last_deploy_at: Option<DateTime<Utc>>,

    /// Timestamp of the most recent successful deployment
    pub last_success_at: Option<DateTime<Utc>>,
}

// ─────────────────────────────────────────────────────────────────────────────
// ID Generation
// ─────────────────────────────────────────────────────────────────────────────

/// Generate a deploy ID in the format: `YYYYMMDD-HHMMSS-XXXXXXX`
///
/// The format includes a human-readable timestamp prefix for easy sorting
/// and identification, plus a short random suffix for uniqueness.
fn generate_deploy_id(timestamp: &DateTime<Utc>) -> String {
    let time_part = timestamp.format("%Y%m%d-%H%M%S").to_string();

    // Generate a short random-ish suffix using FNV hash of high-res time
    let nanos = timestamp.timestamp_subsec_nanos();
    let pid = std::process::id();
    let mut h: u32 = 0x811c_9dc5;
    for byte in nanos.to_le_bytes() {
        h ^= byte as u32;
        h = h.wrapping_mul(0x0100_0193);
    }
    for byte in pid.to_le_bytes() {
        h ^= byte as u32;
        h = h.wrapping_mul(0x0100_0193);
    }

    format!("{}-{:07x}", time_part, h & 0x0FFF_FFFF)
}

/// Generate a release directory name from a deploy timestamp and commit hash.
///
/// Format: `YYYYMMDD-HHMMSS-<short_commit>`
pub fn release_dir_name(timestamp: &DateTime<Utc>, commit_hash: &str) -> String {
    let time_part = timestamp.format("%Y%m%d-%H%M%S").to_string();
    let commit_short = if commit_hash.len() >= 7 {
        &commit_hash[..7]
    } else {
        commit_hash
    };
    format!("{}-{}", time_part, commit_short)
}

// ─────────────────────────────────────────────────────────────────────────────
// Tests
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    fn test_dir() -> TempDir {
        TempDir::new().unwrap()
    }

    // ── DeployStatus Tests ─────────────────────────────────────────────

    #[test]
    fn test_deploy_status_terminal() {
        assert!(DeployStatus::Success.is_terminal());
        assert!(DeployStatus::Failed.is_terminal());
        assert!(DeployStatus::RolledBack.is_terminal());
        assert!(DeployStatus::Cancelled.is_terminal());
        assert!(!DeployStatus::InProgress.is_terminal());
    }

    #[test]
    fn test_deploy_status_display() {
        assert_eq!(format!("{}", DeployStatus::Success), "success");
        assert_eq!(format!("{}", DeployStatus::Failed), "failed");
        assert_eq!(format!("{}", DeployStatus::InProgress), "in_progress");
        assert_eq!(format!("{}", DeployStatus::RolledBack), "rolled_back");
        assert_eq!(format!("{}", DeployStatus::Cancelled), "cancelled");
    }

    // ── StepRecord Tests ───────────────────────────────────────────────

    #[test]
    fn test_step_record_lifecycle() {
        let mut step = StepRecord::start(PipelineStep::Build);
        assert!(!step.is_finished());
        assert!(!step.success);
        assert!(step.finished_at.is_none());

        step.finish_success();
        assert!(step.is_finished());
        assert!(step.success);
        assert!(step.finished_at.is_some());
        assert!(step.duration_ms.is_some());
    }

    #[test]
    fn test_step_record_failure() {
        let mut step = StepRecord::start(PipelineStep::HealthCheck);
        step.finish_failure("Connection refused".to_string());

        assert!(step.is_finished());
        assert!(!step.success);
        assert_eq!(step.error.as_deref(), Some("Connection refused"));
    }

    #[test]
    fn test_step_record_success_with_output() {
        let mut step = StepRecord::start(PipelineStep::InstallDeps);
        step.finish_success_with_output("Installed 42 packages".to_string());

        assert!(step.success);
        assert_eq!(step.output.as_deref(), Some("Installed 42 packages"));
    }

    // ── DeployRecord Tests ─────────────────────────────────────────────

    #[test]
    fn test_deploy_record_new() {
        let record = DeployRecord::new(
            "app-123".to_string(),
            "my-app".to_string(),
            "main".to_string(),
            DeployTrigger::Cli,
        );

        assert!(!record.id.is_empty());
        assert_eq!(record.app_name, "my-app");
        assert_eq!(record.branch, "main");
        assert_eq!(record.status, DeployStatus::InProgress);
        assert!(record.is_in_progress());
        assert!(!record.is_success());
        assert!(!record.is_rollback);
    }

    #[test]
    fn test_deploy_record_rollback() {
        let record = DeployRecord::new_rollback(
            "app-123".to_string(),
            "my-app".to_string(),
            "main".to_string(),
            "20250101-120000-abc1234".to_string(),
        );

        assert!(record.is_rollback);
        assert_eq!(
            record.rollback_target_id.as_deref(),
            Some("20250101-120000-abc1234")
        );
        assert_eq!(record.trigger, DeployTrigger::Rollback);
    }

    #[test]
    fn test_deploy_record_finish_success() {
        let mut record = DeployRecord::new(
            "app-123".to_string(),
            "my-app".to_string(),
            "main".to_string(),
            DeployTrigger::Api,
        );

        record.set_commit("abc123def456".to_string(), Some("Fix bug".to_string()));
        record.finish_success();

        assert!(record.is_success());
        assert!(!record.is_in_progress());
        assert!(record.finished_at.is_some());
        assert!(record.duration_secs.is_some());
        assert_eq!(record.commit_hash, "abc123def456");
        assert_eq!(record.commit_message.as_deref(), Some("Fix bug"));
    }

    #[test]
    fn test_deploy_record_finish_failure() {
        let mut record = DeployRecord::new(
            "app-123".to_string(),
            "my-app".to_string(),
            "main".to_string(),
            DeployTrigger::Webhook,
        );

        record.finish_failure("Build failed: exit code 1".to_string());

        assert!(record.is_failed());
        assert_eq!(
            record.error_message.as_deref(),
            Some("Build failed: exit code 1")
        );
    }

    #[test]
    fn test_deploy_record_cancel() {
        let mut record = DeployRecord::new(
            "app-123".to_string(),
            "my-app".to_string(),
            "main".to_string(),
            DeployTrigger::Cli,
        );

        record.cancel();
        assert_eq!(record.status, DeployStatus::Cancelled);
        assert!(record.status.is_terminal());
    }

    #[test]
    fn test_deploy_record_steps() {
        let mut record = DeployRecord::new(
            "app-123".to_string(),
            "my-app".to_string(),
            "main".to_string(),
            DeployTrigger::Cli,
        );

        let step = record.start_step(PipelineStep::GitClone);
        step.finish_success();

        let step = record.start_step(PipelineStep::Build);
        step.finish_failure("npm ERR! exit code 1".to_string());

        assert_eq!(record.steps.len(), 2);
        assert!(record.steps[0].success);
        assert!(!record.steps[1].success);

        let failed = record.failed_step().unwrap();
        assert_eq!(failed.step, PipelineStep::Build);
    }

    #[test]
    fn test_deploy_record_summary() {
        let mut record = DeployRecord::new(
            "app-123".to_string(),
            "my-app".to_string(),
            "main".to_string(),
            DeployTrigger::Cli,
        );
        record.set_commit("abc123def456789".to_string(), None);
        record.finish_success();

        let summary = record.summary();
        assert!(summary.contains("my-app"));
        assert!(summary.contains("abc123d"));
        assert!(summary.contains("success"));
        assert!(summary.contains("main"));
    }

    #[test]
    fn test_deploy_record_serialization() {
        let mut record = DeployRecord::new(
            "app-123".to_string(),
            "my-app".to_string(),
            "main".to_string(),
            DeployTrigger::Cli,
        );
        record.set_commit("abc123".to_string(), Some("Initial deploy".to_string()));
        record.finish_success();

        let json = serde_json::to_string_pretty(&record).unwrap();
        let deserialized: DeployRecord = serde_json::from_str(&json).unwrap();

        assert_eq!(deserialized.id, record.id);
        assert_eq!(deserialized.app_name, "my-app");
        assert_eq!(deserialized.status, DeployStatus::Success);
        assert_eq!(deserialized.commit_hash, "abc123");
    }

    // ── DeployHistory Tests ────────────────────────────────────────────

    #[test]
    fn test_deploy_history_save_and_load() {
        let tmp = test_dir();
        let history = DeployHistory::new(tmp.path().join("deploys"), 10).unwrap();

        let mut record = DeployRecord::new(
            "app-1".to_string(),
            "my-app".to_string(),
            "main".to_string(),
            DeployTrigger::Cli,
        );
        record.set_commit("abc123".to_string(), Some("Test".to_string()));
        record.finish_success();

        history.save_record(&record).unwrap();

        let loaded = history.load_record(&record.id).unwrap();
        assert_eq!(loaded.id, record.id);
        assert_eq!(loaded.app_name, "my-app");
        assert_eq!(loaded.status, DeployStatus::Success);
    }

    #[test]
    fn test_deploy_history_list() {
        let tmp = test_dir();
        let history = DeployHistory::new(tmp.path().join("deploys"), 10).unwrap();

        // Save 3 records
        for i in 0..3 {
            let mut record = DeployRecord::new(
                "app-1".to_string(),
                "my-app".to_string(),
                "main".to_string(),
                DeployTrigger::Cli,
            );
            record.set_commit(format!("commit{}", i), None);
            record.finish_success();
            history.save_record(&record).unwrap();
        }

        let records = history.list().unwrap();
        assert_eq!(records.len(), 3);
    }

    #[test]
    fn test_deploy_history_last_successful() {
        let tmp = test_dir();
        let history = DeployHistory::new(tmp.path().join("deploys"), 10).unwrap();

        let mut r1 = DeployRecord::new(
            "app-1".to_string(),
            "my-app".to_string(),
            "main".to_string(),
            DeployTrigger::Cli,
        );
        r1.set_commit("aaa".to_string(), None);
        r1.finish_success();
        history.save_record(&r1).unwrap();

        let mut r2 = DeployRecord::new(
            "app-1".to_string(),
            "my-app".to_string(),
            "main".to_string(),
            DeployTrigger::Cli,
        );
        r2.set_commit("bbb".to_string(), None);
        r2.finish_failure("broke".to_string());
        history.save_record(&r2).unwrap();

        let last_success = history.last_successful().unwrap();
        assert!(last_success.is_some());
        assert_eq!(last_success.unwrap().commit_hash, "aaa");
    }

    #[test]
    fn test_deploy_history_not_found() {
        let tmp = test_dir();
        let history = DeployHistory::new(tmp.path().join("deploys"), 10).unwrap();

        let result = history.load_record("nonexistent");
        assert!(matches!(result, Err(HistoryError::NotFound { .. })));
    }

    #[test]
    fn test_deploy_history_prune() {
        let tmp = test_dir();
        let history = DeployHistory::new(tmp.path().join("deploys"), 2).unwrap();

        for i in 0..5 {
            let mut record = DeployRecord::new(
                "app-1".to_string(),
                "my-app".to_string(),
                "main".to_string(),
                DeployTrigger::Cli,
            );
            record.set_commit(format!("commit{}", i), None);
            record.finish_success();
            history.save_record(&record).unwrap();
        }

        assert_eq!(history.count().unwrap(), 5);

        let pruned = history.prune().unwrap();
        assert_eq!(pruned.len(), 3);
        assert_eq!(history.count().unwrap(), 2);
    }

    #[test]
    fn test_deploy_history_clear() {
        let tmp = test_dir();
        let history = DeployHistory::new(tmp.path().join("deploys"), 10).unwrap();

        for _ in 0..3 {
            let mut record = DeployRecord::new(
                "app-1".to_string(),
                "my-app".to_string(),
                "main".to_string(),
                DeployTrigger::Cli,
            );
            record.finish_success();
            history.save_record(&record).unwrap();
        }

        let cleared = history.clear().unwrap();
        assert_eq!(cleared, 3);
        assert_eq!(history.count().unwrap(), 0);
    }

    #[test]
    fn test_deploy_history_stats() {
        let tmp = test_dir();
        let history = DeployHistory::new(tmp.path().join("deploys"), 10).unwrap();

        let mut r1 = DeployRecord::new(
            "app-1".to_string(),
            "my-app".to_string(),
            "main".to_string(),
            DeployTrigger::Cli,
        );
        r1.finish_success();
        history.save_record(&r1).unwrap();

        let mut r2 = DeployRecord::new(
            "app-1".to_string(),
            "my-app".to_string(),
            "main".to_string(),
            DeployTrigger::Api,
        );
        r2.finish_failure("oops".to_string());
        history.save_record(&r2).unwrap();

        let stats = history.stats().unwrap();
        assert_eq!(stats.total_deploys, 2);
        assert_eq!(stats.successful, 1);
        assert_eq!(stats.failed, 1);
        assert_eq!(stats.success_rate, 0.5);
    }

    // ── Log Writer Tests ───────────────────────────────────────────────

    #[test]
    fn test_deploy_log_writer() {
        let tmp = test_dir();
        let history = DeployHistory::new(tmp.path().join("deploys"), 10).unwrap();

        let mut writer = history.create_log_writer("test-deploy-001").unwrap();
        writer.log("Starting deployment").unwrap();
        writer.log_step_start(&PipelineStep::Build).unwrap();
        writer.log("Running npm run build").unwrap();
        writer.log_step_end(&PipelineStep::Build, true).unwrap();
        writer.separator().unwrap();
        writer.log("Deployment complete").unwrap();

        let path = writer.finalize().unwrap();
        assert!(path.exists());

        let content = history.read_log("test-deploy-001").unwrap();
        assert!(content.contains("Starting deployment"));
        assert!(content.contains("Step: build"));
        assert!(content.contains("Deployment complete"));
    }

    #[test]
    fn test_deploy_log_tail() {
        let tmp = test_dir();
        let history = DeployHistory::new(tmp.path().join("deploys"), 10).unwrap();

        let mut writer = history.create_log_writer("test-tail").unwrap();
        for i in 0..10 {
            writer.log(&format!("Line {}", i)).unwrap();
        }
        writer.finalize().unwrap();

        let tail = history.tail_log("test-tail", 3).unwrap();
        assert_eq!(tail.len(), 3);
        assert!(tail[2].contains("Line 9"));
    }

    #[test]
    fn test_deploy_log_not_found() {
        let tmp = test_dir();
        let history = DeployHistory::new(tmp.path().join("deploys"), 10).unwrap();

        let result = history.read_log("nonexistent");
        assert!(matches!(result, Err(HistoryError::LogNotFound { .. })));
    }

    // ── ID Generation Tests ────────────────────────────────────────────

    #[test]
    fn test_generate_deploy_id_format() {
        let now = Utc::now();
        let id = generate_deploy_id(&now);

        // Format: YYYYMMDD-HHMMSS-XXXXXXX
        let parts: Vec<&str> = id.split('-').collect();
        assert_eq!(parts.len(), 3);
        assert_eq!(parts[0].len(), 8); // YYYYMMDD
        assert_eq!(parts[1].len(), 6); // HHMMSS
        assert_eq!(parts[2].len(), 7); // 7 hex chars
    }

    #[test]
    fn test_release_dir_name() {
        let now = Utc::now();
        let name = release_dir_name(&now, "abc123def456789");

        assert!(name.ends_with("-abc123d"));
    }

    #[test]
    fn test_release_dir_name_short_hash() {
        let now = Utc::now();
        let name = release_dir_name(&now, "abc");

        assert!(name.ends_with("-abc"));
    }

    // ── Pipeline Step Display ──────────────────────────────────────────

    #[test]
    fn test_pipeline_step_display() {
        assert_eq!(format!("{}", PipelineStep::PreDeploy), "pre_deploy");
        assert_eq!(format!("{}", PipelineStep::GitClone), "git_clone");
        assert_eq!(format!("{}", PipelineStep::Build), "build");
        assert_eq!(format!("{}", PipelineStep::HealthCheck), "health_check");
        assert_eq!(format!("{}", PipelineStep::Activate), "activate");
    }

    // ── Deploy Trigger Display ─────────────────────────────────────────

    #[test]
    fn test_deploy_trigger_display() {
        assert_eq!(format!("{}", DeployTrigger::Cli), "cli");
        assert_eq!(format!("{}", DeployTrigger::Api), "api");
        assert_eq!(format!("{}", DeployTrigger::Webhook), "webhook");
        assert_eq!(format!("{}", DeployTrigger::Rollback), "rollback");
    }
}
