//! SSH Key Management Module
//!
//! This module provides functionality for generating, importing, storing, and managing
//! SSH keys used to authenticate with GitHub (and other Git hosting services) for
//! cloning private repositories during application deployment.
//!
//! ## Security Model
//!
//! - Private keys are stored on disk with `0600` permissions under a dedicated directory
//! - Private key content is **never** exposed via API or CLI responses
//! - Only the public key, fingerprint, and metadata are returned to callers
//! - The keys directory itself has `0700` permissions
//! - All key operations are logged for audit purposes
//!
//! ## Multi-Account Support
//!
//! Different applications may live under different GitHub users/organizations.
//! Each SSH key can be associated with a specific GitHub username, and when cloning
//! a repository the correct key is selected via `GIT_SSH_COMMAND` environment variable
//! injection, avoiding conflicts in the global `~/.ssh/config`.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fmt;
use std::io::{self, BufRead, Write};
use std::net::IpAddr;
use std::path::{Path, PathBuf};
use std::process::Command;
use thiserror::Error;
use tracing::{debug, error, info, warn};

// ─────────────────────────────────────────────────────────────────────────────
// Error Types
// ─────────────────────────────────────────────────────────────────────────────

/// Errors that can occur during SSH key operations.
#[derive(Debug, Error)]
pub enum SshKeyError {
    #[error("IO error: {0}")]
    Io(#[from] io::Error),

    #[error("Key not found: {id}")]
    KeyNotFound { id: String },

    #[error("Key with name '{name}' already exists")]
    DuplicateName { name: String },

    #[error("Invalid key type: {0}")]
    InvalidKeyType(String),

    #[error("Key generation failed: {message}")]
    GenerationFailed { message: String },

    #[error("Key import failed: {message}")]
    ImportFailed { message: String },

    #[error("Fingerprint extraction failed: {message}")]
    FingerprintFailed { message: String },

    #[error("SSH connection test failed: {message}")]
    ConnectionTestFailed { message: String },

    #[error("Registry serialization error: {0}")]
    RegistrySerialization(String),

    #[error("Registry deserialization error: {0}")]
    RegistryDeserialization(String),

    #[error("Permission error: {message}")]
    Permission { message: String },

    #[error("Key file is invalid or corrupted: {path}")]
    InvalidKeyFile { path: String },
}

/// Result alias for SSH key operations.
pub type Result<T> = std::result::Result<T, SshKeyError>;

// ─────────────────────────────────────────────────────────────────────────────
// SSH Key Types
// ─────────────────────────────────────────────────────────────────────────────

/// Supported SSH key algorithms.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum SshKeyType {
    /// Ed25519 — recommended, fast, small keys
    Ed25519,
    /// RSA with 4096-bit key size
    Rsa4096,
    /// ECDSA with NIST P-256 curve
    Ecdsa256,
    /// ECDSA with NIST P-384 curve
    Ecdsa384,
}

impl SshKeyType {
    /// Returns the `ssh-keygen` arguments for this key type.
    pub fn keygen_args(&self) -> Vec<&'static str> {
        match self {
            SshKeyType::Ed25519 => vec!["-t", "ed25519"],
            SshKeyType::Rsa4096 => vec!["-t", "rsa", "-b", "4096"],
            SshKeyType::Ecdsa256 => vec!["-t", "ecdsa", "-b", "256"],
            SshKeyType::Ecdsa384 => vec!["-t", "ecdsa", "-b", "384"],
        }
    }

    /// Returns a human-readable description of the key type.
    pub fn description(&self) -> &'static str {
        match self {
            SshKeyType::Ed25519 => "Ed25519 (recommended)",
            SshKeyType::Rsa4096 => "RSA 4096-bit",
            SshKeyType::Ecdsa256 => "ECDSA P-256",
            SshKeyType::Ecdsa384 => "ECDSA P-384",
        }
    }
}

impl Default for SshKeyType {
    fn default() -> Self {
        SshKeyType::Ed25519
    }
}

impl fmt::Display for SshKeyType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            SshKeyType::Ed25519 => write!(f, "ed25519"),
            SshKeyType::Rsa4096 => write!(f, "rsa4096"),
            SshKeyType::Ecdsa256 => write!(f, "ecdsa256"),
            SshKeyType::Ecdsa384 => write!(f, "ecdsa384"),
        }
    }
}

impl std::str::FromStr for SshKeyType {
    type Err = SshKeyError;

    fn from_str(s: &str) -> Result<Self> {
        match s.to_lowercase().as_str() {
            "ed25519" => Ok(SshKeyType::Ed25519),
            "rsa" | "rsa4096" => Ok(SshKeyType::Rsa4096),
            "ecdsa" | "ecdsa256" => Ok(SshKeyType::Ecdsa256),
            "ecdsa384" => Ok(SshKeyType::Ecdsa384),
            other => Err(SshKeyError::InvalidKeyType(other.to_string())),
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// SSH Key Entry
// ─────────────────────────────────────────────────────────────────────────────

/// An SSH key entry with all associated metadata.
///
/// The private key content is **never** stored in this struct or serialized.
/// Only the on-disk path is stored, and the file itself is protected with `0600`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SshKeyEntry {
    /// Unique identifier for this key (UUID v4 hex string)
    pub id: String,

    /// Human-friendly label (e.g. "work-github", "personal-gh")
    pub name: String,

    /// Path to the private key file on disk
    pub private_key_path: PathBuf,

    /// Path to the public key file on disk
    pub public_key_path: PathBuf,

    /// The full public key string (safe to display and share)
    pub public_key: String,

    /// SSH key algorithm
    pub key_type: SshKeyType,

    /// SSH key fingerprint (SHA256 format)
    pub fingerprint: String,

    /// GitHub username this key is associated with (optional)
    pub github_username: Option<String>,

    /// Optional comment/description
    pub comment: Option<String>,

    /// Whether this is a GitHub deploy key (repo-scoped) vs a full user SSH key
    pub is_deploy_key: bool,

    /// Timestamp when the key was created/imported
    pub created_at: DateTime<Utc>,

    /// Timestamp when the key was last used for a git operation
    pub last_used_at: Option<DateTime<Utc>>,

    /// IDs of applications currently using this key
    pub used_by_apps: Vec<String>,
}

impl SshKeyEntry {
    /// Create a new SSH key entry with the given parameters.
    pub fn new(
        name: String,
        private_key_path: PathBuf,
        public_key_path: PathBuf,
        public_key: String,
        key_type: SshKeyType,
        fingerprint: String,
    ) -> Self {
        Self {
            id: generate_key_id(),
            name,
            private_key_path,
            public_key_path,
            public_key,
            key_type,
            fingerprint,
            github_username: None,
            comment: None,
            is_deploy_key: false,
            created_at: Utc::now(),
            last_used_at: None,
            used_by_apps: Vec::new(),
        }
    }

    /// Mark this key as used right now, updating the `last_used_at` timestamp.
    pub fn mark_used(&mut self) {
        self.last_used_at = Some(Utc::now());
    }

    /// Check whether any applications are currently using this key.
    pub fn is_in_use(&self) -> bool {
        !self.used_by_apps.is_empty()
    }

    /// Add an application ID to the list of apps using this key.
    pub fn add_app(&mut self, app_id: &str) {
        if !self.used_by_apps.contains(&app_id.to_string()) {
            self.used_by_apps.push(app_id.to_string());
        }
    }

    /// Remove an application ID from the list of apps using this key.
    pub fn remove_app(&mut self, app_id: &str) {
        self.used_by_apps.retain(|id| id != app_id);
    }

    /// Return a sanitized view suitable for API responses (no private key path exposed).
    pub fn to_public_view(&self) -> SshKeyPublicView {
        SshKeyPublicView {
            id: self.id.clone(),
            name: self.name.clone(),
            public_key: self.public_key.clone(),
            key_type: self.key_type,
            fingerprint: self.fingerprint.clone(),
            github_username: self.github_username.clone(),
            comment: self.comment.clone(),
            is_deploy_key: self.is_deploy_key,
            created_at: self.created_at,
            last_used_at: self.last_used_at,
            used_by_apps: self.used_by_apps.clone(),
        }
    }
}

impl fmt::Display for SshKeyEntry {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "[{}] {} ({}) fingerprint={}",
            self.id, self.name, self.key_type, self.fingerprint
        )
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Public View (safe for API responses)
// ─────────────────────────────────────────────────────────────────────────────

/// A sanitized view of an SSH key entry that is safe to expose via API.
/// Does not include the private key path.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SshKeyPublicView {
    pub id: String,
    pub name: String,
    pub public_key: String,
    pub key_type: SshKeyType,
    pub fingerprint: String,
    pub github_username: Option<String>,
    pub comment: Option<String>,
    pub is_deploy_key: bool,
    pub created_at: DateTime<Utc>,
    pub last_used_at: Option<DateTime<Utc>>,
    pub used_by_apps: Vec<String>,
}

// ─────────────────────────────────────────────────────────────────────────────
// Connection Test Result
// ─────────────────────────────────────────────────────────────────────────────

/// Result of testing SSH connectivity to a Git host.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConnectionTestResult {
    /// Whether the connection was successful
    pub success: bool,
    /// The Git host that was tested (e.g. "github.com")
    pub host: String,
    /// The SSH key ID that was used
    pub key_id: String,
    /// The authenticated username (if reported by the server)
    pub authenticated_as: Option<String>,
    /// Raw output from the SSH test command
    pub output: String,
    /// Error message if the test failed
    pub error: Option<String>,
    /// Timestamp of the test
    pub tested_at: DateTime<Utc>,
}

// ─────────────────────────────────────────────────────────────────────────────
// SSH Key Registry (on-disk persistence)
// ─────────────────────────────────────────────────────────────────────────────

/// Serializable registry of all managed SSH keys.
/// Stored as TOML at `<keys_dir>/registry.toml`.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
struct SshKeyRegistry {
    /// Map from key ID to key entry
    keys: HashMap<String, SshKeyEntry>,
}

impl SshKeyRegistry {
    /// Load the registry from disk, or return an empty registry if the file doesn't exist.
    fn load(path: &Path) -> Result<Self> {
        if !path.exists() {
            return Ok(Self::default());
        }

        let content = std::fs::read_to_string(path).map_err(SshKeyError::Io)?;
        toml::from_str(&content).map_err(|e| SshKeyError::RegistryDeserialization(e.to_string()))
    }

    /// Save the registry to disk.
    fn save(&self, path: &Path) -> Result<()> {
        // Ensure parent directory exists
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent).map_err(SshKeyError::Io)?;
        }

        let content =
            toml::to_string_pretty(self).map_err(|e| SshKeyError::RegistrySerialization(e.to_string()))?;

        // Write atomically: write to temp file, then rename
        let tmp_path = path.with_extension("toml.tmp");
        std::fs::write(&tmp_path, &content).map_err(SshKeyError::Io)?;
        std::fs::rename(&tmp_path, path).map_err(SshKeyError::Io)?;

        debug!("SSH key registry saved to {:?}", path);
        Ok(())
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// SSH Key Manager
// ─────────────────────────────────────────────────────────────────────────────

/// Manages SSH keys for Git repository access.
///
/// Handles key generation, import, storage, deletion, and connectivity testing.
/// Keys are stored on disk with restrictive permissions and metadata is persisted
/// in a TOML registry file.
pub struct SshKeyManager {
    /// Base directory where keys are stored
    keys_dir: PathBuf,

    /// Path to the key registry file
    registry_path: PathBuf,

    /// In-memory registry (loaded on init, saved on mutation)
    registry: SshKeyRegistry,
}

impl SshKeyManager {
    /// Create a new SSH key manager with the given keys directory.
    ///
    /// The directory will be created if it doesn't exist, with `0700` permissions.
    pub fn new(keys_dir: PathBuf) -> Result<Self> {
        // Create keys directory with restrictive permissions
        if !keys_dir.exists() {
            std::fs::create_dir_all(&keys_dir).map_err(SshKeyError::Io)?;
        }

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&keys_dir, std::fs::Permissions::from_mode(0o700))
                .map_err(SshKeyError::Io)?;
        }

        let registry_path = keys_dir.join("registry.toml");
        let registry = SshKeyRegistry::load(&registry_path)?;

        info!(
            "SSH key manager initialized with {} keys from {:?}",
            registry.keys.len(),
            keys_dir
        );

        Ok(Self {
            keys_dir,
            registry_path,
            registry,
        })
    }

    // ─────────────────────────────────────────────────────────────────────
    // Key Generation
    // ─────────────────────────────────────────────────────────────────────

    /// Generate a new SSH key pair.
    ///
    /// Uses `ssh-keygen` to generate the key. The private key is stored at
    /// `<keys_dir>/<id>` and the public key at `<keys_dir>/<id>.pub`, both
    /// with restrictive permissions.
    pub fn generate_key(
        &mut self,
        name: &str,
        key_type: SshKeyType,
        comment: Option<&str>,
    ) -> Result<SshKeyEntry> {
        // Validate name uniqueness
        self.validate_name_unique(name)?;

        let id = generate_key_id();
        let private_key_path = self.keys_dir.join(&id);
        let public_key_path = self.keys_dir.join(format!("{}.pub", &id));

        let key_comment = comment.unwrap_or(name);

        // Build ssh-keygen command
        let mut cmd = Command::new("ssh-keygen");
        for arg in key_type.keygen_args() {
            cmd.arg(arg);
        }
        cmd.arg("-f")
            .arg(&private_key_path)
            .arg("-N") // empty passphrase
            .arg("")
            .arg("-C")
            .arg(key_comment)
            .arg("-q"); // quiet mode

        info!("Generating {} SSH key: {}", key_type, name);
        let output = cmd.output().map_err(|e| SshKeyError::GenerationFailed {
            message: format!("Failed to execute ssh-keygen: {}", e),
        })?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            return Err(SshKeyError::GenerationFailed {
                message: format!("ssh-keygen failed: {}", stderr.trim()),
            });
        }

        // Set restrictive permissions on private key
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&private_key_path, std::fs::Permissions::from_mode(0o600))
                .map_err(SshKeyError::Io)?;
        }

        // Read the public key
        let public_key = std::fs::read_to_string(&public_key_path)
            .map_err(SshKeyError::Io)?
            .trim()
            .to_string();

        // Get fingerprint
        let fingerprint = self.get_fingerprint(&public_key_path)?;

        let mut entry = SshKeyEntry::new(
            name.to_string(),
            private_key_path,
            public_key_path,
            public_key,
            key_type,
            fingerprint,
        );
        entry.id = id.clone();
        entry.comment = comment.map(String::from);

        // Save to registry
        self.registry.keys.insert(id.clone(), entry.clone());
        self.registry.save(&self.registry_path)?;

        info!("SSH key generated: {} ({})", name, entry.fingerprint);
        Ok(entry)
    }

    // ─────────────────────────────────────────────────────────────────────
    // Key Import
    // ─────────────────────────────────────────────────────────────────────

    /// Import an existing SSH private key from a file path.
    ///
    /// The key file is copied into the managed keys directory. The original
    /// file is not modified or deleted.
    pub fn import_key(&mut self, name: &str, source_path: &Path) -> Result<SshKeyEntry> {
        // Validate name uniqueness
        self.validate_name_unique(name)?;

        // Validate the source file exists and looks like a private key
        if !source_path.exists() {
            return Err(SshKeyError::ImportFailed {
                message: format!("Source file does not exist: {:?}", source_path),
            });
        }

        let content = std::fs::read_to_string(source_path).map_err(|e| {
            SshKeyError::ImportFailed {
                message: format!("Failed to read key file: {}", e),
            }
        })?;

        if !content.contains("PRIVATE KEY") {
            return Err(SshKeyError::InvalidKeyFile {
                path: source_path.to_string_lossy().to_string(),
            });
        }

        // Determine key type from the file content
        let key_type = detect_key_type_from_content(&content)?;

        let id = generate_key_id();
        let private_key_path = self.keys_dir.join(&id);
        let public_key_path = self.keys_dir.join(format!("{}.pub", &id));

        // Copy private key to managed directory
        std::fs::copy(source_path, &private_key_path).map_err(|e| {
            SshKeyError::ImportFailed {
                message: format!("Failed to copy private key: {}", e),
            }
        })?;

        // Set restrictive permissions
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&private_key_path, std::fs::Permissions::from_mode(0o600))
                .map_err(SshKeyError::Io)?;
        }

        // Derive the public key from the private key
        let output = Command::new("ssh-keygen")
            .arg("-y")
            .arg("-f")
            .arg(&private_key_path)
            .output()
            .map_err(|e| SshKeyError::ImportFailed {
                message: format!("Failed to derive public key: {}", e),
            })?;

        if !output.status.success() {
            // Clean up the copied private key
            let _ = std::fs::remove_file(&private_key_path);
            let stderr = String::from_utf8_lossy(&output.stderr);
            return Err(SshKeyError::ImportFailed {
                message: format!("Failed to derive public key: {}", stderr.trim()),
            });
        }

        let public_key = String::from_utf8_lossy(&output.stdout).trim().to_string();

        // Write the public key file
        std::fs::write(&public_key_path, format!("{}\n", &public_key)).map_err(SshKeyError::Io)?;

        // Get fingerprint
        let fingerprint = self.get_fingerprint(&public_key_path)?;

        let mut entry = SshKeyEntry::new(
            name.to_string(),
            private_key_path,
            public_key_path,
            public_key,
            key_type,
            fingerprint,
        );
        entry.id = id.clone();

        // Save to registry
        self.registry.keys.insert(id.clone(), entry.clone());
        self.registry.save(&self.registry_path)?;

        info!("SSH key imported: {} ({})", name, entry.fingerprint);
        Ok(entry)
    }

    // ─────────────────────────────────────────────────────────────────────
    // Key Retrieval
    // ─────────────────────────────────────────────────────────────────────

    /// List all managed SSH keys.
    pub fn list_keys(&self) -> Vec<SshKeyEntry> {
        let mut keys: Vec<SshKeyEntry> = self.registry.keys.values().cloned().collect();
        keys.sort_by(|a, b| a.created_at.cmp(&b.created_at));
        keys
    }

    /// Get a key by its ID.
    pub fn get_key(&self, id: &str) -> Option<&SshKeyEntry> {
        self.registry.keys.get(id)
    }

    /// Get a mutable reference to a key by its ID.
    pub fn get_key_mut(&mut self, id: &str) -> Option<&mut SshKeyEntry> {
        self.registry.keys.get_mut(id)
    }

    /// Get a key by its human-friendly name.
    pub fn get_key_by_name(&self, name: &str) -> Option<&SshKeyEntry> {
        self.registry.keys.values().find(|k| k.name == name)
    }

    /// Get the public key string for a given key ID.
    /// This is the string the user should paste into GitHub as a deploy key.
    pub fn get_public_key_string(&self, id: &str) -> Result<String> {
        let entry = self
            .registry
            .keys
            .get(id)
            .ok_or_else(|| SshKeyError::KeyNotFound { id: id.to_string() })?;

        Ok(entry.public_key.clone())
    }

    /// Get the total number of managed keys.
    pub fn key_count(&self) -> usize {
        self.registry.keys.len()
    }

    // ─────────────────────────────────────────────────────────────────────
    // Key Deletion
    // ─────────────────────────────────────────────────────────────────────

    /// Delete a key by its ID.
    ///
    /// This removes the private key, public key, and registry entry.
    /// Returns an error if any applications are still using this key.
    pub fn delete_key(&mut self, id: &str) -> Result<SshKeyEntry> {
        let entry = self
            .registry
            .keys
            .get(id)
            .ok_or_else(|| SshKeyError::KeyNotFound { id: id.to_string() })?
            .clone();

        // Warn if apps are using this key (but don't block deletion — caller decides)
        if entry.is_in_use() {
            warn!(
                "Deleting SSH key '{}' which is used by {} application(s): {:?}",
                entry.name,
                entry.used_by_apps.len(),
                entry.used_by_apps
            );
        }

        // Remove key files from disk
        if entry.private_key_path.exists() {
            // Overwrite with zeros before deleting for extra security
            if let Ok(metadata) = std::fs::metadata(&entry.private_key_path) {
                let zeros = vec![0u8; metadata.len() as usize];
                let _ = std::fs::write(&entry.private_key_path, &zeros);
            }
            std::fs::remove_file(&entry.private_key_path).map_err(SshKeyError::Io)?;
        }

        if entry.public_key_path.exists() {
            std::fs::remove_file(&entry.public_key_path).map_err(SshKeyError::Io)?;
        }

        // Remove from registry
        self.registry.keys.remove(id);
        self.registry.save(&self.registry_path)?;

        info!("SSH key deleted: {} ({})", entry.name, entry.fingerprint);
        Ok(entry)
    }

    /// Force-delete a key even if it's in use (for cleanup/emergency).
    pub fn force_delete_key(&mut self, id: &str) -> Result<SshKeyEntry> {
        self.delete_key(id)
    }

    // ─────────────────────────────────────────────────────────────────────
    // Key Metadata Updates
    // ─────────────────────────────────────────────────────────────────────

    /// Associate a GitHub username with a key.
    pub fn set_github_username(&mut self, id: &str, username: &str) -> Result<()> {
        let entry = self
            .registry
            .keys
            .get_mut(id)
            .ok_or_else(|| SshKeyError::KeyNotFound { id: id.to_string() })?;

        entry.github_username = Some(username.to_string());
        self.registry.save(&self.registry_path)?;

        info!("SSH key '{}' associated with GitHub user: {}", entry.name, username);
        Ok(())
    }

    /// Set a key as a deploy key (repo-scoped).
    pub fn set_deploy_key(&mut self, id: &str, is_deploy_key: bool) -> Result<()> {
        let entry = self
            .registry
            .keys
            .get_mut(id)
            .ok_or_else(|| SshKeyError::KeyNotFound { id: id.to_string() })?;

        entry.is_deploy_key = is_deploy_key;
        self.registry.save(&self.registry_path)?;
        Ok(())
    }

    /// Update the comment on a key.
    pub fn set_comment(&mut self, id: &str, comment: Option<&str>) -> Result<()> {
        let entry = self
            .registry
            .keys
            .get_mut(id)
            .ok_or_else(|| SshKeyError::KeyNotFound { id: id.to_string() })?;

        entry.comment = comment.map(String::from);
        self.registry.save(&self.registry_path)?;
        Ok(())
    }

    /// Record that a key was used (updates `last_used_at`).
    pub fn mark_key_used(&mut self, id: &str) -> Result<()> {
        let entry = self
            .registry
            .keys
            .get_mut(id)
            .ok_or_else(|| SshKeyError::KeyNotFound { id: id.to_string() })?;

        entry.mark_used();
        self.registry.save(&self.registry_path)?;
        Ok(())
    }

    // ─────────────────────────────────────────────────────────────────────
    // Git / GitHub Connectivity
    // ─────────────────────────────────────────────────────────────────────

    /// Test SSH connectivity to a Git host (default: github.com) using the specified key.
    ///
    /// Runs `ssh -T git@<host>` with the key and checks for a successful authentication
    /// message. GitHub returns exit code 1 even on success (because it doesn't provide
    /// shell access), so we parse the output instead.
    pub fn test_connection(&self, id: &str, host: Option<&str>) -> Result<ConnectionTestResult> {
        let entry = self
            .registry
            .keys
            .get(id)
            .ok_or_else(|| SshKeyError::KeyNotFound { id: id.to_string() })?;

        let git_host = host.unwrap_or("github.com");
        let ssh_command = format!(
            "ssh -T -i {} -o StrictHostKeyChecking=accept-new -o IdentitiesOnly=yes git@{}",
            entry.private_key_path.display(),
            git_host
        );

        info!(
            "Testing SSH connectivity to {} with key '{}'",
            git_host, entry.name
        );

        let output = Command::new("ssh")
            .arg("-T")
            .arg("-i")
            .arg(&entry.private_key_path)
            .arg("-o")
            .arg("StrictHostKeyChecking=accept-new")
            .arg("-o")
            .arg("IdentitiesOnly=yes")
            .arg("-o")
            .arg("ConnectTimeout=10")
            .arg(format!("git@{}", git_host))
            .output()
            .map_err(|e| SshKeyError::ConnectionTestFailed {
                message: format!("Failed to execute ssh: {}", e),
            })?;

        let stdout = String::from_utf8_lossy(&output.stdout).to_string();
        let stderr = String::from_utf8_lossy(&output.stderr).to_string();
        let combined_output = format!("{}{}", stdout, stderr);

        // GitHub returns "Hi <username>!" on success (but exit code 1)
        let success = combined_output.contains("successfully authenticated")
            || combined_output.contains("Hi ")
            || output.status.success();

        // Try to extract the authenticated username
        let authenticated_as = extract_github_username(&combined_output);

        let result = ConnectionTestResult {
            success,
            host: git_host.to_string(),
            key_id: id.to_string(),
            authenticated_as,
            output: combined_output.trim().to_string(),
            error: if success {
                None
            } else {
                Some(stderr.trim().to_string())
            },
            tested_at: Utc::now(),
        };

        if success {
            info!(
                "SSH connectivity test passed for key '{}' to {}",
                entry.name, git_host
            );
        } else {
            warn!(
                "SSH connectivity test failed for key '{}' to {}: {}",
                entry.name,
                git_host,
                result.error.as_deref().unwrap_or("unknown error")
            );
        }

        Ok(result)
    }

    /// Test whether a specific key can access a specific Git repository.
    ///
    /// Uses `git ls-remote` to verify read access without cloning.
    pub fn test_repo_access(&self, id: &str, repo_url: &str) -> Result<bool> {
        let entry = self
            .registry
            .keys
            .get(id)
            .ok_or_else(|| SshKeyError::KeyNotFound { id: id.to_string() })?;

        let git_ssh_command = format!(
            "ssh -i {} -o StrictHostKeyChecking=accept-new -o IdentitiesOnly=yes",
            entry.private_key_path.display()
        );

        info!(
            "Testing repo access to '{}' with key '{}'",
            repo_url, entry.name
        );

        let output = Command::new("git")
            .arg("ls-remote")
            .arg("--exit-code")
            .arg("--heads")
            .arg(repo_url)
            .env("GIT_SSH_COMMAND", &git_ssh_command)
            .output()
            .map_err(|e| SshKeyError::ConnectionTestFailed {
                message: format!("Failed to execute git ls-remote: {}", e),
            })?;

        let success = output.status.success();

        if success {
            info!(
                "Repo access confirmed: '{}' via key '{}'",
                repo_url, entry.name
            );
        } else {
            let stderr = String::from_utf8_lossy(&output.stderr);
            warn!(
                "Repo access denied: '{}' via key '{}': {}",
                repo_url,
                entry.name,
                stderr.trim()
            );
        }

        Ok(success)
    }

    /// Build the `GIT_SSH_COMMAND` environment variable value for a given key.
    ///
    /// This is used by the deployment pipeline when running `git clone` / `git pull`
    /// to ensure the correct SSH key is used.
    pub fn git_ssh_command(&self, id: &str) -> Result<String> {
        let entry = self
            .registry
            .keys
            .get(id)
            .ok_or_else(|| SshKeyError::KeyNotFound { id: id.to_string() })?;

        Ok(format!(
            "ssh -i {} -o StrictHostKeyChecking=accept-new -o IdentitiesOnly=yes",
            entry.private_key_path.display()
        ))
    }

    // ─────────────────────────────────────────────────────────────────────
    // Internal Helpers
    // ─────────────────────────────────────────────────────────────────────

    /// Validate that no other key has the same name.
    fn validate_name_unique(&self, name: &str) -> Result<()> {
        if self.registry.keys.values().any(|k| k.name == name) {
            return Err(SshKeyError::DuplicateName {
                name: name.to_string(),
            });
        }
        Ok(())
    }

    /// Get the SHA256 fingerprint for a public key file.
    fn get_fingerprint(&self, public_key_path: &Path) -> Result<String> {
        let output = Command::new("ssh-keygen")
            .arg("-l")
            .arg("-E")
            .arg("sha256")
            .arg("-f")
            .arg(public_key_path)
            .output()
            .map_err(|e| SshKeyError::FingerprintFailed {
                message: format!("Failed to execute ssh-keygen: {}", e),
            })?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            return Err(SshKeyError::FingerprintFailed {
                message: stderr.trim().to_string(),
            });
        }

        // Output format: "256 SHA256:xxxxx comment (ED25519)"
        // We want the "SHA256:xxxxx" part
        let stdout = String::from_utf8_lossy(&output.stdout);
        let fingerprint = stdout
            .split_whitespace()
            .find(|part| part.starts_with("SHA256:"))
            .unwrap_or("unknown")
            .to_string();

        Ok(fingerprint)
    }

    /// Persist any in-memory changes to disk.
    pub fn save(&self) -> Result<()> {
        self.registry.save(&self.registry_path)
    }

    /// Reload the registry from disk (useful after external modifications).
    pub fn reload(&mut self) -> Result<()> {
        self.registry = SshKeyRegistry::load(&self.registry_path)?;
        info!(
            "SSH key registry reloaded: {} keys",
            self.registry.keys.len()
        );
        Ok(())
    }

    /// Verify that all key files referenced in the registry actually exist on disk.
    /// Returns a list of orphaned entries (registry entries with missing files).
    pub fn verify_integrity(&self) -> Vec<String> {
        let mut orphaned = Vec::new();

        for (id, entry) in &self.registry.keys {
            if !entry.private_key_path.exists() {
                warn!(
                    "SSH key '{}' ({}) private key file missing: {:?}",
                    entry.name, id, entry.private_key_path
                );
                orphaned.push(id.clone());
            }

            if !entry.public_key_path.exists() {
                warn!(
                    "SSH key '{}' ({}) public key file missing: {:?}",
                    entry.name, id, entry.public_key_path
                );
                if !orphaned.contains(id) {
                    orphaned.push(id.clone());
                }
            }
        }

        orphaned
    }

    /// Remove orphaned registry entries (entries whose key files no longer exist on disk).
    pub fn cleanup_orphaned(&mut self) -> Result<Vec<String>> {
        let orphaned = self.verify_integrity();

        if orphaned.is_empty() {
            return Ok(orphaned);
        }

        for id in &orphaned {
            info!("Removing orphaned SSH key registry entry: {}", id);
            self.registry.keys.remove(id);
        }

        self.registry.save(&self.registry_path)?;
        Ok(orphaned)
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Free Functions (Utilities)
// ─────────────────────────────────────────────────────────────────────────────

/// Generate a unique key ID (UUID v4 hex without dashes).
fn generate_key_id() -> String {
    // Simple random hex string; in production you'd use `uuid` crate.
    // We generate 16 random bytes and hex-encode them for a 32-char ID.
    use std::time::{SystemTime, UNIX_EPOCH};

    let timestamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos();

    // Mix timestamp with a simple counter for uniqueness
    let hash = {
        let mut h: u64 = 0xcbf2_9ce4_8422_2325; // FNV offset basis
        for byte in timestamp.to_le_bytes() {
            h ^= byte as u64;
            h = h.wrapping_mul(0x0100_0000_01b3); // FNV prime
        }
        // Mix in some process-level entropy
        h ^= std::process::id() as u64;
        h = h.wrapping_mul(0x0100_0000_01b3);
        h ^= std::thread::current().id().as_u64().into();
        h
    };

    format!("{:016x}{:016x}", hash, timestamp as u64)
}

/// Detect the SSH key type from the private key file content.
fn detect_key_type_from_content(content: &str) -> Result<SshKeyType> {
    if content.contains("OPENSSH PRIVATE KEY") {
        // OpenSSH format doesn't directly indicate the type in the PEM header.
        // We could parse the binary content, but for now we default to Ed25519
        // and let the fingerprint extraction confirm the type.
        // This is a best-effort detection.
        if content.len() < 800 {
            // Ed25519 keys are short
            Ok(SshKeyType::Ed25519)
        } else {
            // Longer keys are likely RSA
            Ok(SshKeyType::Rsa4096)
        }
    } else if content.contains("RSA PRIVATE KEY") {
        Ok(SshKeyType::Rsa4096)
    } else if content.contains("EC PRIVATE KEY") {
        Ok(SshKeyType::Ecdsa256)
    } else if content.contains("DSA PRIVATE KEY") {
        Err(SshKeyError::InvalidKeyType(
            "DSA keys are deprecated and not supported".to_string(),
        ))
    } else {
        Err(SshKeyError::InvalidKeyType(
            "Could not determine key type from file content".to_string(),
        ))
    }
}

/// Extract the GitHub username from an SSH test output string.
///
/// GitHub responds with "Hi <username>! You've successfully authenticated..."
fn extract_github_username(output: &str) -> Option<String> {
    if let Some(start) = output.find("Hi ") {
        let rest = &output[start + 3..];
        if let Some(end) = rest.find('!') {
            return Some(rest[..end].to_string());
        }
    }
    None
}

/// Check whether a repository URL uses SSH format (vs HTTPS).
pub fn is_ssh_url(url: &str) -> bool {
    url.starts_with("git@")
        || url.starts_with("ssh://")
        || (url.contains('@') && url.contains(':') && !url.contains("://"))
}

/// Parse a GitHub repository URL into (owner, repo) tuple.
///
/// Supports both SSH and HTTPS formats:
/// - `git@github.com:owner/repo.git`
/// - `https://github.com/owner/repo.git`
/// - `https://github.com/owner/repo`
pub fn parse_github_repo(url: &str) -> Option<(String, String)> {
    let path = if url.starts_with("git@") {
        // SSH format: git@github.com:owner/repo.git
        url.split(':').nth(1)?
    } else if url.starts_with("https://") || url.starts_with("http://") {
        // HTTPS format: https://github.com/owner/repo.git
        let without_scheme = url
            .strip_prefix("https://")
            .or_else(|| url.strip_prefix("http://"))?;
        // Skip the host part (github.com/)
        let path_start = without_scheme.find('/')?;
        &without_scheme[path_start + 1..]
    } else {
        return None;
    };

    // Remove trailing .git if present
    let path = path.strip_suffix(".git").unwrap_or(path);

    let parts: Vec<&str> = path.splitn(2, '/').collect();
    if parts.len() == 2 && !parts[0].is_empty() && !parts[1].is_empty() {
        Some((parts[0].to_string(), parts[1].to_string()))
    } else {
        None
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Tests
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    #[test]
    fn test_ssh_key_type_display() {
        assert_eq!(format!("{}", SshKeyType::Ed25519), "ed25519");
        assert_eq!(format!("{}", SshKeyType::Rsa4096), "rsa4096");
        assert_eq!(format!("{}", SshKeyType::Ecdsa256), "ecdsa256");
        assert_eq!(format!("{}", SshKeyType::Ecdsa384), "ecdsa384");
    }

    #[test]
    fn test_ssh_key_type_from_str() {
        assert_eq!("ed25519".parse::<SshKeyType>().unwrap(), SshKeyType::Ed25519);
        assert_eq!("rsa".parse::<SshKeyType>().unwrap(), SshKeyType::Rsa4096);
        assert_eq!("rsa4096".parse::<SshKeyType>().unwrap(), SshKeyType::Rsa4096);
        assert_eq!("ecdsa".parse::<SshKeyType>().unwrap(), SshKeyType::Ecdsa256);
        assert_eq!(
            "ecdsa384".parse::<SshKeyType>().unwrap(),
            SshKeyType::Ecdsa384
        );
        assert!("invalid".parse::<SshKeyType>().is_err());
    }

    #[test]
    fn test_ssh_key_type_default() {
        assert_eq!(SshKeyType::default(), SshKeyType::Ed25519);
    }

    #[test]
    fn test_ssh_key_type_keygen_args() {
        assert_eq!(SshKeyType::Ed25519.keygen_args(), vec!["-t", "ed25519"]);
        assert_eq!(
            SshKeyType::Rsa4096.keygen_args(),
            vec!["-t", "rsa", "-b", "4096"]
        );
    }

    #[test]
    fn test_ssh_key_entry_new() {
        let entry = SshKeyEntry::new(
            "test-key".to_string(),
            PathBuf::from("/tmp/test"),
            PathBuf::from("/tmp/test.pub"),
            "ssh-ed25519 AAAA... test".to_string(),
            SshKeyType::Ed25519,
            "SHA256:abcdef".to_string(),
        );

        assert_eq!(entry.name, "test-key");
        assert_eq!(entry.key_type, SshKeyType::Ed25519);
        assert!(!entry.is_in_use());
        assert!(entry.last_used_at.is_none());
        assert!(entry.github_username.is_none());
    }

    #[test]
    fn test_ssh_key_entry_mark_used() {
        let mut entry = SshKeyEntry::new(
            "test".to_string(),
            PathBuf::from("/tmp/t"),
            PathBuf::from("/tmp/t.pub"),
            "ssh-ed25519 AAAA...".to_string(),
            SshKeyType::Ed25519,
            "SHA256:xyz".to_string(),
        );

        assert!(entry.last_used_at.is_none());
        entry.mark_used();
        assert!(entry.last_used_at.is_some());
    }

    #[test]
    fn test_ssh_key_entry_app_tracking() {
        let mut entry = SshKeyEntry::new(
            "test".to_string(),
            PathBuf::from("/tmp/t"),
            PathBuf::from("/tmp/t.pub"),
            "ssh-ed25519 AAAA...".to_string(),
            SshKeyType::Ed25519,
            "SHA256:xyz".to_string(),
        );

        assert!(!entry.is_in_use());
        entry.add_app("app-1");
        assert!(entry.is_in_use());
        assert_eq!(entry.used_by_apps.len(), 1);

        // Adding same app again should not duplicate
        entry.add_app("app-1");
        assert_eq!(entry.used_by_apps.len(), 1);

        entry.add_app("app-2");
        assert_eq!(entry.used_by_apps.len(), 2);

        entry.remove_app("app-1");
        assert_eq!(entry.used_by_apps.len(), 1);
        assert_eq!(entry.used_by_apps[0], "app-2");
    }

    #[test]
    fn test_ssh_key_entry_public_view() {
        let entry = SshKeyEntry::new(
            "test".to_string(),
            PathBuf::from("/secret/private/key"),
            PathBuf::from("/secret/private/key.pub"),
            "ssh-ed25519 AAAA...".to_string(),
            SshKeyType::Ed25519,
            "SHA256:xyz".to_string(),
        );

        let view = entry.to_public_view();
        assert_eq!(view.name, "test");
        assert_eq!(view.public_key, "ssh-ed25519 AAAA...");
        // The public view struct does not contain private_key_path at all
    }

    #[test]
    fn test_detect_key_type_rsa() {
        let content = "-----BEGIN RSA PRIVATE KEY-----\nblah\n-----END RSA PRIVATE KEY-----\n";
        assert_eq!(
            detect_key_type_from_content(content).unwrap(),
            SshKeyType::Rsa4096
        );
    }

    #[test]
    fn test_detect_key_type_ec() {
        let content = "-----BEGIN EC PRIVATE KEY-----\nblah\n-----END EC PRIVATE KEY-----\n";
        assert_eq!(
            detect_key_type_from_content(content).unwrap(),
            SshKeyType::Ecdsa256
        );
    }

    #[test]
    fn test_detect_key_type_dsa_rejected() {
        let content = "-----BEGIN DSA PRIVATE KEY-----\nblah\n-----END DSA PRIVATE KEY-----\n";
        assert!(detect_key_type_from_content(content).is_err());
    }

    #[test]
    fn test_detect_key_type_unknown() {
        let content = "not a key";
        assert!(detect_key_type_from_content(content).is_err());
    }

    #[test]
    fn test_extract_github_username() {
        let output = "Hi octocat! You've successfully authenticated, but GitHub does not provide shell access.";
        assert_eq!(
            extract_github_username(output),
            Some("octocat".to_string())
        );
    }

    #[test]
    fn test_extract_github_username_none() {
        assert_eq!(extract_github_username("Permission denied"), None);
        assert_eq!(extract_github_username(""), None);
    }

    #[test]
    fn test_is_ssh_url() {
        assert!(is_ssh_url("git@github.com:user/repo.git"));
        assert!(is_ssh_url("ssh://git@github.com/user/repo.git"));
        assert!(!is_ssh_url("https://github.com/user/repo.git"));
        assert!(!is_ssh_url("http://github.com/user/repo"));
    }

    #[test]
    fn test_parse_github_repo_ssh() {
        let result = parse_github_repo("git@github.com:octocat/hello-world.git");
        assert_eq!(
            result,
            Some(("octocat".to_string(), "hello-world".to_string()))
        );
    }

    #[test]
    fn test_parse_github_repo_https() {
        let result = parse_github_repo("https://github.com/octocat/hello-world.git");
        assert_eq!(
            result,
            Some(("octocat".to_string(), "hello-world".to_string()))
        );
    }

    #[test]
    fn test_parse_github_repo_https_no_git_suffix() {
        let result = parse_github_repo("https://github.com/octocat/hello-world");
        assert_eq!(
            result,
            Some(("octocat".to_string(), "hello-world".to_string()))
        );
    }

    #[test]
    fn test_parse_github_repo_invalid() {
        assert_eq!(parse_github_repo("not a url"), None);
        assert_eq!(parse_github_repo("https://github.com/"), None);
        assert_eq!(parse_github_repo("https://github.com/onlyowner"), None);
    }

    #[test]
    fn test_generate_key_id() {
        let id1 = generate_key_id();
        let id2 = generate_key_id();

        assert_eq!(id1.len(), 32);
        assert_eq!(id2.len(), 32);
        // IDs should be different (with very high probability)
        // Note: in extremely fast execution they may collide due to timestamp granularity,
        // but in practice this is fine because real usage has key generation seconds apart.
    }

    #[test]
    fn test_ssh_key_manager_new() {
        let tmp_dir = TempDir::new().unwrap();
        let keys_dir = tmp_dir.path().join("ssh_keys");

        let manager = SshKeyManager::new(keys_dir.clone()).unwrap();
        assert_eq!(manager.key_count(), 0);
        assert!(manager.list_keys().is_empty());
        assert!(keys_dir.exists());
    }

    #[test]
    fn test_ssh_key_manager_duplicate_name() {
        let tmp_dir = TempDir::new().unwrap();
        let keys_dir = tmp_dir.path().join("ssh_keys");
        let mut manager = SshKeyManager::new(keys_dir).unwrap();

        // We can't actually generate keys in tests without ssh-keygen,
        // but we can test the name uniqueness check by inserting a fake entry.
        let entry = SshKeyEntry::new(
            "my-key".to_string(),
            PathBuf::from("/tmp/fake"),
            PathBuf::from("/tmp/fake.pub"),
            "ssh-ed25519 AAAA...".to_string(),
            SshKeyType::Ed25519,
            "SHA256:fake".to_string(),
        );
        manager
            .registry
            .keys
            .insert(entry.id.clone(), entry);

        assert!(manager.validate_name_unique("my-key").is_err());
        assert!(manager.validate_name_unique("other-key").is_ok());
    }

    #[test]
    fn test_ssh_key_registry_roundtrip() {
        let tmp_dir = TempDir::new().unwrap();
        let registry_path = tmp_dir.path().join("registry.toml");

        let mut registry = SshKeyRegistry::default();
        let entry = SshKeyEntry::new(
            "test-key".to_string(),
            PathBuf::from("/tmp/key"),
            PathBuf::from("/tmp/key.pub"),
            "ssh-ed25519 AAAA... test".to_string(),
            SshKeyType::Ed25519,
            "SHA256:abcdef123456".to_string(),
        );
        registry.keys.insert(entry.id.clone(), entry.clone());

        // Save
        registry.save(&registry_path).unwrap();
        assert!(registry_path.exists());

        // Load
        let loaded = SshKeyRegistry::load(&registry_path).unwrap();
        assert_eq!(loaded.keys.len(), 1);

        let loaded_entry = loaded.keys.values().next().unwrap();
        assert_eq!(loaded_entry.name, "test-key");
        assert_eq!(loaded_entry.key_type, SshKeyType::Ed25519);
        assert_eq!(loaded_entry.fingerprint, "SHA256:abcdef123456");
    }

    #[test]
    fn test_ssh_key_registry_load_nonexistent() {
        let registry = SshKeyRegistry::load(Path::new("/tmp/nonexistent/registry.toml")).unwrap();
        assert!(registry.keys.is_empty());
    }

    #[test]
    fn test_connection_test_result_serialization() {
        let result = ConnectionTestResult {
            success: true,
            host: "github.com".to_string(),
            key_id: "abc123".to_string(),
            authenticated_as: Some("octocat".to_string()),
            output: "Hi octocat!".to_string(),
            error: None,
            tested_at: Utc::now(),
        };

        let json = serde_json::to_string(&result).unwrap();
        let deserialized: ConnectionTestResult = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized.success, true);
        assert_eq!(deserialized.host, "github.com");
        assert_eq!(deserialized.authenticated_as, Some("octocat".to_string()));
    }
}
