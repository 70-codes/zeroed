//! SSL / TLS Certificate Management Module
//!
//! This module provides functionality for automating SSL/TLS certificate
//! provisioning, renewal, and management via ACME (Let's Encrypt) or
//! manual certificate import.
//!
//! ## Responsibilities
//!
//! - Request SSL certificates from Let's Encrypt via certbot or built-in ACME
//! - Automatically renew certificates before expiry
//! - Import user-provided certificates (non-ACME)
//! - Check certificate status, expiry dates, and validity
//! - Coordinate with the Nginx manager to update server blocks after cert changes
//! - Perform DNS pre-checks to verify domain ownership before requesting certs
//!
//! ## Certificate Storage
//!
//! Certificates obtained via certbot are stored in the standard location:
//! `/etc/letsencrypt/live/<domain>/`
//!
//! Imported certificates are stored in a Zeroed-managed directory:
//! `/var/lib/zeroed/ssl/<domain>/`
//!
//! ## Renewal Strategy
//!
//! A background task runs daily (configurable) and checks all managed
//! certificates. Any certificate expiring within 30 days is automatically
//! renewed. After renewal, the corresponding Nginx config is regenerated
//! and Nginx is reloaded.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::fmt;
use std::fs;
use std::io;
use std::net::IpAddr;
use std::path::{Path, PathBuf};
use std::process::Command;
use thiserror::Error;
use tracing::{debug, error, info, warn};

// ─────────────────────────────────────────────────────────────────────────────
// Error Types
// ─────────────────────────────────────────────────────────────────────────────

/// Errors specific to SSL certificate operations.
#[derive(Debug, Error)]
pub enum SslError {
    #[error("IO error: {0}")]
    Io(#[from] io::Error),

    #[error("certbot is not installed — install with: apt install certbot python3-certbot-nginx")]
    CertbotNotInstalled,

    #[error("Certificate request failed for domain '{domain}': {message}")]
    RequestFailed { domain: String, message: String },

    #[error("Certificate renewal failed for domain '{domain}': {message}")]
    RenewalFailed { domain: String, message: String },

    #[error("Certificate not found for domain '{domain}'")]
    CertNotFound { domain: String },

    #[error("DNS verification failed for domain '{domain}': {message}")]
    DnsCheckFailed { domain: String, message: String },

    #[error("ACME email is not configured — set deploy.acme_email in zeroed.toml")]
    AcmeEmailNotConfigured,

    #[error("Domain '{domain}' does not resolve to this server's IP address")]
    DomainNotPointingToServer { domain: String },

    #[error("Certificate import failed: {message}")]
    ImportFailed { message: String },

    #[error("Certificate is invalid or expired: {message}")]
    InvalidCertificate { message: String },

    #[error("Certificate revocation failed for domain '{domain}': {message}")]
    RevocationFailed { domain: String, message: String },

    #[error("Port 80 is not reachable — required for HTTP-01 ACME challenge")]
    Port80NotReachable,

    #[error("Serialization error: {0}")]
    Serialization(String),

    #[error("Deserialization error: {0}")]
    Deserialization(String),
}

/// Result alias for SSL operations.
pub type Result<T> = std::result::Result<T, SslError>;

// ─────────────────────────────────────────────────────────────────────────────
// Certificate Provider
// ─────────────────────────────────────────────────────────────────────────────

/// The method used to obtain the certificate.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CertProvider {
    /// Obtained via Let's Encrypt / certbot
    LetsEncrypt,
    /// Obtained via a built-in Rust ACME client (future)
    AcmeBuiltin,
    /// Manually imported by the user
    Manual,
    /// Self-signed certificate (for development/testing)
    SelfSigned,
}

impl Default for CertProvider {
    fn default() -> Self {
        CertProvider::LetsEncrypt
    }
}

impl fmt::Display for CertProvider {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            CertProvider::LetsEncrypt => write!(f, "letsencrypt"),
            CertProvider::AcmeBuiltin => write!(f, "acme_builtin"),
            CertProvider::Manual => write!(f, "manual"),
            CertProvider::SelfSigned => write!(f, "self_signed"),
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Certificate Status
// ─────────────────────────────────────────────────────────────────────────────

/// Current status of a managed certificate.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CertStatus {
    /// Certificate is valid and not expiring soon
    Valid,
    /// Certificate is valid but will expire within the warning threshold
    ExpiringSoon,
    /// Certificate has expired
    Expired,
    /// Certificate is pending (request in progress)
    Pending,
    /// Certificate request or renewal failed
    Failed,
    /// Certificate has been revoked
    Revoked,
    /// Status could not be determined
    Unknown,
}

impl CertStatus {
    /// Whether the certificate is currently usable for HTTPS.
    pub fn is_usable(&self) -> bool {
        matches!(self, CertStatus::Valid | CertStatus::ExpiringSoon)
    }

    /// Whether the certificate needs attention (renewal, re-request, etc.).
    pub fn needs_attention(&self) -> bool {
        matches!(
            self,
            CertStatus::ExpiringSoon
                | CertStatus::Expired
                | CertStatus::Failed
                | CertStatus::Revoked
        )
    }
}

impl Default for CertStatus {
    fn default() -> Self {
        CertStatus::Unknown
    }
}

impl fmt::Display for CertStatus {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            CertStatus::Valid => write!(f, "valid"),
            CertStatus::ExpiringSoon => write!(f, "expiring_soon"),
            CertStatus::Expired => write!(f, "expired"),
            CertStatus::Pending => write!(f, "pending"),
            CertStatus::Failed => write!(f, "failed"),
            CertStatus::Revoked => write!(f, "revoked"),
            CertStatus::Unknown => write!(f, "unknown"),
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Certificate Info
// ─────────────────────────────────────────────────────────────────────────────

/// Metadata about a managed SSL certificate.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CertInfo {
    /// The primary domain name this certificate covers
    pub domain: String,

    /// Additional Subject Alternative Names (SANs)
    pub alt_names: Vec<String>,

    /// Path to the full-chain certificate file
    pub cert_path: PathBuf,

    /// Path to the private key file
    pub key_path: PathBuf,

    /// Path to the certificate chain file (intermediate certs)
    pub chain_path: Option<PathBuf>,

    /// When the certificate was issued
    pub issued_at: Option<DateTime<Utc>>,

    /// When the certificate expires
    pub expires_at: Option<DateTime<Utc>>,

    /// Certificate issuer (e.g. "Let's Encrypt Authority X3")
    pub issuer: Option<String>,

    /// How the certificate was obtained
    pub provider: CertProvider,

    /// Current status
    pub status: CertStatus,

    /// Whether automatic renewal is enabled
    pub auto_renew: bool,

    /// The application ID this certificate is associated with (if any)
    pub app_id: Option<String>,

    /// When the certificate was last renewed
    pub last_renewed_at: Option<DateTime<Utc>>,

    /// Number of times this certificate has been renewed
    pub renewal_count: u32,

    /// Last renewal error (if any)
    pub last_error: Option<String>,
}

impl CertInfo {
    /// Create a new CertInfo for a Let's Encrypt certificate.
    pub fn new_letsencrypt(domain: String, certs_dir: &Path) -> Self {
        let domain_dir = certs_dir.join(&domain);
        Self {
            domain: domain.clone(),
            alt_names: Vec::new(),
            cert_path: domain_dir.join("fullchain.pem"),
            key_path: domain_dir.join("privkey.pem"),
            chain_path: Some(domain_dir.join("chain.pem")),
            issued_at: None,
            expires_at: None,
            issuer: Some("Let's Encrypt".to_string()),
            provider: CertProvider::LetsEncrypt,
            status: CertStatus::Pending,
            auto_renew: true,
            app_id: None,
            last_renewed_at: None,
            renewal_count: 0,
            last_error: None,
        }
    }

    /// Create a new CertInfo for a manually imported certificate.
    pub fn new_manual(domain: String, cert_path: PathBuf, key_path: PathBuf) -> Self {
        Self {
            domain,
            alt_names: Vec::new(),
            cert_path,
            key_path,
            chain_path: None,
            issued_at: None,
            expires_at: None,
            issuer: None,
            provider: CertProvider::Manual,
            status: CertStatus::Unknown,
            auto_renew: false,
            app_id: None,
            last_renewed_at: None,
            renewal_count: 0,
            last_error: None,
        }
    }

    /// Check how many days until the certificate expires.
    /// Returns None if expiry date is unknown.
    pub fn days_until_expiry(&self) -> Option<i64> {
        self.expires_at.map(|exp| {
            let now = Utc::now();
            (exp - now).num_days()
        })
    }

    /// Check whether the certificate is expiring within the given number of days.
    pub fn is_expiring_within(&self, days: i64) -> bool {
        self.days_until_expiry()
            .map(|d| d <= days)
            .unwrap_or(false)
    }

    /// Check whether the certificate has expired.
    pub fn is_expired(&self) -> bool {
        self.days_until_expiry()
            .map(|d| d < 0)
            .unwrap_or(false)
    }

    /// Check whether the certificate files exist on disk.
    pub fn files_exist(&self) -> bool {
        self.cert_path.exists() && self.key_path.exists()
    }

    /// Update the status based on the current expiry date.
    pub fn refresh_status(&mut self) {
        if !self.files_exist() {
            self.status = CertStatus::Unknown;
            return;
        }

        if self.is_expired() {
            self.status = CertStatus::Expired;
        } else if self.is_expiring_within(30) {
            self.status = CertStatus::ExpiringSoon;
        } else {
            self.status = CertStatus::Valid;
        }
    }
}

impl fmt::Display for CertInfo {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let expiry = self
            .days_until_expiry()
            .map(|d| format!("{} days", d))
            .unwrap_or_else(|| "unknown".to_string());

        write!(
            f,
            "{} [{}] provider={} expires_in={} auto_renew={}",
            self.domain, self.status, self.provider, expiry, self.auto_renew
        )
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// DNS Check Result
// ─────────────────────────────────────────────────────────────────────────────

/// Result of a DNS pre-check before requesting a certificate.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DnsCheckResult {
    /// The domain that was checked
    pub domain: String,
    /// Whether the DNS check passed
    pub success: bool,
    /// The resolved IP addresses
    pub resolved_ips: Vec<String>,
    /// The server's public IP addresses
    pub server_ips: Vec<String>,
    /// Whether any resolved IP matches a server IP
    pub ip_matches: bool,
    /// Error or warning message
    pub message: Option<String>,
}

// ─────────────────────────────────────────────────────────────────────────────
// SSL Certificate Registry
// ─────────────────────────────────────────────────────────────────────────────

/// On-disk registry of all managed SSL certificates.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
struct SslRegistry {
    /// Map from domain name to certificate info
    certificates: std::collections::HashMap<String, CertInfo>,
}

impl SslRegistry {
    /// Load the registry from disk.
    fn load(path: &Path) -> Result<Self> {
        if !path.exists() {
            return Ok(Self::default());
        }

        let content = fs::read_to_string(path).map_err(SslError::Io)?;
        toml::from_str(&content).map_err(|e| SslError::Deserialization(e.to_string()))
    }

    /// Save the registry to disk.
    fn save(&self, path: &Path) -> Result<()> {
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent).map_err(SslError::Io)?;
        }

        let content =
            toml::to_string_pretty(self).map_err(|e| SslError::Serialization(e.to_string()))?;

        let tmp_path = path.with_extension("toml.tmp");
        fs::write(&tmp_path, &content).map_err(SslError::Io)?;
        fs::rename(&tmp_path, path).map_err(SslError::Io)?;

        debug!("SSL registry saved to {:?}", path);
        Ok(())
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// SSL Manager
// ─────────────────────────────────────────────────────────────────────────────

/// Manages SSL/TLS certificates for deployed applications.
///
/// Coordinates certificate requests, renewals, imports, and status checks.
/// Integrates with certbot for Let's Encrypt and supports manual certificate
/// import for users who obtain certificates through other means.
pub struct SslManager {
    /// Base directory for certificate storage (e.g. /etc/letsencrypt/live)
    certs_dir: PathBuf,

    /// Email address for ACME account registration
    acme_email: String,

    /// Path to the SSL registry file
    registry_path: PathBuf,

    /// In-memory certificate registry
    registry: SslRegistry,

    /// Whether certbot is available on the system
    certbot_available: bool,

    /// Number of days before expiry to trigger renewal
    renewal_threshold_days: i64,
}

impl SslManager {
    /// Create a new SSL manager.
    ///
    /// Detects whether certbot is installed and loads the certificate registry.
    pub fn new(certs_dir: PathBuf, acme_email: String) -> Result<Self> {
        let certbot_available = Self::check_certbot_installed();

        let registry_path = certs_dir
            .parent()
            .unwrap_or(&certs_dir)
            .join("zeroed-ssl-registry.toml");

        let registry = SslRegistry::load(&registry_path).unwrap_or_default();

        if certbot_available {
            info!(
                "SSL manager initialized with certbot (certs dir: {:?}, {} certs tracked)",
                certs_dir,
                registry.certificates.len()
            );
        } else {
            warn!(
                "SSL manager initialized WITHOUT certbot — automatic certificate \
                 requests will not work. Install with: apt install certbot python3-certbot-nginx"
            );
        }

        if acme_email.is_empty() {
            warn!("ACME email is not configured — certificate requests will fail");
        }

        Ok(Self {
            certs_dir,
            acme_email,
            registry_path,
            registry,
            certbot_available,
            renewal_threshold_days: 30,
        })
    }

    // ─────────────────────────────────────────────────────────────────────
    // Certificate Requests
    // ─────────────────────────────────────────────────────────────────────

    /// Request a new SSL certificate for the given domain via Let's Encrypt.
    ///
    /// Prerequisites:
    /// - certbot must be installed
    /// - ACME email must be configured
    /// - Domain DNS must resolve to this server
    /// - Port 80 must be accessible for HTTP-01 challenge
    ///
    /// This uses `certbot certonly --nginx` for the most seamless integration.
    pub fn request_certificate(&mut self, domain: &str) -> Result<CertInfo> {
        self.require_certbot()?;
        self.require_acme_email()?;

        info!("Requesting SSL certificate for domain: {}", domain);

        // Create a pending entry in the registry
        let mut cert_info = CertInfo::new_letsencrypt(domain.to_string(), &self.certs_dir);

        // Run certbot
        let output = Command::new("certbot")
            .arg("certonly")
            .arg("--nginx")
            .arg("--non-interactive")
            .arg("--agree-tos")
            .arg("--email")
            .arg(&self.acme_email)
            .arg("-d")
            .arg(domain)
            .output()
            .map_err(|e| SslError::RequestFailed {
                domain: domain.to_string(),
                message: format!("Failed to execute certbot: {}", e),
            })?;

        if output.status.success() {
            cert_info.status = CertStatus::Valid;
            cert_info.issued_at = Some(Utc::now());
            cert_info.last_renewed_at = Some(Utc::now());

            // Try to read expiry from the certificate
            if let Some(expiry) = self.read_cert_expiry(&cert_info.cert_path) {
                cert_info.expires_at = Some(expiry);
            }

            // Save to registry
            self.registry
                .certificates
                .insert(domain.to_string(), cert_info.clone());
            self.registry.save(&self.registry_path)?;

            info!("SSL certificate obtained for domain: {}", domain);
            Ok(cert_info)
        } else {
            let stderr = String::from_utf8_lossy(&output.stderr);
            let stdout = String::from_utf8_lossy(&output.stdout);
            let combined = format!("{}\n{}", stdout.trim(), stderr.trim());

            cert_info.status = CertStatus::Failed;
            cert_info.last_error = Some(combined.clone());

            // Save the failed state to registry
            self.registry
                .certificates
                .insert(domain.to_string(), cert_info);
            let _ = self.registry.save(&self.registry_path);

            Err(SslError::RequestFailed {
                domain: domain.to_string(),
                message: combined,
            })
        }
    }

    /// Renew the certificate for the given domain.
    pub fn renew_certificate(&mut self, domain: &str) -> Result<CertInfo> {
        self.require_certbot()?;

        info!("Renewing SSL certificate for domain: {}", domain);

        let output = Command::new("certbot")
            .arg("renew")
            .arg("--cert-name")
            .arg(domain)
            .arg("--non-interactive")
            .output()
            .map_err(|e| SslError::RenewalFailed {
                domain: domain.to_string(),
                message: format!("Failed to execute certbot renew: {}", e),
            })?;

        if output.status.success() {
            // Update registry entry
            if let Some(cert_info) = self.registry.certificates.get_mut(domain) {
                cert_info.status = CertStatus::Valid;
                cert_info.last_renewed_at = Some(Utc::now());
                cert_info.renewal_count += 1;
                cert_info.last_error = None;

                if let Some(expiry) = self.read_cert_expiry(&cert_info.cert_path) {
                    cert_info.expires_at = Some(expiry);
                }

                let updated = cert_info.clone();
                self.registry.save(&self.registry_path)?;

                info!("SSL certificate renewed for domain: {}", domain);
                Ok(updated)
            } else {
                // Certificate exists on disk but not in our registry — add it
                let mut cert_info =
                    CertInfo::new_letsencrypt(domain.to_string(), &self.certs_dir);
                cert_info.status = CertStatus::Valid;
                cert_info.last_renewed_at = Some(Utc::now());

                if let Some(expiry) = self.read_cert_expiry(&cert_info.cert_path) {
                    cert_info.expires_at = Some(expiry);
                }

                let result = cert_info.clone();
                self.registry
                    .certificates
                    .insert(domain.to_string(), cert_info);
                self.registry.save(&self.registry_path)?;

                Ok(result)
            }
        } else {
            let stderr = String::from_utf8_lossy(&output.stderr);

            if let Some(cert_info) = self.registry.certificates.get_mut(domain) {
                cert_info.last_error = Some(stderr.trim().to_string());
                let _ = self.registry.save(&self.registry_path);
            }

            Err(SslError::RenewalFailed {
                domain: domain.to_string(),
                message: stderr.trim().to_string(),
            })
        }
    }

    /// Renew all certificates that are expiring within the renewal threshold.
    ///
    /// Returns a list of (domain, result) pairs for each renewal attempted.
    pub fn renew_all_expiring(&mut self) -> Vec<(String, Result<CertInfo>)> {
        let domains_to_renew: Vec<String> = self
            .registry
            .certificates
            .iter()
            .filter(|(_, cert)| {
                cert.auto_renew && cert.is_expiring_within(self.renewal_threshold_days)
            })
            .map(|(domain, _)| domain.clone())
            .collect();

        if domains_to_renew.is_empty() {
            info!("No certificates need renewal");
            return Vec::new();
        }

        info!(
            "{} certificate(s) need renewal",
            domains_to_renew.len()
        );

        let mut results = Vec::new();
        for domain in domains_to_renew {
            let result = self.renew_certificate(&domain);
            results.push((domain, result));
        }

        results
    }

    // ─────────────────────────────────────────────────────────────────────
    // Certificate Import
    // ─────────────────────────────────────────────────────────────────────

    /// Import a user-provided certificate.
    ///
    /// The certificate and key files are copied to the managed SSL directory.
    /// Automatic renewal is NOT enabled for imported certificates.
    pub fn import_certificate(
        &mut self,
        domain: &str,
        cert_path: &Path,
        key_path: &Path,
    ) -> Result<CertInfo> {
        // Validate files exist
        if !cert_path.exists() {
            return Err(SslError::ImportFailed {
                message: format!("Certificate file not found: {:?}", cert_path),
            });
        }

        if !key_path.exists() {
            return Err(SslError::ImportFailed {
                message: format!("Key file not found: {:?}", key_path),
            });
        }

        // Create a directory for this domain's cert
        let dest_dir = self.certs_dir.join(domain);
        fs::create_dir_all(&dest_dir).map_err(SslError::Io)?;

        let dest_cert = dest_dir.join("fullchain.pem");
        let dest_key = dest_dir.join("privkey.pem");

        // Copy files
        fs::copy(cert_path, &dest_cert).map_err(|e| SslError::ImportFailed {
            message: format!("Failed to copy certificate: {}", e),
        })?;

        fs::copy(key_path, &dest_key).map_err(|e| SslError::ImportFailed {
            message: format!("Failed to copy key: {}", e),
        })?;

        // Set restrictive permissions on the key
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let _ = fs::set_permissions(&dest_key, fs::Permissions::from_mode(0o600));
        }

        let mut cert_info = CertInfo::new_manual(domain.to_string(), dest_cert, dest_key);
        cert_info.status = CertStatus::Valid;
        cert_info.issued_at = Some(Utc::now());

        // Try to read expiry from the certificate
        if let Some(expiry) = self.read_cert_expiry(&cert_info.cert_path) {
            cert_info.expires_at = Some(expiry);
            cert_info.refresh_status();
        }

        // Save to registry
        self.registry
            .certificates
            .insert(domain.to_string(), cert_info.clone());
        self.registry.save(&self.registry_path)?;

        info!("SSL certificate imported for domain: {}", domain);
        Ok(cert_info)
    }

    // ─────────────────────────────────────────────────────────────────────
    // Certificate Revocation
    // ─────────────────────────────────────────────────────────────────────

    /// Revoke a certificate for the given domain.
    pub fn revoke_certificate(&mut self, domain: &str) -> Result<()> {
        self.require_certbot()?;

        info!("Revoking SSL certificate for domain: {}", domain);

        let cert_info = self.registry.certificates.get(domain).ok_or_else(|| {
            SslError::CertNotFound {
                domain: domain.to_string(),
            }
        })?;

        let cert_path = cert_info.cert_path.clone();

        let output = Command::new("certbot")
            .arg("revoke")
            .arg("--cert-path")
            .arg(&cert_path)
            .arg("--non-interactive")
            .output()
            .map_err(|e| SslError::RevocationFailed {
                domain: domain.to_string(),
                message: format!("Failed to execute certbot revoke: {}", e),
            })?;

        if output.status.success() {
            if let Some(cert_info) = self.registry.certificates.get_mut(domain) {
                cert_info.status = CertStatus::Revoked;
                cert_info.auto_renew = false;
            }
            self.registry.save(&self.registry_path)?;

            info!("SSL certificate revoked for domain: {}", domain);
            Ok(())
        } else {
            let stderr = String::from_utf8_lossy(&output.stderr);
            Err(SslError::RevocationFailed {
                domain: domain.to_string(),
                message: stderr.trim().to_string(),
            })
        }
    }

    // ─────────────────────────────────────────────────────────────────────
    // Certificate Queries
    // ─────────────────────────────────────────────────────────────────────

    /// Get certificate info for a specific domain.
    pub fn get_certificate(&self, domain: &str) -> Option<&CertInfo> {
        self.registry.certificates.get(domain)
    }

    /// Get a mutable reference to certificate info for a specific domain.
    pub fn get_certificate_mut(&mut self, domain: &str) -> Option<&mut CertInfo> {
        self.registry.certificates.get_mut(domain)
    }

    /// List all managed certificates.
    pub fn list_certificates(&self) -> Vec<&CertInfo> {
        let mut certs: Vec<&CertInfo> = self.registry.certificates.values().collect();
        certs.sort_by(|a, b| a.domain.cmp(&b.domain));
        certs
    }

    /// List certificates that are expiring within the given number of days.
    pub fn list_expiring(&self, days: i64) -> Vec<&CertInfo> {
        self.registry
            .certificates
            .values()
            .filter(|c| c.is_expiring_within(days))
            .collect()
    }

    /// Check the status of a certificate and update the registry.
    pub fn check_certificate(&mut self, domain: &str) -> Result<CertInfo> {
        let cert_info = self
            .registry
            .certificates
            .get_mut(domain)
            .ok_or_else(|| SslError::CertNotFound {
                domain: domain.to_string(),
            })?;

        // Re-read expiry from disk
        if let Some(expiry) = self.read_cert_expiry(&cert_info.cert_path) {
            cert_info.expires_at = Some(expiry);
        }

        cert_info.refresh_status();

        let result = cert_info.clone();
        self.registry.save(&self.registry_path)?;

        Ok(result)
    }

    /// Refresh the status of all certificates in the registry.
    pub fn check_all_certificates(&mut self) -> Result<Vec<CertInfo>> {
        let domains: Vec<String> = self.registry.certificates.keys().cloned().collect();
        let mut results = Vec::new();

        for domain in domains {
            match self.check_certificate(&domain) {
                Ok(info) => results.push(info),
                Err(e) => {
                    warn!("Failed to check certificate for {}: {}", domain, e);
                }
            }
        }

        Ok(results)
    }

    /// Remove a certificate from the registry (does not delete files on disk).
    pub fn remove_certificate(&mut self, domain: &str) -> Result<Option<CertInfo>> {
        let removed = self.registry.certificates.remove(domain);
        if removed.is_some() {
            self.registry.save(&self.registry_path)?;
            info!("Certificate removed from registry: {}", domain);
        }
        Ok(removed)
    }

    /// Get the total number of managed certificates.
    pub fn certificate_count(&self) -> usize {
        self.registry.certificates.len()
    }

    // ─────────────────────────────────────────────────────────────────────
    // DNS Pre-Checks
    // ─────────────────────────────────────────────────────────────────────

    /// Perform a DNS check to verify the domain resolves to this server.
    ///
    /// This should be called before requesting a certificate to catch
    /// DNS misconfigurations early (instead of waiting for the ACME
    /// challenge to fail).
    pub fn check_dns(&self, domain: &str) -> DnsCheckResult {
        info!("Performing DNS check for domain: {}", domain);

        // Resolve the domain using the `dig` command or `host` command
        let resolved = self.resolve_domain(domain);
        let server_ips = self.get_server_public_ips();

        let resolved_ips: Vec<String> = resolved.iter().map(|ip| ip.to_string()).collect();
        let server_ip_strs: Vec<String> = server_ips.iter().map(|ip| ip.to_string()).collect();

        let ip_matches = resolved
            .iter()
            .any(|resolved_ip| server_ips.contains(resolved_ip));

        let message = if resolved.is_empty() {
            Some(format!(
                "Domain '{}' could not be resolved. Ensure an A/AAAA record exists.",
                domain
            ))
        } else if !ip_matches {
            Some(format!(
                "Domain '{}' resolves to {:?} but this server has IPs {:?}. \
                 Update DNS to point to this server.",
                domain, resolved_ips, server_ip_strs
            ))
        } else {
            None
        };

        let success = !resolved.is_empty() && ip_matches;

        DnsCheckResult {
            domain: domain.to_string(),
            success,
            resolved_ips,
            server_ips: server_ip_strs,
            ip_matches,
            message,
        }
    }

    /// Resolve a domain name to IP addresses using the system resolver.
    fn resolve_domain(&self, domain: &str) -> Vec<IpAddr> {
        // Use `getent ahosts <domain>` which is available on most Linux systems
        match Command::new("getent").arg("ahosts").arg(domain).output() {
            Ok(output) if output.status.success() => {
                let stdout = String::from_utf8_lossy(&output.stdout);
                let mut ips: Vec<IpAddr> = stdout
                    .lines()
                    .filter_map(|line| {
                        let first_field = line.split_whitespace().next()?;
                        first_field.parse::<IpAddr>().ok()
                    })
                    .collect();

                // Deduplicate
                ips.sort_by(|a, b| a.to_string().cmp(&b.to_string()));
                ips.dedup();
                ips
            }
            _ => {
                // Fallback: try using `host` command
                match Command::new("host").arg(domain).output() {
                    Ok(output) if output.status.success() => {
                        let stdout = String::from_utf8_lossy(&output.stdout);
                        stdout
                            .lines()
                            .filter_map(|line| {
                                if line.contains("has address") || line.contains("has IPv6 address")
                                {
                                    let ip_str = line.split_whitespace().last()?;
                                    ip_str.parse::<IpAddr>().ok()
                                } else {
                                    None
                                }
                            })
                            .collect()
                    }
                    _ => Vec::new(),
                }
            }
        }
    }

    /// Get the server's public IP addresses.
    ///
    /// Tries multiple methods to determine the server's external IP.
    fn get_server_public_ips(&self) -> Vec<IpAddr> {
        let mut ips = Vec::new();

        // Method 1: Use the `hostname -I` command to get all IPs
        if let Ok(output) = Command::new("hostname").arg("-I").output() {
            if output.status.success() {
                let stdout = String::from_utf8_lossy(&output.stdout);
                for ip_str in stdout.split_whitespace() {
                    if let Ok(ip) = ip_str.parse::<IpAddr>() {
                        ips.push(ip);
                    }
                }
            }
        }

        // Method 2: Try to get external IP via a well-known service
        if ips.is_empty() || ips.iter().all(|ip| ip.is_loopback()) {
            if let Ok(output) = Command::new("curl")
                .arg("-s")
                .arg("--max-time")
                .arg("5")
                .arg("https://api.ipify.org")
                .output()
            {
                if output.status.success() {
                    let ip_str = String::from_utf8_lossy(&output.stdout);
                    if let Ok(ip) = ip_str.trim().parse::<IpAddr>() {
                        ips.push(ip);
                    }
                }
            }
        }

        ips
    }

    // ─────────────────────────────────────────────────────────────────────
    // Certificate File Utilities
    // ─────────────────────────────────────────────────────────────────────

    /// Read the expiry date from a certificate file using openssl.
    fn read_cert_expiry(&self, cert_path: &Path) -> Option<DateTime<Utc>> {
        if !cert_path.exists() {
            return None;
        }

        let output = Command::new("openssl")
            .arg("x509")
            .arg("-enddate")
            .arg("-noout")
            .arg("-in")
            .arg(cert_path)
            .output()
            .ok()?;

        if !output.status.success() {
            return None;
        }

        let stdout = String::from_utf8_lossy(&output.stdout);
        // Output format: "notAfter=Jan  1 00:00:00 2025 GMT"
        let date_str = stdout.trim().strip_prefix("notAfter=")?;

        // Parse the date — openssl uses a specific format
        chrono::NaiveDateTime::parse_from_str(date_str, "%b %d %H:%M:%S %Y GMT")
            .or_else(|_| chrono::NaiveDateTime::parse_from_str(date_str, "%b  %d %H:%M:%S %Y GMT"))
            .ok()
            .map(|naive| DateTime::<Utc>::from_naive_utc_and_offset(naive, Utc))
    }

    /// Read the issuer from a certificate file using openssl.
    fn read_cert_issuer(&self, cert_path: &Path) -> Option<String> {
        if !cert_path.exists() {
            return None;
        }

        let output = Command::new("openssl")
            .arg("x509")
            .arg("-issuer")
            .arg("-noout")
            .arg("-in")
            .arg(cert_path)
            .output()
            .ok()?;

        if output.status.success() {
            let stdout = String::from_utf8_lossy(&output.stdout);
            let issuer = stdout.trim().strip_prefix("issuer=")?;
            Some(issuer.to_string())
        } else {
            None
        }
    }

    /// Read the Subject Alternative Names from a certificate file.
    fn read_cert_sans(&self, cert_path: &Path) -> Vec<String> {
        if !cert_path.exists() {
            return Vec::new();
        }

        let output = Command::new("openssl")
            .arg("x509")
            .arg("-text")
            .arg("-noout")
            .arg("-in")
            .arg(cert_path)
            .output();

        match output {
            Ok(o) if o.status.success() => {
                let stdout = String::from_utf8_lossy(&o.stdout);
                stdout
                    .lines()
                    .filter(|line| line.contains("DNS:"))
                    .flat_map(|line| {
                        line.split(',')
                            .filter_map(|part| {
                                let trimmed = part.trim();
                                trimmed
                                    .strip_prefix("DNS:")
                                    .map(|s| s.trim().to_string())
                            })
                    })
                    .collect()
            }
            _ => Vec::new(),
        }
    }

    // ─────────────────────────────────────────────────────────────────────
    // Statistics & Summary
    // ─────────────────────────────────────────────────────────────────────

    /// Get a summary of all managed certificates.
    pub fn summary(&self) -> SslSummary {
        let certs: Vec<&CertInfo> = self.registry.certificates.values().collect();

        SslSummary {
            total: certs.len(),
            valid: certs.iter().filter(|c| c.status == CertStatus::Valid).count(),
            expiring_soon: certs
                .iter()
                .filter(|c| c.status == CertStatus::ExpiringSoon)
                .count(),
            expired: certs
                .iter()
                .filter(|c| c.status == CertStatus::Expired)
                .count(),
            failed: certs.iter().filter(|c| c.status == CertStatus::Failed).count(),
            auto_renew_enabled: certs.iter().filter(|c| c.auto_renew).count(),
            letsencrypt: certs
                .iter()
                .filter(|c| c.provider == CertProvider::LetsEncrypt)
                .count(),
            manual: certs
                .iter()
                .filter(|c| c.provider == CertProvider::Manual)
                .count(),
        }
    }

    // ─────────────────────────────────────────────────────────────────────
    // Configuration & Status
    // ─────────────────────────────────────────────────────────────────────

    /// Get the certificates directory.
    pub fn certs_dir(&self) -> &Path {
        &self.certs_dir
    }

    /// Get the configured ACME email.
    pub fn acme_email(&self) -> &str {
        &self.acme_email
    }

    /// Set a new ACME email address.
    pub fn set_acme_email(&mut self, email: String) {
        self.acme_email = email;
    }

    /// Check whether certbot is available.
    pub fn is_certbot_available(&self) -> bool {
        self.certbot_available
    }

    /// Get the renewal threshold in days.
    pub fn renewal_threshold_days(&self) -> i64 {
        self.renewal_threshold_days
    }

    /// Set the renewal threshold in days.
    pub fn set_renewal_threshold_days(&mut self, days: i64) {
        self.renewal_threshold_days = days;
    }

    /// Reload the SSL registry from disk.
    pub fn reload(&mut self) -> Result<()> {
        self.registry = SslRegistry::load(&self.registry_path)?;
        info!(
            "SSL registry reloaded: {} certificates",
            self.registry.certificates.len()
        );
        Ok(())
    }

    // ─────────────────────────────────────────────────────────────────────
    // Internal Helpers
    // ─────────────────────────────────────────────────────────────────────

    /// Check whether certbot is installed.
    fn check_certbot_installed() -> bool {
        Command::new("which")
            .arg("certbot")
            .output()
            .map(|o| o.status.success())
            .unwrap_or(false)
    }

    /// Require that certbot is installed, returning an error if not.
    fn require_certbot(&self) -> Result<()> {
        if self.certbot_available {
            Ok(())
        } else {
            Err(SslError::CertbotNotInstalled)
        }
    }

    /// Require that ACME email is configured, returning an error if not.
    fn require_acme_email(&self) -> Result<()> {
        if self.acme_email.is_empty() {
            Err(SslError::AcmeEmailNotConfigured)
        } else {
            Ok(())
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// SSL Summary
// ─────────────────────────────────────────────────────────────────────────────

/// Summary statistics about managed SSL certificates.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SslSummary {
    /// Total number of managed certificates
    pub total: usize,
    /// Number of valid, non-expiring certificates
    pub valid: usize,
    /// Number of certificates expiring within the threshold
    pub expiring_soon: usize,
    /// Number of expired certificates
    pub expired: usize,
    /// Number of certificates in a failed state
    pub failed: usize,
    /// Number of certificates with auto-renewal enabled
    pub auto_renew_enabled: usize,
    /// Number of Let's Encrypt certificates
    pub letsencrypt: usize,
    /// Number of manually imported certificates
    pub manual: usize,
}

// ─────────────────────────────────────────────────────────────────────────────
// Tests
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    // ── CertStatus Tests ───────────────────────────────────────────────

    #[test]
    fn test_cert_status_display() {
        assert_eq!(format!("{}", CertStatus::Valid), "valid");
        assert_eq!(format!("{}", CertStatus::ExpiringSoon), "expiring_soon");
        assert_eq!(format!("{}", CertStatus::Expired), "expired");
        assert_eq!(format!("{}", CertStatus::Pending), "pending");
        assert_eq!(format!("{}", CertStatus::Failed), "failed");
        assert_eq!(format!("{}", CertStatus::Revoked), "revoked");
        assert_eq!(format!("{}", CertStatus::Unknown), "unknown");
    }

    #[test]
    fn test_cert_status_usable() {
        assert!(CertStatus::Valid.is_usable());
        assert!(CertStatus::ExpiringSoon.is_usable());
        assert!(!CertStatus::Expired.is_usable());
        assert!(!CertStatus::Failed.is_usable());
        assert!(!CertStatus::Revoked.is_usable());
        assert!(!CertStatus::Pending.is_usable());
    }

    #[test]
    fn test_cert_status_needs_attention() {
        assert!(!CertStatus::Valid.needs_attention());
        assert!(CertStatus::ExpiringSoon.needs_attention());
        assert!(CertStatus::Expired.needs_attention());
        assert!(CertStatus::Failed.needs_attention());
        assert!(CertStatus::Revoked.needs_attention());
    }

    // ── CertProvider Tests ─────────────────────────────────────────────

    #[test]
    fn test_cert_provider_display() {
        assert_eq!(format!("{}", CertProvider::LetsEncrypt), "letsencrypt");
        assert_eq!(format!("{}", CertProvider::Manual), "manual");
        assert_eq!(format!("{}", CertProvider::SelfSigned), "self_signed");
    }

    #[test]
    fn test_cert_provider_default() {
        assert_eq!(CertProvider::default(), CertProvider::LetsEncrypt);
    }

    // ── CertInfo Tests ─────────────────────────────────────────────────

    #[test]
    fn test_cert_info_new_letsencrypt() {
        let certs_dir = PathBuf::from("/etc/letsencrypt/live");
        let cert = CertInfo::new_letsencrypt("example.com".to_string(), &certs_dir);

        assert_eq!(cert.domain, "example.com");
        assert_eq!(cert.provider, CertProvider::LetsEncrypt);
        assert_eq!(cert.status, CertStatus::Pending);
        assert!(cert.auto_renew);
        assert!(cert.cert_path.to_string_lossy().contains("example.com"));
        assert!(cert.key_path.to_string_lossy().contains("example.com"));
    }

    #[test]
    fn test_cert_info_new_manual() {
        let cert = CertInfo::new_manual(
            "example.com".to_string(),
            PathBuf::from("/path/to/cert.pem"),
            PathBuf::from("/path/to/key.pem"),
        );

        assert_eq!(cert.domain, "example.com");
        assert_eq!(cert.provider, CertProvider::Manual);
        assert!(!cert.auto_renew);
    }

    #[test]
    fn test_cert_info_days_until_expiry() {
        let mut cert = CertInfo::new_manual(
            "test.com".to_string(),
            PathBuf::from("/tmp/cert"),
            PathBuf::from("/tmp/key"),
        );

        // No expiry set
        assert!(cert.days_until_expiry().is_none());

        // Set expiry 30 days from now
        cert.expires_at = Some(Utc::now() + chrono::Duration::days(30));
        let days = cert.days_until_expiry().unwrap();
        assert!(days >= 29 && days <= 30);

        // Set expiry in the past
        cert.expires_at = Some(Utc::now() - chrono::Duration::days(5));
        let days = cert.days_until_expiry().unwrap();
        assert!(days < 0);
    }

    #[test]
    fn test_cert_info_is_expiring_within() {
        let mut cert = CertInfo::new_manual(
            "test.com".to_string(),
            PathBuf::from("/tmp/cert"),
            PathBuf::from("/tmp/key"),
        );

        cert.expires_at = Some(Utc::now() + chrono::Duration::days(15));
        assert!(cert.is_expiring_within(30));
        assert!(cert.is_expiring_within(15));
        assert!(!cert.is_expiring_within(10));
    }

    #[test]
    fn test_cert_info_is_expired() {
        let mut cert = CertInfo::new_manual(
            "test.com".to_string(),
            PathBuf::from("/tmp/cert"),
            PathBuf::from("/tmp/key"),
        );

        cert.expires_at = Some(Utc::now() + chrono::Duration::days(30));
        assert!(!cert.is_expired());

        cert.expires_at = Some(Utc::now() - chrono::Duration::days(1));
        assert!(cert.is_expired());
    }

    #[test]
    fn test_cert_info_files_exist() {
        let cert = CertInfo::new_manual(
            "test.com".to_string(),
            PathBuf::from("/nonexistent/cert.pem"),
            PathBuf::from("/nonexistent/key.pem"),
        );
        assert!(!cert.files_exist());
    }

    #[test]
    fn test_cert_info_refresh_status() {
        let mut cert = CertInfo::new_manual(
            "test.com".to_string(),
            PathBuf::from("/nonexistent/cert.pem"),
            PathBuf::from("/nonexistent/key.pem"),
        );

        // Files don't exist → Unknown
        cert.refresh_status();
        assert_eq!(cert.status, CertStatus::Unknown);
    }

    #[test]
    fn test_cert_info_display() {
        let mut cert = CertInfo::new_letsencrypt(
            "example.com".to_string(),
            &PathBuf::from("/etc/letsencrypt/live"),
        );
        cert.status = CertStatus::Valid;

        let display = format!("{}", cert);
        assert!(display.contains("example.com"));
        assert!(display.contains("valid"));
        assert!(display.contains("letsencrypt"));
    }

    // ── SSL Registry Tests ─────────────────────────────────────────────

    #[test]
    fn test_ssl_registry_roundtrip() {
        let tmp = TempDir::new().unwrap();
        let registry_path = tmp.path().join("ssl-registry.toml");

        let mut registry = SslRegistry::default();
        let cert = CertInfo::new_letsencrypt(
            "example.com".to_string(),
            &PathBuf::from("/etc/letsencrypt/live"),
        );
        registry
            .certificates
            .insert("example.com".to_string(), cert);

        // Save
        registry.save(&registry_path).unwrap();
        assert!(registry_path.exists());

        // Load
        let loaded = SslRegistry::load(&registry_path).unwrap();
        assert_eq!(loaded.certificates.len(), 1);
        assert!(loaded.certificates.contains_key("example.com"));
    }

    #[test]
    fn test_ssl_registry_load_nonexistent() {
        let registry =
            SslRegistry::load(Path::new("/nonexistent/ssl-registry.toml")).unwrap();
        assert!(registry.certificates.is_empty());
    }

    // ── DNS Check Result Tests ─────────────────────────────────────────

    #[test]
    fn test_dns_check_result_serialization() {
        let result = DnsCheckResult {
            domain: "example.com".to_string(),
            success: true,
            resolved_ips: vec!["93.184.216.34".to_string()],
            server_ips: vec!["93.184.216.34".to_string()],
            ip_matches: true,
            message: None,
        };

        let json = serde_json::to_string(&result).unwrap();
        let deserialized: DnsCheckResult = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized.domain, "example.com");
        assert!(deserialized.success);
        assert!(deserialized.ip_matches);
    }

    // ── SSL Manager Tests ──────────────────────────────────────────────

    #[test]
    fn test_ssl_manager_new() {
        let tmp = TempDir::new().unwrap();
        let certs_dir = tmp.path().join("certs");

        let manager =
            SslManager::new(certs_dir, "admin@example.com".to_string()).unwrap();

        assert_eq!(manager.acme_email(), "admin@example.com");
        assert_eq!(manager.certificate_count(), 0);
        assert_eq!(manager.renewal_threshold_days(), 30);
    }

    #[test]
    fn test_ssl_manager_empty_email_warning() {
        let tmp = TempDir::new().unwrap();
        let certs_dir = tmp.path().join("certs");

        let manager = SslManager::new(certs_dir, String::new()).unwrap();
        assert!(manager.acme_email().is_empty());
    }

    #[test]
    fn test_ssl_manager_require_acme_email() {
        let tmp = TempDir::new().unwrap();
        let certs_dir = tmp.path().join("certs");

        let manager = SslManager::new(certs_dir, String::new()).unwrap();
        assert!(manager.require_acme_email().is_err());

        let tmp2 = TempDir::new().unwrap();
        let certs_dir2 = tmp2.path().join("certs");
        let manager2 =
            SslManager::new(certs_dir2, "test@example.com".to_string()).unwrap();
        assert!(manager2.require_acme_email().is_ok());
    }

    #[test]
    fn test_ssl_manager_list_certificates_empty() {
        let tmp = TempDir::new().unwrap();
        let manager =
            SslManager::new(tmp.path().join("certs"), "a@b.com".to_string()).unwrap();

        let certs = manager.list_certificates();
        assert!(certs.is_empty());
    }

    #[test]
    fn test_ssl_manager_get_certificate_not_found() {
        let tmp = TempDir::new().unwrap();
        let manager =
            SslManager::new(tmp.path().join("certs"), "a@b.com".to_string()).unwrap();

        assert!(manager.get_certificate("nonexistent.com").is_none());
    }

    #[test]
    fn test_ssl_manager_summary_empty() {
        let tmp = TempDir::new().unwrap();
        let manager =
            SslManager::new(tmp.path().join("certs"), "a@b.com".to_string()).unwrap();

        let summary = manager.summary();
        assert_eq!(summary.total, 0);
        assert_eq!(summary.valid, 0);
        assert_eq!(summary.letsencrypt, 0);
    }

    #[test]
    fn test_ssl_manager_set_renewal_threshold() {
        let tmp = TempDir::new().unwrap();
        let mut manager =
            SslManager::new(tmp.path().join("certs"), "a@b.com".to_string()).unwrap();

        assert_eq!(manager.renewal_threshold_days(), 30);
        manager.set_renewal_threshold_days(14);
        assert_eq!(manager.renewal_threshold_days(), 14);
    }

    #[test]
    fn test_ssl_manager_set_acme_email() {
        let tmp = TempDir::new().unwrap();
        let mut manager =
            SslManager::new(tmp.path().join("certs"), "old@example.com".to_string())
                .unwrap();

        assert_eq!(manager.acme_email(), "old@example.com");
        manager.set_acme_email("new@example.com".to_string());
        assert_eq!(manager.acme_email(), "new@example.com");
    }

    // ── SslSummary Tests ───────────────────────────────────────────────

    #[test]
    fn test_ssl_summary_serialization() {
        let summary = SslSummary {
            total: 5,
            valid: 3,
            expiring_soon: 1,
            expired: 0,
            failed: 1,
            auto_renew_enabled: 4,
            letsencrypt: 4,
            manual: 1,
        };

        let json = serde_json::to_string(&summary).unwrap();
        let deserialized: SslSummary = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized.total, 5);
        assert_eq!(deserialized.valid, 3);
        assert_eq!(deserialized.letsencrypt, 4);
    }
}
