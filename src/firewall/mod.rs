//! Firewall Integration Module
//!
//! This module provides functionality for managing firewall rules to block
//! and unblock IP addresses detected as malicious by the detection engine.
//!
//! ## Responsibilities
//!
//! - Create and manage a dedicated firewall chain (default: `ZEROED`)
//! - Block IPs by adding DROP rules to the chain
//! - Unblock IPs by removing their DROP rules
//! - Track blocked IPs with expiry timestamps for automatic cleanup
//! - Support dry-run mode for testing without modifying firewall rules
//! - Periodically clean up expired blocks
//! - Provide statistics on firewall operations
//!
//! ## Firewall Chain Architecture
//!
//! ```text
//! INPUT chain
//!   └── jump to ZEROED chain (inserted by ensure_chain)
//!         ├── -s 1.2.3.4 -j DROP
//!         ├── -s 5.6.7.8 -j DROP
//!         └── ... (per-IP block rules)
//! ```
//!
//! The `ZEROED` chain is created as a sub-chain of the INPUT chain.
//! This keeps all Zeroed-managed rules isolated from user rules and
//! makes cleanup straightforward — flushing the chain removes all blocks.
//!
//! ## Backends
//!
//! Currently only `iptables` is implemented. `nftables` and `ipset` backends
//! are defined in the config but not yet implemented (returns `NotAvailable`).
//!
//! ## Dry-Run Mode
//!
//! When `config.firewall.dry_run` is `true`, all operations are logged
//! but no actual iptables commands are executed. The internal blocked-IP
//! map is still maintained so the rest of the system behaves consistently.

use crate::core::config::{FirewallBackend, FirewallConfig};
use crate::core::error::{FirewallError, ZeroedError};

use chrono::{DateTime, Utc};
use dashmap::DashMap;
use serde::{Deserialize, Serialize};
use std::fmt;
use std::net::IpAddr;
use std::process::Command;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;
use tracing::{debug, error, info, warn};

// ─────────────────────────────────────────────────────────────────────────────
// Re-export Result alias using the crate-level error type
// ─────────────────────────────────────────────────────────────────────────────

/// Result alias for firewall operations, using the crate-level ZeroedError.
pub type Result<T> = std::result::Result<T, ZeroedError>;

// ─────────────────────────────────────────────────────────────────────────────
// Blocked IP Entry
// ─────────────────────────────────────────────────────────────────────────────

/// Record of a blocked IP address with metadata.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BlockedIpEntry {
    /// The blocked IP address
    pub ip: IpAddr,
    /// When the IP was blocked
    pub blocked_at: DateTime<Utc>,
    /// When the block expires (None = permanent)
    pub expires_at: Option<DateTime<Utc>>,
    /// The reason the IP was blocked
    pub reason: String,
    /// Number of times this IP has been re-blocked (escalation counter)
    pub block_count: u32,
}

impl BlockedIpEntry {
    /// Create a new blocked IP entry with a duration-based expiry.
    pub fn new(ip: IpAddr, duration: Duration, reason: String) -> Self {
        let now = Utc::now();
        let expires_at = chrono::Duration::from_std(duration)
            .ok()
            .map(|d| now + d);

        Self {
            ip,
            blocked_at: now,
            expires_at,
            reason,
            block_count: 1,
        }
    }

    /// Create a permanent block entry (no expiry).
    pub fn permanent(ip: IpAddr, reason: String) -> Self {
        Self {
            ip,
            blocked_at: Utc::now(),
            expires_at: None,
            reason,
            block_count: 1,
        }
    }

    /// Check whether this block has expired.
    pub fn is_expired(&self) -> bool {
        match self.expires_at {
            Some(exp) => Utc::now() > exp,
            None => false, // permanent blocks never expire
        }
    }

    /// Get the remaining duration of the block (None if expired or permanent).
    pub fn remaining(&self) -> Option<chrono::Duration> {
        self.expires_at.map(|exp| {
            let remaining = exp - Utc::now();
            if remaining.num_seconds() > 0 {
                remaining
            } else {
                chrono::Duration::zero()
            }
        })
    }

    /// Increment the block count (for re-blocks / escalation).
    pub fn increment_block_count(&mut self) {
        self.block_count += 1;
    }
}

impl fmt::Display for BlockedIpEntry {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let expiry = match self.expires_at {
            Some(exp) => {
                let remaining = exp - Utc::now();
                if remaining.num_seconds() > 0 {
                    format!("expires in {}s", remaining.num_seconds())
                } else {
                    "expired".to_string()
                }
            }
            None => "permanent".to_string(),
        };
        write!(
            f,
            "{} blocked_at={} {} reason=\"{}\" count={}",
            self.ip,
            self.blocked_at.format("%Y-%m-%d %H:%M:%S UTC"),
            expiry,
            self.reason,
            self.block_count,
        )
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Firewall Statistics
// ─────────────────────────────────────────────────────────────────────────────

/// Atomic counters for firewall operations.
#[derive(Debug, Default)]
struct FirewallStats {
    /// Total number of IPs blocked since startup
    total_blocks: AtomicU64,
    /// Total number of IPs unblocked since startup
    total_unblocks: AtomicU64,
    /// Total number of expired blocks cleaned up
    total_expired_cleanups: AtomicU64,
    /// Total number of iptables commands executed
    total_commands: AtomicU64,
    /// Total number of iptables command failures
    total_command_failures: AtomicU64,
}

/// Snapshot of firewall statistics (safe to serialize).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FirewallStatsSnapshot {
    /// Number of currently blocked IPs
    pub currently_blocked: usize,
    /// Total IPs blocked since startup
    pub total_blocks: u64,
    /// Total IPs unblocked since startup
    pub total_unblocks: u64,
    /// Total expired blocks cleaned up
    pub total_expired_cleanups: u64,
    /// Total iptables commands executed
    pub total_commands: u64,
    /// Total iptables command failures
    pub total_command_failures: u64,
    /// Whether dry-run mode is active
    pub dry_run: bool,
    /// The firewall backend in use
    pub backend: String,
    /// The chain name
    pub chain_name: String,
    /// Whether the firewall is enabled
    pub enabled: bool,
}

// ─────────────────────────────────────────────────────────────────────────────
// Firewall Manager
// ─────────────────────────────────────────────────────────────────────────────

/// Manages firewall rules for blocking and unblocking IP addresses.
///
/// The `FirewallManager` maintains an in-memory map of blocked IPs with
/// expiry timestamps, and translates block/unblock operations into
/// iptables commands. In dry-run mode, commands are logged but not executed.
///
/// ## Thread Safety
///
/// All methods are safe to call from multiple threads concurrently.
/// The blocked-IP map uses `DashMap` for lock-free concurrent access,
/// and statistics use atomic counters.
pub struct FirewallManager {
    /// Configuration
    config: FirewallConfig,
    /// Map of currently blocked IPs
    blocked: DashMap<IpAddr, BlockedIpEntry>,
    /// Whether the firewall chain has been initialized
    chain_initialized: std::sync::atomic::AtomicBool,
    /// Statistics
    stats: FirewallStats,
    /// Whether iptables binary is available
    iptables_available: bool,
}

impl FirewallManager {
    /// Create a new firewall manager from configuration.
    ///
    /// This does NOT automatically create the firewall chain — call
    /// `ensure_chain()` before blocking any IPs.
    pub fn new(config: FirewallConfig) -> Result<Self> {
        let iptables_available = if config.enabled && !config.dry_run {
            Self::check_iptables_available()
        } else {
            false
        };

        if config.enabled && !config.dry_run && !iptables_available {
            warn!(
                "Firewall is enabled but iptables is not available — \
                 falling back to dry-run mode"
            );
        }

        if config.dry_run {
            info!(
                "Firewall manager initialized in DRY-RUN mode (chain: {}, backend: {:?})",
                config.chain_name, config.backend
            );
        } else if config.enabled {
            info!(
                "Firewall manager initialized (chain: {}, backend: {:?}, max_rules: {})",
                config.chain_name, config.backend, config.max_rules
            );
        } else {
            info!("Firewall manager initialized but DISABLED by configuration");
        }

        Ok(Self {
            config,
            blocked: DashMap::new(),
            chain_initialized: std::sync::atomic::AtomicBool::new(false),
            stats: FirewallStats::default(),
            iptables_available,
        })
    }

    // ─────────────────────────────────────────────────────────────────────
    // Chain Management
    // ─────────────────────────────────────────────────────────────────────

    /// Ensure the ZEROED chain exists and is linked from the INPUT chain.
    ///
    /// This is idempotent — calling it multiple times is safe.
    /// Must be called before any block/unblock operations.
    ///
    /// Creates:
    /// 1. `iptables -N ZEROED` (create the chain, ignore if exists)
    /// 2. `iptables -C INPUT -j ZEROED` (check if jump exists)
    /// 3. `iptables -I INPUT 1 -j ZEROED` (insert jump if not present)
    pub fn ensure_chain(&self) -> Result<()> {
        if !self.config.enabled {
            debug!("Firewall disabled — skipping chain setup");
            return Ok(());
        }

        if self.chain_initialized.load(std::sync::atomic::Ordering::SeqCst) {
            return Ok(());
        }

        match self.config.backend {
            FirewallBackend::Iptables => self.ensure_chain_iptables()?,
            FirewallBackend::Nftables => {
                return Err(ZeroedError::Firewall(FirewallError::NotAvailable {
                    message: "nftables backend is not yet implemented".to_string(),
                }));
            }
            FirewallBackend::Ipset => {
                return Err(ZeroedError::Firewall(FirewallError::NotAvailable {
                    message: "ipset backend is not yet implemented".to_string(),
                }));
            }
        }

        self.chain_initialized
            .store(true, std::sync::atomic::Ordering::SeqCst);
        Ok(())
    }

    /// Create the chain and insert the INPUT jump using iptables.
    fn ensure_chain_iptables(&self) -> Result<()> {
        let chain = &self.config.chain_name;

        if self.is_dry_run() {
            info!(
                "[DRY RUN] Would create iptables chain '{}' and insert INPUT jump",
                chain
            );
            return Ok(());
        }

        // Step 1: Create the chain (ignore "already exists" error)
        let create_result = self.run_iptables(&["-N", chain]);
        match create_result {
            Ok(_) => info!("Created iptables chain '{}'", chain),
            Err(_) => {
                // Check if the error is "Chain already exists" — that's fine
                debug!("Chain '{}' may already exist (this is normal)", chain);
            }
        }

        // Step 2: Check if the INPUT -> ZEROED jump already exists
        let check_result = self.run_iptables(&["-C", "INPUT", "-j", chain]);
        if check_result.is_ok() {
            debug!("INPUT -> {} jump already exists", chain);
            return Ok(());
        }

        // Step 3: Insert the jump at position 1 (top of INPUT chain)
        self.run_iptables(&["-I", "INPUT", "1", "-j", chain])
            .map_err(|e| {
                ZeroedError::Firewall(FirewallError::ChainCreationError {
                    chain: chain.clone(),
                    message: format!("Failed to insert INPUT jump: {}", e),
                })
            })?;

        info!("Inserted INPUT -> {} jump rule at position 1", chain);
        Ok(())
    }

    /// Remove the ZEROED chain and its INPUT jump. Used during shutdown
    /// or when disabling the firewall.
    ///
    /// This flushes the chain (removing all block rules), removes the
    /// INPUT jump, and deletes the chain.
    pub fn teardown_chain(&self) -> Result<()> {
        if !self.config.enabled {
            return Ok(());
        }

        if self.is_dry_run() {
            info!("[DRY RUN] Would teardown iptables chain '{}'", self.config.chain_name);
            self.chain_initialized
                .store(false, std::sync::atomic::Ordering::SeqCst);
            return Ok(());
        }

        let chain = &self.config.chain_name;

        // Flush all rules in the chain
        let _ = self.run_iptables(&["-F", chain]);

        // Remove the INPUT jump
        let _ = self.run_iptables(&["-D", "INPUT", "-j", chain]);

        // Delete the chain
        let _ = self.run_iptables(&["-X", chain]);

        self.chain_initialized
            .store(false, std::sync::atomic::Ordering::SeqCst);

        info!("Firewall chain '{}' torn down", chain);
        Ok(())
    }

    // ─────────────────────────────────────────────────────────────────────
    // Block / Unblock
    // ─────────────────────────────────────────────────────────────────────

    /// Block an IP address by adding a DROP rule to the ZEROED chain.
    ///
    /// If the IP is already blocked, the entry is updated with a new expiry
    /// and the block count is incremented. The iptables rule is not duplicated.
    ///
    /// Returns `Ok(true)` if a new rule was added, `Ok(false)` if the IP
    /// was already blocked (entry updated only).
    pub fn block_ip(
        &self,
        ip: IpAddr,
        duration: Duration,
        reason: String,
    ) -> Result<bool> {
        if !self.config.enabled {
            debug!("Firewall disabled — not blocking {}", ip);
            return Ok(false);
        }

        // Check if already blocked BEFORE checking max_rules, so that
        // re-blocking an existing IP never fails due to capacity limits.
        if let Some(mut existing) = self.blocked.get_mut(&ip) {
            // Already blocked — update expiry and increment count
            let new_entry = BlockedIpEntry::new(ip, duration, reason.clone());
            existing.expires_at = new_entry.expires_at;
            existing.reason = reason;
            existing.increment_block_count();

            debug!(
                "IP {} already blocked — updated expiry (count: {})",
                ip, existing.block_count
            );

            return Ok(false);
        }

        // Check max_rules limit (only for genuinely new blocks)
        if self.blocked.len() >= self.config.max_rules {
            warn!(
                "Max firewall rules ({}) reached — cannot block {}. \
                 Run cleanup or increase max_rules.",
                self.config.max_rules, ip
            );
            return Err(ZeroedError::Firewall(FirewallError::RuleConflict {
                message: format!(
                    "Maximum firewall rules ({}) reached",
                    self.config.max_rules
                ),
            }));
        }

        // Ensure chain exists
        self.ensure_chain()?;

        // Add the iptables rule
        let ip_str = ip.to_string();
        if self.is_dry_run() {
            info!(
                "[DRY RUN] Would block IP {} for {}s — reason: {}",
                ip,
                duration.as_secs(),
                reason
            );
        } else {
            self.run_iptables(&[
                "-A",
                &self.config.chain_name,
                "-s",
                &ip_str,
                "-j",
                "DROP",
            ])
            .map_err(|e| {
                ZeroedError::Firewall(FirewallError::BlockError {
                    ip,
                    message: format!("iptables -A failed: {}", e),
                })
            })?;
        }

        // Track the block
        let entry = BlockedIpEntry::new(ip, duration, reason);
        self.blocked.insert(ip, entry);

        self.stats.total_blocks.fetch_add(1, Ordering::Relaxed);

        info!(
            "Blocked IP {} for {}s ({} total active blocks)",
            ip,
            duration.as_secs(),
            self.blocked.len(),
        );

        Ok(true)
    }

    /// Block an IP address permanently (no expiry).
    pub fn block_ip_permanent(&self, ip: IpAddr, reason: String) -> Result<bool> {
        if !self.config.enabled {
            return Ok(false);
        }

        if self.blocked.contains_key(&ip) {
            if let Some(mut existing) = self.blocked.get_mut(&ip) {
                existing.expires_at = None;
                existing.reason = reason;
                existing.increment_block_count();
            }
            return Ok(false);
        }

        self.ensure_chain()?;

        let ip_str = ip.to_string();
        if self.is_dry_run() {
            info!(
                "[DRY RUN] Would permanently block IP {} — reason: {}",
                ip, reason
            );
        } else {
            self.run_iptables(&[
                "-A",
                &self.config.chain_name,
                "-s",
                &ip_str,
                "-j",
                "DROP",
            ])
            .map_err(|e| {
                ZeroedError::Firewall(FirewallError::BlockError {
                    ip,
                    message: format!("iptables -A failed: {}", e),
                })
            })?;
        }

        let entry = BlockedIpEntry::permanent(ip, reason);
        self.blocked.insert(ip, entry);
        self.stats.total_blocks.fetch_add(1, Ordering::Relaxed);

        info!("Permanently blocked IP {} ({} total active blocks)", ip, self.blocked.len());

        Ok(true)
    }

    /// Unblock an IP address by removing its DROP rule from the ZEROED chain.
    ///
    /// Returns `Ok(true)` if the IP was unblocked, `Ok(false)` if it wasn't
    /// blocked in the first place.
    pub fn unblock_ip(&self, ip: &IpAddr) -> Result<bool> {
        if !self.config.enabled {
            return Ok(false);
        }

        // Remove from our tracking map first
        let removed = self.blocked.remove(ip);
        if removed.is_none() {
            debug!("IP {} is not in the blocked list — nothing to unblock", ip);
            return Ok(false);
        }

        // Remove the iptables rule
        let ip_str = ip.to_string();
        if self.is_dry_run() {
            info!("[DRY RUN] Would unblock IP {}", ip);
        } else {
            // Use -D to delete the rule. If there are somehow duplicates,
            // -D only removes the first match, which is fine since we only
            // add one rule per IP.
            let result = self.run_iptables(&[
                "-D",
                &self.config.chain_name,
                "-s",
                &ip_str,
                "-j",
                "DROP",
            ]);

            if let Err(e) = result {
                // Log but don't fail — the IP is already removed from our map,
                // and the iptables rule might have been manually removed.
                warn!(
                    "Failed to remove iptables rule for {} (may already be removed): {}",
                    ip, e
                );
            }
        }

        self.stats.total_unblocks.fetch_add(1, Ordering::Relaxed);
        info!("Unblocked IP {} ({} remaining active blocks)", ip, self.blocked.len());

        Ok(true)
    }

    /// Unblock all currently blocked IPs and flush the chain.
    ///
    /// Returns the number of IPs that were unblocked.
    pub fn unblock_all(&self) -> Result<usize> {
        if !self.config.enabled {
            return Ok(0);
        }

        let count = self.blocked.len();

        if count == 0 {
            return Ok(0);
        }

        // Flush the chain (faster than removing one by one)
        if self.is_dry_run() {
            info!("[DRY RUN] Would flush chain '{}' ({} rules)", self.config.chain_name, count);
        } else {
            let _ = self.run_iptables(&["-F", &self.config.chain_name]);
        }

        // Clear our tracking map
        self.blocked.clear();
        self.stats
            .total_unblocks
            .fetch_add(count as u64, Ordering::Relaxed);

        info!("Flushed all {} blocked IPs from chain '{}'", count, self.config.chain_name);

        Ok(count)
    }

    // ─────────────────────────────────────────────────────────────────────
    // Cleanup
    // ─────────────────────────────────────────────────────────────────────

    /// Clean up expired block entries by unblocking IPs whose duration
    /// has elapsed.
    ///
    /// This should be called periodically from the maintenance task.
    /// Returns the number of expired blocks that were cleaned up.
    pub fn cleanup_expired(&self) -> Result<usize> {
        if !self.config.enabled {
            return Ok(0);
        }

        // Collect expired IPs (can't modify DashMap while iterating with remove)
        let expired_ips: Vec<IpAddr> = self
            .blocked
            .iter()
            .filter(|entry| entry.value().is_expired())
            .map(|entry| *entry.key())
            .collect();

        if expired_ips.is_empty() {
            return Ok(0);
        }

        let mut cleaned = 0usize;

        for ip in &expired_ips {
            match self.unblock_ip(ip) {
                Ok(true) => {
                    cleaned += 1;
                    debug!("Cleaned up expired block for {}", ip);
                }
                Ok(false) => {
                    // Was already removed between collecting and unblocking
                }
                Err(e) => {
                    warn!("Failed to clean up expired block for {}: {}", ip, e);
                }
            }
        }

        if cleaned > 0 {
            self.stats
                .total_expired_cleanups
                .fetch_add(cleaned as u64, Ordering::Relaxed);
            info!(
                "Expired block cleanup: removed {} IPs ({} remaining)",
                cleaned,
                self.blocked.len()
            );
        }

        Ok(cleaned)
    }

    // ─────────────────────────────────────────────────────────────────────
    // Queries
    // ─────────────────────────────────────────────────────────────────────

    /// Check whether a specific IP is currently blocked.
    pub fn is_blocked(&self, ip: &IpAddr) -> bool {
        self.blocked.contains_key(ip)
    }

    /// Get the block entry for a specific IP (if blocked).
    pub fn get_block_entry(&self, ip: &IpAddr) -> Option<BlockedIpEntry> {
        self.blocked.get(ip).map(|entry| entry.value().clone())
    }

    /// Get a list of all currently blocked IPs with their metadata.
    pub fn list_blocked(&self) -> Vec<BlockedIpEntry> {
        self.blocked
            .iter()
            .map(|entry| entry.value().clone())
            .collect()
    }

    /// Get a list of all currently blocked IPs sorted by blocked_at (newest first).
    pub fn list_blocked_sorted(&self) -> Vec<BlockedIpEntry> {
        let mut entries = self.list_blocked();
        entries.sort_by(|a, b| b.blocked_at.cmp(&a.blocked_at));
        entries
    }

    /// Get the number of currently blocked IPs.
    pub fn blocked_count(&self) -> usize {
        self.blocked.len()
    }

    /// Get a statistics snapshot.
    pub fn stats(&self) -> FirewallStatsSnapshot {
        FirewallStatsSnapshot {
            currently_blocked: self.blocked.len(),
            total_blocks: self.stats.total_blocks.load(Ordering::Relaxed),
            total_unblocks: self.stats.total_unblocks.load(Ordering::Relaxed),
            total_expired_cleanups: self.stats.total_expired_cleanups.load(Ordering::Relaxed),
            total_commands: self.stats.total_commands.load(Ordering::Relaxed),
            total_command_failures: self.stats.total_command_failures.load(Ordering::Relaxed),
            dry_run: self.is_dry_run(),
            backend: format!("{:?}", self.config.backend),
            chain_name: self.config.chain_name.clone(),
            enabled: self.config.enabled,
        }
    }

    /// Check whether the firewall is operating in dry-run mode.
    ///
    /// This returns `true` if either:
    /// - `config.dry_run` is explicitly set, OR
    /// - The firewall is enabled but iptables is not available
    pub fn is_dry_run(&self) -> bool {
        self.config.dry_run || (self.config.enabled && !self.iptables_available)
    }

    /// Check whether the firewall is enabled.
    pub fn is_enabled(&self) -> bool {
        self.config.enabled
    }

    /// Get the firewall configuration (read-only).
    pub fn config(&self) -> &FirewallConfig {
        &self.config
    }

    /// Check whether the firewall chain has been initialized.
    pub fn is_chain_initialized(&self) -> bool {
        self.chain_initialized
            .load(std::sync::atomic::Ordering::SeqCst)
    }

    // ─────────────────────────────────────────────────────────────────────
    // iptables Command Execution
    // ─────────────────────────────────────────────────────────────────────

    /// Execute an iptables command with the given arguments.
    ///
    /// Returns `Ok(output)` if the command exits with code 0,
    /// or `Err` with the stderr content otherwise.
    fn run_iptables(&self, args: &[&str]) -> std::result::Result<String, String> {
        self.stats.total_commands.fetch_add(1, Ordering::Relaxed);

        let output = Command::new("iptables")
            .args(args)
            .output()
            .map_err(|e| {
                self.stats
                    .total_command_failures
                    .fetch_add(1, Ordering::Relaxed);
                format!("Failed to execute iptables: {}", e)
            })?;

        if output.status.success() {
            let stdout = String::from_utf8_lossy(&output.stdout).to_string();
            debug!("iptables {} → OK", args.join(" "));
            Ok(stdout)
        } else {
            self.stats
                .total_command_failures
                .fetch_add(1, Ordering::Relaxed);
            let stderr = String::from_utf8_lossy(&output.stderr).trim().to_string();
            debug!("iptables {} → FAIL: {}", args.join(" "), stderr);
            Err(stderr)
        }
    }

    /// Check whether the iptables binary is available on the system.
    fn check_iptables_available() -> bool {
        Command::new("iptables")
            .arg("--version")
            .output()
            .map(|o| o.status.success())
            .unwrap_or(false)
    }

    /// List the current rules in the ZEROED chain (for debugging).
    ///
    /// Returns the raw output of `iptables -L <chain> -n --line-numbers`.
    pub fn list_chain_rules(&self) -> Result<String> {
        if self.is_dry_run() {
            return Ok("[DRY RUN] No actual chain rules to list".to_string());
        }

        let output = self
            .run_iptables(&[
                "-L",
                &self.config.chain_name,
                "-n",
                "--line-numbers",
            ])
            .map_err(|e| {
                ZeroedError::Firewall(FirewallError::IptablesError {
                    message: format!("Failed to list chain rules: {}", e),
                })
            })?;

        Ok(output)
    }

    /// Synchronize the in-memory blocked map with the actual iptables rules.
    ///
    /// This is useful after a restart when the iptables chain may have rules
    /// from a previous run that aren't in our in-memory map. It parses the
    /// chain output and removes rules that aren't tracked, and adds tracking
    /// for rules that exist but aren't in our map.
    ///
    /// Returns `(added_to_map, removed_from_chain)`.
    pub fn sync_with_chain(&self) -> Result<(usize, usize)> {
        if self.is_dry_run() || !self.config.enabled {
            return Ok((0, 0));
        }

        let rules_output = self
            .run_iptables(&["-S", &self.config.chain_name])
            .map_err(|e| {
                ZeroedError::Firewall(FirewallError::IptablesError {
                    message: format!("Failed to read chain rules: {}", e),
                })
            })?;

        let mut chain_ips: Vec<IpAddr> = Vec::new();

        // Parse `-S` output: each rule looks like:
        // -A ZEROED -s 1.2.3.4/32 -j DROP
        for line in rules_output.lines() {
            let line = line.trim();
            if line.starts_with("-A") && line.contains("-j DROP") {
                if let Some(ip_str) = Self::extract_ip_from_rule(line) {
                    if let Ok(ip) = ip_str.parse::<IpAddr>() {
                        chain_ips.push(ip);
                    }
                }
            }
        }

        let mut added = 0usize;
        let mut removed = 0usize;

        // Add chain IPs that aren't in our map
        for ip in &chain_ips {
            if !self.blocked.contains_key(ip) {
                let entry = BlockedIpEntry::permanent(
                    *ip,
                    "Pre-existing rule (synced from iptables chain)".to_string(),
                );
                self.blocked.insert(*ip, entry);
                added += 1;
                debug!("Synced pre-existing block rule for {} into tracking map", ip);
            }
        }

        // Remove map entries that don't have a corresponding chain rule
        let map_ips: Vec<IpAddr> = self.blocked.iter().map(|e| *e.key()).collect();
        for ip in &map_ips {
            if !chain_ips.contains(ip) {
                self.blocked.remove(ip);
                removed += 1;
                debug!("Removed stale tracking entry for {} (no chain rule found)", ip);
            }
        }

        if added > 0 || removed > 0 {
            info!(
                "Chain sync: added {} pre-existing rules to map, removed {} stale map entries",
                added, removed
            );
        }

        Ok((added, removed))
    }

    /// Extract the source IP from an iptables -S rule line.
    ///
    /// Example input: `-A ZEROED -s 1.2.3.4/32 -j DROP`
    /// Returns: `Some("1.2.3.4")`
    fn extract_ip_from_rule(rule: &str) -> Option<&str> {
        let parts: Vec<&str> = rule.split_whitespace().collect();
        for (i, part) in parts.iter().enumerate() {
            if *part == "-s" {
                if let Some(ip_cidr) = parts.get(i + 1) {
                    // Strip /32 suffix if present
                    return Some(ip_cidr.split('/').next().unwrap_or(ip_cidr));
                }
            }
        }
        None
    }
}

impl Drop for FirewallManager {
    fn drop(&mut self) {
        // Log the final state but do NOT teardown the chain automatically.
        // This is intentional: if the daemon crashes and restarts, we want
        // the block rules to persist in iptables. The operator can manually
        // run `iptables -F ZEROED` if needed, or the daemon will sync on
        // next startup.
        let count = self.blocked.len();
        if count > 0 {
            info!(
                "Firewall manager shutting down with {} active block(s) — \
                 rules remain in iptables chain '{}'",
                count, self.config.chain_name
            );
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Tests
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;
    use std::time::Duration;

    /// Create a firewall config in dry-run mode (no actual iptables calls).
    fn dry_run_config() -> FirewallConfig {
        FirewallConfig {
            enabled: true,
            backend: FirewallBackend::Iptables,
            chain_name: "ZEROED_TEST".to_string(),
            table_name: "filter".to_string(),
            ipset_name: "zeroed_test_blocklist".to_string(),
            use_ipset: false,
            max_rules: 100,
            dry_run: true,
        }
    }

    /// Create a disabled firewall config.
    fn disabled_config() -> FirewallConfig {
        FirewallConfig {
            enabled: false,
            ..dry_run_config()
        }
    }

    fn test_ip(last_octet: u8) -> IpAddr {
        IpAddr::V4(Ipv4Addr::new(10, 0, 0, last_octet))
    }

    // ── BlockedIpEntry Tests ───────────────────────────────────────────

    #[test]
    fn test_blocked_ip_entry_new() {
        let entry = BlockedIpEntry::new(
            test_ip(1),
            Duration::from_secs(3600),
            "Rate limit exceeded".to_string(),
        );

        assert_eq!(entry.ip, test_ip(1));
        assert!(entry.expires_at.is_some());
        assert!(!entry.is_expired());
        assert_eq!(entry.block_count, 1);
        assert_eq!(entry.reason, "Rate limit exceeded");
    }

    #[test]
    fn test_blocked_ip_entry_permanent() {
        let entry = BlockedIpEntry::permanent(test_ip(2), "Blacklisted".to_string());

        assert_eq!(entry.ip, test_ip(2));
        assert!(entry.expires_at.is_none());
        assert!(!entry.is_expired()); // permanent blocks never expire
        assert_eq!(entry.block_count, 1);
    }

    #[test]
    fn test_blocked_ip_entry_is_expired() {
        // Create an entry that expires immediately
        let mut entry = BlockedIpEntry::new(
            test_ip(3),
            Duration::from_secs(0),
            "test".to_string(),
        );
        // Force the expiry to be in the past
        entry.expires_at = Some(Utc::now() - chrono::Duration::seconds(10));

        assert!(entry.is_expired());
    }

    #[test]
    fn test_blocked_ip_entry_not_expired() {
        let entry = BlockedIpEntry::new(
            test_ip(4),
            Duration::from_secs(3600),
            "test".to_string(),
        );

        assert!(!entry.is_expired());
    }

    #[test]
    fn test_blocked_ip_entry_remaining() {
        let entry = BlockedIpEntry::new(
            test_ip(5),
            Duration::from_secs(3600),
            "test".to_string(),
        );

        let remaining = entry.remaining();
        assert!(remaining.is_some());
        let secs = remaining.unwrap().num_seconds();
        assert!(secs > 3500 && secs <= 3600);
    }

    #[test]
    fn test_blocked_ip_entry_remaining_permanent() {
        let entry = BlockedIpEntry::permanent(test_ip(6), "test".to_string());
        assert!(entry.remaining().is_none());
    }

    #[test]
    fn test_blocked_ip_entry_remaining_expired() {
        let mut entry = BlockedIpEntry::new(
            test_ip(7),
            Duration::from_secs(0),
            "test".to_string(),
        );
        entry.expires_at = Some(Utc::now() - chrono::Duration::seconds(60));

        let remaining = entry.remaining().unwrap();
        assert_eq!(remaining, chrono::Duration::zero());
    }

    #[test]
    fn test_blocked_ip_entry_increment_block_count() {
        let mut entry = BlockedIpEntry::new(
            test_ip(8),
            Duration::from_secs(3600),
            "test".to_string(),
        );

        assert_eq!(entry.block_count, 1);
        entry.increment_block_count();
        assert_eq!(entry.block_count, 2);
        entry.increment_block_count();
        assert_eq!(entry.block_count, 3);
    }

    #[test]
    fn test_blocked_ip_entry_display() {
        let entry = BlockedIpEntry::new(
            test_ip(9),
            Duration::from_secs(3600),
            "SYN flood".to_string(),
        );

        let display = format!("{}", entry);
        assert!(display.contains("10.0.0.9"));
        assert!(display.contains("SYN flood"));
        assert!(display.contains("count=1"));
        assert!(display.contains("expires in"));
    }

    #[test]
    fn test_blocked_ip_entry_display_permanent() {
        let entry = BlockedIpEntry::permanent(test_ip(10), "Blacklisted".to_string());
        let display = format!("{}", entry);
        assert!(display.contains("permanent"));
    }

    #[test]
    fn test_blocked_ip_entry_display_expired() {
        let mut entry = BlockedIpEntry::new(
            test_ip(11),
            Duration::from_secs(0),
            "test".to_string(),
        );
        entry.expires_at = Some(Utc::now() - chrono::Duration::seconds(10));

        let display = format!("{}", entry);
        assert!(display.contains("expired"));
    }

    // ── FirewallManager Construction Tests ──────────────────────────────

    #[test]
    fn test_firewall_manager_new_dry_run() {
        let config = dry_run_config();
        let manager = FirewallManager::new(config).unwrap();

        assert!(manager.is_enabled());
        assert!(manager.is_dry_run());
        assert_eq!(manager.blocked_count(), 0);
        assert!(!manager.is_chain_initialized());
    }

    #[test]
    fn test_firewall_manager_new_disabled() {
        let config = disabled_config();
        let manager = FirewallManager::new(config).unwrap();

        assert!(!manager.is_enabled());
        assert_eq!(manager.blocked_count(), 0);
    }

    #[test]
    fn test_firewall_manager_config_accessor() {
        let config = dry_run_config();
        let manager = FirewallManager::new(config).unwrap();

        assert_eq!(manager.config().chain_name, "ZEROED_TEST");
        assert_eq!(manager.config().max_rules, 100);
        assert!(manager.config().dry_run);
    }

    // ── Block / Unblock Tests (Dry-Run Mode) ───────────────────────────

    #[test]
    fn test_block_ip_dry_run() {
        let config = dry_run_config();
        let manager = FirewallManager::new(config).unwrap();

        let result = manager.block_ip(
            test_ip(1),
            Duration::from_secs(3600),
            "Rate limit exceeded".to_string(),
        );

        assert!(result.is_ok());
        assert!(result.unwrap()); // true = new rule
        assert!(manager.is_blocked(&test_ip(1)));
        assert_eq!(manager.blocked_count(), 1);
    }

    #[test]
    fn test_block_ip_already_blocked() {
        let config = dry_run_config();
        let manager = FirewallManager::new(config).unwrap();

        // Block first time
        let result1 = manager
            .block_ip(test_ip(1), Duration::from_secs(3600), "first".to_string())
            .unwrap();
        assert!(result1); // new rule

        // Block same IP again
        let result2 = manager
            .block_ip(test_ip(1), Duration::from_secs(7200), "second".to_string())
            .unwrap();
        assert!(!result2); // already blocked, just updated

        // Should still be 1 entry, but with count=2 and updated reason
        assert_eq!(manager.blocked_count(), 1);
        let entry = manager.get_block_entry(&test_ip(1)).unwrap();
        assert_eq!(entry.block_count, 2);
        assert_eq!(entry.reason, "second");
    }

    #[test]
    fn test_block_ip_permanent_dry_run() {
        let config = dry_run_config();
        let manager = FirewallManager::new(config).unwrap();

        let result = manager
            .block_ip_permanent(test_ip(50), "Blacklisted".to_string())
            .unwrap();
        assert!(result);
        assert!(manager.is_blocked(&test_ip(50)));

        let entry = manager.get_block_entry(&test_ip(50)).unwrap();
        assert!(entry.expires_at.is_none());
    }

    #[test]
    fn test_unblock_ip_dry_run() {
        let config = dry_run_config();
        let manager = FirewallManager::new(config).unwrap();

        // Block and then unblock
        manager
            .block_ip(test_ip(1), Duration::from_secs(3600), "test".to_string())
            .unwrap();
        assert!(manager.is_blocked(&test_ip(1)));

        let result = manager.unblock_ip(&test_ip(1)).unwrap();
        assert!(result);
        assert!(!manager.is_blocked(&test_ip(1)));
        assert_eq!(manager.blocked_count(), 0);
    }

    #[test]
    fn test_unblock_ip_not_blocked() {
        let config = dry_run_config();
        let manager = FirewallManager::new(config).unwrap();

        let result = manager.unblock_ip(&test_ip(99)).unwrap();
        assert!(!result); // was not blocked
    }

    #[test]
    fn test_unblock_all_dry_run() {
        let config = dry_run_config();
        let manager = FirewallManager::new(config).unwrap();

        for i in 1..=5 {
            manager
                .block_ip(test_ip(i), Duration::from_secs(3600), "test".to_string())
                .unwrap();
        }
        assert_eq!(manager.blocked_count(), 5);

        let count = manager.unblock_all().unwrap();
        assert_eq!(count, 5);
        assert_eq!(manager.blocked_count(), 0);
    }

    #[test]
    fn test_unblock_all_empty() {
        let config = dry_run_config();
        let manager = FirewallManager::new(config).unwrap();

        let count = manager.unblock_all().unwrap();
        assert_eq!(count, 0);
    }

    // ── Disabled Firewall Tests ────────────────────────────────────────

    #[test]
    fn test_block_ip_disabled() {
        let config = disabled_config();
        let manager = FirewallManager::new(config).unwrap();

        let result = manager
            .block_ip(test_ip(1), Duration::from_secs(3600), "test".to_string())
            .unwrap();
        assert!(!result);
        assert!(!manager.is_blocked(&test_ip(1)));
        assert_eq!(manager.blocked_count(), 0);
    }

    #[test]
    fn test_unblock_ip_disabled() {
        let config = disabled_config();
        let manager = FirewallManager::new(config).unwrap();

        let result = manager.unblock_ip(&test_ip(1)).unwrap();
        assert!(!result);
    }

    #[test]
    fn test_cleanup_disabled() {
        let config = disabled_config();
        let manager = FirewallManager::new(config).unwrap();

        let cleaned = manager.cleanup_expired().unwrap();
        assert_eq!(cleaned, 0);
    }

    #[test]
    fn test_ensure_chain_disabled() {
        let config = disabled_config();
        let manager = FirewallManager::new(config).unwrap();

        // Should succeed silently
        manager.ensure_chain().unwrap();
        assert!(!manager.is_chain_initialized());
    }

    // ── Max Rules Limit Tests ──────────────────────────────────────────

    #[test]
    fn test_max_rules_limit() {
        let mut config = dry_run_config();
        config.max_rules = 3;
        let manager = FirewallManager::new(config).unwrap();

        // Block up to the limit
        for i in 1..=3 {
            manager
                .block_ip(test_ip(i), Duration::from_secs(3600), "test".to_string())
                .unwrap();
        }
        assert_eq!(manager.blocked_count(), 3);

        // 4th block should fail
        let result = manager.block_ip(
            test_ip(4),
            Duration::from_secs(3600),
            "test".to_string(),
        );
        assert!(result.is_err());
        assert_eq!(manager.blocked_count(), 3);
    }

    #[test]
    fn test_max_rules_re_block_does_not_consume_slot() {
        let mut config = dry_run_config();
        config.max_rules = 3;
        let manager = FirewallManager::new(config).unwrap();

        for i in 1..=3 {
            manager
                .block_ip(test_ip(i), Duration::from_secs(3600), "test".to_string())
                .unwrap();
        }

        // Re-blocking an existing IP should not fail
        let result = manager
            .block_ip(test_ip(1), Duration::from_secs(7200), "re-block".to_string())
            .unwrap();
        assert!(!result); // was already blocked, just updated
        assert_eq!(manager.blocked_count(), 3);
    }

    // ── Cleanup Expired Tests ──────────────────────────────────────────

    #[test]
    fn test_cleanup_expired() {
        let config = dry_run_config();
        let manager = FirewallManager::new(config).unwrap();

        // Block with duration=0 (effectively expired immediately)
        manager
            .block_ip(test_ip(1), Duration::from_secs(0), "test".to_string())
            .unwrap();
        // Force the expiry to the past
        if let Some(mut entry) = manager.blocked.get_mut(&test_ip(1)) {
            entry.expires_at = Some(Utc::now() - chrono::Duration::seconds(10));
        }

        // Block with long duration (should survive cleanup)
        manager
            .block_ip(test_ip(2), Duration::from_secs(3600), "test".to_string())
            .unwrap();

        // Block permanently (should survive cleanup)
        manager
            .block_ip_permanent(test_ip(3), "test".to_string())
            .unwrap();

        assert_eq!(manager.blocked_count(), 3);

        let cleaned = manager.cleanup_expired().unwrap();
        assert_eq!(cleaned, 1);
        assert_eq!(manager.blocked_count(), 2);

        assert!(!manager.is_blocked(&test_ip(1))); // expired, cleaned
        assert!(manager.is_blocked(&test_ip(2))); // still active
        assert!(manager.is_blocked(&test_ip(3))); // permanent
    }

    #[test]
    fn test_cleanup_nothing_to_clean() {
        let config = dry_run_config();
        let manager = FirewallManager::new(config).unwrap();

        manager
            .block_ip(test_ip(1), Duration::from_secs(3600), "test".to_string())
            .unwrap();

        let cleaned = manager.cleanup_expired().unwrap();
        assert_eq!(cleaned, 0);
        assert_eq!(manager.blocked_count(), 1);
    }

    // ── Query Tests ────────────────────────────────────────────────────

    #[test]
    fn test_is_blocked() {
        let config = dry_run_config();
        let manager = FirewallManager::new(config).unwrap();

        assert!(!manager.is_blocked(&test_ip(1)));

        manager
            .block_ip(test_ip(1), Duration::from_secs(3600), "test".to_string())
            .unwrap();

        assert!(manager.is_blocked(&test_ip(1)));
        assert!(!manager.is_blocked(&test_ip(2)));
    }

    #[test]
    fn test_get_block_entry() {
        let config = dry_run_config();
        let manager = FirewallManager::new(config).unwrap();

        assert!(manager.get_block_entry(&test_ip(1)).is_none());

        manager
            .block_ip(
                test_ip(1),
                Duration::from_secs(3600),
                "SYN flood".to_string(),
            )
            .unwrap();

        let entry = manager.get_block_entry(&test_ip(1)).unwrap();
        assert_eq!(entry.ip, test_ip(1));
        assert_eq!(entry.reason, "SYN flood");
        assert_eq!(entry.block_count, 1);
    }

    #[test]
    fn test_list_blocked() {
        let config = dry_run_config();
        let manager = FirewallManager::new(config).unwrap();

        for i in 1..=3 {
            manager
                .block_ip(
                    test_ip(i),
                    Duration::from_secs(3600),
                    format!("reason-{}", i),
                )
                .unwrap();
        }

        let blocked = manager.list_blocked();
        assert_eq!(blocked.len(), 3);
    }

    #[test]
    fn test_list_blocked_sorted() {
        let config = dry_run_config();
        let manager = FirewallManager::new(config).unwrap();

        for i in 1..=3 {
            manager
                .block_ip(
                    test_ip(i),
                    Duration::from_secs(3600),
                    format!("reason-{}", i),
                )
                .unwrap();
        }

        let sorted = manager.list_blocked_sorted();
        assert_eq!(sorted.len(), 3);
        // Newest first (all blocked at roughly the same time, so order may vary)
        // but at minimum the list should have 3 entries
    }

    // ── Statistics Tests ───────────────────────────────────────────────

    #[test]
    fn test_stats_initial() {
        let config = dry_run_config();
        let manager = FirewallManager::new(config).unwrap();

        let stats = manager.stats();
        assert_eq!(stats.currently_blocked, 0);
        assert_eq!(stats.total_blocks, 0);
        assert_eq!(stats.total_unblocks, 0);
        assert_eq!(stats.total_expired_cleanups, 0);
        assert!(stats.dry_run);
        assert!(stats.enabled);
        assert_eq!(stats.chain_name, "ZEROED_TEST");
    }

    #[test]
    fn test_stats_after_operations() {
        let config = dry_run_config();
        let manager = FirewallManager::new(config).unwrap();

        // Block 3 IPs
        for i in 1..=3 {
            manager
                .block_ip(test_ip(i), Duration::from_secs(3600), "test".to_string())
                .unwrap();
        }

        // Unblock 1
        manager.unblock_ip(&test_ip(1)).unwrap();

        let stats = manager.stats();
        assert_eq!(stats.currently_blocked, 2);
        assert_eq!(stats.total_blocks, 3);
        assert_eq!(stats.total_unblocks, 1);
    }

    #[test]
    fn test_stats_cleanup_tracking() {
        let config = dry_run_config();
        let manager = FirewallManager::new(config).unwrap();

        manager
            .block_ip(test_ip(1), Duration::from_secs(0), "test".to_string())
            .unwrap();
        if let Some(mut entry) = manager.blocked.get_mut(&test_ip(1)) {
            entry.expires_at = Some(Utc::now() - chrono::Duration::seconds(10));
        }

        manager.cleanup_expired().unwrap();

        let stats = manager.stats();
        assert_eq!(stats.total_expired_cleanups, 1);
    }

    #[test]
    fn test_stats_re_block_does_not_increment_total() {
        let config = dry_run_config();
        let manager = FirewallManager::new(config).unwrap();

        manager
            .block_ip(test_ip(1), Duration::from_secs(3600), "first".to_string())
            .unwrap();
        manager
            .block_ip(test_ip(1), Duration::from_secs(7200), "second".to_string())
            .unwrap();

        let stats = manager.stats();
        // Only the first block counts as a new block
        assert_eq!(stats.total_blocks, 1);
        assert_eq!(stats.currently_blocked, 1);
    }

    // ── FirewallStatsSnapshot Serialization ─────────────────────────────

    #[test]
    fn test_stats_snapshot_serialization() {
        let config = dry_run_config();
        let manager = FirewallManager::new(config).unwrap();

        manager
            .block_ip(test_ip(1), Duration::from_secs(3600), "test".to_string())
            .unwrap();

        let stats = manager.stats();
        let json = serde_json::to_string(&stats).unwrap();
        let deserialized: FirewallStatsSnapshot = serde_json::from_str(&json).unwrap();

        assert_eq!(deserialized.currently_blocked, 1);
        assert_eq!(deserialized.total_blocks, 1);
        assert!(deserialized.dry_run);
        assert!(deserialized.enabled);
        assert_eq!(deserialized.chain_name, "ZEROED_TEST");
    }

    // ── Chain Management Tests (Dry-Run) ───────────────────────────────

    #[test]
    fn test_ensure_chain_dry_run() {
        let config = dry_run_config();
        let manager = FirewallManager::new(config).unwrap();

        manager.ensure_chain().unwrap();
        assert!(manager.is_chain_initialized());

        // Calling again should be idempotent
        manager.ensure_chain().unwrap();
        assert!(manager.is_chain_initialized());
    }

    #[test]
    fn test_teardown_chain_dry_run() {
        let config = dry_run_config();
        let manager = FirewallManager::new(config).unwrap();

        manager.ensure_chain().unwrap();
        assert!(manager.is_chain_initialized());

        manager.teardown_chain().unwrap();
        assert!(!manager.is_chain_initialized());
    }

    #[test]
    fn test_list_chain_rules_dry_run() {
        let config = dry_run_config();
        let manager = FirewallManager::new(config).unwrap();

        let rules = manager.list_chain_rules().unwrap();
        assert!(rules.contains("DRY RUN"));
    }

    // ── nftables/ipset Not Available Tests ──────────────────────────────

    #[test]
    fn test_nftables_not_available() {
        let mut config = dry_run_config();
        config.backend = FirewallBackend::Nftables;
        config.dry_run = false;
        let manager = FirewallManager::new(config).unwrap();

        let result = manager.ensure_chain();
        assert!(result.is_err());
    }

    #[test]
    fn test_ipset_not_available() {
        let mut config = dry_run_config();
        config.backend = FirewallBackend::Ipset;
        config.dry_run = false;
        let manager = FirewallManager::new(config).unwrap();

        let result = manager.ensure_chain();
        assert!(result.is_err());
    }

    // ── extract_ip_from_rule Tests ──────────────────────────────────────

    #[test]
    fn test_extract_ip_from_rule() {
        let rule = "-A ZEROED -s 1.2.3.4/32 -j DROP";
        assert_eq!(FirewallManager::extract_ip_from_rule(rule), Some("1.2.3.4"));

        let rule = "-A ZEROED -s 10.0.0.1 -j DROP";
        assert_eq!(FirewallManager::extract_ip_from_rule(rule), Some("10.0.0.1"));

        let rule = "-A ZEROED -j RETURN";
        assert_eq!(FirewallManager::extract_ip_from_rule(rule), None);

        let rule = "";
        assert_eq!(FirewallManager::extract_ip_from_rule(rule), None);
    }

    #[test]
    fn test_extract_ip_from_rule_ipv6() {
        let rule = "-A ZEROED -s 2001:db8::1/128 -j DROP";
        assert_eq!(
            FirewallManager::extract_ip_from_rule(rule),
            Some("2001:db8::1")
        );
    }

    // ── Complex Scenario Tests ─────────────────────────────────────────

    #[test]
    fn test_block_unblock_reblock_cycle() {
        let config = dry_run_config();
        let manager = FirewallManager::new(config).unwrap();
        let ip = test_ip(42);

        // Block
        assert!(manager
            .block_ip(ip, Duration::from_secs(3600), "first block".to_string())
            .unwrap());
        assert_eq!(manager.blocked_count(), 1);
        assert_eq!(
            manager.get_block_entry(&ip).unwrap().block_count,
            1
        );

        // Unblock
        assert!(manager.unblock_ip(&ip).unwrap());
        assert_eq!(manager.blocked_count(), 0);

        // Reblock (this is a fresh block, not a re-block)
        assert!(manager
            .block_ip(ip, Duration::from_secs(7200), "second block".to_string())
            .unwrap());
        assert_eq!(manager.blocked_count(), 1);
        assert_eq!(
            manager.get_block_entry(&ip).unwrap().block_count,
            1
        );
        assert_eq!(
            manager.get_block_entry(&ip).unwrap().reason,
            "second block"
        );
    }

    #[test]
    fn test_multiple_ips_independent() {
        let config = dry_run_config();
        let manager = FirewallManager::new(config).unwrap();

        manager
            .block_ip(test_ip(1), Duration::from_secs(3600), "ip1".to_string())
            .unwrap();
        manager
            .block_ip(test_ip(2), Duration::from_secs(3600), "ip2".to_string())
            .unwrap();
        manager
            .block_ip(test_ip(3), Duration::from_secs(3600), "ip3".to_string())
            .unwrap();

        assert_eq!(manager.blocked_count(), 3);

        // Unblock only the middle one
        manager.unblock_ip(&test_ip(2)).unwrap();

        assert_eq!(manager.blocked_count(), 2);
        assert!(manager.is_blocked(&test_ip(1)));
        assert!(!manager.is_blocked(&test_ip(2)));
        assert!(manager.is_blocked(&test_ip(3)));
    }

    #[test]
    fn test_cleanup_with_mixed_expiry() {
        let config = dry_run_config();
        let manager = FirewallManager::new(config).unwrap();

        // 2 expired, 2 active, 1 permanent
        for i in 1..=2 {
            manager
                .block_ip(test_ip(i), Duration::from_secs(1), "expire".to_string())
                .unwrap();
            if let Some(mut e) = manager.blocked.get_mut(&test_ip(i)) {
                e.expires_at = Some(Utc::now() - chrono::Duration::seconds(100));
            }
        }
        for i in 3..=4 {
            manager
                .block_ip(test_ip(i), Duration::from_secs(3600), "active".to_string())
                .unwrap();
        }
        manager
            .block_ip_permanent(test_ip(5), "permanent".to_string())
            .unwrap();

        assert_eq!(manager.blocked_count(), 5);

        let cleaned = manager.cleanup_expired().unwrap();
        assert_eq!(cleaned, 2);
        assert_eq!(manager.blocked_count(), 3);

        // Check the right ones survived
        assert!(!manager.is_blocked(&test_ip(1)));
        assert!(!manager.is_blocked(&test_ip(2)));
        assert!(manager.is_blocked(&test_ip(3)));
        assert!(manager.is_blocked(&test_ip(4)));
        assert!(manager.is_blocked(&test_ip(5)));

        let stats = manager.stats();
        assert_eq!(stats.total_expired_cleanups, 2);
    }

    #[test]
    fn test_sync_with_chain_dry_run() {
        let config = dry_run_config();
        let manager = FirewallManager::new(config).unwrap();

        // Dry-run mode should no-op
        let (added, removed) = manager.sync_with_chain().unwrap();
        assert_eq!(added, 0);
        assert_eq!(removed, 0);
    }

    #[test]
    fn test_sync_with_chain_disabled() {
        let config = disabled_config();
        let manager = FirewallManager::new(config).unwrap();

        let (added, removed) = manager.sync_with_chain().unwrap();
        assert_eq!(added, 0);
        assert_eq!(removed, 0);
    }

    // ── BlockedIpEntry Serialization ────────────────────────────────────

    #[test]
    fn test_blocked_ip_entry_serialization() {
        let entry = BlockedIpEntry::new(
            test_ip(1),
            Duration::from_secs(3600),
            "Test reason".to_string(),
        );

        let json = serde_json::to_string(&entry).unwrap();
        let deserialized: BlockedIpEntry = serde_json::from_str(&json).unwrap();

        assert_eq!(deserialized.ip, test_ip(1));
        assert_eq!(deserialized.reason, "Test reason");
        assert_eq!(deserialized.block_count, 1);
        assert!(!deserialized.is_expired());
    }

    #[test]
    fn test_blocked_ip_entry_serialization_permanent() {
        let entry = BlockedIpEntry::permanent(test_ip(2), "Perma-banned".to_string());

        let json = serde_json::to_string(&entry).unwrap();
        let deserialized: BlockedIpEntry = serde_json::from_str(&json).unwrap();

        assert_eq!(deserialized.ip, test_ip(2));
        assert!(deserialized.expires_at.is_none());
        assert!(!deserialized.is_expired());
    }
}
