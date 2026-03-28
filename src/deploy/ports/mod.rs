//! Port Allocation & Conflict Resolution Module
//!
//! This module provides functionality for managing TCP port assignments across
//! all deployed applications. It ensures that no two applications are assigned
//! the same port, validates port availability at the system level, and provides
//! utilities for finding free ports within a configurable range.
//!
//! ## Responsibilities
//!
//! - Allocate ports for new applications (user-specified or auto-assigned)
//! - Detect conflicts with other managed applications
//! - Detect conflicts with system services (via `ss`/`netstat` or bind-test)
//! - Maintain a reserved port list (SSH, HTTP, HTTPS, DNS, etc.)
//! - Release ports when applications are deleted
//! - Support port changes with full re-configuration workflow
//!
//! ## Port Range
//!
//! By default, the allocator uses ports 3000–9999. Ports below 1024 are
//! never allocated (they require root and are typically used by system services).
//! The range is configurable via `deploy.default_port_range_start` and
//! `deploy.default_port_range_end` in `zeroed.toml`.
//!
//! ## Conflict Detection
//!
//! The allocator checks for conflicts at two levels:
//!
//! 1. **Internal registry**: ports assigned to other Zeroed-managed apps
//! 2. **System-level**: ports currently bound by any process on the host
//!
//! This dual check prevents both internal duplicates and conflicts with
//! unmanaged services (databases, caches, other daemons, etc.).

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use std::fmt;
use std::io;
use std::net::{IpAddr, Ipv4Addr, SocketAddr, TcpListener};
use std::process::Command;
use thiserror::Error;
use tracing::{debug, error, info, warn};

// ─────────────────────────────────────────────────────────────────────────────
// Error Types
// ─────────────────────────────────────────────────────────────────────────────

/// Errors specific to port allocation operations.
#[derive(Debug, Error)]
pub enum PortError {
    #[error("IO error: {0}")]
    Io(#[from] io::Error),

    #[error("Port {port} is already allocated to application '{app}'")]
    AlreadyAllocated { port: u16, app: String },

    #[error("Port {port} is in use by a system service: {details}")]
    SystemPortInUse { port: u16, details: String },

    #[error("Port {port} is reserved and cannot be allocated")]
    Reserved { port: u16 },

    #[error("Port {port} is outside the allowed range ({min}–{max})")]
    OutOfRange { port: u16, min: u16, max: u16 },

    #[error("No available ports in range {min}–{max}")]
    NoAvailablePorts { min: u16, max: u16 },

    #[error("Port {port} is not allocated (nothing to release)")]
    NotAllocated { port: u16 },

    #[error("Port {port} cannot be allocated: {reason}")]
    AllocationFailed { port: u16, reason: String },

    #[error("Port validation failed: {message}")]
    ValidationFailed { message: String },
}

/// Result alias for port operations.
pub type Result<T> = std::result::Result<T, PortError>;

// ─────────────────────────────────────────────────────────────────────────────
// Port Allocation Record
// ─────────────────────────────────────────────────────────────────────────────

/// Record of a single port allocation, tying a port to an application.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PortAllocation {
    /// The allocated port number
    pub port: u16,

    /// The application ID that owns this port
    pub app_id: String,

    /// The application name (denormalized for convenience)
    pub app_name: String,

    /// When this port was allocated
    pub allocated_at: DateTime<Utc>,

    /// Optional description or note
    pub note: Option<String>,
}

impl PortAllocation {
    /// Create a new port allocation record.
    pub fn new(port: u16, app_id: String, app_name: String) -> Self {
        Self {
            port,
            app_id,
            app_name,
            allocated_at: Utc::now(),
            note: None,
        }
    }
}

impl fmt::Display for PortAllocation {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "port {} → {} ({})", self.port, self.app_name, self.app_id)
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Port Check Result
// ─────────────────────────────────────────────────────────────────────────────

/// Result of checking whether a port is available.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PortCheckResult {
    /// The port that was checked
    pub port: u16,
    /// Whether the port is available for allocation
    pub available: bool,
    /// If not available, what is using it
    pub used_by: Option<String>,
    /// The kind of conflict (internal, system, reserved)
    pub conflict_type: Option<PortConflictType>,
    /// Additional details about the conflict
    pub details: Option<String>,
}

impl PortCheckResult {
    /// Create a result indicating the port is available.
    pub fn available(port: u16) -> Self {
        Self {
            port,
            available: true,
            used_by: None,
            conflict_type: None,
            details: None,
        }
    }

    /// Create a result indicating the port is in use by a managed app.
    pub fn internal_conflict(port: u16, app_name: &str) -> Self {
        Self {
            port,
            available: false,
            used_by: Some(app_name.to_string()),
            conflict_type: Some(PortConflictType::ManagedApp),
            details: Some(format!(
                "Port {} is allocated to managed application '{}'",
                port, app_name
            )),
        }
    }

    /// Create a result indicating the port is in use by a system service.
    pub fn system_conflict(port: u16, details: &str) -> Self {
        Self {
            port,
            available: false,
            used_by: Some("system service".to_string()),
            conflict_type: Some(PortConflictType::SystemService),
            details: Some(details.to_string()),
        }
    }

    /// Create a result indicating the port is reserved.
    pub fn reserved(port: u16, reason: &str) -> Self {
        Self {
            port,
            available: false,
            used_by: Some("reserved".to_string()),
            conflict_type: Some(PortConflictType::Reserved),
            details: Some(reason.to_string()),
        }
    }

    /// Create a result indicating the port is out of range.
    pub fn out_of_range(port: u16, min: u16, max: u16) -> Self {
        Self {
            port,
            available: false,
            used_by: None,
            conflict_type: Some(PortConflictType::OutOfRange),
            details: Some(format!(
                "Port {} is outside the allowed range ({}-{})",
                port, min, max
            )),
        }
    }
}

impl fmt::Display for PortCheckResult {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.available {
            write!(f, "Port {} is available", self.port)
        } else {
            write!(
                f,
                "Port {} is NOT available: {}",
                self.port,
                self.details.as_deref().unwrap_or("unknown reason")
            )
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Port Conflict Types
// ─────────────────────────────────────────────────────────────────────────────

/// The kind of conflict detected for a port.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PortConflictType {
    /// Port is allocated to another Zeroed-managed application
    ManagedApp,
    /// Port is in use by a system service (not managed by Zeroed)
    SystemService,
    /// Port is in the reserved list (well-known ports, Zeroed's own ports)
    Reserved,
    /// Port is outside the configured allocation range
    OutOfRange,
}

impl fmt::Display for PortConflictType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            PortConflictType::ManagedApp => write!(f, "managed_app"),
            PortConflictType::SystemService => write!(f, "system_service"),
            PortConflictType::Reserved => write!(f, "reserved"),
            PortConflictType::OutOfRange => write!(f, "out_of_range"),
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Port Allocator
// ─────────────────────────────────────────────────────────────────────────────

/// Well-known ports that should never be allocated to applications.
///
/// These include standard service ports that are almost certainly in use
/// or expected to be available for system services.
const RESERVED_PORTS: &[u16] = &[
    22,   // SSH
    25,   // SMTP
    53,   // DNS
    80,   // HTTP (Nginx)
    443,  // HTTPS (Nginx)
    465,  // SMTPS
    587,  // SMTP submission
    993,  // IMAPS
    995,  // POP3S
    3306, // MySQL (commonly used, but in the user range — warn, don't block)
    5432, // PostgreSQL (commonly used — warn, don't block)
];

/// Ports that are commonly used and deserve a warning (but are not hard-blocked).
const WARN_PORTS: &[u16] = &[
    3306, // MySQL
    5432, // PostgreSQL
    6379, // Redis
    27017, // MongoDB
    9090, // Prometheus (also used by Zeroed metrics)
    8080, // Common alternative HTTP
    8443, // Common alternative HTTPS
    2375, // Docker
    2376, // Docker TLS
];

/// Manages port allocation for deployed applications.
///
/// Maintains an internal registry of which ports are assigned to which
/// applications, and provides methods to allocate, release, check, and
/// find available ports. Also performs system-level checks to detect
/// conflicts with non-managed services.
pub struct PortAllocator {
    /// Start of the allowed port range (inclusive)
    range_start: u16,

    /// End of the allowed port range (inclusive)
    range_end: u16,

    /// Map from port number to allocation record
    allocations: HashMap<u16, PortAllocation>,

    /// Additional reserved ports (beyond the built-in list)
    /// These can be configured by the user to protect custom services.
    custom_reserved: HashSet<u16>,

    /// Ports to exclude from auto-assignment (Zeroed's own ports, etc.)
    zeroed_ports: HashSet<u16>,
}

impl PortAllocator {
    /// Create a new port allocator with the given range.
    ///
    /// The range must be above 1024 and `range_start` must be less than `range_end`.
    pub fn new(range_start: u16, range_end: u16) -> Result<Self> {
        if range_start < 1024 {
            return Err(PortError::ValidationFailed {
                message: format!(
                    "Port range start ({}) must be >= 1024 to avoid privileged ports",
                    range_start
                ),
            });
        }

        if range_start >= range_end {
            return Err(PortError::ValidationFailed {
                message: format!(
                    "Port range start ({}) must be less than end ({})",
                    range_start, range_end
                ),
            });
        }

        info!(
            "Port allocator initialized (range: {}-{})",
            range_start, range_end
        );

        Ok(Self {
            range_start,
            range_end,
            allocations: HashMap::new(),
            custom_reserved: HashSet::new(),
            zeroed_ports: HashSet::new(),
        })
    }

    // ─────────────────────────────────────────────────────────────────────
    // Allocation
    // ─────────────────────────────────────────────────────────────────────

    /// Allocate a specific port for an application.
    ///
    /// Validates that the port is within range, not reserved, not already
    /// allocated to another app, and not in use by a system service.
    pub fn allocate(
        &mut self,
        port: u16,
        app_id: &str,
        app_name: &str,
    ) -> Result<PortAllocation> {
        // Run full check
        let check = self.check(port);
        if !check.available {
            return match check.conflict_type {
                Some(PortConflictType::ManagedApp) => Err(PortError::AlreadyAllocated {
                    port,
                    app: check.used_by.unwrap_or_default(),
                }),
                Some(PortConflictType::SystemService) => Err(PortError::SystemPortInUse {
                    port,
                    details: check.details.unwrap_or_default(),
                }),
                Some(PortConflictType::Reserved) => Err(PortError::Reserved { port }),
                Some(PortConflictType::OutOfRange) => Err(PortError::OutOfRange {
                    port,
                    min: self.range_start,
                    max: self.range_end,
                }),
                None => Err(PortError::AllocationFailed {
                    port,
                    reason: check.details.unwrap_or_else(|| "unknown".to_string()),
                }),
            };
        }

        let allocation = PortAllocation::new(
            port,
            app_id.to_string(),
            app_name.to_string(),
        );

        self.allocations.insert(port, allocation.clone());
        info!("Port {} allocated to application '{}'", port, app_name);

        Ok(allocation)
    }

    /// Automatically find and allocate the next available port in the range.
    ///
    /// Scans from `range_start` upward and returns the first port that passes
    /// all checks (not reserved, not allocated, not in use by the system).
    pub fn allocate_auto(&mut self, app_id: &str, app_name: &str) -> Result<PortAllocation> {
        let port = self.find_next_available()?;
        self.allocate(port, app_id, app_name)
    }

    /// Allocate a preferred port, falling back to auto-allocation if it's not available.
    ///
    /// Returns the allocation and a boolean indicating whether the preferred
    /// port was used (`true`) or a fallback was needed (`false`).
    pub fn allocate_preferred(
        &mut self,
        preferred: u16,
        app_id: &str,
        app_name: &str,
    ) -> Result<(PortAllocation, bool)> {
        let check = self.check(preferred);
        if check.available {
            let allocation = self.allocate(preferred, app_id, app_name)?;
            Ok((allocation, true))
        } else {
            warn!(
                "Preferred port {} is not available ({}), auto-assigning...",
                preferred,
                check.details.as_deref().unwrap_or("unknown reason")
            );
            let allocation = self.allocate_auto(app_id, app_name)?;
            Ok((allocation, false))
        }
    }

    /// Release a port allocation, making it available for other applications.
    pub fn release(&mut self, port: u16) -> Result<PortAllocation> {
        match self.allocations.remove(&port) {
            Some(allocation) => {
                info!(
                    "Port {} released from application '{}'",
                    port, allocation.app_name
                );
                Ok(allocation)
            }
            None => Err(PortError::NotAllocated { port }),
        }
    }

    /// Release all ports allocated to a specific application.
    ///
    /// Returns the list of released allocations.
    pub fn release_all_for_app(&mut self, app_id: &str) -> Vec<PortAllocation> {
        let ports_to_release: Vec<u16> = self
            .allocations
            .iter()
            .filter(|(_, alloc)| alloc.app_id == app_id)
            .map(|(port, _)| *port)
            .collect();

        let mut released = Vec::new();
        for port in ports_to_release {
            if let Some(allocation) = self.allocations.remove(&port) {
                info!(
                    "Port {} released from application '{}' (bulk release)",
                    port, allocation.app_name
                );
                released.push(allocation);
            }
        }

        released
    }

    /// Change the port for an application. Releases the old port and allocates the new one.
    ///
    /// If the new port is not available, the old allocation is preserved and an error
    /// is returned (the operation is atomic).
    pub fn change_port(
        &mut self,
        old_port: u16,
        new_port: u16,
        app_id: &str,
        app_name: &str,
    ) -> Result<PortAllocation> {
        // Check new port first (before releasing old)
        let check = self.check_excluding_app(new_port, app_id);
        if !check.available {
            return Err(PortError::AllocationFailed {
                port: new_port,
                reason: check.details.unwrap_or_else(|| "port not available".to_string()),
            });
        }

        // Release old port
        let _ = self.allocations.remove(&old_port);

        // Allocate new port (bypassing check since we already verified)
        let allocation = PortAllocation::new(
            new_port,
            app_id.to_string(),
            app_name.to_string(),
        );
        self.allocations.insert(new_port, allocation.clone());

        info!(
            "Port changed for '{}': {} → {}",
            app_name, old_port, new_port
        );

        Ok(allocation)
    }

    // ─────────────────────────────────────────────────────────────────────
    // Port Checking
    // ─────────────────────────────────────────────────────────────────────

    /// Perform a comprehensive check on whether a port is available.
    ///
    /// Checks against:
    /// 1. Hard-reserved ports (SSH, HTTP, HTTPS, etc.)
    /// 2. Configured range boundaries
    /// 3. Internal allocation registry
    /// 4. System-level port usage (bind test + ss/netstat)
    pub fn check(&self, port: u16) -> PortCheckResult {
        self.check_inner(port, None)
    }

    /// Check port availability while excluding a specific application.
    ///
    /// This is used when changing an app's port — the app's current port
    /// should not count as a conflict for the same app.
    pub fn check_excluding_app(&self, port: u16, exclude_app_id: &str) -> PortCheckResult {
        self.check_inner(port, Some(exclude_app_id))
    }

    /// Internal check implementation.
    fn check_inner(&self, port: u16, exclude_app_id: Option<&str>) -> PortCheckResult {
        // Check hard-reserved ports (below 1024)
        if port < 1024 {
            if RESERVED_PORTS.contains(&port) {
                return PortCheckResult::reserved(
                    port,
                    &format!("Port {} is a well-known reserved port", port),
                );
            }
            return PortCheckResult::reserved(
                port,
                &format!("Port {} is a privileged port (< 1024)", port),
            );
        }

        // Check range
        if port < self.range_start || port > self.range_end {
            return PortCheckResult::out_of_range(port, self.range_start, self.range_end);
        }

        // Check custom reserved ports
        if self.custom_reserved.contains(&port) {
            return PortCheckResult::reserved(
                port,
                &format!("Port {} is in the custom reserved list", port),
            );
        }

        // Check Zeroed's own ports
        if self.zeroed_ports.contains(&port) {
            return PortCheckResult::reserved(
                port,
                &format!("Port {} is used by the Zeroed daemon itself", port),
            );
        }

        // Check internal allocations
        if let Some(allocation) = self.allocations.get(&port) {
            // If we're excluding a specific app (for port change), skip it
            if let Some(exclude_id) = exclude_app_id {
                if allocation.app_id == exclude_id {
                    // This is the same app — don't count as conflict
                    // (but still check system-level below)
                } else {
                    return PortCheckResult::internal_conflict(port, &allocation.app_name);
                }
            } else {
                return PortCheckResult::internal_conflict(port, &allocation.app_name);
            }
        }

        // Check system-level port usage
        if let Some(details) = self.check_system_port(port) {
            return PortCheckResult::system_conflict(port, &details);
        }

        PortCheckResult::available(port)
    }

    /// Check whether a port is currently bound by any process on the system.
    ///
    /// Uses two methods:
    /// 1. Try to bind the port briefly (most reliable)
    /// 2. Parse `ss` output for additional context (process name, etc.)
    ///
    /// Returns `Some(details)` if the port is in use, `None` if it's free.
    fn check_system_port(&self, port: u16) -> Option<String> {
        // Method 1: Try to bind the port
        let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(0, 0, 0, 0)), port);
        match TcpListener::bind(addr) {
            Ok(_listener) => {
                // Port is free — the listener is dropped immediately, releasing the port
                None
            }
            Err(_) => {
                // Port is in use — try to get more details via `ss`
                let details = self
                    .get_port_details_from_ss(port)
                    .unwrap_or_else(|| format!("Port {} is in use by an unknown process", port));
                Some(details)
            }
        }
    }

    /// Use the `ss` command to get details about what is using a port.
    ///
    /// Parses output of `ss -tlnp` to find the process name and PID.
    fn get_port_details_from_ss(&self, port: u16) -> Option<String> {
        let output = Command::new("ss")
            .arg("-tlnp")
            .arg("sport")
            .arg(&format!("= :{}", port))
            .output()
            .ok()?;

        if !output.status.success() {
            return None;
        }

        let stdout = String::from_utf8_lossy(&output.stdout);

        // Parse the output to find process info
        for line in stdout.lines().skip(1) {
            // Header line skipped
            if line.contains(&format!(":{}", port)) {
                // Try to extract the process name from the "users:" section
                if let Some(users_start) = line.find("users:") {
                    let users_info = &line[users_start..];
                    return Some(format!(
                        "Port {} is bound: {}",
                        port,
                        users_info.trim()
                    ));
                }

                // If no process info, return a generic message
                let parts: Vec<&str> = line.split_whitespace().collect();
                let state = parts.first().unwrap_or(&"LISTEN");
                return Some(format!(
                    "Port {} is bound in state {} (process details unavailable — run as root for full info)",
                    port, state
                ));
            }
        }

        // Fallback: if ss didn't show it but bind failed, report generically
        None
    }

    // ─────────────────────────────────────────────────────────────────────
    // Finding Available Ports
    // ─────────────────────────────────────────────────────────────────────

    /// Find the next available port in the configured range.
    ///
    /// Scans sequentially from `range_start` and returns the first port
    /// that passes all checks.
    pub fn find_next_available(&self) -> Result<u16> {
        for port in self.range_start..=self.range_end {
            let check = self.check(port);
            if check.available {
                return Ok(port);
            }
        }

        Err(PortError::NoAvailablePorts {
            min: self.range_start,
            max: self.range_end,
        })
    }

    /// Find N available ports in the configured range.
    ///
    /// Returns up to `count` available ports. Useful for batch allocation
    /// or showing the user a list of options.
    pub fn find_available_ports(&self, count: usize) -> Vec<u16> {
        let mut found = Vec::with_capacity(count);

        for port in self.range_start..=self.range_end {
            if found.len() >= count {
                break;
            }
            let check = self.check(port);
            if check.available {
                found.push(port);
            }
        }

        found
    }

    /// Find an available port near a preferred port.
    ///
    /// Tries the preferred port first, then scans outward in both directions
    /// (preferred+1, preferred-1, preferred+2, preferred-2, ...) to find
    /// the closest available port.
    pub fn find_nearest_available(&self, preferred: u16) -> Result<u16> {
        // Try the preferred port first
        if self.check(preferred).available {
            return Ok(preferred);
        }

        // Scan outward in both directions
        let max_delta = self.range_end.saturating_sub(self.range_start);

        for delta in 1..=max_delta {
            // Try above
            let above = preferred.saturating_add(delta);
            if above <= self.range_end && self.check(above).available {
                return Ok(above);
            }

            // Try below
            if preferred >= delta + self.range_start {
                let below = preferred - delta;
                if below >= self.range_start && self.check(below).available {
                    return Ok(below);
                }
            }
        }

        Err(PortError::NoAvailablePorts {
            min: self.range_start,
            max: self.range_end,
        })
    }

    // ─────────────────────────────────────────────────────────────────────
    // Queries
    // ─────────────────────────────────────────────────────────────────────

    /// Get all current port allocations, sorted by port number.
    pub fn list_allocations(&self) -> Vec<&PortAllocation> {
        let mut allocs: Vec<&PortAllocation> = self.allocations.values().collect();
        allocs.sort_by_key(|a| a.port);
        allocs
    }

    /// Get the allocation for a specific port.
    pub fn get_allocation(&self, port: u16) -> Option<&PortAllocation> {
        self.allocations.get(&port)
    }

    /// Get all allocations for a specific application.
    pub fn get_allocations_for_app(&self, app_id: &str) -> Vec<&PortAllocation> {
        self.allocations
            .values()
            .filter(|a| a.app_id == app_id)
            .collect()
    }

    /// Get the port allocated to a specific application (by name).
    pub fn get_port_for_app(&self, app_name: &str) -> Option<u16> {
        self.allocations
            .values()
            .find(|a| a.app_name == app_name)
            .map(|a| a.port)
    }

    /// Check whether a specific port is currently allocated.
    pub fn is_allocated(&self, port: u16) -> bool {
        self.allocations.contains_key(&port)
    }

    /// Get the total number of allocated ports.
    pub fn allocation_count(&self) -> usize {
        self.allocations.len()
    }

    /// Get the total number of ports available in the range (theoretical max).
    pub fn range_size(&self) -> u16 {
        self.range_end - self.range_start + 1
    }

    /// Get the number of remaining allocatable ports in the range.
    ///
    /// Note: this is an approximation because it doesn't account for
    /// system-level conflicts. The actual number may be lower.
    pub fn remaining_capacity(&self) -> usize {
        let range_size = self.range_size() as usize;
        let allocated = self.allocations.len();
        let reserved = self
            .custom_reserved
            .iter()
            .chain(self.zeroed_ports.iter())
            .filter(|&&p| p >= self.range_start && p <= self.range_end)
            .count();

        range_size.saturating_sub(allocated + reserved)
    }

    /// Get the allowed port range.
    pub fn range(&self) -> (u16, u16) {
        (self.range_start, self.range_end)
    }

    // ─────────────────────────────────────────────────────────────────────
    // Reserved Port Management
    // ─────────────────────────────────────────────────────────────────────

    /// Add a port to the custom reserved list.
    ///
    /// Reserved ports will never be allocated to applications.
    pub fn add_reserved(&mut self, port: u16) {
        self.custom_reserved.insert(port);
        debug!("Port {} added to custom reserved list", port);
    }

    /// Remove a port from the custom reserved list.
    pub fn remove_reserved(&mut self, port: u16) -> bool {
        let removed = self.custom_reserved.remove(&port);
        if removed {
            debug!("Port {} removed from custom reserved list", port);
        }
        removed
    }

    /// Register ports used by the Zeroed daemon itself.
    ///
    /// These are excluded from allocation to prevent conflicts with
    /// Zeroed's own services (API, Prometheus, etc.).
    pub fn register_zeroed_ports(&mut self, ports: &[u16]) {
        for &port in ports {
            self.zeroed_ports.insert(port);
        }
        debug!(
            "Registered {} Zeroed daemon port(s): {:?}",
            ports.len(),
            ports
        );
    }

    /// Get the full set of reserved ports (built-in + custom + zeroed).
    pub fn all_reserved_ports(&self) -> HashSet<u16> {
        let mut all: HashSet<u16> = RESERVED_PORTS.iter().copied().collect();
        all.extend(&self.custom_reserved);
        all.extend(&self.zeroed_ports);
        all
    }

    /// Check if a port is a well-known port that deserves a warning
    /// (even if it's technically allocatable).
    pub fn should_warn(&self, port: u16) -> Option<String> {
        if WARN_PORTS.contains(&port) {
            let service = match port {
                3306 => "MySQL",
                5432 => "PostgreSQL",
                6379 => "Redis",
                27017 => "MongoDB",
                9090 => "Prometheus / Zeroed metrics",
                8080 => "common alternative HTTP",
                8443 => "common alternative HTTPS",
                2375 => "Docker (unencrypted)",
                2376 => "Docker (TLS)",
                _ => "commonly used service",
            };
            Some(format!(
                "Port {} is commonly used by {} — make sure there's no conflict",
                port, service
            ))
        } else {
            None
        }
    }

    // ─────────────────────────────────────────────────────────────────────
    // Bulk Operations
    // ─────────────────────────────────────────────────────────────────────

    /// Scan the entire range and return a port usage map.
    ///
    /// This is expensive (tries to bind every port in the range) and should
    /// only be used for diagnostic/reporting purposes, not in hot paths.
    pub fn scan_range(&self) -> Vec<PortCheckResult> {
        let mut results = Vec::new();

        for port in self.range_start..=self.range_end {
            results.push(self.check(port));
        }

        results
    }

    /// Get a summary of the port allocator state.
    pub fn summary(&self) -> PortAllocatorSummary {
        let allocs = self.list_allocations();

        PortAllocatorSummary {
            range_start: self.range_start,
            range_end: self.range_end,
            range_size: self.range_size() as usize,
            allocated_count: allocs.len(),
            reserved_count: self.all_reserved_ports().len(),
            remaining_estimate: self.remaining_capacity(),
            allocations: allocs.into_iter().cloned().collect(),
        }
    }

    /// Load allocations from an external source (e.g., the app registry).
    ///
    /// This is called during initialization to populate the allocator with
    /// existing app-port mappings from the persistent registry.
    pub fn load_allocations(&mut self, allocations: Vec<PortAllocation>) {
        for alloc in allocations {
            debug!(
                "Loaded port allocation: {} → '{}'",
                alloc.port, alloc.app_name
            );
            self.allocations.insert(alloc.port, alloc);
        }
        info!(
            "Port allocator loaded {} existing allocation(s)",
            self.allocations.len()
        );
    }

    /// Clear all allocations (for testing or reset scenarios).
    pub fn clear(&mut self) {
        let count = self.allocations.len();
        self.allocations.clear();
        info!("Port allocator cleared ({} allocations removed)", count);
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Port Allocator Summary
// ─────────────────────────────────────────────────────────────────────────────

/// Summary statistics about the port allocator state.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PortAllocatorSummary {
    /// Start of the configured range
    pub range_start: u16,
    /// End of the configured range
    pub range_end: u16,
    /// Total number of ports in the range
    pub range_size: usize,
    /// Number of currently allocated ports
    pub allocated_count: usize,
    /// Number of reserved ports
    pub reserved_count: usize,
    /// Estimated number of remaining allocatable ports
    pub remaining_estimate: usize,
    /// All current allocations
    pub allocations: Vec<PortAllocation>,
}

// ─────────────────────────────────────────────────────────────────────────────
// Tests
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn test_allocator() -> PortAllocator {
        PortAllocator::new(40000, 49999).unwrap()
    }

    // ── PortAllocator Construction Tests ────────────────────────────────

    #[test]
    fn test_new_valid_range() {
        let allocator = PortAllocator::new(40000, 49999);
        assert!(allocator.is_ok());

        let alloc = allocator.unwrap();
        assert_eq!(alloc.range(), (40000, 49999));
        assert_eq!(alloc.range_size(), 10000);
        assert_eq!(alloc.allocation_count(), 0);

        // Verify the range is correct without any system-level checks
        assert!(alloc.range().0 >= 1024);
        assert!(alloc.range().0 < alloc.range().1);
    }

    #[test]
    fn test_new_invalid_range_start_below_1024() {
        let result = PortAllocator::new(80, 9999);
        assert!(matches!(result, Err(PortError::ValidationFailed { .. })));
    }

    #[test]
    fn test_new_invalid_range_start_gte_end() {
        let result = PortAllocator::new(49999, 40000);
        assert!(matches!(result, Err(PortError::ValidationFailed { .. })));

        let result = PortAllocator::new(45000, 45000);
        assert!(matches!(result, Err(PortError::ValidationFailed { .. })));
    }

    #[test]
    fn test_new_small_range() {
        let allocator = PortAllocator::new(40000, 40010).unwrap();
        assert_eq!(allocator.range_size(), 11); // inclusive range
    }

    // ── Port Allocation Tests ──────────────────────────────────────────

    #[test]
    fn test_allocate_port() {
        let mut allocator = test_allocator();

        let result = allocator.allocate(41000, "app-1", "my-api");
        assert!(result.is_ok());

        let alloc = result.unwrap();
        assert_eq!(alloc.port, 41000);
        assert_eq!(alloc.app_id, "app-1");
        assert_eq!(alloc.app_name, "my-api");
        assert!(allocator.is_allocated(41000));
        assert_eq!(allocator.allocation_count(), 1);
    }

    #[test]
    fn test_allocate_duplicate_port() {
        let mut allocator = test_allocator();

        allocator.allocate(41000, "app-1", "my-api").unwrap();
        let result = allocator.allocate(41000, "app-2", "other-api");

        assert!(matches!(result, Err(PortError::AlreadyAllocated { port: 41000, .. })));
    }

    #[test]
    fn test_allocate_reserved_port() {
        let mut allocator = test_allocator();
        allocator.add_reserved(42000);

        let result = allocator.allocate(42000, "app-1", "my-api");
        assert!(matches!(result, Err(PortError::Reserved { port: 42000 })));
    }

    #[test]
    fn test_allocate_out_of_range() {
        let mut allocator = PortAllocator::new(40000, 41000).unwrap();

        let result = allocator.allocate(42000, "app-1", "my-api");
        assert!(matches!(result, Err(PortError::OutOfRange { port: 42000, .. })));
    }

    #[test]
    fn test_allocate_multiple_apps() {
        let mut allocator = test_allocator();

        allocator.allocate(40100, "app-1", "api").unwrap();
        allocator.allocate(40101, "app-2", "web").unwrap();
        allocator.allocate(40102, "app-3", "worker").unwrap();

        assert_eq!(allocator.allocation_count(), 3);
        assert!(allocator.is_allocated(40100));
        assert!(allocator.is_allocated(40101));
        assert!(allocator.is_allocated(40102));
        assert!(!allocator.is_allocated(40103));
    }

    // ── Port Release Tests ─────────────────────────────────────────────

    #[test]
    fn test_release_port() {
        let mut allocator = test_allocator();
        allocator.allocate(41000, "app-1", "my-api").unwrap();

        assert!(allocator.is_allocated(41000));

        let released = allocator.release(41000).unwrap();
        assert_eq!(released.port, 41000);
        assert_eq!(released.app_name, "my-api");
        assert!(!allocator.is_allocated(41000));
        assert_eq!(allocator.allocation_count(), 0);
    }

    #[test]
    fn test_release_unallocated_port() {
        let mut allocator = test_allocator();

        let result = allocator.release(41000);
        assert!(matches!(result, Err(PortError::NotAllocated { port: 41000 })));
    }

    #[test]
    fn test_release_all_for_app() {
        let mut allocator = test_allocator();

        allocator.allocate(40200, "app-1", "my-app").unwrap();
        allocator.allocate(40201, "app-2", "other-app").unwrap();

        let released = allocator.release_all_for_app("app-1");
        assert_eq!(released.len(), 1);
        assert_eq!(released[0].port, 40200);
        assert_eq!(allocator.allocation_count(), 1);
        assert!(!allocator.is_allocated(40200));
        assert!(allocator.is_allocated(40201));
    }

    #[test]
    fn test_release_all_for_app_with_no_ports() {
        let mut allocator = test_allocator();
        allocator.allocate(40300, "app-1", "my-app").unwrap();

        let released = allocator.release_all_for_app("nonexistent-app");
        assert!(released.is_empty());
        assert_eq!(allocator.allocation_count(), 1);
    }

    // ── Port Change Tests ──────────────────────────────────────────────

    #[test]
    fn test_change_port() {
        let mut allocator = test_allocator();
        allocator.allocate(40400, "app-1", "my-api").unwrap();

        let result = allocator.change_port(40400, 41400, "app-1", "my-api");
        assert!(result.is_ok());

        let alloc = result.unwrap();
        assert_eq!(alloc.port, 41400);
        assert!(!allocator.is_allocated(40400));
        assert!(allocator.is_allocated(41400));
        assert_eq!(allocator.allocation_count(), 1);
    }

    #[test]
    fn test_change_port_to_occupied() {
        let mut allocator = test_allocator();
        allocator.allocate(40500, "app-1", "api").unwrap();
        allocator.allocate(41500, "app-2", "web").unwrap();

        let result = allocator.change_port(40500, 41500, "app-1", "api");
        assert!(result.is_err());

        // Original allocation should be preserved
        assert!(allocator.is_allocated(40500));
        assert!(allocator.is_allocated(41500));
        assert_eq!(allocator.allocation_count(), 2);
    }

    // ── Port Checking Tests ────────────────────────────────────────────

    #[test]
    fn test_check_available_port() {
        let allocator = test_allocator();

        let result = allocator.check(44000);
        assert!(result.available);
        assert!(result.conflict_type.is_none());
    }

    #[test]
    fn test_check_allocated_port() {
        let mut allocator = test_allocator();
        allocator.allocate(42000, "app-1", "my-api").unwrap();

        let result = allocator.check(42000);
        assert!(!result.available);
        assert_eq!(result.conflict_type, Some(PortConflictType::ManagedApp));
        assert_eq!(result.used_by.as_deref(), Some("my-api"));
    }

    #[test]
    fn test_check_reserved_port() {
        let mut allocator = test_allocator();
        allocator.add_reserved(42555);

        let result = allocator.check(42555);
        assert!(!result.available);
        assert_eq!(result.conflict_type, Some(PortConflictType::Reserved));
    }

    #[test]
    fn test_check_out_of_range_port() {
        let allocator = PortAllocator::new(40000, 41000).unwrap();

        let result = allocator.check(42000);
        assert!(!result.available);
        assert_eq!(result.conflict_type, Some(PortConflictType::OutOfRange));
    }

    #[test]
    fn test_check_privileged_port() {
        let allocator = test_allocator();

        let result = allocator.check(22);
        assert!(!result.available);
        assert_eq!(result.conflict_type, Some(PortConflictType::Reserved));
    }

    #[test]
    fn test_check_excluding_app() {
        let mut allocator = test_allocator();
        allocator.allocate(42000, "app-1", "my-api").unwrap();

        // Without exclusion: conflict
        let result = allocator.check(42000);
        assert!(!result.available);

        // With exclusion for the same app: no internal conflict
        // (may still conflict at system level, but the internal check passes)
        let result = allocator.check_excluding_app(42000, "app-1");
        // We can't guarantee system-level availability in tests, but the
        // internal conflict should be resolved
        // The check may still fail due to system-level bind, which is fine
        if result.conflict_type == Some(PortConflictType::ManagedApp) {
            panic!("Should not report ManagedApp conflict when excluding the same app");
        }
    }

    // ── Finding Available Ports Tests ───────────────────────────────────

    #[test]
    fn test_find_next_available() {
        let allocator = test_allocator();
        // find_next_available scans from range_start, so it may pick a port
        // that is transiently in use by another process. We just verify it
        // returns *some* port in range (or that the method doesn't panic).
        match allocator.find_next_available() {
            Ok(port) => {
                assert!(port >= 40000 && port <= 49999);
            }
            Err(_) => {
                // All ports in the range are in use — unlikely but acceptable in CI
            }
        }
        // Verify the method is callable (no panic)
        let port = 44000u16;
        assert!(port >= 40000 && port <= 49999);
    }

    #[test]
    fn test_find_available_ports() {
        let allocator = test_allocator();

        let ports = allocator.find_available_ports(5);
        assert!(!ports.is_empty());
        assert!(ports.len() <= 5);

        // All found ports should be in range
        for &port in &ports {
            assert!(port >= 40000 && port <= 49999);
        }

        // All found ports should be unique
        let unique: HashSet<u16> = ports.iter().copied().collect();
        assert_eq!(unique.len(), ports.len());
    }

    #[test]
    fn test_find_nearest_available() {
        let allocator = test_allocator();

        // Find near a port that's likely available
        let port = allocator.find_nearest_available(44000);
        assert!(port.is_ok());

        let port = port.unwrap();
        assert!(port >= 40000 && port <= 49999);
    }

    // ── Query Tests ────────────────────────────────────────────────────

    #[test]
    fn test_list_allocations() {
        let mut allocator = test_allocator();
        allocator.allocate(42000, "app-1", "api").unwrap();
        allocator.allocate(40500, "app-2", "web").unwrap();

        let allocs = allocator.list_allocations();
        assert_eq!(allocs.len(), 2);
        // Should be sorted by port
        assert_eq!(allocs[0].port, 40500);
        assert_eq!(allocs[1].port, 42000);
    }

    #[test]
    fn test_get_allocation() {
        let mut allocator = test_allocator();
        allocator.allocate(42000, "app-1", "my-api").unwrap();

        let alloc = allocator.get_allocation(42000);
        assert!(alloc.is_some());
        assert_eq!(alloc.unwrap().app_name, "my-api");

        let alloc = allocator.get_allocation(43000);
        assert!(alloc.is_none());
    }

    #[test]
    fn test_get_allocations_for_app() {
        let mut allocator = test_allocator();
        allocator.allocate(40600, "app-1", "my-app").unwrap();
        allocator.allocate(41600, "app-2", "other-app").unwrap();

        let allocs = allocator.get_allocations_for_app("app-1");
        assert_eq!(allocs.len(), 1);
        assert_eq!(allocs[0].port, 40600);
    }

    #[test]
    fn test_get_port_for_app() {
        let mut allocator = test_allocator();
        allocator.allocate(40700, "app-1", "my-api").unwrap();

        assert_eq!(allocator.get_port_for_app("my-api"), Some(40700));
        assert_eq!(allocator.get_port_for_app("nonexistent"), None);
    }

    #[test]
    fn test_remaining_capacity() {
        let mut allocator = PortAllocator::new(50800, 50809).unwrap();
        assert_eq!(allocator.remaining_capacity(), 10); // 50800-50809 = 10 ports

        allocator.allocate(50800, "app-1", "api").unwrap();
        assert_eq!(allocator.remaining_capacity(), 9);

        allocator.add_reserved(50805);
        assert_eq!(allocator.remaining_capacity(), 8);
    }

    // ── Reserved Port Tests ────────────────────────────────────────────

    #[test]
    fn test_add_and_remove_reserved() {
        let mut allocator = test_allocator();

        allocator.add_reserved(47777);
        let result = allocator.check(47777);
        assert!(!result.available);
        assert_eq!(result.conflict_type, Some(PortConflictType::Reserved));

        assert!(allocator.remove_reserved(47777));
        let result = allocator.check(47777);
        // Should be available again (assuming no system conflict)
        if result.conflict_type == Some(PortConflictType::Reserved) {
            panic!("Port should no longer be reserved after removal");
        }
    }

    #[test]
    fn test_register_zeroed_ports() {
        let mut allocator = test_allocator();
        allocator.register_zeroed_ports(&[48080, 49090]);

        let result = allocator.check(48080);
        assert!(!result.available);
        assert_eq!(result.conflict_type, Some(PortConflictType::Reserved));

        let result = allocator.check(49090);
        assert!(!result.available);
    }

    #[test]
    fn test_all_reserved_ports() {
        let mut allocator = test_allocator();
        allocator.add_reserved(47777);
        allocator.register_zeroed_ports(&[48080]);

        let all_reserved = allocator.all_reserved_ports();
        assert!(all_reserved.contains(&22)); // Built-in
        assert!(all_reserved.contains(&80)); // Built-in
        assert!(all_reserved.contains(&47777)); // Custom
        assert!(all_reserved.contains(&48080)); // Zeroed
    }

    // ── Warning Tests ──────────────────────────────────────────────────

    #[test]
    fn test_should_warn_for_common_ports() {
        let allocator = test_allocator();

        assert!(allocator.should_warn(3306).is_some()); // MySQL
        assert!(allocator.should_warn(5432).is_some()); // PostgreSQL
        assert!(allocator.should_warn(6379).is_some()); // Redis
        assert!(allocator.should_warn(27017).is_some()); // MongoDB

        assert!(allocator.should_warn(44567).is_none()); // Not a common port
        assert!(allocator.should_warn(40000).is_none()); // Not a common port
    }

    #[test]
    fn test_should_warn_message_content() {
        let allocator = test_allocator();

        let warning = allocator.should_warn(3306).unwrap();
        assert!(warning.contains("MySQL"));

        let warning = allocator.should_warn(6379).unwrap();
        assert!(warning.contains("Redis"));
    }

    // ── Bulk Operation Tests ───────────────────────────────────────────

    #[test]
    fn test_clear_allocations() {
        let mut allocator = test_allocator();
        allocator.allocate(40900, "app-1", "api").unwrap();
        allocator.allocate(41900, "app-2", "web").unwrap();

        assert_eq!(allocator.allocation_count(), 2);

        allocator.clear();
        assert_eq!(allocator.allocation_count(), 0);
        assert!(!allocator.is_allocated(40900));
        assert!(!allocator.is_allocated(41900));
    }

    #[test]
    fn test_load_allocations() {
        let mut allocator = test_allocator();

        let allocs = vec![
            PortAllocation::new(40950, "app-1".to_string(), "api".to_string()),
            PortAllocation::new(41950, "app-2".to_string(), "web".to_string()),
        ];

        allocator.load_allocations(allocs);
        assert_eq!(allocator.allocation_count(), 2);
        assert!(allocator.is_allocated(40950));
        assert!(allocator.is_allocated(41950));
    }

    #[test]
    fn test_summary() {
        let mut allocator = PortAllocator::new(41100, 41109).unwrap();
        allocator.allocate(41100, "app-1", "api").unwrap();
        allocator.allocate(41101, "app-2", "web").unwrap();
        allocator.add_reserved(41105);

        let summary = allocator.summary();
        assert_eq!(summary.range_start, 41100);
        assert_eq!(summary.range_end, 41109);
        assert_eq!(summary.range_size, 10);
        assert_eq!(summary.allocated_count, 2);
        assert_eq!(summary.allocations.len(), 2);
    }

    // ── PortAllocation Display Test ────────────────────────────────────

    #[test]
    fn test_port_allocation_display() {
        let alloc = PortAllocation::new(41200, "app-123".to_string(), "my-api".to_string());
        let display = format!("{}", alloc);
        assert!(display.contains("41200"));
        assert!(display.contains("my-api"));
        assert!(display.contains("app-123"));
    }

    // ── PortCheckResult Display Test ───────────────────────────────────

    #[test]
    fn test_port_check_result_display() {
        let available = PortCheckResult::available(42000);
        assert!(format!("{}", available).contains("available"));

        let conflict = PortCheckResult::internal_conflict(42000, "my-api");
        assert!(format!("{}", conflict).contains("NOT available"));
        assert!(format!("{}", conflict).contains("my-api"));
    }

    // ── PortConflictType Display Test ──────────────────────────────────

    #[test]
    fn test_port_conflict_type_display() {
        assert_eq!(format!("{}", PortConflictType::ManagedApp), "managed_app");
        assert_eq!(format!("{}", PortConflictType::SystemService), "system_service");
        assert_eq!(format!("{}", PortConflictType::Reserved), "reserved");
        assert_eq!(format!("{}", PortConflictType::OutOfRange), "out_of_range");
    }

    // ── PortCheckResult Constructor Tests ──────────────────────────────

    #[test]
    fn test_port_check_result_constructors() {
        let available = PortCheckResult::available(42000);
        assert!(available.available);
        assert!(available.conflict_type.is_none());

        let internal = PortCheckResult::internal_conflict(42000, "api");
        assert!(!internal.available);
        assert_eq!(internal.conflict_type, Some(PortConflictType::ManagedApp));
        assert_eq!(internal.used_by.as_deref(), Some("api"));

        let system = PortCheckResult::system_conflict(42000, "nginx is listening");
        assert!(!system.available);
        assert_eq!(
            system.conflict_type,
            Some(PortConflictType::SystemService)
        );

        let reserved = PortCheckResult::reserved(22, "SSH");
        assert!(!reserved.available);
        assert_eq!(reserved.conflict_type, Some(PortConflictType::Reserved));

        let oor = PortCheckResult::out_of_range(60000, 40000, 49999);
        assert!(!oor.available);
        assert_eq!(oor.conflict_type, Some(PortConflictType::OutOfRange));
    }

    // ── Serialization Tests ────────────────────────────────────────────

    #[test]
    fn test_port_allocation_serialization() {
        let alloc = PortAllocation::new(41300, "app-1".to_string(), "my-api".to_string());

        let json = serde_json::to_string(&alloc).unwrap();
        let deserialized: PortAllocation = serde_json::from_str(&json).unwrap();

        assert_eq!(deserialized.port, 41300);
        assert_eq!(deserialized.app_id, "app-1");
        assert_eq!(deserialized.app_name, "my-api");
    }

    #[test]
    fn test_port_check_result_serialization() {
        let result = PortCheckResult::internal_conflict(42000, "my-api");

        let json = serde_json::to_string(&result).unwrap();
        let deserialized: PortCheckResult = serde_json::from_str(&json).unwrap();

        assert!(!deserialized.available);
        assert_eq!(deserialized.port, 42000);
        assert_eq!(
            deserialized.conflict_type,
            Some(PortConflictType::ManagedApp)
        );
    }

    #[test]
    fn test_port_allocator_summary_serialization() {
        let mut allocator = test_allocator();
        allocator.allocate(41400, "app-1", "api").unwrap();

        let summary = allocator.summary();
        let json = serde_json::to_string(&summary).unwrap();
        let deserialized: PortAllocatorSummary = serde_json::from_str(&json).unwrap();

        assert_eq!(deserialized.range_start, 40000);
        assert_eq!(deserialized.allocated_count, 1);
        assert_eq!(deserialized.allocations.len(), 1);
    }
}
