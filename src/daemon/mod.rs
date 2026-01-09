//! Daemon module for process lifecycle management
//!
//! This module provides functionality for running Zeroed as a system daemon,
//! including signal handling, privilege dropping, and process management.

pub mod lifecycle;
pub mod signals;

use crate::core::config::DaemonConfig;
use crate::core::error::{DaemonError, Result, ZeroedError};
use std::fs::{self, File};
use std::io::Write;
use std::path::Path;
use tracing::{debug, error, info, warn};

/// Daemon state
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DaemonState {
    /// Daemon is initializing
    Initializing,
    /// Daemon is running normally
    Running,
    /// Daemon is shutting down
    ShuttingDown,
    /// Daemon has stopped
    Stopped,
    /// Daemon encountered an error
    Error,
}

/// Daemon process manager
pub struct DaemonManager {
    /// Configuration
    config: DaemonConfig,
    /// Current state
    state: std::sync::atomic::AtomicU8,
    /// Start time
    start_time: std::time::Instant,
}

impl DaemonManager {
    /// Create a new daemon manager
    pub fn new(config: DaemonConfig) -> Self {
        Self {
            config,
            state: std::sync::atomic::AtomicU8::new(DaemonState::Initializing as u8),
            start_time: std::time::Instant::now(),
        }
    }

    /// Get current state
    pub fn state(&self) -> DaemonState {
        match self.state.load(std::sync::atomic::Ordering::SeqCst) {
            0 => DaemonState::Initializing,
            1 => DaemonState::Running,
            2 => DaemonState::ShuttingDown,
            3 => DaemonState::Stopped,
            _ => DaemonState::Error,
        }
    }

    /// Set daemon state
    pub fn set_state(&self, state: DaemonState) {
        self.state
            .store(state as u8, std::sync::atomic::Ordering::SeqCst);
    }

    /// Get uptime in seconds
    pub fn uptime_secs(&self) -> u64 {
        self.start_time.elapsed().as_secs()
    }

    /// Write PID file
    pub fn write_pid_file(&self) -> Result<()> {
        let pid = std::process::id();
        let pid_path = &self.config.pid_file;

        // Create parent directory if needed
        if let Some(parent) = pid_path.parent() {
            fs::create_dir_all(parent).map_err(|e| {
                ZeroedError::Daemon(DaemonError::PidFileError {
                    path: pid_path.clone(),
                    message: format!("Failed to create directory: {}", e),
                })
            })?;
        }

        let mut file = File::create(pid_path).map_err(|e| {
            ZeroedError::Daemon(DaemonError::PidFileError {
                path: pid_path.clone(),
                message: format!("Failed to create PID file: {}", e),
            })
        })?;

        writeln!(file, "{}", pid).map_err(|e| {
            ZeroedError::Daemon(DaemonError::PidFileError {
                path: pid_path.clone(),
                message: format!("Failed to write PID: {}", e),
            })
        })?;

        info!("PID file written: {:?} (PID: {})", pid_path, pid);
        Ok(())
    }

    /// Remove PID file
    pub fn remove_pid_file(&self) -> Result<()> {
        let pid_path = &self.config.pid_file;

        if pid_path.exists() {
            fs::remove_file(pid_path).map_err(|e| {
                ZeroedError::Daemon(DaemonError::PidFileError {
                    path: pid_path.clone(),
                    message: format!("Failed to remove PID file: {}", e),
                })
            })?;
            debug!("PID file removed: {:?}", pid_path);
        }

        Ok(())
    }

    /// Check if another instance is running
    pub fn check_existing_instance(&self) -> Result<Option<u32>> {
        let pid_path = &self.config.pid_file;

        if !pid_path.exists() {
            return Ok(None);
        }

        let content = fs::read_to_string(pid_path).map_err(|e| {
            ZeroedError::Daemon(DaemonError::PidFileError {
                path: pid_path.clone(),
                message: format!("Failed to read PID file: {}", e),
            })
        })?;

        let pid: u32 = content.trim().parse().map_err(|e| {
            ZeroedError::Daemon(DaemonError::PidFileError {
                path: pid_path.clone(),
                message: format!("Invalid PID: {}", e),
            })
        })?;

        // Check if process is running
        #[cfg(unix)]
        {
            let result = nix::sys::signal::kill(
                nix::unistd::Pid::from_raw(pid as i32),
                None, // Just check if process exists
            );

            if result.is_ok() {
                return Err(ZeroedError::Daemon(DaemonError::AlreadyRunning { pid }));
            }
        }

        // Stale PID file
        warn!("Stale PID file found, removing...");
        self.remove_pid_file()?;

        Ok(None)
    }

    /// Drop privileges to configured user/group
    #[cfg(unix)]
    pub fn drop_privileges(&self) -> Result<()> {
        use nix::unistd::{setgid, setuid, Gid, Uid, User};

        if let Some(ref username) = self.config.user {
            let user = User::from_name(username)
                .map_err(|e| {
                    ZeroedError::Daemon(DaemonError::PrivilegeDropError {
                        user: username.clone(),
                        message: format!("Failed to lookup user: {}", e),
                    })
                })?
                .ok_or_else(|| {
                    ZeroedError::Daemon(DaemonError::PrivilegeDropError {
                        user: username.clone(),
                        message: "User not found".to_string(),
                    })
                })?;

            // Set group first (must be done before dropping user privileges)
            setgid(user.gid).map_err(|e| {
                ZeroedError::Daemon(DaemonError::PrivilegeDropError {
                    user: username.clone(),
                    message: format!("Failed to set GID: {}", e),
                })
            })?;

            // Set user
            setuid(user.uid).map_err(|e| {
                ZeroedError::Daemon(DaemonError::PrivilegeDropError {
                    user: username.clone(),
                    message: format!("Failed to set UID: {}", e),
                })
            })?;

            info!("Dropped privileges to user: {}", username);
        }

        Ok(())
    }

    #[cfg(not(unix))]
    pub fn drop_privileges(&self) -> Result<()> {
        warn!("Privilege dropping not supported on this platform");
        Ok(())
    }
}

impl Drop for DaemonManager {
    fn drop(&mut self) {
        if let Err(e) = self.remove_pid_file() {
            error!("Failed to remove PID file on shutdown: {}", e);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    #[test]
    fn test_daemon_state() {
        let config = DaemonConfig {
            pid_file: PathBuf::from("/tmp/test.pid"),
            user: None,
            group: None,
            working_dir: PathBuf::from("/tmp"),
            daemonize: false,
            worker_threads: 0,
            max_memory_mb: 0,
        };

        let manager = DaemonManager::new(config);
        assert_eq!(manager.state(), DaemonState::Initializing);

        manager.set_state(DaemonState::Running);
        assert_eq!(manager.state(), DaemonState::Running);
    }
}
