//! Daemon lifecycle management
//!
//! This module handles the lifecycle stages of the Zeroed daemon,
//! including initialization, running, and graceful shutdown.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use tokio::sync::broadcast;
use tracing::{debug, error, info, warn};

/// Lifecycle events that can be broadcast to components
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LifecycleEvent {
    /// Daemon is starting up
    Starting,
    /// Daemon has finished initialization
    Started,
    /// Daemon is reloading configuration
    Reloading,
    /// Daemon is beginning shutdown
    ShuttingDown,
    /// Daemon has stopped
    Stopped,
}

/// Lifecycle manager for coordinating daemon state
pub struct LifecycleManager {
    /// Event broadcaster
    event_tx: broadcast::Sender<LifecycleEvent>,
    /// Shutdown flag
    shutdown_flag: Arc<AtomicBool>,
    /// Reload flag
    reload_flag: Arc<AtomicBool>,
}

impl LifecycleManager {
    /// Create a new lifecycle manager
    pub fn new() -> Self {
        let (event_tx, _) = broadcast::channel(16);

        Self {
            event_tx,
            shutdown_flag: Arc::new(AtomicBool::new(false)),
            reload_flag: Arc::new(AtomicBool::new(false)),
        }
    }

    /// Subscribe to lifecycle events
    pub fn subscribe(&self) -> broadcast::Receiver<LifecycleEvent> {
        self.event_tx.subscribe()
    }

    /// Broadcast a lifecycle event
    pub fn broadcast(&self, event: LifecycleEvent) {
        let _ = self.event_tx.send(event);
        debug!("Lifecycle event: {:?}", event);
    }

    /// Request shutdown
    pub fn request_shutdown(&self) {
        self.shutdown_flag.store(true, Ordering::SeqCst);
        self.broadcast(LifecycleEvent::ShuttingDown);
        info!("Shutdown requested");
    }

    /// Check if shutdown is requested
    pub fn is_shutdown_requested(&self) -> bool {
        self.shutdown_flag.load(Ordering::SeqCst)
    }

    /// Request configuration reload
    pub fn request_reload(&self) {
        self.reload_flag.store(true, Ordering::SeqCst);
        self.broadcast(LifecycleEvent::Reloading);
        info!("Configuration reload requested");
    }

    /// Check if reload is requested and clear the flag
    pub fn take_reload_request(&self) -> bool {
        self.reload_flag.swap(false, Ordering::SeqCst)
    }

    /// Get the shutdown flag for sharing
    pub fn shutdown_flag(&self) -> Arc<AtomicBool> {
        Arc::clone(&self.shutdown_flag)
    }
}

impl Default for LifecycleManager {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_lifecycle_manager() {
        let manager = LifecycleManager::new();

        assert!(!manager.is_shutdown_requested());

        manager.request_shutdown();
        assert!(manager.is_shutdown_requested());
    }

    #[test]
    fn test_reload_request() {
        let manager = LifecycleManager::new();

        assert!(!manager.take_reload_request());

        manager.request_reload();
        assert!(manager.take_reload_request());
        assert!(!manager.take_reload_request()); // Should be cleared
    }
}
