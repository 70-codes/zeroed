//! Signal handling module for the Zeroed daemon
//!
//! This module provides functionality for handling Unix signals
//! such as SIGTERM, SIGINT, SIGHUP, and SIGUSR1/SIGUSR2.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use tokio::sync::broadcast;
use tracing::{debug, info, warn};

/// Signal types that the daemon handles
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Signal {
    /// Terminate signal (SIGTERM)
    Terminate,
    /// Interrupt signal (SIGINT, Ctrl+C)
    Interrupt,
    /// Hangup signal (SIGHUP) - typically used for config reload
    Hangup,
    /// User signal 1 (SIGUSR1) - can be used for custom actions
    User1,
    /// User signal 2 (SIGUSR2) - can be used for custom actions
    User2,
}

impl std::fmt::Display for Signal {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Signal::Terminate => write!(f, "SIGTERM"),
            Signal::Interrupt => write!(f, "SIGINT"),
            Signal::Hangup => write!(f, "SIGHUP"),
            Signal::User1 => write!(f, "SIGUSR1"),
            Signal::User2 => write!(f, "SIGUSR2"),
        }
    }
}

/// Signal handler that broadcasts received signals
pub struct SignalHandler {
    /// Broadcast sender for signal notifications
    sender: broadcast::Sender<Signal>,
    /// Flag indicating if shutdown has been requested
    shutdown_requested: Arc<AtomicBool>,
    /// Flag indicating if reload has been requested
    reload_requested: Arc<AtomicBool>,
}

impl SignalHandler {
    /// Create a new signal handler
    pub fn new() -> Self {
        let (sender, _) = broadcast::channel(16);

        Self {
            sender,
            shutdown_requested: Arc::new(AtomicBool::new(false)),
            reload_requested: Arc::new(AtomicBool::new(false)),
        }
    }

    /// Subscribe to signal notifications
    pub fn subscribe(&self) -> broadcast::Receiver<Signal> {
        self.sender.subscribe()
    }

    /// Check if shutdown has been requested
    pub fn is_shutdown_requested(&self) -> bool {
        self.shutdown_requested.load(Ordering::SeqCst)
    }

    /// Check if reload has been requested
    pub fn is_reload_requested(&self) -> bool {
        self.reload_requested.load(Ordering::SeqCst)
    }

    /// Clear the reload flag after handling
    pub fn clear_reload_request(&self) {
        self.reload_requested.store(false, Ordering::SeqCst);
    }

    /// Get a clone of the shutdown flag
    pub fn shutdown_flag(&self) -> Arc<AtomicBool> {
        Arc::clone(&self.shutdown_requested)
    }

    /// Get a clone of the reload flag
    pub fn reload_flag(&self) -> Arc<AtomicBool> {
        Arc::clone(&self.reload_requested)
    }

    /// Start listening for signals (Unix-specific)
    #[cfg(unix)]
    pub async fn listen(&self) {
        use tokio::signal::unix::{signal, SignalKind};

        // Create signal streams
        let mut sigterm =
            signal(SignalKind::terminate()).expect("Failed to register SIGTERM handler");
        let mut sigint =
            signal(SignalKind::interrupt()).expect("Failed to register SIGINT handler");
        let mut sighup = signal(SignalKind::hangup()).expect("Failed to register SIGHUP handler");
        let mut sigusr1 =
            signal(SignalKind::user_defined1()).expect("Failed to register SIGUSR1 handler");
        let mut sigusr2 =
            signal(SignalKind::user_defined2()).expect("Failed to register SIGUSR2 handler");

        info!("Signal handler initialized");

        loop {
            let signal = tokio::select! {
                _ = sigterm.recv() => {
                    info!("Received SIGTERM");
                    self.shutdown_requested.store(true, Ordering::SeqCst);
                    Signal::Terminate
                }
                _ = sigint.recv() => {
                    info!("Received SIGINT");
                    self.shutdown_requested.store(true, Ordering::SeqCst);
                    Signal::Interrupt
                }
                _ = sighup.recv() => {
                    info!("Received SIGHUP - configuration reload requested");
                    self.reload_requested.store(true, Ordering::SeqCst);
                    Signal::Hangup
                }
                _ = sigusr1.recv() => {
                    debug!("Received SIGUSR1");
                    Signal::User1
                }
                _ = sigusr2.recv() => {
                    debug!("Received SIGUSR2");
                    Signal::User2
                }
            };

            // Broadcast the signal to all subscribers
            let _ = self.sender.send(signal);

            // If shutdown was requested, stop listening
            if self.shutdown_requested.load(Ordering::SeqCst) {
                info!("Shutdown requested, signal handler exiting");
                break;
            }
        }
    }

    /// Fallback for non-Unix systems
    #[cfg(not(unix))]
    pub async fn listen(&self) {
        use tokio::signal;

        info!("Signal handler initialized (non-Unix mode)");

        // On non-Unix systems, we can only handle Ctrl+C
        loop {
            match signal::ctrl_c().await {
                Ok(()) => {
                    info!("Received Ctrl+C");
                    self.shutdown_requested.store(true, Ordering::SeqCst);
                    let _ = self.sender.send(Signal::Interrupt);
                    break;
                }
                Err(e) => {
                    warn!("Error handling Ctrl+C: {}", e);
                }
            }
        }
    }
}

impl Default for SignalHandler {
    fn default() -> Self {
        Self::new()
    }
}

/// Install signal handlers for graceful shutdown
#[cfg(unix)]
pub fn install_panic_handler() {
    // Set up a custom panic hook that logs the panic
    let default_hook = std::panic::take_hook();

    std::panic::set_hook(Box::new(move |panic_info| {
        // Log the panic
        let location = panic_info
            .location()
            .map(|l| format!("{}:{}:{}", l.file(), l.line(), l.column()))
            .unwrap_or_else(|| "unknown location".to_string());

        let message = if let Some(s) = panic_info.payload().downcast_ref::<&str>() {
            s.to_string()
        } else if let Some(s) = panic_info.payload().downcast_ref::<String>() {
            s.clone()
        } else {
            "Unknown panic payload".to_string()
        };

        // Log to stderr since logging might not be available
        eprintln!("PANIC at {}: {}", location, message);

        // Call the default hook
        default_hook(panic_info);
    }));
}

#[cfg(not(unix))]
pub fn install_panic_handler() {
    // Basic panic handler for non-Unix systems
    let default_hook = std::panic::take_hook();

    std::panic::set_hook(Box::new(move |panic_info| {
        eprintln!("PANIC: {:?}", panic_info);
        default_hook(panic_info);
    }));
}

/// Utility function to block SIGPIPE (useful for network daemons)
#[cfg(unix)]
pub fn block_sigpipe() {
    unsafe {
        libc::signal(libc::SIGPIPE, libc::SIG_IGN);
    }
    debug!("SIGPIPE blocked");
}

#[cfg(not(unix))]
pub fn block_sigpipe() {
    // No-op on non-Unix systems
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_signal_display() {
        assert_eq!(format!("{}", Signal::Terminate), "SIGTERM");
        assert_eq!(format!("{}", Signal::Interrupt), "SIGINT");
        assert_eq!(format!("{}", Signal::Hangup), "SIGHUP");
    }

    #[test]
    fn test_signal_handler_creation() {
        let handler = SignalHandler::new();
        assert!(!handler.is_shutdown_requested());
        assert!(!handler.is_reload_requested());
    }

    #[test]
    fn test_shutdown_flag() {
        let handler = SignalHandler::new();
        let flag = handler.shutdown_flag();

        assert!(!flag.load(Ordering::SeqCst));
        flag.store(true, Ordering::SeqCst);
        assert!(handler.is_shutdown_requested());
    }

    #[test]
    fn test_reload_flag() {
        let handler = SignalHandler::new();

        handler.reload_flag().store(true, Ordering::SeqCst);
        assert!(handler.is_reload_requested());

        handler.clear_reload_request();
        assert!(!handler.is_reload_requested());
    }
}
