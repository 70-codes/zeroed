//! Zeroed - A High-Performance Linux DoS/DDoS Protection Daemon
//!
//! This is the main entry point for the Zeroed daemon, which provides
//! real-time network traffic monitoring, DoS attack detection, and
//! automatic mitigation through firewall integration.
//!
//! ## Features
//! - Real-time packet capture and analysis
//! - IP and MAC address tracking
//! - Geographic source detection
//! - Configurable rate limiting and thresholds
//! - Automatic firewall rule management (iptables/nftables)
//! - Efficient custom storage system
//! - REST API and Unix socket control interface
//! - Prometheus metrics export
//!
//! ## Usage
//!
//! ```bash
//! # Start the daemon
//! sudo zeroed start
//!
//! # Start with custom config
//! sudo zeroed start --config /etc/zeroed/config.toml
//!
//! # Check status
//! zeroctl status
//!
//! # View blocked IPs
//! zeroctl list blocked
//! ```

use clap::{Parser, Subcommand};
use std::path::PathBuf;
use std::process::ExitCode;
use std::sync::Arc;
use tokio::signal;
use tokio::sync::{broadcast, mpsc};
use tracing::{debug, error, info, warn, Level};
use tracing_subscriber::{fmt, prelude::*, EnvFilter};

// Import our modules
mod api;
mod core;
mod daemon;
mod detection;
mod geo;
mod network;
mod storage;

use crate::core::config::ZeroedConfig;
use crate::core::error::{Result, ZeroedError};

// ─────────────────────────────────────────────────────────────────────────────
// Constants
// ─────────────────────────────────────────────────────────────────────────────

/// Default configuration file path
const DEFAULT_CONFIG_PATH: &str = "/etc/zeroed/config.toml";

/// Default PID file path
const DEFAULT_PID_PATH: &str = "/var/run/zeroed/zeroed.pid";

/// Application name
const APP_NAME: &str = "zeroed";

/// Application version
const APP_VERSION: &str = env!("CARGO_PKG_VERSION");

// ─────────────────────────────────────────────────────────────────────────────
// CLI Definition
// ─────────────────────────────────────────────────────────────────────────────

/// Zeroed - High-Performance DoS/DDoS Protection Daemon for Linux
#[derive(Parser, Debug)]
#[command(
    name = APP_NAME,
    version = APP_VERSION,
    author = "Security Team",
    about = "A high-performance Linux daemon for DoS/DDoS attack protection",
    long_about = r#"
Zeroed is a real-time network traffic monitoring and DoS protection daemon.

It captures network packets, analyzes traffic patterns, detects potential
attacks based on configurable thresholds, and automatically blocks malicious
IPs through firewall integration.

Key Features:
  • Real-time packet capture and deep inspection
  • IP/MAC address tracking with frequency analysis
  • GeoIP-based source region identification
  • SYN flood, UDP flood, and HTTP flood detection
  • Automatic iptables/nftables rule management
  • Efficient custom storage for logging
  • REST API and Unix socket control interface
  • Prometheus metrics export

Run 'zeroed start' to begin protection, or use 'zeroctl' for management.
    "#
)]
struct Cli {
    /// Path to configuration file
    #[arg(short, long, default_value = DEFAULT_CONFIG_PATH)]
    config: PathBuf,

    /// Enable verbose output (can be repeated for more verbosity)
    #[arg(short, long, action = clap::ArgAction::Count)]
    verbose: u8,

    /// Run in foreground (don't daemonize)
    #[arg(short, long)]
    foreground: bool,

    /// Quiet mode - only show errors
    #[arg(short, long)]
    quiet: bool,

    #[command(subcommand)]
    command: Commands,
}

/// Available commands
#[derive(Subcommand, Debug)]
enum Commands {
    /// Start the Zeroed daemon
    Start {
        /// Network interface to monitor (default: auto-detect)
        #[arg(short, long)]
        interface: Option<String>,

        /// Override PID file location
        #[arg(long)]
        pid_file: Option<PathBuf>,

        /// Dry run - don't apply firewall rules
        #[arg(long)]
        dry_run: bool,
    },

    /// Stop the running daemon
    Stop {
        /// PID file location
        #[arg(long, default_value = DEFAULT_PID_PATH)]
        pid_file: PathBuf,

        /// Force stop (SIGKILL)
        #[arg(short, long)]
        force: bool,
    },

    /// Restart the daemon
    Restart {
        /// Network interface to monitor
        #[arg(short, long)]
        interface: Option<String>,
    },

    /// Check daemon status
    Status {
        /// PID file location
        #[arg(long, default_value = DEFAULT_PID_PATH)]
        pid_file: PathBuf,
    },

    /// Validate configuration file
    ConfigCheck {
        /// Show parsed configuration
        #[arg(long)]
        show: bool,
    },

    /// Generate default configuration file
    ConfigGen {
        /// Output path for configuration file
        #[arg(short, long)]
        output: Option<PathBuf>,

        /// Overwrite existing file
        #[arg(short, long)]
        force: bool,
    },

    /// List network interfaces
    Interfaces,

    /// Show version information
    Version {
        /// Show detailed build information
        #[arg(long)]
        detailed: bool,
    },
}

// ─────────────────────────────────────────────────────────────────────────────
// Main Entry Point
// ─────────────────────────────────────────────────────────────────────────────

fn main() -> ExitCode {
    // Parse command line arguments
    let cli = Cli::parse();

    // Initialize logging based on verbosity
    init_logging(cli.verbose, cli.quiet);

    // Execute the appropriate command
    match run(cli) {
        Ok(_) => ExitCode::SUCCESS,
        Err(e) => {
            error!("Fatal error: {}", e);
            eprintln!("Error: {}", e);
            ExitCode::FAILURE
        }
    }
}

/// Initialize the logging subsystem
fn init_logging(verbose: u8, quiet: bool) {
    let level = if quiet {
        Level::ERROR
    } else {
        match verbose {
            0 => Level::INFO,
            1 => Level::DEBUG,
            _ => Level::TRACE,
        }
    };

    let filter =
        EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new(level.to_string()));

    tracing_subscriber::registry()
        .with(fmt::layer().with_target(true).with_thread_ids(true))
        .with(filter)
        .init();

    debug!("Logging initialized at level: {:?}", level);
}

/// Main command dispatcher
fn run(cli: Cli) -> Result<()> {
    match cli.command {
        Commands::Start {
            interface,
            pid_file,
            dry_run,
        } => cmd_start(cli.config, cli.foreground, interface, pid_file, dry_run),

        Commands::Stop { pid_file, force } => cmd_stop(pid_file, force),

        Commands::Restart { interface } => cmd_restart(cli.config, interface),

        Commands::Status { pid_file } => cmd_status(pid_file),

        Commands::ConfigCheck { show } => cmd_config_check(cli.config, show),

        Commands::ConfigGen { output, force } => cmd_config_gen(output, force),

        Commands::Interfaces => cmd_interfaces(),

        Commands::Version { detailed } => cmd_version(detailed),
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Command Implementations
// ─────────────────────────────────────────────────────────────────────────────

/// Start the daemon
fn cmd_start(
    config_path: PathBuf,
    foreground: bool,
    interface: Option<String>,
    pid_file: Option<PathBuf>,
    dry_run: bool,
) -> Result<()> {
    info!("Starting {} v{}", APP_NAME, APP_VERSION);

    // Check for root privileges
    if !is_root() {
        error!("This daemon requires root privileges to capture packets");
        return Err(ZeroedError::PermissionDenied {
            operation: "start daemon".to_string(),
        });
    }

    // Load configuration
    let mut config = load_config(&config_path)?;

    // Override interface if specified
    if let Some(iface) = interface {
        config.network.interfaces = vec![iface];
    }

    // Override PID file if specified
    if let Some(pid) = pid_file {
        config.daemon.pid_file = pid;
    }

    // Set dry run mode
    if dry_run {
        config.firewall.dry_run = true;
        warn!("Running in dry-run mode - firewall rules will NOT be applied");
    }

    // Validate configuration
    config.validate().map_err(|e| {
        ZeroedError::Config(core::error::ConfigError::ValidationError {
            message: e.to_string(),
        })
    })?;

    info!("Configuration loaded from {:?}", config_path);

    // Daemonize unless foreground mode
    if !foreground && config.daemon.daemonize {
        info!("Daemonizing process...");
        daemonize(&config)?;
    }

    // Run the main daemon loop
    run_daemon(config)
}

/// Run the main daemon
fn run_daemon(config: ZeroedConfig) -> Result<()> {
    // Create tokio runtime
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(if config.daemon.worker_threads > 0 {
            config.daemon.worker_threads
        } else {
            num_cpus::get()
        })
        .enable_all()
        .build()
        .map_err(|e| ZeroedError::Internal {
            message: format!("Failed to create runtime: {}", e),
        })?;

    // Run the async main loop
    runtime.block_on(async_main(config))
}

/// Async main loop
async fn async_main(config: ZeroedConfig) -> Result<()> {
    info!("Initializing Zeroed daemon...");

    // Create shutdown broadcast channel
    let (shutdown_tx, _) = broadcast::channel::<()>(1);
    let shutdown_rx = shutdown_tx.subscribe();

    // Create packet channel
    let (packet_tx, mut packet_rx) = mpsc::channel(10_000);

    // Initialize storage engine
    info!("Initializing storage engine...");
    let storage = Arc::new(storage::StorageEngine::new(config.storage.clone()).await?);

    // Load existing state
    if let Err(e) = storage.load_ip_cache() {
        warn!("Could not load IP cache: {}", e);
    }

    // Initialize network manager
    info!("Initializing network capture...");
    let network_manager = Arc::new(network::NetworkManager::new(10_000));

    // Get interface to monitor
    let interface = if config.network.interfaces.is_empty() {
        network::capture::CaptureEngine::default_interface()?
    } else {
        config.network.interfaces[0].clone()
    };

    info!("Monitoring interface: {}", interface);

    // Create capture engine
    let capture_config = config.network.clone();
    let capture_engine = network::capture::CaptureEngine::new(capture_config);
    let capture_stats = capture_engine.stats();

    // Spawn capture task
    let capture_handle = {
        let mut shutdown_rx = shutdown_tx.subscribe();
        let packet_tx = packet_tx.clone();

        tokio::spawn(async move {
            tokio::select! {
                result = capture_engine.start(packet_tx) => {
                    if let Err(e) = result {
                        error!("Capture engine error: {}", e);
                    }
                }
                _ = shutdown_rx.recv() => {
                    info!("Capture engine received shutdown signal");
                    capture_engine.stop();
                }
            }
        })
    };

    // Spawn packet processing task
    let processing_handle = {
        let storage = Arc::clone(&storage);
        let network_manager = Arc::clone(&network_manager);
        let detection_config = config.detection.clone();
        let mut shutdown_rx = shutdown_tx.subscribe();

        tokio::spawn(async move {
            let mut packets_processed = 0u64;

            loop {
                tokio::select! {
                    Some(packet) = packet_rx.recv() => {
                        packets_processed += 1;

                        // Create connection record from captured packet
                        let id = packets_processed;
                        let record = packet.to_connection_record(id);

                        // Store the record
                        if let Err(e) = storage.store(&record) {
                            debug!("Failed to store record: {}", e);
                        }

                        // Update connection tracker
                        network_manager.connection_tracker().update(&record);

                        // Check rate limits and update tracking
                        // TODO: Implement detection logic here

                        // Log progress periodically
                        if packets_processed % 10_000 == 0 {
                            info!("Processed {} packets", packets_processed);
                        }
                    }
                    _ = shutdown_rx.recv() => {
                        info!("Packet processor received shutdown signal");
                        break;
                    }
                }
            }

            info!(
                "Packet processor stopped. Total processed: {}",
                packets_processed
            );
        })
    };

    // Spawn periodic maintenance task
    let maintenance_handle = {
        let storage = Arc::clone(&storage);
        let mut shutdown_rx = shutdown_tx.subscribe();

        tokio::spawn(async move {
            let mut interval = tokio::time::interval(std::time::Duration::from_secs(60));

            loop {
                tokio::select! {
                    _ = interval.tick() => {
                        // Periodic maintenance
                        debug!("Running periodic maintenance...");

                        // Flush storage
                        if let Err(e) = storage.flush().await {
                            warn!("Storage flush error: {}", e);
                        }

                        // Cleanup expired entries
                        if let Err(e) = storage.cleanup().await {
                            warn!("Storage cleanup error: {}", e);
                        }

                        // Log statistics
                        let stats = storage.stats();
                        info!(
                            "Storage stats: {} records written, {} ring buffer entries, {} tracked IPs",
                            stats.records_written,
                            storage.ring_buffer_size(),
                            storage.ip_cache_size()
                        );
                    }
                    _ = shutdown_rx.recv() => {
                        info!("Maintenance task received shutdown signal");
                        break;
                    }
                }
            }
        })
    };

    // Wait for shutdown signal
    info!("Zeroed daemon started successfully");
    info!("Press Ctrl+C to stop");

    // Handle shutdown signals
    tokio::select! {
        _ = signal::ctrl_c() => {
            info!("Received Ctrl+C, initiating shutdown...");
        }
        _ = async {
            #[cfg(unix)]
            {
                let mut sigterm = signal::unix::signal(signal::unix::SignalKind::terminate())
                    .expect("Failed to register SIGTERM handler");
                sigterm.recv().await;
            }
            #[cfg(not(unix))]
            {
                std::future::pending::<()>().await;
            }
        } => {
            info!("Received SIGTERM, initiating shutdown...");
        }
    }

    // Send shutdown signal to all tasks
    info!("Sending shutdown signal to all tasks...");
    let _ = shutdown_tx.send(());

    // Wait for tasks to complete (with timeout)
    let shutdown_timeout = std::time::Duration::from_secs(10);
    let shutdown_result = tokio::time::timeout(shutdown_timeout, async {
        let _ = capture_handle.await;
        let _ = processing_handle.await;
        let _ = maintenance_handle.await;
    })
    .await;

    if shutdown_result.is_err() {
        warn!("Shutdown timed out, some tasks may not have completed gracefully");
    }

    // Final storage flush
    info!("Performing final storage flush...");
    storage.shutdown().await?;

    info!("Zeroed daemon stopped");
    Ok(())
}

/// Stop the daemon
fn cmd_stop(pid_file: PathBuf, force: bool) -> Result<()> {
    info!("Stopping {} daemon...", APP_NAME);

    let pid = read_pid_file(&pid_file)?;

    let signal = if force {
        nix::sys::signal::Signal::SIGKILL
    } else {
        nix::sys::signal::Signal::SIGTERM
    };

    nix::sys::signal::kill(nix::unistd::Pid::from_raw(pid), signal).map_err(|e| {
        ZeroedError::Internal {
            message: format!("Failed to send signal to process {}: {}", pid, e),
        }
    })?;

    info!("Signal sent to process {}", pid);

    // Wait for process to exit
    if !force {
        for _ in 0..30 {
            std::thread::sleep(std::time::Duration::from_millis(100));
            if !is_process_running(pid) {
                info!("Daemon stopped successfully");
                // Clean up PID file
                let _ = std::fs::remove_file(&pid_file);
                return Ok(());
            }
        }
        warn!("Daemon did not stop within 3 seconds");
    }

    Ok(())
}

/// Restart the daemon
fn cmd_restart(config_path: PathBuf, interface: Option<String>) -> Result<()> {
    info!("Restarting {} daemon...", APP_NAME);

    // Try to stop existing daemon
    let pid_file = PathBuf::from(DEFAULT_PID_PATH);
    if pid_file.exists() {
        let _ = cmd_stop(pid_file.clone(), false);
        std::thread::sleep(std::time::Duration::from_secs(1));
    }

    // Start new daemon
    cmd_start(config_path, false, interface, Some(pid_file), false)
}

/// Check daemon status
fn cmd_status(pid_file: PathBuf) -> Result<()> {
    if !pid_file.exists() {
        println!("Status: STOPPED (no PID file)");
        return Ok(());
    }

    match read_pid_file(&pid_file) {
        Ok(pid) => {
            if is_process_running(pid) {
                println!("Status: RUNNING (PID: {})", pid);
            } else {
                println!(
                    "Status: STOPPED (stale PID file, process {} not running)",
                    pid
                );
            }
        }
        Err(e) => {
            println!("Status: UNKNOWN (failed to read PID file: {})", e);
        }
    }

    Ok(())
}

/// Validate configuration file
fn cmd_config_check(config_path: PathBuf, show: bool) -> Result<()> {
    info!("Validating configuration: {:?}", config_path);

    match load_config(&config_path) {
        Ok(config) => {
            println!("Configuration is valid!");

            if show {
                println!("\nParsed configuration:");
                println!(
                    "{}",
                    toml::to_string_pretty(&config)
                        .unwrap_or_else(|_| "Failed to serialize".to_string())
                );
            }

            Ok(())
        }
        Err(e) => {
            eprintln!("Configuration is invalid: {}", e);
            Err(e)
        }
    }
}

/// Generate default configuration file
fn cmd_config_gen(output: Option<PathBuf>, force: bool) -> Result<()> {
    let output_path = output.unwrap_or_else(|| PathBuf::from("./zeroed.toml"));

    if output_path.exists() && !force {
        return Err(ZeroedError::Internal {
            message: format!(
                "File {:?} already exists. Use --force to overwrite.",
                output_path
            ),
        });
    }

    let config = ZeroedConfig::default();
    let toml_str = toml::to_string_pretty(&config).map_err(|e| ZeroedError::Internal {
        message: format!("Failed to serialize config: {}", e),
    })?;

    // Add comments
    let commented = format!(
        r#"# Zeroed DoS Protection Daemon Configuration
# Generated by zeroed v{}
#
# See documentation for detailed configuration options.

{}"#,
        APP_VERSION, toml_str
    );

    std::fs::write(&output_path, commented).map_err(|e| ZeroedError::Internal {
        message: format!("Failed to write config file: {}", e),
    })?;

    println!("Configuration file generated: {:?}", output_path);
    Ok(())
}

/// List network interfaces
fn cmd_interfaces() -> Result<()> {
    println!("Available network interfaces:\n");

    let interfaces = network::capture::CaptureEngine::list_interfaces()?;

    for iface in interfaces {
        let status = if iface.is_up { "UP" } else { "DOWN" };
        let loopback = if iface.is_loopback { " (loopback)" } else { "" };

        println!("  {} [{}]{}", iface.name, status, loopback);

        if !iface.addresses.is_empty() {
            for addr in &iface.addresses {
                println!("    Address: {}", addr);
            }
        }

        if !iface.description.is_empty() {
            println!("    Description: {}", iface.description);
        }

        println!();
    }

    // Show default interface
    if let Ok(default) = network::capture::CaptureEngine::default_interface() {
        println!("Default interface: {}", default);
    }

    Ok(())
}

/// Show version information
fn cmd_version(detailed: bool) -> Result<()> {
    println!("{} v{}", APP_NAME, APP_VERSION);

    if detailed {
        println!();
        println!("Build Information:");
        println!("  Rust version: {}", rustc_version());
        println!("  Target: {}", std::env::consts::ARCH);
        println!("  OS: {}", std::env::consts::OS);
        println!();
        println!("Features:");
        println!("  GeoIP support: {}", cfg!(feature = "geoip"));
        println!("  Prometheus metrics: {}", cfg!(feature = "prometheus"));
        println!();
        println!("Repository: https://github.com/security/zeroed");
        println!("License: MIT");
    }

    Ok(())
}

// ─────────────────────────────────────────────────────────────────────────────
// Helper Functions
// ─────────────────────────────────────────────────────────────────────────────

/// Load configuration from file
fn load_config(path: &PathBuf) -> Result<ZeroedConfig> {
    if !path.exists() {
        warn!("Configuration file not found: {:?}, using defaults", path);
        return Ok(ZeroedConfig::default());
    }

    ZeroedConfig::from_file(path).map_err(|e| {
        ZeroedError::Config(core::error::ConfigError::ParseError {
            message: e.to_string(),
        })
    })
}

/// Check if running as root
fn is_root() -> bool {
    #[cfg(unix)]
    {
        nix::unistd::getuid().is_root()
    }
    #[cfg(not(unix))]
    {
        false
    }
}

/// Daemonize the process
fn daemonize(config: &ZeroedConfig) -> Result<()> {
    use daemonize::Daemonize;

    // Create PID file directory
    if let Some(parent) = config.daemon.pid_file.parent() {
        std::fs::create_dir_all(parent).map_err(|e| ZeroedError::Internal {
            message: format!("Failed to create PID directory: {}", e),
        })?;
    }

    // Create working directory
    std::fs::create_dir_all(&config.daemon.working_dir).map_err(|e| ZeroedError::Internal {
        message: format!("Failed to create working directory: {}", e),
    })?;

    let daemonize = Daemonize::new()
        .pid_file(&config.daemon.pid_file)
        .working_directory(&config.daemon.working_dir)
        .umask(0o027);

    daemonize.start().map_err(|e| ZeroedError::Internal {
        message: format!("Failed to daemonize: {}", e),
    })?;

    Ok(())
}

/// Read PID from file
fn read_pid_file(path: &PathBuf) -> Result<i32> {
    let content = std::fs::read_to_string(path).map_err(|e| ZeroedError::Internal {
        message: format!("Failed to read PID file: {}", e),
    })?;

    content.trim().parse().map_err(|e| ZeroedError::Internal {
        message: format!("Invalid PID in file: {}", e),
    })
}

/// Check if a process is running
fn is_process_running(pid: i32) -> bool {
    #[cfg(unix)]
    {
        nix::sys::signal::kill(nix::unistd::Pid::from_raw(pid), None).is_ok()
    }
    #[cfg(not(unix))]
    {
        false
    }
}

/// Get Rust compiler version (placeholder)
fn rustc_version() -> &'static str {
    "1.75.0" // Would be populated at build time
}
