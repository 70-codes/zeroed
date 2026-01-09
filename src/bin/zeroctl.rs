//! Zeroctl - Control utility for the Zeroed DoS Protection Daemon
//!
//! This binary provides a command-line interface for managing and monitoring
//! the Zeroed daemon. It communicates with the daemon via Unix socket.
//!
//! ## Usage
//!
//! ```bash
//! # Check daemon status
//! zeroctl status
//!
//! # List blocked IPs
//! zeroctl list blocked
//!
//! # Block an IP
//! zeroctl block 192.168.1.100
//!
//! # Unblock an IP
//! zeroctl unblock 192.168.1.100
//!
//! # View statistics
//! zeroctl stats
//! ```

use clap::{Parser, Subcommand};
use serde::{Deserialize, Serialize};
use std::io::{Read, Write};
use std::os::unix::net::UnixStream;
use std::path::PathBuf;
use std::process::ExitCode;
use std::time::Duration;

// ─────────────────────────────────────────────────────────────────────────────
// Constants
// ─────────────────────────────────────────────────────────────────────────────

/// Default socket path for daemon communication
const DEFAULT_SOCKET_PATH: &str = "/var/run/zeroed/zeroed.sock";

/// Application name
const APP_NAME: &str = "zeroctl";

/// Application version (should match daemon version)
const APP_VERSION: &str = env!("CARGO_PKG_VERSION");

/// Connection timeout in seconds
const CONNECTION_TIMEOUT_SECS: u64 = 5;

/// Read timeout in seconds
const READ_TIMEOUT_SECS: u64 = 30;

// ─────────────────────────────────────────────────────────────────────────────
// CLI Definition
// ─────────────────────────────────────────────────────────────────────────────

/// Zeroctl - Control utility for the Zeroed DoS Protection Daemon
#[derive(Parser, Debug)]
#[command(
    name = APP_NAME,
    version = APP_VERSION,
    author = "Security Team",
    about = "Control utility for the Zeroed DoS protection daemon",
    long_about = r#"
Zeroctl is the command-line control utility for the Zeroed daemon.

It allows you to:
  • Check daemon status and health
  • View and manage blocked IPs
  • View traffic statistics
  • Manage whitelists and blacklists
  • Reload configuration
  • View recent security events

The utility communicates with the daemon via a Unix socket.
    "#
)]
struct Cli {
    /// Path to daemon control socket
    #[arg(short, long, default_value = DEFAULT_SOCKET_PATH)]
    socket: PathBuf,

    /// Output format: "text" (default), "json", "table"
    #[arg(short, long, default_value = "text")]
    format: OutputFormat,

    /// Enable verbose output
    #[arg(short, long)]
    verbose: bool,

    /// Quiet mode - only show errors
    #[arg(short, long)]
    quiet: bool,

    #[command(subcommand)]
    command: Commands,
}

/// Output format options
#[derive(Debug, Clone, Copy, PartialEq, Eq, clap::ValueEnum)]
enum OutputFormat {
    Text,
    Json,
    Table,
}

/// Available commands
#[derive(Subcommand, Debug)]
enum Commands {
    /// Show daemon status
    Status,

    /// Show traffic and detection statistics
    Stats {
        /// Show detailed statistics
        #[arg(short, long)]
        detailed: bool,
    },

    /// List various entities
    List {
        #[command(subcommand)]
        what: ListCommands,
    },

    /// Block an IP address
    Block {
        /// IP address to block
        ip: String,

        /// Block duration in seconds (0 = permanent)
        #[arg(short, long, default_value = "3600")]
        duration: u64,

        /// Reason for blocking
        #[arg(short, long)]
        reason: Option<String>,
    },

    /// Unblock an IP address
    Unblock {
        /// IP address to unblock
        ip: String,
    },

    /// Add IP to whitelist
    WhitelistAdd {
        /// IP address or CIDR to whitelist
        ip: String,

        /// Comment/reason for whitelisting
        #[arg(short, long)]
        comment: Option<String>,
    },

    /// Remove IP from whitelist
    WhitelistRemove {
        /// IP address or CIDR to remove
        ip: String,
    },

    /// Add IP to blacklist
    BlacklistAdd {
        /// IP address or CIDR to blacklist
        ip: String,

        /// Comment/reason for blacklisting
        #[arg(short, long)]
        comment: Option<String>,
    },

    /// Remove IP from blacklist
    BlacklistRemove {
        /// IP address or CIDR to remove
        ip: String,
    },

    /// Show recent events
    Events {
        /// Number of events to show
        #[arg(short, long, default_value = "20")]
        count: usize,

        /// Filter by event type
        #[arg(short, long)]
        filter: Option<String>,
    },

    /// Lookup information about an IP
    Lookup {
        /// IP address to lookup
        ip: String,
    },

    /// Flush various caches and data
    Flush {
        #[command(subcommand)]
        what: FlushCommands,
    },

    /// Reload daemon configuration
    Reload,

    /// Request daemon shutdown
    Shutdown {
        /// Force shutdown without graceful cleanup
        #[arg(short, long)]
        force: bool,
    },

    /// Show daemon version
    Version,

    /// Test connection to daemon
    Ping,

    /// Export data
    Export {
        /// What to export: "blocked", "whitelist", "blacklist", "stats"
        what: String,

        /// Output file (stdout if not specified)
        #[arg(short, long)]
        output: Option<PathBuf>,
    },

    /// Import data
    Import {
        /// What to import: "whitelist", "blacklist"
        what: String,

        /// Input file
        file: PathBuf,
    },
}

/// List subcommands
#[derive(Subcommand, Debug)]
enum ListCommands {
    /// List blocked IPs
    Blocked {
        /// Maximum number of entries
        #[arg(short, long, default_value = "50")]
        limit: usize,
    },

    /// List tracked IPs
    Tracked {
        /// Maximum number of entries
        #[arg(short, long, default_value = "50")]
        limit: usize,

        /// Sort by: "requests", "bytes", "threat", "recent"
        #[arg(short, long, default_value = "requests")]
        sort: String,
    },

    /// List whitelisted IPs
    Whitelist,

    /// List blacklisted IPs
    Blacklist,

    /// List monitored interfaces
    Interfaces,

    /// List active rules
    Rules,
}

/// Flush subcommands
#[derive(Subcommand, Debug)]
enum FlushCommands {
    /// Flush all blocked IPs
    Blocked,

    /// Flush tracking data
    Tracking,

    /// Flush storage cache
    Cache,

    /// Flush all data
    All,
}

// ─────────────────────────────────────────────────────────────────────────────
// API Types
// ─────────────────────────────────────────────────────────────────────────────

/// Request to send to the daemon
#[derive(Debug, Serialize, Deserialize)]
#[serde(tag = "command", content = "params")]
enum ApiRequest {
    Status,
    Stats {
        detailed: bool,
    },
    ListBlocked {
        limit: usize,
    },
    ListTracked {
        limit: usize,
        sort: String,
    },
    ListWhitelist,
    ListBlacklist,
    ListInterfaces,
    ListRules,
    Block {
        ip: String,
        duration: u64,
        reason: Option<String>,
    },
    Unblock {
        ip: String,
    },
    WhitelistAdd {
        ip: String,
        comment: Option<String>,
    },
    WhitelistRemove {
        ip: String,
    },
    BlacklistAdd {
        ip: String,
        comment: Option<String>,
    },
    BlacklistRemove {
        ip: String,
    },
    Events {
        count: usize,
        filter: Option<String>,
    },
    Lookup {
        ip: String,
    },
    FlushBlocked,
    FlushTracking,
    FlushCache,
    FlushAll,
    Reload,
    Shutdown {
        force: bool,
    },
    Version,
    Ping,
    Export {
        what: String,
    },
    Import {
        what: String,
        data: String,
    },
}

/// Response from the daemon
#[derive(Debug, Serialize, Deserialize)]
#[serde(tag = "status")]
enum ApiResponse {
    Success { data: serde_json::Value },
    Error { code: u32, message: String },
}

// ─────────────────────────────────────────────────────────────────────────────
// Main Entry Point
// ─────────────────────────────────────────────────────────────────────────────

fn main() -> ExitCode {
    let cli = Cli::parse();

    match run(cli) {
        Ok(_) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("Error: {}", e);
            ExitCode::FAILURE
        }
    }
}

/// Main command dispatcher
fn run(cli: Cli) -> Result<(), String> {
    let request = build_request(&cli.command)?;

    // Handle special cases that don't need daemon connection
    match &cli.command {
        Commands::Version => {
            println!("{} v{}", APP_NAME, APP_VERSION);
            return Ok(());
        }
        _ => {}
    }

    // Send request to daemon
    let response = send_request(&cli.socket, &request)?;

    // Format and display response
    display_response(&cli, &cli.command, response)
}

/// Build API request from CLI command
fn build_request(cmd: &Commands) -> Result<ApiRequest, String> {
    let request = match cmd {
        Commands::Status => ApiRequest::Status,

        Commands::Stats { detailed } => ApiRequest::Stats {
            detailed: *detailed,
        },

        Commands::List { what } => match what {
            ListCommands::Blocked { limit } => ApiRequest::ListBlocked { limit: *limit },
            ListCommands::Tracked { limit, sort } => ApiRequest::ListTracked {
                limit: *limit,
                sort: sort.clone(),
            },
            ListCommands::Whitelist => ApiRequest::ListWhitelist,
            ListCommands::Blacklist => ApiRequest::ListBlacklist,
            ListCommands::Interfaces => ApiRequest::ListInterfaces,
            ListCommands::Rules => ApiRequest::ListRules,
        },

        Commands::Block {
            ip,
            duration,
            reason,
        } => ApiRequest::Block {
            ip: ip.clone(),
            duration: *duration,
            reason: reason.clone(),
        },

        Commands::Unblock { ip } => ApiRequest::Unblock { ip: ip.clone() },

        Commands::WhitelistAdd { ip, comment } => ApiRequest::WhitelistAdd {
            ip: ip.clone(),
            comment: comment.clone(),
        },

        Commands::WhitelistRemove { ip } => ApiRequest::WhitelistRemove { ip: ip.clone() },

        Commands::BlacklistAdd { ip, comment } => ApiRequest::BlacklistAdd {
            ip: ip.clone(),
            comment: comment.clone(),
        },

        Commands::BlacklistRemove { ip } => ApiRequest::BlacklistRemove { ip: ip.clone() },

        Commands::Events { count, filter } => ApiRequest::Events {
            count: *count,
            filter: filter.clone(),
        },

        Commands::Lookup { ip } => ApiRequest::Lookup { ip: ip.clone() },

        Commands::Flush { what } => match what {
            FlushCommands::Blocked => ApiRequest::FlushBlocked,
            FlushCommands::Tracking => ApiRequest::FlushTracking,
            FlushCommands::Cache => ApiRequest::FlushCache,
            FlushCommands::All => ApiRequest::FlushAll,
        },

        Commands::Reload => ApiRequest::Reload,

        Commands::Shutdown { force } => ApiRequest::Shutdown { force: *force },

        Commands::Version => ApiRequest::Version,

        Commands::Ping => ApiRequest::Ping,

        Commands::Export { what, .. } => ApiRequest::Export { what: what.clone() },

        Commands::Import { what, file } => {
            let data =
                std::fs::read_to_string(file).map_err(|e| format!("Failed to read file: {}", e))?;
            ApiRequest::Import {
                what: what.clone(),
                data,
            }
        }
    };

    Ok(request)
}

/// Send request to daemon via Unix socket
fn send_request(socket_path: &PathBuf, request: &ApiRequest) -> Result<ApiResponse, String> {
    // Check if socket exists
    if !socket_path.exists() {
        return Err(format!(
            "Daemon socket not found at {:?}. Is the daemon running?",
            socket_path
        ));
    }

    // Connect to socket with timeout
    let stream = UnixStream::connect(socket_path)
        .map_err(|e| format!("Failed to connect to daemon: {}", e))?;

    stream
        .set_read_timeout(Some(Duration::from_secs(READ_TIMEOUT_SECS)))
        .map_err(|e| format!("Failed to set read timeout: {}", e))?;

    stream
        .set_write_timeout(Some(Duration::from_secs(CONNECTION_TIMEOUT_SECS)))
        .map_err(|e| format!("Failed to set write timeout: {}", e))?;

    // Serialize and send request
    let request_json = serde_json::to_string(request)
        .map_err(|e| format!("Failed to serialize request: {}", e))?;

    let mut stream = stream;
    writeln!(stream, "{}", request_json).map_err(|e| format!("Failed to send request: {}", e))?;

    stream
        .flush()
        .map_err(|e| format!("Failed to flush request: {}", e))?;

    // Read response
    let mut response_str = String::new();
    stream
        .read_to_string(&mut response_str)
        .map_err(|e| format!("Failed to read response: {}", e))?;

    // Parse response
    serde_json::from_str(&response_str).map_err(|e| format!("Failed to parse response: {}", e))
}

/// Display response in the requested format
fn display_response(cli: &Cli, cmd: &Commands, response: ApiResponse) -> Result<(), String> {
    match response {
        ApiResponse::Success { data } => {
            match cli.format {
                OutputFormat::Json => {
                    println!("{}", serde_json::to_string_pretty(&data).unwrap());
                }
                OutputFormat::Text | OutputFormat::Table => {
                    display_text_response(cmd, &data)?;
                }
            }
            Ok(())
        }
        ApiResponse::Error { code, message } => Err(format!("Error {}: {}", code, message)),
    }
}

/// Display response as formatted text
fn display_text_response(cmd: &Commands, data: &serde_json::Value) -> Result<(), String> {
    match cmd {
        Commands::Status => {
            println!("╔════════════════════════════════════════════════════════════╗");
            println!("║              Zeroed Daemon Status                          ║");
            println!("╠════════════════════════════════════════════════════════════╣");

            if let Some(obj) = data.as_object() {
                let running_status = serde_json::json!("Running");
                let uptime_val = obj.get("uptime_secs").map(|v| {
                    let secs = v.as_u64().unwrap_or(0);
                    serde_json::json!(format_duration(secs))
                });
                let memory_val = obj.get("memory_usage").map(|v| {
                    let bytes = v.as_u64().unwrap_or(0);
                    serde_json::json!(format_bytes(bytes))
                });

                print_kv("Version", obj.get("version"));
                print_kv("Status", Some(&running_status));
                print_kv("Uptime", uptime_val.as_ref());
                print_kv("Tracked IPs", obj.get("tracked_ips"));
                print_kv("Blocked IPs", obj.get("blocked_ips"));
                print_kv("Packets Processed", obj.get("packets_processed"));
                print_kv("Memory Usage", memory_val.as_ref());
            }

            println!("╚════════════════════════════════════════════════════════════╝");
        }

        Commands::Stats { .. } => {
            println!("╔════════════════════════════════════════════════════════════╗");
            println!("║              Traffic Statistics                            ║");
            println!("╠════════════════════════════════════════════════════════════╣");

            if let Some(obj) = data.as_object() {
                for (key, value) in obj {
                    print_kv(&format_key(key), Some(value));
                }
            }

            println!("╚════════════════════════════════════════════════════════════╝");
        }

        Commands::List { what } => match what {
            ListCommands::Blocked { .. } => {
                println!("Blocked IP Addresses:");
                println!("─────────────────────────────────────────────────────────────");

                if let Some(arr) = data.as_array() {
                    if arr.is_empty() {
                        println!("  No blocked IPs");
                    } else {
                        println!(
                            "{:<20} {:<20} {:<20}",
                            "IP Address", "Blocked At", "Expires"
                        );
                        println!("─────────────────────────────────────────────────────────────");

                        for entry in arr {
                            let ip = entry.get("ip").and_then(|v| v.as_str()).unwrap_or("-");
                            let blocked_at = entry
                                .get("blocked_at")
                                .and_then(|v| v.as_str())
                                .unwrap_or("-");
                            let expires = entry
                                .get("expires")
                                .and_then(|v| v.as_str())
                                .unwrap_or("never");

                            println!("{:<20} {:<20} {:<20}", ip, blocked_at, expires);
                        }
                    }
                }
            }

            ListCommands::Tracked { .. } => {
                println!("Tracked IP Addresses:");
                println!("─────────────────────────────────────────────────────────────");

                if let Some(arr) = data.as_array() {
                    if arr.is_empty() {
                        println!("  No tracked IPs");
                    } else {
                        println!(
                            "{:<18} {:<12} {:<12} {:<10} {:<10}",
                            "IP Address", "Requests", "Bytes", "Threat", "Last Seen"
                        );
                        println!("─────────────────────────────────────────────────────────────");

                        for entry in arr {
                            let ip = entry.get("ip").and_then(|v| v.as_str()).unwrap_or("-");
                            let requests =
                                entry.get("requests").and_then(|v| v.as_u64()).unwrap_or(0);
                            let bytes = entry.get("bytes").and_then(|v| v.as_u64()).unwrap_or(0);
                            let threat = entry
                                .get("threat_level")
                                .and_then(|v| v.as_str())
                                .unwrap_or("-");
                            let last_seen = entry
                                .get("last_seen")
                                .and_then(|v| v.as_str())
                                .unwrap_or("-");

                            println!(
                                "{:<18} {:<12} {:<12} {:<10} {:<10}",
                                ip,
                                requests,
                                format_bytes(bytes),
                                threat,
                                last_seen
                            );
                        }
                    }
                }
            }

            ListCommands::Whitelist => {
                println!("Whitelisted IPs:");
                println!("─────────────────────────────────────────────────────────────");
                print_ip_list(data);
            }

            ListCommands::Blacklist => {
                println!("Blacklisted IPs:");
                println!("─────────────────────────────────────────────────────────────");
                print_ip_list(data);
            }

            ListCommands::Interfaces => {
                println!("Monitored Interfaces:");
                println!("─────────────────────────────────────────────────────────────");

                if let Some(arr) = data.as_array() {
                    for iface in arr {
                        if let Some(name) = iface.as_str() {
                            println!("  • {}", name);
                        }
                    }
                }
            }

            ListCommands::Rules => {
                println!("Active Detection Rules:");
                println!("─────────────────────────────────────────────────────────────");

                if let Some(arr) = data.as_array() {
                    for rule in arr {
                        let id = rule.get("id").and_then(|v| v.as_u64()).unwrap_or(0);
                        let name = rule.get("name").and_then(|v| v.as_str()).unwrap_or("-");
                        let enabled = rule
                            .get("enabled")
                            .and_then(|v| v.as_bool())
                            .unwrap_or(false);

                        let status = if enabled { "✓" } else { "✗" };
                        println!("  {} [{}] {}", status, id, name);
                    }
                }
            }
        },

        Commands::Block { ip, .. } => {
            println!("✓ IP {} has been blocked", ip);
        }

        Commands::Unblock { ip } => {
            println!("✓ IP {} has been unblocked", ip);
        }

        Commands::WhitelistAdd { ip, .. } => {
            println!("✓ IP {} has been added to whitelist", ip);
        }

        Commands::WhitelistRemove { ip } => {
            println!("✓ IP {} has been removed from whitelist", ip);
        }

        Commands::BlacklistAdd { ip, .. } => {
            println!("✓ IP {} has been added to blacklist", ip);
        }

        Commands::BlacklistRemove { ip } => {
            println!("✓ IP {} has been removed from blacklist", ip);
        }

        Commands::Events { .. } => {
            println!("Recent Events:");
            println!("─────────────────────────────────────────────────────────────");

            if let Some(arr) = data.as_array() {
                for event in arr {
                    let timestamp = event
                        .get("timestamp")
                        .and_then(|v| v.as_str())
                        .unwrap_or("-");
                    let event_type = event.get("type").and_then(|v| v.as_str()).unwrap_or("-");
                    let message = event.get("message").and_then(|v| v.as_str()).unwrap_or("-");

                    println!("[{}] {} - {}", timestamp, event_type, message);
                }
            }
        }

        Commands::Lookup { ip } => {
            println!("Information for {}:", ip);
            println!("─────────────────────────────────────────────────────────────");

            if let Some(obj) = data.as_object() {
                for (key, value) in obj {
                    print_kv(&format_key(key), Some(value));
                }
            }
        }

        Commands::Flush { what } => {
            let what_str = match what {
                FlushCommands::Blocked => "blocked IPs",
                FlushCommands::Tracking => "tracking data",
                FlushCommands::Cache => "cache",
                FlushCommands::All => "all data",
            };
            println!("✓ Successfully flushed {}", what_str);
        }

        Commands::Reload => {
            println!("✓ Configuration reloaded successfully");
        }

        Commands::Shutdown { .. } => {
            println!("✓ Shutdown request sent to daemon");
        }

        Commands::Version => {
            if let Some(version) = data.as_str() {
                println!("Daemon version: {}", version);
            }
        }

        Commands::Ping => {
            println!("✓ Daemon is responding");
            if let Some(latency) = data.get("latency_ms") {
                println!("  Latency: {}ms", latency);
            }
        }

        Commands::Export { what, output } => {
            if let Some(output_path) = output {
                let content = serde_json::to_string_pretty(&data).unwrap();
                std::fs::write(output_path, content)
                    .map_err(|e| format!("Failed to write file: {}", e))?;
                println!("✓ Exported {} to {:?}", what, output_path);
            } else {
                println!("{}", serde_json::to_string_pretty(&data).unwrap());
            }
        }

        Commands::Import { what, .. } => {
            println!("✓ Successfully imported {}", what);
            if let Some(count) = data.get("imported_count") {
                println!("  Imported {} entries", count);
            }
        }
    }

    Ok(())
}

// ─────────────────────────────────────────────────────────────────────────────
// Helper Functions
// ─────────────────────────────────────────────────────────────────────────────

/// Print a key-value pair
fn print_kv(key: &str, value: Option<&serde_json::Value>) {
    let val_str = match value {
        Some(v) => {
            if v.is_string() {
                v.as_str().unwrap_or("-").to_string()
            } else {
                v.to_string()
            }
        }
        None => "-".to_string(),
    };
    println!("║  {:<20} │ {:<35} ║", key, val_str);
}

/// Print a list of IPs
fn print_ip_list(data: &serde_json::Value) {
    if let Some(arr) = data.as_array() {
        if arr.is_empty() {
            println!("  (empty)");
        } else {
            for entry in arr {
                if let Some(ip) = entry.as_str() {
                    println!("  • {}", ip);
                } else if let Some(obj) = entry.as_object() {
                    let ip = obj.get("ip").and_then(|v| v.as_str()).unwrap_or("-");
                    let comment = obj.get("comment").and_then(|v| v.as_str());

                    if let Some(c) = comment {
                        println!("  • {} ({})", ip, c);
                    } else {
                        println!("  • {}", ip);
                    }
                }
            }
        }
    }
}

/// Format a key name (snake_case to Title Case)
fn format_key(key: &str) -> String {
    key.split('_')
        .map(|word| {
            let mut chars = word.chars();
            match chars.next() {
                None => String::new(),
                Some(first) => first.to_uppercase().chain(chars).collect(),
            }
        })
        .collect::<Vec<_>>()
        .join(" ")
}

/// Format bytes in human-readable form
fn format_bytes(bytes: u64) -> String {
    const KB: u64 = 1024;
    const MB: u64 = KB * 1024;
    const GB: u64 = MB * 1024;
    const TB: u64 = GB * 1024;

    if bytes >= TB {
        format!("{:.2} TB", bytes as f64 / TB as f64)
    } else if bytes >= GB {
        format!("{:.2} GB", bytes as f64 / GB as f64)
    } else if bytes >= MB {
        format!("{:.2} MB", bytes as f64 / MB as f64)
    } else if bytes >= KB {
        format!("{:.2} KB", bytes as f64 / KB as f64)
    } else {
        format!("{} B", bytes)
    }
}

/// Format duration in human-readable form
fn format_duration(secs: u64) -> String {
    if secs < 60 {
        format!("{}s", secs)
    } else if secs < 3600 {
        format!("{}m {}s", secs / 60, secs % 60)
    } else if secs < 86400 {
        let hours = secs / 3600;
        let mins = (secs % 3600) / 60;
        format!("{}h {}m", hours, mins)
    } else {
        let days = secs / 86400;
        let hours = (secs % 86400) / 3600;
        format!("{}d {}h", days, hours)
    }
}
