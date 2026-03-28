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

    /// Manage deployed applications
    App {
        #[command(subcommand)]
        subcmd: AppCommands,
    },

    /// Manage SSH keys for GitHub access
    SshKey {
        #[command(subcommand)]
        subcmd: SshKeyCommands,
    },

    /// Manage port allocations
    Ports {
        #[command(subcommand)]
        subcmd: PortCommands,
    },

    /// Manage SSL certificates
    Ssl {
        #[command(subcommand)]
        subcmd: SslCommands,
    },
}

/// App management subcommands
#[derive(Subcommand, Debug)]
enum AppCommands {
    /// Create a new application
    Create {
        /// Application name (slug format: lowercase, hyphens only)
        name: String,

        /// Git repository URL
        #[arg(long)]
        repo: String,

        /// Application type: backend, static, hybrid
        #[arg(long, default_value = "backend")]
        r#type: String,

        /// Port for the application (backend/hybrid only)
        #[arg(long, default_value = "0")]
        port: u16,

        /// Git branch
        #[arg(long)]
        branch: Option<String>,

        /// SSH key ID for private repos
        #[arg(long)]
        key: Option<String>,

        /// Custom domain name
        #[arg(long)]
        domain: Option<String>,

        /// Build command (e.g. "npm run build")
        #[arg(long)]
        build_cmd: Option<String>,

        /// Start command (e.g. "node server.js")
        #[arg(long)]
        start_cmd: Option<String>,

        /// Build output directory (e.g. "dist", "build")
        #[arg(long)]
        build_dir: Option<String>,

        /// Enable SPA mode (try_files fallback to index.html)
        #[arg(long)]
        spa: bool,
    },

    /// Deploy or redeploy an application
    Deploy {
        /// Application name
        name: String,

        /// Override branch for this deploy
        #[arg(long)]
        branch: Option<String>,

        /// Force deploy even if no new commits
        #[arg(long)]
        force: bool,

        /// Skip dependency installation
        #[arg(long)]
        skip_deps: bool,

        /// Skip build step
        #[arg(long)]
        skip_build: bool,

        /// Skip health check after deploy
        #[arg(long)]
        skip_health_check: bool,
    },

    /// List all managed applications
    List,

    /// Show detailed information about an application
    Info {
        /// Application name
        name: String,
    },

    /// Stop a running application
    Stop {
        /// Application name
        name: String,
    },

    /// Start a stopped application
    Start {
        /// Application name
        name: String,
    },

    /// Restart an application
    Restart {
        /// Application name
        name: String,
    },

    /// Delete an application
    Delete {
        /// Application name
        name: String,

        /// Also delete all files on disk
        #[arg(long)]
        force: bool,
    },

    /// View application logs (from journalctl)
    Logs {
        /// Application name
        name: String,

        /// Number of log lines to show
        #[arg(short, long, default_value = "50")]
        lines: usize,

        /// Show logs since this time (journalctl format)
        #[arg(long)]
        since: Option<String>,
    },

    /// Rollback to a previous release
    Rollback {
        /// Application name
        name: String,

        /// Target deploy ID to rollback to (default: previous successful)
        #[arg(long)]
        to: Option<String>,
    },

    /// List deployment history / releases
    Releases {
        /// Application name
        name: String,
    },

    /// Change an application's port
    Port {
        /// Application name
        name: String,

        /// New port number
        port: u16,
    },

    /// Set or change an application's domain
    Domain {
        /// Application name
        name: String,

        /// Domain name
        domain: String,
    },

    /// Manage SSL for an application
    SslCmd {
        /// Application name
        name: String,

        /// Action: enable, disable, status
        action: String,
    },

    /// Show the generated nginx config
    Nginx {
        /// Application name
        name: String,
    },

    /// Manage environment variables
    Env {
        /// Application name
        name: String,

        /// Action: list, set KEY=VALUE, unset KEY
        #[arg(trailing_var_arg = true)]
        args: Vec<String>,
    },
}

/// SSH key management subcommands
#[derive(Subcommand, Debug)]
enum SshKeyCommands {
    /// Generate a new SSH key
    Generate {
        /// Key name (human-friendly label)
        name: String,

        /// Key type: ed25519 (default), rsa
        #[arg(long, default_value = "ed25519")]
        r#type: String,
    },

    /// List all managed SSH keys
    List,

    /// Delete an SSH key
    Delete {
        /// Key ID or name
        id: String,
    },

    /// Show the public key (for pasting into GitHub)
    ShowPublic {
        /// Key ID or name
        id: String,
    },

    /// Test SSH connectivity to GitHub
    Test {
        /// Key ID or name
        id: String,
    },
}

/// Port management subcommands
#[derive(Subcommand, Debug)]
enum PortCommands {
    /// List all allocated ports
    List,

    /// Check if a port is available
    Check {
        /// Port number to check
        port: u16,
    },
}

/// SSL management subcommands
#[derive(Subcommand, Debug)]
enum SslCommands {
    /// List all managed certificates
    List,

    /// Check all certificates for expiry
    Check,

    /// Manually renew a certificate
    Renew {
        /// Domain name
        domain: String,
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
    // Deploy commands
    CreateApp { name: String, repo_url: String, app_type: String, port: u16, branch: Option<String>, ssh_key_id: Option<String>, domain: Option<String>, build_cmd: Option<String>, start_cmd: Option<String>, build_dir: Option<String>, spa: bool },
    DeployApp { name: String, branch: Option<String>, force: bool, skip_deps: bool, skip_build: bool, skip_health_check: bool },
    StopApp { name: String },
    StartApp { name: String },
    RestartApp { name: String },
    DeleteApp { name: String, force: bool },
    AppInfo { name: String },
    ListApps,
    AppLogs { name: String, lines: usize, since: Option<String> },
    RollbackApp { name: String, target_id: Option<String> },
    AppReleases { name: String },
    AppSetPort { name: String, port: u16 },
    AppSetDomain { name: String, domain: String },
    AppEnableSsl { name: String },
    AppDisableSsl { name: String },
    AppNginxShow { name: String },
    AppEnvSet { name: String, key: String, value: String },
    AppEnvUnset { name: String, key: String },
    AppEnvList { name: String },
    // SSH key commands
    SshKeyGenerate { name: String, key_type: Option<String> },
    SshKeyList,
    SshKeyDelete { id: String },
    SshKeyShowPublic { id: String },
    SshKeyTest { id: String },
    // Port & SSL commands
    PortsList,
    PortCheck { port: u16 },
    SslList,
    SslCheck,
    SslRenew { domain: String },
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

        // ── App Commands ─────────────────────────────────────────────
        Commands::App { subcmd } => match subcmd {
            AppCommands::Create { name, repo, r#type, port, branch, key, domain, build_cmd, start_cmd, build_dir, spa } => {
                ApiRequest::CreateApp {
                    name: name.clone(), repo_url: repo.clone(), app_type: r#type.clone(),
                    port: *port, branch: branch.clone(), ssh_key_id: key.clone(),
                    domain: domain.clone(), build_cmd: build_cmd.clone(),
                    start_cmd: start_cmd.clone(), build_dir: build_dir.clone(), spa: *spa,
                }
            }
            AppCommands::Deploy { name, branch, force, skip_deps, skip_build, skip_health_check } => {
                ApiRequest::DeployApp {
                    name: name.clone(), branch: branch.clone(), force: *force,
                    skip_deps: *skip_deps, skip_build: *skip_build, skip_health_check: *skip_health_check,
                }
            }
            AppCommands::List => ApiRequest::ListApps,
            AppCommands::Info { name } => ApiRequest::AppInfo { name: name.clone() },
            AppCommands::Stop { name } => ApiRequest::StopApp { name: name.clone() },
            AppCommands::Start { name } => ApiRequest::StartApp { name: name.clone() },
            AppCommands::Restart { name } => ApiRequest::RestartApp { name: name.clone() },
            AppCommands::Delete { name, force } => ApiRequest::DeleteApp { name: name.clone(), force: *force },
            AppCommands::Logs { name, lines, since } => ApiRequest::AppLogs { name: name.clone(), lines: *lines, since: since.clone() },
            AppCommands::Rollback { name, to } => ApiRequest::RollbackApp { name: name.clone(), target_id: to.clone() },
            AppCommands::Releases { name } => ApiRequest::AppReleases { name: name.clone() },
            AppCommands::Port { name, port } => ApiRequest::AppSetPort { name: name.clone(), port: *port },
            AppCommands::Domain { name, domain } => ApiRequest::AppSetDomain { name: name.clone(), domain: domain.clone() },
            AppCommands::SslCmd { name, action } => match action.as_str() {
                "enable" => ApiRequest::AppEnableSsl { name: name.clone() },
                "disable" => ApiRequest::AppDisableSsl { name: name.clone() },
                _ => return Err(format!("Unknown SSL action '{}'. Use: enable, disable", action)),
            },
            AppCommands::Nginx { name } => ApiRequest::AppNginxShow { name: name.clone() },
            AppCommands::Env { name, args } => {
                if args.is_empty() || args[0] == "list" {
                    ApiRequest::AppEnvList { name: name.clone() }
                } else if args[0] == "set" && args.len() >= 2 {
                    let kv = &args[1];
                    if let Some((k, v)) = kv.split_once('=') {
                        ApiRequest::AppEnvSet { name: name.clone(), key: k.to_string(), value: v.to_string() }
                    } else {
                        return Err("Usage: app env <name> set KEY=VALUE".to_string());
                    }
                } else if args[0] == "unset" && args.len() >= 2 {
                    ApiRequest::AppEnvUnset { name: name.clone(), key: args[1].clone() }
                } else {
                    return Err("Usage: app env <name> [list|set KEY=VALUE|unset KEY]".to_string());
                }
            }
        },

        // ── SSH Key Commands ─────────────────────────────────────────
        Commands::SshKey { subcmd } => match subcmd {
            SshKeyCommands::Generate { name, r#type } => ApiRequest::SshKeyGenerate { name: name.clone(), key_type: Some(r#type.clone()) },
            SshKeyCommands::List => ApiRequest::SshKeyList,
            SshKeyCommands::Delete { id } => ApiRequest::SshKeyDelete { id: id.clone() },
            SshKeyCommands::ShowPublic { id } => ApiRequest::SshKeyShowPublic { id: id.clone() },
            SshKeyCommands::Test { id } => ApiRequest::SshKeyTest { id: id.clone() },
        },

        // ── Port Commands ────────────────────────────────────────────
        Commands::Ports { subcmd } => match subcmd {
            PortCommands::List => ApiRequest::PortsList,
            PortCommands::Check { port } => ApiRequest::PortCheck { port: *port },
        },

        // ── SSL Commands ─────────────────────────────────────────────
        Commands::Ssl { subcmd } => match subcmd {
            SslCommands::List => ApiRequest::SslList,
            SslCommands::Check => ApiRequest::SslCheck,
            SslCommands::Renew { domain } => ApiRequest::SslRenew { domain: domain.clone() },
        },
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
        // ── Deploy display handlers ──────────────────────────────────
        Commands::App { subcmd } => {
            match subcmd {
                AppCommands::List => {
                    if let Some(apps) = data.get("apps").and_then(|a| a.as_array()) {
                        if apps.is_empty() {
                            println!("No applications registered.");
                        } else {
                            println!("{:<20} {:<12} {:<10} {:<8} {:<20} {:<10}", "NAME", "TYPE", "STATUS", "PORT", "DOMAIN", "COMMIT");
                            println!("{}", "─".repeat(80));
                            for app in apps {
                                println!("{:<20} {:<12} {:<10} {:<8} {:<20} {:<10}",
                                    app["name"].as_str().unwrap_or("-"),
                                    app["app_type"].as_str().unwrap_or("-"),
                                    app["status"].as_str().unwrap_or("-"),
                                    app["port"].as_u64().map(|p| p.to_string()).unwrap_or_else(|| "-".into()),
                                    app["domain"].as_str().unwrap_or("-"),
                                    app["current_commit"].as_str().unwrap_or("-"),
                                );
                            }
                        }
                        if let Some(summary) = data.get("summary") {
                            println!("\nTotal: {} | Running: {} | Stopped: {} | Failed: {}",
                                summary["total"].as_u64().unwrap_or(0),
                                summary["running"].as_u64().unwrap_or(0),
                                summary["stopped"].as_u64().unwrap_or(0),
                                summary["failed"].as_u64().unwrap_or(0),
                            );
                        }
                    }
                }
                AppCommands::Info { .. } => {
                    if let Some(obj) = data.as_object() {
                        println!("Application: {}", obj.get("name").and_then(|v| v.as_str()).unwrap_or("?"));
                        println!("{}", "─".repeat(50));
                        for (key, val) in obj {
                            let display_val = if val.is_null() { "-".to_string() } else { format!("{}", val).trim_matches('"').to_string() };
                            println!("  {:<20} {}", format_key(key), display_val);
                        }
                    }
                }
                AppCommands::Deploy { .. } => {
                    let success = data.get("success").and_then(|v| v.as_bool()).unwrap_or(false);
                    if success {
                        println!("✓ Deployment successful");
                        println!("  Deploy ID: {}", data["deploy_id"].as_str().unwrap_or("?"));
                        println!("  Commit:    {}", data["commit"].as_str().unwrap_or("?"));
                        println!("  Duration:  {}s", data["duration_secs"].as_u64().unwrap_or(0));
                        if let Some(warns) = data.get("warnings").and_then(|w| w.as_array()) {
                            for w in warns {
                                println!("  ⚠ {}", w.as_str().unwrap_or(""));
                            }
                        }
                    } else {
                        println!("✗ Deployment failed");
                        if let Some(err) = data.get("error").and_then(|v| v.as_str()) {
                            println!("  Error: {}", err);
                        }
                    }
                }
                AppCommands::Logs { .. } => {
                    if let Some(logs) = data.get("logs").and_then(|v| v.as_str()) {
                        print!("{}", logs);
                    }
                }
                AppCommands::Releases { .. } => {
                    if let Some(releases) = data.get("releases").and_then(|r| r.as_array()) {
                        println!("{:<26} {:<10} {:<10} {:<8} {:<8} {}", "ID", "STATUS", "COMMIT", "BRANCH", "SECS", "TRIGGER");
                        println!("{}", "─".repeat(80));
                        for r in releases {
                            println!("{:<26} {:<10} {:<10} {:<8} {:<8} {}",
                                r["id"].as_str().unwrap_or("-"),
                                r["status"].as_str().unwrap_or("-"),
                                r["commit"].as_str().unwrap_or("-"),
                                r["branch"].as_str().unwrap_or("-"),
                                r["duration_secs"].as_u64().map(|d| d.to_string()).unwrap_or_else(|| "-".into()),
                                r["trigger"].as_str().unwrap_or("-"),
                            );
                        }
                    }
                }
                AppCommands::Nginx { .. } => {
                    if let Some(config) = data.get("nginx_config").and_then(|v| v.as_str()) {
                        println!("{}", config);
                    }
                }
                AppCommands::Env { .. } => {
                    if let Some(env) = data.get("env").and_then(|e| e.as_object()) {
                        for (k, v) in env {
                            println!("{}={}", k, v.as_str().unwrap_or(""));
                        }
                    } else {
                        // Single set/unset response
                        println!("{}", serde_json::to_string_pretty(data).unwrap_or_default());
                    }
                }
                _ => {
                    // Generic JSON output for other app subcommands
                    println!("{}", serde_json::to_string_pretty(data).unwrap_or_default());
                }
            }
        }

        Commands::SshKey { subcmd } => {
            match subcmd {
                SshKeyCommands::List => {
                    if let Some(keys) = data.get("keys").and_then(|k| k.as_array()) {
                        if keys.is_empty() {
                            println!("No SSH keys registered.");
                        } else {
                            println!("{:<34} {:<16} {:<10} {:<30}", "ID", "NAME", "TYPE", "FINGERPRINT");
                            println!("{}", "─".repeat(90));
                            for k in keys {
                                println!("{:<34} {:<16} {:<10} {:<30}",
                                    k["id"].as_str().unwrap_or("-"),
                                    k["name"].as_str().unwrap_or("-"),
                                    k["key_type"].as_str().unwrap_or("-"),
                                    k["fingerprint"].as_str().unwrap_or("-"),
                                );
                            }
                        }
                    }
                }
                SshKeyCommands::ShowPublic { .. } => {
                    if let Some(pk) = data.get("public_key").and_then(|v| v.as_str()) {
                        println!("{}", pk);
                    }
                }
                _ => {
                    println!("{}", serde_json::to_string_pretty(data).unwrap_or_default());
                }
            }
        }

        Commands::Ports { subcmd } => {
            match subcmd {
                PortCommands::List => {
                    if let Some(allocs) = data.get("allocations").and_then(|a| a.as_array()) {
                        if allocs.is_empty() {
                            println!("No ports allocated.");
                        } else {
                            println!("{:<8} {:<20}", "PORT", "APPLICATION");
                            println!("{}", "─".repeat(30));
                            for a in allocs {
                                println!("{:<8} {:<20}",
                                    a["port"].as_u64().unwrap_or(0),
                                    a["app"].as_str().unwrap_or("-"),
                                );
                            }
                        }
                    }
                }
                PortCommands::Check { port } => {
                    let available = data.get("available").and_then(|v| v.as_bool()).unwrap_or(false);
                    if available {
                        println!("✓ Port {} is available", port);
                    } else {
                        println!("✗ Port {} is NOT available: {}", port,
                            data.get("details").and_then(|v| v.as_str()).unwrap_or("unknown reason"));
                    }
                }
            }
        }

        Commands::Ssl { subcmd } => {
            match subcmd {
                SslCommands::List => {
                    if let Some(certs) = data.get("certificates").and_then(|c| c.as_array()) {
                        if certs.is_empty() {
                            println!("No SSL certificates managed.");
                        } else {
                            println!("{:<30} {:<14} {:<14} {:<6}", "DOMAIN", "STATUS", "PROVIDER", "DAYS");
                            println!("{}", "─".repeat(65));
                            for c in certs {
                                println!("{:<30} {:<14} {:<14} {:<6}",
                                    c["domain"].as_str().unwrap_or("-"),
                                    c["status"].as_str().unwrap_or("-"),
                                    c["provider"].as_str().unwrap_or("-"),
                                    c["days_until_expiry"].as_i64().map(|d| d.to_string()).unwrap_or_else(|| "?".into()),
                                );
                            }
                        }
                    }
                }
                _ => {
                    println!("{}", serde_json::to_string_pretty(data).unwrap_or_default());
                }
            }
        }

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
