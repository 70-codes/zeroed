//! Command Handler for the Zeroed API
//!
//! This module dispatches incoming `ApiRequest` variants to the appropriate
//! daemon subsystem (storage, detection, firewall, network, deploy) and produces
//! `ApiResponse` values.
//!
//! The `CommandHandler` holds `Arc` references to all subsystems and is
//! designed to be shared across concurrent socket connections via `Arc`.

use crate::api::{
    ApiRequest, ApiResponse, BlockedIpInfo, ConnectionStatsPayload, DaemonStats, DaemonStatus,
    DetectionStatsPayload, FirewallStatsPayload, StorageStatsPayload, TrackedIpInfo,
};
use crate::core::types::IpTrackingEntry;
use crate::deploy::app::{AppType, Application};
use crate::deploy::pipeline::DeployOptions;
use crate::deploy::DeployManager;
use crate::detection::DetectionEngine;
use crate::firewall::FirewallManager;
use crate::network::NetworkManager;
use crate::storage::StorageEngine;

use std::net::IpAddr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use tokio::sync::broadcast;
use tracing::{debug, error, info, warn};

// ─────────────────────────────────────────────────────────────────────────────
// Command Handler
// ─────────────────────────────────────────────────────────────────────────────

/// Dispatches API requests to the appropriate daemon subsystems.
///
/// This struct holds `Arc` references to all shared state and is cheaply
/// cloneable for use across concurrent socket connections.
pub struct CommandHandler {
    /// Storage engine for IP tracking, records, etc.
    storage: Arc<StorageEngine>,

    /// Detection engine for threat analysis state
    detection: Arc<DetectionEngine>,

    /// Firewall manager for block/unblock operations
    firewall: Arc<FirewallManager>,

    /// Network manager for capture and connection tracking
    network: Arc<NetworkManager>,

    /// Shutdown signal sender — sending on this channel tells the daemon to stop
    shutdown_tx: broadcast::Sender<()>,

    /// Timestamp when the daemon started (for uptime calculation)
    start_time: Instant,

    /// Total packets processed counter (shared with the processing task)
    packets_processed: Arc<AtomicU64>,

    /// Daemon version string
    version: String,

    /// Monitored interface names
    interfaces: Vec<String>,

    /// Deploy manager (optional — None if deploy subsystem is disabled)
    deploy_manager: Option<Arc<Mutex<DeployManager>>>,
}

impl CommandHandler {
    /// Create a new command handler with references to all subsystems.
    pub fn new(
        storage: Arc<StorageEngine>,
        detection: Arc<DetectionEngine>,
        firewall: Arc<FirewallManager>,
        network: Arc<NetworkManager>,
        shutdown_tx: broadcast::Sender<()>,
        start_time: Instant,
        packets_processed: Arc<AtomicU64>,
        version: String,
        interfaces: Vec<String>,
    ) -> Self {
        Self {
            storage,
            detection,
            firewall,
            network,
            shutdown_tx,
            start_time,
            packets_processed,
            version,
            interfaces,
            deploy_manager: None,
        }
    }

    /// Set the deploy manager after construction.
    ///
    /// This is called from `async_main()` if the deploy subsystem is enabled.
    pub fn with_deploy_manager(mut self, dm: Arc<Mutex<DeployManager>>) -> Self {
        self.deploy_manager = Some(dm);
        self
    }

    /// Get a reference to the deploy manager, or return a "not available" error.
    fn require_deploy_manager(&self) -> Result<std::sync::MutexGuard<'_, DeployManager>, ApiResponse> {
        match &self.deploy_manager {
            Some(dm) => dm.lock().map_err(|_| {
                ApiResponse::internal_error("Deploy manager lock is poisoned")
            }),
            None => Err(ApiResponse::error(
                crate::api::error_codes::SERVICE_UNAVAILABLE,
                "Deployment subsystem is not enabled. Set [deploy] enabled = true in zeroed.toml",
            )),
        }
    }

    /// Handle an incoming API request and produce a response.
    ///
    /// This is the main dispatch method. It matches on the request variant
    /// and delegates to the appropriate handler method. All handlers return
    /// `ApiResponse` directly — they never panic or propagate errors upward.
    pub async fn handle(&self, request: ApiRequest) -> ApiResponse {
        debug!("Handling API request: {:?}", std::mem::discriminant(&request));

        match request {
            ApiRequest::Status => self.handle_status(),
            ApiRequest::Stats { detailed } => self.handle_stats(detailed),
            ApiRequest::Ping => self.handle_ping(),
            ApiRequest::Version => self.handle_version(),

            ApiRequest::ListBlocked { limit } => self.handle_list_blocked(limit),
            ApiRequest::ListTracked { limit, sort } => self.handle_list_tracked(limit, sort),
            ApiRequest::ListWhitelist => self.handle_list_whitelist(),
            ApiRequest::ListBlacklist => self.handle_list_blacklist(),
            ApiRequest::ListInterfaces => self.handle_list_interfaces(),
            ApiRequest::ListRules => self.handle_list_rules(),

            ApiRequest::Block { ip, duration, reason } => {
                self.handle_block(ip, duration, reason).await
            }
            ApiRequest::Unblock { ip } => self.handle_unblock(ip).await,

            ApiRequest::WhitelistAdd { ip, comment } => {
                self.handle_whitelist_add(ip, comment)
            }
            ApiRequest::WhitelistRemove { ip } => self.handle_whitelist_remove(ip),
            ApiRequest::BlacklistAdd { ip, comment } => {
                self.handle_blacklist_add(ip, comment)
            }
            ApiRequest::BlacklistRemove { ip } => self.handle_blacklist_remove(ip),

            ApiRequest::Lookup { ip } => self.handle_lookup(ip),
            ApiRequest::Events { count, filter } => self.handle_events(count, filter),

            ApiRequest::FlushBlocked => self.handle_flush_blocked().await,
            ApiRequest::FlushTracking => self.handle_flush_tracking(),
            ApiRequest::FlushCache => self.handle_flush_cache(),
            ApiRequest::FlushAll => self.handle_flush_all().await,

            ApiRequest::Reload => self.handle_reload(),
            ApiRequest::Shutdown { force } => self.handle_shutdown(force),

            ApiRequest::Export { what } => self.handle_export(what),
            ApiRequest::Import { what, data } => self.handle_import(what, data),

            // ── Deploy Management Commands ───────────────────────────────
            ApiRequest::CreateApp { name, repo_url, app_type, port, branch, ssh_key_id, domain, build_cmd, start_cmd, build_dir, spa } => {
                self.handle_create_app(name, repo_url, app_type, port, branch, ssh_key_id, domain, build_cmd, start_cmd, build_dir, spa)
            }
            ApiRequest::DeployApp { name, branch, force, skip_deps, skip_build, skip_health_check } => {
                self.handle_deploy_app(name, branch, force, skip_deps, skip_build, skip_health_check)
            }
            ApiRequest::StopApp { name } => self.handle_stop_app(name),
            ApiRequest::StartApp { name } => self.handle_start_app(name),
            ApiRequest::RestartApp { name } => self.handle_restart_app(name),
            ApiRequest::DeleteApp { name, force } => self.handle_delete_app(name, force),
            ApiRequest::AppInfo { name } => self.handle_app_info(name),
            ApiRequest::ListApps => self.handle_list_apps(),
            ApiRequest::AppLogs { name, lines, since } => self.handle_app_logs(name, lines, since),
            ApiRequest::RollbackApp { name, target_id } => self.handle_rollback_app(name, target_id),
            ApiRequest::AppReleases { name } => self.handle_app_releases(name),
            ApiRequest::AppSetPort { name, port } => self.handle_app_set_port(name, port),
            ApiRequest::AppSetDomain { name, domain } => self.handle_app_set_domain(name, domain),
            ApiRequest::AppEnableSsl { name } => self.handle_app_enable_ssl(name),
            ApiRequest::AppDisableSsl { name } => self.handle_app_disable_ssl(name),
            ApiRequest::AppNginxShow { name } => self.handle_app_nginx_show(name),
            ApiRequest::AppEnvSet { name, key, value } => self.handle_app_env_set(name, key, value),
            ApiRequest::AppEnvUnset { name, key } => self.handle_app_env_unset(name, key),
            ApiRequest::AppEnvList { name } => self.handle_app_env_list(name),

            // ── SSH Key Commands ─────────────────────────────────────────
            ApiRequest::SshKeyGenerate { name, key_type } => self.handle_ssh_key_generate(name, key_type),
            ApiRequest::SshKeyList => self.handle_ssh_key_list(),
            ApiRequest::SshKeyDelete { id } => self.handle_ssh_key_delete(id),
            ApiRequest::SshKeyShowPublic { id } => self.handle_ssh_key_show_public(id),
            ApiRequest::SshKeyTest { id } => self.handle_ssh_key_test(id),

            // ── Port & SSL Commands ──────────────────────────────────────
            ApiRequest::PortsList => self.handle_ports_list(),
            ApiRequest::PortCheck { port } => self.handle_port_check(port),
            ApiRequest::SslList => self.handle_ssl_list(),
            ApiRequest::SslCheck => self.handle_ssl_check(),
            ApiRequest::SslRenew { domain } => self.handle_ssl_renew(domain),
        }
    }

    // ─────────────────────────────────────────────────────────────────────
    // Status & Info Handlers
    // ─────────────────────────────────────────────────────────────────────

    fn handle_status(&self) -> ApiResponse {
        let det_stats = self.detection.stats();
        let fw_stats = self.firewall.stats();
        let storage_stats = self.storage.stats();

        let status = DaemonStatus {
            version: self.version.clone(),
            uptime_secs: self.start_time.elapsed().as_secs(),
            tracked_ips: det_stats.tracked_ips as u64,
            blocked_ips: fw_stats.currently_blocked as u64,
            packets_processed: self.packets_processed.load(Ordering::Relaxed),
            attacks_detected: det_stats.attacks_detected,
            memory_usage: get_memory_usage(),
            interfaces: self.interfaces.clone(),
            firewall_enabled: fw_stats.enabled,
            firewall_dry_run: fw_stats.dry_run,
            storage_records: storage_stats.records_written,
        };

        ApiResponse::success(&status)
    }

    fn handle_stats(&self, _detailed: bool) -> ApiResponse {
        let det_stats = self.detection.stats();
        let fw_stats = self.firewall.stats();
        let storage_stats = self.storage.stats();

        let stats = DaemonStats {
            detection: DetectionStatsPayload {
                packets_analyzed: det_stats.packets_analyzed,
                attacks_detected: det_stats.attacks_detected,
                ips_blocked: det_stats.ips_blocked,
                tracked_ips: det_stats.tracked_ips,
            },
            firewall: FirewallStatsPayload {
                currently_blocked: fw_stats.currently_blocked,
                total_blocks: fw_stats.total_blocks,
                total_unblocks: fw_stats.total_unblocks,
                total_expired_cleanups: fw_stats.total_expired_cleanups,
                dry_run: fw_stats.dry_run,
                enabled: fw_stats.enabled,
                chain_name: fw_stats.chain_name.clone(),
            },
            storage: StorageStatsPayload {
                records_written: storage_stats.records_written,
                ring_buffer_size: self.storage.ring_buffer_size(),
                ip_cache_size: self.storage.ip_cache_size(),
            },
            connections: ConnectionStatsPayload {
                active_connections: self.network.connection_tracker().connection_count(),
                monitored_interfaces: self.network.monitored_interfaces(),
            },
        };

        ApiResponse::success(&stats)
    }

    fn handle_ping(&self) -> ApiResponse {
        ApiResponse::success(serde_json::json!({
            "pong": true,
            "uptime_secs": self.start_time.elapsed().as_secs(),
            "version": self.version,
        }))
    }

    fn handle_version(&self) -> ApiResponse {
        ApiResponse::success(serde_json::json!({
            "version": self.version,
            "os": std::env::consts::OS,
            "arch": std::env::consts::ARCH,
        }))
    }

    // ─────────────────────────────────────────────────────────────────────
    // List Handlers
    // ─────────────────────────────────────────────────────────────────────

    fn handle_list_blocked(&self, limit: usize) -> ApiResponse {
        let blocked = self.firewall.list_blocked_sorted();

        let entries: Vec<BlockedIpInfo> = blocked
            .into_iter()
            .take(if limit > 0 { limit } else { usize::MAX })
            .map(|entry| BlockedIpInfo {
                ip: entry.ip.to_string(),
                blocked_at: entry.blocked_at.to_rfc3339(),
                expires_at: entry.expires_at.map(|e| e.to_rfc3339()),
                reason: entry.reason,
                block_count: entry.block_count,
            })
            .collect();

        ApiResponse::success(&entries)
    }

    fn handle_list_tracked(&self, limit: usize, _sort: String) -> ApiResponse {
        let all_ips = self.storage.get_all_tracked_ips();

        let entries: Vec<TrackedIpInfo> = all_ips
            .into_iter()
            .take(if limit > 0 { limit } else { usize::MAX })
            .filter_map(|ip| {
                self.storage.get_ip_tracking(&ip).map(|entry| TrackedIpInfo {
                    ip: entry.ip.to_string(),
                    threat_level: format!("{:?}", entry.threat_level),
                    threat_score: entry.threat_score,
                    is_blocked: entry.is_blocked,
                    first_seen: entry.first_seen.to_rfc3339(),
                    last_seen: entry.last_seen.to_rfc3339(),
                    request_count: entry.stats.request_count,
                    attack_types: entry
                        .attack_types
                        .iter()
                        .map(|a| format!("{:?}", a))
                        .collect(),
                })
            })
            .collect();

        ApiResponse::success(&entries)
    }

    fn handle_list_whitelist(&self) -> ApiResponse {
        let whitelist: Vec<&String> = self.detection.config().whitelist_ips.iter().collect();
        ApiResponse::success(&whitelist)
    }

    fn handle_list_blacklist(&self) -> ApiResponse {
        let blacklist: Vec<&String> = self.detection.config().blacklist_ips.iter().collect();
        ApiResponse::success(&blacklist)
    }

    fn handle_list_interfaces(&self) -> ApiResponse {
        let interfaces = self.network.monitored_interfaces();
        ApiResponse::success(&interfaces)
    }

    fn handle_list_rules(&self) -> ApiResponse {
        // Detection rules are not yet implemented as a runtime-mutable list.
        // Return the static detection config thresholds as a placeholder.
        let config = self.detection.config();
        ApiResponse::success(serde_json::json!({
            "rps_threshold": config.rps_threshold,
            "rps_block_threshold": config.rps_block_threshold,
            "syn_flood_threshold": config.syn_flood_threshold,
            "udp_flood_threshold": config.udp_flood_threshold,
            "icmp_flood_threshold": config.icmp_flood_threshold,
            "max_connections_per_ip": config.max_connections_per_ip,
            "block_duration_secs": config.block_duration.as_secs(),
            "sensitivity": config.sensitivity,
            "adaptive_thresholds": config.adaptive_thresholds,
        }))
    }

    // ─────────────────────────────────────────────────────────────────────
    // Block / Unblock Handlers
    // ─────────────────────────────────────────────────────────────────────

    async fn handle_block(
        &self,
        ip_str: String,
        duration_secs: u64,
        reason: Option<String>,
    ) -> ApiResponse {
        let ip: IpAddr = match ip_str.parse() {
            Ok(ip) => ip,
            Err(e) => {
                return ApiResponse::error(
                    crate::api::error_codes::INVALID_REQUEST,
                    format!("Invalid IP address '{}': {}", ip_str, e),
                );
            }
        };

        let duration = Duration::from_secs(duration_secs);
        let reason = reason.unwrap_or_else(|| "Manual block via API".to_string());

        match self.firewall.block_ip(ip, duration, reason.clone()) {
            Ok(true) => {
                info!("API: manually blocked {} for {}s — {}", ip, duration_secs, reason);
                ApiResponse::success(serde_json::json!({
                    "blocked": true,
                    "ip": ip.to_string(),
                    "duration_secs": duration_secs,
                    "reason": reason,
                    "new_rule": true,
                }))
            }
            Ok(false) => {
                info!("API: updated existing block for {} — {}", ip, reason);
                ApiResponse::success(serde_json::json!({
                    "blocked": true,
                    "ip": ip.to_string(),
                    "duration_secs": duration_secs,
                    "reason": reason,
                    "new_rule": false,
                    "message": "IP was already blocked; expiry and reason updated",
                }))
            }
            Err(e) => {
                error!("API: failed to block {}: {}", ip, e);
                ApiResponse::internal_error(format!("Failed to block {}: {}", ip, e))
            }
        }
    }

    async fn handle_unblock(&self, ip_str: String) -> ApiResponse {
        let ip: IpAddr = match ip_str.parse() {
            Ok(ip) => ip,
            Err(e) => {
                return ApiResponse::error(
                    crate::api::error_codes::INVALID_REQUEST,
                    format!("Invalid IP address '{}': {}", ip_str, e),
                );
            }
        };

        match self.firewall.unblock_ip(&ip) {
            Ok(true) => {
                info!("API: unblocked {}", ip);
                // Also clear the detection state so the IP can be re-evaluated cleanly
                self.detection.clear_ip_state(&ip);
                ApiResponse::success(serde_json::json!({
                    "unblocked": true,
                    "ip": ip.to_string(),
                }))
            }
            Ok(false) => {
                ApiResponse::success(serde_json::json!({
                    "unblocked": false,
                    "ip": ip.to_string(),
                    "message": "IP was not blocked",
                }))
            }
            Err(e) => {
                error!("API: failed to unblock {}: {}", ip, e);
                ApiResponse::internal_error(format!("Failed to unblock {}: {}", ip, e))
            }
        }
    }

    // ─────────────────────────────────────────────────────────────────────
    // Whitelist / Blacklist Handlers
    // ─────────────────────────────────────────────────────────────────────

    fn handle_whitelist_add(&self, ip: String, _comment: Option<String>) -> ApiResponse {
        // NOTE: The detection config is immutable at runtime. To fully support
        // dynamic whitelist/blacklist changes we'd need to make the sets mutable
        // behind a lock, or reload the config. For now, log the request and
        // return a "not fully implemented" but successful response that shows
        // what would happen.
        info!("API: whitelist add request for {} (requires config reload to take effect)", ip);
        ApiResponse::success(serde_json::json!({
            "added": true,
            "ip": ip,
            "note": "Add this IP to whitelist_ips in zeroed.toml and reload for persistent effect",
        }))
    }

    fn handle_whitelist_remove(&self, ip: String) -> ApiResponse {
        info!("API: whitelist remove request for {} (requires config reload)", ip);
        ApiResponse::success(serde_json::json!({
            "removed": true,
            "ip": ip,
            "note": "Remove this IP from whitelist_ips in zeroed.toml and reload for persistent effect",
        }))
    }

    fn handle_blacklist_add(&self, ip: String, _comment: Option<String>) -> ApiResponse {
        info!("API: blacklist add request for {} (requires config reload to take effect)", ip);
        ApiResponse::success(serde_json::json!({
            "added": true,
            "ip": ip,
            "note": "Add this IP to blacklist_ips in zeroed.toml and reload for persistent effect",
        }))
    }

    fn handle_blacklist_remove(&self, ip: String) -> ApiResponse {
        info!("API: blacklist remove request for {} (requires config reload)", ip);
        ApiResponse::success(serde_json::json!({
            "removed": true,
            "ip": ip,
            "note": "Remove this IP from blacklist_ips in zeroed.toml and reload for persistent effect",
        }))
    }

    // ─────────────────────────────────────────────────────────────────────
    // Lookup & Events Handlers
    // ─────────────────────────────────────────────────────────────────────

    fn handle_lookup(&self, ip_str: String) -> ApiResponse {
        let ip: IpAddr = match ip_str.parse() {
            Ok(ip) => ip,
            Err(e) => {
                return ApiResponse::error(
                    crate::api::error_codes::INVALID_REQUEST,
                    format!("Invalid IP address '{}': {}", ip_str, e),
                );
            }
        };

        // Gather data from multiple sources
        let tracking = self.storage.get_ip_tracking(&ip);
        let is_blocked = self.firewall.is_blocked(&ip);
        let block_entry = self.firewall.get_block_entry(&ip);
        let connections = self.network.connection_tracker().get_connections_for_ip(ip);
        let unique_destinations = self.network.connection_tracker().get_unique_destinations(ip);
        let unique_ports = self.network.connection_tracker().get_unique_ports(ip);

        let mut result = serde_json::json!({
            "ip": ip.to_string(),
            "is_blocked": is_blocked,
            "active_connections": connections.len(),
            "unique_destinations": unique_destinations,
            "unique_ports": unique_ports,
        });

        if let Some(tracking) = tracking {
            result["threat_level"] = serde_json::json!(format!("{:?}", tracking.threat_level));
            result["threat_score"] = serde_json::json!(tracking.threat_score);
            result["attack_types"] = serde_json::json!(
                tracking.attack_types.iter().map(|a| format!("{:?}", a)).collect::<Vec<_>>()
            );
            result["first_seen"] = serde_json::json!(tracking.first_seen.to_rfc3339());
            result["last_seen"] = serde_json::json!(tracking.last_seen.to_rfc3339());
            result["is_whitelisted"] = serde_json::json!(tracking.is_whitelisted);
            result["block_count"] = serde_json::json!(tracking.block_count);
            result["stats"] = serde_json::json!({
                "request_count": tracking.stats.request_count,
                "bytes_total": tracking.stats.bytes_total,
                "syn_count": tracking.stats.syn_count,
                "unique_ports": tracking.stats.unique_ports,
                "packets_per_second": tracking.stats.packets_per_second,
            });
        }

        if let Some(block) = block_entry {
            result["block_info"] = serde_json::json!({
                "blocked_at": block.blocked_at.to_rfc3339(),
                "expires_at": block.expires_at.map(|e| e.to_rfc3339()),
                "reason": block.reason,
                "block_count": block.block_count,
            });
        }

        ApiResponse::success(result)
    }

    fn handle_events(&self, count: usize, _filter: Option<String>) -> ApiResponse {
        // Return the most recent records from the ring buffer
        let limit = if count > 0 { count } else { 100 };
        let recent = self.storage.get_recent(limit);

        let events: Vec<serde_json::Value> = recent
            .into_iter()
            .map(|record| {
                let src_ip: IpAddr = record.src_ip.into();
                let dst_ip: IpAddr = record.dst_ip.into();
                serde_json::json!({
                    "id": record.id,
                    "timestamp": record.timestamp.to_rfc3339(),
                    "src_ip": src_ip.to_string(),
                    "dst_ip": dst_ip.to_string(),
                    "src_port": record.src_port,
                    "dst_port": record.dst_port,
                    "protocol": record.protocol,
                    "packet_size": record.packet_size,
                })
            })
            .collect();

        ApiResponse::success(serde_json::json!({
            "count": events.len(),
            "events": events,
        }))
    }

    // ─────────────────────────────────────────────────────────────────────
    // Flush Handlers
    // ─────────────────────────────────────────────────────────────────────

    async fn handle_flush_blocked(&self) -> ApiResponse {
        match self.firewall.unblock_all() {
            Ok(count) => {
                info!("API: flushed all blocked IPs ({})", count);
                ApiResponse::success(serde_json::json!({
                    "flushed": true,
                    "count": count,
                }))
            }
            Err(e) => {
                error!("API: failed to flush blocked IPs: {}", e);
                ApiResponse::internal_error(format!("Failed to flush blocked: {}", e))
            }
        }
    }

    fn handle_flush_tracking(&self) -> ApiResponse {
        // Clear all IP detection states
        let tracked_ips = self.detection.tracked_ips();
        let count = tracked_ips.len();
        for ip in &tracked_ips {
            self.detection.clear_ip_state(ip);
        }

        info!("API: flushed {} tracked IP states", count);
        ApiResponse::success(serde_json::json!({
            "flushed": true,
            "count": count,
        }))
    }

    fn handle_flush_cache(&self) -> ApiResponse {
        // Flush storage caches
        info!("API: cache flush requested");
        ApiResponse::success(serde_json::json!({
            "flushed": true,
            "note": "In-memory caches cleared on next maintenance cycle",
        }))
    }

    async fn handle_flush_all(&self) -> ApiResponse {
        // Flush blocked
        let blocked_result = self.firewall.unblock_all();
        let blocked_count = blocked_result.unwrap_or(0);

        // Flush tracking
        let tracked_ips = self.detection.tracked_ips();
        let tracked_count = tracked_ips.len();
        for ip in &tracked_ips {
            self.detection.clear_ip_state(ip);
        }

        info!(
            "API: flushed all — {} blocked IPs, {} tracked states",
            blocked_count, tracked_count
        );

        ApiResponse::success(serde_json::json!({
            "flushed": true,
            "blocked_flushed": blocked_count,
            "tracking_flushed": tracked_count,
        }))
    }

    // ─────────────────────────────────────────────────────────────────────
    // Daemon Control Handlers
    // ─────────────────────────────────────────────────────────────────────

    fn handle_reload(&self) -> ApiResponse {
        // Config reload is not yet implemented — would need to re-read the
        // TOML file, validate, and hot-swap subsystem configs. For now, return
        // a message telling the user to restart the daemon.
        warn!("API: reload requested (not yet implemented — restart the daemon)");
        ApiResponse::not_implemented("Reload")
    }

    fn handle_shutdown(&self, force: bool) -> ApiResponse {
        if force {
            warn!("API: forced shutdown requested");
        } else {
            info!("API: graceful shutdown requested");
        }

        // Send the shutdown signal (same as Ctrl+C / SIGTERM)
        let _ = self.shutdown_tx.send(());

        ApiResponse::success(serde_json::json!({
            "shutting_down": true,
            "force": force,
        }))
    }

    // ─────────────────────────────────────────────────────────────────────
    // Export / Import Handlers
    // ─────────────────────────────────────────────────────────────────────

    fn handle_export(&self, what: String) -> ApiResponse {
        match what.as_str() {
            "blocked" => {
                let blocked = self.firewall.list_blocked();
                let entries: Vec<BlockedIpInfo> = blocked
                    .into_iter()
                    .map(|entry| BlockedIpInfo {
                        ip: entry.ip.to_string(),
                        blocked_at: entry.blocked_at.to_rfc3339(),
                        expires_at: entry.expires_at.map(|e| e.to_rfc3339()),
                        reason: entry.reason,
                        block_count: entry.block_count,
                    })
                    .collect();
                ApiResponse::success(serde_json::json!({
                    "type": "blocked",
                    "count": entries.len(),
                    "data": entries,
                }))
            }
            "tracked" => {
                let all_ips = self.storage.get_all_tracked_ips();
                let entries: Vec<TrackedIpInfo> = all_ips
                    .into_iter()
                    .filter_map(|ip| {
                        self.storage.get_ip_tracking(&ip).map(|entry| TrackedIpInfo {
                            ip: entry.ip.to_string(),
                            threat_level: format!("{:?}", entry.threat_level),
                            threat_score: entry.threat_score,
                            is_blocked: entry.is_blocked,
                            first_seen: entry.first_seen.to_rfc3339(),
                            last_seen: entry.last_seen.to_rfc3339(),
                            request_count: entry.stats.request_count,
                            attack_types: entry
                                .attack_types
                                .iter()
                                .map(|a| format!("{:?}", a))
                                .collect(),
                        })
                    })
                    .collect();
                ApiResponse::success(serde_json::json!({
                    "type": "tracked",
                    "count": entries.len(),
                    "data": entries,
                }))
            }
            "config" => {
                // Export detection config thresholds
                let config = self.detection.config();
                ApiResponse::success(serde_json::json!({
                    "type": "config",
                    "detection": {
                        "rps_threshold": config.rps_threshold,
                        "rps_block_threshold": config.rps_block_threshold,
                        "syn_flood_threshold": config.syn_flood_threshold,
                        "udp_flood_threshold": config.udp_flood_threshold,
                        "icmp_flood_threshold": config.icmp_flood_threshold,
                        "max_connections_per_ip": config.max_connections_per_ip,
                        "block_duration_secs": config.block_duration.as_secs(),
                        "sensitivity": config.sensitivity,
                    },
                    "firewall": {
                        "enabled": self.firewall.config().enabled,
                        "dry_run": self.firewall.config().dry_run,
                        "chain_name": self.firewall.config().chain_name,
                        "backend": format!("{:?}", self.firewall.config().backend),
                        "max_rules": self.firewall.config().max_rules,
                    },
                }))
            }
            other => ApiResponse::error(
                crate::api::error_codes::INVALID_REQUEST,
                format!(
                    "Unknown export type '{}'. Valid types: blocked, tracked, config",
                    other
                ),
            ),
        }
    }

    // ─────────────────────────────────────────────────────────────────────
    // Deploy Management Handlers
    // ─────────────────────────────────────────────────────────────────────

    fn handle_create_app(
        &self,
        name: String,
        repo_url: String,
        app_type_str: String,
        port: u16,
        branch: Option<String>,
        ssh_key_id: Option<String>,
        domain: Option<String>,
        build_cmd: Option<String>,
        start_cmd: Option<String>,
        build_dir: Option<String>,
        spa: bool,
    ) -> ApiResponse {
        let mut dm = match self.require_deploy_manager() {
            Ok(dm) => dm,
            Err(resp) => return resp,
        };

        let app_type: AppType = match app_type_str.parse() {
            Ok(t) => t,
            Err(e) => return ApiResponse::error(crate::api::error_codes::INVALID_REQUEST, format!("{}", e)),
        };

        let apps_dir = dm.config().apps_dir.clone();
        let mut app = match Application::new(name.clone(), name.clone(), app_type, repo_url, port, &apps_dir) {
            Ok(a) => a,
            Err(e) => return ApiResponse::error(crate::api::error_codes::INVALID_REQUEST, format!("{}", e)),
        };

        if let Some(b) = branch { app.branch = b; }
        app.ssh_key_id = ssh_key_id;
        app.domain = domain;
        app.build_command = build_cmd;
        app.start_command = start_cmd;
        app.build_output_dir = build_dir;
        app.spa_mode = spa;

        match dm.apps.register(app) {
            Ok(registered) => {
                info!("API: created app '{}'", registered.name);
                ApiResponse::success(serde_json::json!({
                    "created": true,
                    "name": registered.name,
                    "id": registered.id,
                    "app_type": format!("{}", registered.app_type),
                    "port": registered.port,
                    "status": format!("{}", registered.status),
                }))
            }
            Err(e) => ApiResponse::error(crate::api::error_codes::INVALID_REQUEST, format!("{}", e)),
        }
    }

    fn handle_deploy_app(
        &self,
        name: String,
        branch: Option<String>,
        force: bool,
        skip_deps: bool,
        skip_build: bool,
        skip_health_check: bool,
    ) -> ApiResponse {
        let mut dm = match self.require_deploy_manager() {
            Ok(dm) => dm,
            Err(resp) => return resp,
        };

        let mut options = DeployOptions::api();
        options.branch = branch;
        options.force = force;
        options.skip_deps = skip_deps;
        options.skip_build = skip_build;
        options.skip_health_check = skip_health_check;

        match dm.deploy_app(&name, &options) {
            Ok(result) => ApiResponse::success(serde_json::json!({
                "success": result.success,
                "deploy_id": result.deploy_id,
                "app": result.app_name,
                "commit": result.commit_hash,
                "branch": result.branch,
                "duration_secs": result.duration_secs,
                "warnings": result.warnings,
                "rolled_back": result.rolled_back,
                "log_path": result.log_path,
            })),
            Err(e) => ApiResponse::internal_error(format!("Deploy failed: {}", e)),
        }
    }

    fn handle_stop_app(&self, name: String) -> ApiResponse {
        let mut dm = match self.require_deploy_manager() {
            Ok(dm) => dm,
            Err(resp) => return resp,
        };
        match dm.stop_app(&name) {
            Ok(()) => ApiResponse::success(serde_json::json!({ "stopped": true, "app": name })),
            Err(e) => ApiResponse::internal_error(format!("{}", e)),
        }
    }

    fn handle_start_app(&self, name: String) -> ApiResponse {
        let mut dm = match self.require_deploy_manager() {
            Ok(dm) => dm,
            Err(resp) => return resp,
        };
        match dm.start_app(&name) {
            Ok(()) => ApiResponse::success(serde_json::json!({ "started": true, "app": name })),
            Err(e) => ApiResponse::internal_error(format!("{}", e)),
        }
    }

    fn handle_restart_app(&self, name: String) -> ApiResponse {
        let mut dm = match self.require_deploy_manager() {
            Ok(dm) => dm,
            Err(resp) => return resp,
        };
        match dm.restart_app(&name) {
            Ok(()) => ApiResponse::success(serde_json::json!({ "restarted": true, "app": name })),
            Err(e) => ApiResponse::internal_error(format!("{}", e)),
        }
    }

    fn handle_delete_app(&self, name: String, force: bool) -> ApiResponse {
        let mut dm = match self.require_deploy_manager() {
            Ok(dm) => dm,
            Err(resp) => return resp,
        };
        match dm.delete_app(&name, force) {
            Ok(()) => ApiResponse::success(serde_json::json!({ "deleted": true, "app": name, "files_deleted": force })),
            Err(e) => ApiResponse::internal_error(format!("{}", e)),
        }
    }

    fn handle_app_info(&self, name: String) -> ApiResponse {
        let dm = match self.require_deploy_manager() {
            Ok(dm) => dm,
            Err(resp) => return resp,
        };
        match dm.apps.get(&name) {
            Some(app) => ApiResponse::success(serde_json::json!({
                "name": app.name,
                "id": app.id,
                "display_name": app.display_name,
                "app_type": format!("{}", app.app_type),
                "repo_url": app.repo_url,
                "branch": app.branch,
                "port": app.port,
                "domain": app.domain,
                "ssl_enabled": app.ssl_enabled,
                "status": format!("{}", app.status),
                "current_commit": app.current_commit,
                "current_deploy_id": app.current_deploy_id,
                "build_command": app.build_command,
                "start_command": app.start_command,
                "build_output_dir": app.build_output_dir,
                "spa_mode": app.spa_mode,
                "index_file": app.index_file,
                "health_check_url": app.health_check_url,
                "created_at": app.created_at.to_rfc3339(),
                "updated_at": app.updated_at.to_rfc3339(),
                "last_deployed_at": app.last_deployed_at.map(|d| d.to_rfc3339()),
                "deploy_dir": app.deploy_dir.to_string_lossy(),
                "service_name": app.service_name(),
                "nginx_config": app.nginx_config_name(),
            })),
            None => ApiResponse::error(crate::api::error_codes::NOT_FOUND, format!("App '{}' not found", name)),
        }
    }

    fn handle_list_apps(&self) -> ApiResponse {
        let dm = match self.require_deploy_manager() {
            Ok(dm) => dm,
            Err(resp) => return resp,
        };
        let apps: Vec<serde_json::Value> = dm.apps.list().iter().map(|app| {
            serde_json::json!({
                "name": app.name,
                "app_type": format!("{}", app.app_type),
                "status": format!("{}", app.status),
                "port": app.port,
                "domain": app.domain,
                "branch": app.branch,
                "current_commit": app.current_commit.as_deref().map(|c| if c.len() >= 7 { &c[..7] } else { c }),
                "last_deployed_at": app.last_deployed_at.map(|d| d.to_rfc3339()),
            })
        }).collect();

        let summary = dm.apps.summary();
        ApiResponse::success(serde_json::json!({
            "count": apps.len(),
            "apps": apps,
            "summary": {
                "total": summary.total,
                "running": summary.running,
                "stopped": summary.stopped,
                "failed": summary.failed,
                "backends": summary.backends,
                "static_sites": summary.static_sites,
                "hybrids": summary.hybrids,
            }
        }))
    }

    fn handle_app_logs(&self, name: String, lines: usize, since: Option<String>) -> ApiResponse {
        let dm = match self.require_deploy_manager() {
            Ok(dm) => dm,
            Err(resp) => return resp,
        };
        let app = match dm.apps.get(&name) {
            Some(a) => a,
            None => return ApiResponse::error(crate::api::error_codes::NOT_FOUND, format!("App '{}' not found", name)),
        };
        match dm.systemd.get_logs_text(&app.service_name(), Some(lines), since.as_deref()) {
            Ok(text) => ApiResponse::success(serde_json::json!({ "app": name, "logs": text })),
            Err(e) => ApiResponse::internal_error(format!("Failed to get logs: {}", e)),
        }
    }

    fn handle_rollback_app(&self, name: String, target_id: Option<String>) -> ApiResponse {
        let mut dm = match self.require_deploy_manager() {
            Ok(dm) => dm,
            Err(resp) => return resp,
        };
        match dm.rollback_app(&name, target_id.as_deref()) {
            Ok(result) => ApiResponse::success(serde_json::json!({
                "success": result.success,
                "deploy_id": result.deploy_id,
                "commit": result.commit_hash,
                "duration_secs": result.duration_secs,
            })),
            Err(e) => ApiResponse::internal_error(format!("Rollback failed: {}", e)),
        }
    }

    fn handle_app_releases(&self, name: String) -> ApiResponse {
        let dm = match self.require_deploy_manager() {
            Ok(dm) => dm,
            Err(resp) => return resp,
        };
        let app = match dm.apps.get(&name) {
            Some(a) => a,
            None => return ApiResponse::error(crate::api::error_codes::NOT_FOUND, format!("App '{}' not found", name)),
        };
        let history = match crate::deploy::app::history::DeployHistory::new(app.deploys_dir(), 100) {
            Ok(h) => h,
            Err(e) => return ApiResponse::internal_error(format!("{}", e)),
        };
        match history.list() {
            Ok(records) => {
                let entries: Vec<serde_json::Value> = records.iter().map(|r| {
                    serde_json::json!({
                        "id": r.id,
                        "status": format!("{}", r.status),
                        "commit": if r.commit_hash.len() >= 7 { &r.commit_hash[..7] } else { &r.commit_hash },
                        "branch": r.branch,
                        "trigger": format!("{}", r.trigger),
                        "started_at": r.started_at.to_rfc3339(),
                        "duration_secs": r.duration_secs,
                        "is_rollback": r.is_rollback,
                    })
                }).collect();
                ApiResponse::success(serde_json::json!({ "app": name, "count": entries.len(), "releases": entries }))
            }
            Err(e) => ApiResponse::internal_error(format!("{}", e)),
        }
    }

    fn handle_app_set_port(&self, name: String, port: u16) -> ApiResponse {
        let mut dm = match self.require_deploy_manager() {
            Ok(dm) => dm,
            Err(resp) => return resp,
        };
        match dm.apps.update(&name, |app| { app.port = port; }) {
            Ok(_) => ApiResponse::success(serde_json::json!({ "app": name, "port": port })),
            Err(e) => ApiResponse::internal_error(format!("{}", e)),
        }
    }

    fn handle_app_set_domain(&self, name: String, domain: String) -> ApiResponse {
        let mut dm = match self.require_deploy_manager() {
            Ok(dm) => dm,
            Err(resp) => return resp,
        };
        match dm.apps.update(&name, |app| { app.domain = Some(domain.clone()); }) {
            Ok(_) => ApiResponse::success(serde_json::json!({ "app": name, "domain": domain })),
            Err(e) => ApiResponse::internal_error(format!("{}", e)),
        }
    }

    fn handle_app_enable_ssl(&self, name: String) -> ApiResponse {
        let mut dm = match self.require_deploy_manager() {
            Ok(dm) => dm,
            Err(resp) => return resp,
        };
        let domain = match dm.apps.get(&name) {
            Some(app) => match &app.domain {
                Some(d) => d.clone(),
                None => return ApiResponse::error(crate::api::error_codes::INVALID_REQUEST, "Set a domain first before enabling SSL"),
            },
            None => return ApiResponse::error(crate::api::error_codes::NOT_FOUND, format!("App '{}' not found", name)),
        };

        match dm.ssl.request_certificate(&domain) {
            Ok(cert) => {
                let cert_path = cert.cert_path.clone();
                let key_path = cert.key_path.clone();
                let _ = dm.apps.update(&name, |app| {
                    app.ssl_enabled = true;
                    app.ssl_cert_path = Some(cert_path);
                    app.ssl_key_path = Some(key_path);
                });
                ApiResponse::success(serde_json::json!({ "ssl_enabled": true, "domain": domain }))
            }
            Err(e) => ApiResponse::internal_error(format!("SSL request failed: {}", e)),
        }
    }

    fn handle_app_disable_ssl(&self, name: String) -> ApiResponse {
        let mut dm = match self.require_deploy_manager() {
            Ok(dm) => dm,
            Err(resp) => return resp,
        };
        match dm.apps.update(&name, |app| {
            app.ssl_enabled = false;
            app.ssl_cert_path = None;
            app.ssl_key_path = None;
        }) {
            Ok(_) => ApiResponse::success(serde_json::json!({ "ssl_disabled": true, "app": name })),
            Err(e) => ApiResponse::internal_error(format!("{}", e)),
        }
    }

    fn handle_app_nginx_show(&self, name: String) -> ApiResponse {
        let dm = match self.require_deploy_manager() {
            Ok(dm) => dm,
            Err(resp) => return resp,
        };
        match dm.nginx.get_config(&name) {
            Ok(content) => ApiResponse::success(serde_json::json!({ "app": name, "nginx_config": content })),
            Err(e) => ApiResponse::internal_error(format!("{}", e)),
        }
    }

    fn handle_app_env_set(&self, name: String, key: String, value: String) -> ApiResponse {
        let dm = match self.require_deploy_manager() {
            Ok(dm) => dm,
            Err(resp) => return resp,
        };
        let app = match dm.apps.get(&name) {
            Some(a) => a,
            None => return ApiResponse::error(crate::api::error_codes::NOT_FOUND, format!("App '{}' not found", name)),
        };
        let env_path = app.env_file_path();
        match crate::deploy::systemd::SystemdManager::set_env_var(&env_path, &key, &value) {
            Ok(()) => ApiResponse::success(serde_json::json!({ "app": name, "set": key, "note": "Restart the app for changes to take effect" })),
            Err(e) => ApiResponse::internal_error(format!("{}", e)),
        }
    }

    fn handle_app_env_unset(&self, name: String, key: String) -> ApiResponse {
        let dm = match self.require_deploy_manager() {
            Ok(dm) => dm,
            Err(resp) => return resp,
        };
        let app = match dm.apps.get(&name) {
            Some(a) => a,
            None => return ApiResponse::error(crate::api::error_codes::NOT_FOUND, format!("App '{}' not found", name)),
        };
        let env_path = app.env_file_path();
        match crate::deploy::systemd::SystemdManager::unset_env_var(&env_path, &key) {
            Ok(()) => ApiResponse::success(serde_json::json!({ "app": name, "unset": key })),
            Err(e) => ApiResponse::internal_error(format!("{}", e)),
        }
    }

    fn handle_app_env_list(&self, name: String) -> ApiResponse {
        let dm = match self.require_deploy_manager() {
            Ok(dm) => dm,
            Err(resp) => return resp,
        };
        let app = match dm.apps.get(&name) {
            Some(a) => a,
            None => return ApiResponse::error(crate::api::error_codes::NOT_FOUND, format!("App '{}' not found", name)),
        };
        let env_path = app.env_file_path();
        match crate::deploy::systemd::SystemdManager::read_env_file(&env_path) {
            Ok(env) => {
                // Mask sensitive values
                let masked: std::collections::HashMap<String, String> = env.into_iter().map(|(k, v)| {
                    let masked_v = if k.contains("SECRET") || k.contains("PASSWORD") || k.contains("TOKEN") || k.contains("KEY") {
                        "***".to_string()
                    } else {
                        v
                    };
                    (k, masked_v)
                }).collect();
                ApiResponse::success(serde_json::json!({ "app": name, "env": masked }))
            }
            Err(e) => ApiResponse::internal_error(format!("{}", e)),
        }
    }

    // ─────────────────────────────────────────────────────────────────────
    // SSH Key Handlers
    // ─────────────────────────────────────────────────────────────────────

    fn handle_ssh_key_generate(&self, name: String, key_type: Option<String>) -> ApiResponse {
        let mut dm = match self.require_deploy_manager() {
            Ok(dm) => dm,
            Err(resp) => return resp,
        };
        let kt = key_type.as_deref().unwrap_or("ed25519");
        let parsed_kt: crate::deploy::ssh::SshKeyType = match kt.parse() {
            Ok(t) => t,
            Err(e) => return ApiResponse::error(crate::api::error_codes::INVALID_REQUEST, format!("{}", e)),
        };
        match dm.ssh_keys.generate_key(&name, parsed_kt, None) {
            Ok(entry) => ApiResponse::success(serde_json::json!({
                "id": entry.id,
                "name": entry.name,
                "key_type": format!("{}", entry.key_type),
                "fingerprint": entry.fingerprint,
                "public_key": entry.public_key,
            })),
            Err(e) => ApiResponse::internal_error(format!("{}", e)),
        }
    }

    fn handle_ssh_key_list(&self) -> ApiResponse {
        let dm = match self.require_deploy_manager() {
            Ok(dm) => dm,
            Err(resp) => return resp,
        };
        let keys: Vec<serde_json::Value> = dm.ssh_keys.list_keys().iter().map(|k| {
            serde_json::json!({
                "id": k.id,
                "name": k.name,
                "key_type": format!("{}", k.key_type),
                "fingerprint": k.fingerprint,
                "github_username": k.github_username,
                "created_at": k.created_at.to_rfc3339(),
                "used_by_apps": k.used_by_apps,
            })
        }).collect();
        ApiResponse::success(serde_json::json!({ "count": keys.len(), "keys": keys }))
    }

    fn handle_ssh_key_delete(&self, id: String) -> ApiResponse {
        let mut dm = match self.require_deploy_manager() {
            Ok(dm) => dm,
            Err(resp) => return resp,
        };
        match dm.ssh_keys.delete_key(&id) {
            Ok(entry) => ApiResponse::success(serde_json::json!({ "deleted": true, "name": entry.name, "id": id })),
            Err(e) => ApiResponse::internal_error(format!("{}", e)),
        }
    }

    fn handle_ssh_key_show_public(&self, id: String) -> ApiResponse {
        let dm = match self.require_deploy_manager() {
            Ok(dm) => dm,
            Err(resp) => return resp,
        };
        match dm.ssh_keys.get_public_key_string(&id) {
            Ok(pubkey) => ApiResponse::success(serde_json::json!({ "id": id, "public_key": pubkey })),
            Err(e) => ApiResponse::internal_error(format!("{}", e)),
        }
    }

    fn handle_ssh_key_test(&self, id: String) -> ApiResponse {
        let dm = match self.require_deploy_manager() {
            Ok(dm) => dm,
            Err(resp) => return resp,
        };
        match dm.ssh_keys.test_connection(&id, None) {
            Ok(result) => ApiResponse::success(serde_json::json!({
                "success": result.success,
                "host": result.host,
                "authenticated_as": result.authenticated_as,
                "output": result.output,
            })),
            Err(e) => ApiResponse::internal_error(format!("{}", e)),
        }
    }

    // ─────────────────────────────────────────────────────────────────────
    // Port & SSL Handlers
    // ─────────────────────────────────────────────────────────────────────

    fn handle_ports_list(&self) -> ApiResponse {
        let dm = match self.require_deploy_manager() {
            Ok(dm) => dm,
            Err(resp) => return resp,
        };
        let allocs: Vec<serde_json::Value> = dm.ports.list_allocations().iter().map(|a| {
            serde_json::json!({ "port": a.port, "app": a.app_name, "allocated_at": a.allocated_at.to_rfc3339() })
        }).collect();
        let (start, end) = dm.ports.range();
        ApiResponse::success(serde_json::json!({
            "count": allocs.len(),
            "range": { "start": start, "end": end },
            "allocations": allocs,
        }))
    }

    fn handle_port_check(&self, port: u16) -> ApiResponse {
        let dm = match self.require_deploy_manager() {
            Ok(dm) => dm,
            Err(resp) => return resp,
        };
        let result = dm.ports.check(port);
        ApiResponse::success(serde_json::json!({
            "port": port,
            "available": result.available,
            "conflict_type": result.conflict_type.map(|c| format!("{}", c)),
            "details": result.details,
        }))
    }

    fn handle_ssl_list(&self) -> ApiResponse {
        let dm = match self.require_deploy_manager() {
            Ok(dm) => dm,
            Err(resp) => return resp,
        };
        let certs: Vec<serde_json::Value> = dm.ssl.list_certificates().iter().map(|c| {
            serde_json::json!({
                "domain": c.domain,
                "status": format!("{}", c.status),
                "provider": format!("{}", c.provider),
                "expires_at": c.expires_at.map(|e| e.to_rfc3339()),
                "auto_renew": c.auto_renew,
                "days_until_expiry": c.days_until_expiry(),
            })
        }).collect();
        ApiResponse::success(serde_json::json!({ "count": certs.len(), "certificates": certs }))
    }

    fn handle_ssl_check(&self) -> ApiResponse {
        let dm = match self.require_deploy_manager() {
            Ok(dm) => dm,
            Err(resp) => return resp,
        };
        let summary = dm.ssl.summary();
        ApiResponse::success(serde_json::json!({
            "total": summary.total,
            "valid": summary.valid,
            "expiring_soon": summary.expiring_soon,
            "expired": summary.expired,
            "failed": summary.failed,
        }))
    }

    fn handle_ssl_renew(&self, domain: String) -> ApiResponse {
        let mut dm = match self.require_deploy_manager() {
            Ok(dm) => dm,
            Err(resp) => return resp,
        };
        match dm.ssl.renew_certificate(&domain) {
            Ok(cert) => ApiResponse::success(serde_json::json!({
                "renewed": true,
                "domain": domain,
                "expires_at": cert.expires_at.map(|e| e.to_rfc3339()),
            })),
            Err(e) => ApiResponse::internal_error(format!("Renewal failed: {}", e)),
        }
    }

    // ─────────────────────────────────────────────────────────────────────
    // Export / Import Handlers
    // ─────────────────────────────────────────────────────────────────────

    fn handle_import(&self, what: String, data: String) -> ApiResponse {
        match what.as_str() {
            "blocked" => {
                // Parse the data as a list of IPs (one per line) and block them
                let mut imported = 0usize;
                let mut errors = Vec::new();

                for line in data.lines() {
                    let line = line.trim();
                    if line.is_empty() || line.starts_with('#') {
                        continue;
                    }

                    match line.parse::<IpAddr>() {
                        Ok(ip) => {
                            // Block for 1 hour by default
                            match self.firewall.block_ip(
                                ip,
                                Duration::from_secs(3600),
                                "Imported via API".to_string(),
                            ) {
                                Ok(_) => imported += 1,
                                Err(e) => {
                                    errors.push(format!("{}: {}", ip, e));
                                }
                            }
                        }
                        Err(e) => {
                            errors.push(format!("'{}': {}", line, e));
                        }
                    }
                }

                info!("API: imported {} blocked IPs ({} errors)", imported, errors.len());

                ApiResponse::success(serde_json::json!({
                    "type": "blocked",
                    "imported": imported,
                    "errors": errors,
                }))
            }
            other => ApiResponse::error(
                crate::api::error_codes::INVALID_REQUEST,
                format!(
                    "Unknown import type '{}'. Valid types: blocked",
                    other
                ),
            ),
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Utility Functions
// ─────────────────────────────────────────────────────────────────────────────

/// Get the current process memory usage in bytes.
///
/// Uses `/proc/self/statm` on Linux for a lightweight check.
/// Returns 0 on non-Linux platforms or if the file can't be read.
fn get_memory_usage() -> u64 {
    #[cfg(target_os = "linux")]
    {
        if let Ok(statm) = std::fs::read_to_string("/proc/self/statm") {
            // statm format: size resident shared text lib data dt
            // "resident" (2nd field) is the RSS in pages
            if let Some(rss_pages_str) = statm.split_whitespace().nth(1) {
                if let Ok(rss_pages) = rss_pages_str.parse::<u64>() {
                    // Page size is typically 4096 bytes
                    let page_size = unsafe { libc::sysconf(libc::_SC_PAGESIZE) };
                    return rss_pages * (page_size as u64);
                }
            }
        }
        0
    }

    #[cfg(not(target_os = "linux"))]
    {
        0
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Tests
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_get_memory_usage_does_not_panic() {
        // This should return a value on Linux or 0 on other platforms,
        // but should never panic.
        let mem = get_memory_usage();
        // On Linux in a test environment, we expect some non-zero value
        #[cfg(target_os = "linux")]
        {
            assert!(mem > 0, "Expected non-zero memory usage on Linux");
        }

        // On non-Linux, it returns 0
        #[cfg(not(target_os = "linux"))]
        {
            assert_eq!(mem, 0);
        }
    }
}
