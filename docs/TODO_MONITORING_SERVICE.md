# Zeroed Monitoring & Configuration Service — TODO & Implementation Plan

**Feature:** Unified monitoring dashboard for deployed apps, system services, network security, and configuration management  
**Created:** 2025  
**Status:** Planning  
**Replaces:** Steps 8 (Prometheus metrics) and 9 (HTTP REST API) from the original checklist  
**Priority:** High — this is the next major feature after the deploy pipeline (Steps 1–7 complete)

---

## Table of Contents

1. [Overview](#1-overview)
2. [Architecture](#2-architecture)
3. [Phase 1 — Monitoring Engine Core](#phase-1--monitoring-engine-core)
4. [Phase 2 — Deployed Application Monitoring](#phase-2--deployed-application-monitoring)
5. [Phase 3 — System Service Discovery & Monitoring](#phase-3--system-service-discovery--monitoring)
6. [Phase 4 — Suspicious Service Detection](#phase-4--suspicious-service-detection)
7. [Phase 5 — Security State Dashboard](#phase-5--security-state-dashboard)
8. [Phase 6 — Configuration Interface](#phase-6--configuration-interface)
9. [Phase 7 — HTTP API Server](#phase-7--http-api-server)
10. [Phase 8 — Web Dashboard UI](#phase-8--web-dashboard-ui)
11. [Phase 9 — Alerting & Notifications](#phase-9--alerting--notifications)
12. [Phase 10 — Prometheus Export (Optional Compatibility)](#phase-10--prometheus-export-optional-compatibility)
13. [Data Models](#data-models)
14. [API Endpoints Reference](#api-endpoints-reference)
15. [Open Questions & Decisions](#open-questions--decisions)

---

## 1. Overview

Instead of a generic Prometheus metrics exporter and a separate HTTP REST API, we build a **unified monitoring and configuration service** that is purpose-built for the Zeroed ecosystem. This service:

- **Monitors deployed applications** — health status, uptime, restart count, resource usage, response times
- **Monitors system services** — discovers all systemd services on the host, tracks their state, flags anomalies
- **Flags suspicious services** — detects unknown/unexpected services, services running as root that shouldn't be, services listening on unusual ports, recently installed services
- **Displays security state** — blocked IPs, allowed IPs, threat levels, detection stats, firewall rules, GeoIP data
- **Provides configuration** — change detection thresholds, manage whitelists/blacklists, firewall settings, deploy config — all from a web UI or API
- **Optionally exports Prometheus metrics** — for users who already have Grafana/Prometheus infrastructure

### Why Not Just Prometheus?

| Prometheus | This Service |
|------------|-------------|
| Generic time-series metrics | Purpose-built for Zeroed's specific needs |
| Requires external Grafana setup | Self-contained web dashboard |
| Pull-based scraping | Push + pull + real-time WebSocket |
| No configuration capability | Full configuration management built in |
| No service discovery awareness | Knows about deployed apps and system services |
| No security context | Integrated with detection engine, firewall, GeoIP |

---

## 2. Architecture

```text
┌─────────────────────────────────────────────────────────────────────┐
│                      Web Dashboard (SPA)                            │
│         (embedded static files served by the HTTP server)           │
├─────────────────────────────────────────────────────────────────────┤
│                      HTTP API Server                                │
│    REST endpoints · WebSocket streams · Auth middleware              │
├──────────┬──────────┬──────────┬──────────┬──────────┬──────────────┤
│  App     │ System   │ Security │ Config   │ Alerts   │ Prometheus   │
│  Monitor │ Monitor  │ State    │ Manager  │ Engine   │ Exporter     │
├──────────┴──────────┴──────────┴──────────┴──────────┴──────────────┤
│                    Monitoring Engine Core                            │
│        (scheduler, collectors, state store, event bus)               │
├─────────────────────────────────────────────────────────────────────┤
│                    Existing Zeroed Subsystems                        │
│  StorageEngine · DetectionEngine · FirewallManager · DeployManager   │
│  NetworkManager · GeoIpService · SystemdManager · NginxManager       │
└─────────────────────────────────────────────────────────────────────┘
```

### Key Design Principles

1. **Single binary** — the monitoring service runs inside the existing zeroed daemon, not as a separate process
2. **Non-blocking** — monitoring runs on its own tokio tasks, never blocking the packet processing pipeline
3. **Graceful degradation** — if the web UI is disabled, monitoring still collects data accessible via zeroctl
4. **Minimal dependencies** — use `axum` for HTTP (lightweight, tokio-native), no heavy frontend build step (vanilla JS or a single-file SPA framework)
5. **Secure by default** — HTTP API requires token auth, listens on localhost only unless explicitly configured

---

## Phase 1 — Monitoring Engine Core

The scheduler and data collection framework that all other phases build on.

### 1.1 Module Structure

- [ ] **1.1.1** Create `src/monitor/mod.rs` — top-level module with `MonitorEngine` struct
- [ ] **1.1.2** Create `src/monitor/collector.rs` — trait and scheduler for data collectors
- [ ] **1.1.3** Create `src/monitor/state.rs` — in-memory state store for monitoring data
- [ ] **1.1.4** Create `src/monitor/event.rs` — event bus for real-time updates (feeds WebSocket)

### 1.2 MonitorEngine

- [ ] **1.2.1** Define `MonitorEngine` struct:
  ```
  MonitorEngine {
      config: MonitorConfig,
      state: Arc<RwLock<MonitorState>>,
      event_tx: broadcast::Sender<MonitorEvent>,
      collectors: Vec<Box<dyn Collector>>,
      scheduler_handle: Option<JoinHandle<()>>,
  }
  ```
- [ ] **1.2.2** Implement `MonitorEngine::new(config) -> Self`
- [ ] **1.2.3** Implement `MonitorEngine::start()` — spawns the scheduler task that runs collectors at configured intervals
- [ ] **1.2.4** Implement `MonitorEngine::stop()` — cancels the scheduler
- [ ] **1.2.5** Implement `MonitorEngine::subscribe() -> broadcast::Receiver<MonitorEvent>` — for WebSocket streaming
- [ ] **1.2.6** Implement `MonitorEngine::snapshot() -> MonitorState` — current state for API responses

### 1.3 Collector Trait

- [ ] **1.3.1** Define the `Collector` trait:
  ```rust
  #[async_trait]
  pub trait Collector: Send + Sync {
      /// Human-readable name of this collector
      fn name(&self) -> &str;
      
      /// How often this collector should run (in seconds)
      fn interval_secs(&self) -> u64;
      
      /// Collect data and update the monitoring state
      async fn collect(&self, state: &mut MonitorState) -> Result<(), CollectorError>;
  }
  ```
- [ ] **1.3.2** Implement the scheduler loop that calls each collector at its configured interval
- [ ] **1.3.3** Handle collector failures gracefully — log the error, skip, try again next interval

### 1.4 MonitorState

- [ ] **1.4.1** Define `MonitorState` struct that holds the latest data from all collectors:
  ```
  MonitorState {
      // Daemon
      daemon_uptime_secs: u64,
      daemon_version: String,
      daemon_pid: u32,
      
      // System
      system_info: SystemInfo,
      cpu_usage: f64,
      memory_usage: MemoryInfo,
      disk_usage: Vec<DiskInfo>,
      load_average: (f64, f64, f64),
      
      // Deployed Apps
      app_statuses: HashMap<String, AppMonitorStatus>,
      
      // System Services
      system_services: Vec<ServiceMonitorEntry>,
      suspicious_services: Vec<SuspiciousServiceEntry>,
      
      // Security
      security_state: SecurityState,
      
      // Timestamps
      last_updated: DateTime<Utc>,
      collection_errors: Vec<CollectionError>,
  }
  ```

### 1.5 MonitorEvent (for real-time streaming)

- [ ] **1.5.1** Define `MonitorEvent` enum:
  ```
  MonitorEvent {
      AppStatusChanged { name, old_status, new_status },
      ServiceStateChanged { name, old_state, new_state },
      SuspiciousServiceDetected { name, reason },
      IpBlocked { ip, reason, threat_level },
      IpUnblocked { ip },
      ThresholdExceeded { metric, value, threshold },
      DeployCompleted { app, deploy_id, success },
      CertificateExpiring { domain, days_remaining },
      HighCpuUsage { percent },
      HighMemoryUsage { percent },
      DiskSpaceLow { mount_point, percent_used },
      ConfigChanged { section, key, old_value, new_value },
  }
  ```

### 1.6 MonitorConfig

- [ ] **1.6.1** Add `[monitor]` section to `ZeroedConfig` / `zeroed.toml`:
  ```toml
  [monitor]
  enabled = true
  
  # Collection intervals (in seconds)
  app_check_interval = 30
  system_check_interval = 60
  service_scan_interval = 300
  security_check_interval = 10
  
  # HTTP dashboard server
  http_enabled = true
  http_bind = "127.0.0.1"
  http_port = 8080
  auth_token = ""    # required if http is enabled; generate with: openssl rand -hex 32
  
  # Thresholds for alerts
  cpu_alert_percent = 90
  memory_alert_percent = 85
  disk_alert_percent = 90
  app_restart_alert_count = 3    # alert if app restarts more than N times in 10 minutes
  
  # Suspicious service detection
  enable_suspicious_detection = true
  known_services_file = ""  # path to a file listing expected services (one per line)
  
  # Prometheus compatibility endpoint (optional)
  prometheus_enabled = false
  prometheus_path = "/metrics"
  ```

---

## Phase 2 — Deployed Application Monitoring

Continuously monitor the health and resource usage of apps deployed via the Zeroed deploy system.

### 2.1 AppMonitorCollector

- [ ] **2.1.1** Create `src/monitor/collectors/app_collector.rs`
- [ ] **2.1.2** Implement `AppMonitorCollector` that:
  - Iterates all registered apps from `DeployManager.apps.list()`
  - For each app, checks:
    - **Systemd service status** via `systemctl is-active` (backend/hybrid only)
    - **Process resource usage** — CPU%, memory RSS, open file descriptors (from `/proc/<pid>/`)
    - **HTTP health check** — if `health_check_url` is configured, GET it and record response time + status code
    - **Nginx upstream availability** — check if nginx is serving the app (optional, via `curl localhost:port`)
    - **Restart count** — from `systemctl show NRestarts`
    - **Uptime** — from `systemctl show ActiveEnterTimestamp`
    - **Last deploy** — from app registry metadata

### 2.2 AppMonitorStatus

- [ ] **2.2.1** Define `AppMonitorStatus`:
  ```
  AppMonitorStatus {
      name: String,
      app_type: AppType,
      status: AppHealthStatus,          // Healthy | Degraded | Down | Unknown
      systemd_state: String,            // "active", "inactive", "failed"
      pid: Option<u32>,
      cpu_percent: Option<f64>,
      memory_rss_bytes: Option<u64>,
      memory_percent: Option<f64>,
      open_fds: Option<u32>,
      uptime_secs: Option<u64>,
      restart_count: u32,
      last_restart: Option<DateTime<Utc>>,
      health_check_status: Option<u16>, // HTTP status code from health check
      health_check_latency_ms: Option<u64>,
      health_check_error: Option<String>,
      port: u16,
      domain: Option<String>,
      ssl_enabled: bool,
      current_commit: Option<String>,
      last_deployed_at: Option<DateTime<Utc>>,
      warnings: Vec<String>,
      checked_at: DateTime<Utc>,
  }
  ```

### 2.3 AppHealthStatus

- [ ] **2.3.1** Define `AppHealthStatus` enum:
  - `Healthy` — service running, health check passing, no warnings
  - `Degraded` — service running but health check failing, or high restart count, or high resource usage
  - `Down` — service not running or failed
  - `Deploying` — deployment in progress
  - `Unknown` — status could not be determined
  - `NotDeployed` — app registered but never deployed

### 2.4 Process Resource Collection

- [ ] **2.4.1** Implement `/proc/<pid>/stat` parser for CPU usage calculation
- [ ] **2.4.2** Implement `/proc/<pid>/statm` parser for memory RSS
- [ ] **2.4.3** Implement `/proc/<pid>/fd` counting for open file descriptors
- [ ] **2.4.4** Handle the case where the PID is not found (process died between check and read)
- [ ] **2.4.5** Calculate CPU% as delta between two samples (requires storing previous sample)

---

## Phase 3 — System Service Discovery & Monitoring

Monitor ALL systemd services on the host, not just Zeroed-managed ones.

### 3.1 SystemServiceCollector

- [ ] **3.1.1** Create `src/monitor/collectors/system_service_collector.rs`
- [ ] **3.1.2** Implement `SystemServiceCollector` that:
  - Runs `systemctl list-units --type=service --all --no-pager --output=json` (or parse the plain-text output)
  - For each service, records: name, description, load state, active state, sub state, PID, memory usage
  - Categorizes services into groups:
    - **Zeroed-managed** — services matching `zeroed-app-*` pattern
    - **System critical** — sshd, systemd-*, NetworkManager, firewalld, etc.
    - **Database** — postgresql, mysql, mariadb, mongodb, redis, etc.
    - **Web server** — nginx, apache2, httpd, caddy, etc.
    - **Other known** — docker, containerd, cron, etc.
    - **Unknown** — everything else (candidates for suspicious detection)

### 3.2 ServiceMonitorEntry

- [ ] **3.2.1** Define `ServiceMonitorEntry`:
  ```
  ServiceMonitorEntry {
      name: String,
      description: String,
      active_state: String,       // "active", "inactive", "failed", "activating"
      sub_state: String,          // "running", "dead", "exited", "listening"
      pid: Option<u32>,
      memory_bytes: Option<u64>,
      cpu_usage_secs: Option<f64>,
      category: ServiceCategory,
      is_zeroed_managed: bool,
      enabled: bool,              // starts on boot
      listening_ports: Vec<u16>,  // ports this service binds to
      user: Option<String>,       // user the service runs as
      started_at: Option<DateTime<Utc>>,
      restart_count: u32,
  }
  ```

### 3.3 Service Port Discovery

- [ ] **3.3.1** Parse `ss -tlnp` output to map PIDs to listening ports
- [ ] **3.3.2** Cross-reference with service PIDs to determine which service listens on which port
- [ ] **3.3.3** Store as `listening_ports` on each `ServiceMonitorEntry`

### 3.4 Service State Change Detection

- [ ] **3.4.1** Compare current service states with previous snapshot
- [ ] **3.4.2** Emit `MonitorEvent::ServiceStateChanged` for any transitions (e.g., active → failed)
- [ ] **3.4.3** Track service state history (last N state changes per service) for the UI timeline view

---

## Phase 4 — Suspicious Service Detection

Identify services that look unusual, unexpected, or potentially malicious.

### 4.1 Suspicion Heuristics

- [ ] **4.1.1** Create `src/monitor/suspicious.rs`
- [ ] **4.1.2** Implement the following heuristics (each produces a suspicion score):

| Heuristic | Description | Score |
|-----------|-------------|-------|
| **Unknown service** | Not in the known services list (if configured) | 0.3 |
| **Recently installed** | Unit file modified within the last 24 hours | 0.2 |
| **Running as root** | Service runs as root but doesn't need to (not in a root-expected list) | 0.4 |
| **Unusual port** | Listening on a port >1024 that's not assigned to any known service | 0.2 |
| **Hidden name** | Service name starts with `.` or contains random-looking strings | 0.5 |
| **No description** | Unit file has no `Description=` field | 0.1 |
| **Excessive resources** | Service using >50% CPU or >1GB memory without being a known heavy process | 0.3 |
| **Network activity from unknown** | Service with outbound connections to non-whitelisted destinations | 0.4 |
| **Unusual binary path** | ExecStart path is in /tmp, /dev/shm, or a user home directory | 0.6 |
| **Deleted binary** | The binary in ExecStart no longer exists on disk (or has been replaced) | 0.8 |

- [ ] **4.1.3** Sum the scores for each service; flag as suspicious if total > 0.5

### 4.2 SuspiciousServiceEntry

- [ ] **4.2.1** Define:
  ```
  SuspiciousServiceEntry {
      name: String,
      suspicion_score: f64,
      reasons: Vec<SuspicionReason>,
      service_info: ServiceMonitorEntry,
      first_detected: DateTime<Utc>,
      acknowledged: bool,          // user dismissed the alert
  }
  ```

### 4.3 Known Services File

- [ ] **4.3.1** Support a `known_services_file` config option — a plain text file listing expected service names (one per line)
- [ ] **4.3.2** Services in this file are never flagged as "unknown"
- [ ] **4.3.3** Auto-generate the initial file from the current running services: `zeroctl monitor init-known-services`

### 4.4 Acknowledgment

- [ ] **4.4.1** Users can acknowledge a suspicious service via the API/UI, which suppresses further alerts for that service
- [ ] **4.4.2** Acknowledged services are stored in a file at `/var/lib/zeroed/monitor/acknowledged_services.toml`
- [ ] **4.4.3** If an acknowledged service changes its binary or behavior, re-flag it

---

## Phase 5 — Security State Dashboard

Real-time view of the network security posture managed by Zeroed.

### 5.1 SecurityStateCollector

- [ ] **5.1.1** Create `src/monitor/collectors/security_collector.rs`
- [ ] **5.1.2** Collect from existing subsystems:
  - **Detection engine stats** — packets analyzed, attacks detected, tracked IPs, top threats
  - **Firewall state** — currently blocked IPs (with reason, duration, remaining time), total blocks/unblocks
  - **GeoIP data** — blocked countries list, IPs by country, suspicious region IPs
  - **Rate limiter state** — per-IP rates, IPs near threshold
  - **Connection tracker** — active connections, top talkers, half-open connections (SYN flood indicator)

### 5.2 SecurityState

- [ ] **5.2.1** Define:
  ```
  SecurityState {
      // Blocked IPs
      blocked_ips: Vec<BlockedIpDisplay>,
      blocked_count: usize,
      
      // Whitelisted / Blacklisted
      whitelisted_ips: Vec<String>,
      whitelisted_cidrs: Vec<String>,
      blacklisted_ips: Vec<String>,
      blacklisted_cidrs: Vec<String>,
      
      // Detection stats
      packets_analyzed: u64,
      attacks_detected: u64,
      threats_by_type: HashMap<String, u64>,   // "SynFlood" -> 42
      threats_by_country: HashMap<String, u64>, // "CN" -> 15
      
      // Top threats (IPs with highest threat scores)
      top_threats: Vec<ThreatEntry>,
      
      // Firewall
      firewall_enabled: bool,
      firewall_dry_run: bool,
      firewall_chain_rules: usize,
      
      // Connection stats
      active_connections: usize,
      half_open_connections: usize,
      connections_per_second: f64,
      
      // Thresholds (current config)
      rps_threshold: u32,
      rps_block_threshold: u32,
      syn_flood_threshold: u32,
      udp_flood_threshold: u32,
      icmp_flood_threshold: u32,
      
      // GeoIP
      geoip_enabled: bool,
      blocked_countries: Vec<String>,
      
      // Timeline (recent events)
      recent_blocks: Vec<RecentBlockEvent>,
      recent_detections: Vec<RecentDetectionEvent>,
      
      checked_at: DateTime<Utc>,
  }
  ```

### 5.3 BlockedIpDisplay

- [ ] **5.3.1** Define:
  ```
  BlockedIpDisplay {
      ip: String,
      blocked_at: DateTime<Utc>,
      expires_at: Option<DateTime<Utc>>,
      remaining_secs: Option<i64>,
      reason: String,
      block_count: u32,
      country: Option<String>,
      city: Option<String>,
      threat_level: String,
      threat_score: f64,
  }
  ```
- [ ] **5.3.2** Enrich blocked IPs with GeoIP data (country, city) for the dashboard map view

### 5.4 ThreatEntry (Top Threats)

- [ ] **5.4.1** Define:
  ```
  ThreatEntry {
      ip: String,
      threat_level: String,
      threat_score: f64,
      attack_types: Vec<String>,
      request_count: u64,
      bytes_total: u64,
      first_seen: DateTime<Utc>,
      last_seen: DateTime<Utc>,
      is_blocked: bool,
      country: Option<String>,
  }
  ```

---

## Phase 6 — Configuration Interface

Allow users to view and modify Zeroed's configuration through the API and web UI.

### 6.1 Readable Configuration

- [ ] **6.1.1** Create `src/monitor/config_manager.rs`
- [ ] **6.1.2** Expose current configuration as a structured JSON response for each section:
  - `GET /api/config/detection` — thresholds, sensitivity, windows, whitelist/blacklist
  - `GET /api/config/firewall` — enabled, backend, chain, dry_run, max_rules
  - `GET /api/config/network` — interfaces, promiscuous, BPF filter, monitored ports
  - `GET /api/config/storage` — data_dir, format, TTL, shard count, WAL
  - `GET /api/config/geoip` — enabled, database path, blocked/allowed countries
  - `GET /api/config/deploy` — apps_dir, port range, max apps, timeouts
  - `GET /api/config/monitor` — intervals, thresholds, HTTP settings
  - `GET /api/config/all` — everything in one response

### 6.2 Writable Configuration (Hot-Reload)

- [ ] **6.2.1** Support runtime modification of safe-to-change settings:

| Setting | Hot-reloadable? | Requires restart? |
|---------|----------------|-------------------|
| Detection thresholds (RPS, SYN, UDP, ICMP) | ✅ Yes | No |
| Detection sensitivity | ✅ Yes | No |
| Whitelist IPs / CIDRs | ✅ Yes | No |
| Blacklist IPs / CIDRs | ✅ Yes | No |
| Firewall dry_run toggle | ✅ Yes | No |
| Firewall max_rules | ✅ Yes | No |
| GeoIP blocked/allowed countries | ✅ Yes | No |
| Block duration | ✅ Yes | No |
| Monitor intervals / thresholds | ✅ Yes | No |
| Network interfaces | ❌ No | Yes |
| Storage format / shard count | ❌ No | Yes |
| Daemon worker threads | ❌ No | Yes |
| API socket path | ❌ No | Yes |
| Deploy apps_dir / port range | ⚠️ Partial | Some changes need restart |

- [ ] **6.2.2** Implement `PUT /api/config/<section>` endpoints that:
  1. Validate the new values
  2. Apply them to the running subsystem (e.g., update `DetectionEngine`'s thresholds in-memory)
  3. Persist the change to `zeroed.toml` on disk (so it survives restart)
  4. Emit a `MonitorEvent::ConfigChanged` event
  5. Return the updated config section

- [ ] **6.2.3** Make `DetectionConfig` fields updatable at runtime:
  - Wrap the config in `Arc<RwLock<DetectionConfig>>` instead of a plain clone
  - The detection engine reads from the RwLock on each `analyze()` call
  - The config API writes to the RwLock + persists to disk

- [ ] **6.2.4** Whitelist/Blacklist management:
  - `POST /api/config/whitelist` — add IP or CIDR
  - `DELETE /api/config/whitelist/:entry` — remove
  - `POST /api/config/blacklist` — add IP or CIDR
  - `DELETE /api/config/blacklist/:entry` — remove
  - Changes take effect immediately (update the `HashSet` in the detection config)

### 6.3 Config Validation

- [ ] **6.3.1** Every config change goes through validation before being applied
- [ ] **6.3.2** Return clear error messages for invalid values (e.g., "rps_threshold must be > 0")
- [ ] **6.3.3** Prevent dangerous changes without confirmation (e.g., disabling the firewall, setting thresholds to 0)

### 6.4 Config History

- [ ] **6.4.1** Keep a log of all config changes at `/var/lib/zeroed/monitor/config_history.jsonl`:
  ```json
  {"timestamp":"2025-01-15T12:00:00Z","section":"detection","key":"rps_block_threshold","old":"500","new":"1000","source":"api","user":"admin"}
  ```
- [ ] **6.4.2** `GET /api/config/history` — return recent config changes

---

## Phase 7 — HTTP API Server

The HTTP server that serves the dashboard UI and API endpoints.

### 7.1 Server Setup

- [ ] **7.1.1** Add `axum` as a dependency (lightweight, tokio-native HTTP framework)
- [ ] **7.1.2** Create `src/monitor/http/mod.rs` — HTTP server setup and router
- [ ] **7.1.3** Create `src/monitor/http/auth.rs` — token-based authentication middleware
- [ ] **7.1.4** Create `src/monitor/http/routes.rs` — route definitions
- [ ] **7.1.5** Create `src/monitor/http/websocket.rs` — WebSocket handler for real-time events

### 7.2 Authentication

- [ ] **7.2.1** Implement bearer token authentication:
  - Token is configured in `[monitor] auth_token = "..."`
  - All API requests must include `Authorization: Bearer <token>` header
  - The dashboard UI stores the token in localStorage after initial login
- [ ] **7.2.2** If `auth_token` is empty, require the user to set one before enabling HTTP
- [ ] **7.2.3** Rate-limit failed auth attempts (5 failures per IP per minute)

### 7.3 API Routes

(See [API Endpoints Reference](#api-endpoints-reference) for the full list)

- [ ] **7.3.1** Mount all routes under `/api/v1/`
- [ ] **7.3.2** CORS headers for development (configurable)
- [ ] **7.3.3** Request/response logging middleware
- [ ] **7.3.4** Error handling middleware that returns consistent JSON error responses

### 7.4 WebSocket Endpoint

- [ ] **7.4.1** `GET /api/v1/events` — WebSocket endpoint that streams `MonitorEvent`s in real-time
- [ ] **7.4.2** Client can optionally filter events by type (query param `?types=app,security,service`)
- [ ] **7.4.3** Heartbeat ping/pong every 30 seconds to detect dead connections

### 7.5 Static File Serving

- [ ] **7.5.1** Serve the web dashboard at `/` — either:
  - **Option A:** Embed the HTML/JS/CSS files directly in the binary using `include_dir!` macro (single-binary deployment, no external files needed)
  - **Option B:** Serve from a configurable directory on disk (easier to customize)
  - **Recommendation:** Option A for production, with a `--dashboard-dir` override for development
- [ ] **7.5.2** `GET /` → `index.html`
- [ ] **7.5.3** `GET /assets/*` → JS/CSS/image files with proper cache headers

### 7.6 Wire into Daemon

- [ ] **7.6.1** Spawn the HTTP server as a tokio task in `async_main()` (alongside the existing Unix socket API server)
- [ ] **7.6.2** Pass the same `Arc` references to subsystems
- [ ] **7.6.3** Include in the shutdown join block

---

## Phase 8 — Web Dashboard UI

A self-contained web interface for monitoring and configuration.

### 8.1 Technology Choice

- [ ] **8.1.1** Use vanilla JS + a lightweight reactive library (e.g., Alpine.js, htmx, or Preact)
  - **Rationale:** No build step needed, small file size, embeddable in the binary
  - Alpine.js (~15KB) provides reactivity without a build toolchain
  - htmx (~14KB) provides server-driven interactivity
  - Alternatively: a single-file Preact app with a simple build step
- [ ] **8.1.2** CSS: use a minimal CSS framework (e.g., Pico CSS, Water.css, or Simple.css) for clean styling without heavy dependencies

### 8.2 Dashboard Pages

- [ ] **8.2.1** **Overview** (`/`)
  - System health at a glance: CPU, memory, disk, load
  - Deployed apps summary: N running, N stopped, N failed
  - Security summary: N blocked IPs, N attacks detected, threat level gauge
  - Recent events timeline (auto-updating via WebSocket)

- [ ] **8.2.2** **Applications** (`/apps`)
  - Table: name, type, status (color-coded), port, domain, commit, last deployed, uptime
  - Click to expand: resource usage chart, health check history, restart timeline
  - Action buttons: deploy, start, stop, restart, rollback, delete
  - Quick-add form for registering a new app

- [ ] **8.2.3** **Application Detail** (`/apps/:name`)
  - Full app info (all fields from AppInfo)
  - Live resource usage (CPU%, memory, connections)
  - Health check history (last N checks with response times)
  - Deployment history table
  - Log viewer (streaming from journalctl via WebSocket)
  - Environment variables editor
  - Nginx config viewer (syntax-highlighted)

- [ ] **8.2.4** **System Services** (`/services`)
  - Table: name, state, category, PID, memory, ports, user
  - Filter by: category, state, zeroed-managed
  - Suspicious services panel (highlighted in red/yellow with scores and reasons)
  - Acknowledge button for false positives

- [ ] **8.2.5** **Security** (`/security`)
  - **Blocked IPs table:** IP, country (with flag emoji), reason, blocked since, expires in, threat score, actions (unblock)
  - **Threat map:** world map with dots sized by threat volume per country (using a simple SVG map or canvas)
  - **Top threats table:** IPs with highest threat scores, attack types, request rates
  - **Detection stats:** packets/sec, attacks/min, block rate — with mini sparkline charts
  - **Whitelist/Blacklist editor:** add/remove entries inline
  - **Rate monitor:** per-IP rates for the top N talkers

- [ ] **8.2.6** **Configuration** (`/config`)
  - Grouped by section (Detection, Firewall, Network, GeoIP, Deploy, Monitor)
  - Each field shows: current value, description, editable input
  - Save button per section that PUTs the changes to the API
  - Validation errors shown inline
  - Config change history log at the bottom

- [ ] **8.2.7** **SSH Keys** (`/ssh-keys`)
  - Table: name, type, fingerprint, GitHub user, used by apps
  - Generate new key form
  - Show public key (copy to clipboard button)
  - Test connectivity button
  - Delete with confirmation

- [ ] **8.2.8** **SSL Certificates** (`/ssl`)
  - Table: domain, status (color-coded), provider, expires in, auto-renew
  - Renew button
  - Certificate detail (issuer, SANs, expiry date)

- [ ] **8.2.9** **Ports** (`/ports`)
  - Visual port map (range bar showing allocated vs free)
  - Table: port, application, allocated at
  - Port availability checker

### 8.3 Real-time Updates

- [ ] **8.3.1** Connect to WebSocket on page load
- [ ] **8.3.2** Update relevant page sections when events arrive (e.g., app status changes, new blocks)
- [ ] **8.3.3** Show a toast notification for important events (new block, app went down, suspicious service)
- [ ] **8.3.4** Reconnect automatically on WebSocket disconnect

---

## Phase 9 — Alerting & Notifications

### 9.1 Alert Rules

- [ ] **9.1.1** Define configurable alert rules:
  ```toml
  [[monitor.alerts]]
  name = "High CPU"
  condition = "system.cpu_percent > 90"
  duration_secs = 300   # must be true for 5 minutes
  severity = "warning"
  
  [[monitor.alerts]]
  name = "App Down"
  condition = "app.status == 'Down'"
  duration_secs = 0     # immediate
  severity = "critical"
  
  [[monitor.alerts]]
  name = "Disk Full"
  condition = "system.disk_percent > 95"
  severity = "critical"
  ```

### 9.2 Alert Channels

- [ ] **9.2.1** **Dashboard notification** — always on, shows in the UI
- [ ] **9.2.2** **Log entry** — always on, writes to the zeroed log
- [ ] **9.2.3** **Webhook** (optional) — POST alert JSON to a configured URL (Slack, Discord, PagerDuty, etc.)
  ```toml
  [monitor.webhook]
  url = "https://hooks.slack.com/services/XXX/YYY/ZZZ"
  headers = { "Content-Type" = "application/json" }
  template = '{"text": "🚨 {{alert.name}}: {{alert.message}}"}'
  ```
- [ ] **9.2.4** **Email** (optional, future) — send alert emails via SMTP

### 9.3 Alert State Management

- [ ] **9.3.1** Track active alerts with deduplication (don't re-alert for the same condition)
- [ ] **9.3.2** Auto-resolve alerts when the condition clears
- [ ] **9.3.3** Alert history: `GET /api/v1/alerts/history`

---

## Phase 10 — Prometheus Export (Optional Compatibility)

For users with existing Prometheus + Grafana infrastructure, expose a standard `/metrics` endpoint.

### 10.1 Prometheus Metrics

- [ ] **10.1.1** If `[monitor] prometheus_enabled = true`, serve a `/metrics` endpoint
- [ ] **10.1.2** Export metrics using the `metrics` + `metrics-exporter-prometheus` crates (already dependencies)
- [ ] **10.1.3** Metrics to export:

```
# Daemon
zeroed_uptime_seconds gauge
zeroed_packets_total counter
zeroed_packets_dropped counter

# Detection
zeroed_attacks_detected_total{type} counter
zeroed_ips_tracked gauge
zeroed_ips_blocked gauge
zeroed_threat_score{ip} gauge

# Firewall
zeroed_firewall_blocks_total counter
zeroed_firewall_unblocks_total counter
zeroed_firewall_active_rules gauge

# Apps
zeroed_app_status{app} gauge (1=running, 0=stopped, -1=failed)
zeroed_app_uptime_seconds{app} gauge
zeroed_app_restarts_total{app} counter
zeroed_app_health_check_latency_ms{app} gauge
zeroed_app_cpu_percent{app} gauge
zeroed_app_memory_bytes{app} gauge

# SSL
zeroed_ssl_cert_expiry_days{domain} gauge

# System
zeroed_system_cpu_percent gauge
zeroed_system_memory_percent gauge
zeroed_system_disk_percent{mount} gauge
zeroed_system_services_total{state} gauge
zeroed_system_suspicious_services gauge
```

---

## Data Models

### Module Map

| Model | Module |
|-------|--------|
| `MonitorEngine` | `src/monitor/mod.rs` |
| `MonitorState` | `src/monitor/state.rs` |
| `MonitorEvent` | `src/monitor/event.rs` |
| `MonitorConfig` | `src/core/config.rs` |
| `Collector` trait | `src/monitor/collector.rs` |
| `AppMonitorCollector` | `src/monitor/collectors/app_collector.rs` |
| `SystemServiceCollector` | `src/monitor/collectors/system_service_collector.rs` |
| `SecurityCollector` | `src/monitor/collectors/security_collector.rs` |
| `SuspiciousDetector` | `src/monitor/suspicious.rs` |
| `ConfigManager` | `src/monitor/config_manager.rs` |
| HTTP routes | `src/monitor/http/routes.rs` |
| WebSocket handler | `src/monitor/http/websocket.rs` |
| Auth middleware | `src/monitor/http/auth.rs` |

### File System Layout

```text
/var/lib/zeroed/
├── monitor/
│   ├── acknowledged_services.toml    # user-dismissed suspicious services
│   ├── config_history.jsonl          # config change audit log
│   ├── known_services.txt            # expected system services list
│   └── alert_state.json              # active alerts (persisted across restarts)
├── apps/                             # (existing) deployed applications
├── ssh/                              # (existing) SSH keys
├── data/                             # (existing) storage data
└── deploy/                           # (existing) app registry
```

---

## API Endpoints Reference

### Monitoring Endpoints

```
GET  /api/v1/monitor/overview           — full dashboard overview (all sections)
GET  /api/v1/monitor/system             — system info (CPU, memory, disk, load)
GET  /api/v1/monitor/apps               — all deployed app statuses
GET  /api/v1/monitor/apps/:name         — single app detailed status
GET  /api/v1/monitor/services           — all system services
GET  /api/v1/monitor/services/suspicious — suspicious services only
POST /api/v1/monitor/services/:name/acknowledge — acknowledge a suspicious service
GET  /api/v1/monitor/security           — full security state
GET  /api/v1/monitor/security/blocked   — blocked IPs with enriched data
GET  /api/v1/monitor/security/threats   — top threat IPs
GET  /api/v1/monitor/security/timeline  — recent security events
GET  /api/v1/events                     — WebSocket: real-time event stream
```

### Configuration Endpoints

```
GET  /api/v1/config                     — all config sections
GET  /api/v1/config/:section            — one section (detection, firewall, etc.)
PUT  /api/v1/config/:section            — update a section (hot-reload)
GET  /api/v1/config/history             — config change history
POST /api/v1/config/whitelist           — add whitelist entry
DELETE /api/v1/config/whitelist/:entry  — remove whitelist entry
POST /api/v1/config/blacklist           — add blacklist entry
DELETE /api/v1/config/blacklist/:entry  — remove blacklist entry
```

### Existing Endpoints (migrated from Unix socket)

```
GET  /api/v1/status                     — daemon status
GET  /api/v1/stats                      — detailed statistics
POST /api/v1/block                      — block an IP
POST /api/v1/unblock                    — unblock an IP
GET  /api/v1/lookup/:ip                 — IP lookup with GeoIP enrichment
```

### Deploy Endpoints (migrated from Unix socket)

```
POST   /api/v1/apps                     — create app
POST   /api/v1/apps/:name/deploy        — deploy app
POST   /api/v1/apps/:name/stop          — stop app
POST   /api/v1/apps/:name/start         — start app
POST   /api/v1/apps/:name/restart       — restart app
DELETE /api/v1/apps/:name               — delete app
POST   /api/v1/apps/:name/rollback      — rollback
GET    /api/v1/apps/:name/logs          — get logs
GET    /api/v1/apps/:name/releases      — deployment history
PUT    /api/v1/apps/:name/env           — set env vars
GET    /api/v1/apps/:name/nginx         — show nginx config
```

### SSH Key Endpoints

```
POST   /api/v1/ssh-keys                 — generate key
GET    /api/v1/ssh-keys                 — list keys
DELETE /api/v1/ssh-keys/:id             — delete key
GET    /api/v1/ssh-keys/:id/public      — get public key
POST   /api/v1/ssh-keys/:id/test        — test connectivity
```

### Alert Endpoints

```
GET  /api/v1/alerts                     — active alerts
GET  /api/v1/alerts/history             — alert history
POST /api/v1/alerts/:id/acknowledge     — acknowledge an alert
```

### Prometheus

```
GET  /metrics                           — Prometheus-format metrics (if enabled)
```

---

## Open Questions & Decisions

### Needs Decision

1. **Web UI framework** — Alpine.js + htmx (no build step, ~30KB total) vs Preact (needs build, ~10KB, more capable)? **Recommendation: Alpine.js + htmx for v1** — no build toolchain, works with server-rendered HTML, easier to embed.

2. **HTTP framework** — `axum` (most popular tokio-native) vs `warp` (filter-based, lighter) vs `actix-web` (fastest, but actix runtime)? **Recommendation: `axum`** — best ecosystem fit with tokio, good middleware support, widely adopted.

3. **Embed dashboard in binary?** — Using `include_dir!` to bake the HTML/JS/CSS into the binary means true single-binary deployment. The downside is binary size increase (~500KB–2MB). **Recommendation: Yes, embed** — operational simplicity outweighs the size cost.

4. **Should config changes write to zeroed.toml?** — Writing back to the config file preserves changes across restarts but modifies a file the user may have hand-edited. **Recommendation: Yes, write back** — but preserve comments and formatting where possible, and keep a backup at `zeroed.toml.bak`.

5. **Should the HTTP server be on a different port than the Unix socket API?** — Yes. The HTTP server serves the web dashboard and REST API on a TCP port (default 8080). The Unix socket API continues to serve `zeroctl` commands. Both share the same `CommandHandler` / `DeployManager` / subsystems. **This is not a replacement — it's an additional interface.**

### Assumptions

- The HTTP server listens on localhost (127.0.0.1) by default for security
- Token auth is mandatory when HTTP is enabled
- The WebSocket connection uses the same auth token as REST endpoints
- System service monitoring only works on systemd-based Linux systems
- Suspicious service detection is opt-in (disabled by default to avoid false positives on first run)
- The web dashboard works in all modern browsers (no IE11 support)

### Priority Order for Implementation

| Priority | Phase | Reason |
|----------|-------|--------|
| 1 | Phase 1 (Engine Core) | Everything builds on this |
| 2 | Phase 7 (HTTP Server) | Need the server to serve anything |
| 3 | Phase 5 (Security State) | Highest immediate value — see blocked IPs, threats, firewall state |
| 4 | Phase 2 (App Monitoring) | Second highest value — see deployed app health |
| 5 | Phase 6 (Configuration) | Change settings without editing TOML files |
| 6 | Phase 3 (System Services) | Useful but less urgent |
| 7 | Phase 8 (Web Dashboard) | Makes everything visual |
| 8 | Phase 4 (Suspicious Detection) | Advanced feature, needs tuning |
| 9 | Phase 9 (Alerting) | Nice to have, can use external tools meanwhile |
| 10 | Phase 10 (Prometheus) | Only for users with existing Prometheus infrastructure |

---

*This document is a living plan. Update checkboxes as tasks are completed. Add new items as requirements evolve.*