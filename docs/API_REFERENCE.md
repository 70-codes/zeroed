# Zeroed API Reference

## Table of Contents

1. [Overview](#overview)
2. [Unix Socket API](#unix-socket-api)
3. [HTTP REST API](#http-rest-api)
4. [CLI Reference (zeroctl)](#cli-reference-zeroctl)
5. [Prometheus Metrics](#prometheus-metrics)
6. [Event Types](#event-types)
7. [Error Codes](#error-codes)
8. [Data Types](#data-types)

---

## Overview

Zeroed provides multiple interfaces for control and monitoring:

| Interface     | Protocol      | Use Case                        | Authentication |
| ------------- | ------------- | ------------------------------- | -------------- |
| Unix Socket   | Custom binary | Local administration (zeroctl)  | Unix perms     |
| HTTP REST API | HTTP/HTTPS    | Remote management, integrations | Token-based    |
| Prometheus    | HTTP          | Metrics collection              | Optional       |

### Connection Information

| Interface   | Default Endpoint              |
| ----------- | ----------------------------- |
| Unix Socket | `/var/run/zeroed/zeroed.sock` |
| HTTP API    | `http://127.0.0.1:8080`       |
| Prometheus  | `http://0.0.0.0:9090/metrics` |

---

## Unix Socket API

The Unix socket API is the primary interface for local administration. It uses a simple request-response protocol over a Unix domain socket.

### Connection

```bash
# Connect using socat (for debugging)
socat - UNIX-CONNECT:/var/run/zeroed/zeroed.sock

# Or use the zeroctl command
zeroctl status
```

### Protocol Format

**Request:**

```
<command> [arguments]\n
```

**Response:**

```json
{
  "status": "ok|error",
  "data": { ... },
  "error": { "code": 1001, "message": "..." }
}
```

### Commands

#### status

Get daemon status and basic statistics.

**Request:**

```
status
```

**Response:**

```json
{
  "status": "ok",
  "data": {
    "version": "0.1.0",
    "uptime_seconds": 3600,
    "state": "running",
    "pid": 12345,
    "interfaces": ["eth0"],
    "packets_processed": 1234567,
    "packets_dropped": 0,
    "blocked_ips_count": 45,
    "tracked_ips_count": 15234,
    "memory_bytes": 52428800,
    "cpu_percent": 2.5
  }
}
```

#### stats

Get detailed statistics.

**Request:**

```
stats [category]
```

**Categories:** `all`, `network`, `detection`, `storage`, `memory`

**Response (all):**

```json
{
  "status": "ok",
  "data": {
    "network": {
      "packets_total": 1234567,
      "packets_dropped": 123,
      "bytes_total": 987654321,
      "packets_by_protocol": {
        "tcp": 900000,
        "udp": 300000,
        "icmp": 34567
      },
      "interfaces": {
        "eth0": {
          "packets": 1234567,
          "bytes": 987654321,
          "dropped": 123
        }
      }
    },
    "detection": {
      "attacks_detected": 15,
      "alerts_triggered": 234,
      "blocks_applied": 45,
      "false_positives_reported": 2,
      "attacks_by_type": {
        "syn_flood": 8,
        "udp_flood": 5,
        "icmp_flood": 2
      }
    },
    "storage": {
      "ring_buffer_size": 100000,
      "ring_buffer_used": 45000,
      "bloom_filter_fill_ratio": 0.15,
      "wal_segments": 3,
      "disk_usage_bytes": 104857600,
      "records_written": 5678900
    },
    "memory": {
      "total_bytes": 52428800,
      "ip_tracking_bytes": 20971520,
      "connections_bytes": 10485760,
      "ring_buffer_bytes": 10485760,
      "bloom_filter_bytes": 1048576,
      "other_bytes": 9437184
    }
  }
}
```

#### list

List various tracked items.

**Request:**

```
list <type> [options]
```

**Types:**

- `blocked` - Currently blocked IPs
- `tracked` - All tracked IPs
- `connections` - Active connections
- `rules` - Detection rules
- `whitelist` - Whitelisted IPs
- `blacklist` - Blacklisted IPs

**Options:**

- `--limit N` - Limit results (default: 100)
- `--offset N` - Skip first N results
- `--sort field` - Sort by field
- `--format json|table` - Output format

**Example - List Blocked IPs:**

```
list blocked --limit 10 --sort blocked_at
```

**Response:**

```json
{
  "status": "ok",
  "data": {
    "total": 45,
    "offset": 0,
    "limit": 10,
    "items": [
      {
        "ip": "192.0.2.1",
        "blocked_at": "2024-01-15T10:30:00Z",
        "expires_at": "2024-01-15T11:30:00Z",
        "reason": "syn_flood",
        "threat_score": 85,
        "block_count": 3,
        "packets_blocked": 12345
      }
    ]
  }
}
```

**Example - List Tracked IPs:**

```
list tracked --limit 5
```

**Response:**

```json
{
  "status": "ok",
  "data": {
    "total": 15234,
    "items": [
      {
        "ip": "192.0.2.10",
        "first_seen": "2024-01-15T08:00:00Z",
        "last_seen": "2024-01-15T10:35:00Z",
        "request_count": 1234,
        "bytes_total": 567890,
        "packets_per_second": 12.5,
        "threat_level": "low",
        "threat_score": 15,
        "is_blocked": false,
        "country": "US",
        "asn": "AS15169"
      }
    ]
  }
}
```

#### block

Manually block an IP address.

**Request:**

```
block <ip> [options]
```

**Options:**

- `--duration N` - Block duration in seconds (default: from config)
- `--reason text` - Reason for block
- `--permanent` - Block permanently (no expiry)

**Example:**

```
block 192.0.2.1 --duration 7200 --reason "manual block"
```

**Response:**

```json
{
  "status": "ok",
  "data": {
    "ip": "192.0.2.1",
    "blocked_at": "2024-01-15T10:35:00Z",
    "expires_at": "2024-01-15T12:35:00Z",
    "reason": "manual block",
    "firewall_rule_id": "ZEROED-1234"
  }
}
```

#### unblock

Remove block from an IP address.

**Request:**

```
unblock <ip>
```

**Response:**

```json
{
  "status": "ok",
  "data": {
    "ip": "192.0.2.1",
    "was_blocked": true,
    "blocked_duration_seconds": 3600,
    "firewall_rule_removed": true
  }
}
```

#### whitelist

Manage IP whitelist.

**Request:**

```
whitelist <action> <ip_or_cidr>
```

**Actions:** `add`, `remove`, `check`

**Example:**

```
whitelist add 192.168.1.0/24
```

**Response:**

```json
{
  "status": "ok",
  "data": {
    "action": "add",
    "entry": "192.168.1.0/24",
    "type": "cidr",
    "total_entries": 15
  }
}
```

#### blacklist

Manage IP blacklist.

**Request:**

```
blacklist <action> <ip_or_cidr>
```

**Actions:** `add`, `remove`, `check`

#### lookup

Look up detailed information about an IP.

**Request:**

```
lookup <ip>
```

**Response:**

```json
{
  "status": "ok",
  "data": {
    "ip": "192.0.2.1",
    "tracking": {
      "first_seen": "2024-01-15T08:00:00Z",
      "last_seen": "2024-01-15T10:35:00Z",
      "request_count": 5678,
      "bytes_total": 1234567,
      "unique_ports_accessed": [80, 443, 8080],
      "unique_destinations": 3
    },
    "statistics": {
      "packets_per_second": 45.2,
      "bytes_per_second": 12345,
      "syn_count": 234,
      "active_connections": 5,
      "half_open_connections": 0,
      "failed_connections": 12
    },
    "threat": {
      "level": "medium",
      "score": 45,
      "attack_types": ["rate_limit_exceeded"],
      "alerts_triggered": 3,
      "blocks_count": 0
    },
    "geo": {
      "country_code": "US",
      "country_name": "United States",
      "region": "California",
      "city": "San Francisco",
      "latitude": 37.7749,
      "longitude": -122.4194,
      "asn": "AS15169",
      "org": "Google LLC"
    },
    "mac": {
      "address": "00:1a:2b:3c:4d:5e",
      "vendor": "Cisco Systems"
    },
    "status": {
      "is_blocked": false,
      "is_whitelisted": false,
      "is_blacklisted": false
    }
  }
}
```

#### flush

Flush various caches or data.

**Request:**

```
flush <type>
```

**Types:**

- `blocks` - Remove all temporary blocks
- `tracking` - Clear IP tracking data
- `connections` - Clear connection tracking
- `bloom` - Rebuild bloom filters
- `all` - Flush everything

**Response:**

```json
{
  "status": "ok",
  "data": {
    "type": "blocks",
    "items_flushed": 45,
    "firewall_rules_removed": 45
  }
}
```

#### reload

Reload configuration without restart.

**Request:**

```
reload
```

**Response:**

```json
{
  "status": "ok",
  "data": {
    "config_path": "/etc/zeroed/config.toml",
    "reloaded_at": "2024-01-15T10:35:00Z",
    "changes_applied": [
      "detection.rps_threshold: 100 -> 150",
      "detection.block_duration: 3600 -> 7200"
    ]
  }
}
```

#### shutdown

Gracefully shutdown the daemon.

**Request:**

```
shutdown [--force]
```

**Response:**

```json
{
  "status": "ok",
  "data": {
    "message": "Shutdown initiated",
    "graceful": true,
    "pending_writes": 0
  }
}
```

---

## HTTP REST API

The HTTP REST API provides remote access when enabled. All endpoints return JSON.

### Configuration

```toml
[api]
http_enabled = true
http_bind = "127.0.0.1"
http_port = 8080
tls_enabled = false
auth_token = "your-secret-token"
```

### Authentication

Include the auth token in the `Authorization` header:

```http
Authorization: Bearer your-secret-token
```

Or as a query parameter:

```
GET /api/v1/status?token=your-secret-token
```

### Common Response Format

**Success:**

```json
{
  "success": true,
  "data": { ... },
  "timestamp": "2024-01-15T10:35:00Z"
}
```

**Error:**

```json
{
  "success": false,
  "error": {
    "code": 1001,
    "message": "IP not found",
    "details": "192.0.2.1 is not being tracked"
  },
  "timestamp": "2024-01-15T10:35:00Z"
}
```

### Endpoints

#### GET /api/v1/status

Get daemon status.

**Response:**

```json
{
  "success": true,
  "data": {
    "version": "0.1.0",
    "uptime_seconds": 3600,
    "state": "running",
    "interfaces": ["eth0"],
    "summary": {
      "packets_processed": 1234567,
      "blocked_ips": 45,
      "tracked_ips": 15234
    }
  }
}
```

#### GET /api/v1/stats

Get detailed statistics.

**Query Parameters:**

- `category` - Filter by category (network, detection, storage, memory)

**Example:**

```http
GET /api/v1/stats?category=detection
```

#### GET /api/v1/blocked

List blocked IPs.

**Query Parameters:**

- `limit` (integer) - Max results (default: 100)
- `offset` (integer) - Skip results
- `sort` (string) - Sort field
- `order` (string) - asc/desc

**Example:**

```http
GET /api/v1/blocked?limit=10&sort=blocked_at&order=desc
```

#### POST /api/v1/block

Block an IP address.

**Request Body:**

```json
{
  "ip": "192.0.2.1",
  "duration": 3600,
  "reason": "manual block"
}
```

**Response:**

```json
{
  "success": true,
  "data": {
    "ip": "192.0.2.1",
    "blocked_at": "2024-01-15T10:35:00Z",
    "expires_at": "2024-01-15T11:35:00Z"
  }
}
```

#### DELETE /api/v1/block/{ip}

Unblock an IP address.

**Example:**

```http
DELETE /api/v1/block/192.0.2.1
```

#### GET /api/v1/tracked

List tracked IPs.

**Query Parameters:**

- `limit`, `offset`, `sort`, `order`
- `threat_level` - Filter by threat level (none, low, medium, high, critical)
- `country` - Filter by country code

#### GET /api/v1/ip/{ip}

Get detailed information about an IP.

**Example:**

```http
GET /api/v1/ip/192.0.2.1
```

#### GET /api/v1/connections

List active connections.

**Query Parameters:**

- `limit`, `offset`
- `ip` - Filter by IP
- `state` - Filter by TCP state

#### POST /api/v1/whitelist

Add to whitelist.

**Request Body:**

```json
{
  "entry": "192.168.1.0/24",
  "comment": "Internal network"
}
```

#### DELETE /api/v1/whitelist/{entry}

Remove from whitelist.

#### POST /api/v1/blacklist

Add to blacklist.

#### DELETE /api/v1/blacklist/{entry}

Remove from blacklist.

#### POST /api/v1/reload

Reload configuration.

#### GET /api/v1/config

Get current running configuration (sensitive values redacted).

#### GET /api/v1/rules

List detection rules.

#### PUT /api/v1/rules/{id}

Update a detection rule.

**Request Body:**

```json
{
  "enabled": false,
  "threshold": 200
}
```

#### POST /api/v1/flush

Flush caches/data.

**Request Body:**

```json
{
  "type": "blocks"
}
```

#### GET /api/v1/events

Get recent events (Server-Sent Events for streaming).

**Example:**

```http
GET /api/v1/events
Accept: text/event-stream
```

**Stream Format:**

```
event: block
data: {"ip": "192.0.2.1", "reason": "syn_flood", "timestamp": "..."}

event: alert
data: {"ip": "192.0.2.2", "type": "rate_limit", "value": 550}
```

---

## CLI Reference (zeroctl)

`zeroctl` is the command-line tool for managing Zeroed.

### Global Options

```
-s, --socket <path>    Unix socket path (default: /var/run/zeroed/zeroed.sock)
-H, --host <host>      HTTP API host (default: 127.0.0.1)
-p, --port <port>      HTTP API port (default: 8080)
-t, --token <token>    API authentication token
    --http             Use HTTP API instead of Unix socket
-o, --output <format>  Output format: table, json, yaml (default: table)
-v, --verbose          Verbose output
-q, --quiet            Quiet mode (errors only)
    --help             Show help
    --version          Show version
```

### Commands

#### zeroctl status

Show daemon status.

```bash
zeroctl status
zeroctl status --verbose
zeroctl status --output json
```

#### zeroctl stats

Show statistics.

```bash
zeroctl stats
zeroctl stats network
zeroctl stats detection
zeroctl stats storage
zeroctl stats memory
zeroctl stats --period 24h  # Last 24 hours
```

#### zeroctl list

List items.

```bash
zeroctl list blocked
zeroctl list blocked --limit 20 --sort threat_score
zeroctl list tracked --threat-level high
zeroctl list connections --state established
zeroctl list rules
zeroctl list whitelist
zeroctl list blacklist
```

#### zeroctl block

Block an IP.

```bash
zeroctl block 192.0.2.1
zeroctl block 192.0.2.1 --duration 7200
zeroctl block 192.0.2.1 --permanent
zeroctl block 192.0.2.1 --reason "Suspicious activity"
```

#### zeroctl unblock

Unblock an IP.

```bash
zeroctl unblock 192.0.2.1
zeroctl unblock --all  # Unblock all IPs
```

#### zeroctl whitelist

Manage whitelist.

```bash
zeroctl whitelist add 192.168.1.0/24
zeroctl whitelist add 10.0.0.1 --comment "Admin server"
zeroctl whitelist remove 192.168.1.0/24
zeroctl whitelist check 192.168.1.50
```

#### zeroctl blacklist

Manage blacklist.

```bash
zeroctl blacklist add 192.0.2.0/24
zeroctl blacklist remove 192.0.2.0/24
zeroctl blacklist import blocklist.txt
```

#### zeroctl lookup

Look up IP information.

```bash
zeroctl lookup 192.0.2.1
zeroctl lookup 192.0.2.1 --verbose
```

#### zeroctl top

Real-time traffic view.

```bash
zeroctl top
zeroctl top --sort pps      # Sort by packets/sec
zeroctl top --sort bps      # Sort by bytes/sec
zeroctl top --sort threat   # Sort by threat score
zeroctl top -n 20           # Show top 20
```

#### zeroctl watch

Watch events in real-time.

```bash
zeroctl watch
zeroctl watch --type block
zeroctl watch --type alert
zeroctl watch --ip 192.0.2.1
```

#### zeroctl flush

Flush data.

```bash
zeroctl flush blocks
zeroctl flush tracking
zeroctl flush connections
zeroctl flush bloom
zeroctl flush all --confirm
```

#### zeroctl reload

Reload configuration.

```bash
zeroctl reload
```

#### zeroctl config

Configuration operations.

```bash
zeroctl config show
zeroctl config validate /etc/zeroed/config.toml
zeroctl config diff  # Show changes from default
```

#### zeroctl import / export

Import and export data.

```bash
# Export blocked IPs
zeroctl export blocked > blocked.json
zeroctl export blocked --format csv > blocked.csv

# Import blocklist
zeroctl import blocked.json
zeroctl import blocklist.txt --format plain

# Export full state
zeroctl export state > state.json
```

#### zeroctl diagnose

Run diagnostics.

```bash
zeroctl diagnose
zeroctl diagnose --full
```

---

## Prometheus Metrics

Zeroed exports Prometheus metrics on the configured endpoint (default: `http://0.0.0.0:9090/metrics`).

### Metric Types

| Type      | Description                          |
| --------- | ------------------------------------ |
| Counter   | Cumulative values that only increase |
| Gauge     | Values that can increase or decrease |
| Histogram | Observations bucketed by value       |
| Summary   | Similar to histogram with quantiles  |

### Available Metrics

#### Packet Metrics

```prometheus
# HELP zeroed_packets_total Total packets captured
# TYPE zeroed_packets_total counter
zeroed_packets_total{interface="eth0"} 1234567

# HELP zeroed_packets_dropped Total packets dropped by kernel
# TYPE zeroed_packets_dropped counter
zeroed_packets_dropped{interface="eth0"} 123

# HELP zeroed_bytes_total Total bytes captured
# TYPE zeroed_bytes_total counter
zeroed_bytes_total{interface="eth0"} 987654321

# HELP zeroed_packets_by_protocol Packets by protocol
# TYPE zeroed_packets_by_protocol counter
zeroed_packets_by_protocol{protocol="tcp"} 900000
zeroed_packets_by_protocol{protocol="udp"} 300000
zeroed_packets_by_protocol{protocol="icmp"} 34567
```

#### Detection Metrics

```prometheus
# HELP zeroed_blocked_ips_total Total IPs blocked (cumulative)
# TYPE zeroed_blocked_ips_total counter
zeroed_blocked_ips_total 150

# HELP zeroed_blocked_ips_current Currently blocked IPs
# TYPE zeroed_blocked_ips_current gauge
zeroed_blocked_ips_current 45

# HELP zeroed_tracked_ips_current Currently tracked IPs
# TYPE zeroed_tracked_ips_current gauge
zeroed_tracked_ips_current 15234

# HELP zeroed_attacks_detected Total attacks detected
# TYPE zeroed_attacks_detected counter
zeroed_attacks_detected{type="syn_flood"} 8
zeroed_attacks_detected{type="udp_flood"} 5
zeroed_attacks_detected{type="rate_limit"} 234

# HELP zeroed_alerts_triggered Total alerts triggered
# TYPE zeroed_alerts_triggered counter
zeroed_alerts_triggered 500

# HELP zeroed_threat_score_distribution Distribution of threat scores
# TYPE zeroed_threat_score_distribution histogram
zeroed_threat_score_distribution_bucket{le="10"} 10000
zeroed_threat_score_distribution_bucket{le="25"} 13000
zeroed_threat_score_distribution_bucket{le="50"} 14500
zeroed_threat_score_distribution_bucket{le="75"} 15000
zeroed_threat_score_distribution_bucket{le="100"} 15234
```

#### Performance Metrics

```prometheus
# HELP zeroed_detection_latency_seconds Detection latency
# TYPE zeroed_detection_latency_seconds histogram
zeroed_detection_latency_seconds_bucket{le="0.001"} 900000
zeroed_detection_latency_seconds_bucket{le="0.005"} 990000
zeroed_detection_latency_seconds_bucket{le="0.01"} 999000
zeroed_detection_latency_seconds_sum 500.5
zeroed_detection_latency_seconds_count 1000000

# HELP zeroed_processing_rate_pps Current packet processing rate
# TYPE zeroed_processing_rate_pps gauge
zeroed_processing_rate_pps 50000

# HELP zeroed_queue_size Current packet queue size
# TYPE zeroed_queue_size gauge
zeroed_queue_size 1234
```

#### Storage Metrics

```prometheus
# HELP zeroed_storage_records_written Total records written
# TYPE zeroed_storage_records_written counter
zeroed_storage_records_written 5678900

# HELP zeroed_storage_bytes_written Total bytes written to storage
# TYPE zeroed_storage_bytes_written counter
zeroed_storage_bytes_written 1234567890

# HELP zeroed_ring_buffer_size Ring buffer capacity
# TYPE zeroed_ring_buffer_size gauge
zeroed_ring_buffer_size 100000

# HELP zeroed_ring_buffer_used Ring buffer current usage
# TYPE zeroed_ring_buffer_used gauge
zeroed_ring_buffer_used 45000

# HELP zeroed_bloom_filter_fill_ratio Bloom filter fill ratio
# TYPE zeroed_bloom_filter_fill_ratio gauge
zeroed_bloom_filter_fill_ratio 0.15

# HELP zeroed_wal_segments_count Number of WAL segments
# TYPE zeroed_wal_segments_count gauge
zeroed_wal_segments_count 3
```

#### Resource Metrics

```prometheus
# HELP zeroed_memory_bytes Memory usage in bytes
# TYPE zeroed_memory_bytes gauge
zeroed_memory_bytes{component="total"} 52428800
zeroed_memory_bytes{component="ip_tracking"} 20971520
zeroed_memory_bytes{component="connections"} 10485760
zeroed_memory_bytes{component="ring_buffer"} 10485760
zeroed_memory_bytes{component="bloom_filter"} 1048576

# HELP zeroed_cpu_seconds_total CPU time used
# TYPE zeroed_cpu_seconds_total counter
zeroed_cpu_seconds_total{mode="user"} 1234.5
zeroed_cpu_seconds_total{mode="system"} 567.8

# HELP zeroed_threads_count Number of active threads
# TYPE zeroed_threads_count gauge
zeroed_threads_count 8
```

#### GeoIP Metrics

```prometheus
# HELP zeroed_geoip_lookups_total GeoIP lookups performed
# TYPE zeroed_geoip_lookups_total counter
zeroed_geoip_lookups_total 500000

# HELP zeroed_geoip_cache_hits GeoIP cache hits
# TYPE zeroed_geoip_cache_hits counter
zeroed_geoip_cache_hits 450000

# HELP zeroed_blocked_by_country IPs blocked by country
# TYPE zeroed_blocked_by_country counter
zeroed_blocked_by_country{country="CN"} 50
zeroed_blocked_by_country{country="RU"} 30
```

#### Firewall Metrics

```prometheus
# HELP zeroed_firewall_rules_count Current firewall rules
# TYPE zeroed_firewall_rules_count gauge
zeroed_firewall_rules_count 45

# HELP zeroed_firewall_operations_total Firewall operations
# TYPE zeroed_firewall_operations_total counter
zeroed_firewall_operations_total{operation="add"} 150
zeroed_firewall_operations_total{operation="remove"} 105

# HELP zeroed_firewall_errors_total Firewall operation errors
# TYPE zeroed_firewall_errors_total counter
zeroed_firewall_errors_total 2
```

---

## Event Types

Events are emitted by Zeroed for logging and streaming.

### Event Structure

```json
{
  "id": "evt_123456",
  "type": "block",
  "timestamp": "2024-01-15T10:35:00.123456Z",
  "data": { ... }
}
```

### Event Types

#### block

IP was blocked.

```json
{
  "type": "block",
  "data": {
    "ip": "192.0.2.1",
    "reason": "syn_flood",
    "threat_score": 85,
    "duration": 3600,
    "expires_at": "2024-01-15T11:35:00Z",
    "automatic": true
  }
}
```

#### unblock

IP was unblocked.

```json
{
  "type": "unblock",
  "data": {
    "ip": "192.0.2.1",
    "reason": "expired",
    "blocked_duration_seconds": 3600
  }
}
```

#### alert

Alert triggered (threshold exceeded but not blocked).

```json
{
  "type": "alert",
  "data": {
    "ip": "192.0.2.1",
    "alert_type": "rate_limit_exceeded",
    "current_value": 150,
    "threshold": 100,
    "threat_score": 45
  }
}
```

#### attack_detected

Attack pattern detected.

```json
{
  "type": "attack_detected",
  "data": {
    "source_ip": "192.0.2.1",
    "attack_type": "syn_flood",
    "confidence": 0.95,
    "packets_per_second": 5000,
    "action_taken": "blocked"
  }
}
```

#### connection

Connection state change.

```json
{
  "type": "connection",
  "data": {
    "event": "opened",
    "src_ip": "192.0.2.1",
    "src_port": 54321,
    "dst_ip": "10.0.0.1",
    "dst_port": 80,
    "protocol": "tcp"
  }
}
```

#### config_reloaded

Configuration was reloaded.

```json
{
  "type": "config_reloaded",
  "data": {
    "changes": ["detection.rps_threshold: 100 -> 150"]
  }
}
```

---

## Error Codes

| Code | Name                | Description                     |
| ---- | ------------------- | ------------------------------- |
| 1000 | UNKNOWN_ERROR       | Unknown error occurred          |
| 1001 | NOT_FOUND           | Resource not found              |
| 1002 | INVALID_IP          | Invalid IP address format       |
| 1003 | INVALID_CIDR        | Invalid CIDR notation           |
| 1004 | INVALID_PARAMETER   | Invalid parameter value         |
| 1005 | MISSING_PARAMETER   | Required parameter missing      |
| 1006 | ALREADY_EXISTS      | Resource already exists         |
| 1007 | NOT_BLOCKED         | IP is not currently blocked     |
| 1008 | WHITELISTED         | Cannot block whitelisted IP     |
| 1009 | PERMISSION_DENIED   | Permission denied               |
| 1010 | RATE_LIMITED        | API rate limit exceeded         |
| 2001 | FIREWALL_ERROR      | Firewall operation failed       |
| 2002 | STORAGE_ERROR       | Storage operation failed        |
| 2003 | CONFIG_ERROR        | Configuration error             |
| 2004 | CAPTURE_ERROR       | Packet capture error            |
| 3001 | INTERNAL_ERROR      | Internal server error           |
| 3002 | TIMEOUT             | Operation timed out             |
| 3003 | SERVICE_UNAVAILABLE | Service temporarily unavailable |
| 3004 | NOT_IMPLEMENTED     | Feature not implemented         |

### Error Response Example

```json
{
  "status": "error",
  "error": {
    "code": 1002,
    "message": "Invalid IP address format",
    "details": "The provided value '192.168.1.999' is not a valid IPv4 or IPv6 address"
  },
  "timestamp": "2024-01-15T10:35:00Z"
}
```

---

## Data Types

### IP Address Types

```rust
// IPv4 or IPv6 address
type IpAddr = std::net::IpAddr;

// CIDR notation (e.g., "192.168.1.0/24")
type Cidr = String;

// MAC address (e.g., "00:1a:2b:3c:4d:5e")
type MacAddr = String;
```

### Time Types

All timestamps are in RFC 3339 format (ISO 8601):

```
"2024-01-15T10:35:00.123456Z"
```

Durations are expressed in seconds as integers:

```json
{
  "block_duration": 3600,
  "uptime_seconds": 86400
}
```

### Threat Levels

```rust
pub enum ThreatLevel {
    None,      // Score 0-10
    Low,       // Score 11-25
    Medium,    // Score 26-50
    High,      // Score 51-75
    Critical,  // Score 76-100
}
```

### Attack Types

```rust
pub enum AttackType {
    SynFlood,
    UdpFlood,
    IcmpFlood,
    Slowloris,
    DnsAmplification,
    NtpAmplification,
    HttpFlood,
    RateLimitExceeded,
    ConnectionExhaustion,
    Unknown,
}
```

### Block Reasons

```rust
pub enum BlockReason {
    Manual,              // Manually blocked via API
    SynFlood,            // Detected SYN flood attack
    UdpFlood,            // Detected UDP flood attack
    IcmpFlood,           // Detected ICMP flood attack
    RateLimitExceeded,   // Exceeded rate limit threshold
    ThreatScoreHigh,     // Threat score exceeded critical threshold
    Blacklisted,         // IP is on blacklist
    GeoBlocked,          // Blocked by country/region
    RuleTriggered,       // Custom detection rule triggered
}
```

### Connection States (TCP)

```rust
pub enum TcpState {
    New,
    SynSent,
    SynReceived,
    Established,
    FinWait1,
    FinWait2,
    CloseWait,
    Closing,
    LastAck,
    TimeWait,
    Closed,
}
```

### Protocol Types

```rust
pub enum Protocol {
    Tcp,
    Udp,
    Icmp,
    Icmpv6,
    Other(u8),
}
```

### Pagination

List endpoints support pagination with these parameters:

| Parameter | Type    | Default | Description             |
| --------- | ------- | ------- | ----------------------- |
| `limit`   | integer | 100     | Maximum items to return |
| `offset`  | integer | 0       | Number of items to skip |
| `sort`    | string  | varies  | Field to sort by        |
| `order`   | string  | "desc"  | Sort order (asc/desc)   |

**Paginated Response:**

```json
{
  "status": "ok",
  "data": {
    "total": 1500,
    "offset": 100,
    "limit": 50,
    "items": [ ... ]
  }
}
```

### Rate Limit Headers

When rate limiting is enabled on the API:

| Header                  | Description                          |
| ----------------------- | ------------------------------------ |
| `X-RateLimit-Limit`     | Maximum requests per window          |
| `X-RateLimit-Remaining` | Remaining requests in current window |
| `X-RateLimit-Reset`     | Unix timestamp when window resets    |

---

## Appendix: Quick Reference

### Common Operations

| Task                 | Unix Socket Command  | HTTP Endpoint               |
| -------------------- | -------------------- | --------------------------- |
| Get status           | `status`             | `GET /api/v1/status`        |
| Block an IP          | `block <ip>`         | `POST /api/v1/block`        |
| Unblock an IP        | `unblock <ip>`       | `DELETE /api/v1/block/{ip}` |
| List blocked IPs     | `list blocked`       | `GET /api/v1/blocked`       |
| Add to whitelist     | `whitelist add <ip>` | `POST /api/v1/whitelist`    |
| Get IP details       | `lookup <ip>`        | `GET /api/v1/ip/{ip}`       |
| Get statistics       | `stats`              | `GET /api/v1/stats`         |
| Reload configuration | `reload`             | `POST /api/v1/reload`       |

### Response Status Codes (HTTP)

| Code | Meaning               | When Used                      |
| ---- | --------------------- | ------------------------------ |
| 200  | OK                    | Successful GET, DELETE         |
| 201  | Created               | Successful POST (new resource) |
| 204  | No Content            | Successful DELETE (no body)    |
| 400  | Bad Request           | Invalid parameters             |
| 401  | Unauthorized          | Missing or invalid auth token  |
| 403  | Forbidden             | Insufficient permissions       |
| 404  | Not Found             | Resource doesn't exist         |
| 409  | Conflict              | Resource already exists        |
| 429  | Too Many Requests     | Rate limit exceeded            |
| 500  | Internal Server Error | Server-side error              |
| 503  | Service Unavailable   | Daemon not ready               |

---

_Document Version: 1.0_
_Last Updated: 2025_
