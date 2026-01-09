# Zeroed DoS Protection Daemon - Complete Capabilities Document

**Version:** 0.1.0  
**Last Updated:** 2024  
**License:** MIT

---

## Table of Contents

1. [Executive Summary](#1-executive-summary)
2. [System Architecture](#2-system-architecture)
3. [Network Monitoring Capabilities](#3-network-monitoring-capabilities)
4. [Attack Detection Engine](#4-attack-detection-engine)
5. [Storage System](#5-storage-system)
6. [IP and MAC Address Tracking](#6-ip-and-mac-address-tracking)
7. [Geographic Source Detection](#7-geographic-source-detection)
8. [Firewall Integration](#8-firewall-integration)
9. [Rate Limiting Algorithms](#9-rate-limiting-algorithms)
10. [API and Control Interface](#10-api-and-control-interface)
11. [Metrics and Monitoring](#11-metrics-and-monitoring)
12. [Configuration System](#12-configuration-system)
13. [Daemon Management](#13-daemon-management)
14. [Performance Characteristics](#14-performance-characteristics)
15. [Security Features](#15-security-features)

---

## 1. Executive Summary

Zeroed is a high-performance Linux daemon designed to protect servers from Denial of Service (DoS) and Distributed Denial of Service (DDoS) attacks. It operates as a userspace daemon that captures network traffic, analyzes patterns in real-time, and automatically mitigates threats through firewall integration.

### Core Capabilities Overview

| Capability | Description |
|------------|-------------|
| **Packet Capture** | Real-time network traffic monitoring using libpcap |
| **Protocol Analysis** | Deep inspection of TCP, UDP, ICMP, and ARP packets |
| **Attack Detection** | Multiple algorithms for detecting various attack types |
| **Automatic Mitigation** | Integration with iptables/nftables for blocking |
| **Efficient Storage** | Custom binary format with minimal I/O overhead |
| **Geographic Filtering** | GeoIP-based country blocking and monitoring |
| **API Control** | Unix socket and optional HTTP REST API |
| **Metrics Export** | Prometheus-compatible metrics endpoint |

---

## 2. System Architecture

### 2.1 High-Level Architecture

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                              ZEROED DAEMON                                   │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                             │
│  ┌──────────────┐   ┌──────────────┐   ┌──────────────┐   ┌──────────────┐ │
│  │   Network    │──▶│   Packet     │──▶│  Detection   │──▶│  Firewall    │ │
│  │   Capture    │   │   Parser     │   │   Engine     │   │  Manager     │ │
│  │   Engine     │   │              │   │              │   │              │ │
│  └──────────────┘   └──────────────┘   └──────────────┘   └──────────────┘ │
│         │                  │                  │                  │         │
│         │                  │                  │                  │         │
│         ▼                  ▼                  ▼                  ▼         │
│  ┌──────────────┐   ┌──────────────┐   ┌──────────────┐   ┌──────────────┐ │
│  │  Interface   │   │  Connection  │   │     IP       │   │  iptables/   │ │
│  │  Manager     │   │   Tracker    │   │   Tracker    │   │  nftables    │ │
│  └──────────────┘   └──────────────┘   └──────────────┘   └──────────────┘ │
│                                                                             │
│  ┌─────────────────────────────────────────────────────────────────────┐   │
│  │                        STORAGE ENGINE                                │   │
│  │  ┌────────────┐ ┌────────────┐ ┌────────────┐ ┌────────────┐       │   │
│  │  │   Ring     │ │   Bloom    │ │  Sharded   │ │   Write    │       │   │
│  │  │  Buffer    │ │  Filters   │ │  Storage   │ │  Ahead Log │       │   │
│  │  └────────────┘ └────────────┘ └────────────┘ └────────────┘       │   │
│  └─────────────────────────────────────────────────────────────────────┘   │
│                                                                             │
│  ┌──────────────┐   ┌──────────────┐   ┌──────────────┐                    │
│  │   GeoIP      │   │    API       │   │  Prometheus  │                    │
│  │   Service    │   │   Server     │   │   Exporter   │                    │
│  └──────────────┘   └──────────────┘   └──────────────┘                    │
│                                                                             │
└─────────────────────────────────────────────────────────────────────────────┘
```

### 2.2 Module Structure

```
src/
├── core/           # Core types, configuration, error handling
├── network/        # Packet capture, parsing, connection tracking
├── storage/        # Custom efficient storage system
├── detection/      # Attack detection algorithms
├── geo/            # Geographic IP lookup
├── daemon/         # Process lifecycle management
└── api/            # Control interface
```

### 2.3 Data Flow

1. **Capture**: Packets captured from network interface via libpcap
2. **Parse**: Ethernet, IP, and transport layer headers extracted
3. **Track**: Connection state and IP statistics updated
4. **Analyze**: Detection algorithms evaluate traffic patterns
5. **Act**: Firewall rules applied for detected threats
6. **Store**: Events logged to efficient storage system
7. **Report**: Metrics exported for monitoring

---

## 3. Network Monitoring Capabilities

### 3.1 Packet Capture Engine

#### Supported Capture Methods
- **libpcap**: Primary capture method, kernel-level packet filtering
- **Raw sockets**: Alternative for specific use cases
- **BPF Filters**: Berkeley Packet Filter for efficient pre-filtering

#### Capture Features

| Feature | Description | Configuration |
|---------|-------------|---------------|
| **Promiscuous Mode** | Capture all traffic on interface | `promiscuous = true` |
| **Multiple Interfaces** | Monitor multiple NICs simultaneously | `interfaces = ["eth0", "eth1"]` |
| **BPF Filtering** | Kernel-level packet filtering | `bpf_filter = "tcp port 80"` |
| **Configurable Buffer** | Adjust capture buffer size | `capture_buffer_mb = 64` |
| **Snapshot Length** | Control captured packet size | `snap_len = 65535` |

#### Interface Management

```rust
// Capabilities
- Auto-detect default interface
- List all available interfaces
- Monitor interface state changes
- Read interface statistics from /proc/net/dev
- Detect virtual/hypervisor interfaces by MAC OUI
```

### 3.2 Protocol Support

#### Layer 2 (Data Link)
- **Ethernet**: Frame parsing, MAC address extraction
- **ARP**: ARP request/reply monitoring for MAC-IP correlation

#### Layer 3 (Network)
- **IPv4**: Full header parsing, fragmentation detection
- **IPv6**: Header parsing, extension header awareness

#### Layer 4 (Transport)
- **TCP**: 
  - Full flag analysis (SYN, ACK, FIN, RST, PSH, URG, ECE, CWR)
  - Sequence/acknowledgment number tracking
  - Window size monitoring
  - Connection state machine implementation
- **UDP**: Port and length extraction
- **ICMP/ICMPv6**: Type and code extraction, echo request/reply identification

### 3.3 Connection Tracking

#### TCP State Machine

```
         ┌──────────┐
         │  LISTEN  │
         └────┬─────┘
              │ SYN received
              ▼
       ┌──────────────┐
       │ SYN_RECEIVED │
       └──────┬───────┘
              │ ACK received
              ▼
       ┌─────────────┐
       │ ESTABLISHED │◀──────────────────┐
       └──────┬──────┘                   │
              │ FIN sent/received        │
              ▼                          │
    ┌─────────────────┐                  │
    │   FIN_WAIT_1    │                  │
    └────────┬────────┘                  │
             │                           │
    ┌────────▼────────┐                  │
    │   FIN_WAIT_2    │                  │
    └────────┬────────┘                  │
             │                           │
    ┌────────▼────────┐    ┌───────────┐│
    │   TIME_WAIT     │    │CLOSE_WAIT ││
    └────────┬────────┘    └─────┬─────┘│
             │                   │       │
    ┌────────▼────────┐    ┌─────▼─────┐│
    │     CLOSED      │    │ LAST_ACK  ││
    └─────────────────┘    └───────────┘│
```

#### Connection Tracking Features

| Feature | Description |
|---------|-------------|
| **Bidirectional Tracking** | Track both directions of a flow |
| **Five-Tuple Identification** | src_ip, dst_ip, src_port, dst_port, protocol |
| **Connection Normalization** | Consistent key generation for lookups |
| **State Timeout Management** | Configurable timeouts per state |
| **Half-Open Detection** | Identify incomplete handshakes |
| **Symmetry Analysis** | Detect unidirectional traffic patterns |

### 3.4 Packet Classification

```rust
pub enum PacketClass {
    TcpSyn,           // Connection initiation
    TcpSynAck,        // Connection acceptance
    TcpAck,           // Pure acknowledgment
    TcpFin,           // Connection termination
    TcpRst,           // Connection reset
    TcpData,          // Data transfer
    Udp,              // UDP packet
    IcmpEchoRequest,  // Ping request
    IcmpEchoReply,    // Ping reply
    IcmpOther,        // Other ICMP
    Arp,              // ARP packet
    Other,            // Unclassified
}
```

---

## 4. Attack Detection Engine

### 4.1 Supported Attack Types

| Attack Type | Detection Method | Default Threshold |
|-------------|------------------|-------------------|
| **SYN Flood** | Half-open connection rate | 1000 SYN/s |
| **UDP Flood** | UDP packet rate per source | 5000 pkt/s |
| **ICMP Flood** | ICMP packet rate | 500 pkt/s |
| **HTTP Flood** | HTTP request rate | Configurable |
| **Slowloris** | Connection data rate | < 100 bytes/s |
| **Connection Exhaustion** | Concurrent connections | 100 per IP |
| **Port Scan** | Unique ports accessed | High port entropy |
| **Volumetric Attack** | Total bandwidth | Configurable |

### 4.2 Detection Algorithms

#### Rate Limiting

**Token Bucket Algorithm**
```
- Allows bursts up to bucket capacity
- Refills at configured rate
- Smooth rate limiting for traffic shaping

Parameters:
  - Burst Size: Maximum tokens (burst capacity)
  - Refill Rate: Tokens per second
```

**Sliding Window Algorithm**
```
- Tracks timestamps within time window
- Accurate rate measurement
- Memory-efficient with bounded storage

Parameters:
  - Window Duration: Time window size
  - Max Requests: Maximum allowed in window
```

**Leaky Bucket Algorithm**
```
- Traffic shaping with constant drain rate
- Prevents burst accumulation
- Overflow indicates rate violation

Parameters:
  - Capacity: Bucket size
  - Leak Rate: Drain rate per second
```

#### Threat Scoring

```rust
pub enum ThreatLevel {
    None = 0,      // Normal traffic (score < 0.2)
    Low = 1,       // Slightly elevated (0.2 - 0.4)
    Medium = 2,    // Suspicious activity (0.4 - 0.6)
    High = 3,      // Probable attack (0.6 - 0.8)
    Critical = 4,  // Confirmed attack (> 0.8)
}
```

#### Adaptive Thresholds

- **Learning Rate**: Configurable adaptation speed
- **Baseline Calculation**: Exponential moving average
- **Sensitivity Levels**: 1-10 scale for detection aggressiveness
- **Min/Max Bounds**: Prevents threshold drift

### 4.3 Detection Rules Engine

```rust
struct DetectionRule {
    id: u64,
    name: String,
    enabled: bool,
    priority: i32,           // Higher = checked first
    criteria: RuleCriteria,  // Matching conditions
    action: Action,          // Response action
    threat_level: ThreatLevel,
}

struct RuleCriteria {
    src_ip: Option<String>,      // Source IP/CIDR
    dst_ip: Option<String>,      // Destination IP/CIDR
    src_port: Option<(u16, u16)>, // Port range
    dst_port: Option<(u16, u16)>,
    protocol: Option<Protocol>,
    min_pps: Option<u32>,        // Packets per second
    min_bps: Option<u64>,        // Bytes per second
    min_connections: Option<u32>,
    countries: Option<Vec<String>>,
    time_range: Option<(u8, u8)>, // Hour range (UTC)
}
```

### 4.4 Response Actions

| Action | Description |
|--------|-------------|
| **Allow** | Permit traffic (whitelist) |
| **LogOnly** | Log but don't block |
| **RateLimit** | Apply rate limiting |
| **Drop** | Silently drop packets |
| **Reject** | Drop with RST/ICMP unreachable |
| **Tarpit** | Slow down responses |
| **Challenge** | Apply SYN cookies |

---

## 5. Storage System

### 5.1 Storage Architecture

```
data/
├── ring/                 # Ring buffer for recent events
│   └── current.bin       # Memory-mapped ring buffer
├── archive/              # Historical data (date-organized)
│   └── YYYY-MM-DD/
│       └── hour_XX.zbin  # Hourly compressed archives
├── index/                # Fast lookup structures
│   ├── ip_bloom.bin      # Bloom filter for IPs
│   └── mac_bloom.bin     # Bloom filter for MACs
├── state/                # Runtime state
│   └── tracking.bin      # IP tracking cache
├── shards/               # Parallel write shards
│   └── shard_XXXX.shard  # Individual shard files
└── wal/                  # Write-ahead log
    └── wal_XXXXXXXX.bin  # WAL segment files
```

### 5.2 Ring Buffer

#### Capabilities
- **Fixed Size**: Configurable capacity (default: 100,000 records)
- **O(1) Operations**: Constant time push/pop
- **Automatic Eviction**: Oldest records overwritten when full
- **Thread-Safe**: Lock-free reads, synchronized writes
- **Memory-Mapped Option**: Persistent ring buffer via mmap

#### Implementation Variants

| Type | Use Case | Features |
|------|----------|----------|
| **RingBuffer<T>** | In-memory recent events | Basic circular buffer |
| **TimedRingBuffer<T>** | TTL-based expiration | Auto-expires old entries |
| **ShardedRingBuffer<T>** | High concurrency | Distributed across shards |
| **MmapRingBuffer** | Persistent storage | Survives daemon restart |

#### Statistics Tracked
```rust
struct RingBufferStats {
    capacity: usize,
    current_size: usize,
    total_added: u64,
    total_evicted: u64,
    utilization: f64,  // 0.0 to 1.0
}
```

### 5.3 Bloom Filters

#### Purpose
- Fast probabilistic membership testing
- "Have we seen this IP before?"
- Space-efficient alternative to hash sets

#### Implementations

**Standard Bloom Filter**
```
- Configurable false positive rate
- Optimal hash function count auto-calculated
- Save/load persistence support

Formula: m = -n * ln(p) / (ln(2)^2)
  where: m = bits, n = items, p = false positive rate
```

**Counting Bloom Filter**
```
- 4-bit counters instead of single bits
- Supports deletion operations
- Higher memory usage (4x standard)
```

**Scalable Bloom Filter**
```
- Grows automatically as items added
- Maintains target false positive rate
- Multiple filter slices with tightening FP rates
```

#### Configuration
```toml
[storage]
bloom_fp_rate = 0.01          # 1% false positive rate
expected_unique_ips = 1000000 # Size the filter appropriately
```

### 5.4 Sharded Storage

#### Purpose
- Distribute writes across multiple files
- Reduce lock contention
- Enable parallel I/O

#### Sharding Strategy
```rust
// IP-based sharding for locality
fn shard_for_ip(ip: IpAddr) -> usize {
    hash(ip) % shard_count
}

// Round-robin for even distribution
fn shard_round_robin() -> usize {
    counter.fetch_add(1) % shard_count
}
```

#### Configuration
```toml
[storage]
shard_count = 16              # Number of shards
buffer_size = 65536           # Per-shard buffer (64KB)
```

### 5.5 Write-Ahead Log (WAL)

#### Purpose
- Durability guarantee before main storage write
- Crash recovery support
- Transaction-like semantics

#### Features
- Sequential append-only writes
- CRC32 checksums per entry
- Automatic file rotation
- Checkpoint markers for recovery

#### Entry Types
```rust
pub enum EntryType {
    Connection = 1,    // Connection record
    IpTracking = 2,    // IP tracking update
    Block = 3,         // Block event
    Unblock = 4,       // Unblock event
    Checkpoint = 5,    // Recovery marker
    TxBegin = 6,       // Transaction start
    TxCommit = 7,      // Transaction commit
    TxRollback = 8,    // Transaction rollback
}
```

### 5.6 Binary Format

#### Record Header (16 bytes)
```
┌─────────────┬─────────────┬─────────────┬─────────────┐
│ record_type │   flags     │  reserved   │ payload_len │
│   (1 byte)  │  (1 byte)   │  (2 bytes)  │  (4 bytes)  │
├─────────────┴─────────────┴─────────────┴─────────────┤
│                    checksum (4 bytes)                  │
├───────────────────────────────────────────────────────┤
│                    timestamp (4 bytes)                 │
└───────────────────────────────────────────────────────┘
```

#### Compact IP Encoding
```
IPv4: 1 byte (version) + 4 bytes (address) = 5 bytes
IPv6: 1 byte (version) + 16 bytes (address) = 17 bytes
```

#### Variable-Length Integer (Varint)
```
- 7 bits per byte, MSB indicates continuation
- Efficient for small numbers
- Up to 10 bytes for 64-bit values
```

---

## 6. IP and MAC Address Tracking

### 6.1 IP Tracking Entry

```rust
struct IpTrackingEntry {
    ip: IpAddr,
    mac: Option<MacAddress>,
    geo: Option<GeoLocation>,
    threat_level: ThreatLevel,
    threat_score: f64,           // 0.0 - 1.0
    attack_types: Vec<AttackType>,
    first_seen: DateTime<Utc>,
    last_seen: DateTime<Utc>,
    stats: IpStatistics,
    is_blocked: bool,
    block_expires: Option<DateTime<Utc>>,
    block_count: u32,            // Times blocked
    is_whitelisted: bool,
    notes: Option<String>,
}
```

### 6.2 Per-IP Statistics

```rust
struct IpStatistics {
    request_count: u64,
    bytes_total: u64,
    syn_count: u64,
    unique_ports: u32,
    failed_connections: u64,
    avg_packet_size: f64,
    packets_per_second: f64,
    bytes_per_second: f64,
    window_start: DateTime<Utc>,
    window_duration_secs: u64,
}
```

### 6.3 MAC Address Tracking

#### Capabilities
- Link MAC to IP addresses (ARP correlation)
- Detect virtual/hypervisor MACs by OUI
- Track MAC spoofing attempts
- Identify device types

#### Virtual MAC Detection
```rust
// Known virtual MAC OUIs
VMware:     00:0C:29, 00:50:56
Parallels:  00:1C:42
Xen:        00:16:3E
VirtualBox: 08:00:27
QEMU/KVM:   52:54:00
Hyper-V:    00:15:5D
```

### 6.4 Connection Statistics

```rust
struct IpConnectionStats {
    total_connections: u64,
    active_connections: u64,
    half_open_connections: u64,  // Potential SYN flood
    failed_connections: u64,      // RST received
    syn_packets: u64,
    unique_destinations: u64,
    unique_ports: u64,
}
```

---

## 7. Geographic Source Detection

### 7.1 GeoIP Capabilities

| Feature | Description |
|---------|-------------|
| **Country Detection** | ISO 3166-1 alpha-2 codes |
| **City/Region** | Sub-country location |
| **Coordinates** | Latitude/longitude |
| **ASN Lookup** | Autonomous System Number |
| **Organization** | ISP/hosting provider |

### 7.2 Geographic Data Structure

```rust
struct GeoLocation {
    country_code: String,    // "US", "CN", etc.
    country_name: String,    // "United States"
    region: Option<String>,  // State/province
    city: Option<String>,
    latitude: Option<f64>,
    longitude: Option<f64>,
    asn: Option<u32>,        // AS number
    org: Option<String>,     // Organization name
}
```

### 7.3 Geographic Filtering

#### Country Blocking
```toml
[geoip]
# Block specific countries
blocked_countries = ["CN", "RU", "KP"]

# Or allow only specific countries
allowed_countries = ["US", "CA", "GB"]

# Flag for extra scrutiny
suspicious_regions = ["XX"]
```

### 7.4 GeoIP Database

- **Format**: MaxMind GeoLite2 (MMDB)
- **Auto-Update**: Optional with license key
- **Caching**: LRU cache for frequent lookups
- **Fallback**: Graceful degradation if unavailable

---

## 8. Firewall Integration

### 8.1 Supported Backends

| Backend | Description | Use Case |
|---------|-------------|----------|
| **iptables** | Legacy Linux firewall | Compatibility |
| **nftables** | Modern Linux firewall | Performance |
| **ipset** | IP set management | Large blocklists |

### 8.2 Firewall Operations

```rust
// Automatic operations
- Create dedicated chain (ZEROED)
- Add/remove block rules
- Manage ipset for efficiency
- Handle IPv4 and IPv6

// Rule management
- Maximum rules limit
- Automatic cleanup of expired blocks
- Dry-run mode for testing
```

### 8.3 Chain Structure

```
iptables -N ZEROED
iptables -I INPUT -j ZEROED
iptables -I FORWARD -j ZEROED

# In ZEROED chain:
-A ZEROED -m set --match-set zeroed_blocklist src -j DROP
```

### 8.4 IPSet Integration

```bash
# Create ipset for blocked IPs
ipset create zeroed_blocklist hash:ip timeout 3600

# Add blocked IP
ipset add zeroed_blocklist 192.168.1.100 timeout 3600

# Remove IP
ipset del zeroed_blocklist 192.168.1.100
```

### 8.5 Configuration

```toml
[firewall]
enabled = true
backend = "iptables"      # or "nftables"
chain_name = "ZEROED"
table_name = "filter"
ipset_name = "zeroed_blocklist"
use_ipset = true          # Recommended for large lists
max_rules = 10000
dry_run = false           # Set true for testing
```

---

## 9. Rate Limiting Algorithms

### 9.1 Token Bucket

```
Algorithm:
1. Bucket starts full (burst_size tokens)
2. Each request consumes 1 token
3. Tokens refill at rate tokens/second
4. Request denied if no tokens available

Properties:
- Allows bursts up to bucket size
- Smooth average rate limiting
- Memory: O(1) per tracked entity
```

### 9.2 Sliding Window

```
Algorithm:
1. Maintain queue of request timestamps
2. Remove timestamps older than window
3. Count remaining = current request count
4. Deny if count >= max_requests

Properties:
- Accurate rate measurement
- No burst allowance
- Memory: O(n) where n = max_requests
```

### 9.3 Leaky Bucket

```
Algorithm:
1. Bucket fills with incoming traffic
2. Bucket drains at constant rate
3. Overflow = rate exceeded

Properties:
- Traffic shaping (smoothing)
- Constant output rate
- Memory: O(1) per tracked entity
```

### 9.4 Per-IP Rate Limiter

```rust
struct RateLimiter {
    alert_threshold: f64,    // Warning level
    block_threshold: f64,    // Block level
    window: Duration,        // Measurement window
    ip_windows: DashMap<IpAddr, SlidingWindowLimiter>,
}

enum RateLimitResult {
    Allow { rate: f64 },
    Alert { rate: f64 },     // Elevated but allowed
    Block { rate: f64 },     // Blocked
}
```

---

## 10. API and Control Interface

### 10.1 Unix Socket API

#### Connection
```bash
# Socket path (configurable)
/var/run/zeroed/zeroed.sock
```

#### Protocol
- JSON-based request/response
- Newline-delimited messages
- Synchronous request-response pattern

### 10.2 Available Commands

| Command | Description | Parameters |
|---------|-------------|------------|
| `Status` | Daemon status | - |
| `Stats` | Traffic statistics | `detailed: bool` |
| `ListBlocked` | List blocked IPs | `limit: usize` |
| `ListTracked` | List tracked IPs | `limit, sort` |
| `ListWhitelist` | Show whitelist | - |
| `ListBlacklist` | Show blacklist | - |
| `Block` | Block an IP | `ip, duration, reason` |
| `Unblock` | Unblock an IP | `ip` |
| `WhitelistAdd` | Add to whitelist | `ip, comment` |
| `WhitelistRemove` | Remove from whitelist | `ip` |
| `BlacklistAdd` | Add to blacklist | `ip, comment` |
| `BlacklistRemove` | Remove from blacklist | `ip` |
| `Events` | Recent events | `count, filter` |
| `Lookup` | IP information | `ip` |
| `FlushBlocked` | Clear all blocks | - |
| `FlushTracking` | Clear tracking data | - |
| `FlushCache` | Clear caches | - |
| `Reload` | Reload configuration | - |
| `Shutdown` | Stop daemon | `force: bool` |
| `Ping` | Health check | - |

### 10.3 Response Format

```json
// Success
{
  "status": "Success",
  "data": { ... }
}

// Error
{
  "status": "Error",
  "code": 400,
  "message": "Invalid request"
}
```

### 10.4 CLI Tool (zeroctl)

```bash
# Status
zeroctl status

# Statistics
zeroctl stats --detailed

# List operations
zeroctl list blocked --limit 50
zeroctl list tracked --sort requests
zeroctl list whitelist
zeroctl list blacklist
zeroctl list interfaces
zeroctl list rules

# Block/unblock
zeroctl block 192.168.1.100 --duration 3600 --reason "Manual block"
zeroctl unblock 192.168.1.100

# Whitelist management
zeroctl whitelist-add 10.0.0.0/8 --comment "Internal network"
zeroctl whitelist-remove 10.0.0.0/8

# Events and lookup
zeroctl events --count 50 --filter attack
zeroctl lookup 192.168.1.100

# Maintenance
zeroctl flush blocked
zeroctl reload
zeroctl shutdown

# Export/Import
zeroctl export blocked --output blocked.json
zeroctl import whitelist whitelist.txt
```

### 10.5 HTTP REST API (Optional)

```yaml
Endpoints:
  GET  /api/v1/status
  GET  /api/v1/stats
  GET  /api/v1/blocked
  POST /api/v1/blocked         # Block IP
  DELETE /api/v1/blocked/{ip}  # Unblock IP
  GET  /api/v1/tracked
  GET  /api/v1/tracked/{ip}
  GET  /api/v1/whitelist
  POST /api/v1/whitelist
  DELETE /api/v1/whitelist/{ip}
  GET  /api/v1/blacklist
  POST /api/v1/blacklist
  DELETE /api/v1/blacklist/{ip}
  GET  /api/v1/events
  POST /api/v1/reload
  POST /api/v1/shutdown
```

---

## 11. Metrics and Monitoring

### 11.1 Prometheus Metrics

#### Packet Metrics
```prometheus
# Total packets captured
zeroed_packets_total{interface="eth0"} 1234567

# Packets dropped by kernel
zeroed_packets_dropped{interface="eth0"} 123

# Total bytes captured
zeroed_bytes_total{interface="eth0"} 987654321

# Packets by protocol
zeroed_packets_by_protocol{protocol="tcp"} 800000
zeroed_packets_by_protocol{protocol="udp"} 300000
zeroed_packets_by_protocol{protocol="icmp"} 50000
```

#### Detection Metrics
```prometheus
# Blocked IPs
zeroed_blocked_ips_total 150
zeroed_blocked_ips_current 45

# Attacks detected by type
zeroed_attacks_
