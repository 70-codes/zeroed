# Zeroed Architecture Documentation

## Table of Contents

1. [Overview](#overview)
2. [System Design Principles](#system-design-principles)
3. [Core Architecture](#core-architecture)
4. [Module Architecture](#module-architecture)
5. [Data Flow](#data-flow)
6. [Concurrency Model](#concurrency-model)
7. [Memory Management](#memory-management)
8. [Storage Architecture](#storage-architecture)
9. [Detection Pipeline](#detection-pipeline)
10. [Integration Points](#integration-points)
11. [Security Architecture](#security-architecture)
12. [Scalability Considerations](#scalability-considerations)

---

## Overview

Zeroed is a high-performance DoS/DDoS protection daemon designed for Linux systems. The architecture prioritizes:

- **Low Latency**: Sub-millisecond packet processing
- **High Throughput**: 100k+ packets/second per core
- **Memory Efficiency**: Minimal memory footprint per tracked entity
- **Reliability**: Crash recovery and data durability
- **Modularity**: Loosely coupled components for maintainability

### Technology Stack

| Component      | Technology           | Purpose                      |
| -------------- | -------------------- | ---------------------------- |
| Language       | Rust 1.70+           | Memory safety, performance   |
| Packet Capture | libpcap/pnet         | Network packet capture       |
| Storage        | Custom binary format | High-performance persistence |
| IPC            | Unix domain sockets  | Local control interface      |
| Firewall       | iptables/nftables    | Traffic blocking             |
| Metrics        | Prometheus           | Monitoring and alerting      |

---

## System Design Principles

### 1. Zero-Copy Where Possible

The system minimizes data copying through:

- Memory-mapped file I/O
- Ring buffers with in-place operations
- Direct packet buffer access

### 2. Lock-Free Data Structures

Critical paths use lock-free algorithms:

- Atomic counters for statistics
- Lock-free ring buffers for event queues
- Read-copy-update (RCU) for configuration

### 3. Bounded Memory Usage

All data structures have configurable bounds:

- Fixed-size ring buffers
- Bloom filters with predictable memory
- LRU eviction for tracking entries

### 4. Fail-Safe Defaults

The system fails safely:

- Unknown packets are allowed (not blocked)
- Firewall rule failures are logged but don't crash
- Storage failures degrade gracefully

---

## Core Architecture

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                              Zeroed Daemon                                   │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                             │
│  ┌─────────────────────────────────────────────────────────────────────┐   │
│  │                         Main Event Loop                              │   │
│  │  ┌──────────┐  ┌──────────┐  ┌──────────┐  ┌──────────┐            │   │
│  │  │  Packet  │  │  Timer   │  │  Signal  │  │   API    │            │   │
│  │  │  Events  │  │  Events  │  │  Events  │  │  Events  │            │   │
│  │  └────┬─────┘  └────┬─────┘  └────┬─────┘  └────┬─────┘            │   │
│  │       │              │              │              │                 │   │
│  │       └──────────────┴──────────────┴──────────────┘                 │   │
│  │                              │                                        │   │
│  └──────────────────────────────┼────────────────────────────────────────┘   │
│                                 ▼                                            │
│  ┌─────────────────────────────────────────────────────────────────────┐   │
│  │                        Event Dispatcher                              │   │
│  └─────────────────────────────────────────────────────────────────────┘   │
│           │                    │                    │                        │
│           ▼                    ▼                    ▼                        │
│  ┌─────────────────┐  ┌─────────────────┐  ┌─────────────────┐             │
│  │    Network      │  │   Detection     │  │    Response     │             │
│  │    Module       │  │    Module       │  │    Module       │             │
│  └────────┬────────┘  └────────┬────────┘  └────────┬────────┘             │
│           │                    │                    │                        │
│           ▼                    ▼                    ▼                        │
│  ┌─────────────────────────────────────────────────────────────────────┐   │
│  │                        Storage Engine                                │   │
│  └─────────────────────────────────────────────────────────────────────┘   │
│                                                                             │
└─────────────────────────────────────────────────────────────────────────────┘
```

### Component Responsibilities

| Component        | Responsibility                        |
| ---------------- | ------------------------------------- |
| Main Event Loop  | Multiplexes all event sources         |
| Event Dispatcher | Routes events to appropriate handlers |
| Network Module   | Captures and parses packets           |
| Detection Module | Analyzes traffic patterns             |
| Response Module  | Manages firewall rules                |
| Storage Engine   | Persists data efficiently             |

---

## Module Architecture

### Source Code Organization

```
src/
├── main.rs              # Entry point and CLI
├── bin/
│   └── zeroctl.rs       # Control utility binary
├── core/
│   ├── mod.rs           # Core module exports
│   ├── config.rs        # Configuration management
│   ├── error.rs         # Error types and handling
│   └── types.rs         # Common type definitions
├── daemon/
│   └── mod.rs           # Daemon lifecycle management
├── network/
│   ├── mod.rs           # Network module exports
│   ├── capture.rs       # Packet capture engine
│   ├── connection.rs    # TCP connection tracking
│   ├── interface.rs     # Network interface management
│   ├── packet.rs        # Packet representation
│   └── parser.rs        # Protocol parsing
├── detection/
│   ├── mod.rs           # Detection module exports
│   ├── analyzer.rs      # Traffic analyzer
│   ├── rate_limiter.rs  # Rate limiting algorithms
│   ├── rules.rs         # Detection rules engine
│   └── threshold.rs     # Adaptive thresholds
├── storage/
│   ├── mod.rs           # Storage module exports
│   ├── archive.rs       # Historical data archival
│   ├── binary.rs        # Binary serialization
│   ├── bloom.rs         # Bloom filter implementation
│   ├── index.rs         # Data indexing
│   ├── mmap.rs          # Memory-mapped files
│   ├── mmap_ring.rs     # Memory-mapped ring buffer
│   ├── ring.rs          # Generic ring buffer
│   ├── ring_buffer.rs   # Specialized ring buffer
│   ├── shard.rs         # Sharded storage
│   └── wal.rs           # Write-ahead logging
├── geo/
│   └── mod.rs           # Geographic IP lookup
└── api/
    └── mod.rs           # Control API server
```

### Module Dependencies

```
┌─────────┐
│  core   │ ◄──── All modules depend on core
└────┬────┘
     │
     ├───────────────────────────────────┐
     │                                   │
     ▼                                   ▼
┌─────────┐                        ┌─────────┐
│ network │ ──────────────────────▶│detection│
└────┬────┘                        └────┬────┘
     │                                  │
     │         ┌─────────┐              │
     └────────▶│ storage │◄─────────────┘
               └────┬────┘
                    │
                    ▼
               ┌─────────┐
               │   geo   │
               └─────────┘
```

### Interface Contracts

Each module exposes a trait-based interface for loose coupling:

```rust
// Network capture interface
pub trait PacketCapture {
    fn start(&mut self) -> Result<(), CaptureError>;
    fn stop(&mut self) -> Result<(), CaptureError>;
    fn next_packet(&mut self) -> Option<Packet>;
}

// Detection interface
pub trait Detector {
    fn analyze(&mut self, packet: &Packet) -> DetectionResult;
    fn get_threats(&self) -> Vec<ThreatInfo>;
}

// Storage interface
pub trait Storage {
    fn write(&mut self, record: &Record) -> Result<(), StorageError>;
    fn read(&self, key: &Key) -> Option<Record>;
    fn flush(&mut self) -> Result<(), StorageError>;
}

// Firewall interface
pub trait Firewall {
    fn block_ip(&mut self, ip: IpAddr, duration: Duration) -> Result<(), FirewallError>;
    fn unblock_ip(&mut self, ip: IpAddr) -> Result<(), FirewallError>;
    fn list_blocked(&self) -> Vec<BlockedIp>;
}
```

---

## Data Flow

### Packet Processing Pipeline

```
                            ┌─────────────────────────────────────────────┐
                            │             PACKET PROCESSING PIPELINE       │
                            └─────────────────────────────────────────────┘

┌──────────┐    ┌──────────┐    ┌──────────┐    ┌──────────┐    ┌──────────┐
│  NIC     │───▶│ libpcap  │───▶│  Parser  │───▶│ Tracker  │───▶│ Analyzer │
│          │    │ Buffer   │    │          │    │          │    │          │
└──────────┘    └──────────┘    └──────────┘    └──────────┘    └──────────┘
                                     │              │               │
                                     ▼              ▼               ▼
                               ┌──────────┐   ┌──────────┐    ┌──────────┐
                               │  Bloom   │   │   IP     │    │  Rules   │
                               │  Filter  │   │ Tracking │    │  Engine  │
                               └──────────┘   └──────────┘    └──────────┘
                                                                    │
                                                                    ▼
                                     ┌──────────────────────────────────────┐
                                     │          RESPONSE ACTIONS            │
                                     ├──────────┬──────────┬───────────────┤
                                     │   Log    │  Alert   │     Block     │
                                     └──────────┴──────────┴───────────────┘
```

### Detailed Processing Steps

1. **Packet Capture** (Network Layer)
   - libpcap captures raw packets from NIC
   - BPF filter pre-filters at kernel level
   - Packets queued in capture buffer

2. **Packet Parsing** (Parser Module)
   - Extract Ethernet header (MAC addresses)
   - Parse IP header (source/dest IP, protocol)
   - Parse transport header (TCP/UDP/ICMP)
   - Classify packet type

3. **Tracking Update** (Tracker Module)
   - Update Bloom filter (fast seen-before check)
   - Update IP tracking entry
   - Update connection state (TCP)
   - Update statistics counters

4. **Analysis** (Analyzer Module)
   - Apply rate limiting algorithms
   - Check detection rules
   - Calculate threat scores
   - Determine required action

5. **Response** (Response Module)
   - Log event details
   - Send alerts if threshold exceeded
   - Block IP via firewall if needed
   - Update metrics

### Event Types and Flow

```rust
pub enum Event {
    // Network events
    PacketReceived(Packet),
    ConnectionOpened(Connection),
    ConnectionClosed(Connection),

    // Detection events
    ThresholdExceeded(IpAddr, ThresholdType),
    AttackDetected(AttackInfo),
    ThreatScoreChanged(IpAddr, u32),

    // Response events
    IpBlocked(IpAddr, Duration),
    IpUnblocked(IpAddr),
    RuleTriggered(RuleId, IpAddr),

    // System events
    ConfigReloaded,
    StorageFlushed,
    MetricsUpdated,
}
```

---

## Concurrency Model

### Thread Architecture

```
┌─────────────────────────────────────────────────────────────────────────┐
│                           THREAD ARCHITECTURE                            │
├─────────────────────────────────────────────────────────────────────────┤
│                                                                         │
│  ┌─────────────────┐                                                    │
│  │   Main Thread   │ ◄─── Signal handling, coordination                 │
│  └────────┬────────┘                                                    │
│           │                                                             │
│           │  spawns                                                     │
│           │                                                             │
│  ┌────────┴────────┬─────────────────┬─────────────────┐               │
│  │                 │                 │                 │               │
│  ▼                 ▼                 ▼                 ▼               │
│ ┌─────────┐   ┌─────────┐   ┌─────────┐   ┌─────────┐                 │
│ │Capture  │   │Capture  │   │Analysis │   │  API    │                 │
│ │Thread 0 │   │Thread N │   │ Thread  │   │ Thread  │                 │
│ │(eth0)   │   │(ethN)   │   │         │   │         │                 │
│ └────┬────┘   └────┬────┘   └────┬────┘   └────┬────┘                 │
│      │             │             │             │                        │
│      └─────────────┴─────────────┘             │                        │
│                    │                           │                        │
│                    ▼                           │                        │
│            ┌───────────────┐                   │                        │
│            │ Packet Queue  │◄──────────────────┘                        │
│            │ (MPSC Channel)│                                            │
│            └───────┬───────┘                                            │
│                    │                                                    │
│                    ▼                                                    │
│            ┌───────────────┐                                            │
│            │Storage Writer │                                            │
│            │   Threads     │                                            │
│            └───────────────┘                                            │
│                                                                         │
└─────────────────────────────────────────────────────────────────────────┘
```

### Thread Responsibilities

| Thread         | Count           | Responsibility                                |
| -------------- | --------------- | --------------------------------------------- |
| Main           | 1               | Initialization, signal handling, coordination |
| Capture        | 1 per interface | Packet capture from NIC                       |
| Analysis       | Configurable    | Packet analysis and detection                 |
| Storage Writer | 1 per shard     | Persisting data to disk                       |
| API            | 1               | Handling control commands                     |
| Timer          | 1               | Periodic tasks (cleanup, flush)               |

### Synchronization Primitives

```rust
// Inter-thread communication
use std::sync::mpsc::{Sender, Receiver};      // Message passing
use crossbeam::channel::{bounded, unbounded}; // High-perf channels

// Shared state
use std::sync::atomic::{AtomicU64, AtomicBool}; // Lock-free counters
use std::sync::{Arc, RwLock};                   // Shared ownership
use parking_lot::Mutex;                         // Fast mutex

// Coordination
use std::sync::Barrier;                         // Thread synchronization
use tokio::sync::Notify;                        // Async notification
```

### Channel Architecture

```
┌──────────────┐     packet_tx     ┌──────────────┐
│   Capture    │ ─────────────────▶│   Analysis   │
│   Thread     │                   │   Thread     │
└──────────────┘                   └──────┬───────┘
                                          │
                                   event_tx│
                                          ▼
┌──────────────┐     cmd_tx       ┌──────────────┐
│     API      │ ─────────────────▶│    Main     │
│   Thread     │ ◄─────────────────│   Thread    │
└──────────────┘     resp_rx      └──────────────┘
```

---

## Memory Management

### Memory Layout

```
┌─────────────────────────────────────────────────────────────────────────┐
│                           MEMORY LAYOUT                                  │
├─────────────────────────────────────────────────────────────────────────┤
│                                                                         │
│  STACK (per thread)                                                     │
│  ├── Local variables                                                    │
│  └── Function call frames                                               │
│                                                                         │
│  HEAP                                                                   │
│  ├── Configuration (Arc<Config>)           ~4 KB                        │
│  ├── IP Tracking HashMap                   ~100 bytes per IP            │
│  ├── Connection Tracking                   ~200 bytes per connection    │
│  ├── Rate Limiter Windows                  ~64 bytes per IP             │
│  └── Detection Rules                       ~1 KB per rule               │
│                                                                         │
│  MEMORY-MAPPED REGIONS                                                  │
│  ├── Ring Buffer (configurable)            Default: 10 MB               │
│  ├── Bloom Filter                          ~1.2 MB per 1M IPs           │
│  ├── WAL Segment                           ~16 MB per segment           │
│  └── Archive Files                         Variable                     │
│                                                                         │
└─────────────────────────────────────────────────────────────────────────┘
```

### Memory Budget Calculation

```rust
fn calculate_memory_budget(config: &Config) -> MemoryBudget {
    let ip_tracking = config.expected_ips * 100;  // ~100 bytes/IP
    let connections = config.max_connections * 200; // ~200 bytes/conn
    let ring_buffer = config.ring_buffer_size * std::mem::size_of::<Event>();
    let bloom_filter = bloom_filter_size(config.expected_ips, config.fp_rate);

    MemoryBudget {
        ip_tracking,
        connections,
        ring_buffer,
        bloom_filter,
        total: ip_tracking + connections + ring_buffer + bloom_filter,
    }
}
```

### Memory Limits and Eviction

When memory limits are reached:

1. **Ring Buffer**: Oldest entries overwritten (circular)
2. **IP Tracking**: LRU eviction of inactive IPs
3. **Connections**: Timeout-based cleanup
4. **Bloom Filter**: Rebuild with fresh filter (periodic)

---

## Storage Architecture

### Storage Layer Hierarchy

```
┌─────────────────────────────────────────────────────────────────────────┐
│                         STORAGE ARCHITECTURE                             │
├─────────────────────────────────────────────────────────────────────────┤
│                                                                         │
│  HOT DATA (In-Memory)                                                   │
│  ┌─────────────────────────────────────────────────────────────────┐   │
│  │  Ring Buffer         Bloom Filter          Active Tracking      │   │
│  │  [Recent Events]     [Seen IPs]            [Current Stats]      │   │
│  └─────────────────────────────────────────────────────────────────┘   │
│                              │                                          │
│                              ▼ flush                                    │
│  WARM DATA (Memory-Mapped)                                              │
│  ┌─────────────────────────────────────────────────────────────────┐   │
│  │  WAL Segments         Index Files           State Snapshots     │   │
│  │  [Pending Writes]     [Fast Lookup]         [Checkpoints]       │   │
│  └─────────────────────────────────────────────────────────────────┘   │
│                              │                                          │
│                              ▼ archive                                  │
│  COLD DATA (Disk Files)                                                 │
│  ┌─────────────────────────────────────────────────────────────────┐   │
│  │  Sharded Archives     Compressed Logs       Historical Stats    │   │
│  │  [Per-hour files]     [Rotated logs]        [Aggregated data]   │   │
│  └─────────────────────────────────────────────────────────────────┘   │
│                                                                         │
└─────────────────────────────────────────────────────────────────────────┘
```

### File System Layout

```
/var/lib/zeroed/
├── data/
│   ├── ring/
│   │   └── current.bin         # Active ring buffer (mmap)
│   ├── bloom/
│   │   ├── ip_seen.bin         # IP bloom filter
│   │   └── mac_seen.bin        # MAC bloom filter
│   ├── state/
│   │   ├── tracking.bin        # IP tracking state
│   │   └── connections.bin     # Connection state
│   ├── index/
│   │   └── ip_index.bin        # IP lookup index
│   ├── wal/
│   │   ├── wal_000001.bin      # WAL segment 1
│   │   └── wal_000002.bin      # WAL segment 2
│   ├── shard/
│   │   ├── shard_00.bin        # Shard 0
│   │   ├── shard_01.bin        # Shard 1
│   │   └── ...
│   └── archive/
│       └── 2024/
│           └── 01/
│               └── 15/
│                   ├── hour_00.zbin
│                   └── hour_01.zbin
├── GeoLite2-City.mmdb          # GeoIP database
└── config.toml                 # Runtime config copy
```

### Write-Ahead Log (WAL)

The WAL ensures durability and crash recovery:

```
┌─────────────────────────────────────────────────────────────────────────┐
│                        WAL ENTRY FORMAT                                  │
├─────────────────────────────────────────────────────────────────────────┤
│                                                                         │
│  ┌────────┬────────┬────────┬────────┬─────────────────┬────────────┐  │
│  │ Magic  │  Len   │ CRC32  │  Type  │     Payload     │   Padding  │  │
│  │ (4B)   │  (4B)  │  (4B)  │  (1B)  │   (variable)    │  (0-7B)    │  │
│  └────────┴────────┴────────┴────────┴─────────────────┴────────────┘  │
│                                                                         │
│  Entry Types:                                                           │
│  0x01 = Connection event                                                │
│  0x02 = IP tracking update                                              │
│  0x03 = Block action                                                    │
│  0x04 = Unblock action                                                  │
│  0x10 = Checkpoint                                                      │
│  0x20 = Transaction begin                                               │
│  0x21 = Transaction commit                                              │
│  0x22 = Transaction rollback                                            │
│                                                                         │
└─────────────────────────────────────────────────────────────────────────┘
```

### Sharding Strategy

Data is distributed across shards for parallel writes:

```rust
impl ShardStrategy {
    /// Hash-based sharding for even distribution
    fn shard_by_ip(ip: IpAddr, shard_count: usize) -> usize {
        let hash = hash_ip(ip);
        hash as usize % shard_count
    }

    /// Round-robin for sequential data
    fn shard_round_robin(counter: &AtomicU64, shard_count: usize) -> usize {
        counter.fetch_add(1, Ordering::Relaxed) as usize % shard_count
    }

    /// Time-based for temporal locality
    fn shard_by_time(timestamp: u64, shard_count: usize) -> usize {
        (timestamp / 3600) as usize % shard_count // Hour-based
    }
}
```

---

## Detection Pipeline

### Detection Algorithm Flow

```
┌─────────────────────────────────────────────────────────────────────────┐
│                       DETECTION ALGORITHM FLOW                           │
├─────────────────────────────────────────────────────────────────────────┤
│                                                                         │
│  Input: Parsed Packet                                                   │
│           │                                                             │
│           ▼                                                             │
│  ┌─────────────────┐                                                    │
│  │ 1. Whitelist    │──── Is IP whitelisted? ────▶ ALLOW                │
│  │    Check        │                                                    │
│  └────────┬────────┘                                                    │
│           │ No                                                          │
│           ▼                                                             │
│  ┌─────────────────┐                                                    │
│  │ 2. Blacklist    │──── Is IP blacklisted? ────▶ BLOCK                │
│  │    Check        │                                                    │
│  └────────┬────────┘                                                    │
│           │ No                                                          │
│           ▼                                                             │
│  ┌─────────────────┐                                                    │
│  │ 3. Rate Limit   │──── Exceeds block threshold? ──▶ BLOCK            │
│  │    Check        │                                                    │
│  │                 │──── Exceeds alert threshold? ──▶ ALERT            │
│  └────────┬────────┘                                                    │
│           │ Pass                                                        │
│           ▼                                                             │
│  ┌─────────────────┐                                                    │
│  │ 4. Pattern      │──── Matches attack pattern? ──▶ BLOCK/ALERT       │
│  │    Matching     │                                                    │
│  └────────┬────────┘                                                    │
│           │ No match                                                    │
│           ▼                                                             │
│  ┌─────────────────┐                                                    │
│  │ 5. Threat Score │──── Score > critical? ────▶ BLOCK                 │
│  │    Evaluation   │──── Score > high? ────▶ ALERT                     │
│  └────────┬────────┘                                                    │
│           │ Low score                                                   │
│           ▼                                                             │
│        ALLOW                                                            │
│                                                                         │
└─────────────────────────────────────────────────────────────────────────┘
```

### Rate Limiting Algorithms

#### Token Bucket

```rust
struct TokenBucket {
    capacity: u64,      // Maximum tokens
    tokens: AtomicU64,  // Current tokens
    refill_rate: u64,   // Tokens per second
    last_refill: AtomicU64,
}

impl TokenBucket {
    fn allow(&self) -> bool {
        self.refill();
        self.tokens.fetch_sub(1, Ordering::Relaxed) > 0
    }
}
```

#### Sliding Window

```rust
struct SlidingWindow {
    window_size: Duration,
    buckets: Vec<AtomicU64>,  // Time-sliced counters
    bucket_duration: Duration,
}

impl SlidingWindow {
    fn count(&self) -> u64 {
        let now = current_bucket();
        self.buckets.iter()
            .skip(now.saturating_sub(self.buckets.len()))
            .take(self.window_buckets())
            .map(|b| b.load(Ordering::Relaxed))
            .sum()
    }
}
```

### Threat Score Calculation

```rust
fn calculate_threat_score(ip: &IpTrackingEntry) -> u32 {
    let mut score: u32 = 0;

    // Rate-based scoring
    if ip.stats.packets_per_second > 100 { score += 10; }
    if ip.stats.packets_per
_second > 500 { score += 20; }
    if ip.stats.packets_per_second > 1000 { score += 40; }

    // Connection-based scoring
    if ip.stats.half_open_connections > 50 { score += 15; }
    if ip.stats.failed_connections > 100 { score += 25; }

    // Pattern-based scoring
    if ip.has_syn_flood_pattern() { score += 30; }
    if ip.has_slowloris_pattern() { score += 25; }

    // Historical scoring
    score += ip.block_count * 10;  // Previous blocks

    // Geographic scoring
    if ip.geo.is_suspicious_region() { score += 5; }

    score.min(100)  // Cap at 100
}
```

---

## Integration Points

### Firewall Integration

```
┌─────────────────────────────────────────────────────────────────────────┐
│                      FIREWALL INTEGRATION                                │
├─────────────────────────────────────────────────────────────────────────┤
│                                                                         │
│  Zeroed Daemon                                                          │
│       │                                                                 │
│       ├──── iptables backend ────▶ iptables -A ZEROED -s IP -j DROP    │
│       │                                                                 │
│       ├──── nftables backend ────▶ nft add rule ip zeroed drop         │
│       │                                                                 │
│       └──── ipset backend ───────▶ ipset add zeroed_blocklist IP       │
│                                                                         │
│  Rule Chain Structure:                                                  │
│                                                                         │
│  INPUT ──▶ ZEROED (custom chain) ──▶ ACCEPT/DROP                       │
│                                                                         │
└─────────────────────────────────────────────────────────────────────────┘
```

### Metrics Export

```
┌─────────────────────────────────────────────────────────────────────────┐
│                      METRICS INTEGRATION                                 │
├─────────────────────────────────────────────────────────────────────────┤
│                                                                         │
│  Zeroed ────▶ Prometheus Exporter (:9090) ────▶ Prometheus Server       │
│     │                                                │                  │
│     │                                                ▼                  │
│     │                                          ┌──────────┐            │
│     │                                          │ Grafana  │            │
│     │                                          └──────────┘            │
│     │                                                                   │
│     └────▶ Internal Stats ────▶ zeroctl stats                          │
│                                                                         │
│  Metric Types:                                                          │
│  • Counters: packets_total, blocks_total, attacks_detected             │
│  • Gauges: blocked_ips_current, memory_bytes, queue_size               │
│  • Histograms: detection_latency, packet_size_distribution             │
│                                                                         │
└─────────────────────────────────────────────────────────────────────────┘
```

### GeoIP Integration

```
┌─────────────────────────────────────────────────────────────────────────┐
│                        GEOIP INTEGRATION                                 │
├─────────────────────────────────────────────────────────────────────────┤
│                                                                         │
│  Source IP ────▶ GeoIP Lookup ────▶ Location Data                       │
│                       │                                                 │
│                       ▼                                                 │
│              ┌─────────────────┐                                        │
│              │  MaxMind DB     │                                        │
│              │  (mmdb format)  │                                        │
│              └────────┬────────┘                                        │
│                       │                                                 │
│                       ▼                                                 │
│              ┌─────────────────┐                                        │
│              │  LRU Cache      │  ◄── Configurable size                 │
│              │  (10k entries)  │                                        │
│              └────────┬────────┘                                        │
│                       │                                                 │
│                       ▼                                                 │
│  ┌─────────────────────────────────────────────────────────────────┐   │
│  │  GeoLocation { country, region, city, lat, lon, asn, org }      │   │
│  └─────────────────────────────────────────────────────────────────┘   │
│                                                                         │
│  Use Cases:                                                             │
│  • Country-based blocking/allowing                                      │
│  • Regional threat analysis                                             │
│  • ASN-based reputation                                                 │
│                                                                         │
└─────────────────────────────────────────────────────────────────────────┘
```

### API Architecture

```
┌─────────────────────────────────────────────────────────────────────────┐
│                         API ARCHITECTURE                                 │
├─────────────────────────────────────────────────────────────────────────┤
│                                                                         │
│  ┌─────────────────────────────────────────────────────────────────┐   │
│  │                      API Server                                  │   │
│  │  ┌─────────────────┐         ┌─────────────────┐                │   │
│  │  │  Unix Socket    │         │   HTTP Server   │                │   │
│  │  │  (default)      │         │   (optional)    │                │   │
│  │  └────────┬────────┘         └────────┬────────┘                │   │
│  │           │                           │                          │   │
│  │           └───────────┬───────────────┘                          │   │
│  │                       │                                          │   │
│  │                       ▼                                          │   │
│  │           ┌─────────────────────┐                                │   │
│  │           │  Command Dispatcher │                                │   │
│  │           └──────────┬──────────┘                                │   │
│  │                      │                                           │   │
│  │    ┌─────────────────┼─────────────────┐                        │   │
│  │    │                 │                 │                        │   │
│  │    ▼                 ▼                 ▼                        │   │
│  │ ┌──────┐        ┌──────┐         ┌──────┐                      │   │
│  │ │Status│        │Block │         │Stats │                      │   │
│  │ │Cmds  │        │Cmds  │         │Cmds  │                      │   │
│  │ └──────┘        └──────┘         └──────┘                      │   │
│  └─────────────────────────────────────────────────────────────────┘   │
│                                                                         │
│  Request Flow:                                                          │
│  1. Client connects (Unix socket or HTTP)                               │
│  2. Authentication (Unix perms or token)                                │
│  3. Command parsing and validation                                      │
│  4. Dispatch to appropriate handler                                     │
│  5. Execute and return JSON response                                    │
│                                                                         │
└─────────────────────────────────────────────────────────────────────────┘
```

---

## Security Architecture

### Defense in Depth

```
┌─────────────────────────────────────────────────────────────────────────┐
│                      SECURITY ARCHITECTURE                               │
├─────────────────────────────────────────────────────────────────────────┤
│                                                                         │
│  Layer 1: Process Isolation                                             │
│  ┌─────────────────────────────────────────────────────────────────┐   │
│  │  • Non-root user (zeroed:zeroed)                                 │   │
│  │  • Linux capabilities (CAP_NET_ADMIN, CAP_NET_RAW only)         │   │
│  │  • Systemd sandboxing                                            │   │
│  └─────────────────────────────────────────────────────────────────┘   │
│                                                                         │
│  Layer 2: Memory Safety                                                 │
│  ┌─────────────────────────────────────────────────────────────────┐   │
│  │  • Rust memory safety guarantees                                 │   │
│  │  • Bounds checking on all packet parsing                         │   │
│  │  • No unsafe code in critical paths                              │   │
│  └─────────────────────────────────────────────────────────────────┘   │
│                                                                         │
│  Layer 3: Input Validation                                              │
│  ┌─────────────────────────────────────────────────────────────────┐   │
│  │  • Strict IP address validation                                  │   │
│  │  • Configuration schema validation                               │   │
│  │  • API request sanitization                                      │   │
│  └─────────────────────────────────────────────────────────────────┘   │
│                                                                         │
│  Layer 4: Access Control                                                │
│  ┌─────────────────────────────────────────────────────────────────┐   │
│  │  • Unix socket permissions (root/zeroed group only)              │   │
│  │  • HTTP API token authentication                                 │   │
│  │  • TLS encryption for remote API                                 │   │
│  └─────────────────────────────────────────────────────────────────┘   │
│                                                                         │
└─────────────────────────────────────────────────────────────────────────┘
```

### Privilege Separation

```rust
// Capability requirements by component
struct CapabilityRequirements {
    // Packet capture requires raw socket access
    capture: vec![Capability::NET_RAW, Capability::NET_ADMIN],

    // Firewall control requires admin
    firewall: vec![Capability::NET_ADMIN],

    // Storage needs only file access (no capabilities)
    storage: vec![],

    // API needs only socket access (no capabilities)
    api: vec![],
}

// Drop capabilities after initialization
fn drop_unnecessary_capabilities() {
    // Keep only what's needed for runtime operation
    caps::clear(None, CapSet::Effective).unwrap();
    caps::set(None, CapSet::Effective, &[
        Capability::NET_RAW,
        Capability::NET_ADMIN,
    ]).unwrap();
}
```

---

## Scalability Considerations

### Vertical Scaling

| Resource    | Scaling Strategy                            | Limit              |
| ----------- | ------------------------------------------- | ------------------ |
| CPU         | Add worker threads, use BPF filtering       | ~8 cores effective |
| Memory      | Increase ring buffer, bloom filter capacity | System RAM         |
| Storage I/O | Add shards, use faster storage              | Disk throughput    |
| Network I/O | Multiple interfaces, kernel bypass          | NIC capacity       |

### Horizontal Scaling

```
┌─────────────────────────────────────────────────────────────────────────┐
│                    HORIZONTAL SCALING OPTIONS                            │
├─────────────────────────────────────────────────────────────────────────┤
│                                                                         │
│  Option 1: Per-Server Deployment                                        │
│  ┌─────────────────────────────────────────────────────────────────┐   │
│  │  Each server runs its own Zeroed instance                        │   │
│  │  + Simple, no coordination needed                                │   │
│  │  - No shared blocklist                                           │   │
│  └─────────────────────────────────────────────────────────────────┘   │
│                                                                         │
│  Option 2: Centralized with Agents                                      │
│  ┌─────────────────────────────────────────────────────────────────┐   │
│  │  Central Zeroed + lightweight agents on each server              │   │
│  │  + Shared intelligence                                           │   │
│  │  + Coordinated response                                          │   │
│  │  - Single point of failure                                       │   │
│  └─────────────────────────────────────────────────────────────────┘   │
│                                                                         │
│  Option 3: Distributed Mesh                                             │
│  ┌─────────────────────────────────────────────────────────────────┐   │
│  │  Zeroed instances share blocklists via gossip protocol           │   │
│  │  + No single point of failure                                    │   │
│  │  + Shared intelligence                                           │   │
│  │  - Complex coordination                                          │   │
│  └─────────────────────────────────────────────────────────────────┘   │
│                                                                         │
└─────────────────────────────────────────────────────────────────────────┘
```

### Performance Targets

| Metric                  | Target            | Notes                        |
| ----------------------- | ----------------- | ---------------------------- |
| Packets/sec             | 100,000+ per core | With BPF filtering           |
| Detection latency (p99) | < 10ms            | From capture to decision     |
| Memory per IP           | ~100 bytes        | Tracking entry               |
| Storage writes/sec      | 50,000+           | With sharding                |
| API response time       | < 5ms             | For status/lookup operations |
| Block application       | < 100ms           | Time to apply firewall rule  |

---

## Future Architecture Considerations

### Planned Enhancements

1. **eBPF Integration**
   - Kernel-level packet filtering
   - XDP for wire-speed processing
   - Reduced userspace overhead

2. **Machine Learning Pipeline**
   - Anomaly detection models
   - Traffic pattern learning
   - Adaptive threshold tuning

3. **Distributed Mode**
   - Blocklist synchronization
   - Coordinated threat response
   - Multi-site deployment

4. **Cloud Integration**
   - Cloud firewall API support (AWS, GCP, Azure)
   - Kubernetes network policies
   - Service mesh integration

### Extension Points

```rust
/// Plugin trait for custom detection algorithms
pub trait DetectionPlugin: Send + Sync {
    fn name(&self) -> &str;
    fn analyze(&self, packet: &Packet, context: &AnalysisContext) -> Option<Detection>;
    fn configure(&mut self, config: &PluginConfig) -> Result<(), ConfigError>;
}

/// Plugin trait for custom response actions
pub trait ResponsePlugin: Send + Sync {
    fn name(&self) -> &str;
    fn execute(&self, action: &Action, target: &IpAddr) -> Result<(), ActionError>;
}

/// Plugin trait for custom storage backends
pub trait StoragePlugin: Send + Sync {
    fn name(&self) -> &str;
    fn write(&mut self, record: &Record) -> Result<(), StorageError>;
    fn read(&self, query: &Query) -> Result<Vec<Record>, StorageError>;
}
```

---

## Appendix: Architecture Decision Records

### ADR-001: Rust as Implementation Language

**Status**: Accepted

**Context**: Need a language that provides memory safety, high performance, and good concurrency support for a security-critical network daemon.

**Decision**: Use Rust for the implementation.

**Consequences**:

- (+) Memory safety without garbage collection
- (+) Zero-cost abstractions for performance
- (+) Strong type system catches bugs at compile time
- (-) Steeper learning curve
- (-) Longer compile times

### ADR-002: Custom Storage Format

**Status**: Accepted

**Context**: Need efficient storage for high-throughput event logging with fast lookups.

**Decision**: Implement custom binary storage format with ring buffers, bloom filters, and sharded writes.

**Consequences**:

- (+) Optimized for our specific access patterns
- (+) Better performance than general-purpose databases
- (-) More code to maintain
- (-) No standard tooling for inspection

### ADR-003: Unix Socket as Primary API

**Status**: Accepted

**Context**: Need a control interface that is secure by default and efficient for local administration.

**Decision**: Use Unix domain socket as the primary API, with optional HTTP API.

**Consequences**:

- (+) Secure by default (filesystem permissions)
- (+) No network exposure
- (+) Efficient IPC
- (-) Local-only access
- (-) Need separate HTTP API for remote management

---

_Document Version: 1.0_
_Last Updated: 2025_
