# Zeroed Performance Tuning Guide

## Table of Contents

1. [Overview](#overview)
2. [Baseline Measurements](#baseline-measurements)
3. [Network Capture Tuning](#network-capture-tuning)
4. [Detection Threshold Tuning](#detection-threshold-tuning)
5. [Storage Performance](#storage-performance)
6. [Memory Optimization](#memory-optimization)
7. [CPU Optimization](#cpu-optimization)
8. [System-Level Tuning](#system-level-tuning)
9. [Workload-Specific Tuning](#workload-specific-tuning)
10. [Monitoring and Benchmarking](#monitoring-and-benchmarking)
11. [Tuning Profiles](#tuning-profiles)

---

## Overview

This guide helps you optimize Zeroed for your specific environment and workload. Performance tuning involves balancing several factors:

- **Throughput**: Packets processed per second
- **Latency**: Time from packet capture to action
- **Memory Usage**: RAM consumption
- **CPU Usage**: Processing overhead
- **Detection Accuracy**: False positive/negative rates
- **Storage I/O**: Disk write performance

### Tuning Philosophy

1. **Measure First**: Always establish baselines before making changes
2. **One Change at a Time**: Isolate the impact of each modification
3. **Test Under Load**: Verify improvements under realistic conditions
4. **Document Changes**: Track what works for your environment

---

## Baseline Measurements

Before tuning, establish baseline performance metrics.

### Capture Baseline Metrics

```bash
# Start Zeroed with metrics enabled
sudo zeroed start --foreground --config /etc/zeroed/config.toml

# In another terminal, monitor metrics
watch -n 1 'curl -s localhost:9090/metrics | grep zeroed'

# Key metrics to record:
# - zeroed_packets_total (rate)
# - zeroed_packets_dropped (rate)
# - zeroed_memory_bytes
# - zeroed_cpu_seconds_total (rate)
# - zeroed_detection_latency_seconds
```

### Generate Test Traffic

```bash
# Use hping3 for synthetic traffic
sudo hping3 -S -p 80 --flood your_server_ip

# Or use wrk for HTTP traffic
wrk -t12 -c400 -d60s http://your_server_ip/

# Or replay captured traffic
sudo tcpreplay -i eth0 -M 100 captured.pcap
```

### Record Baseline

| Metric                | Value | Notes                 |
| --------------------- | ----- | --------------------- |
| Packets/sec processed |       | Normal traffic rate   |
| Packets/sec dropped   |       | Should be 0 or near 0 |
| Memory usage          |       | Stable value          |
| CPU usage             |       | Per core percentage   |
| Detection latency p99 |       | 99th percentile       |

---

## Network Capture Tuning

### Capture Buffer Size

The capture buffer holds packets between kernel and userspace. Too small causes drops; too large wastes memory.

```toml
[network]
# Default: 64 MB
# Range: 16 - 512 MB
# Increase if seeing packet drops
capture_buffer_mb = 64
```

**Tuning Guidelines:**

| Traffic Rate    | Recommended Buffer |
| --------------- | ------------------ |
| < 10k pps       | 16 MB              |
| 10k - 50k pps   | 32 MB              |
| 50k - 100k pps  | 64 MB              |
| 100k - 500k pps | 128 MB             |
| > 500k pps      | 256+ MB            |

**Monitor drops:**

```bash
# Check kernel packet drops
cat /proc/net/dev | grep eth0

# Check libpcap drops
zeroctl stats | grep dropped
```

### BPF Filter Optimization

BPF filters run in the kernel, reducing userspace load. More specific = better performance.

```toml
[network]
# Filter at kernel level (before packets reach userspace)
# Only capture traffic you need to analyze

# Example: Only HTTP/HTTPS
bpf_filter = "tcp port 80 or tcp port 443"

# Example: Exclude known-good traffic
bpf_filter = "not (src net 10.0.0.0/8) and tcp"

# Example: Only SYN packets (for SYN flood detection)
bpf_filter = "tcp[tcpflags] & tcp-syn != 0"
```

**Performance Impact:**

| Filter Specificity | Packets to Process | CPU Savings |
| ------------------ | ------------------ | ----------- |
| No filter          | 100%               | 0%          |
| Port filter        | ~20-40%            | 30-50%      |
| Protocol + Port    | ~10-20%            | 50-70%      |
| Flag filter        | ~5-10%             | 70-90%      |

### Promiscuous Mode

```toml
[network]
# true = see all traffic on segment
# false = only traffic to this host
promiscuous = true
```

- Enable for: Network monitoring, IDS mode, shared segments
- Disable for: Single server protection (reduces CPU)

### Snap Length

Capture only the bytes you need:

```toml
[network]
# Full packet (default)
snap_len = 65535

# Headers only (TCP/IP = ~60 bytes, with margin)
snap_len = 128

# Headers + some payload (for DPI)
snap_len = 256
```

**When to reduce:**

- High-volume environments (> 100k pps)
- When only analyzing headers
- Not performing deep packet inspection

### Interface Selection

```toml
[network]
# Monitor specific interfaces
interfaces = ["eth0"]

# For multi-homed servers, choose carefully:
# - eth0: public interface (monitor this)
# - eth1: private/management (skip this)
```

**Multiple Interfaces:**
Each interface spawns a capture thread. Only monitor what's necessary.

---

## Detection Threshold Tuning

### Rate Limiting Thresholds

Finding the right thresholds is critical for balancing security and usability.

```toml
[detection]
# Alert threshold (requests per second per IP)
rps_threshold = 100

# Block threshold (auto-block if exceeded)
rps_block_threshold = 500

# Time window for rate calculation
rate_window = 60
```

**Methodology for Setting Thresholds:**

1. **Analyze Normal Traffic:**

   ```bash
   # Collect baseline RPS distribution
   zeroctl stats --period 24h | grep rps_percentiles

   # Look at:
   # - Average RPS per IP
   # - 95th percentile
   # - 99th percentile
   # - Maximum
   ```

2. **Set Alert Threshold:**
   - Start at 2-3x the 99th percentile of normal traffic
   - Example: If p99 is 30 rps, start at 60-90 rps

3. **Set Block Threshold:**
   - Start at 5-10x normal peak
   - Should rarely trigger for legitimate users

4. **Monitor and Adjust:**

   ```bash
   # Check alert frequency
   grep "threshold exceeded" /var/log/zeroed/security.log | wc -l

   # Check false positive rate
   zeroctl stats | grep false_positive
   ```

### Attack-Specific Thresholds

```toml
[detection]
# SYN flood: SYN packets per second from single IP
# Normal clients: 1-10 SYN/sec
# Attack: 1000+ SYN/sec
syn_flood_threshold = 1000

# UDP flood: packets per second
# Depends heavily on application
# DNS server: higher threshold
# Web server: lower threshold
udp_flood_threshold = 5000

# ICMP flood
# Most hosts need minimal ICMP
icmp_flood_threshold = 500

# Max concurrent connections per IP
# Browsers: 6-8 connections
# APIs: varies widely
max_connections_per_ip = 100
```

### Sensitivity Level

Global sensitivity multiplier:

```toml
[detection]
# Range: 1 (low) to 10 (high)
# Lower = fewer false positives, may miss attacks
# Higher = catches more attacks, more false positives
sensitivity = 5
```

| Sensitivity | Use Case                         | False Positive Risk |
| ----------- | -------------------------------- | ------------------- |
| 1-3         | High-traffic sites, APIs         | Low                 |
| 4-6         | General web servers              | Medium              |
| 7-10        | Critical infrastructure, banking | High                |

### Adaptive Thresholds

Enable learning-based threshold adjustment:

```toml
[detection]
# Learn from traffic patterns
adaptive_thresholds = true

# Learning period in hours
learning_period = 168  # 1 week

# Adjustment range (multiplier)
# Thresholds can vary by this factor
adjustment_range = 0.5  # ±50%
```

**How Adaptive Thresholds Work:**

1. Observes traffic patterns over time
2. Detects time-of-day and day-of-week patterns
3. Adjusts thresholds based on expected traffic
4. Example: Higher thresholds during business hours

---

## Storage Performance

### Ring Buffer Sizing

The ring buffer stores recent events for quick access.

```toml
[storage]
# Number of events to keep in memory
ring_buffer_size = 100000
```

**Sizing Formula:**

```
ring_buffer_size = (events_per_second × retention_seconds) × safety_margin

Example:
- 1000 events/sec
- 60 second retention
- 1.5x safety margin
= 1000 × 60 × 1.5 = 90,000 events
```

**Memory Impact:**

| Buffer Size | Approximate Memory |
| ----------- | ------------------ |
| 10,000      | ~2 MB              |
| 100,000     | ~20 MB             |
| 1,000,000   | ~200 MB            |

### Shard Configuration

Sharding enables parallel writes:

```toml
[storage]
# Number of parallel write shards
shard_count = 16

# Buffer size per shard (bytes)
buffer_size = 65536
```

**Tuning Guidelines:**

| Disk Type | Recommended Shards | Buffer Size |
| --------- | ------------------ | ----------- |
| HDD       | 4-8                | 128 KB      |
| SATA SSD  | 8-16               | 64 KB       |
| NVMe SSD  | 16-32              | 32 KB       |

**Rule of Thumb:** Start with `shard_count = CPU_cores × 2`

### Write-Ahead Log (WAL)

```toml
[storage]
# Enable for crash recovery
wal_enabled = true

# WAL segment size (bytes)
# Larger = fewer rotations, more recovery time
wal_segment_size = 16777216  # 16 MB

# Sync mode: "none", "normal", "full"
# none: fastest, risk of data loss
# normal: balanced
# full: safest, slowest
wal_sync_mode = "normal"
```

**Performance vs. Durability:**

| Sync Mode | Write Speed | Data Loss Risk |
| --------- | ----------- | -------------- |
| none      | Fastest     | High           |
| normal    | Good        | Low            |
| full      | Slow        | Minimal        |

### Compression

```toml
[storage]
# Enable compression for archived data
compression = true

# Compression level (1-9)
# Higher = better compression, more CPU
compression_level = 6
```

**Trade-offs:**

| Level | Compression Ratio | CPU Cost |
| ----- | ----------------- | -------- |
| 1     | ~40%              | Low      |
| 6     | ~60%              | Medium   |
| 9     | ~70%              | High     |

### Bloom Filter Tuning

```toml
[storage]
# False positive rate (lower = more memory)
bloom_fp_rate = 0.01  # 1%

# Expected unique IPs
expected_unique_ips = 1000000
```

**Memory Usage Formula:**

```
memory_bits = -1.44 × n × ln(p)
memory_bytes = memory_bits / 8

Where:
- n = expected_unique_ips
- p = bloom_fp_rate

Example (1M IPs, 1% FP rate):
= -1.44 × 1,000,000 × ln(0.01)
= -1.44 × 1,000,000 × -4.6
≈ 6.6 million bits
≈ 830 KB
```

---

## Memory Optimization

### Memory Budget

```toml
[daemon]
# Hard memory limit (0 = unlimited)
max_memory_mb = 512

# Target memory usage (triggers cleanup)
target_memory_mb = 400
```

### Component Memory Allocation

Estimate memory usage by component:

| Component    | Formula                            | Example (1M IPs) |
| ------------ | ---------------------------------- | ---------------- |
| IP Tracking  | `unique_ips × 100 bytes`           | 100 MB           |
| Connections  | `max_connections × 200 bytes`      | 20 MB            |
| Ring Buffer  | `buffer_size × event_size (~200B)` | 20 MB            |
| Bloom Filter | `see formula above`                | 1 MB             |
| Rate Windows | `unique_ips × 64 bytes`            | 64 MB            |
| **Total**    |                                    | ~205 MB          |

### Reducing Memory Usage

**1. Limit Tracked IPs:**

```toml
[detection]
# Maximum unique IPs to track
max_tracked_ips = 500000

# Eviction policy: "lru" or "oldest"
eviction_policy = "lru"
```

**2. Reduce Retention:**

```toml
[storage]
# Time-to-live for records
record_ttl = 86400  # 1 day instead of 7
```

**3. Smaller Ring Buffer:**

```toml
[storage]
ring_buffer_size = 50000  # Instead of 100000
```

**4. Higher Bloom FP Rate:**

```toml
[storage]
bloom_fp_rate = 0.05  # 5% instead of 1%
# Saves ~50% bloom filter memory
```

### Memory Monitoring

```bash
# Monitor Zeroed memory usage
watch -n 5 'ps -o pid,rss,vsz,comm -p $(pgrep zeroed)'

# Detailed memory breakdown
zeroctl stats memory

# Memory metrics via Prometheus
curl -s localhost:9090/metrics | grep memory
```

---

## CPU Optimization

### Worker Threads

```toml
[daemon]
# Number of analysis threads
# 0 = auto (one per CPU core)
worker_threads = 0
```

**Guidelines:**

- **CPU-bound workloads:** `worker_threads = CPU_cores`
- **I/O-bound workloads:** `worker_threads = CPU_cores × 2`
- **Memory-constrained:** Reduce threads (each has stack)

### Reducing CPU Usage

**1. Use BPF Filters (Most Effective):**

```toml
[network]
bpf_filter = "tcp port 80 or tcp port 443"
```

**2. Reduce Logging:**

```toml
[logging]
level = "warn"  # Instead of "info" or "debug"
```

**3. Disable Unnecessary Features:**

```toml
[geoip]
enabled = false  # If not needed

[detection]
track_mac_addresses = false  # If not needed
adaptive_thresholds = false  # Simpler detection
```

**4. Increase Rate Calculation Window:**

```toml
[detection]
# Larger window = less frequent calculations
rate_window = 120  # Instead of 60
```

### CPU Affinity

Pin Zeroed to specific cores:

```bash
# Pin to cores 0-3
sudo taskset -c 0-3 zeroed start --config /etc/zeroed/config.toml

# Or in systemd service:
[Service]
CPUAffinity=0 1 2 3
```

### NUMA Considerations

For multi-socket systems:

```bash
# Run on NUMA node with NIC
numactl --cpunodebind=0 --membind=0 zeroed start

# Check NUMA topology
numactl --hardware
lstopo
```

---

## System-Level Tuning

### Kernel Network Parameters

Add to `/etc/sysctl.d/99-zeroed.conf`:

```bash
# Increase network buffer sizes
net.core.rmem_max = 134217728
net.core.rmem_default = 16777216
net.core.wmem_max = 134217728
net.core.netdev_max_backlog = 300000
net.core.netdev_budget = 600

# Connection tracking (if using iptables)
net.netfilter.nf_conntrack_max = 2097152
net.netfilter.nf_conntrack_buckets = 524288

# TCP tuning
net.ipv4.tcp_max_syn_backlog = 65536
net.ipv4.tcp_syncookies = 1
net.ipv4.tcp_tw_reuse = 1

# File descriptors
fs.file-max = 2097152
```

Apply:

```bash
sudo sysctl -p /etc/sysctl.d/99-zeroed.conf
```

### Increase File Descriptors

```bash
# In /etc/security/limits.d/zeroed.conf
zeroed soft nofile 65535
zeroed hard nofile 65535
zeroed soft memlock unlimited
zeroed hard memlock unlimited

# In systemd service
[Service]
LimitNOFILE=65535
LimitMEMLOCK=infinity
```

### IRQ Affinity

Distribute network interrupts across CPUs:

```bash
# Find IRQ numbers for NIC
grep eth0 /proc/interrupts

# Set affinity (example: IRQ 25 to CPU 0)
echo 1 > /proc/irq/25/smp_affinity

# Or use irqbalance for automatic distribution
sudo systemctl enable irqbalance
```

### NIC Ring Buffer

```bash
# Check current settings
ethtool -g eth0

# Increase ring buffer
sudo ethtool -G eth0 rx 4096 tx 4096
```

### Enable Receive Packet Steering (RPS)

For NICs without multi-queue support:

```bash
# Enable RPS on eth0 (use all CPUs)
echo ffff > /sys/class/net/eth0/queues/rx-0/rps_cpus

# Enable RFS
echo 32768 > /proc/sys/net/core/rps_sock_flow_entries
echo 4096 > /sys/class/net/eth0/queues/rx-0/rps_flow_cnt
```

### Disable Power Saving

For consistent performance:

```bash
# Disable CPU frequency scaling
for cpu in /sys/devices/system/cpu/cpu*/cpufreq/scaling_governor; do
    echo performance > $cpu
done

# Or use tuned profile
sudo tuned-adm profile network-latency
```

---

## Workload-Specific Tuning

### High-Traffic Web Server

```toml
# Optimized for >100k requests/second

[network]
interfaces = ["eth0"]
promiscuous = false
capture_buffer_mb = 128
bpf_filter = "tcp port 80 or tcp port 443"
snap_len = 128

[detection]
rps_threshold = 500
rps_block_threshold = 2000
max_connections_per_ip = 200
sensitivity = 3
adaptive_thresholds = true

[storage]
ring_buffer_size = 200000
shard_count = 32
compression = true
compression_level = 3

[daemon]
worker_threads = 0
max_memory_mb = 2048
```

### API Gateway

```toml
# Optimized for API traffic patterns

[network]
interfaces = ["eth0"]
bpf_filter = "tcp port 443 or tcp port 8443"

[detection]
rps_threshold = 1000
rps_block_threshold = 5000
max_connections_per_ip = 500
rate_window = 30
sensitivity = 4

# APIs often have legitimate high-frequency clients
whitelist_cidrs = [
    "10.0.0.0/8",      # Internal services
]

[storage]
ring_buffer_size = 100000
record_ttl = 43200  # 12 hours
```

### Gaming Server

```toml
# Optimized for UDP-heavy gaming traffic

[network]
interfaces = ["eth0"]
bpf_filter = "udp port 27015 or udp port 27016"

[detection]
udp_flood_threshold = 50000
icmp_flood_threshold = 1000
max_connections_per_ip = 50
sensitivity = 5

# Gaming often has many connections from same IP (NAT)
rps_threshold = 2000
rps_block_threshold = 10000
```

### Low-Resource VPS

```toml
# Optimized for minimal resource usage

[network]
interfaces = ["eth0"]
promiscuous = false
capture_buffer_mb = 16
snap_len = 64

[detection]
sensitivity = 4
adaptive_thresholds = false
track_mac_addresses = false

[storage]
ring_buffer_size = 10000
shard_count = 4
wal_enabled = false  # Accept some data loss risk
compression = true
compression_level = 9
record_ttl = 43200

[daemon]
worker_threads = 2
max_memory_mb = 256

[geoip]
enabled = false

[metrics]
enabled = false
```

---

## Monitoring and Benchmarking

### Key Performance Metrics

| Metric                    | Target         | Action if Exceeded          |
| ------------------------- | -------------- | --------------------------- |
| Packet drop rate          | < 0.1%         | Increase buffer, add BPF    |
| CPU usage                 | < 70%          | Add BPF filter, reduce work |
| Memory usage              | < 80% of limit | Reduce retention, buffer    |
| Detection latency p99     | < 10ms         | Reduce analysis, more CPUs  |
| Storage write latency p99 | < 50ms         | More shards, faster disk    |

### Benchmarking Commands

```bash
# Measure packet processing rate
zeroctl benchmark --duration 60 --report

# Measure detection latency
zeroctl benchmark --latency --percentiles 50,95,99

# Stress test with synthetic traffic
zeroctl benchmark --stress --rate 100000

# Memory pressure test
zeroctl benchmark --memory --target-mb 1024
```

### Profiling

```bash
# CPU profiling with perf
sudo perf record -g -p $(pgrep zeroed) -- sleep 30
sudo perf report

# Memory profiling with heaptrack
heaptrack zeroed start --foreground

# Flame graph generation
sudo perf script | stackcollapse-perf.pl | flamegraph.pl > flame.svg
```

### Creating Performance Reports

```bash
#!/bin/bash
# performance-report.sh

echo "=== Zeroed Performance Report ==="
echo "Date: $(date)"
echo ""

echo "=== System Info ==="
uname -a
echo "CPUs: $(nproc)"
echo "Memory: $(free -h | grep Mem | awk '{print $2}')"
echo ""

echo "=== Zeroed Status ==="
zeroctl status
echo ""

echo "=== Key Metrics ==="
zeroctl stats | grep -E "(packets|dropped|memory|latency)"
echo ""

echo "=== Resource Usage ==="
ps -o pid,%cpu,%mem,rss,vsz -p $(pgrep zeroed)
echo ""

echo "=== Network Interface Stats ==="
cat /proc/net/dev | grep -E "(eth0|ens)"
```

---

## Tuning Profiles

### Quick Reference Profiles

**Profile: Minimal**

```toml
# For resource-constrained environments
capture_buffer_mb = 16
ring_buffer_size = 10000
shard_count = 4
max_memory_mb = 256
worker_threads = 2
```

**Profile: Balanced**

```toml
# Default, works for most use cases
capture_buffer_mb = 64
ring_buffer_size = 100000
shard_count = 16
max_memory_mb = 512
worker_threads = 0  # auto
```

**Profile: Performance**

```toml
# For high-traffic environments
capture_buffer_mb = 128
ring_buffer_size = 200000
shard_count = 32
max_memory_mb = 2048
worker_threads = 0
bpf_filter = "tcp"  # Add appropriate filter
```

**Profile: Maximum Security**

```toml
# For critical infrastructure
sensitivity = 8
adaptive_thresholds = true
rps_threshold = 50
rps_block_threshold = 200
wal_enabled = true
wal_sync_mode = "full"
```

---

## Appendix: Quick Tuning Checklist

- [ ] Establish baseline metrics before changes
- [ ] Configure appropriate BPF filter
- [ ] Set capture buffer based on traffic rate
- [ ] Tune detection thresholds for your traffic patterns
- [ ] Configure appropriate whitelist/blacklist
- [ ] Size ring buffer for retention needs
- [ ] Set memory limits to prevent OOM
- [ ] Apply kernel network tuning
- [ ] Enable monitoring and alerting
- [ ] Document your configuration
- [ ] Test under realistic load
- [ ] Schedule periodic reviews

---

_Last updated: 2025_
