# Zeroed Deployment Guide

## Table of Contents

1. [Prerequisites](#prerequisites)
2. [Installation Methods](#installation-methods)
3. [Initial Configuration](#initial-configuration)
4. [Deployment Scenarios](#deployment-scenarios)
5. [Security Hardening](#security-hardening)
6. [Systemd Integration](#systemd-integration)
7. [Monitoring Setup](#monitoring-setup)
8. [High Availability](#high-availability)
9. [Upgrades and Maintenance](#upgrades-and-maintenance)
10. [Troubleshooting Deployment Issues](#troubleshooting-deployment-issues)

---

## Prerequisites

### System Requirements

| Component       | Minimum              | Recommended           |
| --------------- | -------------------- | --------------------- |
| OS              | Linux (kernel 3.10+) | Linux (kernel 5.4+)   |
| CPU             | 2 cores              | 4+ cores              |
| RAM             | 512 MB               | 2 GB+                 |
| Disk            | 1 GB                 | 10 GB+ (for logging)  |
| Network         | 100 Mbps             | 1 Gbps+               |

### Supported Distributions

| Distribution       | Version    | Status        |
| ------------------ | ---------- | ------------- |
| Ubuntu             | 20.04+     | ✅ Supported  |
| Debian             | 11+        | ✅ Supported  |
| RHEL/CentOS/Rocky  | 8+         | ✅ Supported  |
| Fedora             | 36+        | ✅ Supported  |
| Arch Linux         | Rolling    | ✅ Supported  |
| Alpine             | 3.16+      | ⚠️ Experimental |

### Required Dependencies

#### Debian/Ubuntu

```bash
sudo apt-get update
sudo apt-get install -y \
    build-essential \
    pkg-config \
    libpcap-dev \
    iptables \
    ipset \
    curl \
    git
```

#### RHEL/CentOS/Fedora

```bash
sudo dnf install -y \
    gcc \
    gcc-c++ \
    make \
    pkg-config \
    libpcap-devel \
    iptables \
    ipset \
    curl \
    git
```

#### Arch Linux

```bash
sudo pacman -S \
    base-devel \
    libpcap \
    iptables \
    ipset \
    curl \
    git
```

### Install Rust Toolchain

```bash
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
source $HOME/.cargo/env
rustup default stable
```

---

## Installation Methods

### Method 1: From Source (Recommended)

```bash
# Clone the repository
git clone https://github.com/security/zeroed.git
cd zeroed

# Build in release mode
cargo build --release

# Verify the build
./target/release/zeroed --version
./target/release/zeroctl --version

# Install binaries
sudo install -m 755 target/release/zeroed /usr/local/bin/
sudo install -m 755 target/release/zeroctl /usr/local/bin/
```

### Method 2: Using Cargo

```bash
cargo install zeroed
```

### Method 3: Pre-built Binaries

```bash
# Download latest release
VERSION="0.1.0"
ARCH="x86_64-unknown-linux-gnu"
curl -LO "https://github.com/security/zeroed/releases/download/v${VERSION}/zeroed-${VERSION}-${ARCH}.tar.gz"

# Verify checksum
curl -LO "https://github.com/security/zeroed/releases/download/v${VERSION}/zeroed-${VERSION}-${ARCH}.tar.gz.sha256"
sha256sum -c "zeroed-${VERSION}-${ARCH}.tar.gz.sha256"

# Extract and install
tar xzf "zeroed-${VERSION}-${ARCH}.tar.gz"
sudo install -m 755 zeroed-${VERSION}/zeroed /usr/local/bin/
sudo install -m 755 zeroed-${VERSION}/zeroctl /usr/local/bin/
```

### Method 4: Docker

```bash
# Build the image
docker build -t zeroed:latest .

# Or pull from registry
docker pull ghcr.io/security/zeroed:latest
```

---

## Initial Configuration

### Create System User

```bash
# Create dedicated user for zeroed
sudo useradd -r -s /bin/false -d /var/lib/zeroed -c "Zeroed DoS Protection" zeroed
```

### Create Directory Structure

```bash
# Create required directories
sudo mkdir -p /etc/zeroed
sudo mkdir -p /var/lib/zeroed/data
sudo mkdir -p /var/log/zeroed
sudo mkdir -p /var/run/zeroed

# Set ownership
sudo chown -R zeroed:zeroed /var/lib/zeroed
sudo chown -R zeroed:zeroed /var/log/zeroed
sudo chown zeroed:zeroed /var/run/zeroed

# Set permissions
sudo chmod 750 /etc/zeroed
sudo chmod 750 /var/lib/zeroed
sudo chmod 750 /var/log/zeroed
sudo chmod 755 /var/run/zeroed
```

### Install Configuration File

```bash
# Copy default configuration
sudo cp config/zeroed.toml /etc/zeroed/config.toml

# Edit configuration
sudo nano /etc/zeroed/config.toml

# Set secure permissions
sudo chmod 640 /etc/zeroed/config.toml
sudo chown root:zeroed /etc/zeroed/config.toml
```

### Essential Configuration Options

Edit `/etc/zeroed/config.toml`:

```toml
# Network interfaces to monitor
[network]
interfaces = ["eth0"]  # Change to your interface(s)
promiscuous = true

# Detection thresholds (adjust based on your traffic)
[detection]
rps_threshold = 100         # Alert threshold
rps_block_threshold = 500   # Block threshold
block_duration = 3600       # 1 hour blocks

# Add your trusted IPs
whitelist_ips = [
    "10.0.0.1",             # Your gateway
    "192.168.1.100",        # Your admin IP
]

# Firewall backend
[firewall]
enabled = true
backend = "iptables"        # or "nftables"
use_ipset = true
```

### Install GeoIP Database (Optional)

```bash
# Create GeoIP directory
sudo mkdir -p /var/lib/zeroed/geoip

# Download GeoLite2 database (requires MaxMind account)
# Register at: https://dev.maxmind.com/geoip/geolite2-free-geolocation-data

# Manual download (after obtaining license key)
curl -L "https://download.maxmind.com/app/geoip_download?edition_id=GeoLite2-City&license_key=YOUR_KEY&suffix=tar.gz" | \
    tar xz --strip-components=1 -C /var/lib/zeroed/geoip

# Set permissions
sudo chown -R zeroed:zeroed /var/lib/zeroed/geoip
```

### Validate Configuration

```bash
# Check configuration syntax
sudo zeroed config-check --config /etc/zeroed/config.toml

# List available interfaces
zeroed interfaces

# Test packet capture (requires root)
sudo zeroed start --dry-run --foreground
```

---

## Deployment Scenarios

### Scenario 1: Single Server Protection

Protect a single web server from DoS attacks.

```
┌──────────────────────────────────────────┐
│            Single Server                  │
│  ┌─────────┐    ┌─────────┐              │
│  │ Zeroed  │───▶│  Web    │              │
│  │ Daemon  │    │ Server  │              │
│  └────┬────┘    └─────────┘              │
│       │                                   │
│       ▼                                   │
│  ┌─────────┐                             │
│  │iptables │                             │
│  └─────────┘                             │
└──────────────────────────────────────────┘
```

**Configuration:**

```toml
[network]
interfaces = ["eth0"]
monitored_ports = [80, 443]

[detection]
rps_threshold = 100
rps_block_threshold = 300
max_connections_per_ip = 50

[firewall]
enabled = true
backend = "iptables"
```

### Scenario 2: Load Balancer / Reverse Proxy

Protect a load balancer that serves multiple backends.

```
                    ┌─────────────────────────────┐
Internet ──────────▶│    Load Balancer + Zeroed   │
                    │  ┌─────────┐  ┌──────────┐  │
                    │  │ Zeroed  │──│  Nginx/  │  │
                    │  │         │  │  HAProxy │  │
                    │  └─────────┘  └────┬─────┘  │
                    └────────────────────┼────────┘
                              ┌──────────┼──────────┐
                              ▼          ▼          ▼
                         ┌────────┐ ┌────────┐ ┌────────┐
                         │Backend1│ │Backend2│ │Backend3│
                         └────────┘ └────────┘ └────────┘
```

**Configuration:**

```toml
[network]
interfaces = ["eth0"]  # Public interface
monitored_ports = [80, 443]

[detection]
rps_threshold = 500
rps_block_threshold = 2000
track_mac_addresses = false  # Not useful behind NAT

# Trust backend servers
whitelist_cidrs = [
    "10.0.0.0/24",  # Backend network
]

[firewall]
enabled = true
use_ipset = true  # Efficient for large blocklists
```

### Scenario 3: Multi-Interface Server

Server with multiple network interfaces (public and private).

```
┌─────────────────────────────────────────────────┐
│              Multi-Interface Server              │
│                                                 │
│        ┌─────────────┐                          │
│        │   Zeroed    │                          │
│        │   Daemon    │                          │
│        └──────┬──────┘                          │
│               │                                 │
│     ┌─────────┼─────────┐                       │
│     │         │         │                       │
│  ┌──┴──┐   ┌──┴──┐   ┌──┴──┐                   │
│  │eth0 │   │eth1 │   │eth2 │                   │
│  │(pub)│   │(mgmt)│  │(priv)│                  │
│  └──┬──┘   └──┬──┘   └──┬──┘                   │
└─────┼─────────┼─────────┼────────────────────────┘
      │         │         │
  Internet   Admin     Internal
            Network    Network
```

**Configuration:**

```toml
[network]
interfaces = ["eth0"]  # Only monitor public interface
promiscuous = true

# Don't block management or internal IPs
whitelist_cidrs = [
    "192.168.100.0/24",  # Management network
    "10.0.0.0/8",        # Internal network
]
```

### Scenario 4: Docker Deployment

Run Zeroed in a Docker container with host network access.

**docker-compose.yml:**

```yaml
version: '3.8'

services:
  zeroed:
    image: ghcr.io/security/zeroed:latest
    container_name: zeroed
    restart: unless-stopped
    network_mode: host
    cap_add:
      - NET_ADMIN
      - NET_RAW
    volumes:
      - ./config:/etc/zeroed:ro
      - zeroed-data:/var/lib/zeroed
      - zeroed-logs:/var/log/zeroed
    environment:
      - ZEROED_CONFIG=/etc/zeroed/config.toml

volumes:
  zeroed-data:
  zeroed-logs:
```

**Run:**

```bash
docker-compose up -d
docker logs -f zeroed
```

### Scenario 5: Kubernetes DaemonSet

Deploy Zeroed on every node in a Kubernetes cluster.

**zeroed-daemonset.yaml:**

```yaml
apiVersion: apps/v1
kind: DaemonSet
metadata:
  name: zeroed
  namespace: kube-system
  labels:
    app: zeroed
spec:
  selector:
    matchLabels:
      app: zeroed
  template:
    metadata:
      labels:
        app: zeroed
    spec:
      hostNetwork: true
      hostPID: true
      containers:
        - name: zeroed
          image: ghcr.io/security/zeroed:latest
          securityContext:
            privileged: true
            capabilities:
              add:
                - NET_ADMIN
                - NET_RAW
          volumeMounts:
            - name: config
              mountPath: /etc/zeroed
              readOnly: true
            - name: data
              mountPath: /var/lib/zeroed
          resources:
            requests:
              cpu: 100m
              memory: 256Mi
            limits:
              cpu: 1000m
              memory: 1Gi
      volumes:
        - name: config
          configMap:
            name: zeroed-config
        - name: data
          hostPath:
            path: /var/lib/zeroed
            type: DirectoryOrCreate
      tolerations:
        - operator: Exists
```

---

## Security Hardening

### Linux Capabilities

Run Zeroed with minimal privileges using capabilities instead of root:

```bash
# Set required capabilities on the binary
sudo setcap 'cap_net_admin,cap_net_raw+eip' /usr/local/bin/zeroed

# Verify capabilities
getcap /usr/local/bin/zeroed
```

### Systemd Hardening

Add security options to the systemd service:

```ini
[Service]
# Run as non-root
User=zeroed
Group=zeroed

# Restrict capabilities
CapabilityBoundingSet=CAP_NET_ADMIN CAP_NET_RAW
AmbientCapabilities=CAP_NET_ADMIN CAP_NET_RAW

# Filesystem restrictions
ProtectSystem=strict
ProtectHome=true
PrivateTmp=true
ReadWritePaths=/var/lib/zeroed /var/log/zeroed /var/run/zeroed

# Network restrictions
RestrictAddressFamilies=AF_INET AF_INET6 AF_UNIX AF_NETLINK AF_PACKET

# System call filtering
SystemCallFilter=@system-service @network-io @io-event
SystemCallArchitectures=native

# Other hardening
NoNewPrivileges=true
ProtectKernelTunables=true
ProtectKernelModules=true
ProtectControlGroups=true
LockPersonality=true
MemoryDenyWriteExecute=true
RestrictRealtime=true
RestrictSUIDSGID=true
```

### Firewall Rules for Zeroed

Protect the Zeroed API and metrics endpoints:

```bash
# Allow only localhost to access API socket (already Unix socket, inherently local)

# Restrict Prometheus metrics to monitoring network
sudo iptables -A INPUT -p tcp --dport 9090 -s 10.0.0.0/8 -j ACCEPT
sudo iptables -A INPUT -p tcp --dport 9090 -j DROP

# If HTTP API is enabled, restrict access
sudo iptables -A INPUT -p tcp --dport 8080 -s 127.0.0.1 -j ACCEPT
sudo iptables -A INPUT -p tcp --dport 8080 -j DROP
```

### File Permissions Checklist

```bash
# Configuration files (root read, zeroed group read)
sudo chmod 640 /etc/zeroed/config.toml
sudo chown root:zeroed /etc/zeroed/config.toml

# Data directory (zeroed read/write)
sudo chmod 750 /var/lib/zeroed
sudo chown zeroed:zeroed /var/lib/zeroed

# Log directory
sudo chmod 750 /var/log/zeroed
sudo chown zeroed:zeroed /var/log/zeroed

# PID/socket directory
sudo chmod 755 /var/run/zeroed
sudo chown zeroed:zeroed /var/run/zeroed

# Binary files
sudo chmod 755 /usr/local/bin/zeroed
sudo chmod 755 /usr/local/bin/zeroctl
```

### SELinux Policy (RHEL/CentOS)

```bash
# Check SELinux status
getenforce

# Create custom policy for zeroed
cat > zeroed.te << 'EOF'
module zeroed 1.0;

require {
    type unreserved_port_t;
    type node_t;
    class tcp_socket { create accept listen bind };
    class udp_socket { create bind };
    class rawip_socket { create bind getopt setopt };
    class packet_socket { create bind setopt };
    class capability { net_admin net_raw };
}

allow zeroed_t self:capability { net_admin net_raw };
allow zeroed_t self:rawip_socket { create bind getopt setopt };
allow zeroed_t self:packet_socket { create bind setopt };
EOF

# Compile and install
checkmodule -M -m -o zeroed.mod zeroed.te
semodule_package -o zeroed.pp -m zeroed.mod
sudo semodule -i zeroed.pp
```

### AppArmor Profile (Ubuntu/Debian)

Create `/etc/apparmor.d/usr.local.bin.zeroed`:

```
#include <tunables/global>

/usr/local/bin/zeroed {
  #include <abstractions/base>
  #include <abstractions/nameservice>

  capability net_admin,
  capability net_raw,

  network inet raw,
  network inet6 raw,
  network packet raw,

  /etc/zeroed/config.toml r,
  /var/lib/zeroed/** rw,
  /var/log/zeroed/** rw,
  /var/run/zeroed/** rw,

  /usr/local/bin/zeroed mr,
  /proc/sys/net/** r,
}
```

```bash
# Load the profile
sudo apparmor_parser -r /etc/apparmor.d/usr.local.bin.zeroed
```

---

## Systemd Integration

### Service File

Create `/etc/systemd/system/zeroed.service`:

```ini
[Unit]
Description=Zeroed DoS Protection Daemon
Documentation=https://github.com/security/zeroed
After=network-online.target firewalld.service iptables.service
Wants=network-online.target

[Service]
Type=notify
User=zeroed
Group=zeroed
ExecStart=/usr/local/bin/zeroed start --config /etc/zeroed/config.toml
ExecReload=/bin/kill -HUP $MAINPID
ExecStop=/bin/kill -TERM $MAINPID
Restart=on-failure
RestartSec=5
TimeoutStartSec=30
TimeoutStopSec=30

# Logging
StandardOutput=journal
StandardError=journal
SyslogIdentifier=zeroed

# Security hardening (see Security Hardening section)
CapabilityBoundingSet=CAP_NET_ADMIN CAP_NET_RAW
AmbientCapabilities=CAP_NET_ADMIN CAP_NET_RAW
ProtectSystem=strict
ProtectHome=true
PrivateTmp=true
ReadWritePaths=/var/lib/zeroed /var/log/zeroed /var/run/zeroed
NoNewPrivileges=true

# Resource limits
LimitNOFILE=65535
LimitMEMLOCK=infinity

[Install]
WantedBy=multi-user.target
```

### Enable and Start

```bash
# Reload systemd
sudo systemctl daemon-reload

# Enable on boot
sudo systemctl enable zeroed

# Start the service
sudo systemctl start zeroed

# Check status
sudo systemctl status zeroed

# View logs
sudo journalctl -u zeroed -f
```

### Log Rotation

Create `/etc/logrotate.d/zeroed`:

```
/var/log/zeroed/*.log {
    daily
    missingok
    rotate 14
    compress
    delaycompress
    notifempty
    create 640 zeroed zeroed
    sharedscripts
    postrotate
        /usr/bin/systemctl reload zeroed > /dev/null 2>&1 || true
    endscript
}
```

---

## Monitoring Setup

### Prometheus Integration

**prometheus.yml:**

```yaml
scrape_configs:
  - job_name: 'zeroed'
    static_configs:
      - targets: ['localhost:9090']
    scrape_interval: 15s
    metrics_path: /metrics
```

### Grafana Dashboard

Import the Zeroed dashboard or create panels for key metrics:

**Key Metrics to Monitor:**

| Metric                         | Description                | Alert Threshold |
| ------------------------------ | -------------------------- | --------------- |
| `zeroed_packets_total`         | Total packets processed    | -               |
| `zeroed_packets_dropped`       | Packets dropped by kernel  | > 1% of total   |
| `zeroed_blocked_ips_current`   | Currently blocked IPs      | > 1000          |
| `zeroed_attacks_detected`      | Attacks detected           | Any             |
| `zeroed_memory_bytes`          | Memory usage               | > 80% of limit  |
| `zeroed_storage_bytes_written` | Storage writes             | -               |

### Alertmanager Rules

**zeroed-alerts.yml:**

```yaml
groups:
  - name: zeroed
    rules:
      - alert: ZeroedHighPacketDrop
        expr: rate(zeroed_packets_dropped[5m]) / rate(zeroed_packets_total[5m]) > 0.01
        for: 5m
        labels:
          severity: warning
        annotations:
          summary: "High packet drop rate on {{ $labels.instance }}"
          description: "Zeroed is dropping more than 1% of packets"

      - alert: ZeroedAttackDetected
        expr: increase(zeroed_attacks_detected[5m]) > 0
        for: 0m
        labels:
          severity: critical
        annotations:
          summary: "Attack detected on {{ $labels.instance }}"
          description: "Zeroed detected {{ $value }} attacks in the last 5 minutes"

      - alert: ZeroedHighBlockedIPs
        expr: zeroed_blocked_ips_current > 1000
        for: 10m
        labels:
          severity: warning
        annotations:
          summary: "High number of blocked IPs on {{ $labels.instance }}"

      - alert: ZeroedDown
        expr: up{job="zeroed"} == 0
        for: 1m
        labels:
          severity: critical
        annotations:
          summary: "Zeroed is down on {{ $labels.instance }}"
```

### Health Check Script

Create `/usr/local/bin/zeroed-healthcheck`:

```bash
#!/bin/bash

# Check if process is running
if ! pgrep -x zeroed > /dev/null; then
    echo "CRITICAL: Zeroed process not running"
    exit 2
fi

# Check if socket is responsive
if ! timeout 5 zeroctl status > /dev/null 2>&1; then
    echo "WARNING: Zeroed not responding to commands"
    exit 1
fi

# Check memory usage
MEM_USAGE=$(ps -o rss= -p $(pgrep -x zeroed) | awk '{print $1/1024}')
if (( $(echo "$MEM_USAGE > 1024" | bc -l) )); then
    echo "WARNING: Zeroed memory usage high: ${MEM_USAGE}MB"
    exit 1
fi

echo "OK: Zeroed is healthy"
exit 0
```

---

## High Availability

### Active-Passive Setup

For critical environments, deploy Zeroed in an active-passive configuration:

```
┌─────────────────────────────────────────────────────────────────┐
│                    High Availability Setup                       │
├─────────────────────────────────────────────────────────────────┤
│                                                                 │
│   ┌──────────────┐              ┌──────────────┐               │
│   │   Server 1   │              │   Server 2   │               │
│   │   (Active)   │              │  (Standby)   │               │
│   │  ┌────────┐  │              │  ┌────────┐  │               │
│   │  │ Zeroed │  │              │  │ Zeroed │  │               │
│   │  └────────┘  │              │  └────────┘  │               │
│   └──────┬───────┘              └──────┬───────┘               │
│          │                             │                        │
│          └─────────────┬───────────────┘                        │
│                        │                                        │
│                  ┌─────┴─────┐                                  │
│                  │ Keepalived│                                  │
│                  │    VIP    │                                  │
│                  └───────────┘                                  │
│                                                                 │
└─────────────────────────────────────────────────────────────────┘
```

**Keepalived Configuration:**

```conf
vrrp_script check_zeroed {
    script "/usr/local/bin/zeroed-healthcheck"
    interval 2
    weight -20
}

vrrp_instance VI_1 {
    state MASTER
    interface eth0
    virtual_router_id 51
    priority 100
    advert_int 1
    
    authentication {
        auth_type PASS
        auth_pass secret
    }
    
    virtual_ipaddress {
        192.168.1.100/24
    }
    
    track_script {
        check_zeroed
    }
}
```

### State Synchronization

Synchronize blocklists between nodes:

```bash
# Export blocked IPs from active node
zeroctl list blocked --format json > /tmp/blocklist.json

# Sync to standby (via rsync/scp)
rsync -avz /tmp/blocklist.json standby:/tmp/

# Import on standby node
zeroctl import /tmp/blocklist.json
```

---

## Upgrades and Maintenance

### Upgrade Procedure

```bash
# 1. Check current version
zeroed --version

# 2. Download new version
cd /tmp
git clone https://github.com/security/zeroed.git
cd zeroed
git checkout v0.2.0  # New version tag

# 3. Build new version
cargo build --release

# 4. Stop service (brief downtime)
sudo systemctl stop zeroed

# 5. Backup current binary
sudo cp /usr/local/bin/zeroed /usr/local/bin/zeroed.bak

# 6. Install new binary
sudo install -m 755 target/release/zeroed /usr/local/bin/

# 7. Verify new version
zeroed --version

# 8. Start service
sudo systemctl start zeroed

# 9. Verify operation
sudo systemctl status zeroed
zeroctl status
```

### Rollback Procedure

```bash
# Stop service
sudo systemctl stop zeroed

# Restore backup
sudo mv /usr/local/bin/zeroed.bak /usr/local/bin/zeroed

# Start service
sudo systemctl start zeroed

# Verify
zeroed --version
```

### Configuration Changes

```bash
# 1. Backup current config
sudo cp /etc/zeroed/config.toml /etc/zeroed/config.toml.bak

# 2. Edit configuration
sudo nano /etc/zeroed/config.toml

# 3. Validate new configuration
sudo zeroed config-check --config /etc/zeroed/config.toml

# 4. Reload configuration (no restart needed)
sudo systemctl reload zeroed
# or
zeroctl reload
```

### Data Maintenance

```bash
# View storage statistics
zeroctl stats storage

# Clean old archived data (older than 30 days)
find /var/lib/zeroed/data/archive -type f -mtime +30 -delete

# Compact storage (if supported)
zeroctl maintenance compact

# Rebuild bloom filters
zeroctl maintenance rebuild-bloom

# Backup data directory
tar -czf zeroed-backup-$(date +%Y%m%d).tar.gz /var/lib/zeroed/data
```

---

## Troubleshooting Deployment Issues

### Common Issues

#### Service Won't Start

```bash
# Check logs
sudo journalctl -u zeroed -n 100 --no-pager

# Common causes:
# 1. Permission denied - check file permissions and capabilities
# 2. Interface not found - verify interface name in config
# 3. Port already in use - check for conflicting services
# 4. Missing dependencies - install libpcap

# Test manually
sudo /usr/local/bin/zeroed start --foreground --config /etc/zeroed/config.toml
```

#### High CPU Usage

```bash
# Check which component is using CPU
perf top -p $(pgrep zeroed)

# Common causes:
# 1. High traffic volume - adjust capture filter
# 2. Too many IPs tracked - increase cleanup frequency
# 3. Debug logging enabled - set log level to info

# Solutions:
# Add BPF filter to reduce captured packets
[network]
bpf_filter = "tcp port 80 or tcp port 443"

# Reduce tracking retention
[storage]
record_ttl = 86400  # 1 day instead of 7
```

#### Memory Leaks

```bash
# Monitor memory usage
watch -n 5 'ps -o rss,vsz -p $(pgrep zeroed)'

# Check for memory growth pattern
for i in {1..60}; do
    echo "$(date): $(ps -o rss= -p $(pgrep zeroed))"
    sleep 60
done | tee memory-log.txt

# Solutions:
# Limit ring buffer size
[storage]
ring_buffer_size = 50000

# Enable memory limit
[daemon]
max_memory_mb = 512
```

#### Packets Not Being Captured

```bash
# Verify interface is up
ip link show eth0

# Check if promiscuous mode is enabled
ip link show eth0 | grep PROMISC

# Test with tcpdump
sudo tcpdump -i eth0 -c 10

# Verify libpcap is working
sudo zeroed interfaces

# Check BPF filter syntax
tcpdump -d "tcp port 80"  # Should not error
```

#### Firewall Rules Not Applied

```bash
# Check if firewall is enabled in config
grep -A5 "\[firewall\]" /etc/zeroed/config.toml

# Verify iptables chain exists
sudo iptables -L ZEROED -n

# Check for dry_run mode
grep dry_run /etc/zeroed/config.toml

# Manually test rule application
sudo iptables -A ZEROED -s 192.0.2.1 -j DROP
sudo iptables -L ZEROED -n

# Check ipset (if enabled)
sudo ipset list zeroed_blocklist
```

### Diagnostic Commands

```bash
# Full system diagnostic
zeroctl diagnose

# Check daemon status
zeroctl status --verbose

# View current statistics
zeroctl stats

# List active connections
zeroctl list connections

#
