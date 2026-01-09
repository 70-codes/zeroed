# Security Policy

## Table of Contents

1. [Supported Versions](#supported-versions)
2. [Reporting a Vulnerability](#reporting-a-vulnerability)
3. [Security Model](#security-model)
4. [Hardening Guide](#hardening-guide)
5. [Known Security Considerations](#known-security-considerations)
6. [Security Checklist](#security-checklist)

---

## Supported Versions

| Version | Supported          | Notes                        |
| ------- | ------------------ | ---------------------------- |
| 0.1.x   | :white_check_mark: | Current development version  |
| < 0.1   | :x:                | Pre-release, not supported   |

Security updates are prioritized for the latest minor version. We recommend always running the latest release.

---

## Reporting a Vulnerability

### Do NOT Report Security Vulnerabilities Publicly

**Please do not report security vulnerabilities through public GitHub issues, discussions, or pull requests.**

### How to Report

1. **Email**: Send details to security@example.com
2. **Subject Line**: `[SECURITY] Zeroed - Brief Description`
3. **Encrypt** (optional): Use our PGP key (available at security@example.com)

### What to Include

- Type of vulnerability (e.g., buffer overflow, privilege escalation, DoS)
- Full paths of source file(s) related to the issue
- Step-by-step instructions to reproduce
- Proof-of-concept or exploit code (if possible)
- Impact assessment
- Suggested fix (if any)

### Response Timeline

| Stage              | Timeline         |
| ------------------ | ---------------- |
| Acknowledgment     | Within 48 hours  |
| Initial Assessment | Within 1 week    |
| Fix Development    | 1-4 weeks        |
| Public Disclosure  | After fix release|

### Disclosure Policy

- We follow responsible disclosure practices
- We will coordinate with you on disclosure timing
- We will credit you in the security advisory (unless you prefer anonymity)
- We ask that you do not disclose until a fix is available

---

## Security Model

### Threat Model

Zeroed is designed to protect against:

| Threat                    | Protection Level | Notes                              |
| ------------------------- | ---------------- | ---------------------------------- |
| DoS/DDoS attacks          | Primary          | Core functionality                 |
| Network reconnaissance    | Secondary        | Through traffic analysis           |
| Brute force attacks       | Secondary        | Through rate limiting              |
| Malicious insiders        | Limited          | Requires system access controls    |
| Physical access attacks   | Out of scope     | Requires OS-level protection       |

### Trust Boundaries

```
┌─────────────────────────────────────────────────────────────────┐
│                        Untrusted                                 │
│   ┌─────────────────────────────────────────────────────────┐   │
│   │                   Network Traffic                        │   │
│   │   (All external packets are considered hostile)          │   │
│   └─────────────────────────────────────────────────────────┘   │
└───────────────────────────────┬─────────────────────────────────┘
                                │
                                ▼
┌─────────────────────────────────────────────────────────────────┐
│                        Zeroed Daemon                             │
│   ┌─────────────────────────────────────────────────────────┐   │
│   │   Packet Processing (sandboxed, minimal privileges)      │   │
│   └─────────────────────────────────────────────────────────┘   │
│   ┌─────────────────────────────────────────────────────────┐   │
│   │   Storage Engine (restricted file access)                │   │
│   └─────────────────────────────────────────────────────────┘   │
│   ┌─────────────────────────────────────────────────────────┐   │
│   │   API (authenticated, local only by default)             │   │
│   └─────────────────────────────────────────────────────────┘   │
└───────────────────────────────┬─────────────────────────────────┘
                                │
                                ▼
┌─────────────────────────────────────────────────────────────────┐
│                          Trusted                                 │
│   ┌─────────────────────────────────────────────────────────┐   │
│   │   Configuration Files (root-owned, group-readable)       │   │
│   └─────────────────────────────────────────────────────────┘   │
│   ┌─────────────────────────────────────────────────────────┐   │
│   │   Firewall (kernel netfilter)                            │   │
│   └─────────────────────────────────────────────────────────┘   │
└─────────────────────────────────────────────────────────────────┘
```

### Privilege Model

Zeroed follows the principle of least privilege:

| Component          | Required Privileges              |
| ------------------ | -------------------------------- |
| Packet Capture     | `CAP_NET_RAW`, `CAP_NET_ADMIN`   |
| Firewall Control   | `CAP_NET_ADMIN`                  |
| Storage            | File write to data directory     |
| API Socket         | Unix socket creation             |
| Logging            | File write to log directory      |

---

## Hardening Guide

### 1. Run with Minimal Privileges

**Use Linux capabilities instead of root:**

```bash
# Remove root requirement, use capabilities
sudo setcap 'cap_net_admin,cap_net_raw+eip' /usr/local/bin/zeroed

# Verify
getcap /usr/local/bin/zeroed
```

### 2. Create Dedicated User

```bash
# Create system user with no shell
sudo useradd -r -s /bin/false -d /var/lib/zeroed -c "Zeroed Daemon" zeroed

# Lock the account
sudo passwd -l zeroed
```

### 3. File Permissions

```bash
# Configuration (readable by root and zeroed group)
sudo chmod 640 /etc/zeroed/config.toml
sudo chown root:zeroed /etc/zeroed/config.toml

# Data directory
sudo chmod 750 /var/lib/zeroed
sudo chown zeroed:zeroed /var/lib/zeroed

# Log directory
sudo chmod 750 /var/log/zeroed
sudo chown zeroed:zeroed /var/log/zeroed

# Binaries (owned by root, executable by all)
sudo chmod 755 /usr/local/bin/zeroed
sudo chmod 755 /usr/local/bin/zeroctl
```

### 4. Systemd Sandboxing

Add to `/etc/systemd/system/zeroed.service`:

```ini
[Service]
# User/Group
User=zeroed
Group=zeroed

# Capabilities
CapabilityBoundingSet=CAP_NET_ADMIN CAP_NET_RAW
AmbientCapabilities=CAP_NET_ADMIN CAP_NET_RAW
NoNewPrivileges=true

# Filesystem
ProtectSystem=strict
ProtectHome=true
PrivateTmp=true
PrivateDevices=true
ReadWritePaths=/var/lib/zeroed /var/log/zeroed /var/run/zeroed

# Network
RestrictAddressFamilies=AF_INET AF_INET6 AF_UNIX AF_NETLINK AF_PACKET

# System calls
SystemCallFilter=@system-service @network-io @io-event
SystemCallArchitectures=native

# Kernel
ProtectKernelTunables=true
ProtectKernelModules=true
ProtectKernelLogs=true
ProtectControlGroups=true

# Other
LockPersonality=true
MemoryDenyWriteExecute=true
RestrictRealtime=true
RestrictSUIDSGID=true
PrivateUsers=true
```

### 5. SELinux/AppArmor

**AppArmor Profile** (`/etc/apparmor.d/usr.local.bin.zeroed`):

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

  deny /home/** rw,
  deny /root/** rw,
}
```

### 6. Secure API Configuration

```toml
[api]
# Use Unix socket (local only) instead of HTTP
enabled = true
socket_path = "/var/run/zeroed/zeroed.sock"

# If HTTP is needed, restrict access
http_enabled = false  # Disable unless required
# http_bind = "127.0.0.1"  # Local only, never 0.0.0.0
# tls_enabled = true  # Always use TLS for remote
# auth_token = "..."  # Strong random token

# Restrict to specific clients
allowed_clients = ["127.0.0.1", "::1"]
```

### 7. Protect Secrets

**Never commit secrets to version control:**

```toml
# BAD - Don't do this
auth_token = "my-secret-token"

# GOOD - Use environment variable
# auth_token = "${ZEROED_AUTH_TOKEN}"

# GOOD - Use separate secrets file
# Include file with 600 permissions
```

### 8. Network Segmentation

```bash
# Only allow metrics scraping from monitoring network
iptables -A INPUT -p tcp --dport 9090 -s 10.0.0.0/8 -j ACCEPT
iptables -A INPUT -p tcp --dport 9090 -j DROP

# Only allow API from localhost
iptables -A INPUT -p tcp --dport 8080 -s 127.0.0.1 -j ACCEPT
iptables -A INPUT -p tcp --dport 8080 -j DROP
```

### 9. Audit Logging

Enable comprehensive logging for security events:

```toml
[logging]
level = "info"
output = "file"
file_path = "/var/log/zeroed/zeroed.log"

# Separate security-relevant events
security_log_path = "/var/log/zeroed/security.log"

# Include enough context for forensics
json_format = true
include_location = true
```

### 10. Regular Updates

```bash
# Check for updates
zeroed --version
git fetch origin --tags
git describe --tags --abbrev=0

# Subscribe to security announcements
# Watch the repository for releases
```

---

## Known Security Considerations

### 1. Packet Processing

**Risk**: Malformed packets could potentially cause crashes or undefined behavior.

**Mitigations**:
- All packet parsing uses bounds checking
- Fuzzing is performed on packet parsers
- Memory-safe Rust prevents buffer overflows
- Malformed packets are dropped, not processed

### 2. Denial of Service Against Zeroed

**Risk**: Attackers could try to overwhelm Zeroed itself.

**Mitigations**:
- Rate limiting on API endpoints
- Bounded data structures prevent memory exhaustion
- BPF filtering reduces processing load
- Watchdog monitoring for daemon health

### 3. False Positive Blocking

**Risk**: Legitimate users could be incorrectly blocked.

**Mitigations**:
- Whitelist trusted IPs and networks
- Tune detection thresholds appropriately
- Use temporary blocks (not permanent)
- Monitor and alert on blocking events
- Provide easy unblocking via API

### 4. Log Injection

**Risk**: Malicious IPs could contain control characters.

**Mitigations**:
- All user-controlled data is sanitized before logging
- JSON logging escapes special characters
- IP addresses are validated before processing

### 5. Time-of-Check to Time-of-Use (TOCTOU)

**Risk**: Race conditions between detection and action.

**Mitigations**:
- Atomic operations for critical state changes
- Lock-free data structures where possible
- Idempotent firewall operations

### 6. Configuration Injection

**Risk**: Malicious configuration could compromise the system.

**Mitigations**:
- Configuration files should be root-owned
- Validate all configuration values on load
- Restrict file permissions (640 root:zeroed)
- Use `zeroed config-check` before applying

---

## Security Checklist

### Deployment Checklist

- [ ] Running as non-root user with capabilities
- [ ] Configuration file permissions are 640 root:zeroed
- [ ] Data directory permissions are 750 zeroed:zeroed
- [ ] Log directory permissions are 750 zeroed:zeroed
- [ ] Systemd sandboxing enabled
- [ ] SELinux/AppArmor profile applied
- [ ] API restricted to localhost or authenticated
- [ ] HTTP API disabled or uses TLS + auth
- [ ] Prometheus metrics network-restricted
- [ ] Whitelist includes trusted IPs
- [ ] Log rotation configured
- [ ] Monitoring and alerting configured
- [ ] Regular update process documented

### Configuration Security Review

- [ ] No hardcoded secrets in config files
- [ ] Strong API authentication token (if HTTP enabled)
- [ ] Appropriate detection thresholds
- [ ] Reasonable block durations
- [ ] Private networks whitelisted
- [ ] GeoIP database up to date
- [ ] Firewall dry-run disabled in production

### Operational Security

- [ ] Regular log review
- [ ] False positive monitoring
- [ ] Performance monitoring
- [ ] Update schedule established
- [ ] Incident response plan documented
- [ ] Backup and recovery tested

---

## Security Resources

- [Rust Security Guidelines](https://anssi-fr.github.io/rust-guide/)
- [Linux Capabilities](https://man7.org/linux/man-pages/man7/capabilities.7.html)
- [Systemd Security Features](https://www.freedesktop.org/software/systemd/man/systemd.exec.html)
- [AppArmor Documentation](https://gitlab.com/apparmor/apparmor/-/wikis/Documentation)
- [SELinux Project](https://selinuxproject.org/)

---

## Contact

- **Security Issues**: security@example.com
- **General Questions**: GitHub Discussions
- **Bug Reports**: GitHub Issues

Thank you for helping keep Zeroed secure!
