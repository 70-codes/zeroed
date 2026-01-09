# Contributing to Zeroed

Thank you for your interest in contributing to Zeroed! This document provides guidelines and information for contributors.

## Table of Contents

1. [Code of Conduct](#code-of-conduct)
2. [Getting Started](#getting-started)
3. [Development Setup](#development-setup)
4. [Project Structure](#project-structure)
5. [Coding Standards](#coding-standards)
6. [Testing](#testing)
7. [Submitting Changes](#submitting-changes)
8. [Pull Request Process](#pull-request-process)
9. [Issue Guidelines](#issue-guidelines)
10. [Security Vulnerabilities](#security-vulnerabilities)

---

## Code of Conduct

### Our Pledge

We are committed to providing a welcoming and inclusive environment for all contributors. We expect everyone participating in this project to:

- Be respectful and considerate
- Accept constructive criticism gracefully
- Focus on what's best for the community
- Show empathy towards other community members

### Unacceptable Behavior

- Harassment, discrimination, or offensive comments
- Personal attacks or trolling
- Publishing others' private information
- Other conduct that could reasonably be considered inappropriate

Violations may result in removal from the project.

---

## Getting Started

### Prerequisites

Before contributing, ensure you have:

- **Rust**: Version 1.70 or later
- **Git**: For version control
- **Linux**: Development and testing require Linux (or WSL2)
- **libpcap**: Development headers (`libpcap-dev` or `libpcap-devel`)
- **iptables**: For firewall integration testing

### First-Time Contributors

If you're new to open source or this project:

1. Start by reading the [README](README.md) and [ARCHITECTURE](ARCHITECTURE.md) docs
2. Look for issues labeled `good first issue` or `help wanted`
3. Ask questions in GitHub Discussions if anything is unclear
4. Don't hesitate to ask for help in your PR

---

## Development Setup

### 1. Fork and Clone

```bash
# Fork the repository on GitHub, then:
git clone https://github.com/YOUR_USERNAME/zeroed.git
cd zeroed
git remote add upstream https://github.com/security/zeroed.git
```

### 2. Install Dependencies

**Debian/Ubuntu:**
```bash
sudo apt-get update
sudo apt-get install -y \
    build-essential \
    pkg-config \
    libpcap-dev \
    iptables \
    ipset
```

**RHEL/CentOS/Fedora:**
```bash
sudo dnf install -y \
    gcc \
    gcc-c++ \
    make \
    pkg-config \
    libpcap-devel \
    iptables \
    ipset
```

### 3. Install Rust Toolchain

```bash
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
source $HOME/.cargo/env

# Install additional components
rustup component add rustfmt clippy
```

### 4. Build the Project

```bash
# Debug build
cargo build

# Release build
cargo build --release

# Run tests
cargo test

# Run with debug logging
RUST_LOG=debug cargo run -- start --foreground --dry-run
```

### 5. IDE Setup

**VS Code (recommended):**
- Install `rust-analyzer` extension
- Install `CodeLLDB` for debugging
- Install `Even Better TOML` for config files

**Settings (`.vscode/settings.json`):**
```json
{
    "rust-analyzer.checkOnSave.command": "clippy",
    "rust-analyzer.cargo.features": "all",
    "editor.formatOnSave": true,
    "[rust]": {
        "editor.defaultFormatter": "rust-lang.rust-analyzer"
    }
}
```

---

## Project Structure

```
zeroed/
├── src/
│   ├── main.rs              # Entry point
│   ├── bin/
│   │   └── zeroctl.rs       # CLI tool
│   ├── core/                # Core types and utilities
│   │   ├── mod.rs
│   │   ├── config.rs        # Configuration management
│   │   ├── error.rs         # Error types
│   │   └── types.rs         # Common types
│   ├── daemon/              # Daemon lifecycle
│   ├── network/             # Packet capture and parsing
│   │   ├── capture.rs       # libpcap integration
│   │   ├── connection.rs    # Connection tracking
│   │   ├── packet.rs        # Packet structures
│   │   └── parser.rs        # Protocol parsing
│   ├── detection/           # Attack detection
│   │   ├── analyzer.rs      # Traffic analysis
│   │   ├── rate_limiter.rs  # Rate limiting
│   │   ├── rules.rs         # Detection rules
│   │   └── threshold.rs     # Adaptive thresholds
│   ├── storage/             # Data persistence
│   │   ├── bloom.rs         # Bloom filters
│   │   ├── ring.rs          # Ring buffer
│   │   ├── shard.rs         # Sharded storage
│   │   └── wal.rs           # Write-ahead log
│   ├── geo/                 # GeoIP lookups
│   └── api/                 # Control API
├── config/                  # Configuration files
├── docs/                    # Documentation
├── scripts/                 # Build and deployment scripts
└── tests/                   # Integration tests
```

### Module Responsibilities

| Module      | Responsibility                                |
|-------------|-----------------------------------------------|
| `core`      | Shared types, configuration, error handling   |
| `daemon`    | Process lifecycle, signal handling            |
| `network`   | Packet capture, parsing, connection tracking  |
| `detection` | Attack detection, rate limiting, analysis     |
| `storage`   | Persistence, ring buffers, bloom filters      |
| `geo`       | Geographic IP lookups                         |
| `api`       | Unix socket and HTTP APIs                     |

---

## Coding Standards

### Rust Style Guide

We follow the official [Rust Style Guide](https://doc.rust-lang.org/nightly/style-guide/) with these additions:

#### Formatting

- Use `rustfmt` with default settings
- Run `cargo fmt` before committing
- Maximum line length: 100 characters

```bash
# Format all code
cargo fmt

# Check formatting without changing files
cargo fmt -- --check
```

#### Linting

- All code must pass `clippy` with no warnings
- Fix or explicitly allow clippy warnings with justification

```bash
# Run clippy
cargo clippy -- -D warnings

# Run clippy on all targets
cargo clippy --all-targets --all-features -- -D warnings
```

#### Naming Conventions

```rust
// Structs and Enums: PascalCase
struct PacketCapture { }
enum ThreatLevel { High, Medium, Low }

// Functions and variables: snake_case
fn process_packet(packet: &Packet) -> Result<()> { }
let packet_count = 0;

// Constants: SCREAMING_SNAKE_CASE
const MAX_PACKET_SIZE: usize = 65535;

// Type parameters: single uppercase letter or PascalCase
fn process<T: Send>(item: T) { }
fn process<Item: Send>(item: Item) { }
```

#### Documentation

- All public items must have documentation
- Use `///` for doc comments
- Include examples for complex functions

```rust
/// Analyzes a packet for potential threats.
///
/// This function examines the packet headers and payload to determine
/// if it matches any known attack patterns.
///
/// # Arguments
///
/// * `packet` - The packet to analyze
///
/// # Returns
///
/// Returns `Ok(ThreatLevel)` indicating the threat level, or an error
/// if the packet could not be analyzed.
///
/// # Examples
///
/// ```
/// let packet = Packet::new(data);
/// let threat = analyze_packet(&packet)?;
/// println!("Threat level: {:?}", threat);
/// ```
pub fn analyze_packet(packet: &Packet) -> Result<ThreatLevel> {
    // ...
}
```

#### Error Handling

- Use `Result<T, E>` for fallible operations
- Use `thiserror` for error definitions
- Provide context with error messages

```rust
use thiserror::Error;

#[derive(Error, Debug)]
pub enum CaptureError {
    #[error("failed to open interface '{interface}': {source}")]
    OpenInterface {
        interface: String,
        #[source]
        source: pcap::Error,
    },

    #[error("capture timeout after {0} seconds")]
    Timeout(u64),
}
```

#### Performance Considerations

- Avoid unnecessary allocations in hot paths
- Use `&str` instead of `String` when ownership isn't needed
- Prefer `Vec::with_capacity()` when size is known
- Use appropriate data structures (HashMap for lookups, Vec for iteration)

### Git Commit Messages

Follow the [Conventional Commits](https://www.conventionalcommits.org/) specification:

```
<type>(<scope>): <description>

[optional body]

[optional footer(s)]
```

**Types:**
- `feat`: New feature
- `fix`: Bug fix
- `docs`: Documentation changes
- `style`: Formatting, missing semicolons, etc.
- `refactor`: Code change that neither fixes a bug nor adds a feature
- `perf`: Performance improvement
- `test`: Adding or updating tests
- `chore`: Maintenance tasks

**Examples:**
```
feat(detection): add slowloris attack detection

Implements detection for slowloris-style HTTP slow attacks.
The detector monitors connection duration and data rate to
identify connections that are intentionally slow.

Closes #42
```

```
fix(storage): prevent ring buffer overflow on high traffic

The ring buffer was not properly handling the wraparound case
when write speed exceeded the buffer capacity. This could cause
data corruption in high-traffic scenarios.

Fixes #108
```

---

## Testing

### Running Tests

```bash
# Run all tests
cargo test

# Run tests with output
cargo test -- --nocapture

# Run specific test
cargo test test_rate_limiter

# Run tests in a specific module
cargo test detection::

# Run tests with coverage (requires cargo-tarpaulin)
cargo tarpaulin --out Html
```

### Test Categories

#### Unit Tests

Place unit tests in the same file as the code being tested:

```rust
// src/detection/rate_limiter.rs

pub struct RateLimiter { /* ... */ }

impl RateLimiter {
    pub fn check(&self, ip: IpAddr) -> RateLimitResult {
        // ...
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_allows_traffic_under_threshold() {
        let limiter = RateLimiter::new(100);
        let ip = "192.0.2.1".parse().unwrap();

        for _ in 0..50 {
            assert!(matches!(limiter.check(ip), RateLimitResult::Allow { .. }));
        }
    }

    #[test]
    fn test_blocks_traffic_over_threshold() {
        let limiter = RateLimiter::new(100);
        let ip = "192.0.2.1".parse().unwrap();

        for _ in 0..150 {
            limiter.check(ip);
        }

        assert!(matches!(limiter.check(ip), RateLimitResult::Block { .. }));
    }
}
```

#### Integration Tests

Place integration tests in the `tests/` directory:

```rust
// tests/integration_test.rs

use zeroed::detection::Analyzer;
use zeroed::network::Packet;

#[test]
fn test_full_detection_pipeline() {
    // Setup
    let analyzer = Analyzer::new(Default::default());

    // Create test packet
    let packet = create_test_syn_packet("192.0.2.1", "10.0.0.1", 80);

    // Process
    let result = analyzer.analyze(&packet);

    // Verify
    assert!(result.is_ok());
}
```

#### Property-Based Tests

Use `proptest` for property-based testing:

```rust
use proptest::prelude::*;

proptest! {
    #[test]
    fn test_bloom_filter_no_false_negatives(ips in prop::collection::vec(any::<u32>(), 0..1000)) {
        let mut filter = BloomFilter::new(10000, 0.01);

        // Add all IPs
        for ip in &ips {
            filter.insert(*ip);
        }

        // Verify no false negatives
        for ip in &ips {
            prop_assert!(filter.contains(*ip));
        }
    }
}
```

### Test Requirements

- All new features must include tests
- Bug fixes should include regression tests
- Aim for >80% code coverage on new code
- Tests must pass on CI before merging

---

## Submitting Changes

### Branch Naming

Use descriptive branch names:

```
feat/slowloris-detection
fix/ring-buffer-overflow
docs/api-reference
refactor/storage-module
```

### Before Submitting

Run this checklist before creating a PR:

```bash
# 1. Format code
cargo fmt

# 2. Run clippy
cargo clippy --all-targets --all-features -- -D warnings

# 3. Run tests
cargo test

# 4. Build release
cargo build --release

# 5. Update documentation if needed
# Edit relevant .md files

# 6. Rebase on latest main
git fetch upstream
git rebase upstream/main
```

---

## Pull Request Process

### 1. Create the PR

- Fill out the PR template completely
- Link related issues
- Add appropriate labels
- Request reviews from maintainers

### 2. PR Template

```markdown
## Description

Brief description of changes.

## Type of Change

- [ ] Bug fix (non-breaking change that fixes an issue)
- [ ] New feature (non-breaking change that adds functionality)
- [ ] Breaking change (fix or feature that would cause existing functionality to not work as expected)
- [ ] Documentation update

## Related Issues

Fixes #(issue number)

## Testing

Describe tests you ran and how to reproduce.

## Checklist

- [ ] My code follows the project's style guidelines
- [ ] I have performed a self-review of my code
- [ ] I have commented my code, particularly in hard-to-understand areas
- [ ] I have made corresponding changes to the documentation
- [ ] My changes generate no new warnings
- [ ] I have added tests that prove my fix/feature works
- [ ] New and existing tests pass locally
```

### 3. Review Process

1. **Automated Checks**: CI must pass (formatting, linting, tests)
2. **Code Review**: At least one maintainer approval required
3. **Changes Requested**: Address feedback and push updates
4. **Approval**: Once approved, a maintainer will merge

### 4. After Merge

- Delete your branch
- Pull the latest changes to your local main
- Close related issues if not auto-closed

---

## Issue Guidelines

### Bug Reports

Use the bug report template and include:

- **Zeroed version**: Output of `zeroed --version`
- **OS and version**: e.g., Ubuntu 22.04
- **Steps to reproduce**: Minimal steps to trigger the bug
- **Expected behavior**: What should happen
- **Actual behavior**: What actually happens
- **Logs**: Relevant log output (redact sensitive info)

### Feature Requests

- Check existing issues and discussions first
- Describe the problem your feature would solve
- Propose a solution if you have one
- Be open to alternative approaches

### Questions

- Use GitHub Discussions instead of issues
- Search existing discussions first
- Provide context about what you're trying to achieve

---

## Security Vulnerabilities

**Do NOT report security vulnerabilities through public GitHub issues.**

Instead:

1. Email security@example.com with details
2. Include steps to reproduce
3. Allow reasonable time for a fix before public disclosure

We will:
- Acknowledge receipt within 48 hours
- Provide an estimated timeline for a fix
- Notify you when the vulnerability is fixed
- Credit you in the security advisory (if desired)

---

## Recognition

Contributors are recognized in several ways:

- Listed in the CONTRIBUTORS file
- Mentioned in release notes
- GitHub contributor badge

Thank you for contributing to Zeroed! Your efforts help make the internet a safer place.

---

## Questions?

- **GitHub Discussions**: For general questions
- **GitHub Issues**: For bugs and feature requests
- **Email**: For private matters

We're here to help you contribute successfully!
