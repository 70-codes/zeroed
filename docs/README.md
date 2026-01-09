# Zeroed Documentation

Welcome to the Zeroed documentation. This directory contains comprehensive guides for deploying, configuring, and developing with Zeroed.

## Quick Links

| Document                             | Description                                 |
| ------------------------------------ | ------------------------------------------- |
| [Main README](../README.md)          | Project overview and quick start            |
| [CAPABILITIES.md](CAPABILITIES.md)   | Complete feature and capabilities reference |
| [ARCHITECTURE.md](ARCHITECTURE.md)   | Technical architecture and design           |
| [DEPLOYMENT.md](DEPLOYMENT.md)       | Installation and deployment guide           |
| [TUNING.md](TUNING.md)               | Performance tuning guide                    |
| [API_REFERENCE.md](API_REFERENCE.md) | Complete API documentation                  |
| [CONTRIBUTING.md](CONTRIBUTING.md)   | Contribution guidelines                     |
| [SECURITY.md](SECURITY.md)           | Security policy and hardening               |

## Documentation Overview

### Getting Started

1. **[Main README](../README.md)** - Start here for an overview of Zeroed, features, installation, and quick start guide.

2. **[DEPLOYMENT.md](DEPLOYMENT.md)** - Comprehensive guide covering:
   - System requirements and prerequisites
   - Installation methods (source, cargo, binary, Docker)
   - Initial configuration
   - Deployment scenarios (single server, load balancer, Docker, Kubernetes)
   - Security hardening
   - Systemd integration
   - Monitoring setup
   - High availability configurations
   - Upgrades and maintenance

### Understanding Zeroed

3. **[CAPABILITIES.md](CAPABILITIES.md)** - Detailed feature documentation:
   - Network monitoring capabilities
   - Attack detection algorithms
   - Storage system details
   - IP/MAC tracking features
   - GeoIP integration
   - Firewall integration
   - Rate limiting algorithms
   - API interfaces
   - Metrics and monitoring

4. **[ARCHITECTURE.md](ARCHITECTURE.md)** - Technical deep dive:
   - System design principles
   - Core architecture
   - Module structure
   - Data flow pipelines
   - Concurrency model
   - Memory management
   - Storage architecture
   - Detection pipeline
   - Integration points

### Configuration & Optimization

5. **[TUNING.md](TUNING.md)** - Performance optimization guide:
   - Baseline measurements
   - Network capture tuning
   - Detection threshold tuning
   - Storage performance
   - Memory optimization
   - CPU optimization
   - System-level tuning
   - Workload-specific profiles
   - Monitoring and benchmarking

### API & Integration

6. **[API_REFERENCE.md](API_REFERENCE.md)** - Complete API documentation:
   - Unix socket API
   - HTTP REST API
   - CLI reference (zeroctl)
   - Prometheus metrics
   - Event types
   - Error codes
   - Data types

### Contributing & Security

7. **[CONTRIBUTING.md](CONTRIBUTING.md)** - How to contribute:
   - Code of conduct
   - Development setup
   - Project structure
   - Coding standards
   - Testing requirements
   - Pull request process
   - Issue guidelines

8. **[SECURITY.md](SECURITY.md)** - Security information:
   - Reporting vulnerabilities
   - Security model
   - Hardening guide
   - Security checklist
   - Known considerations

## Additional Resources

### Configuration Reference

See the [example configuration file](../config/zeroed.toml) for all available options with detailed comments.

### Source Code

Explore the [source code](../src/) for implementation details:

- `src/core/` - Core types and configuration
- `src/network/` - Packet capture and parsing
- `src/detection/` - Attack detection algorithms
- `src/storage/` - Data persistence
- `src/geo/` - Geographic IP lookups
- `src/api/` - Control API

### Tests

See the [tests directory](../tests/) for integration tests and examples.

## Document Conventions

Throughout this documentation:

- `code blocks` indicate commands, code, or configuration
- **Bold** highlights important terms or warnings
- _Italic_ indicates emphasis or variable values
- > Blockquotes provide tips or additional context

## Getting Help

- **GitHub Issues**: Report bugs or request features
- **GitHub Discussions**: Ask questions and share ideas
- **Security Issues**: Email security@example.com (do not use public issues)

## License

Zeroed is licensed under the MIT License. See [LICENSE](../LICENSE) for details.
