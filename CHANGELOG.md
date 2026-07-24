# Changelog

All notable changes to QYVORA Sentinel will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.1.0] - 2024-01-01

### Added

#### Core Engine
- Module loader with manifest-based discovery and registration
- Parallel and sequential execution scheduler
- Structured result reporting with severity levels (info, low, medium, high, critical)
- Configurable scan profiles (full, quick, custom)
- Global and per-module verbosity controls

#### CLI
- `sentinel scan` — run full or targeted security scans
- `sentinel modules` — list, enable, and disable modules
- `sentinel baseline` — create, compare, and manage security baselines
- `sentinel report` — generate reports in text, JSON, CSV, and HTML formats
- `sentinel doctor` — verify system dependencies and configuration
- `sentinel version` — display version and build information

#### Modules
- `kernel-hardening` — audit kernel parameters against hardening baselines
- `user-audit` — enumerate users, groups, shells, and sudo privileges
- `file-permissions` — detect world-writable files, SUID/SGID binaries, and sticky bits
- `network-recon` — map listening ports, established connections, and firewall rules
- `cron-audit` — inspect cron jobs for persistence and misconfigurations
- `log-integrity` — verify system log integrity and detect tampering
- `ioc-scanner` — scan for known indicators of compromise via signatures
- `service-audit` — review systemd services for unsafe configurations
- `ssh-hardening` — evaluate SSH daemon configuration against best practices
- `process-anomaly` — identify anomalous processes by behavior and resource usage
- `compliance-baseline` — evaluate system against CIS and custom compliance profiles
- `incident-triage` — automated incident response triage and evidence collection

#### Infrastructure
- IOC signature database with initial set of known threat indicators
- Baseline snapshot engine with diff comparison
- Configuration system with defaults, site overrides, and environment variables
- HTML report template with executive summary and per-module breakdown
- Makefile-based build and installation system
- ShellCheck and shfmt integration for code quality
- Bats test framework integration

#### Documentation
- README with installation, usage, and architecture overview
- Contributing guide with development setup and coding standards
- Security policy and vulnerability reporting process
- Code of Conduct (Contributor Covenant v2.1)
- Project governance document
- Roadmap through v1.0
