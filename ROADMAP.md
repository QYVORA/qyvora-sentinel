# Roadmap

High-level direction for QYVORA Sentinel. Dates are approximate and subject to change based on community input and contributor availability.

---

## v0.1 — MVP (Current)

**Goal:** Functional security auditing framework with core scanning, baselining, and reporting.

### Delivered

- Module loader and execution engine
- 12 initial security audit modules
- CLI with scan, modules, baseline, report, and doctor commands
- IOC signature database (initial set)
- Baseline creation and diff comparison
- Multi-format reporting (text, JSON, CSV, HTML)
- ShellCheck/shfmt enforced code quality
- Bats test framework with module-level test support

---

## v0.2 — Expanded Modules and Hardening

**Goal:** Broader coverage, richer output, and automated remediation suggestions.

### Planned

- [ ] Expand module library to 25+ modules covering:
  - Container security (Docker, Podman)
  - Systemd service hardening
  - Package vulnerability cross-referencing (CVE lookup)
  - Firewall rule analysis (iptables, nftables, firewalld)
  - DNS configuration auditing
- [ ] Automated remediation recommendations (advisory mode)
- [ ] SARIF output format for IDE and CI integration
- [ ] Diff-based HTML reports (baseline vs current)
- [ ] Plugin hot-reload without sentinel restart
- [ ] Persistent scan history with SQLite backend
- [ ] Interactive TUI mode for interactive exploration
- [ ] Extended IOC signature database with community contributions
- [ ] Custom check DSL for declarative rule definitions

---

## v0.3 — Plugin Marketplace and Ecosystem

**Goal:** Establish a plugin ecosystem and community-driven extensibility.

### Planned

- [ ] Plugin marketplace with discovery, install, and update commands
  - `sentinel plugin search <query>`
  - `sentinel plugin install <name>`
  - `sentinel plugin update`
- [ ] Plugin signing and verification (GPG-based trust chain)
- [ ] Remote signature feeds with automatic update
- [ ] Compliance profile editor (visual YAML builder)
- [ ] API server mode for centralized fleet auditing
  - REST API for scan execution and result retrieval
  - Authentication and role-based access control
  - WebSocket streaming for real-time scan progress
- [ ] Scheduled scan daemon with cron/systemd timer integration
- [ ] Notification system (webhook, email, Slack)
- [ ] Multi-host orchestration for fleet-wide scanning
- [ ] Performance profiling and optimization for large-scale scans
- [ ] Comprehensive documentation site (MkDocs or equivalent)

---

## v1.0 — Stable Release

**Goal:** Production-ready, stable API, enterprise features, and long-term support commitment.

### Planned

- [ ] Stable module API (semver-guaranteed interface)
- [ ] Stable plugin API with backward compatibility guarantees
- [ ] LTS support policy (2-year support windows)
- [ ] Enterprise features:
  - RBAC for multi-tenant environments
  - Audit logging of all sentinel operations
  - Encryption at rest for scan results and baselines
  - LDAP/AD integration for user and permission management
- [ ] Certified compliance profiles (CIS Benchmark, DISA STIG, PCI-DSS, HIPAA)
- [ ] Formal security audit of the codebase
- [ ] Reproducible builds with SLSA provenance
- [ ] Comprehensive man pages for all commands
- [ ] Localization support (i18n framework)
- [ ] Package repository packages (DEB, RPM, AUR)
- [ ] Migration guide from v0.x to v1.0
