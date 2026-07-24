<p align="center">
  <img src="docs/assets/sentinel-logo.svg" alt="QYVORA Sentinel" width="200">
</p>

<h1 align="center">QYVORA Sentinel</h1>

<p align="center">
  A comprehensive Linux security auditing and incident response framework.
</p>

<p align="center">
  <a href="#features"><img src="https://img.shields.io/badge/features-8+-blue" alt="Features"></a>
  <a href="#installation"><img src="https://img.shields.io/badge/install-git%20clone%20%2B%20make-green" alt="Installation"></a>
  <a href="LICENSE"><img src="https://img.shields.io/badge/license-MIT-yellow" alt="License"></a>
  <a href="CONTRIBUTING.md"><img src="https://img.shields.io/badge/contributions-welcome-orange" alt="Contributions"></a>
  <a href="#roadmap"><img src="https://img.shields.io/badge/version-0.1.0--mvp-red" alt="Version"></a>
</p>

---

## Features

- **OPSEC Auditing** — Detect operational security weaknesses and exposure vectors across the system.
- **Incident Response** — Automated triage, evidence collection, and containment workflows for active security events.
- **System Reconnaissance** — Deep system inventory including network configuration, running processes, open ports, and user activity.
- **Security Posture Assessment** — Evaluate hardening level against known benchmarks (CIS, STIG, custom baselines).
- **IOC Discovery** — Hunt for indicators of compromise using signature matching, behavioral analysis, and heuristic detection.
- **Misconfiguration Detection** — Identify insecure configurations in system services, kernel parameters, file permissions, and cron jobs.
- **Forensics Support** — Timeline generation, artifact extraction, log analysis, and volatile data preservation.
- **Compliance Reporting** — Generate structured reports in multiple formats for audit and regulatory requirements.

## Installation

### Prerequisites

- Linux kernel 4.9+
- Bash 4.0+
- Root or sudo privileges (required for full system access)
- `make`, `git`, `curl`, `jq`

### Install from source

```bash
git clone https://github.com/qyvora/qyvora-sentinel.git
cd qyvora-sentinel
sudo make install
```

### Verify installation

```bash
sentinel doctor
```

## Quick Start

### Scan the system

```bash
sudo sentinel scan
```

### List available modules

```bash
sentinel modules
```

### Create a security baseline

```bash
sudo sentinel baseline --create --label "clean-state"
```

### Generate a compliance report

```bash
sudo sentinel report --format html --output /var/reports/sentinel-report.html
```

### Check system health and dependencies

```bash
sentinel doctor
```

## CLI Reference

| Command | Description |
|---------|-------------|
| `sentinel scan` | Run a full security scan using all enabled modules |
| `sentinel scan --module <name>` | Run a specific module |
| `sentinel modules` | List all available modules with status |
| `sentinel modules --enable <name>` | Enable a specific module |
| `sentinel modules --disable <name>` | Disable a specific module |
| `sentinel baseline` | Manage security baselines |
| `sentinel baseline --create` | Create a new baseline snapshot |
| `sentinel baseline --diff` | Compare current state against last baseline |
| `sentinel report` | Generate a report from scan results |
| `sentinel report --format <fmt>` | Output in `text`, `json`, `csv`, or `html` |
| `sentinel doctor` | Verify system dependencies and configuration |
| `sentinel version` | Display version and build information |

## Modules

| Module | Category | Description |
|--------|----------|-------------|
| `kernel-hardening` | Posture | Audit kernel parameters against hardening baselines |
| `user-audit` | Recon | Enumerate users, groups, shells, and sudo privileges |
| `file-permissions` | Misconfig | Detect world-writable files, SUID/SGID binaries, and sticky bits |
| `network-recon` | Recon | Map listening ports, established connections, and firewall rules |
| `cron-audit` | Misconfig | Inspect cron jobs for persistence and misconfigurations |
| `log-integrity` | Forensics | Verify system log integrity and detect tampering |
| `ioc-scanner` | Detection | Scan for known indicators of compromise via signatures |
| `service-audit` | Posture | Review systemd services for unsafe configurations |
| `ssh-hardening` | Posture | Evaluate SSH daemon configuration against best practices |
| `process-anomaly` | Detection | Identify anomalous processes by behavior and resource usage |
| `compliance-baseline` | Compliance | Evaluate system against CIS and custom compliance profiles |
| `incident-triage` | IR | Automated incident response triage and evidence collection |

## Architecture

```
qyvora-sentinel/
├── bin/                  # CLI entrypoint (sentinel)
├── lib/                  # Core libraries (logging, config, module API)
│   ├── core/             # Engine: module loader, scheduler, reporter
│   ├── utils/            # Shared utilities (output, validation, crypto)
│   └── api/              # Module API and hook definitions
├── modules/              # Security audit modules (one per concern)
├── plugins/              # External plugin interface
├── signatures/           # IOC signature database
├── baselines/            # Stored baseline snapshots
├── configs/              # Default and site-specific configuration
├── tests/                # Test suites and fixtures
├── reports/              # Generated report output
├── examples/             # Example configurations and usage
└── docs/                 # Documentation and assets
```

**Design principles:**

- **Modular** — Each check is an isolated module with a standard API. Modules are discoverable, toggleable, and independently testable.
- **Declarative baselines** — Snapshots of known-good state enable drift detection and delta reporting.
- **Extensible** — External plugins and custom signatures integrate through well-defined interfaces.
- **Idempotent** — All operations are safe to re-run without side effects.
- **Minimal dependencies** — Core functionality relies only on standard Linux utilities and Bash.

## Contributing

Contributions are welcome. See [CONTRIBUTING.md](CONTRIBUTING.md) for development setup, coding standards, and the pull request process.

## License

This project is licensed under the MIT License. See [LICENSE](LICENSE) for details.
