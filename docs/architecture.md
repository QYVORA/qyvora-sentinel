# QYVORA Sentinel - Architecture Overview

> QYVORA Sentinel is a modular Bash-first Linux security auditing framework designed for comprehensive system hardening assessments, compliance checks, and threat detection.

## System Overview

QYVORA Sentinel is written entirely in Bash, targeting Linux environments where Python or other runtimes may not be available. It operates as a single CLI entry point (`sentinel`) that discovers, loads, and executes security audit modules against the local system. Findings are collected, scored, and reported in multiple formats.

**Key design principles:**

- **Zero external runtime dependencies** - requires only Bash 4.0+ and standard coreutils
- **Read-only by default** - scanning never modifies the system state
- **Modular architecture** - modules and plugins are independently developed and loaded
- **Fail-safe** - trap-based cleanup, graceful degradation on missing tools
- **Portable** - works across Debian, RHEL, Arch, Alpine, and other Linux distributions

## Component Diagram

```
┌──────────────────────────────────────────────────────────────┐
│                      sentinel (CLI)                          │
│  ┌──────────┐  ┌──────────┐  ┌──────────┐  ┌──────────┐    │
│  │   scan   │  │ baseline │  │  report  │  │  doctor  │    │
│  └────┬─────┘  └────┬─────┘  └────┬─────┘  └────┬─────┘    │
│       │              │              │              │          │
│  ┌────▼──────────────▼──────────────▼──────────────▼────┐    │
│  │              Global Option Parser                     │    │
│  │   parse_global_options() / _setup_output_mode()      │    │
│  └────────────────────────┬─────────────────────────────┘    │
│                           │                                  │
│  ┌────────────────────────▼─────────────────────────────┐    │
│  │                   Library Layer (lib/)                │    │
│  │  colors │ logger │ config │ utils │ hashing │ perms  │    │
│  │  filesystem │ process │ network │ output │ validation │    │
│  │  cli │ reporting │ baseline │ plugin_loader           │    │
│  └────────────────────────┬─────────────────────────────┘    │
│                           │                                  │
│  ┌────────────────────────▼─────────────────────────────┐    │
│  │                 Module System (modules/)              │    │
│  │  filesystem/ │ ssh/ │ users/ │ network/ │ docker/    │    │
│  │  kernel/ │ malware/ │ secrets/ │ persistence/ │ ...   │    │
│  │              (21 modules total)                       │    │
│  └────────────────────────┬─────────────────────────────┘    │
│                           │                                  │
│  ┌────────────────────────▼─────────────────────────────┐    │
│  │                 Plugin System (plugins/)              │    │
│  │            Dynamic loading, validation, execution     │    │
│  └──────────────────────────────────────────────────────┘    │
│                                                              │
│  ┌──────────────────────────────────────────────────────┐    │
│  │               Output & Reporting                      │    │
│  │  text │ JSON │ Markdown │ HTML │ SIEM integration     │    │
│  └──────────────────────────────────────────────────────┘    │
└──────────────────────────────────────────────────────────────┘
```

## Library Layer

All shared functionality resides in `lib/` as individual `.sh` files, sourced at startup by the main `sentinel` script. Each library is self-contained with its own shebang, strict mode, and sourced dependencies.

### Library Inventory

| File | Purpose |
|------|---------|
| `colors.sh` | ANSI color constants, `colorize()`, `severity_color()`, terminal detection, `NO_COLOR` support |
| `logger.sh` | Structured logging (`log_debug`, `log_info`, `log_warning`, `log_error`, `log_fatal`), file logging, level filtering |
| `config.sh` | INI-style config parser (`config_init`, `config_get`, `config_set`), section queries, write-back |
| `utils.sh` | OS detection (`get_os`, `get_os_family`), command checks, temp directory management, `retry()`, `timeout()`, UUID generation |
| `hashing.sh` | File hashing (`hash_sha256`, `hash_md5`), integrity verification |
| `permissions.sh` | Permission checks (`is_suid`, `is_sgid`, `is_world_writable`, `is_sticky`), `find_suid_files`, capability inspection |
| `filesystem.sh` | Filesystem operations, path queries, safe file enumeration |
| `process.sh` | Process inspection, process tree analysis |
| `network.sh` | Network utilities, connection listing, DNS queries |
| `output.sh` | Terminal UI (`print_banner`, `print_header`, `print_finding`, `print_success`, `print_warning`, `print_error`, `print_progress`, `print_risk_score`) |
| `validation.sh` | Input validators (`validate_path`, `validate_port`, `validate_severity`, `validate_url`, `sanitize_input`) |
| `cli.sh` | CLI argument parsing helpers |
| `reporting.sh` | Multi-format report generation (text, JSON, Markdown, HTML), risk score calculation, finding management |
| `baseline.sh` | Baseline capture (file hashes, services, users, cron, ports, packages, kernel modules, config), diff/comparison |
| `plugin_loader.sh` | Plugin discovery, validation, loading, unloading, execution, and registry |

### Library Loading

Libraries are sourced in bulk at startup:

```bash
_source_libs() {
    for lib_file in "${lib_dir}"/*.sh; do
        source "${lib_file}" 2>/dev/null || true
    done
}
```

The `set +e` / `set -e` bracket around sourcing tolerates readonly variable redefinition between libraries (e.g., `colors.sh` and `output.sh` both define color constants). After sourcing, `errtrace` (`set +E`) is disabled so that ERR traps do not propagate into functions using `|| true` guards.

## Module System

### Module Discovery

Modules are discovered by scanning `modules/*/main.sh`:

```
modules/
├── browser/main.sh
├── cloud/main.sh
├── containers/main.sh
├── crypto/main.sh
├── docker/main.sh
├── filesystem/main.sh
├── forensic/main.sh
├── kernel/main.sh
├── kubernetes/main.sh
├── logs/main.sh
├── malware/main.sh
├── memory/main.sh
├── network/main.sh
├── packages/main.sh
├── permissions/main.sh
├── persistence/main.sh
├── secrets/main.sh
├── ssh/main.sh
├── system/main.sh
├── timeline/main.sh
└── users/main.sh
```

Each subdirectory under `modules/` contains a `main.sh` file. The `_discover_modules()` function iterates through `modules/*/` and registers any directory that has a valid `main.sh`.

### Module Loading

When a module is loaded (`_load_module`):

1. Previous module state is cleaned (unset `MODULE_NAME`, `MODULE_DESCRIPTION`, etc.)
2. The module's `main.sh` is sourced
3. Required exports are validated: `MODULE_NAME`, `run()` function
4. The module is ready for execution

### Module Execution

For each enabled module (`_run_module`):

1. **Filter check** - module is skipped if excluded by `--module`, `--exclude`, or `--include` flags
2. **Severity threshold** - module is skipped if its `MODULE_SEVERITY_THRESHOLD` is above the current `--severity` filter
3. **Loading** - module file is sourced
4. **Execution** - `run()` function is called with error capture
5. **Timing** - duration is logged
6. **Cleanup** - `SENTINEL_CURRENT_MODULE` is reset

### Module Filtering Priority

```
--module name      → Only that specific module runs
--include name     → Only listed modules run (like --module but repeatable)
--exclude name     → Listed modules are skipped from default set
(default)          → All discovered modules run
```

## Plugin System

Plugins extend Sentinel without modifying core code. They live in `plugins/` and follow the same convention as modules.

### Plugin Discovery

The `plugin_loader.sh` library scans `plugins/*.sh` files (flat directory, not subdirectories). Each plugin file must:

1. Start with `#!/usr/bin/env bash` or `#!/bin/bash`
2. Export required metadata variables
3. Define a `run()` function

### Plugin Interface

```bash
readonly PLUGIN_NAME="my-plugin"
readonly PLUGIN_VERSION="1.0.0"
readonly PLUGIN_AUTHOR="Author Name"
readonly PLUGIN_DESCRIPTION="What this plugin does"

run() {
    # Plugin logic here
    # Has access to all Sentinel library functions
    # Can use add_finding() to record findings
    return 0
}
```

### Plugin Lifecycle

```
plugin_loader_init() → plugin_scan() → plugin_validate() → plugin_load() → plugin_run()
```

1. **Init** - sets plugin directory, creates it if missing
2. **Scan** - finds all `.sh` files in plugin directory
3. **Validate** - checks shebang, required exports, `run()` function
4. **Load** - sources plugin file, registers metadata in global arrays
5. **Run** - executes `run()` with optional arguments

### Plugin State Tracking

Loaded plugins are tracked in associative arrays:

- `SENTINEL_PLUGIN_NAMES[name]` - plugin name
- `SENTINEL_PLUGIN_PATHS[name]` - file path
- `SENTINEL_PLUGIN_VERSIONS[name]` - version string
- `SENTINEL_PLUGIN_AUTHORS[name]` - author name
- `SENTINEL_PLUGIN_DESCRIPTIONS[name]` - description
- `SENTINEL_PLUGIN_ENABLED[name]` - enable/disable flag

## Data Flow

The scan pipeline follows a linear flow with accumulation:

```
CLI Input
    │
    ▼
parse_global_options()
    │
    ▼
_setup_output_mode()
    │
    ▼
config_init()                    ← INI config loaded
    │
    ▼
_discover_modules()              ← modules/ scanned, registry built
    │
    ▼
┌─────────────────────────────┐
│  For each module:           │
│    _is_module_enabled()     │  ← filter check
│    _load_module()           │  ← source module
│    _severity_meets_threshold() ← severity gate
│    run()                    │  ← module executes
│      │                      │
│      ▼                      │
│    add_finding()            │  ← findings accumulated
│    print_finding()          │  ← terminal output
└─────────────────────────────┘
    │
    ▼
_calculate_risk_score()         ← weighted score from findings
    │
    ▼
_print_scan_summary()           ← terminal summary
    │
    ▼
_save_scan_results()            ← JSON to reports/scan-*.json
    │
    ▼
_generate_report()              ← optional format output
```

## Finding Structure

Each finding is stored as a pipe-delimited string:

```
SEVERITY|MODULE|MESSAGE|DETAIL|TIMESTAMP
```

The reporting system (`lib/reporting.sh`) provides a richer structure with parallel arrays:

| Field | Description |
|-------|-------------|
| `id` | Sequential integer identifier |
| `module` | Source module name |
| `severity` | INFO, LOW, MEDIUM, HIGH, CRITICAL |
| `title` | Short finding title |
| `description` | Detailed explanation |
| `evidence` | Raw data or command output supporting the finding |
| `recommendation` | Remediation guidance |
| `reference` | External reference (CVE, CIS, etc.) |

## Risk Score Calculation

The risk score is a weighted sum capped at 100:

```
score = (critical × 25) + (high × 15) + (medium × 8) + (low × 3) + (info × 0)
if score > 100: score = 100
```

| Score Range | Risk Level |
|-------------|------------|
| 0-20 | MINIMAL |
| 21-40 | LOW |
| 41-60 | MEDIUM |
| 61-80 | HIGH |
| 81-100 | CRITICAL |

The `calculate_risk_score()` in `lib/reporting.sh` uses a normalized approach: `total_weighted / max_possible × 100`, where max_possible assumes all findings are CRITICAL.

## Configuration System

### INI Parser

Sentinel uses an INI-style configuration parser (`lib/config.sh`). Configuration files use standard INI syntax:

```ini
[section]
key = value
# comment
```

Configuration is stored in the `SENTINEL_CONFIG` associative array with keys formatted as `section.key` (e.g., `general.scan_mode`, `output.default_format`).

### Configuration File Locations

| File | Purpose |
|------|---------|
| `configs/sentinel.conf` | Main configuration |
| `configs/modules.conf` | Per-module enable/disable and timeouts |
| `configs/ignore.conf` | Paths, users, processes to skip |
| `configs/severity.conf` | Severity level definitions and scoring |
| `~/.config/qyvora-sentinel/sentinel.conf` | User-level overrides |

### Config API

```bash
config_init [config_file]        # Load config, write defaults if missing
config_get "section.key" "default"   # Read value
config_set "section.key" "value"     # Write value (persists to file)
config_get_boolean "section.key" "false"  # Read as boolean
config_get_integer "section.key" "0"      # Read as integer
config_has "section.key"                 # Check existence
config_get_section "section"             # List all keys in section
```

### Ignore Lists

The `configs/ignore.conf` file defines exclusions:

- **paths** - filesystem paths to skip during scanning
- **safe_suid** - known-safe SUID binaries
- **users** - system accounts to ignore
- **processes** - known-safe kernel/system processes
- **cron** - standard cron directories to skip

## Reporting Pipeline

### Output Formats

| Format | Function | Description |
|--------|----------|-------------|
| text | `generate_report_text()` | Human-readable terminal output with box-drawing characters |
| json | `generate_report_json()` | Machine-parseable JSON with full finding details |
| markdown | `generate_report_markdown()` | GitHub-flavored Markdown with tables |
| html | `generate_report_html()` | Self-contained HTML with inline CSS, responsive layout |

### Report Sections

All reports include:

1. **Executive Summary** - hostname, scan date, duration, total findings, risk score, severity breakdown
2. **System Overview** - kernel, architecture, OS, uptime
3. **Findings Detail** - each finding with id, severity, title, module, description, evidence, recommendation, reference
4. **Prioritized Recommendations** - grouped by priority (CRITICAL first)
5. **Appendix** - scan metadata, module breakdown

### Report Storage

Scan results are saved to `reports/scan-YYYYMMDDTHHMMSSZ.json` after each scan. The `report` subcommand can regenerate reports from saved scan data or from in-memory findings.

## Baseline System

### Baseline Capture

`sentinel baseline [name]` captures a point-in-time snapshot:

- SUID/SGID files
- World-writable files and directories
- Installed packages (dpkg/rpm)
- Running services (systemctl)
- Listening ports (ss/netstat)
- User accounts (login shells)
- Crontabs (system + user)
- Kernel modules (lsmod)
- SHA-256 hashes of critical config files (`/etc/passwd`, `/etc/shadow`, `/etc/ssh/sshd_config`, etc.)

Baselines are stored as `.baseline` files in `baselines/` using a structured text format with pipe-delimited records.

### Baseline Comparison

`sentinel compare --baseline [name]` extracts a saved baseline and compares current system state against it using `comm` and `diff`. Differences are reported as findings (new SUID files = HIGH, package changes = INFO, port changes = MEDIUM, new users = MEDIUM).

### Baseline Diff

`baseline_diff()` in `lib/baseline.sh` performs section-by-section comparison, reporting added, removed, and changed entries for each tracked category.

## Execution Model

### Sequential by Default

Modules execute sequentially in alphabetical order by directory name. Each module completes before the next begins. This ensures predictable behavior and avoids resource contention.

### Optional Parallelism

The `--threads N` flag and `[performance] parallel = true` config option enable parallel execution. When enabled, modules can run in background subshells with a thread pool. This is experimental and not the default.

### Module Timeouts

Per-module timeouts are defined in `configs/modules.conf`. The `timeout()` utility in `lib/utils.sh` wraps command execution with a deadline, using either the system `timeout` command or a fallback background-process-and-kill approach.

## Error Handling Strategy

### Trap-Based Cleanup

```bash
trap '_cleanup' EXIT              # Remove temp files
trap '_on_error ${LINENO} $?' ERR  # Log error line/code, cleanup, exit
trap '_on_signal HUP'  HUP
trap '_on_signal INT'  INT
trap '_on_signal TERM' TERM
```

The `_cleanup()` function removes `SENTINEL_TEMP_DIR` (a `mktemp -d` created at startup).

### Graceful Degradation

- Commands that may not exist (`ss`, `netstat`, `sha256sum`, `docker`, `kubectl`) are guarded with `command_exists` checks
- Missing tools produce warnings rather than failures
- Module failures are logged and counted but do not abort the scan
- `set -Eeuo pipefail` is used in libraries but `errexit` is carefully managed around modules using `|| module_exit=$?`

### Error Recovery

The main `sentinel` script temporarily disables `errexit` during library sourcing (to tolerate readonly variable conflicts) and re-enables it afterward. The ERR trap is also disabled during sourcing and reset after, ensuring it only applies to the main execution flow.
