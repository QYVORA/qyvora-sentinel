# QYVORA Sentinel - CLI Reference

> Complete command-line reference for the `sentinel` CLI tool.

## Usage

```bash
sentinel [global-options] <command> [command-options]
```

If no arguments are provided, `sentinel` displays the help message.

---

## Commands

### sentinel scan

Run all enabled security audit modules against the local system.

```bash
sentinel scan [options]
```

**Options (in addition to global options):**

| Option | Description |
|--------|-------------|
| `--risk-score` | Display a risk score after the scan completes |

**Behavior:**

1. Displays the scan banner with hostname, user, severity filter, and output format
2. Initializes the configuration system
3. Discovers and loads all enabled modules
4. Executes each module sequentially (sorted alphabetically)
5. Calculates the risk score from accumulated findings
6. Displays a summary with severity counts
7. Saves scan results to `reports/scan-<timestamp>.json`
8. Generates output in the requested format (if non-text)

**Examples:**

```bash
sentinel scan                                      # Full scan, text output
sentinel scan --severity medium --json             # JSON output, medium+ findings
sentinel scan --module ssh --module filesystem     # Only specific modules
sentinel scan --exclude malware --risk-score       # Skip malware module
sentinel scan -o /tmp/report.html --html           # Save HTML report
sentinel scan -q --json -o results.json            # Quiet, machine-readable
```

---

### sentinel baseline

Create a baseline snapshot of the current system state.

```bash
sentinel baseline [NAME]
```

**Arguments:**

| Argument | Default | Description |
|----------|---------|-------------|
| `NAME` | `default` | Name for the baseline snapshot |

**Captured data:**

- SUID files in `/usr`, `/bin`, `/sbin`
- SGID files
- World-writable files in `/etc`, `/usr`, `/var`
- Installed packages (dpkg/rpm)
- Running services (systemctl)
- Listening ports (ss/netstat)
- User accounts with login shells
- Crontabs (system and per-user)
- Kernel modules (lsmod)
- SHA-256 hashes of critical config files

**Examples:**

```bash
sentinel baseline                    # Create "default" baseline
sentinel baseline production         # Create "production" baseline
sentinel baseline pre-upgrade        # Named baseline before an upgrade
```

---

### sentinel compare

Compare current system state against a saved baseline.

```bash
sentinel compare [--baseline NAME]
```

**Options:**

| Option | Default | Description |
|--------|---------|-------------|
| `--baseline NAME` | `default` | Which baseline to compare against |

**What is compared:**

- SUID files (added/removed)
- Installed packages (added/removed)
- Listening ports (changes detected)
- User accounts (added/removed)

**Examples:**

```bash
sentinel compare                          # Compare to "default" baseline
sentinel compare --baseline production    # Compare to "production" baseline
```

---

### sentinel modules

List all available modules and their status.

```bash
sentinel modules
```

**Output columns:**

| Column | Description |
|--------|-------------|
| NAME | Module directory name |
| DESCRIPTION | Module's `MODULE_DESCRIPTION` value |
| STATUS | `enabled` or `disabled` (based on current filters) |

**Example output:**

```
NAME                 DESCRIPTION                                     STATUS
──────────────────── ─────────────────────────────────────────────── ──────────
browser              Browser artifact audit                          enabled
cloud                Cloud configuration audit                       enabled
filesystem           Filesystem permissions and artifact audit       enabled
ssh                  SSH configuration audit                         enabled
users                User account and privilege audit                enabled
...

Total: 21 | Enabled: 21 | Disabled: 0
```

---

### sentinel report

Generate a report from the most recent scan results.

```bash
sentinel report [--format FORMAT] [--output FILE]
```

**Options:**

| Option | Description |
|--------|-------------|
| `--output FILE`, `-o FILE` | Write report to file instead of stdout |

**Behavior:**

- If findings exist in memory (from a preceding `scan` command), uses those
- Otherwise, loads the most recent scan JSON from `reports/scan-*.json`
- Generates the report in the format specified by global options

**Examples:**

```bash
sentinel report --json                         # JSON to stdout
sentinel report --html -o report.html          # HTML to file
sentinel report --markdown -o audit.md         # Markdown to file
```

---

### sentinel doctor

Check system dependencies, configuration, and health.

```bash
sentinel doctor
```

**Checks performed:**

| Category | Items |
|----------|-------|
| Required Commands | bash, find, ps, cat, grep, awk, sed, chmod, chown, id, whoami, uname, ls, file, stat |
| Network Commands | ss or netstat (at least one) |
| Hash Commands | sha256sum/shasum, md5sum |
| Optional Commands | docker, kubectl, systemctl, journalctl, iptables, nftables, ufw, fail2ban-client |
| Configuration | Config file existence and validity |
| Directories | Report and baseline directory writability |
| Modules | Module discovery count |

**Exit codes:**

- `0` - System is healthy (may have warnings)
- `1` - Errors found (system may not function correctly)

---

### sentinel version

Display version and system information.

```bash
sentinel version
```

**Output includes:**

- Product name and version
- Bash version
- Platform and kernel
- Architecture
- OS identifier
- Hostname
- Install path

---

### sentinel update

Check for available updates.

```bash
sentinel update
```

**Behavior:**

- If in a git repository: fetches from remote and compares commits
- If not in a git repo: displays the project URL for manual checking

---

### sentinel plugins

List installed plugins.

```bash
sentinel plugins
```

**Output:** Lists each plugin directory with its description. Warns about directories missing `main.sh`.

---

### sentinel help

Display the help message.

```bash
sentinel help
```

---

## Global Options

These options can be placed before any command:

| Option | Short | Argument | Description |
|--------|-------|----------|-------------|
| `--module NAME` | `-m` | `NAME` | Run a specific module (repeatable) |
| `--exclude MODULE` | `-e` | `MODULE` | Exclude a module from scanning (repeatable) |
| `--include MODULE` | `-I` | `MODULE` | Include only these modules (repeatable) |
| `--severity LEVEL` | `-s` | `LEVEL` | Minimum severity to report: `INFO`, `LOW`, `MEDIUM`, `HIGH`, `CRITICAL` |
| `--output FILE` | `-o` | `FILE` | Write output to a file |
| `--config FILE` | `-c` | `FILE` | Use a custom configuration file |
| `--baseline NAME` | `-b` | `NAME` | Baseline name for the `compare` command |
| `--compare` | | | Enable comparison mode |
| `--threads N` | `-t` | `N` | Number of parallel threads (experimental) |
| `--risk-score` | | | Display risk score after scan |
| `--quiet` | `-q` | | Suppress non-essential output |
| `--verbose` | `-v` | | Enable verbose output |
| `--debug` | | | Enable debug output (`set -x`) |
| `--json` | | | Output in JSON format |
| `--html` | | | Output in HTML format |
| `--markdown` | | | Output in Markdown format |
| `--text` | | | Output in text format (default) |
| `--color` | | | Force colored output |
| `--no-color` | | | Disable colored output |
| `--help` | `-h` | | Show help message |
| `--version` | `-V` | | Show version information |

### Option Parsing

- Global options are parsed first, before the subcommand
- Options can appear in any order before the subcommand
- The subcommand is the first non-option argument
- Everything after the subcommand is passed as subcommand arguments
- `--` signals end of global options

**Example with mixed options:**

```bash
sentinel --severity medium --json --module ssh scan --output report.json
#              ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^  ^^^^^^^^^^^^^^^^^
#                    global options                    subcommand + args
```

---

## Exit Codes

| Code | Meaning |
|------|---------|
| `0` | Success |
| `1` | General error (unknown command, invalid option, missing file) |
| `130` | Interrupted by signal (Ctrl+C, SIGTERM, SIGHUP) |

---

## Environment Variables

| Variable | Description |
|----------|-------------|
| `NO_COLOR` | If set, disables color output (per [no-color.org](https://no-color.org)) |
| `SENTINEL_NO_COLOR` | If set to `1`, disables color output |
| `XDG_CONFIG_HOME` | Used to locate the default config directory (`$XDG_CONFIG_HOME/qyvora-sentinel/`) |
| `HOME` | Fallback for config directory (`~/.config/qyvora-sentinel/`) |
| `SENTINEL_LOG_LEVEL` | Override default log level |
| `SENTINEL_PLUGIN_DIR` | Override default plugin directory |

---

## Configuration File Locations

Configuration is loaded in priority order (first found wins):

1. `--config PATH` command-line argument
2. `$SENTINEL_CONFIG_FILE` (if set in environment)
3. `$XDG_CONFIG_HOME/qyvora-sentinel/sentinel.conf`
4. `$HOME/.config/qyvora-sentinel/sentinel.conf`
5. Defaults auto-generated on first run

### Configuration Files in `configs/`

| File | Description |
|------|-------------|
| `configs/sentinel.conf` | Main configuration (scan mode, timeouts, output, logging, performance) |
| `configs/modules.conf` | Per-module enable/disable, timeout, description |
| `configs/ignore.conf` | Paths, users, processes, and cron entries to skip |
| `configs/severity.conf` | Severity level definitions, scoring weights, display icons |

---

## Common Usage Patterns

### Quick Security Check

```bash
sentinel scan --severity medium -q --json -o quick-check.json
```

### Full Audit with HTML Report

```bash
sentinel scan --risk-score --html -o /var/log/audit-$(date +%Y%m%d).html
```

### Targeted Module Scan

```bash
sentinel scan -m ssh -m users -m filesystem --verbose
```

### Baseline Workflow

```bash
# 1. Create initial baseline
sentinel baseline production

# 2. Later, check for drift
sentinel compare --baseline production

# 3. After changes, update baseline
sentinel baseline production
```

### CI/CD Integration

```bash
sentinel scan --severity high --json -q -o scan-results.json
exit_code=$?

if [[ ${exit_code} -ne 0 ]]; then
    echo "Scan encountered errors"
fi

# Parse JSON with jq
critical=$(jq '.severity_breakdown.critical' scan-results.json)
if [[ "${critical}" -gt 0 ]]; then
    echo "CRITICAL findings detected - blocking deployment"
    exit 1
fi
```

### System Health Check

```bash
sentinel doctor
sentinel version
```
