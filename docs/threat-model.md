# QYVORA Sentinel - Threat Model

> Threat model for the QYVORA Sentinel framework itself, covering assets, threat agents, attack vectors, mitigations, and security principles.

## Purpose

This document identifies the security threats relevant to the QYVORA Sentinel framework and its operational environment. Sentinel runs with elevated privileges to audit system security, making it a high-value target and requiring careful security analysis of the framework itself.

## Asset Identification

### Primary Assets

| Asset | Sensitivity | Description |
|-------|-------------|-------------|
| Scan results | HIGH | Contains detailed system configuration, open ports, user accounts, file permissions, running processes, and security weaknesses |
| Configuration files | MEDIUM | Module enable/disable states, ignore lists, severity thresholds, scan scope |
| Reports | HIGH | Generated findings with evidence, recommendations, and system metadata |
| Baseline snapshots | HIGH | Historical system state including file hashes, services, users, packages, and configuration |
| Module code | HIGH | Security audit logic that determines what is checked and how findings are classified |
| Plugin code | HIGH | Third-party extensions that execute with full framework privileges |
| IOC signatures | MEDIUM | Malware indicators and threat signatures used for detection |

### Secondary Assets

| Asset | Sensitivity | Description |
|-------|-------------|-------------|
| Log files | MEDIUM | Operational logs with timestamps and module execution details |
| Temp files | LOW | Ephemeral working files created during scans |
| Framework source code | MEDIUM | The sentinel CLI and library implementations |

## Threat Agents

### 1. Malicious Insider

**Capability:** High - has legitimate access to the system

**Motivation:** Cover tracks, disable security auditing, exfiltrate data

**Access:** User-level or root-level

**Scenarios:**
- Disabling specific modules to avoid detection
- Modifying ignore lists to suppress findings
- Tampering with baseline snapshots to hide changes
- Altering scan results before they are reviewed

### 2. External Attacker (Post-Compromise)

**Capability:** Medium-High - gained access through exploitation

**Motivation:** Persist undetected, disable security controls

**Access:** Variable, may escalate to root

**Scenarios:**
- Modifying sentinel source code to skip certain checks
- Installing malicious plugins that report false negatives
- Exfiltrating scan results to understand defense posture
- Replacing the sentinel binary with a trojanized version

### 3. Supply Chain Attacker

**Capability:** High - controls upstream dependencies

**Motivation:** Inject backdoors, weaken security checks

**Access:** Controls module/plugin distribution channels

**Scenarios:**
- Publishing malicious plugins that appear legitimate
- Compromising module repositories
- Tampering with release artifacts

### 4. Automated Threats

**Capability:** Low-Medium - script-based attacks

**Motivation:** Opportunistic exploitation

**Access:** Limited, typically unauthenticated

**Scenarios:**
- Exploiting misconfigurations that sentinel identifies but cannot remediate
- Race conditions between scan and remediation

## Attack Vectors

### 1. Supply Chain Attacks

**Vector:** Malicious code injection through modules, plugins, or framework updates

**Risk:** HIGH

**Attack scenarios:**
- Malicious plugin that silently suppresses findings
- Backdoored module that reports false negatives for specific conditions
- Compromised library dependency

**Mitigations:**
- All plugins are validated before loading (shebang, required exports, run() function)
- Module code is self-contained in `modules/*/main.sh` with no external dependencies
- Framework uses `readonly` for critical constants to prevent runtime modification
- `--update` command verifies repository authenticity via git
- No dynamic code execution (`eval`, `exec`) in the framework

### 2. Configuration Manipulation

**Vector:** Tampering with configuration files to alter scan behavior

**Risk:** MEDIUM

**Attack scenarios:**
- Adding legitimate paths to `ignore.conf` to skip scanning
- Disabling modules in `modules.conf`
- Modifying severity thresholds to suppress low-level findings
- Changing report output directory to prevent review

**Mitigations:**
- Configuration files use INI format with clear comments
- `sentinel doctor` checks configuration integrity
- Baselines capture configuration state for comparison
- Ignore lists are documented and version-controlled
- Default ignore list only contains standard system paths

### 3. Output Tampering

**Vector:** Modifying scan results or reports after generation

**Risk:** HIGH

**Attack scenarios:**
- Editing JSON reports to remove findings before review
- Modifying the `reports/` directory permissions
- Overwriting scan files with sanitized versions
- Intercepting report output during generation

**Mitigations:**
- Scan results include timestamps and hostname for integrity verification
- Results are written atomically (write to temp, then rename)
- `reports/` directory permissions can be hardened (owned by root, mode 700)
- JSON reports include scan metadata for tamper detection
- Off-system forwarding of results is recommended

### 4. Privilege Abuse

**Vector:** Sentinel requires elevated privileges for comprehensive scanning

**Risk:** HIGH

**Attack scenarios:**
- Running sentinel as root unnecessarily
- Exploiting the scanning framework to access sensitive files
- Using sentinel's file enumeration capabilities for reconnaissance

**Mitigations:**
- Sentinel scans read-only by default (never modifies system state)
- No `eval`, `exec`, or dynamic code execution in scan logic
- Temporary files are created with restrictive permissions (`mktemp -d`)
- Temp directory is cleaned up via EXIT trap on all exit paths
- Module timeout prevents runaway scans
- `--severity` filter limits scan scope

### 5. Information Disclosure

**Vector:** Scan results contain sensitive system information

**Risk:** MEDIUM

**Attack scenarios:**
- Scan results exposed on shared filesystem
- Reports written to world-readable directories
- Log files containing sensitive configuration details
- Baseline files exposing system state to unauthorized users

**Mitigations:**
- Default report directory is project-local (`reports/`)
- JSON escaping prevents injection in output
- No passwords or secrets are included in scan results
- `--quiet` mode reduces information in terminal output
- File permissions on reports default to user-only

### 6. Denial of Service

**Vector:** Resource exhaustion through scan operations

**Risk:** LOW

**Attack scenarios:**
- Recursive filesystem scans consuming excessive I/O
- Module timeouts causing long-running processes
- Large baseline comparisons consuming memory
- Multiple concurrent scans competing for resources

**Mitigations:**
- Per-module timeouts (`configs/modules.conf`)
- Total scan timeout (`total_timeout = 3600`)
- File depth limits (`max_depth = 10`)
- File size limits (`max_file_size = 104857600`)
- Excluded paths reduce scan scope (`/proc`, `/sys`, `/dev`, `/run`)
- `--threads` limits parallel execution

## Mitigations

### Read-Only Default

Sentinel's scanning operations never modify the system:

- No files are created (except reports and baselines in designated directories)
- No configurations are changed
- No services are started or stopped
- No packages are installed or removed
- File permissions are queried but never set

The only write operations are:
1. Writing scan results to `reports/`
2. Writing baseline snapshots to `baselines/`
3. Writing log files to configured log location
4. Creating temp files in `SENTINEL_TEMP_DIR` (cleaned on exit)

### Input Validation

All external inputs are validated before use:

- **CLI arguments** - Parsed with explicit option matching; unknown options cause immediate exit
- **Config values** - `validate_config_value()` checks type (boolean, integer, string, path)
- **File paths** - `validate_path()` and `validate_file()` check existence and readability
- **Severity levels** - `validate_severity()` checks against known values
- **Ports** - `validate_port()` validates range 1-65535
- **User input** - `sanitize_input()` strips null bytes, CR, ANSI escapes, and control characters
- **Filenames** - `sanitize_filename()` strips path separators and dangerous characters

### Permission Checks

Before performing operations:

- `command_exists()` verifies required tools are available
- `is_root()` / `require_root()` enforces privilege requirements
- File readability is checked before access
- Write permissions are verified before output operations

### Shell Security

- `set -Eeuo pipefail` enforced in all files
- `IFS=$'\n\t'` prevents word-splitting attacks
- All variables are quoted to prevent glob expansion
- `[[ ]]` used instead of `[ ]` for safer tests
- No `eval` or `exec` with user-controlled input
- No temporary files in predictable locations (`mktemp -d -t "sentinel.XXXXXX"`)
- ERR traps with line numbers for debugging

### Temp File Handling

```bash
# Temp directory created with random suffix
SENTINEL_TEMP_DIR="$(mktemp -d -t "sentinel.XXXXXX" 2>/dev/null || mktemp -d)"

# Cleanup guaranteed on any exit
trap '_cleanup' EXIT

_cleanup() {
    if [[ -d "${SENTINEL_TEMP_DIR:-}" ]]; then
        rm -rf "${SENTINEL_TEMP_DIR}" 2>/dev/null || true
    fi
}
```

## Security Principles

### 1. Least Privilege

- Sentinel runs with the privileges of the invoking user
- `require_root()` explicitly requests root only when needed
- Modules should not require root unless absolutely necessary
- Plugins run in the same process as the framework (no privilege separation)

### 2. Defense in Depth

Multiple layers of protection:

1. Input validation at CLI, config, and module levels
2. Shell strict mode prevents silent failures
3. Error traps catch unexpected conditions
4. Temp file cleanup prevents residual data
5. Read-only scanning prevents system modification
6. Module isolation through function scoping

### 3. Separation of Concerns

- CLI parsing is separate from scan logic
- Library code is separate from module code
- Configuration is separate from code
- Findings are accumulated separately from display
- Report generation is separate from scan execution

### 4. Fail-Safe Defaults

- All modules enabled by default (comprehensive scanning)
- Severity threshold starts at INFO (maximum visibility)
- Output format defaults to text (human-readable)
- Color output auto-detected (respects NO_COLOR)
- Ignore list contains standard system paths (safe defaults)

### 5. Audit Trail

- All scan results are timestamped with UTC ISO-8601
- Scan metadata includes hostname, user, kernel, architecture
- Log files record module execution with timestamps
- Baseline snapshots are immutable once created
- Finding IDs are sequential and permanent within a scan

## Trust Boundaries

```
+-----------------------------------------------------+
|                    User Input                        |
|  CLI arguments, config files, environment variables  |
+--------------------------+--------------------------+
                           | VALIDATION
+--------------------------v--------------------------+
|                 Sentinel Framework                   |
|  +-------------+  +----------+  +---------------+   |
|  |  CLI Parser  |  |  Config  |  |   Lib Layer   |  |
|  +------+------+  +----+-----+  +------+--------+  |
|         |              |               |             |
|  +------v--------------v---------------v--------+   |
|  |              Module Execution                 |   |
|  |  Modules source files, query system state     |   |
|  +----------------------+-----------------------+   |
|                         |                           |
|  +----------------------v-----------------------+   |
|  |           Finding Collection                  |   |
|  |  add_finding() accumulates results            |   |
|  +----------------------+-----------------------+   |
+-------------------------+---------------------------+
                          | OUTPUT
+-------------------------v---------------------------+
|              Report Generation                       |
|  Write to reports/, stdout, or file                   |
+-----------------------------------------------------+
```

### Trust Assumptions

1. **The shell environment is trusted** - Sentinel assumes Bash itself and core utilities (grep, awk, find, stat) are not compromised
2. **The filesystem is trusted for reading** - Modules read `/etc/passwd`, `/proc/*`, configuration files, etc.
3. **The user invoking Sentinel is trusted** - CLI arguments and config are taken at face value
4. **Module code is trusted** - Modules are sourced into the same process; a malicious module has full access
5. **Plugin code requires explicit trust** - Plugins are validated but execute with full privileges

### Trust Boundaries Crossed

| Boundary | Direction | Risk |
|----------|-----------|------|
| User to Framework | Inbound | Malicious CLI args, tampered configs |
| Framework to Modules | Inbound | Malicious module code (supply chain) |
| Framework to Plugins | Inbound | Malicious plugin code (supply chain) |
| Modules to System | Outbound | Read-only queries (low risk) |
| Framework to Reports | Outbound | Sensitive data exposure |

## Assumptions and Limitations

### Assumptions

1. The system is running a supported Linux distribution
2. Bash 4.0+ is available
3. Standard coreutils are present and not compromised
4. The user has appropriate permissions for the scan scope
5. No kernel-level rootkits are actively subverting system calls

### Limitations

1. **No real-time monitoring** - Sentinel performs point-in-time scans, not continuous monitoring
2. **Read-only by design** - Cannot remediate findings automatically
3. **Module trust** - No sandboxing of module code; modules run in the same process
4. **Plugin trust** - Plugins execute with full framework privileges; no isolation
5. **No encrypted transport** - Scan results are written to local filesystem; no built-in SIEM forwarding encryption
6. **Bash limitations** - Complex parsing or network operations are less reliable than Python/Go alternatives
7. **Concurrent scan safety** - No file locking on reports directory; concurrent scans may produce interleaved output
8. **Baseline drift** - Baselines capture state at a point in time; system changes between creation and comparison are not tracked
9. **False positives** - Modules report all findings; tuning requires ignore lists and severity filtering
10. **No authentication** - Sentinel does not authenticate users; access control relies on filesystem permissions

### Known Risks

| Risk | Severity | Mitigation Status |
|------|----------|-------------------|
| Malicious module code execution | HIGH | Mitigated by source code review, no external module repos |
| Scan result tampering | HIGH | Partially mitigated (timestamps, but no cryptographic signing) |
| Temp file residual data | LOW | Mitigated by EXIT trap cleanup |
| Resource exhaustion during scan | LOW | Mitigated by timeouts and depth limits |
