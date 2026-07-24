# QYVORA Sentinel - Module Development Guide

> This guide covers everything needed to develop, test, and integrate security audit modules for QYVORA Sentinel.

## Module Directory Structure

Each module is a self-contained directory under `modules/`:

```
modules/
└── mymodule/
    └── main.sh
```

The `main.sh` file is the single required file. Modules are discovered automatically by scanning `modules/*/main.sh`.

## Required Exports

Every module **must** export these variables at the top of `main.sh`:

```bash
readonly MODULE_NAME="mymodule"
readonly MODULE_DESCRIPTION="What this module checks"
readonly MODULE_VERSION="1.0.0"
readonly MODULE_SEVERITY_THRESHOLD="INFO"
```

| Export | Type | Required | Description |
|--------|------|----------|-------------|
| `MODULE_NAME` | `readonly string` | Yes | Unique identifier (must match directory name) |
| `MODULE_DESCRIPTION` | `readonly string` | Yes | Human-readable description shown in module listings |
| `MODULE_VERSION` | `readonly string` | Yes | Semantic version string |
| `MODULE_SEVERITY_THRESHOLD` | `readonly string` | Yes | Minimum severity this module reports (INFO, LOW, MEDIUM, HIGH, CRITICAL). Modules with a threshold above the user's `--severity` filter are skipped entirely. |

## Required Function: `run()`

Every module **must** define a `run()` function. This is the entry point called by the framework:

```bash
run() {
    # Module scan logic goes here
    # Call add_finding() to record findings
    # Use print_* functions for terminal output
    return 0
}
```

The `run()` function must be defined **at the top level** of the module file (not inside a subshell or conditional). The framework verifies its existence via `declare -f run` after sourcing.

## Standard Module Template

```bash
#!/usr/bin/env bash
set -Eeuo pipefail
IFS=$'\n\t'

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
LIB_DIR="${SCRIPT_DIR}/../../lib"

source "${LIB_DIR}/logger.sh"
source "${LIB_DIR}/colors.sh"
source "${LIB_DIR}/utils.sh"
source "${LIB_DIR}/output.sh"
source "${LIB_DIR}/validation.sh"
source "${LIB_DIR}/permissions.sh"
source "${LIB_DIR}/filesystem.sh"
source "${LIB_DIR}/network.sh"
source "${LIB_DIR}/process.sh"
source "${LIB_DIR}/reporting.sh"

readonly MODULE_NAME="mymodule"
readonly MODULE_DESCRIPTION="Description of what this module audits"
readonly MODULE_VERSION="1.0.0"
readonly MODULE_SEVERITY_THRESHOLD="INFO"

_my_check() {
    print_header "My Check Name"

    local result
    result=$(some_command 2>/dev/null || true)

    if [[ -n "${result}" ]]; then
        add_finding "mymodule" "HIGH" "Something concerning found" \
            "Details about the finding" \
            "Remediation steps" \
            "https://reference.url"
        print_error "Concerning finding detected"
    else
        print_success "Check passed"
    fi
}

run() {
    print_header "My Module - ${MODULE_DESCRIPTION}"
    _my_check
}

# Allow running standalone for testing
if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    run
fi
```

## Available Library Functions

### Output Functions (lib/output.sh)

| Function | Usage | Description |
|----------|-------|-------------|
| `print_banner` | `print_banner` | Display the QYVORA Sentinel banner |
| `print_header` | `print_header "Title"` | Box-drawn section header |
| `print_subheader` | `print_subheader "Subtitle"` | Arrow-prefixed subsection header |
| `print_finding` | `print_finding "SEVERITY" "message"` | Severity-colored finding line |
| `print_success` | `print_success "message"` | Green checkmark message |
| `print_warning` | `print_warning "message"` | Yellow warning message |
| `print_error` | `print_error "message"` | Red cross message (to stderr) |
| `print_info` | `print_info "message"` | Blue bullet message |
| `print_separator` | `print_separator [width]` | Horizontal line |
| `print_progress` | `print_progress current total "message"` | Progress bar |
| `print_table_header` | `print_table_header "col1" "col2"` | Formatted table header |
| `print_table_row` | `print_table_row "val1" "val2"` | Formatted table row |
| `print_summary` | `print_summary "key=value" ...` | Severity-coded summary |
| `print_risk_score` | `print_risk_score 42` | Color-coded risk score display |

### Logging Functions (lib/logger.sh)

| Function | Usage | Description |
|----------|-------|-------------|
| `log_debug` | `log_debug "message"` | Debug-level log (only with `--debug`) |
| `log_info` | `log_info "message"` | Informational log |
| `log_warning` | `log_warning "message"` | Warning-level log |
| `log_error` | `log_error "message"` | Error-level log |
| `log_fatal` | `log_fatal "message"` | Fatal log + exit 1 |
| `log_set_level` | `log_set_level "debug"` | Change log level at runtime |
| `log_set_file` | `log_set_file "/path/to/log"` | Enable file logging |

### Validation Functions (lib/validation.sh)

| Function | Returns | Description |
|----------|---------|-------------|
| `validate_path "path"` | 0/1 | Path exists |
| `validate_directory "path"` | 0/1 | Directory exists |
| `validate_file "path"` | 0/1 | File exists and is readable |
| `validate_command "cmd"` | 0/1 | Command exists and is safe |
| `validate_severity "level"` | 0/1 | Valid severity level |
| `validate_port "port"` | 0/1 | Valid port number (1-65535) |
| `validate_url "url"` | 0/1 | Valid HTTP/HTTPS URL |
| `validate_output_format "fmt"` | 0/1 | Valid output format |
| `validate_config_value "val" "type"` | 0/1 | Value matches type (boolean/integer/string/path) |
| `sanitize_input "input"` | string | Strip null bytes, CR, ANSI escapes, control chars |

### Utility Functions (lib/utils.sh)

| Function | Returns | Description |
|----------|---------|-------------|
| `command_exists "cmd"` | 0/1 | Check if command is available |
| `require_command "cmd"` | 0/1 | Check + log error if missing |
| `is_root` | 0/1 | Check if running as root |
| `require_root` | exit | Exit with error if not root |
| `get_os` | string | OS identifier (ubuntu, rhel, arch, etc.) |
| `get_os_family` | string | OS family (debian, rhel, arch, alpine, suse) |
| `get_kernel_version` | string | Kernel version string |
| `get_arch` | string | Normalized architecture (x86_64, aarch64, etc.) |
| `get_hostname` | string | System hostname |
| `get_uptime` | string | System uptime |
| `get_pid_count` | number | Running process count |
| `generate_uuid` | string | Generate UUID |
| `retry N delay cmd...` | 0/1 | Retry command with delay |
| `timeout secs cmd...` | 0/124 | Run command with timeout |
| `temp_dir_create [prefix]` | path | Create managed temp directory |
| `temp_dir_cleanup` | - | Remove all managed temp dirs |
| `sanitize_filename "name"` | string | Safe filename string |
| `file_age_seconds "path"` | number | File age in seconds |
| `human_readable_size bytes` | string | e.g., "42MB" |

### Permission Functions (lib/permissions.sh)

| Function | Returns | Description |
|----------|---------|-------------|
| `check_file_permissions "path"` | detailed | Full permission analysis output |
| `is_suid "path"` | 0/1 | Has SUID bit |
| `is_sgid "path"` | 0/1 | Has SGID bit |
| `is_sticky "path"` | 0/1 | Has sticky bit |
| `is_world_writable "path"` | 0/1 | World-writable |
| `is_symlink "path"` | 0/1 | Is a symbolic link |
| `is_broken_symlink "path"` | 0/1 | Symlink target missing |
| `find_suid_files` | list | Find all SUID files |

### Hashing Functions (lib/hashing.sh)

| Function | Returns | Description |
|----------|---------|-------------|
| `hash_sha256 "file"` | hash | SHA-256 hash |
| `hash_md5 "file"` | hash | MD5 hash |

### Reporting Functions (lib/reporting.sh)

| Function | Description |
|----------|-------------|
| `add_finding "module" "severity" "title" "description" ["evidence"] ["recommendation"] ["reference"]` | Record a finding |
| `clear_findings` | Reset all findings |
| `get_findings_count` | Total finding count |
| `get_findings_by_severity "SEV"` | List finding IDs by severity |
| `get_findings_by_module "mod"` | List finding IDs by module |
| `calculate_risk_score` | Compute risk score (0-100) |
| `generate_report_text [file]` | Generate text report |
| `generate_report_json [file]` | Generate JSON report |
| `generate_report_markdown [file]` | Generate Markdown report |
| `generate_report_html [file]` | Generate HTML report |

## Finding Creation

### add_finding() Signature

```bash
add_finding "module" "severity" "title" "description" ["evidence"] ["recommendation"] ["reference"]
```

**Parameters:**

| Position | Required | Description |
|----------|----------|-------------|
| 1 | Yes | Module name (typically `MODULE_NAME`) |
| 2 | Yes | Severity: `INFO`, `LOW`, `MEDIUM`, `HIGH`, `CRITICAL` |
| 3 | Yes | Short title describing the finding |
| 4 | Yes | Detailed description |
| 5 | No | Evidence (command output, file content, etc.) |
| 6 | No | Remediation recommendation |
| 7 | No | External reference (CIS benchmark, CVE, etc.) |

### Examples

```bash
# Simple informational finding
add_finding "${MODULE_NAME}" "INFO" "SSH service running" "sshd is active on this system"

# Finding with evidence and recommendation
add_finding "${MODULE_NAME}" "HIGH" \
    "Root login permitted via SSH" \
    "PermitRootLogin is set to 'yes' in /etc/ssh/sshd_config" \
    "$(grep PermitRootLogin /etc/ssh/sshd_config)" \
    "Set PermitRootLogin to 'no' in sshd_config and restart sshd" \
    "CIS Ubuntu 20.04 - 5.2.10"

# Finding with just a title
add_finding "${MODULE_NAME}" "CRITICAL" "World-writable /etc/passwd"
```

## Severity Levels

| Level | When to Use | Example |
|-------|-------------|---------|
| `INFO` | Informational observations, system state recording | "SSH service is running", "Kernel version 5.15.0" |
| `LOW` | Minor security concerns, hardening suggestions | "X11Forwarding enabled", "MaxAuthTries above 6" |
| `MEDIUM` | Security issues that should be addressed | "Password authentication enabled for SSH", "World-writable files in /etc" |
| `HIGH` | Significant security risks requiring prompt action | "Root login permitted via SSH", "SUID binary in unexpected location" |
| `CRITICAL` | Critical vulnerabilities requiring immediate response | "Non-root UID 0 account detected", "Backdoor persistence mechanism found" |

**Guidelines:**
- Use `INFO` for status reporting (tool versions, config values, counts)
- Use `LOW` for informational security observations
- Use `MEDIUM` for misconfigurations with security impact
- Use `HIGH` for exploitable weaknesses or policy violations
- Use `CRITICAL` for active compromise indicators or rootkit-like behavior

## Module Lifecycle

```
Discovery → Load → Validate → Run → Report → (Cleanup)
```

### 1. Discovery

`_discover_modules()` scans `modules/*/main.sh` and populates `SENTINEL_MODULE_REGISTRY`.

### 2. Filter Check

`_is_module_enabled()` checks `--module`, `--exclude`, `--include` flags.

### 3. Load

`_load_module()` unsets previous state and sources `main.sh`.

### 4. Validate

Framework verifies `MODULE_NAME` is set and `run()` is defined.

### 5. Severity Gate

`_severity_meets_threshold()` compares module threshold against `--severity` filter.

### 6. Run

`run()` is called. The module executes its checks and calls `add_finding()`.

### 7. Report

Findings are accumulated in the global `SENTINEL_FINDINGS` array and `SENTINEL_FINDING_COUNTS`.

### 8. Cleanup

`SENTINEL_CURRENT_MODULE` is reset. Module-specific temp files should be cleaned up by the module itself.

## Testing Modules Independently

Every module should include the standalone execution guard:

```bash
if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    run
fi
```

This allows direct execution for testing:

```bash
# Run the module directly
./modules/ssh/main.sh

# Test with library path available
LIB_DIR=./lib bash modules/ssh/main.sh
```

## Best Practices

### 1. Always Source Required Libraries

Source all needed libraries at the top of your module. This makes the module self-contained and testable:

```bash
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
LIB_DIR="${SCRIPT_DIR}/../../lib"
source "${LIB_DIR}/logger.sh"
source "${LIB_DIR}/output.sh"
# ... etc.
```

### 2. Guard External Commands

Always check that required commands exist before using them:

```bash
if command -v ss &>/dev/null; then
    ss -tulnp
elif command -v netstat &>/dev/null; then
    netstat -tulnp
else
    print_warning "Neither ss nor netstat available"
fi
```

### 3. Capture Errors Gracefully

Use `|| true` or `|| exit_code=$?` for commands that might fail:

```bash
local result
result=$(dangerous_command 2>/dev/null || true)
```

### 4. Use Private Functions

Prefix internal functions with underscore to signal they are not part of the public API:

```bash
_my_internal_check() { ... }
_another_check() { ... }
run() {
    _my_internal_check
    _another_check
}
```

### 5. Provide Meaningful Findings

Each finding should be actionable:

- **Title**: concise and descriptive
- **Description**: explain what was found and why it matters
- **Evidence**: raw data supporting the finding
- **Recommendation**: specific remediation steps
- **Reference**: external standards (CIS, NIST, CVE)

### 6. Respect Quiet Mode

The framework checks `SENTINEL_CLI_ARGS[quiet]` before printing. Module-level output should respect this:

```bash
if [[ "${SENTINEL_CLI_ARGS[quiet]:-false}" != "true" ]]; then
    print_header "My Check"
fi
```

### 7. Use Consistent Module Names

`MODULE_NAME` should match the directory name and use lowercase letters only.

### 8. Set Appropriate Severity Thresholds

Set `MODULE_SEVERITY_THRESHOLD` to the lowest severity your module can produce. If your module only produces `MEDIUM` and above, set it to `MEDIUM` to avoid being filtered out unnecessarily.

## Complete Example Module

```bash
#!/usr/bin/env bash
# modules/example/main.sh
# Example security audit module for QYVORA Sentinel

set -Eeuo pipefail
IFS=$'\n\t'

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
LIB_DIR="${SCRIPT_DIR}/../../lib"

source "${LIB_DIR}/logger.sh"
source "${LIB_DIR}/colors.sh"
source "${LIB_DIR}/utils.sh"
source "${LIB_DIR}/output.sh"
source "${LIB_DIR}/validation.sh"
source "${LIB_DIR}/permissions.sh"
source "${LIB_DIR}/filesystem.sh"
source "${LIB_DIR}/network.sh"
source "${LIB_DIR}/process.sh"
source "${LIB_DIR}/reporting.sh"

readonly MODULE_NAME="example"
readonly MODULE_DESCRIPTION="Example security audit module"
readonly MODULE_VERSION="1.0.0"
readonly MODULE_SEVERITY_THRESHOLD="INFO"

_check_password_policy() {
    print_header "Password Policy Check"

    if [[ ! -f /etc/login.defs ]]; then
        print_warning "Cannot read /etc/login.defs"
        return 0
    fi

    local max_days
    max_days=$(awk '/^PASS_MAX_DAYS/ {print $2}' /etc/login.defs 2>/dev/null || echo "99999")

    if [[ "${max_days}" -gt 90 ]]; then
        add_finding "${MODULE_NAME}" "MEDIUM" \
            "Password maximum age is too long" \
            "PASS_MAX_DAYS is set to ${max_days} days (recommended: 90 or less)" \
            "Current value: $(grep '^PASS_MAX_DAYS' /etc/login.defs)" \
            "Set PASS_MAX_DAYS to 90 or less in /etc/login.defs" \
            "CIS Distribution Independent Linux - 5.4.1.1"
        print_warning "PASS_MAX_DAYS: ${max_days} (should be <= 90)"
    else
        add_finding "${MODULE_NAME}" "INFO" \
            "Password maximum age is acceptable" \
            "PASS_MAX_DAYS is set to ${max_days} days"
        print_success "PASS_MAX_DAYS: ${max_days} (OK)"
    fi
}

_check_umask() {
    print_header "Default Umask Check"

    local umask_value
    umask_value=$(umask 2>/dev/null | tail -1 || echo "0022")

    if [[ "${umask_value}" == "0027" ]] || [[ "${umask_value}" == "027" ]]; then
        add_finding "${MODULE_NAME}" "INFO" \
            "Default umask is secure" \
            "Current umask: ${umask_value}"
        print_success "Umask: ${umask_value} (OK)"
    else
        add_finding "${MODULE_NAME}" "MEDIUM" \
            "Default umask is not restrictive enough" \
            "Current umask: ${umask_value} (recommended: 027 or 077)" \
            "Set umask to 027 or more restrictive in /etc/profile" \
            "CIS Distribution Independent Linux - 5.4.4"
        print_warning "Umask: ${umask_value} (should be 027 or 077)"
    fi
}

run() {
    print_header "Example Module - ${MODULE_DESCRIPTION}"
    _check_password_policy
    _check_umask
}

if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    run
fi
```
