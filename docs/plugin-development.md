# QYVORA Sentinel - Plugin Development Guide

> Plugins extend QYVORA Sentinel with custom functionality without modifying core code. This guide covers plugin creation, lifecycle, and best practices.

## Plugin Directory

Plugins live in the `plugins/` directory at the project root:

```
plugins/
├── my-plugin.sh          # Flat plugin file
└── another-plugin/
    └── main.sh           # Directory-based plugin
```

**Note:** The current plugin loader (`lib/plugin_loader.sh`) scans for `plugins/*.sh` files. Directory-based plugins (`plugins/name/main.sh`) are supported by the CLI `plugins` command but use a different discovery path than the loader's flat scan.

## Plugin File Structure

Every plugin is a single Bash file that follows this structure:

```bash
#!/usr/bin/env bash
# plugins/my-plugin.sh - Brief description of what this plugin does

set -Eeuo pipefail
IFS=$'\n\t'

# ---------------------------------------------------------------------------
# Required metadata exports
# ---------------------------------------------------------------------------
readonly PLUGIN_NAME="my-plugin"
readonly PLUGIN_VERSION="1.0.0"
readonly PLUGIN_AUTHOR="Your Name"
readonly PLUGIN_DESCRIPTION="Detailed description of what this plugin does"

# ---------------------------------------------------------------------------
# Optional configuration
# ---------------------------------------------------------------------------
readonly PLUGIN_DEFAULT_ARG="value"

# ---------------------------------------------------------------------------
# Required: run() function
# ---------------------------------------------------------------------------
run() {
    # Your plugin logic here
    # Access all Sentinel library functions
    # Use add_finding() to contribute findings
    # Accept arguments: $1, $2, etc.
    return 0
}
```

## Required Exports

| Export | Type | Required | Description |
|--------|------|----------|-------------|
| `PLUGIN_NAME` | `readonly string` | Yes | Unique plugin identifier (lowercase, hyphens allowed) |
| `PLUGIN_VERSION` | `readonly string` | Yes | Semantic version (e.g., `1.0.0`, `2.1.3-beta`) |
| `PLUGIN_AUTHOR` | `readonly string` | Yes | Author name or organization |
| `PLUGIN_DESCRIPTION` | `readonly string` | Yes | Human-readable description |

## Required Function: `run()`

The `run()` function is the entry point. It receives any arguments passed by `plugin_run()`:

```bash
run() {
    local target="${1:-/}"
    local mode="${2:-quick}"

    log_info "Running my-plugin against ${target} in ${mode} mode"

    # Check for a required command
    if ! command_exists "mytool"; then
        log_error "Required command 'mytool' not found"
        return 1
    fi

    # Perform checks
    local result
    result=$(mytool --check "${target}" 2>/dev/null || true)

    if [[ -n "${result}" ]]; then
        add_finding "${PLUGIN_NAME}" "MEDIUM" "Issue detected" "${result}"
        return 0
    fi

    log_info "No issues found"
    return 0
}
```

**Return values:**
- `0` - Success (findings may have been recorded)
- Non-zero - Error (logged by the framework)

## Plugin Lifecycle

```
1. Discovery    plugin_scan() finds plugins/*.sh
       │
2. Validation   plugin_validate() checks shebang, exports, run()
       │
3. Loading      plugin_load() sources file, registers metadata
       │
4. Execution    plugin_run("name", args...) calls run()
       │
5. Querying     plugin_info() / plugin_list() inspect loaded plugins
       │
6. Unloading    plugin_unload("name") removes tracking
```

### 1. Discovery

`plugin_scan()` scans the plugin directory for `.sh` files and validates each one:

```bash
plugin_scan   # Returns list of valid plugin file paths
```

### 2. Validation

`plugin_validate()` checks three things:

1. **Shebang** - file must start with `#!/usr/bin/env bash` or `#!/bin/bash`
2. **Required exports** - `PLUGIN_NAME`, `PLUGIN_VERSION`, `PLUGIN_AUTHOR`, `PLUGIN_DESCRIPTION` must be defined (via `readonly`, `declare -r`, or plain assignment)
3. **Required function** - `run()` must be defined

```bash
plugin_validate "/path/to/plugin.sh"   # Returns 0/1
```

### 3. Loading

`plugin_load()` sources the plugin file and registers its metadata in global arrays:

```bash
plugin_load "/path/to/plugin.sh"
```

After loading, the plugin is tracked in:

| Array | Content |
|-------|---------|
| `SENTINEL_LOADED_PLUGINS` | Ordered list of loaded plugin names |
| `SENTINEL_PLUGIN_NAMES[name]` | Plugin name |
| `SENTINEL_PLUGIN_PATHS[name]` | File path |
| `SENTINEL_PLUGIN_VERSIONS[name]` | Version |
| `SENTINEL_PLUGIN_AUTHORS[name]` | Author |
| `SENTINEL_PLUGIN_DESCRIPTIONS[name]` | Description |
| `SENTINEL_PLUGIN_ENABLED[name]` | Enabled flag (1/0) |

### 4. Execution

```bash
plugin_run "my-plugin" "arg1" "arg2"
```

The framework:
1. Verifies the plugin is loaded and enabled
2. Calls `run()` with the provided arguments
3. Captures the exit code
4. Logs the result

### 5. Unloading

```bash
plugin_unload "my-plugin"
```

**Note:** Since Bash sources plugin files into the current shell, truly unloading functions is not possible. `plugin_unload()` removes the tracking metadata and marks the plugin as unloaded, but any global variables or functions defined by the plugin remain in memory.

## Access to Sentinel Libraries

Plugins have full access to all Sentinel library functions. The libraries are already sourced when plugins run. Available functions include:

```bash
# Logging
log_debug "message"
log_info "message"
log_warning "message"
log_error "message"

# Output
print_header "Title"
print_finding "SEVERITY" "message"
print_success "message"
print_warning "message"
print_error "message"

# Findings
add_finding "module" "severity" "title" "description" ["evidence"] ["rec"] ["ref"]

# Validation
validate_path "/some/path"
validate_port "443"
validate_url "https://example.com"

# Utilities
command_exists "docker"
get_os
get_hostname
retry 3 2 command arg1 arg2

# Configuration
config_get "section.key" "default"

# Hashing
hash_sha256 "/some/file"
hash_md5 "/some/file"

# Permissions
is_suid "/some/file"
is_world_writable "/some/dir"
```

## Plugin Registration and Discovery

### Automatic Discovery

The plugin loader scans the configured plugin directory (default: `plugins/`) for `*.sh` files at startup. Valid plugins are automatically loaded.

### Plugin Directory Configuration

The plugin directory can be configured in `configs/sentinel.conf`:

```ini
[plugins]
plugin_dir = /usr/share/sentinel/plugins
enabled = true
```

Or overridden at runtime:

```bash
export SENTINEL_PLUGIN_DIR="/custom/path"
```

### Listing Loaded Plugins

```bash
sentinel plugins         # CLI command
plugin_list              # Library function
```

## Plugin Arguments and Return Values

### Passing Arguments

Arguments are passed through `plugin_run()`:

```bash
plugin_run "my-plugin" "/target/path" "--deep"
```

Inside the plugin's `run()`:

```bash
run() {
    local target="${1:-/}"
    local deep_mode="${2:-}"

    if [[ "${deep_mode}" == "--deep" ]]; then
        # Deep scan logic
    fi
}
```

### Return Values

- Return `0` for success
- Return non-zero for errors
- The exit code is captured and logged by the framework
- Findings are recorded via `add_finding()` regardless of return code

### Error Handling in Plugins

```bash
run() {
    # Check prerequisites
    if ! command_exists "required-tool"; then
        log_warning "required-tool not available, skipping check"
        return 0  # Don't fail the whole scan
    fi

    # Guard against failures
    local result
    result=$(risky_command 2>/dev/null) || {
        log_error "Failed to execute risky_command"
        return 1
    }

    return 0
}
```

## Example Plugin

```bash
#!/usr/bin/env bash
# plugins/docker-audit.sh - Enhanced Docker security audit plugin

set -Eeuo pipefail
IFS=$'\n\t'

readonly PLUGIN_NAME="docker-audit"
readonly PLUGIN_VERSION="1.0.0"
readonly PLUGIN_AUTHOR="Security Team"
readonly PLUGIN_DESCRIPTION="Extended Docker security checks beyond the built-in module"

_check_docker_daemon_config() {
    local config_file="/etc/docker/daemon.json"

    if [[ ! -f "${config_file}" ]]; then
        add_finding "${PLUGIN_NAME}" "INFO" \
            "Docker daemon config not found" \
            "No daemon.json found at ${config_file}"
        return 0
    fi

    # Check for insecure registries
    if grep -q '"insecure-registries"' "${config_file}" 2>/dev/null; then
        local insecure
        insecure=$(grep '"insecure-registries"' "${config_file}")
        add_finding "${PLUGIN_NAME}" "HIGH" \
            "Docker has insecure registries configured" \
            "Insecure registries found in daemon.json" \
            "${insecure}" \
            "Remove insecure-registries or use TLS certificates"
    fi

    # Check for live-restore
    if ! grep -q '"live-restore".*true' "${config_file}" 2>/dev/null; then
        add_finding "${PLUGIN_NAME}" "LOW" \
            "Docker live-restore not enabled" \
            "Consider enabling live-restore for zero-downtime daemon upgrades" \
            "" \
            "Add \"live-restore\": true to daemon.json"
    fi
}

_check_running_containers() {
    if ! command_exists docker; then
        log_warning "Docker not installed, skipping container checks"
        return 0
    fi

    local container_count
    container_count=$(docker ps -q 2>/dev/null | wc -l || echo 0)

    if [[ "${container_count}" -eq 0 ]]; then
        add_finding "${PLUGIN_NAME}" "INFO" \
            "No running Docker containers" \
            "Container count: 0"
        return 0
    fi

    # Check for privileged containers
    local privileged
    privileged=$(docker ps --quiet --format '{{.ID}} {{.Names}}' 2>/dev/null | \
        while read -r id name; do
            if docker inspect "${id}" --format '{{.HostConfig.Privileged}}' 2>/dev/null | grep -q "true"; then
                echo "${name}"
            fi
        done)

    if [[ -n "${privileged}" ]]; then
        add_finding "${PLUGIN_NAME}" "CRITICAL" \
            "Privileged Docker containers detected" \
            "The following containers run in privileged mode" \
            "${privileged}" \
            "Remove --privileged flag or use specific capabilities" \
            "https://docs.docker.com/engine/reference/run/#runtime-privilege-and-linux-capabilities"
    fi

    # Check for containers running as root
    local root_containers=""
    root_containers=$(docker ps --quiet --format '{{.ID}} {{.Names}}' 2>/dev/null | \
        while read -r id name; do
            local user
            user=$(docker exec "${id}" id -u 2>/dev/null || echo "0")
            if [[ "${user}" == "0" ]]; then
                echo "${name}"
            fi
        done)

    if [[ -n "${root_containers}" ]]; then
        add_finding "${PLUGIN_NAME}" "MEDIUM" \
            "Containers running as root" \
            "These containers are running with UID 0" \
            "${root_containers}" \
            "Add USER directive to Dockerfile or use --user flag"
    fi
}

run() {
    print_header "Docker Audit Plugin - Extended Checks"

    _check_docker_daemon_config
    _check_running_containers

    print_success "Docker audit plugin completed"
}

if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    run
fi
```

## Publishing Plugins

### Naming Convention

- Use lowercase names with hyphens: `cloud-security-scan.sh`
- Use descriptive names: `docker-audit.sh`, not `check1.sh`

### Required Documentation

Include a header comment describing the plugin:

```bash
#!/usr/bin/env bash
# Plugin: my-plugin
# Description: What this plugin does
# Author: Your Name
# Version: 1.0.0
# Dependencies: jq, curl (if needed)
# Compatible with: QYVORA Sentinel 1.0.0+
```

### Distribution

1. Place the `.sh` file in `plugins/`
2. Ensure it passes `plugin_validate()`
3. Test with `sentinel plugins` to verify listing
4. Test execution with `plugin_run "name"` or through the framework

### Security Considerations

- Plugins are sourced into the Sentinel process with full access to the shell environment
- Only load plugins from trusted sources
- Plugin files should use `readonly` for all constants
- Validate all external inputs (file paths, command output)
- Guard all external commands with existence checks
- Do not store secrets in plugin files
