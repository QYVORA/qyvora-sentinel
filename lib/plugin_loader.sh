#!/usr/bin/env bash
# plugin_loader.sh - Plugin framework for dynamic loading for QYVORA Sentinel.
# Provides discovery, validation, loading, unloading, and execution of plugins.

# Source guard - prevent re-sourcing
if [[ "${_SENTINEL_LIB_LOADED:-}" == *"$(basename "${BASH_SOURCE[0]}")"* ]]; then
    return 0 2>/dev/null || true
fi
_SENTINEL_LIB_LOADED="${_SENTINEL_LIB_LOADED:-} $(basename "${BASH_SOURCE[0]}")"

set -Eeuo pipefail
IFS=$'\n\t'

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=colors.sh
source "${SCRIPT_DIR}/colors.sh"
# shellcheck source=logger.sh
source "${SCRIPT_DIR}/logger.sh"
# shellcheck source=utils.sh
source "${SCRIPT_DIR}/utils.sh"
# shellcheck source=validation.sh
source "${SCRIPT_DIR}/validation.sh"

# --- Global State ---
SENTINEL_PLUGIN_DIR=""
declare -ga SENTINEL_LOADED_PLUGINS=()
declare -gA SENTINEL_PLUGIN_NAMES=()
declare -gA SENTINEL_PLUGIN_PATHS=()
declare -gA SENTINEL_PLUGIN_VERSIONS=()
declare -gA SENTINEL_PLUGIN_AUTHORS=()
declare -gA SENTINEL_PLUGIN_DESCRIPTIONS=()
declare -gA SENTINEL_PLUGIN_ENABLED=()

# Required plugin exports (readonly)
readonly SENTINEL_PLUGIN_REQUIRED_EXPORTS=(
    "PLUGIN_NAME"
    "PLUGIN_VERSION"
    "PLUGIN_AUTHOR"
    "PLUGIN_DESCRIPTION"
)
readonly SENTINEL_PLUGIN_REQUIRED_FUNCTION="run"

# --- Initialization ---

plugin_loader_init() {
    SENTINEL_PLUGIN_DIR="${SENTINEL_PLUGIN_DIR:-$(pwd)/plugins}"

    if [[ ! -d "${SENTINEL_PLUGIN_DIR}" ]]; then
        mkdir -p "${SENTINEL_PLUGIN_DIR}"
        log_debug "Created plugin directory: ${SENTINEL_PLUGIN_DIR}"
    fi

    log_debug "Plugin loader initialized. Plugin directory: ${SENTINEL_PLUGIN_DIR}"
}

# --- Validation ---

plugin_validate() {
    local -r plugin_path="${1}"

    if [[ ! -f "${plugin_path}" ]]; then
        log_error "Plugin file not found: ${plugin_path}"
        return 1
    fi

    if [[ ! -r "${plugin_path}" ]]; then
        log_error "Plugin file not readable: ${plugin_path}"
        return 1
    fi

    # Check shebang
    local first_line
    first_line="$(head -1 "${plugin_path}" 2>/dev/null)"
    if [[ "${first_line}" != "#!/usr/bin/env bash" && "${first_line}" != "#!/bin/bash" ]]; then
        log_error "Plugin ${plugin_path} must start with #!/usr/bin/env bash or #!/bin/bash"
        return 1
    fi

    # Check required variable exports
    local export_name
    for export_name in "${SENTINEL_PLUGIN_REQUIRED_EXPORTS[@]}"; do
        if ! grep -qE "^declare\s+-r\s+${export_name}=|^${export_name}=|readonly\s+${export_name}=" "${plugin_path}" 2>/dev/null; then
            # Also check without readonly/declare -r as some plugins may use plain assignment
            if ! grep -qE "^${export_name}=" "${plugin_path}" 2>/dev/null; then
                log_error "Plugin ${plugin_path} missing required export: ${export_name}"
                return 1
            fi
        fi
    done

    # Check required run() function exists
    if ! grep -qE '^run\s*\(\)' "${plugin_path}" 2>/dev/null; then
        log_error "Plugin ${plugin_path} missing required function: run()"
        return 1
    fi

    log_debug "Plugin validation passed: ${plugin_path}"
    return 0
}

plugin_scan() {
    local -a valid_plugins=()

    if [[ ! -d "${SENTINEL_PLUGIN_DIR}" ]]; then
        log_warning "Plugin directory does not exist: ${SENTINEL_PLUGIN_DIR}"
        printf '%s\n' "${valid_plugins[@]+"${valid_plugins[@]}"}"
        return
    fi

    local plugin_file
    for plugin_file in "${SENTINEL_PLUGIN_DIR}"/*.sh; do
        [[ -f "${plugin_file}" ]] || continue

        if plugin_validate "${plugin_file}" 2>/dev/null; then
            valid_plugins+=("${plugin_file}")
        fi
    done

    printf '%s\n' "${valid_plugins[@]+"${valid_plugins[@]}"}"
}

# --- Load / Unload ---

plugin_load() {
    local -r plugin_path="${1}"

    # Validate first
    if ! plugin_validate "${plugin_path}"; then
        return 1
    fi

    # Source the plugin in a subshell to extract metadata, then source globally
    local plugin_name plugin_version plugin_author plugin_description

    plugin_name="$(grep -E '^PLUGIN_NAME=' "${plugin_path}" | head -1 | cut -d= -f2- | tr -d '"')"
    plugin_version="$(grep -E '^PLUGIN_VERSION=' "${plugin_path}" | head -1 | cut -d= -f2- | tr -d '"')"
    plugin_author="$(grep -E '^PLUGIN_AUTHOR=' "${plugin_path}" | head -1 | cut -d= -f2- | tr -d '"')"
    plugin_description="$(grep -E '^PLUGIN_DESCRIPTION=' "${plugin_path}" | head -1 | cut -d= -f2- | tr -d '"')"

    # Check if already loaded
    if [[ -v "SENTINEL_PLUGIN_NAMES[${plugin_name}]" ]]; then
        log_warning "Plugin '${plugin_name}' is already loaded."
        return 0
    fi

    # Source the plugin file (this defines its run() function)
    # shellcheck disable=SC1090
    if ! source "${plugin_path}"; then
        log_error "Failed to source plugin: ${plugin_path}"
        return 1
    fi

    # Verify run() function is now available
    if ! declare -f "${SENTINEL_PLUGIN_REQUIRED_FUNCTION}" >/dev/null 2>&1; then
        log_error "Plugin ${plugin_path} did not define run() function after sourcing."
        return 1
    fi

    # Track the loaded plugin
    SENTINEL_LOADED_PLUGINS+=("${plugin_name}")
    SENTINEL_PLUGIN_NAMES["${plugin_name}"]="${plugin_name}"
    SENTINEL_PLUGIN_PATHS["${plugin_name}"]="${plugin_path}"
    SENTINEL_PLUGIN_VERSIONS["${plugin_name}"]="${plugin_version}"
    SENTINEL_PLUGIN_AUTHORS["${plugin_name}"]="${plugin_author}"
    SENTINEL_PLUGIN_DESCRIPTIONS["${plugin_name}"]="${plugin_description}"
    SENTINEL_PLUGIN_ENABLED["${plugin_name}"]=1

    log_info "Plugin loaded: ${plugin_name} v${plugin_version} (${plugin_author})"
    return 0
}

plugin_load_all() {
    local -r plugin_dir="${1:-${SENTINEL_PLUGIN_DIR}}"
    local loaded=0
    local failed=0

    if [[ ! -d "${plugin_dir}" ]]; then
        log_warning "Plugin directory does not exist: ${plugin_dir}"
        return 0
    fi

    log_info "Loading plugins from: ${plugin_dir}"

    local plugin_file
    for plugin_file in "${plugin_dir}"/*.sh; do
        [[ -f "${plugin_file}" ]] || continue

        if plugin_load "${plugin_file}" 2>/dev/null; then
            (( loaded++ ))
        else
            (( failed++ ))
            log_warning "Failed to load plugin: $(basename "${plugin_file}")"
        fi
    done

    log_info "Plugin loading complete: ${loaded} loaded, ${failed} failed"
}

plugin_unload() {
    local -r plugin_name="${1}"

    if [[ ! -v "SENTINEL_PLUGIN_NAMES[${plugin_name}]" ]]; then
        log_warning "Plugin '${plugin_name}' is not loaded."
        return 1
    fi

    # Note: We cannot truly 'unload' a sourced bash function, but we can
    # remove it from tracking and mark it as disabled.
    unset "SENTINEL_PLUGIN_NAMES[${plugin_name}]"
    unset "SENTINEL_PLUGIN_PATHS[${plugin_name}]"
    unset "SENTINEL_PLUGIN_VERSIONS[${plugin_name}]"
    unset "SENTINEL_PLUGIN_AUTHORS[${plugin_name}]"
    unset "SENTINEL_PLUGIN_DESCRIPTIONS[${plugin_name}]"
    unset "SENTINEL_PLUGIN_ENABLED[${plugin_name}]"

    # Remove from loaded plugins array
    local -a new_loaded=()
    local loaded_plugin
    for loaded_plugin in "${SENTINEL_LOADED_PLUGINS[@]+"${SENTINEL_LOADED_PLUGINS[@]}"}"; do
        if [[ "${loaded_plugin}" != "${plugin_name}" ]]; then
            new_loaded+=("${loaded_plugin}")
        fi
    done
    SENTINEL_LOADED_PLUGINS=("${new_loaded[@]+"${new_loaded[@]}"}")

    log_info "Plugin unloaded: ${plugin_name}"
    return 0
}

# --- Execution ---

plugin_run() {
    local -r plugin_name="${1}"
    shift
    local -a args=("$@")

    if [[ ! -v "SENTINEL_PLUGIN_NAMES[${plugin_name}]" ]]; then
        log_error "Plugin '${plugin_name}' is not loaded."
        return 1
    fi

    if [[ "${SENTINEL_PLUGIN_ENABLED[${plugin_name}]:-0}" -ne 1 ]]; then
        log_error "Plugin '${plugin_name}' is disabled."
        return 1
    fi

    log_debug "Running plugin: ${plugin_name} with args: ${args[*]:-}"

    # The run() function is expected to be defined by the plugin
    # We use the function directly since it was sourced
    if declare -f "${SENTINEL_PLUGIN_REQUIRED_FUNCTION}" >/dev/null 2>&1; then
        "${SENTINEL_PLUGIN_REQUIRED_FUNCTION}" "${args[@]}"
        local exit_code=$?
        log_debug "Plugin '${plugin_name}' finished with exit code: ${exit_code}"
        return "${exit_code}"
    else
        log_error "Plugin '${plugin_name}' run() function not found."
        return 1
    fi
}

# --- Query ---

plugin_info() {
    local -r plugin_name="${1}"

    if [[ ! -v "SENTINEL_PLUGIN_NAMES[${plugin_name}]" ]]; then
        log_error "Plugin '${plugin_name}' is not loaded."
        return 1
    fi

    echo "Plugin: ${SENTINEL_PLUGIN_NAMES[${plugin_name}]}"
    echo "Version: ${SENTINEL_PLUGIN_VERSIONS[${plugin_name}]}"
    echo "Author: ${SENTINEL_PLUGIN_AUTHORS[${plugin_name}]}"
    echo "Description: ${SENTINEL_PLUGIN_DESCRIPTIONS[${plugin_name}]}"
    echo "Path: ${SENTINEL_PLUGIN_PATHS[${plugin_name}]}"
    echo "Enabled: ${SENTINEL_PLUGIN_ENABLED[${plugin_name}]}"
}

plugin_list() {
    local count=0

    echo "Loaded Plugins"
    echo "================================================================"

    local plugin_name
    for plugin_name in "${SENTINEL_LOADED_PLUGINS[@]+"${SENTINEL_LOADED_PLUGINS[@]}"}"; do
        local enabled="enabled"
        if [[ "${SENTINEL_PLUGIN_ENABLED[${plugin_name}]:-0}" -ne 1 ]]; then
            enabled="disabled"
        fi

        printf '  %-20s  v%-10s  %-12s  %s\n' \
            "${SENTINEL_PLUGIN_NAMES[${plugin_name}]}" \
            "${SENTINEL_PLUGIN_VERSIONS[${plugin_name}]}" \
            "[${enabled}]" \
            "${SENTINEL_PLUGIN_DESCRIPTIONS[${plugin_name}]}"
        (( count++ ))
    done

    if [[ "${count}" -eq 0 ]]; then
        echo "  No plugins loaded."
    fi

    echo "================================================================"
    echo "Total loaded: ${count}"
}

plugin_is_loaded() {
    local -r plugin_name="${1}"

    if [[ -v "SENTINEL_PLUGIN_NAMES[${plugin_name}]" ]]; then
        return 0
    fi
    return 1
}
