#!/usr/bin/env bash
# config.sh - INI-style configuration management for QYVORA Sentinel.

# Source guard - prevent re-sourcing
if [[ "${_SENTINEL_LIB_LOADED:-}" == *"$(basename "${BASH_SOURCE[0]}")"* ]]; then
    return 0 2>/dev/null || true
fi
_SENTINEL_LIB_LOADED="${_SENTINEL_LIB_LOADED:-} $(basename "${BASH_SOURCE[0]}")"

set -Eeuo pipefail
IFS=$'\n\t'

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=logger.sh
source "${SCRIPT_DIR}/logger.sh"

readonly SENTINEL_CONFIG_DIR="${XDG_CONFIG_HOME:-${HOME}/.config}/qyvora-sentinel"
readonly SENTINEL_CONFIG_FILE="${SENTINEL_CONFIG_DIR}/sentinel.conf"

# Internal associative array for config storage
declare -gA SENTINEL_CONFIG=()

config_init() {
    local -r config_file="${1:-${SENTINEL_CONFIG_FILE}}"

    mkdir -p "$(dirname "${config_file}")" 2>/dev/null || true

    if [[ ! -f "${config_file}" ]]; then
        _config_write_defaults "${config_file}"
    fi

    config_load "${config_file}"
}

_config_write_defaults() {
    local -r filepath="${1}"

    cat > "${filepath}" <<'DEFAULTS'
# QYVORA Sentinel Configuration
# Generated automatically on first run.

[general]
verbose = false
log_level = info
log_file = 
scan_timeout = 300

[paths]
scan_root = /
excluded_paths = /proc,/sys,/dev,/run

[checks]
enable_suid = true
enable_sgid = true
enable_world_writable = true
enable_capabilities = true
enable_sticky = true

[output]
format = text
color = auto
report_dir = /var/log/qyvora-sentinel
DEFAULTS
}

config_load() {
    local -r filepath="${1}"

    if [[ ! -f "${filepath}" ]]; then
        log_error "Configuration file not found: ${filepath}"
        return 1
    fi

    local current_section="global"
    local line
    local key
    local value

    while IFS= read -r line || [[ -n "${line}" ]]; do
        # Strip leading/trailing whitespace
        line="${line#"${line%%[![:space:]]*}"}"
        line="${line%"${line##*[![:space:]]}"}"

        # Skip empty lines and comments
        [[ -z "${line}" ]] && continue
        [[ "${line}" == \#* ]] && continue
        [[ "${line}" == \;* ]] && continue

        # Section header
        if [[ "${line}" =~ ^\[([a-zA-Z0-9_-]+)\]$ ]]; then
            current_section="${BASH_REMATCH[1]}"
            continue
        fi

        # key = value
        if [[ "${line}" =~ ^([a-zA-Z0-9_.-]+)[[:space:]]*=[[:space:]]*(.+)$ ]]; then
            key="${BASH_REMATCH[1]}"
            value="${BASH_REMATCH[2]}"

            # Trim trailing whitespace from value
            value="${value%"${value##*[![:space:]]}"}"

            SENTINEL_CONFIG["${current_section}.${key}"]="${value}"
        fi
    done < "${filepath}"
}

config_get() {
    local -r key="${1}"
    local -r default="${2:-}"

    if [[ -v "SENTINEL_CONFIG[${key}]" ]]; then
        printf '%s' "${SENTINEL_CONFIG[${key}]}"
    else
        printf '%s' "${default}"
    fi
}

config_set() {
    local -r key="${1}"
    local -r value="${2}"
    local -r config_file="${3:-${SENTINEL_CONFIG_FILE}}"

    SENTINEL_CONFIG["${key}"]="${value}"

    if [[ -f "${config_file}" ]]; then
        _config_write_back "${config_file}"
    fi
}

_config_write_back() {
    local -r filepath="${1}"
    local temp_file
    temp_file="$(mktemp)"

    local current_section="global"
    local key_section
    local key_name
    local found
    local line

    while IFS= read -r line || [[ -n "${line}" ]]; do
        # Section header
        if [[ "${line}" =~ ^\[([a-zA-Z0-9_-]+)\]$ ]]; then
            current_section="${BASH_REMATCH[1]}"
            printf '%s\n' "${line}" >> "${temp_file}"
            continue
        fi

        # key = value line
        if [[ "${line}" =~ ^([a-zA-Z0-9_.-]+)[[:space:]]*=[[:space:]]*(.+)$ ]]; then
            key_name="${BASH_REMATCH[1]}"
            key_section="${current_section}.${key_name}"

            found=0
            if [[ -v "SENTINEL_CONFIG[${key_section}]" ]]; then
                printf '%s = %s\n' "${key_name}" "${SENTINEL_CONFIG[${key_section}]}" >> "${temp_file}"
                found=1
            fi

            if [[ "${found}" -eq 0 ]]; then
                printf '%s\n' "${line}" >> "${temp_file}"
            fi
            continue
        fi

        # Preserve comments and blank lines
        printf '%s\n' "${line}" >> "${temp_file}"
    done < "${filepath}"

    # Append any new keys not already in the file
    for key in "${!SENTINEL_CONFIG[@]}"; do
        if [[ "${key}" =~ ^([a-zA-Z0-9_-]+)\.([a-zA-Z0-9_.-]+)$ ]]; then
            key_section="${BASH_REMATCH[1]}"
            key_name="${BASH_REMATCH[2]}"
            # Check if this key was already written
            if ! grep -q "^${key_name} = " "${temp_file}" 2>/dev/null; then
                printf '%s = %s\n' "${key_name}" "${SENTINEL_CONFIG[${key}]}" >> "${temp_file}"
            fi
        fi
    done

    mv "${temp_file}" "${filepath}"
}

config_has() {
    local -r key="${1}"

    if [[ -v "SENTINEL_CONFIG[${key}]" ]]; then
        return 0
    fi
    return 1
}

config_get_section() {
    local -r section="${1}"
    local key

    for key in "${!SENTINEL_CONFIG[@]}"; do
        if [[ "${key}" =~ ^${section}\. ]]; then
            local key_name="${key#*.}"
            printf '%s=%s\n' "${key_name}" "${SENTINEL_CONFIG[${key}]}"
        fi
    done
}

config_get_boolean() {
    local -r key="${1}"
    local -r default="${2:-false}"
    local value

    value="$(config_get "${key}" "${default}")"

    case "${value,,}" in
        true|yes|1|on)  printf 'true' ;;
        false|no|0|off) printf 'false' ;;
        *)              printf '%s' "${default}" ;;
    esac
}

config_get_integer() {
    local -r key="${1}"
    local -r default="${2:-0}"
    local value

    value="$(config_get "${key}" "${default}")"

    if [[ "${value}" =~ ^-?[0-9]+$ ]]; then
        printf '%s' "${value}"
    else
        printf '%s' "${default}"
    fi
}

config_validate_path() {
    local -r key="${1}"
    local path

    path="$(config_get "${key}")"

    if [[ -z "${path}" ]]; then
        return 0
    fi

    if [[ ! -e "${path}" ]]; then
        log_warning "Config path for '${key}' does not exist: ${path}"
        return 1
    fi

    return 0
}

config_list() {
    local key

    for key in $(compgen -v | sort); do
        if [[ "${key}" =~ ^SENTINEL_CONFIG\[ ]]; then
            printf '%s\n' "${key}"
        fi
    done

    for key in "${!SENTINEL_CONFIG[@]}"; do
        printf '%s=%s\n' "${key}" "${SENTINEL_CONFIG[${key}]}"
    done
}
