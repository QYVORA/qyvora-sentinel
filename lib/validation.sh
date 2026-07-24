#!/usr/bin/env bash
# validation.sh - Input validation functions for QYVORA Sentinel
# Provides validators for paths, commands, ports, URLs, config values,
# and general input sanitization to ensure safe operation.

# Source guard - prevent re-sourcing
if [[ "${_SENTINEL_LIB_LOADED:-}" == *"$(basename "${BASH_SOURCE[0]}")"* ]]; then
    return 0 2>/dev/null || true
fi
_SENTINEL_LIB_LOADED="${_SENTINEL_LIB_LOADED:-} $(basename "${BASH_SOURCE[0]}")"

set -Eeuo pipefail
IFS=$'\n\t'

# Valid severity levels
readonly SENTINEL_VALID_SEVERITIES="INFO LOW MEDIUM HIGH CRITICAL"

# Valid output formats
readonly SENTINEL_VALID_FORMATS="text json markdown html"

# validate_path - Validate that a file path exists and is accessible
validate_path() {
    local path="${1:-}"
    if [[ -z "${path}" ]]; then
        echo "Path cannot be empty" >&2
        return 1
    fi
    if [[ -e "${path}" ]]; then
        return 0
    fi
    echo "Path does not exist: ${path}" >&2
    return 1
}

# validate_directory - Validate that a directory exists
validate_directory() {
    local path="${1:-}"
    if [[ -z "${path}" ]]; then
        echo "Directory path cannot be empty" >&2
        return 1
    fi
    if [[ -d "${path}" ]]; then
        return 0
    fi
    echo "Directory does not exist: ${path}" >&2
    return 1
}

# validate_file - Validate that a file exists and is readable
validate_file() {
    local path="${1:-}"
    if [[ -z "${path}" ]]; then
        echo "File path cannot be empty" >&2
        return 1
    fi
    if [[ -f "${path}" && -r "${path}" ]]; then
        return 0
    fi
    if [[ ! -f "${path}" ]]; then
        echo "File does not exist: ${path}" >&2
    elif [[ ! -r "${path}" ]]; then
        echo "File is not readable: ${path}" >&2
    fi
    return 1
}

# validate_command - Validate that a command name is safe (no shell metacharacters)
validate_command() {
    local cmd="${1:-}"
    if [[ -z "${cmd}" ]]; then
        echo "Command cannot be empty" >&2
        return 1
    fi
    # Check for shell metacharacters
    if [[ "${cmd}" =~ [\;\|\&\$\`\(\)\{\}\<\>\!\#\'\"] ]]; then
        echo "Command contains unsafe characters: ${cmd}" >&2
        return 1
    fi
    # Check command exists
    if ! command -v "${cmd}" &>/dev/null; then
        echo "Command not found: ${cmd}" >&2
        return 1
    fi
    return 0
}

# validate_severity - Validate severity level against allowed values
validate_severity() {
    local level="${1:-}"
    if [[ -z "${level}" ]]; then
        echo "Severity level cannot be empty" >&2
        return 1
    fi
    level="$(echo "${level}" | tr '[:lower:]' '[:upper:]')"
    local valid_level
    local OLDIFS="${IFS}"
    IFS=' '
    for valid_level in ${SENTINEL_VALID_SEVERITIES}; do
        if [[ "${level}" == "${valid_level}" ]]; then
            IFS="${OLDIFS}"
            return 0
        fi
    done
    IFS="${OLDIFS}"
    echo "Invalid severity level: ${level}. Valid: ${SENTINEL_VALID_SEVERITIES}" >&2
    return 1
}

# validate_config_value - Validate a configuration value against its expected type
validate_config_value() {
    local value="${1:-}"
    local type="${2:-string}"

    case "${type}" in
        boolean)
            case "${value}" in
                true|false|yes|no|1|0|on|off)
                    return 0
                    ;;
                *)
                    echo "Invalid boolean value: ${value}" >&2
                    return 1
                    ;;
            esac
            ;;
        integer)
            if [[ "${value}" =~ ^-?[0-9]+$ ]]; then
                return 0
            fi
            echo "Invalid integer value: ${value}" >&2
            return 1
            ;;
        string)
            if [[ -n "${value}" ]]; then
                return 0
            fi
            echo "String value cannot be empty" >&2
            return 1
            ;;
        path)
            if [[ -e "${value}" ]]; then
                return 0
            fi
            echo "Path does not exist: ${value}" >&2
            return 1
            ;;
        *)
            echo "Unknown validation type: ${type}" >&2
            return 1
            ;;
    esac
}

# validate_port - Validate a port number (1-65535)
validate_port() {
    local port="${1:-}"
    if [[ -z "${port}" ]]; then
        echo "Port cannot be empty" >&2
        return 1
    fi
    if [[ "${port}" =~ ^[0-9]+$ && "${port}" -ge 1 && "${port}" -le 65535 ]]; then
        return 0
    fi
    echo "Invalid port number: ${port}. Must be 1-65535." >&2
    return 1
}

# validate_url - Basic URL validation (scheme + host)
validate_url() {
    local url="${1:-}"
    if [[ -z "${url}" ]]; then
        echo "URL cannot be empty" >&2
        return 1
    fi
    if [[ "${url}" =~ ^https?://[a-zA-Z0-9]([a-zA-Z0-9.-]*[a-zA-Z0-9])?(:[0-9]+)?(/[^ ]*)?$ ]]; then
        return 0
    fi
    echo "Invalid URL: ${url}" >&2
    return 1
}

# validate_output_format - Validate output format against allowed values
validate_output_format() {
    local format="${1:-}"
    if [[ -z "${format}" ]]; then
        echo "Output format cannot be empty" >&2
        return 1
    fi
    format="$(echo "${format}" | tr '[:upper:]' '[:lower:]')"
    local valid_format
    local OLDIFS="${IFS}"
    IFS=' '
    for valid_format in ${SENTINEL_VALID_FORMATS}; do
        if [[ "${format}" == "${valid_format}" ]]; then
            IFS="${OLDIFS}"
            return 0
        fi
    done
    IFS="${OLDIFS}"
    echo "Invalid output format: ${format}. Valid: ${SENTINEL_VALID_FORMATS}" >&2
    return 1
}

# sanitize_input - Sanitize user input for safe shell usage
sanitize_input() {
    local input="${1:-}"
    if [[ -z "${input}" ]]; then
        echo ""
        return 0
    fi
    # Remove null bytes
    input="${input//$'\0'/}"
    # Remove carriage returns
    input="${input//$'\r'/}"
    # Remove ANSI escape sequences
    input="$(echo "${input}" | sed 's/\x1b\[[0-9;]*[a-zA-Z]//g')"
    # Remove control characters except newline and tab
    input="$(echo "${input}" | tr -d '\000-\010\013-\037')"
    echo "${input}"
}
