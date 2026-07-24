#!/usr/bin/env bash
# logger.sh - Structured logging system with file and terminal output for QYVORA Sentinel.

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

# Log level constants
readonly SENTINEL_LOG_LEVEL_DEBUG=0
readonly SENTINEL_LOG_LEVEL_INFO=1
readonly SENTINEL_LOG_LEVEL_WARNING=2
readonly SENTINEL_LOG_LEVEL_ERROR=3

# Map string names to numeric levels
readonly -A SENTINEL_LOG_LEVELS=(
    [debug]=0
    [info]=1
    [warning]=2
    [error]=3
    [warn]=2
    [err]=3
)

# Mutable state
SENTINEL_LOG_LEVEL="${SENTINEL_LOG_LEVEL_INFO}"
SENTINEL_LOG_FILE=""
SENTINEL_LOG_FILE_ENABLED=0
SENTINEL_LOG_MODULE="sentinel"

_log_level_to_numeric() {
    local -r level="${1,,}"

    if [[ -v "SENTINEL_LOG_LEVELS[${level}]" ]]; then
        printf '%s' "${SENTINEL_LOG_LEVELS[${level}]}"
    else
        printf '%s' "${SENTINEL_LOG_LEVEL_INFO}"
    fi
}

_log_numeric_to_name() {
    local -r level_num="${1}"

    case "${level_num}" in
        0) printf 'DEBUG' ;;
        1) printf 'INFO' ;;
        2) printf 'WARNING' ;;
        3) printf 'ERROR' ;;
        *) printf 'UNKNOWN' ;;
    esac
}

_log_get_timestamp() {
    date -u '+%Y-%m-%dT%H:%M:%SZ'
}

_log_to_terminal() {
    local -r level_name="${1}"
    local -r module="${2}"
    local -r message="${3}"
    local color
    local level_lower="${level_name,,}"

    case "${level_lower}" in
        debug)   color="${SENTINEL_COLOR_GRAY}" ;;
        info)    color="${SENTINEL_COLOR_GREEN}" ;;
        warning) color="${SENTINEL_COLOR_YELLOW}" ;;
        error)   color="${SENTINEL_COLOR_RED}" ;;
        *)       color="${SENTINEL_COLOR_WHITE}" ;;
    esac

    if [[ "${SENTINEL_COLOR_ENABLED}" -eq 1 ]]; then
        printf '%b[%s]%b [%b%-7s%b] [%b%b%b] %s\n' \
            "${SENTINEL_COLOR_DIM}" "$(_log_get_timestamp)" "${SENTINEL_COLOR_RESET}" \
            "${color}" "${level_name}" "${SENTINEL_COLOR_RESET}" \
            "${SENTINEL_COLOR_BOLD}" "${module}" "${SENTINEL_COLOR_RESET}" \
            "${message}"
    else
        printf '[%s] [%-7s] [%s] %s\n' \
            "$(_log_get_timestamp)" \
            "${level_name}" \
            "${module}" \
            "${message}"
    fi
}

_log_to_file() {
    local -r level_name="${1}"
    local -r module="${2}"
    local -r message="${3}"

    if [[ "${SENTINEL_LOG_FILE_ENABLED}" -eq 1 && -n "${SENTINEL_LOG_FILE}" ]]; then
        printf '[%s] [%-7s] [%s] %s\n' \
            "$(_log_get_timestamp)" \
            "${level_name}" \
            "${module}" \
            "${message}" >> "${SENTINEL_LOG_FILE}"
    fi
}

_log_write() {
    local -r level_num="${1}"
    local -r module="${2}"
    local -r message="${3}"

    local current_level_num
    current_level_num=$(_log_level_to_numeric "${SENTINEL_LOG_LEVEL}")

    if [[ "${level_num}" -lt "${current_level_num}" ]]; then
        return 0
    fi

    local level_name
    level_name=$(_log_numeric_to_name "${level_num}")

    _log_to_terminal "${level_name}" "${module}" "${message}"
    _log_to_file "${level_name}" "${module}" "${message}"
}

log_set_level() {
    local -r level="${1,,}"

    if [[ -v "SENTINEL_LOG_LEVELS[${level}]" ]]; then
        SENTINEL_LOG_LEVEL="${level}"
    else
        printf 'Unknown log level: %s\n' "${level}" >&2
        return 1
    fi
}

log_set_module() {
    SENTINEL_LOG_MODULE="${1:-sentinel}"
}

log_set_file() {
    local -r filepath="${1}"

    if [[ -z "${filepath}" ]]; then
        log_disable_file_logging
        return
    fi

    local dir
    dir="$(dirname "${filepath}")"

    if [[ ! -d "${dir}" ]]; then
        mkdir -p "${dir}"
    fi

    SENTINEL_LOG_FILE="${filepath}"
    SENTINEL_LOG_FILE_ENABLED=1
}

log_enable_file_logging() {
    local -r filepath="${1}"

    log_set_file "${filepath}"
}

log_disable_file_logging() {
    SENTINEL_LOG_FILE=""
    SENTINEL_LOG_FILE_ENABLED=0
}

log_debug() {
    local -r message="${1:-}"
    _log_write "${SENTINEL_LOG_LEVEL_DEBUG}" "${SENTINEL_LOG_MODULE}" "${message}"
}

log_info() {
    local -r message="${1:-}"
    _log_write "${SENTINEL_LOG_LEVEL_INFO}" "${SENTINEL_LOG_MODULE}" "${message}"
}

log_warning() {
    local -r message="${1:-}"
    _log_write "${SENTINEL_LOG_LEVEL_WARNING}" "${SENTINEL_LOG_MODULE}" "${message}"
}

log_error() {
    local -r message="${1:-}"
    _log_write "${SENTINEL_LOG_LEVEL_ERROR}" "${SENTINEL_LOG_MODULE}" "${message}"
}

log_fatal() {
    local -r message="${1:-}"
    _log_write "${SENTINEL_LOG_LEVEL_ERROR}" "${SENTINEL_LOG_MODULE}" "${message}"
    exit 1
}
