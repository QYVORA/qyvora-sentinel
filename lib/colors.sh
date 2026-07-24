#!/usr/bin/env bash
# colors.sh - ANSI color codes, styling helpers, and terminal detection for QYVORA Sentinel.

# Source guard - prevent re-sourcing
if [[ "${_SENTINEL_LIB_LOADED:-}" == *"$(basename "${BASH_SOURCE[0]}")"* ]]; then
    return 0 2>/dev/null || true
fi
_SENTINEL_LIB_LOADED="${_SENTINEL_LIB_LOADED:-} $(basename "${BASH_SOURCE[0]}")"

set -Eeuo pipefail
IFS=$'\n\t'

# Color constants
readonly SENTINEL_COLOR_BLACK='\033[0;30m'
readonly SENTINEL_COLOR_RED='\033[0;31m'
readonly SENTINEL_COLOR_GREEN='\033[0;32m'
readonly SENTINEL_COLOR_YELLOW='\033[0;33m'
readonly SENTINEL_COLOR_BLUE='\033[0;34m'
readonly SENTINEL_COLOR_MAGENTA='\033[0;35m'
readonly SENTINEL_COLOR_CYAN='\033[0;36m'
readonly SENTINEL_COLOR_WHITE='\033[0;37m'
readonly SENTINEL_COLOR_GRAY='\033[0;90m'
readonly SENTINEL_COLOR_BOLD='\033[1m'
readonly SENTINEL_COLOR_DIM='\033[2m'
readonly SENTINEL_COLOR_RESET='\033[0m'

# Sentinel-specific aliases
readonly SENTINEL_CLR_BLACK="${SENTINEL_COLOR_BLACK}"
readonly SENTINEL_CLR_RED="${SENTINEL_COLOR_RED}"
readonly SENTINEL_CLR_GREEN="${SENTINEL_COLOR_GREEN}"
readonly SENTINEL_CLR_YELLOW="${SENTINEL_COLOR_YELLOW}"
readonly SENTINEL_CLR_BLUE="${SENTINEL_COLOR_BLUE}"
readonly SENTINEL_CLR_MAGENTA="${SENTINEL_COLOR_MAGENTA}"
readonly SENTINEL_CLR_CYAN="${SENTINEL_COLOR_CYAN}"
readonly SENTINEL_CLR_WHITE="${SENTINEL_COLOR_WHITE}"
readonly SENTINEL_CLR_GRAY="${SENTINEL_COLOR_GRAY}"
readonly SENTINEL_CLR_BOLD="${SENTINEL_COLOR_BOLD}"
readonly SENTINEL_CLR_DIM="${SENTINEL_COLOR_DIM}"
readonly SENTINEL_CLR_RESET="${SENTINEL_COLOR_RESET}"

# Global flag: whether color output is enabled
SENTINEL_COLOR_ENABLED=1

is_terminal_colorable() {
    if [[ -t 1 ]] && [[ -t 2 ]]; then
        return 0
    fi
    return 1
}

_init_color_support() {
    # Respect NO_COLOR per https://no-color.org/
    if [[ -n "${NO_COLOR:-}" ]]; then
        SENTINEL_COLOR_ENABLED=0
        return
    fi

    # Respect --no-color flag via SENTINEL_NO_COLOR
    if [[ "${SENTINEL_NO_COLOR:-0}" -eq 1 ]]; then
        SENTINEL_COLOR_ENABLED=0
        return
    fi

    # Disable color if not a terminal
    if ! is_terminal_colorable; then
        SENTINEL_COLOR_ENABLED=0
    fi
}

_init_color_support

colorize() {
    local -r color="${1:-}"
    local -r text="${2:-}"

    if [[ "${SENTINEL_COLOR_ENABLED}" -eq 1 ]]; then
        printf '%b%s%b' "${color}" "${text}" "${SENTINEL_COLOR_RESET}"
    else
        printf '%s' "${text}"
    fi
}

bold() {
    local -r text="${1:-}"
    colorize "${SENTINEL_COLOR_BOLD}" "${text}"
}

dim() {
    local -r text="${1:-}"
    colorize "${SENTINEL_COLOR_DIM}" "${text}"
}

red() {
    local -r text="${1:-}"
    colorize "${SENTINEL_COLOR_RED}" "${text}"
}

green() {
    local -r text="${1:-}"
    colorize "${SENTINEL_COLOR_GREEN}" "${text}"
}

yellow() {
    local -r text="${1:-}"
    colorize "${SENTINEL_COLOR_YELLOW}" "${text}"
}

blue() {
    local -r text="${1:-}"
    colorize "${SENTINEL_COLOR_BLUE}" "${text}"
}

cyan() {
    local -r text="${1:-}"
    colorize "${SENTINEL_COLOR_CYAN}" "${text}"
}

magenta() {
    local -r text="${1:-}"
    colorize "${SENTINEL_COLOR_MAGENTA}" "${text}"
}

black() {
    local -r text="${1:-}"
    colorize "${SENTINEL_COLOR_BLACK}" "${text}"
}

white() {
    local -r text="${1:-}"
    colorize "${SENTINEL_COLOR_WHITE}" "${text}"
}

gray() {
    local -r text="${1:-}"
    colorize "${SENTINEL_COLOR_GRAY}" "${text}"
}

severity_color() {
    local -r level="${1:-info}"

    case "${level,,}" in
        critical|fatal)
            printf '%s' "${SENTINEL_COLOR_RED}"
            ;;
        high|error|err)
            printf '%s' "${SENTINEL_COLOR_RED}"
            ;;
        medium|warn|warning)
            printf '%s' "${SENTINEL_COLOR_YELLOW}"
            ;;
        low|info|informational)
            printf '%s' "${SENTINEL_COLOR_GREEN}"
            ;;
        none|info|pass|ok)
            printf '%s' "${SENTINEL_COLOR_GREEN}"
            ;;
        debug|trace)
            printf '%s' "${SENTINEL_COLOR_GRAY}"
            ;;
        *)
            printf '%s' "${SENTINEL_COLOR_WHITE}"
            ;;
    esac
}
