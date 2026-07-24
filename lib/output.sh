#!/usr/bin/env bash
# output.sh - Terminal output formatting and UI for QYVORA Sentinel
# Provides consistent, color-coded output with Unicode symbols for findings,
# summaries, progress bars, tables, and risk scores.

# Source guard - prevent re-sourcing
if [[ "${_SENTINEL_LIB_LOADED:-}" == *"$(basename "${BASH_SOURCE[0]}")"* ]]; then
    return 0 2>/dev/null || true
fi
_SENTINEL_LIB_LOADED="${_SENTINEL_LIB_LOADED:-} $(basename "${BASH_SOURCE[0]}")"

set -Eeuo pipefail
IFS=$'\n\t'

# Unicode symbols
readonly SENTINEL_CHECKMARK="✔"
readonly SENTINEL_WARNING="⚠"
readonly SENTINEL_CROSSMARK="✖"
readonly SENTINEL_ARROW="►"
readonly SENTINEL_BULLET="●"

# Color codes (disabled when NO_COLOR is set or not a terminal)
if [[ -z "${NO_COLOR:-}" && -t 1 ]]; then
    readonly SENTINEL_COLOR_RED='\033[0;31m'
    readonly SENTINEL_COLOR_GREEN='\033[0;32m'
    readonly SENTINEL_COLOR_YELLOW='\033[0;33m'
    readonly SENTINEL_COLOR_BLUE='\033[0;34m'
    readonly SENTINEL_COLOR_MAGENTA='\033[0;35m'
    readonly SENTINEL_COLOR_CYAN='\033[0;36m'
    readonly SENTINEL_COLOR_BOLD='\033[1m'
    readonly SENTINEL_COLOR_RESET='\033[0m'
else
    readonly SENTINEL_COLOR_RED=''
    readonly SENTINEL_COLOR_GREEN=''
    readonly SENTINEL_COLOR_YELLOW=''
    readonly SENTINEL_COLOR_BLUE=''
    readonly SENTINEL_COLOR_MAGENTA=''
    readonly SENTINEL_COLOR_CYAN=''
    readonly SENTINEL_COLOR_BOLD=''
    readonly SENTINEL_COLOR_RESET=''
fi

# print_banner - Display the QYVORA Sentinel banner from assets/banner.txt
print_banner() {
    local script_dir
    script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
    local project_root="${script_dir}/.."
    local banner_file="${project_root}/assets/banner.txt"

    if [[ -f "${banner_file}" ]]; then
        echo -e "${SENTINEL_COLOR_CYAN}${SENTINEL_COLOR_BOLD}"
        cat "${banner_file}"
        echo -e "${SENTINEL_COLOR_RESET}"
    else
        echo -e "${SENTINEL_COLOR_CYAN}${SENTINEL_COLOR_BOLD}"
        echo "╔══════════════════════════════════════════════════════════════╗"
        echo "║                    QYVORA SENTINEL                         ║"
        echo "║              Linux Security Auditing Framework             ║"
        echo "╚══════════════════════════════════════════════════════════════╝"
        echo -e "${SENTINEL_COLOR_RESET}"
    fi
}

# print_header - Print a section header with box drawing
print_header() {
    local title="${1:-}"
    local width=60
    local inner_width=$((width - 2))
    local padding=$(( (inner_width - ${#title} - 2) / 2 ))
    local right_pad=$(( inner_width - padding - ${#title} - 2 ))

    echo ""
    echo -e "${SENTINEL_COLOR_BOLD}╔$(printf '═%.0s' $(seq 1 ${inner_width}))╗${SENTINEL_COLOR_RESET}"
    printf "${SENTINEL_COLOR_BOLD}║${SENTINEL_COLOR_RESET} %*s%s%*s ${SENTINEL_COLOR_BOLD}║${SENTINEL_COLOR_RESET}\n" "${padding}" "" "${title}" "${right_pad}" ""
    echo -e "${SENTINEL_COLOR_BOLD}╚$(printf '═%.0s' $(seq 1 ${inner_width}))╝${SENTINEL_COLOR_RESET}"
}

# print_subheader - Print a subsection header
print_subheader() {
    local title="${1:-}"
    echo ""
    echo -e "${SENTINEL_COLOR_BOLD}${SENTINEL_COLOR_CYAN}${SENTINEL_ARROW} ${title}${SENTINEL_COLOR_RESET}"
    echo -e "${SENTINEL_COLOR_CYAN}$(printf '─%.0s' $(seq 1 $((${#title} + 2))))${SENTINEL_COLOR_RESET}"
}

# print_finding - Print a finding with severity-based color and icon
print_finding() {
    local severity="${1:-INFO}"
    local message="${2:-}"
    local icon color

    case "${severity^^}" in
        CRITICAL)
            icon="${SENTINEL_CROSSMARK}"
            color="${SENTINEL_COLOR_RED}${SENTINEL_COLOR_BOLD}"
            ;;
        HIGH)
            icon="${SENTINEL_CROSSMARK}"
            color="${SENTINEL_COLOR_RED}"
            ;;
        MEDIUM)
            icon="${SENTINEL_WARNING}"
            color="${SENTINEL_COLOR_YELLOW}"
            ;;
        LOW)
            icon="${SENTINEL_WARNING}"
            color="${SENTINEL_COLOR_MAGENTA}"
            ;;
        *)
            icon="${SENTINEL_CHECKMARK}"
            color="${SENTINEL_COLOR_GREEN}"
            ;;
    esac

    echo -e "${color}  [${icon}] ${severity^^}: ${message}${SENTINEL_COLOR_RESET}"
}

# print_success - Print a success indicator
print_success() {
    local message="${1:-}"
    echo -e "${SENTINEL_COLOR_GREEN}  ${SENTINEL_CHECKMARK} ${message}${SENTINEL_COLOR_RESET}"
}

# print_warning - Print a warning indicator
print_warning() {
    local message="${1:-}"
    echo -e "${SENTINEL_COLOR_YELLOW}  ${SENTINEL_WARNING} ${message}${SENTINEL_COLOR_RESET}"
}

# print_error - Print an error indicator
print_error() {
    local message="${1:-}"
    echo -e "${SENTINEL_COLOR_RED}  ${SENTINEL_CROSSMARK} ${message}${SENTINEL_COLOR_RESET}" >&2
}

# print_info - Print an informational indicator
print_info() {
    local message="${1:-}"
    echo -e "${SENTINEL_COLOR_BLUE}  ${SENTINEL_BULLET} ${message}${SENTINEL_COLOR_RESET}"
}

# print_separator - Print a horizontal line
# shellcheck disable=SC2120
print_separator() {
    local width="${1:-60}"
    printf '%*s\n' "${width}" '' | tr ' ' '─'
}

# print_table_header - Print a formatted table header
print_table_header() {
    local columns=("$@")
    local col
    local header=""
    local separator=""

    for col in "${columns[@]}"; do
        header+=$(printf "%-20s" "${col}")
        separator+=$(printf "%-20s" "────────────────────")
    done

    echo -e "${SENTINEL_COLOR_BOLD}${header}${SENTINEL_COLOR_RESET}"
    echo -e "${SENTINEL_COLOR_CYAN}${separator}${SENTINEL_COLOR_RESET}"
}

# print_table_row - Print a formatted table row
print_table_row() {
    local columns=("$@")
    local row=""

    for col in "${columns[@]}"; do
        row+=$(printf "%-20s" "${col}")
    done

    echo "${row}"
}

# print_progress - Print a progress bar
print_progress() {
    local current="${1:-0}"
    local total="${2:-100}"
    local message="${3:-}"
    local width=40
    local percentage=0

    if [[ "${total}" -gt 0 ]]; then
        percentage=$(( (current * 100) / total ))
    fi

    local filled=$(( (current * width) / total ))
    local empty=$(( width - filled ))

    local bar=""
    bar+=$(printf '█%.0s' $(seq 1 "${filled}" 2>/dev/null) || true)
    bar+=$(printf '░%.0s' $(seq 1 "${empty}" 2>/dev/null) || true)

    printf "\r${SENTINEL_COLOR_CYAN}  [${bar}]${SENTINEL_COLOR_RESET} %3d%% %s" "${percentage}" "${message}"

    if [[ "${current}" -eq "${total}" ]]; then
        echo ""
    fi
}

# print_summary - Print a scan summary with counts
print_summary() {
    local -A stats=()
    if [[ $# -gt 0 ]]; then
        while [[ $# -gt 0 ]]; do
            local key="${1%%=*}"
            local value="${1#*=}"
            stats["${key}"]="${value}"
            shift
        done
    fi

    echo ""
    print_header "Scan Summary"
    echo ""

    local total=0
    local key
    for key in "${!stats[@]}"; do
        local value="${stats[${key}]}"
        local severity="INFO"

        if [[ "${value}" -gt 0 ]]; then
            case "${key}" in
                *critical*|*CRITICAL*) severity="CRITICAL" ;;
                *high*|*HIGH*) severity="HIGH" ;;
                *medium*|*MEDIUM*) severity="MEDIUM" ;;
                *low*|*LOW*) severity="LOW" ;;
            esac
            print_finding "${severity}" "${key}: ${value}"
        else
            print_success "${key}: ${value}"
        fi
        total=$((total + value))
    done

    echo ""
    print_separator
    echo -e "${SENTINEL_COLOR_BOLD}  Total findings: ${total}${SENTINEL_COLOR_RESET}"
}

# print_risk_score - Print a risk score with color coding
print_risk_score() {
    local score="${1:-0}"
    local color label

    if [[ "${score}" -ge 80 ]]; then
        color="${SENTINEL_COLOR_RED}${SENTINEL_COLOR_BOLD}"
        label="CRITICAL"
    elif [[ "${score}" -ge 60 ]]; then
        color="${SENTINEL_COLOR_RED}"
        label="HIGH"
    elif [[ "${score}" -ge 40 ]]; then
        color="${SENTINEL_COLOR_YELLOW}"
        label="MEDIUM"
    elif [[ "${score}" -ge 20 ]]; then
        color="${SENTINEL_COLOR_MAGENTA}"
        label="LOW"
    else
        color="${SENTINEL_COLOR_GREEN}"
        label="MINIMAL"
    fi

    echo ""
    print_header "Risk Assessment"
    echo ""
    echo -e "${color}  Risk Score: ${score}/100 [${label}]${SENTINEL_COLOR_RESET}"
    echo ""
    print_separator
}
