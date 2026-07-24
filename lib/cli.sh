#!/usr/bin/env bash
# cli.sh - CLI parsing and option handling for QYVORA Sentinel
# Provides argument parsing, help display, version info, module listing,
# and terminal capability detection for the QYVORA Sentinel framework.

# Source guard - prevent re-sourcing
if [[ "${_SENTINEL_LIB_LOADED:-}" == *"$(basename "${BASH_SOURCE[0]}")"* ]]; then
    return 0 2>/dev/null || true
fi
_SENTINEL_LIB_LOADED="${_SENTINEL_LIB_LOADED:-} $(basename "${BASH_SOURCE[0]}")"

set -Eeuo pipefail
IFS=$'\n\t'

# Version information
readonly SENTINEL_VERSION="1.0.0"
readonly SENTINEL_VERSION_DATE="2026-07-22"

# Associative array for parsed CLI arguments
declare -gA SENTINEL_CLI_ARGS=()

# Available modules
readonly -a SENTINEL_MODULES=("filesystem" "process" "network" "cron" "users" "packages" "services" "kernel" "logging" "crypto")

# parse_global_options - Parse global CLI flags and options
parse_global_options() {
    local args=("$@")
    local i=0

    while [[ ${i} -lt ${#args[@]} ]]; do
        local arg="${args[${i}]}"
        case "${arg}" in
            --json)
                SENTINEL_CLI_ARGS[format]="json"
                ;;
            --html)
                SENTINEL_CLI_ARGS[format]="html"
                ;;
            --text)
                SENTINEL_CLI_ARGS[format]="text"
                ;;
            --quiet|-q)
                SENTINEL_CLI_ARGS[quiet]="true"
                ;;
            --verbose|-v)
                SENTINEL_CLI_ARGS[verbose]="true"
                ;;
            --color)
                SENTINEL_CLI_ARGS[color]="true"
                ;;
            --no-color)
                SENTINEL_CLI_ARGS[color]="false"
                ;;
            --output|-o)
                i=$((i + 1))
                if [[ ${i} -lt ${#args[@]} ]]; then
                    SENTINEL_CLI_ARGS[output]="${args[${i}]}"
                fi
                ;;
            --config|-c)
                i=$((i + 1))
                if [[ ${i} -lt ${#args[@]} ]]; then
                    SENTINEL_CLI_ARGS[config]="${args[${i}]}"
                fi
                ;;
            --debug)
                SENTINEL_CLI_ARGS[debug]="true"
                ;;
            --severity|-s)
                i=$((i + 1))
                if [[ ${i} -lt ${#args[@]} ]]; then
                    SENTINEL_CLI_ARGS[severity]="${args[${i}]}"
                fi
                ;;
            --module|-m)
                i=$((i + 1))
                if [[ ${i} -lt ${#args[@]} ]]; then
                    SENTINEL_CLI_ARGS[module]="${args[${i}]}"
                fi
                ;;
            --exclude|-e)
                i=$((i + 1))
                if [[ ${i} -lt ${#args[@]} ]]; then
                    SENTINEL_CLI_ARGS[exclude]="${args[${i}]}"
                fi
                ;;
            --include|-I)
                i=$((i + 1))
                if [[ ${i} -lt ${#args[@]} ]]; then
                    SENTINEL_CLI_ARGS[include]="${args[${i}]}"
                fi
                ;;
            --baseline|-b)
                i=$((i + 1))
                if [[ ${i} -lt ${#args[@]} ]]; then
                    SENTINEL_CLI_ARGS[baseline]="${args[${i}]}"
                fi
                ;;
            --compare)
                i=$((i + 1))
                if [[ ${i} -lt ${#args[@]} ]]; then
                    SENTINEL_CLI_ARGS[compare]="${args[${i}]}"
                fi
                ;;
            --threads|-t)
                i=$((i + 1))
                if [[ ${i} -lt ${#args[@]} ]]; then
                    SENTINEL_CLI_ARGS[threads]="${args[${i}]}"
                fi
                ;;
            --risk-score)
                SENTINEL_CLI_ARGS[risk_score]="true"
                ;;
            --help|-h)
                show_help
                exit 0
                ;;
            --version|-V)
                show_version
                exit 0
                ;;
            --modules)
                show_modules
                exit 0
                ;;
            --)
                i=$((i + 1))
                break
                ;;
            -*)
                echo "Unknown option: ${arg}" >&2
                return 1
                ;;
            *)
                break
                ;;
        esac
        i=$((i + 1))
    done

    # Set defaults
    SENTINEL_CLI_ARGS[format]="${SENTINEL_CLI_ARGS[format]:-text}"
    SENTINEL_CLI_ARGS[quiet]="${SENTINEL_CLI_ARGS[quiet]:-false}"
    SENTINEL_CLI_ARGS[verbose]="${SENTINEL_CLI_ARGS[verbose]:-false}"
    SENTINEL_CLI_ARGS[color]="${SENTINEL_CLI_ARGS[color]:-auto}"
    SENTINEL_CLI_ARGS[debug]="${SENTINEL_CLI_ARGS[debug]:-false}"
    SENTINEL_CLI_ARGS[severity]="${SENTINEL_CLI_ARGS[severity]:-low}"
    SENTINEL_CLI_ARGS[threads]="${SENTINEL_CLI_ARGS[threads]:-4}"
    SENTINEL_CLI_ARGS[risk_score]="${SENTINEL_CLI_ARGS[risk_score]:-false}"
}

# show_help - Display comprehensive help text
show_help() {
    cat << 'HELP'
QYVORA Sentinel - Linux Security Auditing Framework

Usage: qyvora-sentinel [OPTIONS] [MODULE]

Options:
  -h, --help              Show this help message and exit
  -V, --version           Show version information and exit
  --modules               List all available modules
  -m, --module MODULE     Run a specific module
  -s, --severity LEVEL    Filter by severity (info/low/medium/high/critical)
  -o, --output FILE       Write output to file
  -c, --config FILE       Use custom configuration file
  --json                  Output in JSON format
  --html                  Output in HTML format
  --text                  Output in text format (default)
  -q, --quiet             Suppress non-essential output
  -v, --verbose           Enable verbose output
  --color                 Force colored output
  --no-color              Disable colored output
  --debug                 Enable debug output
  -e, --exclude PATTERN   Exclude files matching pattern
  -I, --include PATTERN   Include only files matching pattern
  -b, --baseline FILE     Load baseline for comparison
  --compare FILE          Compare against previous scan results
  -t, --threads NUM       Number of parallel threads
  --risk-score            Display risk score at end of scan

Examples:
  qyvora-sentinel --help
  qyvora-sentinel -m filesystem --severity medium
  qyvora-sentinel --json -o report.json
  qyvora-sentinel -m process --verbose
HELP
}

# show_version - Display version information
show_version() {
    echo "QYVORA Sentinel v${SENTINEL_VERSION} (${SENTINEL_VERSION_DATE})"
    echo "Linux Security Auditing Framework"
}

# show_modules - List all available modules with descriptions
show_modules() {
    echo "Available modules:"
    echo ""
    printf "  %-15s %s\n" "filesystem" "Filesystem operations and analysis"
    printf "  %-15s %s\n" "process" "Process inspection and analysis"
    printf "  %-15s %s\n" "network" "Network inspection and analysis"
    printf "  %-15s %s\n" "cron" "Cron job and scheduled task analysis"
    printf "  %-15s %s\n" "users" "User and authentication analysis"
    printf "  %-15s %s\n" "packages" "Package integrity checking"
    printf "  %-15s %s\n" "services" "System service analysis"
    printf "  %-15s %s\n" "kernel" "Kernel and system configuration"
    printf "  %-15s %s\n" "logging" "Log file analysis"
    printf "  %-15s %s\n" "crypto" "Cryptographic configuration"
}

# validate_cli_args - Validate parsed CLI arguments
validate_cli_args() {
    local errors=0

    # Validate output format
    if [[ -n "${SENTINEL_CLI_ARGS[format]:-}" ]]; then
        case "${SENTINEL_CLI_ARGS[format]}" in
            text|json|markdown|html)
                ;;
            *)
                echo "Invalid output format: ${SENTINEL_CLI_ARGS[format]}" >&2
                errors=$((errors + 1))
                ;;
        esac
    fi

    # Validate severity
    if [[ -n "${SENTINEL_CLI_ARGS[severity]:-}" ]]; then
        case "${SENTINEL_CLI_ARGS[severity]}" in
            info|low|medium|high|critical)
                ;;
            *)
                echo "Invalid severity: ${SENTINEL_CLI_ARGS[severity]}" >&2
                errors=$((errors + 1))
                ;;
        esac
    fi

    # Validate threads
    if [[ -n "${SENTINEL_CLI_ARGS[threads]:-}" ]]; then
        if ! [[ "${SENTINEL_CLI_ARGS[threads]}" =~ ^[0-9]+$ ]] || [[ "${SENTINEL_CLI_ARGS[threads]}" -lt 1 || "${SENTINEL_CLI_ARGS[threads]}" -gt 32 ]]; then
            echo "Invalid thread count: ${SENTINEL_CLI_ARGS[threads]} (must be 1-32)" >&2
            errors=$((errors + 1))
        fi
    fi

    # Validate module
    if [[ -n "${SENTINEL_CLI_ARGS[module]:-}" ]]; then
        local valid=0
        local m
        for m in "${SENTINEL_MODULES[@]}"; do
            if [[ "${SENTINEL_CLI_ARGS[module]}" == "${m}" ]]; then
                valid=1
                break
            fi
        done
        if [[ "${valid}" -eq 0 ]]; then
            echo "Invalid module: ${SENTINEL_CLI_ARGS[module]}" >&2
            errors=$((errors + 1))
        fi
    fi

    # Validate output file path
    if [[ -n "${SENTINEL_CLI_ARGS[output]:-}" ]]; then
        local outdir
        outdir="$(dirname "${SENTINEL_CLI_ARGS[output]}")"
        if [[ ! -d "${outdir}" ]]; then
            echo "Output directory does not exist: ${outdir}" >&2
            errors=$((errors + 1))
        fi
    fi

    return "${errors}"
}

# get_option - Get a parsed option value
get_option() {
    local key="${1:-}"
    if [[ -z "${key}" ]]; then
        echo ""
        return 1
    fi
    echo "${SENTINEL_CLI_ARGS[${key}]:-}"
}

# has_option - Check if an option was provided
has_option() {
    local key="${1:-}"
    if [[ -z "${key}" ]]; then
        return 1
    fi
    if [[ -n "${SENTINEL_CLI_ARGS[${key}]:-}" ]]; then
        return 0
    fi
    return 1
}

# detect_terminal - Detect terminal capabilities and set defaults
detect_terminal() {
    if [[ -t 1 ]]; then
        SENTINEL_CLI_ARGS[terminal]="true"
        if [[ -z "${NO_COLOR:-}" ]]; then
            SENTINEL_CLI_ARGS[color]="${SENTINEL_CLI_ARGS[color]:-auto}"
        else
            SENTINEL_CLI_ARGS[color]="false"
        fi
    else
        SENTINEL_CLI_ARGS[terminal]="false"
        SENTINEL_CLI_ARGS[color]="false"
    fi

    # Check terminal width
    if command -v tput &>/dev/null; then
        SENTINEL_CLI_ARGS[term_width]="${COLUMNS:-$(tput cols 2>/dev/null || echo 80)}"
    else
        SENTINEL_CLI_ARGS[term_width]="${COLUMNS:-80}"
    fi
}

# setup_output_mode - Configure output based on CLI args
setup_output_mode() {
    detect_terminal

    # Apply color setting
    if [[ "${SENTINEL_CLI_ARGS[color]}" == "false" ]]; then
        export NO_COLOR=1
    elif [[ "${SENTINEL_CLI_ARGS[color]}" == "true" ]]; then
        unset NO_COLOR
    fi

    # Set debug mode
    if [[ "${SENTINEL_CLI_ARGS[debug]}" == "true" ]]; then
        set -x
    fi

    # Set up output redirection
    if [[ -n "${SENTINEL_CLI_ARGS[output]:-}" ]]; then
        exec 1> "${SENTINEL_CLI_ARGS[output]}"
    fi
}
