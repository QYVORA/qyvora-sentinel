#!/usr/bin/env bash
# reporting.sh - Comprehensive reporting system for QYVORA Sentinel.
# Generates findings, risk scores, and multi-format reports (text, JSON, Markdown, HTML).

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
SENTINEL_REPORT_DIR="${SENTINEL_REPORT_DIR:-}"
SENTINEL_FINDING_COUNT=0

declare -ga SENTINEL_FINDING_ID=()
declare -ga SENTINEL_FINDING_MODULE=()
declare -ga SENTINEL_FINDING_SEVERITY=()
declare -ga SENTINEL_FINDING_TITLE=()
declare -ga SENTINEL_FINDING_EVIDENCE=()
declare -ga SENTINEL_FINDING_RECOMMENDATION=()
declare -ga SENTINEL_FINDING_REFERENCE=()

# Risk score weights (readonly)
readonly SENTINEL_RISK_WEIGHT_CRITICAL=25
readonly SENTINEL_RISK_WEIGHT_HIGH=15
readonly SENTINEL_RISK_WEIGHT_MEDIUM=8
readonly SENTINEL_RISK_WEIGHT_LOW=3
readonly SENTINEL_RISK_WEIGHT_INFO=0

# Scan metadata (set externally or via init)
SENTINEL_SCAN_START_TIME=""
SENTINEL_SCAN_END_TIME=""
SENTINEL_SCAN_HOSTNAME=""

# --- Initialization ---

reporting_init() {
    SENTINEL_REPORT_DIR="${SENTINEL_REPORT_DIR:-$(pwd)/reports}"
    SENTINEL_SCAN_HOSTNAME="$(get_hostname 2>/dev/null || hostname 2>/dev/null || echo 'unknown')"

    if [[ ! -d "${SENTINEL_REPORT_DIR}" ]]; then
        mkdir -p "${SENTINEL_REPORT_DIR}"
    fi

    log_debug "Reporting initialized. Report directory: ${SENTINEL_REPORT_DIR}"
}

# --- Finding Management ---

add_finding() {
    local -r module="${1}"
    local -r title="${2}"
    local -r severity="${3}"
    local -r evidence="${4:-}"
    local -r recommendation="${5:-}"
    local -r reference="${6:-}"

    local severity_upper
    severity_upper="$(echo "${severity}" | tr '[:lower:]' '[:upper:]')"

    (( SENTINEL_FINDING_COUNT++ ))

    local -r finding_id="${SENTINEL_FINDING_COUNT}"
    local timestamp
    timestamp="$(date -u '+%Y-%m-%dT%H:%M:%SZ')"

    # Populate the parallel arrays
    SENTINEL_FINDING_ID+=("${finding_id}")
    SENTINEL_FINDING_MODULE+=("${module}")
    SENTINEL_FINDING_SEVERITY+=("${severity_upper}")
    SENTINEL_FINDING_TITLE+=("${title}")
    SENTINEL_FINDING_EVIDENCE+=("${evidence}")
    SENTINEL_FINDING_RECOMMENDATION+=("${recommendation}")
    SENTINEL_FINDING_REFERENCE+=("${reference}")

    # Populate the pipe-delimited SENTINEL_FINDINGS array (used by report output)
    if declare -p SENTINEL_FINDINGS &>/dev/null; then
        local finding="${severity_upper}|${module}|${title}|${evidence}|${timestamp}"
        SENTINEL_FINDINGS+=("${finding}")
    fi

    # Update the sentinel-level finding counts for summary display
    if declare -p SENTINEL_FINDING_COUNTS &>/dev/null; then
        local current_count=0
        if [[ -v "SENTINEL_FINDING_COUNTS[${severity_upper}]" ]]; then
            current_count="${SENTINEL_FINDING_COUNTS[${severity_upper}]}"
        fi
        SENTINEL_FINDING_COUNTS["${severity_upper}"]=$(( current_count + 1 ))
    fi

    # Display unless quiet
    if [[ "${SENTINEL_CLI_ARGS[quiet]:-false}" != "true" ]]; then
        print_finding "${severity}" "[${module}] ${title}"
    fi

    log_debug "Finding #${finding_id} added: [${severity_upper}] ${title}"
}

clear_findings() {
    SENTINEL_FINDING_COUNT=0
    SENTINEL_FINDING_ID=()
    SENTINEL_FINDING_MODULE=()
    SENTINEL_FINDING_SEVERITY=()
    SENTINEL_FINDING_TITLE=()
    SENTINEL_FINDING_EVIDENCE=()
    SENTINEL_FINDING_RECOMMENDATION=()
    SENTINEL_FINDING_REFERENCE=()

    log_debug "All findings cleared."
}

get_findings_count() {
    printf '%s' "${SENTINEL_FINDING_COUNT}"
}

_get_severity_weight() {
    local -r severity="${1}"

    case "${severity}" in
        CRITICAL) printf '%s' "${SENTINEL_RISK_WEIGHT_CRITICAL}" ;;
        HIGH)     printf '%s' "${SENTINEL_RISK_WEIGHT_HIGH}" ;;
        MEDIUM)   printf '%s' "${SENTINEL_RISK_WEIGHT_MEDIUM}" ;;
        LOW)      printf '%s' "${SENTINEL_RISK_WEIGHT_LOW}" ;;
        *)        printf '%s' "${SENTINEL_RISK_WEIGHT_INFO}" ;;
    esac
}

get_findings_by_severity() {
    local -r severity="${1}"
    local severity_upper
    severity_upper="$(echo "${severity}" | tr '[:lower:]' '[:upper:]')"

    local i
    for (( i = 0; i < SENTINEL_FINDING_COUNT; i++ )); do
        if [[ "${SENTINEL_FINDING_SEVERITY[${i}]}" == "${severity_upper}" ]]; then
            printf '%s\n' "${SENTINEL_FINDING_ID[${i}]}"
        fi
    done
}

get_findings_by_module() {
    local -r module="${1}"

    local i
    for (( i = 0; i < SENTINEL_FINDING_COUNT; i++ )); do
        if [[ "${SENTINEL_FINDING_MODULE[${i}]}" == "${module}" ]]; then
            printf '%s\n' "${SENTINEL_FINDING_ID[${i}]}"
        fi
    done
}

_get_findings_array_indices() {
    local -r severity="${1}" 2>/dev/null || true
    local -r module="${2:-}" 2>/dev/null || true

    local indices=()
    local i
    for (( i = 0; i < SENTINEL_FINDING_COUNT; i++ )); do
        local match=1
        if [[ -n "${severity}" ]]; then
            if [[ "${SENTINEL_FINDING_SEVERITY[${i}]}" != "${severity^^}" ]]; then
                match=0
            fi
        fi
        if [[ -n "${module}" && ${match} -eq 1 ]]; then
            if [[ "${SENTINEL_FINDING_MODULE[${i}]}" != "${module}" ]]; then
                match=0
            fi
        fi
        if [[ ${match} -eq 1 ]]; then
            indices+=("${i}")
        fi
    done

    printf '%s\n' "${indices[@]+"${indices[@]}"}"
}

# --- Risk Score ---

calculate_risk_score() {
    if [[ "${SENTINEL_FINDING_COUNT}" -eq 0 ]]; then
        printf '0'
        return
    fi

    local total_score=0
    local max_possible=0
    local i weight

    for (( i = 0; i < SENTINEL_FINDING_COUNT; i++ )); do
        weight=$(_get_severity_weight "${SENTINEL_FINDING_SEVERITY[${i}]}")
        (( total_score += weight ))
    done

    # Max possible: all findings at CRITICAL
    max_possible=$(( SENTINEL_FINDING_COUNT * SENTINEL_RISK_WEIGHT_CRITICAL ))

    if [[ "${max_possible}" -eq 0 ]]; then
        printf '0'
        return
    fi

    local score
    score=$(( (total_score * 100) / max_possible ))

    if [[ "${score}" -gt 100 ]]; then
        score=100
    fi

    printf '%s' "${score}"
}

# --- Severity / Module Breakdown Helpers ---

_get_severity_breakdown() {
    local critical=0 high=0 medium=0 low=0 info=0
    local i

    for (( i = 0; i < SENTINEL_FINDING_COUNT; i++ )); do
        case "${SENTINEL_FINDING_SEVERITY[${i}]}" in
            CRITICAL) (( critical++ )) ;;
            HIGH)     (( high++ )) ;;
            MEDIUM)   (( medium++ )) ;;
            LOW)      (( low++ )) ;;
            *)        (( info++ )) ;;
        esac
    done

    printf 'CRITICAL=%d HIGH=%d MEDIUM=%d LOW=%d INFO=%d' \
        "${critical}" "${high}" "${medium}" "${low}" "${info}"
}

_get_module_breakdown() {
    local -A modules=()
    local i

    for (( i = 0; i < SENTINEL_FINDING_COUNT; i++ )); do
        local mod="${SENTINEL_FINDING_MODULE[${i}]}"
        modules["${mod}"]=$(( ${modules["${mod}"]:-0} + 1 ))
    done

    local mod
    for mod in "${!modules[@]}"; do
        printf '%s=%d ' "${mod}" "${modules[${mod}]}"
    done
}

_get_scan_duration() {
    if [[ -n "${SENTINEL_SCAN_START_TIME}" && -n "${SENTINEL_SCAN_END_TIME}" ]]; then
        local start_epoch end_epoch duration
        start_epoch="$(date -d "${SENTINEL_SCAN_START_TIME}" +%s 2>/dev/null || echo 0)"
        end_epoch="$(date -d "${SENTINEL_SCAN_END_TIME}" +%s 2>/dev/null || echo 0)"
        duration=$(( end_epoch - start_epoch ))
        if [[ "${duration}" -lt 0 ]]; then
            duration=0
        fi
        printf '%ds' "${duration}"
    else
        printf 'N/A'
    fi
}

_report_print_severity_breakdown() {
    local critical=0 high=0 medium=0 low=0 info=0
    local i
    for (( i = 0; i < SENTINEL_FINDING_COUNT; i++ )); do
        case "${SENTINEL_FINDING_SEVERITY[${i}]}" in
            CRITICAL) (( critical++ )) ;;
            HIGH)     (( high++ )) ;;
            MEDIUM)   (( medium++ )) ;;
            LOW)      (( low++ )) ;;
            *)        (( info++ )) ;;
        esac
    done
    echo "  CRITICAL : ${critical}"
    echo "  HIGH     : ${high}"
    echo "  MEDIUM   : ${medium}"
    echo "  LOW      : ${low}"
    echo "  INFO     : ${info}"
}

# --- Report Sections ---

report_executive_summary() {
    local -r findings_file="${1}"
    local risk_score
    risk_score="$(calculate_risk_score)"

    echo "EXECUTIVE SUMMARY"
    echo "================================================================"
    echo ""
    echo "Host:             ${SENTINEL_SCAN_HOSTNAME}"
    echo "Scan Date:        $(date -u '+%Y-%m-%d %H:%M:%S UTC')"
    echo "Scan Duration:    $(_get_scan_duration)"
    echo "Total Findings:   ${SENTINEL_FINDING_COUNT}"
    echo "Risk Score:       ${risk_score}/100"
    echo ""
    echo "Severity Breakdown:"
    _report_print_severity_breakdown
    echo ""
    echo "================================================================"
}

report_system_overview() {
    echo "SYSTEM OVERVIEW"
    echo "================================================================"
    echo ""
    echo "Hostname:         ${SENTINEL_SCAN_HOSTNAME}"
    echo "Kernel:           $(uname -r 2>/dev/null || echo 'N/A')"
    echo "OS:               $(cat /etc/os-release 2>/dev/null | grep '^PRETTY_NAME' | cut -d= -f2 | tr -d '"' || echo 'N/A')"
    echo "Architecture:     $(uname -m 2>/dev/null || echo 'N/A')"
    echo "Uptime:           $(uptime -p 2>/dev/null || echo 'N/A')"
    echo "Report Directory: ${SENTINEL_REPORT_DIR}"
    echo ""
    echo "================================================================"
}

report_recommendations() {
    local -r output="${1:-/dev/stdout}"
    local critical_count=0 high_count=0 medium_count=0 low_count=0 info_count=0
    local i

    for (( i = 0; i < SENTINEL_FINDING_COUNT; i++ )); do
        case "${SENTINEL_FINDING_SEVERITY[${i}]}" in
            CRITICAL) (( critical_count++ )) ;;
            HIGH)     (( high_count++ )) ;;
            MEDIUM)   (( medium_count++ )) ;;
            LOW)      (( low_count++ )) ;;
            *)        (( info_count++ )) ;;
        esac
    done

    {
        echo "PRIORITIZED RECOMMENDATIONS"
        echo "================================================================"
        echo ""

        local priority=1

        if [[ "${critical_count}" -gt 0 ]]; then
            echo "[PRIORITY ${priority} - IMMEDIATE ACTION REQUIRED]"
            echo "  ${critical_count} CRITICAL finding(s) require immediate attention."
            echo "  These represent the highest risk to system security."
            echo ""

            local j
            for (( j = 0; j < SENTINEL_FINDING_COUNT; j++ )); do
                if [[ "${SENTINEL_FINDING_SEVERITY[${j}]}" == "CRITICAL" ]]; then
                    echo "  [F-${SENTINEL_FINDING_ID[${j}]}] ${SENTINEL_FINDING_TITLE[${j}]}"
                    echo "    Module: ${SENTINEL_FINDING_MODULE[${j}]}"
                    if [[ -n "${SENTINEL_FINDING_RECOMMENDATION[${j}]}" ]]; then
                        echo "    Action: ${SENTINEL_FINDING_RECOMMENDATION[${j}]}"
                    fi
                    echo ""
                fi
            done
            (( priority++ ))
        fi

        if [[ "${high_count}" -gt 0 ]]; then
            echo "[PRIORITY ${priority} - URGENT]"
            echo "  ${high_count} HIGH severity finding(s) should be addressed soon."
            echo ""

            local j
            for (( j = 0; j < SENTINEL_FINDING_COUNT; j++ )); do
                if [[ "${SENTINEL_FINDING_SEVERITY[${j}]}" == "HIGH" ]]; then
                    echo "  [F-${SENTINEL_FINDING_ID[${j}]}] ${SENTINEL_FINDING_TITLE[${j}]}"
                    echo "    Module: ${SENTINEL_FINDING_MODULE[${j}]}"
                    if [[ -n "${SENTINEL_FINDING_RECOMMENDATION[${j}]}" ]]; then
                        echo "    Action: ${SENTINEL_FINDING_RECOMMENDATION[${j}]}"
                    fi
                    echo ""
                fi
            done
            (( priority++ ))
        fi

        if [[ "${medium_count}" -gt 0 ]]; then
            echo "[PRIORITY ${priority} - PLAN REMEDIATION]"
            echo "  ${medium_count} MEDIUM severity finding(s) should be planned for remediation."
            echo ""

            local j
            for (( j = 0; j < SENTINEL_FINDING_COUNT; j++ )); do
                if [[ "${SENTINEL_FINDING_SEVERITY[${j}]}" == "MEDIUM" ]]; then
                    echo "  [F-${SENTINEL_FINDING_ID[${j}]}] ${SENTINEL_FINDING_TITLE[${j}]}"
                    echo "    Module: ${SENTINEL_FINDING_MODULE[${j}]}"
                    if [[ -n "${SENTINEL_FINDING_RECOMMENDATION[${j}]}" ]]; then
                        echo "    Action: ${SENTINEL_FINDING_RECOMMENDATION[${j}]}"
                    fi
                    echo ""
                fi
            done
            (( priority++ ))
        fi

        if [[ "${low_count}" -gt 0 ]]; then
            echo "[PRIORITY ${priority} - LOW RISK]"
            echo "  ${low_count} LOW severity finding(s). Address when convenient."
            echo ""

            local j
            for (( j = 0; j < SENTINEL_FINDING_COUNT; j++ )); do
                if [[ "${SENTINEL_FINDING_SEVERITY[${j}]}" == "LOW" ]]; then
                    echo "  [F-${SENTINEL_FINDING_ID[${j}]}] ${SENTINEL_FINDING_TITLE[${j}]}"
                    echo "    Module: ${SENTINEL_FINDING_MODULE[${j}]}"
                    if [[ -n "${SENTINEL_FINDING_RECOMMENDATION[${j}]}" ]]; then
                        echo "    Action: ${SENTINEL_FINDING_RECOMMENDATION[${j}]}"
                    fi
                    echo ""
                fi
            done
            (( priority++ ))
        fi

        if [[ "${info_count}" -gt 0 ]]; then
            echo "[PRIORITY ${priority} - INFORMATIONAL]"
            echo "  ${info_count} INFO finding(s). For awareness only."
            echo ""
            (( priority++ ))
        fi

        echo "================================================================"
    } > "${output}"
}

report_appendix() {
    echo "APPENDIX - SCAN METADATA"
    echo "================================================================"
    echo ""
    echo "Scanner:          QYVORA Sentinel - Linux Security Auditing Framework"
    echo "Report Generated: $(date -u '+%Y-%m-%dT%H:%M:%SZ')"
    echo "Hostname:         ${SENTINEL_SCAN_HOSTNAME}"
    echo "Kernel:           $(uname -r 2>/dev/null || echo 'N/A')"
    echo "Architecture:     $(uname -m 2>/dev/null || echo 'N/A')"
    echo "User:             $(whoami 2>/dev/null || echo 'N/A')"
    echo "UID/EUID:         $(id 2>/dev/null || echo 'N/A')"
    echo ""
    echo "Scan Timing:"
    echo "  Started:   ${SENTINEL_SCAN_START_TIME:-N/A}"
    echo "  Completed: ${SENTINEL_SCAN_END_TIME:-N/A}"
    echo "  Duration:  $(_get_scan_duration)"
    echo ""
    echo "Findings Summary:"
    echo "  Total:     ${SENTINEL_FINDING_COUNT}"
    echo "  Risk Score: $(calculate_risk_score)/100"
    echo ""

    echo "Module Breakdown:"
    local -A modules=()
    local i
    for (( i = 0; i < SENTINEL_FINDING_COUNT; i++ )); do
        local mod="${SENTINEL_FINDING_MODULE[${i}]}"
        modules["${mod}"]=$(( ${modules["${mod}"]:-0} + 1 ))
    done
    local mod
    for mod in $(printf '%s\n' "${!modules[@]}" | sort); do
        echo "  ${mod}: ${modules[${mod}]}"
    done

    echo ""
    echo "================================================================"
}

# --- Text Report ---

generate_report_text() {
    local -r output_file="${1:-}"
    local output_dest

    if [[ -n "${output_file}" ]]; then
        local dir
        dir="$(dirname "${output_file}")"
        if [[ ! -d "${dir}" ]]; then
            mkdir -p "${dir}"
        fi
        output_dest="${output_file}"
    else
        output_dest="/dev/stdout"
    fi

    {
        echo "============================================================"
        echo "       QYVORA SENTINEL - SECURITY AUDIT REPORT"
        echo "============================================================"
        echo ""

        report_executive_summary
        echo ""

        report_system_overview
        echo ""

        echo "FINDINGS DETAIL"
        echo "================================================================"
        echo ""

        if [[ "${SENTINEL_FINDING_COUNT}" -eq 0 ]]; then
            echo "  No findings reported."
        else
            local i
            for (( i = 0; i < SENTINEL_FINDING_COUNT; i++ )); do
                echo "Finding F-${SENTINEL_FINDING_ID[${i}]} [${SENTINEL_FINDING_SEVERITY[${i}]}]"
                echo "  Title:       ${SENTINEL_FINDING_TITLE[${i}]}"
                echo "  Module:      ${SENTINEL_FINDING_MODULE[${i}]}"
                echo "  Description: ${SENTINEL_FINDING_EVIDENCE[${i}]}"
                if [[ -n "${SENTINEL_FINDING_EVIDENCE[${i}]}" ]]; then
                    echo "  Evidence:    ${SENTINEL_FINDING_EVIDENCE[${i}]}"
                fi
                if [[ -n "${SENTINEL_FINDING_RECOMMENDATION[${i}]}" ]]; then
                    echo "  Recommendation: ${SENTINEL_FINDING_RECOMMENDATION[${i}]}"
                fi
                if [[ -n "${SENTINEL_FINDING_REFERENCE[${i}]}" ]]; then
                    echo "  Reference:   ${SENTINEL_FINDING_REFERENCE[${i}]}"
                fi
                echo ""
            done
        fi

        echo "================================================================"
        echo ""

        report_recommendations
        echo ""

        report_appendix

        echo ""
        echo "============================================================"
        echo "                   END OF REPORT"
        echo "============================================================"
    } > "${output_dest}"

    if [[ -n "${output_file}" ]]; then
        log_info "Text report written to ${output_file}"
    fi
}

# --- JSON Report ---

_generate_json_escape() {
    local -r text="${1}"
    local escaped="${text}"
    escaped="${escaped//\\/\\\\}"
    escaped="${escaped//\"/\\\"}"
    escaped="${escaped//$'\n'/\\n}"
    escaped="${escaped//$'\r'/\\r}"
    escaped="${escaped//$'\t'/\\t}"
    printf '%s' "${escaped}"
}

generate_report_json() {
    local -r output_file="${1:-}"
    local output_dest

    if [[ -n "${output_file}" ]]; then
        local dir
        dir="$(dirname "${output_file}")"
        if [[ ! -d "${dir}" ]]; then
            mkdir -p "${dir}"
        fi
        output_dest="${output_file}"
    else
        output_dest="/dev/stdout"
    fi

    local risk_score
    risk_score="$(calculate_risk_score)"

    local critical=0 high=0 medium=0 low=0 info=0
    local i
    for (( i = 0; i < SENTINEL_FINDING_COUNT; i++ )); do
        case "${SENTINEL_FINDING_SEVERITY[${i}]}" in
            CRITICAL) (( critical++ )) ;;
            HIGH)     (( high++ )) ;;
            MEDIUM)   (( medium++ )) ;;
            LOW)      (( low++ )) ;;
            *)        (( info++ )) ;;
        esac
    done

    {
        printf '{\n'
        printf '  "report_type": "QYVORA Sentinel Security Audit Report",\n'
        printf '  "version": "1.0",\n'
        printf '  "generated_at": "%s",\n' "$(date -u '+%Y-%m-%dT%H:%M:%SZ')"
        printf '  "hostname": "%s",\n' "$(_generate_json_escape "${SENTINEL_SCAN_HOSTNAME}")"
        printf '  "scan_start": "%s",\n' "$(_generate_json_escape "${SENTINEL_SCAN_START_TIME:-N/A}")"
        printf '  "scan_end": "%s",\n' "$(_generate_json_escape "${SENTINEL_SCAN_END_TIME:-N/A}")"
        printf '  "scan_duration": "%s",\n' "$(_get_scan_duration)"
        printf '  "total_findings": %d,\n' "${SENTINEL_FINDING_COUNT}"
        printf '  "risk_score": %d,\n' "${risk_score}"
        printf '  "severity_breakdown": {\n'
        printf '    "critical": %d,\n' "${critical}"
        printf '    "high": %d,\n' "${high}"
        printf '    "medium": %d,\n' "${medium}"
        printf '    "low": %d,\n' "${low}"
        printf '    "info": %d\n' "${info}"
        printf '  },\n'
        printf '  "findings": [\n'

        if [[ "${SENTINEL_FINDING_COUNT}" -gt 0 ]]; then
            for (( i = 0; i < SENTINEL_FINDING_COUNT; i++ )); do
                local comma=","
                if [[ $(( i + 1 )) -eq "${SENTINEL_FINDING_COUNT}" ]]; then
                    comma=""
                fi
                printf '    {\n'
                printf '      "id": %d,\n' "${SENTINEL_FINDING_ID[${i}]}"
                printf '      "module": "%s",\n' "$(_generate_json_escape "${SENTINEL_FINDING_MODULE[${i}]}")"
                printf '      "severity": "%s",\n' "${SENTINEL_FINDING_SEVERITY[${i}]}"
                printf '      "title": "%s",\n' "$(_generate_json_escape "${SENTINEL_FINDING_TITLE[${i}]}")"
                printf '      "description": "%s",\n' "$(_generate_json_escape "${SENTINEL_FINDING_EVIDENCE[${i}]}")"
                printf '      "evidence": "%s",\n' "$(_generate_json_escape "${SENTINEL_FINDING_EVIDENCE[${i}]}")"
                printf '      "recommendation": "%s",\n' "$(_generate_json_escape "${SENTINEL_FINDING_RECOMMENDATION[${i}]}")"
                printf '      "reference": "%s"\n' "$(_generate_json_escape "${SENTINEL_FINDING_REFERENCE[${i}]}")"
                printf '    }%s\n' "${comma}"
            done
        fi

        printf '  ]\n'
        printf '}\n'
    } > "${output_dest}"

    if [[ -n "${output_file}" ]]; then
        log_info "JSON report written to ${output_file}"
    fi
}

# --- Markdown Report ---

generate_report_markdown() {
    local -r output_file="${1:-}"
    local output_dest

    if [[ -n "${output_file}" ]]; then
        local dir
        dir="$(dirname "${output_file}")"
        if [[ ! -d "${dir}" ]]; then
            mkdir -p "${dir}"
        fi
        output_dest="${output_file}"
    else
        output_dest="/dev/stdout"
    fi

    local risk_score
    risk_score="$(calculate_risk_score)"

    local critical=0 high=0 medium=0 low=0 info=0
    local i
    for (( i = 0; i < SENTINEL_FINDING_COUNT; i++ )); do
        case "${SENTINEL_FINDING_SEVERITY[${i}]}" in
            CRITICAL) (( critical++ )) ;;
            HIGH)     (( high++ )) ;;
            MEDIUM)   (( medium++ )) ;;
            LOW)      (( low++ )) ;;
            *)        (( info++ )) ;;
        esac
    done

    {
        echo "# QYVORA Sentinel - Security Audit Report"
        echo ""
        echo "**Generated:** $(date -u '+%Y-%m-%d %H:%M:%S UTC')"
        echo "**Host:** ${SENTINEL_SCAN_HOSTNAME}"
        echo "**Risk Score:** ${risk_score}/100"
        echo ""

        echo "## Executive Summary"
        echo ""
        echo "| Metric | Value |"
        echo "|--------|-------|"
        echo "| Hostname | ${SENTINEL_SCAN_HOSTNAME} |"
        echo "| Scan Date | $(date -u '+%Y-%m-%d %H:%M:%S UTC') |"
        echo "| Scan Duration | $(_get_scan_duration) |"
        echo "| Total Findings | ${SENTINEL_FINDING_COUNT} |"
        echo "| Risk Score | ${risk_score}/100 |"
        echo ""

        echo "### Severity Breakdown"
        echo ""
        echo "| Severity | Count |"
        echo "|----------|-------|"
        echo "| CRITICAL | ${critical} |"
        echo "| HIGH | ${high} |"
        echo "| MEDIUM | ${medium} |"
        echo "| LOW | ${low} |"
        echo "| INFO | ${info} |"
        echo ""

        echo "### Module Breakdown"
        echo ""
        local -A modules=()
        for (( i = 0; i < SENTINEL_FINDING_COUNT; i++ )); do
            local mod="${SENTINEL_FINDING_MODULE[${i}]}"
            modules["${mod}"]=$(( ${modules["${mod}"]:-0} + 1 ))
        done
        echo "| Module | Findings |"
        echo "|--------|----------|"
        local mod
        for mod in $(printf '%s\n' "${!modules[@]}" | sort); do
            echo "| ${mod} | ${modules[${mod}]} |"
        done
        echo ""

        echo "## System Overview"
        echo ""
        echo "| Property | Value |"
        echo "|----------|-------|"
        echo "| Kernel | $(uname -r 2>/dev/null || echo 'N/A') |"
        echo "| Architecture | $(uname -m 2>/dev/null || echo 'N/A') |"
        echo "| OS | $(cat /etc/os-release 2>/dev/null | grep '^PRETTY_NAME' | cut -d= -f2 | tr -d '"' || echo 'N/A') |"
        echo ""

        echo "## Findings"
        echo ""

        if [[ "${SENTINEL_FINDING_COUNT}" -eq 0 ]]; then
            echo "No findings reported."
            echo ""
        else
            for (( i = 0; i < SENTINEL_FINDING_COUNT; i++ )); do
                echo "### F-${SENTINEL_FINDING_ID[${i}]} [${SENTINEL_FINDING_SEVERITY[${i}]}] - ${SENTINEL_FINDING_TITLE[${i}]}"
                echo ""
                echo "- **Module:** ${SENTINEL_FINDING_MODULE[${i}]}"
                echo "- **Severity:** ${SENTINEL_FINDING_SEVERITY[${i}]}"
                echo "- **Description:** ${SENTINEL_FINDING_EVIDENCE[${i}]}"
                if [[ -n "${SENTINEL_FINDING_EVIDENCE[${i}]}" ]]; then
                    echo "- **Evidence:**"
                    echo '  ```'
                    echo "  ${SENTINEL_FINDING_EVIDENCE[${i}]}"
                    echo '  ```'
                fi
                if [[ -n "${SENTINEL_FINDING_RECOMMENDATION[${i}]}" ]]; then
                    echo "- **Recommendation:** ${SENTINEL_FINDING_RECOMMENDATION[${i}]}"
                fi
                if [[ -n "${SENTINEL_FINDING_REFERENCE[${i}]}" ]]; then
                    echo "- **Reference:** ${SENTINEL_FINDING_REFERENCE[${i}]}"
                fi
                echo ""
                echo "---"
                echo ""
            done
        fi

        echo "## Recommendations"
        echo ""

        local priority=1
        if [[ "${critical}" -gt 0 ]]; then
            echo "### Priority ${priority} - Immediate Action Required"
            echo ""
            echo "${critical} CRITICAL finding(s) require immediate attention."
            echo ""
            for (( j = 0; j < SENTINEL_FINDING_COUNT; j++ )); do
                if [[ "${SENTINEL_FINDING_SEVERITY[${j}]}" == "CRITICAL" ]]; then
                    echo "- **F-${SENTINEL_FINDING_ID[${j}]}:** ${SENTINEL_FINDING_TITLE[${j}]}"
                    if [[ -n "${SENTINEL_FINDING_RECOMMENDATION[${j}]}" ]]; then
                        echo "  - Action: ${SENTINEL_FINDING_RECOMMENDATION[${j}]}"
                    fi
                fi
            done
            echo ""
            (( priority++ ))
        fi

        if [[ "${high}" -gt 0 ]]; then
            echo "### Priority ${priority} - Urgent"
            echo ""
            echo "${high} HIGH severity finding(s) should be addressed soon."
            echo ""
            for (( j = 0; j < SENTINEL_FINDING_COUNT; j++ )); do
                if [[ "${SENTINEL_FINDING_SEVERITY[${j}]}" == "HIGH" ]]; then
                    echo "- **F-${SENTINEL_FINDING_ID[${j}]}:** ${SENTINEL_FINDING_TITLE[${j}]}"
                    if [[ -n "${SENTINEL_FINDING_RECOMMENDATION[${j}]}" ]]; then
                        echo "  - Action: ${SENTINEL_FINDING_RECOMMENDATION[${j}]}"
                    fi
                fi
            done
            echo ""
            (( priority++ ))
        fi

        if [[ "${medium}" -gt 0 ]]; then
            echo "### Priority ${priority} - Plan Remediation"
            echo ""
            echo "${medium} MEDIUM severity finding(s) should be planned for remediation."
            echo ""
            (( priority++ ))
        fi

        if [[ "${low}" -gt 0 ]]; then
            echo "### Priority ${priority} - Low Risk"
            echo ""
            echo "${low} LOW severity finding(s). Address when convenient."
            echo ""
            (( priority++ ))
        fi

        echo "## Appendix"
        echo ""
        echo "Report generated by **QYVORA Sentinel** - Linux Security Auditing Framework"
        echo ""
        echo "| Metadata | Value |"
        echo "|----------|-------|"
        echo "| Scan Started | ${SENTINEL_SCAN_START_TIME:-N/A} |"
        echo "| Scan Completed | ${SENTINEL_SCAN_END_TIME:-N/A} |"
        echo "| Scan Duration | $(_get_scan_duration) |"
        echo "| Total Findings | ${SENTINEL_FINDING_COUNT} |"
        echo "| Risk Score | ${risk_score}/100 |"
        echo ""
        echo "*End of Report*"
    } > "${output_dest}"

    if [[ -n "${output_file}" ]]; then
        log_info "Markdown report written to ${output_file}"
    fi
}

# --- HTML Report ---

generate_report_html() {
    local -r output_file="${1:-}"
    local output_dest

    if [[ -n "${output_file}" ]]; then
        local dir
        dir="$(dirname "${output_file}")"
        if [[ ! -d "${dir}" ]]; then
            mkdir -p "${dir}"
        fi
        output_dest="${output_file}"
    else
        output_dest="/dev/stdout"
    fi

    local risk_score
    risk_score="$(calculate_risk_score)"

    local critical=0 high=0 medium=0 low_count_val=0 info_count_val=0
    local i
    for (( i = 0; i < SENTINEL_FINDING_COUNT; i++ )); do
        case "${SENTINEL_FINDING_SEVERITY[${i}]}" in
            CRITICAL) (( critical++ )) ;;
            HIGH)     (( high++ )) ;;
            MEDIUM)   (( medium++ )) ;;
            LOW)      (( low_count_val++ )) ;;
            *)        (( info_count_val++ )) ;;
        esac
    done

    local risk_label="MINIMAL"
    local risk_color="#27ae60"
    if [[ "${risk_score}" -ge 80 ]]; then
        risk_label="CRITICAL"
        risk_color="#c0392b"
    elif [[ "${risk_score}" -ge 60 ]]; then
        risk_label="HIGH"
        risk_color="#e74c3c"
    elif [[ "${risk_score}" -ge 40 ]]; then
        risk_label="MEDIUM"
        risk_color="#f39c12"
    elif [[ "${risk_score}" -ge 20 ]]; then
        risk_label="LOW"
        risk_color="#e67e22"
    fi

    {
        echo '<!DOCTYPE html>'
        echo '<html lang="en">'
        echo '<head>'
        echo '<meta charset="UTF-8">'
        echo '<meta name="viewport" content="width=device-width, initial-scale=1.0">'
        echo '<title>QYVORA Sentinel - Security Audit Report</title>'
        echo '<style>'
        echo '  * { margin: 0; padding: 0; box-sizing: border-box; }'
        echo '  body { font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif; background: #f4f6f9; color: #2c3e50; line-height: 1.6; }'
        echo '  .header { background: linear-gradient(135deg, #1a2a3a, #2c3e50); color: #fff; padding: 40px 20px; text-align: center; }'
        echo '  .header h1 { font-size: 2.2em; margin-bottom: 8px; letter-spacing: 1px; }'
        echo '  .header .subtitle { font-size: 1.1em; opacity: 0.85; }'
        echo '  .container { max-width: 1100px; margin: 0 auto; padding: 30px 20px; }'
        echo '  .section { background: #fff; border-radius: 8px; box-shadow: 0 2px 8px rgba(0,0,0,0.07); margin-bottom: 30px; padding: 30px; }'
        echo '  .section h2 { color: #1a2a3a; border-bottom: 3px solid #3498db; padding-bottom: 10px; margin-bottom: 20px; font-size: 1.4em; }'
        echo '  .section h3 { color: #2c3e50; margin: 20px 0 10px 0; }'
        echo '  .summary-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(180px, 1fr)); gap: 16px; margin-bottom: 20px; }'
        echo '  .summary-card { background: #f8f9fa; border-radius: 6px; padding: 18px; text-align: center; border-left: 4px solid #3498db; }'
        echo '  .summary-card .value { font-size: 2em; font-weight: 700; }'
        echo '  .summary-card .label { font-size: 0.85em; color: #7f8c8d; text-transform: uppercase; letter-spacing: 0.5px; }'
        echo '  .risk-badge { display: inline-block; padding: 6px 18px; border-radius: 20px; color: #fff; font-weight: 700; font-size: 1.1em; }'
        echo '  table { width: 100%; border-collapse: collapse; margin: 15px 0; }'
        echo '  th { background: #2c3e50; color: #fff; padding: 12px 15px; text-align: left; font-weight: 600; }'
        echo '  td { padding: 10px 15px; border-bottom: 1px solid #ecf0f1; }'
        echo '  tr:hover td { background: #f8f9fa; }'
        echo '  .severity-CRITICAL { background: #c0392b; color: #fff; padding: 3px 10px; border-radius: 12px; font-weight: 700; font-size: 0.85em; }'
        echo '  .severity-HIGH { background: #e74c3c; color: #fff; padding: 3px 10px; border-radius: 12px; font-weight: 700; font-size: 0.85em; }'
        echo '  .severity-MEDIUM { background: #f39c12; color: #fff; padding: 3px 10px; border-radius: 12px; font-weight: 700; font-size: 0.85em; }'
        echo '  .severity-LOW { background: #e67e22; color: #fff; padding: 3px 10px; border-radius: 12px; font-weight: 700; font-size: 0.85em; }'
        echo '  .severity-INFO { background: #95a5a6; color: #fff; padding: 3px 10px; border-radius: 12px; font-weight: 700; font-size: 0.85em; }'
        echo '  .finding-card { background: #fff; border: 1px solid #ecf0f1; border-radius: 8px; margin: 15px 0; overflow: hidden; }'
        echo '  .finding-header { padding: 15px 20px; display: flex; justify-content: space-between; align-items: center; border-bottom: 1px solid #ecf0f1; }'
        echo '  .finding-body { padding: 15px 20px; }'
        echo '  .finding-body p { margin: 8px 0; }'
        echo '  .evidence-box { background: #f8f9fa; border-left: 4px solid #3498db; padding: 12px 16px; margin: 10px 0; font-family: monospace; font-size: 0.9em; white-space: pre-wrap; }'
        echo '  .recommendation { background: #eaf6ff; border: 1px solid #3498db; border-radius: 6px; padding: 12px 16px; margin-top: 10px; }'
        echo '  .recommendation strong { color: #2980b9; }'
        echo '  .footer { text-align: center; padding: 20px; color: #95a5a6; font-size: 0.85em; }'
        echo '</style>'
        echo '</head>'
        echo '<body>'

        # Header
        echo '<div class="header">'
        echo '<h1>QYVORA Sentinel</h1>'
        echo '<div class="subtitle">Security Audit Report</div>'
        echo '</div>'

        echo '<div class="container">'

        # Executive Summary
        echo '<div class="section">'
        echo '<h2>Executive Summary</h2>'
        echo '<div class="summary-grid">'
        echo "<div class=\"summary-card\"><div class=\"value\">${SENTINEL_SCAN_HOSTNAME}</div><div class=\"label\">Hostname</div></div>"
        echo "<div class=\"summary-card\"><div class=\"value\">$(date -u '+%Y-%m-%d %H:%M')</div><div class=\"label\">Scan Date</div></div>"
        echo "<div class=\"summary-card\"><div class=\"value\">$(_get_scan_duration)</div><div class=\"label\">Duration</div></div>"
        echo "<div class=\"summary-card\"><div class=\"value\">${SENTINEL_FINDING_COUNT}</div><div class=\"label\">Total Findings</div></div>"
        echo "<div class=\"summary-card\"><div class=\"value\" style=\"color:${risk_color}\">${risk_score}/100</div><div class=\"label\">Risk Score</div></div>"
        echo "<div class=\"summary-card\"><div class=\"value\"><span class=\"risk-badge\" style=\"background:${risk_color}\">${risk_label}</span></div><div class=\"label\">Risk Level</div></div>"
        echo '</div>'

        # Severity Breakdown Table
        echo '<h3>Severity Breakdown</h3>'
        echo '<table>'
        echo '<tr><th>Severity</th><th>Count</th><th>Percentage</th></tr>'
        local -a sev_names=("CRITICAL" "HIGH" "MEDIUM" "LOW" "INFO")
        local -a sev_counts=("${critical}" "${high}" "${medium}" "${low_count_val}" "${info_count_val}")
        local si
        for si in "${!sev_names[@]}"; do
            local pct=0
            if [[ "${SENTINEL_FINDING_COUNT}" -gt 0 ]]; then
                pct=$(( (sev_counts[${si}] * 100) / SENTINEL_FINDING_COUNT ))
            fi
            echo "<tr><td><span class=\"severity-${sev_names[${si}]}\">${sev_names[${si}]}</span></td><td>${sev_counts[${si}]}</td><td>${pct}%</td></tr>"
        done
        echo '</table>'

        # Module Breakdown Table
        echo '<h3>Module Breakdown</h3>'
        echo '<table>'
        echo '<tr><th>Module</th><th>Findings</th></tr>'
        local -A hmod=()
        for (( i = 0; i < SENTINEL_FINDING_COUNT; i++ )); do
            local hm="${SENTINEL_FINDING_MODULE[${i}]}"
            hmod["${hm}"]=$(( ${hmod["${hm}"]:-0} + 1 ))
        done
        local hm
        for hm in $(printf '%s\n' "${!hmod[@]}" | sort); do
            echo "<tr><td>${hm}</td><td>${hmod[${hm}]}</td></tr>"
        done
        echo '</table>'
        echo '</div>'

        # System Overview
        echo '<div class="section">'
        echo '<h2>System Overview</h2>'
        echo '<table>'
        echo '<tr><th>Property</th><th>Value</th></tr>'
        echo "<tr><td>Hostname</td><td>${SENTINEL_SCAN_HOSTNAME}</td></tr>"
        echo "<tr><td>Kernel</td><td>$(uname -r 2>/dev/null || echo 'N/A')</td></tr>"
        echo "<tr><td>Architecture</td><td>$(uname -m 2>/dev/null || echo 'N/A')</td></tr>"
        echo "<tr><td>OS</td><td>$(cat /etc/os-release 2>/dev/null | grep '^PRETTY_NAME' | cut -d= -f2 | tr -d '"' || echo 'N/A')</td></tr>"
        echo "<tr><td>User</td><td>$(whoami 2>/dev/null || echo 'N/A')</td></tr>"
        echo '</table>'
        echo '</div>'

        # Findings
        echo '<div class="section">'
        echo '<h2>Findings</h2>'

        if [[ "${SENTINEL_FINDING_COUNT}" -eq 0 ]]; then
            echo '<p>No findings reported.</p>'
        else
            for (( i = 0; i < SENTINEL_FINDING_COUNT; i++ )); do
                local sev="${SENTINEL_FINDING_SEVERITY[${i}]}"
                echo '<div class="finding-card">'
                echo '<div class="finding-header">'
                echo "<strong>F-${SENTINEL_FINDING_ID[${i}]}: ${SENTINEL_FINDING_TITLE[${i}]}</strong>"
                echo "<span class=\"severity-${sev}\">${sev}</span>"
                echo '</div>'
                echo '<div class="finding-body">'
                echo "<p><strong>Module:</strong> ${SENTINEL_FINDING_MODULE[${i}]}</p>"
                echo "<p>${SENTINEL_FINDING_EVIDENCE[${i}]}</p>"
                if [[ -n "${SENTINEL_FINDING_EVIDENCE[${i}]}" ]]; then
                    echo '<div class="evidence-box">'
                    printf '%s\n' "${SENTINEL_FINDING_EVIDENCE[${i}]}"
                    echo '</div>'
                fi
                if [[ -n "${SENTINEL_FINDING_RECOMMENDATION[${i}]}" ]]; then
                    echo '<div class="recommendation">'
                    echo "<strong>Recommendation:</strong> ${SENTINEL_FINDING_RECOMMENDATION[${i}]}"
                    echo '</div>'
                fi
                if [[ -n "${SENTINEL_FINDING_REFERENCE[${i}]}" ]]; then
                    echo "<p><strong>Reference:</strong> ${SENTINEL_FINDING_REFERENCE[${i}]}</p>"
                fi
                echo '</div>'
                echo '</div>'
            done
        fi
        echo '</div>'

        # Recommendations
        echo '<div class="section">'
        echo '<h2>Prioritized Recommendations</h2>'

        local priority=1
        if [[ "${critical}" -gt 0 ]]; then
            echo "<h3>Priority ${priority} - Immediate Action Required</h3>"
            echo "<p>${critical} CRITICAL finding(s) require immediate attention.</p>"
            echo '<ul>'
            for (( j = 0; j < SENTINEL_FINDING_COUNT; j++ )); do
                if [[ "${SENTINEL_FINDING_SEVERITY[${j}]}" == "CRITICAL" ]]; then
                    echo "<li><strong>F-${SENTINEL_FINDING_ID[${j}]}:</strong> ${SENTINEL_FINDING_TITLE[${j}]}"
                    if [[ -n "${SENTINEL_FINDING_RECOMMENDATION[${j}]}" ]]; then
                        echo " - ${SENTINEL_FINDING_RECOMMENDATION[${j}]}"
                    fi
                    echo '</li>'
                fi
            done
            echo '</ul>'
            (( priority++ ))
        fi

        if [[ "${high}" -gt 0 ]]; then
            echo "<h3>Priority ${priority} - Urgent</h3>"
            echo "<p>${high} HIGH severity finding(s) should be addressed soon.</p>"
            echo '<ul>'
            for (( j = 0; j < SENTINEL_FINDING_COUNT; j++ )); do
                if [[ "${SENTINEL_FINDING_SEVERITY[${j}]}" == "HIGH" ]]; then
                    echo "<li><strong>F-${SENTINEL_FINDING_ID[${j}]}:</strong> ${SENTINEL_FINDING_TITLE[${j}]}"
                    if [[ -n "${SENTINEL_FINDING_RECOMMENDATION[${j}]}" ]]; then
                        echo " - ${SENTINEL_FINDING_RECOMMENDATION[${j}]}"
                    fi
                    echo '</li>'
                fi
            done
            echo '</ul>'
            (( priority++ ))
        fi

        if [[ "${medium}" -gt 0 ]]; then
            echo "<h3>Priority ${priority} - Plan Remediation</h3>"
            echo "<p>${medium} MEDIUM severity finding(s) should be planned for remediation.</p>"
            echo '<ul>'
            for (( j = 0; j < SENTINEL_FINDING_COUNT; j++ )); do
                if [[ "${SENTINEL_FINDING_SEVERITY[${j}]}" == "MEDIUM" ]]; then
                    echo "<li><strong>F-${SENTINEL_FINDING_ID[${j}]}:</strong> ${SENTINEL_FINDING_TITLE[${j}]}"
                    if [[ -n "${SENTINEL_FINDING_RECOMMENDATION[${j}]}" ]]; then
                        echo " - ${SENTINEL_FINDING_RECOMMENDATION[${j}]}"
                    fi
                    echo '</li>'
                fi
            done
            echo '</ul>'
            (( priority++ ))
        fi

        if [[ "${low_count_val}" -gt 0 ]]; then
            echo "<h3>Priority ${priority} - Low Risk</h3>"
            echo "<p>${low_count_val} LOW severity finding(s). Address when convenient.</p>"
            (( priority++ ))
        fi

        echo '</div>'

        # Appendix
        echo '<div class="section">'
        echo '<h2>Appendix</h2>'
        echo '<table>'
        echo '<tr><th>Metadata</th><th>Value</th></tr>'
        echo '<tr><td>Scanner</td><td>QYVORA Sentinel</td></tr>'
        echo "<tr><td>Generated</td><td>$(date -u '+%Y-%m-%dT%H:%M:%SZ')</td></tr>"
        echo "<tr><td>Hostname</td><td>${SENTINEL_SCAN_HOSTNAME}</td></tr>"
        echo "<tr><td>Scan Started</td><td>${SENTINEL_SCAN_START_TIME:-N/A}</td></tr>"
        echo "<tr><td>Scan Completed</td><td>${SENTINEL_SCAN_END_TIME:-N/A}</td></tr>"
        echo "<tr><td>Duration</td><td>$(_get_scan_duration)</td></tr>"
        echo "<tr><td>Total Findings</td><td>${SENTINEL_FINDING_COUNT}</td></tr>"
        echo "<tr><td>Risk Score</td><td>${risk_score}/100</td></tr>"
        echo '</table>'
        echo '</div>'

        echo '</div>' # end container

        echo '<div class="footer">'
        echo 'QYVORA Sentinel - Linux Security Auditing Framework'
        echo '</div>'
        echo '</body>'
        echo '</html>'
    } > "${output_dest}"

    if [[ -n "${output_file}" ]]; then
        log_info "HTML report written to ${output_file}"
    fi
}
