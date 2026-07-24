#!/usr/bin/env bash
set -Eeuo pipefail
IFS=$'\n\t'

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="${SCRIPT_DIR}/../.."

# shellcheck source=test_framework.sh
source "${SCRIPT_DIR}/test_framework.sh"

export NO_COLOR=1

# Source libs with errexit disabled (readonly variable conflicts between lib files)
set +e
trap - ERR
for _lib in "${PROJECT_ROOT}"/lib/*.sh; do
    # shellcheck disable=SC1090
    source "${_lib}" 2>/dev/null || true
done
set -eo pipefail

test_suite "reporting.sh"

# Reset state
clear_findings

# --- add_finding / get_findings_count ---
test_case "get_findings_count starts at 0" \
    'result=$(get_findings_count); [[ "${result}" == "0" ]]' \
    0

test_case "add_finding increments count" \
    'clear_findings; add_finding "test" "info" "Title1" "Desc1"; result=$(get_findings_count); [[ "${result}" == "1" ]]' \
    0

test_case "add_finding multiple increments count" \
    'clear_findings; add_finding "test" "info" "T1" "D1"; add_finding "test" "high" "T2" "D2"; add_finding "test" "critical" "T3" "D3"; result=$(get_findings_count); [[ "${result}" == "3" ]]' \
    0

# --- clear_findings ---
test_case "clear_findings resets count to 0" \
    'clear_findings; add_finding "test" "info" "T" "D"; clear_findings; result=$(get_findings_count); [[ "${result}" == "0" ]]' \
    0

# --- calculate_risk_score ---
test_case "calculate_risk_score is 0 with no findings" \
    'clear_findings; result=$(calculate_risk_score); [[ "${result}" == "0" ]]' \
    0

test_case "calculate_risk_score is 100 with all critical" \
    'clear_findings; add_finding "test" "critical" "T1" "D1"; add_finding "test" "critical" "T2" "D2"; result=$(calculate_risk_score); [[ "${result}" == "100" ]]' \
    0

test_case "calculate_risk_score is 0 with all info" \
    'clear_findings; add_finding "test" "info" "T1" "D1"; add_finding "test" "info" "T2" "D2"; result=$(calculate_risk_score); [[ "${result}" == "0" ]]' \
    0

# --- get_findings_by_severity ---
test_case "get_findings_by_severity finds critical" \
    'clear_findings; add_finding "m1" "critical" "T1" "D1"; add_finding "m2" "info" "T2" "D2"; ids=$(get_findings_by_severity "critical"); [[ "${ids}" == "1" ]]' \
    0

test_case "get_findings_by_severity returns empty for missing severity" \
    'clear_findings; add_finding "m1" "info" "T1" "D1"; ids=$(get_findings_by_severity "critical"); [[ -z "${ids}" ]]' \
    0

# --- get_findings_by_module ---
test_case "get_findings_by_module finds matching module" \
    'clear_findings; add_finding "ssh" "high" "T1" "D1"; add_finding "fs" "low" "T2" "D2"; ids=$(get_findings_by_module "ssh"); [[ "${ids}" == "1" ]]' \
    0

test_case "get_findings_by_module returns empty for missing module" \
    'clear_findings; add_finding "ssh" "high" "T1" "D1"; ids=$(get_findings_by_module "network"); [[ -z "${ids}" ]]' \
    0

# --- reporting_init ---
test_case "reporting_init creates report dir" \
    'tmpdir=$(mktemp -d); SENTINEL_REPORT_DIR="${tmpdir}/reports"; reporting_init; [[ -d "${SENTINEL_REPORT_DIR}" ]]; rm -rf "${tmpdir}"' \
    0

# --- generate_report_json ---
test_case "generate_report_json produces valid-ish output" \
    'clear_findings; add_finding "test" "high" "Test Finding" "Test description" "evidence" "fix" "ref"; tmpfile=$(mktemp); generate_report_json "${tmpfile}"; result=$(grep -c "findings" "${tmpfile}"); rm -f "${tmpfile}"; [[ "${result}" -ge 1 ]]' \
    0

test_case "generate_report_json with empty findings" \
    'clear_findings; tmpfile=$(mktemp); generate_report_json "${tmpfile}"; result=$(grep -c "total_findings" "${tmpfile}"); rm -f "${tmpfile}"; [[ "${result}" -ge 1 ]]' \
    0

# --- generate_report_markdown ---
test_case "generate_report_markdown produces output" \
    'clear_findings; add_finding "test" "medium" "MD Test" "Description"; tmpfile=$(mktemp); generate_report_markdown "${tmpfile}"; result=$(grep -c "QYVORA Sentinel" "${tmpfile}"); rm -f "${tmpfile}"; [[ "${result}" -ge 1 ]]' \
    0

# --- generate_report_html ---
test_case "generate_report_html produces HTML" \
    'clear_findings; add_finding "test" "low" "HTML Test" "Description"; tmpfile=$(mktemp); generate_report_html "${tmpfile}"; result=$(grep -c "DOCTYPE html" "${tmpfile}"); rm -f "${tmpfile}"; [[ "${result}" -ge 1 ]]' \
    0

# --- generate_report_text ---
test_case "generate_report_text produces output" \
    'clear_findings; add_finding "test" "info" "Text Test" "Description"; tmpfile=$(mktemp); generate_report_text "${tmpfile}"; result=$(grep -c "SECURITY AUDIT REPORT" "${tmpfile}"); rm -f "${tmpfile}"; [[ "${result}" -ge 1 ]]' \
    0

# Cleanup
clear_findings

test_summary
