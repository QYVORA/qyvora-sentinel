#!/usr/bin/env bash
set -Eeuo pipefail
IFS=$'\n\t'

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="${SCRIPT_DIR}/../.."

# shellcheck source=test_framework.sh
source "${SCRIPT_DIR}/test_framework.sh"

# Disable color for deterministic testing
export NO_COLOR=1

# Source libs with errexit disabled (readonly variable conflicts between lib files)
set +e
trap - ERR
for _lib in "${PROJECT_ROOT}"/lib/*.sh; do
    # shellcheck disable=SC1090
    source "${_lib}" 2>/dev/null || true
done
set -eo pipefail

test_suite "colors.sh"

# --- Colorize function ---
test_case "colorize returns text when colors disabled" \
    'result=$(colorize "${SENTINEL_COLOR_RED}" "hello"); [[ "${result}" == "hello" ]]' \
    0

test_case "colorize with empty text returns empty" \
    'result=$(colorize "${SENTINEL_COLOR_RED}" ""); [[ -z "${result}" ]]' \
    0

test_case "colorize with empty color returns plain text" \
    'result=$(colorize "" "hello"); [[ "${result}" == "hello" ]]' \
    0

# --- Color helper functions ---
test_case "bold returns text" \
    'result=$(bold "test"); [[ "${result}" == "test" ]]' \
    0

test_case "red returns text" \
    'result=$(red "test"); [[ "${result}" == "test" ]]' \
    0

test_case "green returns text" \
    'result=$(green "test"); [[ "${result}" == "test" ]]' \
    0

test_case "yellow returns text" \
    'result=$(yellow "test"); [[ "${result}" == "test" ]]' \
    0

test_case "blue returns text" \
    'result=$(blue "test"); [[ "${result}" == "test" ]]' \
    0

test_case "cyan returns text" \
    'result=$(cyan "test"); [[ "${result}" == "test" ]]' \
    0

test_case "magenta returns text" \
    'result=$(magenta "test"); [[ "${result}" == "test" ]]' \
    0

test_case "dim returns text" \
    'result=$(dim "test"); [[ "${result}" == "test" ]]' \
    0

# --- severity_color ---
test_case "severity_color returns a value for critical" \
    'result=$(severity_color "critical"); [[ -n "${result}" ]]' \
    0

test_case "severity_color returns a value for high" \
    'result=$(severity_color "high"); [[ -n "${result}" ]]' \
    0

test_case "severity_color returns a value for medium" \
    'result=$(severity_color "medium"); [[ -n "${result}" ]]' \
    0

test_case "severity_color returns a value for low" \
    'result=$(severity_color "low"); [[ -n "${result}" ]]' \
    0

test_case "severity_color returns a value for info" \
    'result=$(severity_color "info"); [[ -n "${result}" ]]' \
    0

test_case "severity_color returns a value for unknown" \
    'result=$(severity_color "bogus"); [[ -n "${result}" ]]' \
    0

# --- SENTINEL_COLOR_ENABLED ---
test_case "SENTINEL_COLOR_ENABLED is 0 when NO_COLOR is set" \
    '[[ "${SENTINEL_COLOR_ENABLED}" -eq 0 ]]' \
    0

test_summary
