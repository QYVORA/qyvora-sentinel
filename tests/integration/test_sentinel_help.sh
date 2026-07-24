#!/usr/bin/env bash
set -Eeuo pipefail
IFS=$'\n\t'

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="${SCRIPT_DIR}/../.."

# shellcheck source=../unit/test_framework.sh
source "${SCRIPT_DIR}/../unit/test_framework.sh"

test_suite "Sentinel CLI Integration"

# shellcheck disable=SC2034
SENTINEL="${PROJECT_ROOT}/sentinel"

# --- sentinel --help ---
test_case "sentinel --help exits 0" \
    '"${SENTINEL}" --help' \
    0

test_case "sentinel --help outputs usage info" \
    'output=$("${SENTINEL}" --help 2>&1); [[ "${output}" == *"Usage"* || "${output}" == *"Commands"* ]]' \
    0

# --- sentinel help ---
test_case "sentinel help exits 0" \
    '"${SENTINEL}" help' \
    0

test_case "sentinel help mentions scan command" \
    'output=$("${SENTINEL}" help 2>&1); [[ "${output}" == *"scan"* ]]' \
    0

test_case "sentinel help mentions modules command" \
    'output=$("${SENTINEL}" help 2>&1); [[ "${output}" == *"modules"* ]]' \
    0

# --- sentinel version ---
test_case "sentinel version exits 0" \
    '"${SENTINEL}" version' \
    0

test_case "sentinel version contains version number" \
    'output=$("${SENTINEL}" version 2>&1); [[ "${output}" == *"1.0.0"* ]]' \
    0

test_case "sentinel version contains product name" \
    'output=$("${SENTINEL}" version 2>&1); [[ "${output}" == *"QYVORA Sentinel"* ]]' \
    0

# --- sentinel modules ---
test_case "sentinel modules exits 0" \
    '"${SENTINEL}" modules' \
    0

test_case "sentinel modules lists available modules" \
    'output=$("${SENTINEL}" modules 2>&1); [[ "${output}" == *"filesystem"* || "${output}" == *"ssh"* || "${output}" == *"No modules"* ]]' \
    0

# --- sentinel --version ---
test_case "sentinel --version exits 0" \
    '"${SENTINEL}" --version' \
    0

# --- sentinel with no args ---
test_case "sentinel with no args shows help" \
    'output=$("${SENTINEL}" 2>&1); [[ "${output}" == *"Usage"* || "${output}" == *"Commands"* ]]' \
    0

# --- sentinel with invalid command ---
test_case "sentinel with invalid command exits non-zero" \
    '"${SENTINEL}" bogus_command_xyz' \
    1

test_case "sentinel with invalid command shows error" \
    'output=$("${SENTINEL}" bogus_command_xyz 2>&1 || true); [[ "${output}" == *"Unknown command"* || "${output}" == *"ERROR"* ]]' \
    0

# --- sentinel doctor ---
test_case "sentinel doctor exits 0" \
    '"${SENTINEL}" doctor' \
    0

test_case "sentinel doctor checks for required commands" \
    'output=$("${SENTINEL}" doctor 2>&1); [[ "${output}" == *"bash"* || "${output}" == *"Required"* ]]' \
    0

test_summary
