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

test_suite "config.sh"

# Create a test config file
FIXTURE_DIR=$(mktemp -d -t "sentinel_config_test.XXXXXX")
TEST_CONF="${FIXTURE_DIR}/test.conf"

cat > "${TEST_CONF}" <<'EOF'
# Test configuration

[general]
verbose = true
log_level = debug
scan_timeout = 600

[paths]
scan_root = /home
excluded_paths = /proc,/sys

[output]
format = json
color = off
EOF

# Reset config state
SENTINEL_CONFIG=()

# --- config_load ---
test_case "config_load parses section and keys" \
    'SENTINEL_CONFIG=(); config_load "${TEST_CONF}"; result=$(config_get "general.verbose"); [[ "${result}" == "true" ]]' \
    0

test_case "config_load fails on nonexistent file" \
    'config_load "/nonexistent_config_xyz_12345.conf"' \
    1

# --- config_get ---
test_case "config_get returns correct value" \
    'SENTINEL_CONFIG=(); config_load "${TEST_CONF}"; result=$(config_get "general.log_level"); [[ "${result}" == "debug" ]]' \
    0

test_case "config_get returns default for missing key" \
    'SENTINEL_CONFIG=(); config_load "${TEST_CONF}"; result=$(config_get "general.missing_key" "fallback"); [[ "${result}" == "fallback" ]]' \
    0

test_case "config_get returns empty for missing key without default" \
    'SENTINEL_CONFIG=(); config_load "${TEST_CONF}"; result=$(config_get "general.missing_key"); [[ -z "${result}" ]]' \
    0

# --- config_has ---
test_case "config_has returns 0 for existing key" \
    'SENTINEL_CONFIG=(); config_load "${TEST_CONF}"; config_has "general.verbose"' \
    0

test_case "config_has returns 1 for missing key" \
    'SENTINEL_CONFIG=(); config_load "${TEST_CONF}"; config_has "general.nonexistent"' \
    1

# --- config_set ---
test_case "config_set updates value" \
    'SENTINEL_CONFIG=(); config_load "${TEST_CONF}"; config_set "general.verbose" "false" "${TEST_CONF}"; result=$(config_get "general.verbose"); [[ "${result}" == "false" ]]' \
    0

# --- config_get_boolean ---
test_case "config_get_boolean parses true" \
    'SENTINEL_CONFIG=(); SENTINEL_CONFIG["test.key"]="true"; result=$(config_get_boolean "test.key"); [[ "${result}" == "true" ]]' \
    0

test_case "config_get_boolean parses yes" \
    'SENTINEL_CONFIG=(); SENTINEL_CONFIG["test.key"]="yes"; result=$(config_get_boolean "test.key"); [[ "${result}" == "true" ]]' \
    0

test_case "config_get_boolean parses false" \
    'SENTINEL_CONFIG=(); SENTINEL_CONFIG["test.key"]="false"; result=$(config_get_boolean "test.key"); [[ "${result}" == "false" ]]' \
    0

test_case "config_get_boolean parses no" \
    'SENTINEL_CONFIG=(); SENTINEL_CONFIG["test.key"]="no"; result=$(config_get_boolean "test.key"); [[ "${result}" == "false" ]]' \
    0

test_case "config_get_boolean returns default for invalid" \
    'SENTINEL_CONFIG=(); SENTINEL_CONFIG["test.key"]="maybe"; result=$(config_get_boolean "test.key" "false"); [[ "${result}" == "false" ]]' \
    0

# --- config_get_integer ---
test_case "config_get_integer returns number" \
    'SENTINEL_CONFIG=(); SENTINEL_CONFIG["test.port"]="8080"; result=$(config_get_integer "test.port"); [[ "${result}" == "8080" ]]' \
    0

test_case "config_get_integer returns default for non-numeric" \
    'SENTINEL_CONFIG=(); SENTINEL_CONFIG["test.key"]="abc"; result=$(config_get_integer "test.key" "42"); [[ "${result}" == "42" ]]' \
    0

test_case "config_get_integer handles negative" \
    'SENTINEL_CONFIG=(); SENTINEL_CONFIG["test.key"]="-5"; result=$(config_get_integer "test.key"); [[ "${result}" == "-5" ]]' \
    0

# --- config_get_section ---
test_case "config_get_section returns keys for section" \
    'SENTINEL_CONFIG=(); config_load "${TEST_CONF}"; result=$(config_get_section "general"); [[ "${result}" == *"verbose=true"* && "${result}" == *"scan_timeout=600"* ]]' \
    0

# Cleanup
rm -rf "${FIXTURE_DIR}"

test_summary
