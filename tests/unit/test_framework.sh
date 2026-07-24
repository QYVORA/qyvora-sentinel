#!/usr/bin/env bash
set -Eeuo pipefail
IFS=$'\n\t'

# Simple test framework for QYVORA Sentinel
# Usage: source this file, then use: test_case "name" "command" "expected_exit_code"

TESTS_RUN=0
TESTS_PASSED=0
TESTS_FAILED=0
TEST_SUITE_NAME=""

test_suite() {
    TEST_SUITE_NAME="$1"
    echo "=== Test Suite: ${TEST_SUITE_NAME} ==="
}

test_case() {
    local name="$1"
    local command="$2"
    local expected_exit="${3:-0}"

    TESTS_RUN=$((TESTS_RUN + 1))

    local output
    local actual_exit=0
    output=$(eval "${command}" 2>&1) || actual_exit=$?

    if [[ "${actual_exit}" -eq "${expected_exit}" ]]; then
        TESTS_PASSED=$((TESTS_PASSED + 1))
        echo "  ✔ PASS: ${name}"
    else
        TESTS_FAILED=$((TESTS_FAILED + 1))
        echo "  ✖ FAIL: ${name} (expected exit ${expected_exit}, got ${actual_exit})"
        echo "    Output: ${output}"
    fi
}

test_summary() {
    echo ""
    echo "=== Results ==="
    echo "Total: ${TESTS_RUN} | Passed: ${TESTS_PASSED} | Failed: ${TESTS_FAILED}"
    if [[ "${TESTS_FAILED}" -gt 0 ]]; then
        echo "TESTS FAILED"
        return 1
    fi
    echo "ALL TESTS PASSED"
    return 0
}
