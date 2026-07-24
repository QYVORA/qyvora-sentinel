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

test_suite "permissions.sh"

# Create test fixtures
FIXTURE_DIR=$(mktemp -d -t "sentinel_perms_test.XXXXXX")
chmod 755 "${FIXTURE_DIR}/normal_file" 2>/dev/null || true
chmod 777 "${FIXTURE_DIR}/world_writable" 2>/dev/null || true
chmod 4755 "${FIXTURE_DIR}/suid_file" 2>/dev/null || true
chmod 2755 "${FIXTURE_DIR}/sgid_file" 2>/dev/null || true
chmod 1755 "${FIXTURE_DIR}/sticky_dir" 2>/dev/null || true
touch "${FIXTURE_DIR}/normal_file"
touch "${FIXTURE_DIR}/world_writable"
chmod 777 "${FIXTURE_DIR}/world_writable"
touch "${FIXTURE_DIR}/suid_file"
chmod 4755 "${FIXTURE_DIR}/suid_file"
touch "${FIXTURE_DIR}/sgid_file"
chmod 2755 "${FIXTURE_DIR}/sgid_file"
mkdir -p "${FIXTURE_DIR}/sticky_dir"
chmod 1755 "${FIXTURE_DIR}/sticky_dir"

# --- is_world_writable ---
test_case "is_world_writable detects world-writable file" \
    'is_world_writable "${FIXTURE_DIR}/world_writable"' \
    0

test_case "is_world_writable rejects normal file" \
    'is_world_writable "${FIXTURE_DIR}/normal_file"' \
    1

test_case "is_world_writable rejects nonexistent file" \
    'is_world_writable "/nonexistent_xyz_12345"' \
    1

# --- is_suid ---
test_case "is_suid detects SUID file" \
    'is_suid "${FIXTURE_DIR}/suid_file"' \
    0

test_case "is_suid rejects normal file" \
    'is_suid "${FIXTURE_DIR}/normal_file"' \
    1

test_case "is_suid rejects nonexistent file" \
    'is_suid "/nonexistent_xyz_12345"' \
    1

# --- is_sgid ---
test_case "is_sgid detects SGID file" \
    'is_sgid "${FIXTURE_DIR}/sgid_file"' \
    0

test_case "is_sgid rejects normal file" \
    'is_sgid "${FIXTURE_DIR}/normal_file"' \
    1

# --- is_sticky ---
test_case "is_sticky detects sticky directory" \
    'is_sticky "${FIXTURE_DIR}/sticky_dir"' \
    0

test_case "is_sticky rejects normal file" \
    'is_sticky "${FIXTURE_DIR}/normal_file"' \
    1

# --- is_symlink ---
test_case "is_symlink detects symlink" \
    'ln -sf "${FIXTURE_DIR}/normal_file" "${FIXTURE_DIR}/link" && is_symlink "${FIXTURE_DIR}/link" && rm -f "${FIXTURE_DIR}/link"' \
    0

test_case "is_symlink rejects regular file" \
    'is_symlink "${FIXTURE_DIR}/normal_file"' \
    1

# --- is_broken_symlink ---
test_case "is_broken_symlink detects broken link" \
    'ln -sf /nonexistent_target_xyz "${FIXTURE_DIR}/broken" && is_broken_symlink "${FIXTURE_DIR}/broken" && rm -f "${FIXTURE_DIR}/broken"' \
    0

test_case "is_broken_symlink rejects valid link" \
    'ln -sf "${FIXTURE_DIR}/normal_file" "${FIXTURE_DIR}/good_link"; is_broken_symlink "${FIXTURE_DIR}/good_link"; rc=$?; rm -f "${FIXTURE_DIR}/good_link"; exit $rc' \
    1

# --- permission_string ---
test_case "permission_string for 755" \
    'result=$(permission_string 755); [[ "${result}" == "rwxr-xr-x" ]]' \
    0

test_case "permission_string for 644" \
    'result=$(permission_string 644); [[ "${result}" == "rw-r--r--" ]]' \
    0

test_case "permission_string for 777" \
    'result=$(permission_string 777); [[ "${result}" == "rwxrwxrwx" ]]' \
    0

test_case "permission_string for 000" \
    'result=$(permission_string 000); [[ "${result}" == "---------" ]]' \
    0

test_case "permission_string for 4755 (SUID)" \
    'result=$(permission_string 4755); [[ "${result}" == "rwsr-xr-x" ]]' \
    0

test_case "permission_string for 2755 (SGID)" \
    'result=$(permission_string 2755); [[ "${result}" == "rwxr-sr-x" ]]' \
    0

# --- check_file_permissions ---
test_case "check_file_permissions outputs structured data" \
    'result=$(check_file_permissions "${FIXTURE_DIR}/normal_file"); [[ "${result}" == *"path="* && "${result}" == *"mode="* ]]' \
    0

# --- check_sticky_bit ---
test_case "check_sticky_bit detects sticky dir" \
    'check_sticky_bit "${FIXTURE_DIR}/sticky_dir"' \
    0

test_case "check_sticky_bit rejects normal file" \
    'check_sticky_bit "${FIXTURE_DIR}/normal_file"' \
    1

# Cleanup
rm -rf "${FIXTURE_DIR}"

test_summary
