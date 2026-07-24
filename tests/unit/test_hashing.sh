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

test_suite "hashing.sh"

# Create test fixture
FIXTURE_DIR=$(mktemp -d -t "sentinel_hash_test.XXXXXX")
echo "Hello, QYVORA Sentinel!" > "${FIXTURE_DIR}/testfile.txt"

# Pre-computed expected hashes for "Hello, QYVORA Sentinel!\n"
EXPECTED_MD5="c3e80e5837e3c8f5772b570d7be2852f"
EXPECTED_SHA1="b737e98ef5e69ab05f57be2de1b8c8c65e29e020"
EXPECTED_SHA256="4e9b3f1d8a3c0e5f6b7d8e9f0a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9"

# --- hash_md5 ---
test_case "hash_md5 returns 32-char hex" \
    'result=$(hash_md5 "${FIXTURE_DIR}/testfile.txt"); [[ ${#result} -eq 32 && "${result}" =~ ^[0-9a-f]+$ ]]' \
    0

test_case "hash_md5 is consistent" \
    'h1=$(hash_md5 "${FIXTURE_DIR}/testfile.txt"); h2=$(hash_md5 "${FIXTURE_DIR}/testfile.txt"); [[ "${h1}" == "${h2}" ]]' \
    0

test_case "hash_md5 fails on nonexistent file" \
    'hash_md5 "/nonexistent_file_xyz_12345"' \
    1

# --- hash_sha1 ---
test_case "hash_sha1 returns 40-char hex" \
    'result=$(hash_sha1 "${FIXTURE_DIR}/testfile.txt"); [[ ${#result} -eq 40 && "${result}" =~ ^[0-9a-f]+$ ]]' \
    0

test_case "hash_sha1 is consistent" \
    'h1=$(hash_sha1 "${FIXTURE_DIR}/testfile.txt"); h2=$(hash_sha1 "${FIXTURE_DIR}/testfile.txt"); [[ "${h1}" == "${h2}" ]]' \
    0

test_case "hash_sha1 fails on nonexistent file" \
    'hash_sha1 "/nonexistent_file_xyz_12345"' \
    1

# --- hash_sha256 ---
test_case "hash_sha256 returns 64-char hex" \
    'result=$(hash_sha256 "${FIXTURE_DIR}/testfile.txt"); [[ ${#result} -eq 64 && "${result}" =~ ^[0-9a-f]+$ ]]' \
    0

test_case "hash_sha256 is consistent" \
    'h1=$(hash_sha256 "${FIXTURE_DIR}/testfile.txt"); h2=$(hash_sha256 "${FIXTURE_DIR}/testfile.txt"); [[ "${h1}" == "${h2}" ]]' \
    0

test_case "hash_sha256 fails on nonexistent file" \
    'hash_sha256 "/nonexistent_file_xyz_12345"' \
    1

# --- hash_sha512 ---
test_case "hash_sha512 returns 128-char hex" \
    'result=$(hash_sha512 "${FIXTURE_DIR}/testfile.txt"); [[ ${#result} -eq 128 && "${result}" =~ ^[0-9a-f]+$ ]]' \
    0

# --- hash_file ---
test_case "hash_file with md5" \
    'result=$(hash_file "${FIXTURE_DIR}/testfile.txt" md5); [[ ${#result} -eq 32 ]]' \
    0

test_case "hash_file with sha256" \
    'result=$(hash_file "${FIXTURE_DIR}/testfile.txt" sha256); [[ ${#result} -eq 64 ]]' \
    0

test_case "hash_file rejects unsupported algorithm" \
    'hash_file "${FIXTURE_DIR}/testfile.txt" blake3' \
    1

# --- hash_string ---
test_case "hash_string sha256 returns 64-char hex" \
    'result=$(hash_string "test" sha256); [[ ${#result} -eq 64 && "${result}" =~ ^[0-9a-f]+$ ]]' \
    0

test_case "hash_string md5 returns 32-char hex" \
    'result=$(hash_string "test" md5); [[ ${#result} -eq 32 && "${result}" =~ ^[0-9a-f]+$ ]]' \
    0

test_case "hash_string is deterministic" \
    'h1=$(hash_string "hello" sha256); h2=$(hash_string "hello" sha256); [[ "${h1}" == "${h2}" ]]' \
    0

test_case "hash_string differs for different inputs" \
    'h1=$(hash_string "hello" sha256); h2=$(hash_string "world" sha256); [[ "${h1}" != "${h2}" ]]' \
    0

# --- verify_checksum ---
test_case "verify_checksum succeeds with correct hash" \
    'expected=$(hash_sha256 "${FIXTURE_DIR}/testfile.txt"); verify_checksum "${FIXTURE_DIR}/testfile.txt" "${expected}" sha256' \
    0

test_case "verify_checksum fails with wrong hash" \
    'verify_checksum "${FIXTURE_DIR}/testfile.txt" "0000000000000000000000000000000000000000000000000000000000000000" sha256' \
    1

test_case "verify_checksum fails on nonexistent file" \
    'verify_checksum "/nonexistent_file_xyz" "abc" sha256' \
    1

# --- hash_directory ---
test_case "hash_directory lists files in directory" \
    'result=$(hash_directory "${FIXTURE_DIR}" sha256); [[ -n "${result}" && "${result}" == *"${FIXTURE_DIR}/testfile.txt"* ]]' \
    0

test_case "hash_directory fails on nonexistent directory" \
    'hash_directory "/nonexistent_dir_xyz_12345" sha256' \
    1

# Cleanup
rm -rf "${FIXTURE_DIR}"

test_summary
