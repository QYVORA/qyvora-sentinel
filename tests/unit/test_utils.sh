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

test_suite "utils.sh"

# --- command_exists ---
test_case "command_exists finds bash" \
    'command_exists bash' \
    0

test_case "command_exists rejects nonexistent command" \
    'command_exists __nonexistent_command_xyz__12345' \
    1

# --- get_os ---
test_case "get_os returns non-empty string" \
    'result=$(get_os); [[ -n "${result}" ]]' \
    0

# --- get_os_family ---
test_case "get_os_family returns non-empty string" \
    'result=$(get_os_family); [[ -n "${result}" ]]' \
    0

# --- get_kernel_version ---
test_case "get_kernel_version returns non-empty string" \
    'result=$(get_kernel_version); [[ -n "${result}" ]]' \
    0

# --- get_arch ---
test_case "get_arch returns non-empty string" \
    'result=$(get_arch); [[ -n "${result}" ]]' \
    0

# --- get_hostname ---
test_case "get_hostname returns non-empty string" \
    'result=$(get_hostname); [[ -n "${result}" ]]' \
    0

# --- get_uptime ---
test_case "get_uptime returns non-empty string" \
    'result=$(get_uptime); [[ -n "${result}" ]]' \
    0

# --- get_pid_count ---
test_case "get_pid_count returns a number > 0" \
    'result=$(get_pid_count); [[ "${result}" -gt 0 ]]' \
    0

# --- generate_uuid ---
test_case "generate_uuid returns a non-empty UUID" \
    'result=$(generate_uuid); [[ -n "${result}" ]]' \
    0

test_case "generate_uuid format contains dashes" \
    'result=$(generate_uuid); [[ "${result}" == *-* ]]' \
    0

# --- sanitize_filename ---
test_case "sanitize_filename strips slashes" \
    'result=$(sanitize_filename "foo/bar"); [[ "${result}" == "foo_bar" ]]' \
    0

test_case "sanitize_filename strips dangerous characters" \
    "result=\$(sanitize_filename 'file;rm -rf /'); [[ \"\${result}\" == file_rm_-rf ]]" \
    0

test_case "sanitize_filename handles empty input" \
    'result=$(sanitize_filename ""); [[ "${result}" == "unnamed" ]]' \
    0

test_case "sanitize_filename preserves dots and dashes" \
    'result=$(sanitize_filename "my-file.v2.tar.gz"); [[ "${result}" == "my-file.v2.tar.gz" ]]' \
    0

# --- human_readable_size ---
test_case "human_readable_size for bytes" \
    'result=$(human_readable_size 500); [[ "${result}" == "500B" ]]' \
    0

test_case "human_readable_size for KB" \
    'result=$(human_readable_size 2048); [[ "${result}" == "2KB" ]]' \
    0

test_case "human_readable_size for MB" \
    'result=$(human_readable_size 2097152); [[ "${result}" == "2MB" ]]' \
    0

test_case "human_readable_size for GB" \
    'result=$(human_readable_size 2147483648); [[ "${result}" == "2GB" ]]' \
    0

# --- temp_dir_create ---
test_case "temp_dir_create creates a directory" \
    'dir=$(temp_dir_create "test"); [[ -d "${dir}" ]]; rm -rf "${dir}"' \
    0

# --- measure_time ---
test_case "measure_time returns a timing string" \
    'result=$(measure_time sleep 0); [[ "${result}" == *s ]]' \
    0

# --- file_age_seconds ---
test_case "file_age_seconds returns -1 for nonexistent file" \
    'result=$(file_age_seconds "/nonexistent_file_xyz"); [[ "${result}" == "-1" ]]' \
    0

test_case "file_age_seconds returns number for existing file" \
    'tmpfile=$(mktemp); result=$(file_age_seconds "${tmpfile}"); [[ "${result}" =~ ^[0-9]+$ ]]; rm -f "${tmpfile}"' \
    0

test_summary
