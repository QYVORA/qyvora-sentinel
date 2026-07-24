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

test_suite "validation.sh"

# --- validate_path ---
test_case "validate_path accepts /" \
    'validate_path /' \
    0

test_case "validate_path rejects empty" \
    'validate_path ""' \
    1

test_case "validate_path rejects nonexistent" \
    'validate_path "/nonexistent_path_xyz_12345"' \
    1

# --- validate_directory ---
test_case "validate_directory accepts /tmp" \
    'validate_directory /tmp' \
    0

test_case "validate_directory rejects empty" \
    'validate_directory ""' \
    1

test_case "validate_directory rejects nonexistent" \
    'validate_directory "/nonexistent_dir_xyz_12345"' \
    1

# --- validate_file ---
test_case "validate_file accepts /etc/hostname" \
    'validate_file /etc/hostname || validate_file /etc/hosts' \
    0

test_case "validate_file rejects empty" \
    'validate_file ""' \
    1

test_case "validate_file rejects nonexistent" \
    'validate_file "/nonexistent_file_xyz_12345"' \
    1

# --- validate_severity ---
test_case "validate_severity accepts INFO" \
    'validate_severity INFO' \
    0

test_case "validate_severity accepts LOW" \
    'validate_severity LOW' \
    0

test_case "validate_severity accepts MEDIUM" \
    'validate_severity MEDIUM' \
    0

test_case "validate_severity accepts HIGH" \
    'validate_severity HIGH' \
    0

test_case "validate_severity accepts CRITICAL" \
    'validate_severity CRITICAL' \
    0

test_case "validate_severity accepts lowercase" \
    'validate_severity critical' \
    0

test_case "validate_severity rejects empty" \
    'validate_severity ""' \
    1

test_case "validate_severity rejects invalid" \
    'validate_severity BOGUS' \
    1

# --- validate_port ---
test_case "validate_port accepts 80" \
    'validate_port 80' \
    0

test_case "validate_port accepts 1" \
    'validate_port 1' \
    0

test_case "validate_port accepts 65535" \
    'validate_port 65535' \
    0

test_case "validate_port rejects 0" \
    'validate_port 0' \
    1

test_case "validate_port rejects 65536" \
    'validate_port 65536' \
    1

test_case "validate_port rejects empty" \
    'validate_port ""' \
    1

test_case "validate_port rejects non-numeric" \
    'validate_port "abc"' \
    1

test_case "validate_port rejects negative" \
    'validate_port "-1"' \
    1

# --- validate_url ---
test_case "validate_url accepts https URL" \
    'validate_url "https://example.com"' \
    0

test_case "validate_url accepts http URL" \
    'validate_url "http://example.com:8080/path"' \
    0

test_case "validate_url rejects ftp" \
    'validate_url "ftp://example.com"' \
    1

test_case "validate_url rejects empty" \
    'validate_url ""' \
    1

test_case "validate_url rejects bare string" \
    'validate_url "not-a-url"' \
    1

# --- validate_output_format ---
test_case "validate_output_format accepts text" \
    'validate_output_format text' \
    0

test_case "validate_output_format accepts json" \
    'validate_output_format json' \
    0

test_case "validate_output_format accepts markdown" \
    'validate_output_format markdown' \
    0

test_case "validate_output_format accepts html" \
    'validate_output_format html' \
    0

test_case "validate_output_format rejects empty" \
    'validate_output_format ""' \
    1

test_case "validate_output_format rejects xml" \
    'validate_output_format xml' \
    1

# --- validate_config_value ---
test_case "validate_config_value boolean true" \
    'validate_config_value true boolean' \
    0

test_case "validate_config_value boolean false" \
    'validate_config_value false boolean' \
    0

test_case "validate_config_value boolean yes" \
    'validate_config_value yes boolean' \
    0

test_case "validate_config_value boolean rejects invalid" \
    'validate_config_value maybe boolean' \
    1

test_case "validate_config_value integer 42" \
    'validate_config_value 42 integer' \
    0

test_case "validate_config_value integer -5" \
    'validate_config_value -5 integer' \
    0

test_case "validate_config_value integer rejects string" \
    'validate_config_value abc integer' \
    1

test_case "validate_config_value string non-empty" \
    'validate_config_value hello string' \
    0

test_case "validate_config_value string rejects empty" \
    'validate_config_value "" string' \
    1

# --- sanitize_input ---
test_case "sanitize_input strips ANSI" \
    "result=\$(sanitize_input \$'hello\e[31mworld'); [[ \"\${result}\" == helloworld ]]" \
    0

test_case "sanitize_input strips control chars" \
    "result=\$(sanitize_input \$'hello\x01world'); [[ \"\${result}\" == helloworld ]]" \
    0

test_case "sanitize_input handles empty" \
    'result=$(sanitize_input ""); [[ -z "${result}" ]]' \
    0

test_case "sanitize_input preserves normal text" \
    'result=$(sanitize_input "Hello World 123"); [[ "${result}" == "Hello World 123" ]]' \
    0

test_summary
