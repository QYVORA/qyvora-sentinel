#!/usr/bin/env bash
set -Eeuo pipefail
IFS=$'\n\t'

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="${SCRIPT_DIR}/../.."

# shellcheck source=../unit/test_framework.sh
source "${SCRIPT_DIR}/../unit/test_framework.sh"

export NO_COLOR=1

test_suite "Module Loading Integration"

# Source all libs first (like sentinel does)
LIB_DIR="${PROJECT_ROOT}/lib"
set +e
trap - ERR
for lib_file in "${LIB_DIR}"/*.sh; do
    if [[ -f "${lib_file}" ]]; then
        # shellcheck disable=SC1090
        source "${lib_file}" 2>/dev/null || true
    fi
done
set -eo pipefail

# Discover modules
MODULES_DIR="${PROJECT_ROOT}/modules"
MODULE_COUNT=0

for module_dir in "${MODULES_DIR}"/*/; do
    [[ ! -d "${module_dir}" ]] && continue
    module_main="${module_dir}main.sh"
    [[ ! -f "${module_main}" ]] && continue

    MODULE_COUNT=$((MODULE_COUNT + 1))
    mod_name="$(basename "${module_dir}")"

    # --- Each module can be sourced ---
    test_case "Module '${mod_name}' can be sourced without error" \
        'unset MODULE_NAME 2>/dev/null || true; unset MODULE_DESCRIPTION 2>/dev/null || true; source "'"${module_main}"'" 2>/dev/null' \
        0

    # --- Each module exports MODULE_NAME ---
    test_case "Module '${mod_name}' exports MODULE_NAME" \
        'unset MODULE_NAME 2>/dev/null || true; source "'"${module_main}"'" 2>/dev/null; [[ -n "${MODULE_NAME:-}" ]]' \
        0

    # --- Each module exports MODULE_DESCRIPTION ---
    test_case "Module '${mod_name}' exports MODULE_DESCRIPTION" \
        'unset MODULE_NAME 2>/dev/null || true; unset MODULE_DESCRIPTION 2>/dev/null || true; source "'"${module_main}"'" 2>/dev/null; [[ -n "${MODULE_DESCRIPTION:-}" ]]' \
        0

    # --- Each module defines run() ---
    test_case "Module '${mod_name}' defines run() function" \
        'unset MODULE_NAME 2>/dev/null || true; unset MODULE_DESCRIPTION 2>/dev/null || true; unset -f run 2>/dev/null || true; source "'"${module_main}"'" 2>/dev/null; declare -f run &>/dev/null' \
        0
done

if [[ "${MODULE_COUNT}" -eq 0 ]]; then
    echo "  (No modules found to test)"
fi

test_summary
