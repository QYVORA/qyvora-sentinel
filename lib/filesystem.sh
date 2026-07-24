#!/usr/bin/env bash
# filesystem.sh - Filesystem operations and analysis for QYVORA Sentinel
# Provides functions for scanning filesystem for security-relevant artifacts
# such as SUID/SGID files, world-writable paths, hidden executables, and more.

# Source guard - prevent re-sourcing
if [[ "${_SENTINEL_LIB_LOADED:-}" == *"$(basename "${BASH_SOURCE[0]}")"* ]]; then
    return 0 2>/dev/null || true
fi
_SENTINEL_LIB_LOADED="${_SENTINEL_LIB_LOADED:-} $(basename "${BASH_SOURCE[0]}")"

set -Eeuo pipefail
IFS=$'\n\t'

# Default directories to scan
readonly SENTINEL_SCAN_DIRS="/etc /usr /var /home /tmp /opt"

# find_suid_files - Find all files with the SUID bit set in given directories
find_suid_files() {
    local dirs="${1:-${SENTINEL_SCAN_DIRS}}"
    local dir
    for dir in ${dirs}; do
        if [[ -d "${dir}" ]]; then
            find "${dir}" -xdev -type f -perm -4000 2>/dev/null || true
        fi
    done
}

# find_sgid_files - Find all files with the SGID bit set in given directories
find_sgid_files() {
    local dirs="${1:-${SENTINEL_SCAN_DIRS}}"
    local dir
    for dir in ${dirs}; do
        if [[ -d "${dir}" ]]; then
            find "${dir}" -xdev -type f -perm -2000 2>/dev/null || true
        fi
    done
}

# find_world_writable - Find world-writable files and directories
find_world_writable() {
    local dirs="${1:-${SENTINEL_SCAN_DIRS}}"
    local dir
    for dir in ${dirs}; do
        if [[ -d "${dir}" ]]; then
            find "${dir}" -xdev \( -type f -o -type d \) -perm -0002 2>/dev/null || true
        fi
    done
}

# find_recently_modified - Find files modified within the last N days
find_recently_modified() {
    local dirs="${1:-${SENTINEL_SCAN_DIRS}}"
    local days="${2:-7}"
    local dir
    for dir in ${dirs}; do
        if [[ -d "${dir}" ]]; then
            find "${dir}" -xdev -type f -mtime "-${days}" 2>/dev/null || true
        fi
    done
}

# find_hidden_executables - Find hidden files that have execute permission
find_hidden_executables() {
    local dirs="${1:-${SENTINEL_SCAN_DIRS}}"
    local dir
    for dir in ${dirs}; do
        if [[ -d "${dir}" ]]; then
            find "${dir}" -xdev -type f -name ".*" -perm -111 2>/dev/null || true
        fi
    done
}

# find_broken_symlinks - Find symbolic links that point to non-existent targets
find_broken_symlinks() {
    local dirs="${1:-${SENTINEL_SCAN_DIRS}}"
    local dir
    for dir in ${dirs}; do
        if [[ -d "${dir}" ]]; then
            find "${dir}" -xdev -type l ! -exec test -e {} \; -print 2>/dev/null || true
        fi
    done
}

# find_large_files - Find files larger than a given size in MB
find_large_files() {
    local dirs="${1:-${SENTINEL_SCAN_DIRS}}"
    local size_mb="${2:-100}"
    local dir
    for dir in ${dirs}; do
        if [[ -d "${dir}" ]]; then
            find "${dir}" -xdev -type f -size "+${size_mb}M" 2>/dev/null || true
        fi
    done
}

# find_empty_files - Find zero-byte files
find_empty_files() {
    local dirs="${1:-${SENTINEL_SCAN_DIRS}}"
    local dir
    for dir in ${dirs}; do
        if [[ -d "${dir}" ]]; then
            find "${dir}" -xdev -type f -empty 2>/dev/null || true
        fi
    done
}

# find_writable_by_others - Find files in a directory writable by others (non-owner, non-group)
find_writable_by_others() {
    local dir="${1:-.}"
    if [[ -d "${dir}" ]]; then
        find "${dir}" -xdev \( -type f -o -type d \) -perm -0002 2>/dev/null || true
    fi
}

# get_file_type - Get the MIME type of a file
get_file_type() {
    local path="${1:-}"
    if [[ -z "${path}" ]]; then
        echo ""
        return 1
    fi
    if [[ ! -e "${path}" ]]; then
        echo ""
        return 1
    fi
    if command -v file &>/dev/null; then
        file --mime-type -b "${path}" 2>/dev/null || echo "unknown"
    else
        echo "unknown"
    fi
}

# safe_find - A find wrapper that respects SENTINEL_IGNORE_CONF and handles errors
# Usage: safe_find /path/to/search -name "*.conf" -type f
safe_find() {
    local ignore_conf="${SENTINEL_IGNORE_CONF:-}"
    local ignore_patterns=()
    local find_cmd=("find")
    local sep_found=0
    local args=()

    if [[ -n "${ignore_conf}" && -f "${ignore_conf}" ]]; then
        while IFS= read -r line; do
            line="${line%%#*}"
            line="$(echo "${line}" | xargs)"
            if [[ -n "${line}" ]]; then
                ignore_patterns+=("${line}")
            fi
        done < "${ignore_conf}"
    fi

    while [[ $# -gt 0 ]]; do
        if [[ "${sep_found}" -eq 0 && "$1" == "--" ]]; then
            sep_found=1
            shift
            break
        fi
        args+=("$1")
        shift
    done

    if [[ "${sep_found}" -eq 0 ]]; then
        args=("$@")
    fi

    find_cmd+=("${args[@]}")

    local result
    if result=$("${find_cmd[@]}" 2>/dev/null); then
        if [[ ${#ignore_patterns[@]} -gt 0 ]]; then
            local line
            while IFS= read -r line; do
                local skip=0
                local pattern
                for pattern in "${ignore_patterns[@]}"; do
                    # shellcheck disable=SC2053
                    if [[ "${line}" == ${pattern} ]]; then
                        skip=1
                        break
                    fi
                done
                if [[ "${skip}" -eq 0 && -n "${line}" ]]; then
                    echo "${line}"
                fi
            done <<< "${result}"
        else
            echo "${result}"
        fi
    fi
}
