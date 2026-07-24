#!/usr/bin/env bash
# utils.sh - General utility functions for QYVORA Sentinel.

# Source guard - prevent re-sourcing
if [[ "${_SENTINEL_LIB_LOADED:-}" == *"$(basename "${BASH_SOURCE[0]}")"* ]]; then
    return 0 2>/dev/null || true
fi
_SENTINEL_LIB_LOADED="${_SENTINEL_LIB_LOADED:-} $(basename "${BASH_SOURCE[0]}")"

set -Eeuo pipefail
IFS=$'\n\t'

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=logger.sh
source "${SCRIPT_DIR}/logger.sh"

# Managed temp directory stack
declare -ga SENTINEL_TEMP_DIRS=()

command_exists() {
    local -r cmd="${1}"

    if command -v "${cmd}" >/dev/null 2>&1; then
        return 0
    fi
    return 1
}

require_command() {
    local -r cmd="${1}"

    if ! command_exists "${cmd}"; then
        log_error "Required command not found: ${cmd}"
        return 1
    fi
    return 0
}

is_root() {
    if [[ "${EUID}" -eq 0 ]]; then
        return 0
    fi
    return 1
}

require_root() {
    if ! is_root; then
        log_error "This operation requires root privileges. Please run as root."
        exit 1
    fi
}

get_os() {
    local os_name=""

    if [[ -f /etc/os-release ]]; then
        # shellcheck disable=SC1091
        os_name="$(. /etc/os-release && printf '%s' "${ID}")"
    elif [[ -f /etc/lsb-release ]]; then
        # shellcheck disable=SC1091
        os_name="$(. /etc/lsb-release && printf '%s' "${DISTRIB_ID}")"
    elif [[ -f /etc/redhat-release ]]; then
        os_name="rhel"
    elif [[ -f /etc/debian_version ]]; then
        os_name="debian"
    elif uname -s >/dev/null 2>&1; then
        os_name="$(uname -s | tr '[:upper:]' '[:lower:]')"
    fi

    printf '%s' "${os_name}"
}

get_os_family() {
    local os
    os="$(get_os)"

    case "${os}" in
        ubuntu|debian|linuxmint|pop|elementary|kali|parrot)
            printf 'debian'
            ;;
        rhel|centos|fedora|rocky|alma|ol|amzn)
            printf 'rhel'
            ;;
        opensuse*|sles|suse)
            printf 'suse'
            ;;
        arch|manjaro|endeavouros|garuda)
            printf 'arch'
            ;;
        alpine)
            printf 'alpine'
            ;;
        *)
            printf '%s' "${os}"
            ;;
    esac
}

get_kernel_version() {
    local version=""

    if command_exists uname; then
        version="$(uname -r)"
    fi

    printf '%s' "${version}"
}

get_arch() {
    local arch=""

    if command_exists uname; then
        arch="$(uname -m)"
    fi

    case "${arch}" in
        x86_64|amd64)  printf 'x86_64' ;;
        i*86)          printf 'i686' ;;
        aarch64)       printf 'aarch64' ;;
        armv7l|armhf)  printf 'armv7l' ;;
        armv6l)        printf 'armv6l' ;;
        s390x)         printf 's390x' ;;
        ppc64le)       printf 'ppc64le' ;;
        *)             printf '%s' "${arch}" ;;
    esac
}

get_hostname() {
    local h=""

    if [[ -f /etc/hostname ]]; then
        h="$(< /etc/hostname)"
    elif command_exists hostname; then
        h="$(hostname)"
    fi

    printf '%s' "${h}"
}

get_uptime() {
    local uptime_str=""

    if [[ -f /proc/uptime ]]; then
        local uptime_seconds
        uptime_seconds="$(awk '{print int($1)}' /proc/uptime)"
        printf '%s' "${uptime_seconds}"
    elif command_exists uptime; then
        uptime_str="$(uptime -p 2>/dev/null || uptime)"
        printf '%s' "${uptime_str}"
    else
        printf '0'
    fi
}

get_pid_count() {
    local count=0

    if [[ -d /proc ]]; then
        count="$(ls -1d /proc/[0-9]* 2>/dev/null | wc -l)"
    fi

    printf '%s' "${count}"
}

generate_uuid() {
    local uuid=""

    if command_exists uuidgen; then
        uuid="$(uuidgen | tr '[:upper:]' '[:lower:]')"
    elif [[ -f /proc/sys/kernel/random/uuid ]]; then
        uuid="$(< /proc/sys/kernel/random/uuid)"
    else
        uuid="$(printf '%04x%04x-%04x-%04x-%04x-%04x%04x%04x' \
            $((RANDOM % 65536)) $((RANDOM % 65536)) \
            $((RANDOM % 65536)) \
            $(( (RANDOM % 4096) | 0x4000 )) \
            $(( (RANDOM % 16384) | 0x8000 )) \
            $((RANDOM % 65536)) $((RANDOM % 65536)) $((RANDOM % 65536)))"
    fi

    printf '%s' "${uuid}"
}

retry() {
    local -r max_attempts="${1}"
    local -r delay="${2}"
    shift 2
    local -r cmd=("$@")

    local attempt=1

    while [[ "${attempt}" -le "${max_attempts}" ]]; do
        if "${cmd[@]}"; then
            return 0
        fi

        if [[ "${attempt}" -lt "${max_attempts}" ]]; then
            log_debug "Retry ${attempt}/${max_attempts} failed, waiting ${delay}s..."
            sleep "${delay}"
        fi

        (( attempt++ ))
    done

    log_error "Command failed after ${max_attempts} attempts: ${cmd[*]}"
    return 1
}

timeout() {
    local -r seconds="${1}"
    shift
    local -r cmd=("$@")

    if command_exists timeout; then
        timeout "${seconds}" "${cmd[@]}"
        return $?
    fi

    # Fallback: run in background and kill if overdue
    local -r tmpfile="$(mktemp)"
    local pid

    "${cmd[@]}" > "${tmpfile}" 2>&1 &
    pid=$!

    local elapsed=0

    while kill -0 "${pid}" 2>/dev/null; do
        if [[ "${elapsed}" -ge "${seconds}" ]]; then
            kill -TERM "${pid}" 2>/dev/null || true
            sleep 1
            kill -KILL "${pid}" 2>/dev/null || true
            rm -f "${tmpfile}"
            return 124
        fi
        sleep 1
        (( elapsed++ ))
    done

    wait "${pid}" 2>/dev/null
    local exit_code=$?
    cat "${tmpfile}"
    rm -f "${tmpfile}"
    return "${exit_code}"
}

measure_time() {
    local -r cmd=("$@")
    local start_time
    local end_time
    local elapsed

    start_time=$(date +%s%N 2>/dev/null || date +%s)

    local exit_code=0
    "${cmd[@]}" || exit_code=$?

    end_time=$(date +%s%N 2>/dev/null || date +%s)

    if [[ "${#start_time}" -gt 10 && "${#end_time}" -gt 10 ]]; then
        elapsed=$(( (end_time - start_time) / 1000000 ))
        printf '%dms' "${elapsed}"
    else
        elapsed=$(( end_time - start_time ))
        printf '%ds' "${elapsed}"
    fi

    return "${exit_code}"
}

temp_dir_create() {
    local -r prefix="${1:-sentinel}"

    local dir
    dir="$(mktemp -d -t "${prefix}.XXXXXX")"

    SENTINEL_TEMP_DIRS+=("${dir}")
    printf '%s' "${dir}"
}

temp_dir_cleanup() {
    local dir

    for dir in "${SENTINEL_TEMP_DIRS[@]+"${SENTINEL_TEMP_DIRS[@]}"}"; do
        if [[ -d "${dir}" ]]; then
            rm -rf "${dir}"
            log_debug "Cleaned up temp directory: ${dir}"
        fi
    done

    SENTINEL_TEMP_DIRS=()
}

trap temp_dir_cleanup EXIT

sanitize_filename() {
    local -r name="${1}"

    # Replace path separators and dangerous characters
    local sanitized="${name}"
    sanitized="${sanitized//[\/\\]/_}"
    sanitized="${sanitized//[^a-zA-Z0-9._-]/_}"
    sanitized="${sanitized//__/}"
    sanitized="${sanitized#_}"
    sanitized="${sanitized%_}"

    # Prevent empty names
    if [[ -z "${sanitized}" ]]; then
        sanitized="unnamed"
    fi

    printf '%s' "${sanitized}"
}

file_age_seconds() {
    local -r filepath="${1}"

    if [[ ! -e "${filepath}" ]]; then
        printf '%s' "-1"
        return
    fi

    local age
    age="$(find "${filepath}" -maxdepth 0 -printf '%T+\n' 2>/dev/null | cut -d. -f1)"

    if [[ -n "${age}" ]]; then
        local now
        now="$(date +%s)"
        local file_time
        file_time="$(date -d "${age}" +%s 2>/dev/null || echo 0)"
        printf '%s' "$(( now - file_time ))"
    else
        printf '%s' "0"
    fi
}

human_readable_size() {
    local -r bytes="${1}"
    local size="${bytes}"
    local unit="B"

    if [[ "${size}" -ge 1073741824 ]]; then
        size=$(( size / 1073741824 ))
        unit="GB"
    elif [[ "${size}" -ge 1048576 ]]; then
        size=$(( size / 1048576 ))
        unit="MB"
    elif [[ "${size}" -ge 1024 ]]; then
        size=$(( size / 1024 ))
        unit="KB"
    fi

    printf '%s%s' "${size}" "${unit}"
}
