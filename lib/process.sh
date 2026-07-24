#!/usr/bin/env bash
# process.sh - Process inspection and analysis for QYVORA Sentinel
# Provides functions for enumerating running processes, detecting suspicious
# activity such as mining tools and reverse shells, and inspecting process trees.

# Source guard - prevent re-sourcing
if [[ "${_SENTINEL_LIB_LOADED:-}" == *"$(basename "${BASH_SOURCE[0]}")"* ]]; then
    return 0 2>/dev/null || true
fi
_SENTINEL_LIB_LOADED="${_SENTINEL_LIB_LOADED:-} $(basename "${BASH_SOURCE[0]}")"

set -Eeuo pipefail
IFS=$'\n\t'

# Sentinel suspicious process patterns (mining tools, reverse shells, etc.)
readonly SENTINEL_SUSPICIOUS_PATTERNS="xmrig|xmr-stak|cpuminer|minerd|ethminer|cgminer|bfgminer|stratum\+tcp|nc -e|ncat.*-e|socat.*exec|bash -i|/dev/tcp|/dev/udp|python.*socket.*connect|perl.*socket|ruby.*socket|php.*fsockopen|curl.*sh|wget.*sh"

# list_processes - List all running processes with PID, PPID, user, and command
list_processes() {
    local format="%-8s %-8s %-12s %s\n"
    printf "${format}" "PID" "PPID" "USER" "COMMAND"
    ps -eo pid,ppid,user,args --no-headers 2>/dev/null | while IFS= read -r line; do
        local pid ppid user cmd
        pid="$(echo "${line}" | awk '{print $1}')"
        ppid="$(echo "${line}" | awk '{print $2}')"
        user="$(echo "${line}" | awk '{print $3}')"
        cmd="$(echo "${line}" | awk '{for(i=4;i<=NF;i++) printf "%s ", $i; print ""}' | xargs)"
        printf "${format}" "${pid}" "${ppid}" "${user}" "${cmd}"
    done
}

# find_deleted_executables - Find processes running from deleted binary files
find_deleted_executables() {
    local pid exe
    for pid in /proc/[0-9]*; do
        pid="${pid##*/}"
        if [[ -L "/proc/${pid}/exe" ]]; then
            exe="$(readlink -f "/proc/${pid}/exe" 2>/dev/null || true)"
            if [[ -n "${exe}" && ! -e "${exe}" ]]; then
                local cmdline
                cmdline="$(tr '\0' ' ' < "/proc/${pid}/cmdline" 2>/dev/null || echo "unknown")"
                echo "PID=${pid} DELETED_EXE=${exe} CMD=${cmdline}"
            fi
        fi
    done
}

# find_zombie_processes - Find zombie (Z) state processes
find_zombie_processes() {
    ps -eo pid,ppid,stat,user,comm --no-headers 2>/dev/null | while IFS= read -r line; do
        local stat
        stat="$(echo "${line}" | awk '{print $3}')"
        if [[ "${stat}" == *"Z"* ]]; then
            echo "${line}"
        fi
    done
}

# find_high_cpu - Find processes consuming more than a CPU threshold percentage
find_high_cpu() {
    local threshold="${1:-80}"
    ps -eo pid,user,%cpu,comm --no-headers 2>/dev/null | while IFS= read -r line; do
        local cpu
        cpu="$(echo "${line}" | awk '{print $3}')"
        if [[ "$(echo "${cpu} > ${threshold}" | bc 2>/dev/null || echo 0)" -eq 1 ]]; then
            echo "${line}"
        fi
    done
}

# find_high_memory - Find processes consuming more than a memory threshold percentage
find_high_memory() {
    local threshold="${1:-80}"
    ps -eo pid,user,%mem,comm --no-headers 2>/dev/null | while IFS= read -r line; do
        local mem
        mem="$(echo "${line}" | awk '{print $3}')"
        if [[ "$(echo "${mem} > ${threshold}" | bc 2>/dev/null || echo 0)" -eq 1 ]]; then
            echo "${line}"
        fi
    done
}

# get_process_tree - Show the process tree for a given PID (and its children)
get_process_tree() {
    local pid="${1:-}"
    if [[ -z "${pid}" ]]; then
        return 1
    fi
    if [[ ! -d "/proc/${pid}" ]]; then
        return 1
    fi
    if command -v pstree &>/dev/null; then
        pstree -p "${pid}" 2>/dev/null || true
    else
        local current_pid="${pid}"
        while [[ -n "${current_pid}" && "${current_pid}" != "1" ]]; do
            local ppid cmdline
            ppid="$(awk '{print $4}' "/proc/${current_pid}/stat" 2>/dev/null || echo "")"
            cmdline="$(tr '\0' ' ' < "/proc/${current_pid}/cmdline" 2>/dev/null || echo "unknown")"
            echo "  PID=${current_pid} CMD=${cmdline}"
            if [[ -z "${ppid}" || "${ppid}" == "${current_pid}" ]]; then
                break
            fi
            current_pid="${ppid}"
        done
    fi
}

# detect_suspicious_processes - Detect processes matching known suspicious patterns
detect_suspicious_processes() {
    local pattern="${SENTINEL_SUSPICIOUS_PATTERNS}"
    ps -eo pid,user,comm,args --no-headers 2>/dev/null | while IFS= read -r line; do
        if echo "${line}" | grep -iE "${pattern}" &>/dev/null; then
            echo "${line}"
        fi
    done
}

# get_process_open_files - List open file descriptors for a process
get_process_open_files() {
    local pid="${1:-}"
    if [[ -z "${pid}" ]]; then
        return 1
    fi
    if [[ ! -d "/proc/${pid}/fd" ]]; then
        return 1
    fi
    local fd link
    for fd in "/proc/${pid}/fd/"*; do
        if [[ -L "${fd}" ]]; then
            link="$(readlink "${fd}" 2>/dev/null || echo "deleted")"
            local fd_num="${fd##*/}"
            printf "%-6s %s\n" "${fd_num}" "${link}"
        fi
    done
}

# get_process_environment - Get environment variables for a process (requires root or same user)
get_process_environment() {
    local pid="${1:-}"
    if [[ -z "${pid}" ]]; then
        return 1
    fi
    local environ_file="/proc/${pid}/environ"
    if [[ ! -r "${environ_file}" ]]; then
        echo "Permission denied or process not found" >&2
        return 1
    fi
    tr '\0' '\n' < "${environ_file}" 2>/dev/null || true
}

# is_process_running - Check if a process with a given name is running
is_process_running() {
    local name="${1:-}"
    if [[ -z "${name}" ]]; then
        return 1
    fi
    pgrep -x "${name}" &>/dev/null
}
