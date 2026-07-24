#!/usr/bin/env bash
set -Eeuo pipefail
IFS=$'\n\t'

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
LIB_DIR="${SCRIPT_DIR}/../../lib"
source "${LIB_DIR}/logger.sh"
source "${LIB_DIR}/colors.sh"
source "${LIB_DIR}/utils.sh"
source "${LIB_DIR}/output.sh"
source "${LIB_DIR}/validation.sh"
source "${LIB_DIR}/permissions.sh"
source "${LIB_DIR}/filesystem.sh"
source "${LIB_DIR}/network.sh"
source "${LIB_DIR}/process.sh"
source "${LIB_DIR}/reporting.sh"

readonly MODULE_NAME="memory"
readonly MODULE_DESCRIPTION="Memory and process analysis"
readonly MODULE_VERSION="1.0.0"
readonly MODULE_SEVERITY_THRESHOLD="info"

_top_memory_processes() {
    print_subheader "Top Memory Consuming Processes"

    local procs
    procs="$(ps -eo pid,user,%mem,rss,comm --sort=-%mem --no-headers 2>/dev/null | head -15 || true)"

    if [[ -n "${procs}" ]]; then
        print_table_header "PID" "USER" "%MEM" "RSS(KB)" "COMMAND"
        local line
        while IFS= read -r line; do
            [[ -z "${line}" ]] && continue
            local pid user mem rss comm
            pid="$(echo "${line}" | awk '{print $1}')"
            user="$(echo "${line}" | awk '{print $2}')"
            mem="$(echo "${line}" | awk '{print $3}')"
            rss="$(echo "${line}" | awk '{print $4}')"
            comm="$(echo "${line}" | awk '{print $5}')"
            print_table_row "${pid}" "${user}" "${mem}%" "${rss}" "${comm}"
        done <<< "${procs}"
        print_success "Top memory consumers displayed"
    else
        print_info "No process information available"
    fi
}

_excessive_memory_processes() {
    print_subheader "Processes with Excessive Memory Usage"

    local threshold=20
    local found_issue=false

    local line
    while IFS= read -r line; do
        [[ -z "${line}" ]] && continue
        local pid user mem pct rss comm
        pid="$(echo "${line}" | awk '{print $1}')"
        user="$(echo "${line}" | awk '{print $2}')"
        mem="$(echo "${line}" | awk '{print $3}')"
        rss="$(echo "${line}" | awk '{print $4}')"
        comm="$(echo "${line}" | awk '{print $5}')"

        if [[ -n "${mem}" ]] && awk "BEGIN {exit !(${mem} >= ${threshold})}" 2>/dev/null; then
            local rss_mb=$(( rss / 1024 ))
            add_finding "${MODULE_NAME}" "MEDIUM" \
                "Process using excessive memory" \
                "${comm} (PID ${pid}) using ${mem}% memory (${rss_mb} MB RSS)" \
                "pid=${pid} user=${user} command=${comm} memory=${mem}% rss=${rss_mb}MB" \
                "Investigate process and consider resource limits"
            print_warning "Excessive memory: ${comm} (PID ${pid}) - ${mem}% / ${rss_mb}MB"
            found_issue=true
        fi
    done < <(ps -eo pid,user,%mem,rss,comm --sort=-%mem --no-headers 2>/dev/null | head -20 || true)

    if [[ "${found_issue}" == false ]]; then
        print_success "No processes with excessive memory usage"
    fi
}

_deleted_executables() {
    print_subheader "Deleted Executables in Memory"

    local found_issue=false
    local pid exe

    for pid in /proc/[0-9]*; do
        pid="${pid##*/}"
        if [[ -L "/proc/${pid}/exe" ]]; then
            exe="$(readlink -f "/proc/${pid}/exe" 2>/dev/null || true)"
            if [[ -n "${exe}" && ! -e "${exe}" ]]; then
                local user cmdline
                user="$(stat -c '%U' "/proc/${pid}" 2>/dev/null || echo "unknown")"
                cmdline="$(tr '\0' ' ' < "/proc/${pid}/cmdline" 2>/dev/null || echo "unknown")"

                add_finding "${MODULE_NAME}" "HIGH" \
                    "Deleted executable running in memory" \
                    "PID ${pid} running from deleted binary: ${exe}" \
                    "pid=${pid} user=${user} deleted_exe=${exe} cmdline=${cmdline}" \
                    "Investigate process; binary was deleted but process still running"
                print_error "Deleted exe: PID ${pid} (${exe}) - ${cmdline}"
                found_issue=true
            fi
        fi
    done 2>/dev/null

    if [[ "${found_issue}" == false ]]; then
        print_success "No deleted executables running in memory"
    fi
}

_suspicious_shared_memory() {
    print_subheader "Shared Memory Segments (ipcs)"

    if ! command -v ipcs &>/dev/null; then
        print_info "ipcs not available, skipping"
        return
    fi

    local ipc_shm
    ipc_shm="$(ipcs -m 2>/dev/null || true)"

    if [[ -n "${ipc_shm}" ]]; then
        local count
        count="$(echo "${ipc_shm}" | grep -c "^0x" || echo "0")"

        if [[ "${count}" -gt 0 ]]; then
            add_finding "${MODULE_NAME}" "LOW" \
                "Shared memory segments detected" \
                "${count} shared memory segment(s) found" \
                "count=${count}" \
                "Review shared memory segments for sensitive data"
            print_warning "Shared memory segments: ${count}"
            echo "${ipc_shm}" | head -20

            local segment
            while IFS= read -r segment; do
                [[ -z "${segment}" ]] && continue
                local shmid perms size
                shmid="$(echo "${segment}" | awk '{print $2}')"
                perms="$(echo "${segment}" | awk '{print $6}')"
                size="$(echo "${segment}" | awk '{print $5}')"

                if [[ -n "${perms}" && "${perms}" != "0000" ]]; then
                    local perms_dec=$(( 8#${perms} 2>/dev/null || echo 0 ))
                    if [[ $(( perms_dec & 8#0002 )) -ne 0 ]]; then
                        add_finding "${MODULE_NAME}" "MEDIUM" \
                            "World-writable shared memory segment" \
                            "SHM ID ${shmid} with permissions ${perms}" \
                            "shmid=${shmid} perms=${perms} size=${size}" \
                            "Restrict shared memory permissions"
                        print_error "World-writable SHM: ${shmid} (${perms})"
                    fi
                fi
            done <<< "$(echo "${ipc_shm}" | tail -n +4 | head -n -1)"
        else
            print_success "No shared memory segments found"
        fi
    else
        print_success "No shared memory segments found"
    fi
}

_large_rss_processes() {
    print_subheader "Processes with Large Resident Set Size"

    local rss_threshold=1048576
    local found_issue=false

    local line
    while IFS= read -r line; do
        [[ -z "${line}" ]] && continue
        local pid user rss comm
        pid="$(echo "${line}" | awk '{print $1}')"
        user="$(echo "${line}" | awk '{print $2}')"
        rss="$(echo "${line}" | awk '{print $3}')"
        comm="$(echo "${line}" | awk '{print $4}')"

        if [[ -n "${rss}" && "${rss}" -gt "${rss_threshold}" ]]; then
            local rss_mb=$(( rss / 1024 ))
            add_finding "${MODULE_NAME}" "MEDIUM" \
                "Process with very large RSS" \
                "${comm} (PID ${pid}) RSS: ${rss_mb} MB" \
                "pid=${pid} user=${user} command=${comm} rss=${rss_mb}MB" \
                "Investigate large memory allocation"
            print_warning "Large RSS: ${comm} (PID ${pid}) - ${rss_mb} MB"
            found_issue=true
        fi
    done < <(ps -eo pid,user,rss,comm --sort=-rss --no-headers 2>/dev/null | head -10 || true)

    if [[ "${found_issue}" == false ]]; then
        print_success "No processes with excessively large RSS"
    fi
}

_deleted_mmap_files() {
    print_subheader "Memory-Mapped Deleted Files"

    local found_issue=false
    local pid

    for pid in /proc/[0-9]*; do
        pid="${pid##*/}"
        if [[ -f "/proc/${pid}/maps" ]]; then
            local deleted_maps
            deleted_maps="$(grep "(deleted)" "/proc/${pid}/maps" 2>/dev/null | head -5 || true)"
            if [[ -n "${deleted_maps}" ]]; then
                local comm
                comm="$(cat "/proc/${pid}/comm" 2>/dev/null || echo "unknown")"
                local count
                count="$(echo "${deleted_maps}" | grep -c . || echo "0")"

                add_finding "${MODULE_NAME}" "MEDIUM" \
                    "Process has deleted memory-mapped files" \
                    "${comm} (PID ${pid}) has ${count} deleted mmap file(s)" \
                    "pid=${pid} command=${comm} deleted_maps=${count}" \
                    "Investigate process for potential persistence mechanism"
                print_warning "Deleted mmap: ${comm} (PID ${pid}) - ${count} files"
                found_issue=true
            fi
        fi
    done 2>/dev/null

    if [[ "${found_issue}" == false ]]; then
        print_success "No deleted memory-mapped files detected"
    fi
}

_meminfo_analysis() {
    print_subheader "/proc/meminfo Analysis"

    if [[ ! -r /proc/meminfo ]]; then
        print_info "Cannot read /proc/meminfo"
        return
    fi

    local mem_total mem_free mem_available buffers cached
    mem_total="$(grep '^MemTotal:' /proc/meminfo 2>/dev/null | awk '{print $2}' || echo "0")"
    mem_free="$(grep '^MemFree:' /proc/meminfo 2>/dev/null | awk '{print $2}' || echo "0")"
    mem_available="$(grep '^MemAvailable:' /proc/meminfo 2>/dev/null | awk '{print $2}' || echo "0")"
    buffers="$(grep '^Buffers:' /proc/meminfo 2>/dev/null | awk '{print $2}' || echo "0")"
    cached="$(grep '^Cached:' /proc/meminfo 2>/dev/null | awk '{print $2}' || echo "0")"

    local total_mb=$(( mem_total / 1024 ))
    local free_mb=$(( mem_free / 1024 ))
    local available_mb=$(( mem_available / 1024 ))

    print_info "Total: ${total_mb} MB | Free: ${free_mb} MB | Available: ${available_mb} MB"

    if [[ "${mem_total}" -gt 0 ]]; then
        local usage_pct=$(( ((mem_total - mem_available) * 100) / mem_total ))
        if [[ "${usage_pct}" -ge 95 ]]; then
            add_finding "${MODULE_NAME}" "HIGH" \
                "Critical memory usage" \
                "System memory usage at ${usage_pct}%" \
                "total=${total_mb}MB available=${available_mb}MB usage=${usage_pct}%" \
                "Investigate memory-hungry processes and consider adding RAM"
            print_error "Memory usage critical: ${usage_pct}%"
        elif [[ "${usage_pct}" -ge 85 ]]; then
            add_finding "${MODULE_NAME}" "MEDIUM" \
                "High memory usage" \
                "System memory usage at ${usage_pct}%" \
                "total=${total_mb}MB available=${available_mb}MB usage=${usage_pct}%" \
                "Monitor memory usage"
            print_warning "Memory usage high: ${usage_pct}%"
        else
            print_success "Memory usage: ${usage_pct}%"
        fi
    fi
}

_swap_analysis() {
    print_subheader "Swap Usage"

    if [[ ! -r /proc/meminfo ]]; then
        return
    fi

    local swap_total swap_free
    swap_total="$(grep '^SwapTotal:' /proc/meminfo 2>/dev/null | awk '{print $2}' || echo "0")"
    swap_free="$(grep '^SwapFree:' /proc/meminfo 2>/dev/null | awk '{print $2}' || echo "0")"

    local total_mb=$(( swap_total / 1024 ))
    local free_mb=$(( swap_free / 1024 ))
    local used_mb=$(( total_mb - free_mb ))

    if [[ "${swap_total}" -eq 0 ]]; then
        print_info "No swap configured"
        return
    fi

    print_info "Swap: ${total_mb} MB total | ${used_mb} MB used | ${free_mb} MB free"

    if [[ "${swap_total}" -gt 0 ]]; then
        local usage_pct=$(( (used_mb * 100) / total_mb ))
        if [[ "${usage_pct}" -ge 80 ]]; then
            add_finding "${MODULE_NAME}" "MEDIUM" \
                "High swap usage" \
                "Swap usage at ${usage_pct}% (${used_mb} MB of ${total_mb} MB)" \
                "swap_total=${total_mb}MB swap_used=${used_mb}MB swap_pct=${usage_pct}%" \
                "Investigate memory pressure; consider adding RAM"
            print_warning "Swap usage high: ${usage_pct}%"
        else
            print_success "Swap usage: ${usage_pct}%"
        fi
    fi
}

_slab_memory() {
    print_subheader "Kernel Slab Memory"

    if [[ ! -r /proc/meminfo ]]; then
        return
    fi

    local slab_total
    slab_total="$(grep '^SReclaimable:' /proc/meminfo 2>/dev/null | awk '{print $2}' || echo "0")"
    local slab_unreclaimable
    slab_unreclaimable="$(grep '^SUnreclaim:' /proc/meminfo 2>/dev/null | awk '{print $2}' || echo "0")"

    local total_mb=$(( slab_total / 1024 ))
    local unreclaimable_mb=$(( slab_unreclaimable / 1024 ))

    print_info "Slab reclaimable: ${total_mb} MB | Unreclaimable: ${unreclaimable_mb} MB"

    if [[ "${slab_unreclaimable}" -gt 524288 ]]; then
        add_finding "${MODULE_NAME}" "MEDIUM" \
            "Large unreclaimable slab memory" \
            "Kernel slab unreclaimable memory: ${unreclaimable_mb} MB" \
            "slab_unreclaimable=${unreclaimable_mb}MB" \
            "Investigate potential kernel memory leak"
        print_warning "High unreclaimable slab: ${unreclaimable_mb} MB"
    else
        print_success "Slab memory within normal range"
    fi
}

_process_injection_indicators() {
    print_subheader "Process Injection Indicators"

    local found_issue=false
    local pid

    for pid in /proc/[0-9]*; do
        pid="${pid##*/}"
        [[ ! -f "/proc/${pid}/maps" ]] && continue

        local comm
        comm="$(cat "/proc/${pid}/comm" 2>/dev/null || continue)"

        local anon_exec_count
        anon_exec_count="$(grep -c "rwxp" "/proc/${pid}/maps" 2>/dev/null || echo "0")"

        if [[ "${anon_exec_count}" -gt 5 ]]; then
            local user
            user="$(stat -c '%U' "/proc/${pid}" 2>/dev/null || echo "unknown")"

            add_finding "${MODULE_NAME}" "HIGH" \
                "Possible process injection" \
                "${comm} (PID ${pid}) has ${anon_exec_count} anonymous executable memory regions" \
                "pid=${pid} user=${user} command=${comm} anon_exec=${anon_exec_count}" \
                "Investigate process for code injection or malware"
            print_error "Injection indicator: ${comm} (PID ${pid}) - ${anon_exec_count} anon exec regions"
            found_issue=true
        fi
    done 2>/dev/null

    if [[ "${found_issue}" == false ]]; then
        print_success "No process injection indicators detected"
    fi
}

_network_proc_memory() {
    print_subheader "Processes with Network Connections and Memory Usage"

    if ! command -v ss &>/dev/null; then
        print_info "ss not available, skipping"
        return
    fi

    local procs_with_conns
    procs_with_conns="$(ss -tnp 2>/dev/null | grep -oP 'pid=\K[0-9]+' | sort -u | head -15 || true)"

    if [[ -n "${procs_with_conns}" ]]; then
        local pid
        while IFS= read -r pid; do
            [[ -z "${pid}" ]] && continue
            [[ ! -d "/proc/${pid}" ]] && continue

            local comm rss user
            comm="$(cat "/proc/${pid}/comm" 2>/dev/null || echo "unknown")"
            rss="$(awk '/VmRSS/{print $2}' "/proc/${pid}/status" 2>/dev/null || echo "0")"
            user="$(stat -c '%U' "/proc/${pid}" 2>/dev/null || echo "unknown")"
            local rss_mb=$(( rss / 1024 ))

            print_info "PID ${pid} (${comm}) - User: ${user} - RSS: ${rss_mb} MB"
        done <<< "${procs_with_conns}"
        print_success "Network-connected processes enumerated"
    else
        print_info "No network-connected processes found"
    fi
}

_tmp_dev_shm_processes() {
    print_subheader "Processes Running from /dev/shm or /tmp"

    local found_issue=false
    local pid

    for pid in /proc/[0-9]*; do
        pid="${pid##*/}"
        if [[ -L "/proc/${pid}/exe" ]]; then
            local exe
            exe="$(readlink -f "/proc/${pid}/exe" 2>/dev/null || true)"
            if [[ -n "${exe}" && ( "${exe}" == /dev/shm/* || "${exe}" == /tmp/* || "${exe}" == /var/tmp/* ) ]]; then
                local user cmdline
                user="$(stat -c '%U' "/proc/${pid}" 2>/dev/null || echo "unknown")"
                cmdline="$(tr '\0' ' ' < "/proc/${pid}/cmdline" 2>/dev/null || echo "unknown")"

                add_finding "${MODULE_NAME}" "HIGH" \
                    "Process running from suspicious location" \
                    "${exe} (PID ${pid}) running from ${exe}" \
                    "pid=${pid} user=${user} exe=${exe} cmdline=${cmdline}" \
                    "Investigate immediately; binaries in /tmp or /dev/shm are often malicious"
                print_error "Suspicious location: PID ${pid} - ${exe}"
                found_issue=true
            fi
        fi
    done 2>/dev/null

    if [[ "${found_issue}" == false ]]; then
        print_success "No processes running from /tmp or /dev/shm"
    fi
}

run() {
    print_header "Memory & Process Analysis"

    _top_memory_processes
    _excessive_memory_processes
    _deleted_executables
    _suspicious_shared_memory
    _large_rss_processes
    _deleted_mmap_files
    _meminfo_analysis
    _swap_analysis
    _slab_memory
    _process_injection_indicators
    _network_proc_memory
    _tmp_dev_shm_processes
}

if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    run
fi
