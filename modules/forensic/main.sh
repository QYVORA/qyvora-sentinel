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

# shellcheck disable=SC2034
readonly MODULE_NAME="forensic"
readonly MODULE_DESCRIPTION="Forensic artifact collection"
readonly MODULE_VERSION="1.0.0"
readonly MODULE_SEVERITY_THRESHOLD="info"

_forensic_output_dir=""

_init_output_dir() {
    local timestamp
    timestamp="$(date -u '+%Y%m%d_%H%M%S')"
    _forensic_output_dir="$(pwd)/reports/forensic_${timestamp}"

    if [[ ! -d "${_forensic_output_dir}" ]]; then
        mkdir -p "${_forensic_output_dir}"
    fi

    print_info "Forensic artifacts will be saved to: ${_forensic_output_dir}"
}

_collect_system_metadata() {
    print_subheader "Collecting System Metadata"

    local meta_file="${_forensic_output_dir}/system_metadata.txt"
    {
        echo "=== QYVORA Sentinel Forensic Collection ==="
        echo "Collection Time: $(date -u '+%Y-%m-%dT%H:%M:%SZ')"
        echo ""
        echo "=== Hostname ==="
        hostname 2>/dev/null || echo "N/A"
        echo ""
        echo "=== Uptime ==="
        uptime 2>/dev/null || echo "N/A"
        echo ""
        echo "=== Kernel ==="
        uname -a 2>/dev/null || echo "N/A"
        echo ""
        echo "=== OS Release ==="
        cat /etc/os-release 2>/dev/null || echo "N/A"
        echo ""
        echo "=== Architecture ==="
        uname -m 2>/dev/null || echo "N/A"
        echo ""
        echo "=== Logged-in Users ==="
        w 2>/dev/null || who 2>/dev/null || echo "N/A"
        echo ""
        echo "=== All Users with Login Shells ==="
        grep -v '/nologin\|/false' /etc/passwd 2>/dev/null || echo "N/A"
        echo ""
        echo "=== Date/Time ==="
        date -u '+%Y-%m-%dT%H:%M:%SZ' 2>/dev/null || echo "N/A"
        timedatectl 2>/dev/null || echo "N/A"
    } > "${meta_file}"

    add_finding "${MODULE_NAME}" "INFO" \
        "System metadata collected" \
        "Hostname, uptime, kernel, users, and OS info captured" \
        "output=${meta_file}"
    print_success "System metadata collected"
}

_snapshot_processes() {
    print_subheader "Snapshotting Running Processes"

    local proc_file="${_forensic_output_dir}/processes.txt"
    {
        echo "=== Process List (ps aux) ==="
        ps aux 2>/dev/null || echo "N/A"
        echo ""
        echo "=== Process Tree ==="
        pstree -p 2>/dev/null || ps -ef 2>/dev/null || echo "N/A"
        echo ""
        echo "=== Process with Full Command Lines ==="
        ps -eo pid,ppid,user,comm,args --no-headers 2>/dev/null || echo "N/A"
    } > "${proc_file}"

    local proc_count
    proc_count="$(ps -eo pid --no-headers 2>/dev/null | wc -l || echo 0)"

    add_finding "${MODULE_NAME}" "INFO" \
        "Process snapshot collected" \
        "Captured ${proc_count} running processes" \
        "output=${proc_file} process_count=${proc_count}"
    print_success "Process snapshot collected (${proc_count} processes)"
}

_snapshot_network_connections() {
    print_subheader "Snapshotting Network Connections"

    local net_file="${_forensic_output_dir}/network_connections.txt"
    {
        echo "=== All Network Connections ==="
        ss -tnpa 2>/dev/null || netstat -tnpa 2>/dev/null || echo "N/A"
        echo ""
        echo "=== Established Connections ==="
        ss -tnp state established 2>/dev/null || echo "N/A"
        echo ""
        echo "=== UDP Connections ==="
        ss -unpa 2>/dev/null || echo "N/A"
    } > "${net_file}"

    add_finding "${MODULE_NAME}" "INFO" \
        "Network connection snapshot collected" \
        "Active TCP and UDP connections captured" \
        "output=${net_file}"
    print_success "Network connection snapshot collected"
}

_snapshot_listening_ports() {
    print_subheader "Snapshotting Listening Ports"

    local ports_file="${_forensic_output_dir}/listening_ports.txt"
    {
        echo "=== Listening TCP Ports ==="
        ss -tlnp 2>/dev/null || netstat -tlnp 2>/dev/null || echo "N/A"
        echo ""
        echo "=== Listening UDP Ports ==="
        ss -ulnp 2>/dev/null || netstat -ulnp 2>/dev/null || echo "N/A"
    } > "${ports_file}"

    local port_count
    port_count="$(ss -tlnp 2>/dev/null | grep -c "^LISTEN" || echo "0")"

    add_finding "${MODULE_NAME}" "INFO" \
        "Listening ports snapshot collected" \
        "Found ${port_count} listening TCP ports" \
        "output=${ports_file} port_count=${port_count}"
    print_success "Listening ports snapshot collected (${port_count} ports)"
}

_snapshot_routing_table() {
    print_subheader "Snapshotting Routing Table"

    local route_file="${_forensic_output_dir}/routing_table.txt"
    {
        echo "=== Routing Table ==="
        ip route show 2>/dev/null || route -n 2>/dev/null || echo "N/A"
        echo ""
        echo "=== ARP Table ==="
        ip neigh show 2>/dev/null || arp -an 2>/dev/null || echo "N/A"
        echo ""
        echo "=== Network Interfaces ==="
        ip -br addr show 2>/dev/null || ifconfig -a 2>/dev/null || echo "N/A"
    } > "${route_file}"

    add_finding "${MODULE_NAME}" "INFO" \
        "Routing table snapshot collected" \
        "Kernel routing table, ARP cache, and interfaces captured" \
        "output=${route_file}"
    print_success "Routing table snapshot collected"
}

_snapshot_cron_jobs() {
    print_subheader "Snapshotting Cron Jobs"

    local cron_file="${_forensic_output_dir}/cron_jobs.txt"
    {
        echo "=== System Crontab ==="
        cat /etc/crontab 2>/dev/null || echo "N/A"
        echo ""
        echo "=== /etc/cron.d/ ==="
        ls -la /etc/cron.d/ 2>/dev/null || echo "N/A"
        echo ""
        for f in /etc/cron.d/*; do
            if [[ -f "${f}" ]]; then
                echo "--- ${f} ---"
                cat "${f}" 2>/dev/null || echo "N/A"
                echo ""
            fi
        done
        echo "=== User Crontabs ==="
        for user_home in /home/*; do
            local username="${user_home##*/}"
            local crontab_out
            crontab_out="$(crontab -l -u "${username}" 2>/dev/null || true)"
            if [[ -n "${crontab_out}" ]]; then
                echo "--- ${username} ---"
                echo "${crontab_out}"
                echo ""
            fi
        done
        echo "=== Root Crontab ==="
        crontab -l 2>/dev/null || echo "No root crontab"
        echo ""
        echo "=== Anacrontab ==="
        cat /etc/anacrontab 2>/dev/null || echo "N/A"
    } > "${cron_file}"

    add_finding "${MODULE_NAME}" "INFO" \
        "Cron jobs snapshot collected" \
        "System and user crontabs captured" \
        "output=${cron_file}"
    print_success "Cron jobs snapshot collected"
}

_snapshot_systemd() {
    print_subheader "Snapshotting Systemd Services and Timers"

    local systemd_file="${_forensic_output_dir}/systemd_services.txt"
    {
        echo "=== Enabled Services ==="
        systemctl list-unit-files --type=service --state=enabled 2>/dev/null || echo "N/A"
        echo ""
        echo "=== Running Services ==="
        systemctl list-units --type=service --state=running 2>/dev/null || echo "N/A"
        echo ""
        echo "=== Enabled Timers ==="
        systemctl list-unit-files --type=timer --state=enabled 2>/dev/null || echo "N/A"
        echo ""
        echo "=== Running Timers ==="
        systemctl list-timers --all 2>/dev/null || echo "N/A"
    } > "${systemd_file}"

    add_finding "${MODULE_NAME}" "INFO" \
        "Systemd services and timers snapshot collected" \
        "Enabled and running services/timers captured" \
        "output=${systemd_file}"
    print_success "Systemd snapshot collected"
}

_snapshot_environment() {
    print_subheader "Snapshotting Environment Variables"

    local env_file="${_forensic_output_dir}/environment.txt"
    {
        echo "=== System Environment ==="
        env 2>/dev/null || echo "N/A"
        echo ""
        echo "=== /etc/environment ==="
        cat /etc/environment 2>/dev/null || echo "N/A"
        echo ""
        echo "=== /etc/profile.d/ ==="
        for f in /etc/profile.d/*.sh; do
            if [[ -f "${f}" ]]; then
                echo "--- ${f} ---"
                cat "${f}" 2>/dev/null || echo "N/A"
                echo ""
            fi
        done
    } > "${env_file}"

    add_finding "${MODULE_NAME}" "INFO" \
        "Environment variables snapshot collected" \
        "System environment and profile scripts captured" \
        "output=${env_file}"
    print_success "Environment snapshot collected"
}

_snapshot_kernel_modules() {
    print_subheader "Snapshotting Loaded Kernel Modules"

    local mod_file="${_forensic_output_dir}/kernel_modules.txt"
    {
        echo "=== Loaded Kernel Modules ==="
        lsmod 2>/dev/null || echo "N/A"
        echo ""
        echo "=== Module Parameters ==="
        if [[ -d /proc/sys/kernel ]]; then
            sysctl -a 2>/dev/null | head -100 || echo "N/A"
        fi
    } > "${mod_file}"

    local mod_count
    mod_count="$(lsmod 2>/dev/null | tail -n +2 | wc -l || echo "0")"

    add_finding "${MODULE_NAME}" "INFO" \
        "Kernel modules snapshot collected" \
        "Captured ${mod_count} loaded kernel modules" \
        "output=${mod_file} module_count=${mod_count}"
    print_success "Kernel modules snapshot collected (${mod_count} modules)"
}

_snapshot_mounts() {
    print_subheader "Snapshotting Mount Points"

    local mount_file="${_forensic_output_dir}/mount_points.txt"
    {
        echo "=== Mount Points ==="
        mount 2>/dev/null || cat /proc/mounts 2>/dev/null || echo "N/A"
        echo ""
        echo "=== Disk Usage ==="
        df -h 2>/dev/null || echo "N/A"
        echo ""
        echo "=== /etc/fstab ==="
        cat /etc/fstab 2>/dev/null || echo "N/A"
    } > "${mount_file}"

    add_finding "${MODULE_NAME}" "INFO" \
        "Mount points snapshot collected" \
        "Filesystem mounts and disk usage captured" \
        "output=${mount_file}"
    print_success "Mount points snapshot collected"
}

_snapshot_dns() {
    print_subheader "Snapshotting DNS Configuration"

    local dns_file="${_forensic_output_dir}/dns_config.txt"
    {
        echo "=== /etc/resolv.conf ==="
        cat /etc/resolv.conf 2>/dev/null || echo "N/A"
        echo ""
        echo "=== /etc/hosts ==="
        cat /etc/hosts 2>/dev/null || echo "N/A"
        echo ""
        echo "=== /etc/nsswitch.conf ==="
        cat /etc/nsswitch.conf 2>/dev/null || echo "N/A"
        echo ""
        echo "=== /etc/nscd.conf ==="
        cat /etc/nscd.conf 2>/dev/null || echo "N/A"
    } > "${dns_file}"

    add_finding "${MODULE_NAME}" "INFO" \
        "DNS configuration snapshot collected" \
        "Resolver config, hosts, and NSS config captured" \
        "output=${dns_file}"
    print_success "DNS configuration snapshot collected"
}

_snapshot_passwd_group() {
    print_subheader "Snapshotting /etc/passwd and /etc/group"

    local auth_file="${_forensic_output_dir}/passwd_group.txt"
    {
        echo "=== /etc/passwd ==="
        cat /etc/passwd 2>/dev/null || echo "N/A"
        echo ""
        echo "=== /etc/shadow (if readable) ==="
        cat /etc/shadow 2>/dev/null || echo "Permission denied or not available"
        echo ""
        echo "=== /etc/group ==="
        cat /etc/group 2>/dev/null || echo "N/A"
        echo ""
        echo "=== /etc/gshadow (if readable) ==="
        cat /etc/gshadow 2>/dev/null || echo "Permission denied or not available"
        echo ""
        echo "=== sudoers ==="
        cat /etc/sudoers 2>/dev/null || echo "N/A"
        echo ""
        echo "=== /etc/sudoers.d/ ==="
        ls -la /etc/sudoers.d/ 2>/dev/null || echo "N/A"
        for f in /etc/sudoers.d/*; do
            if [[ -f "${f}" ]]; then
                echo "--- ${f} ---"
                cat "${f}" 2>/dev/null || echo "N/A"
                echo ""
            fi
        done
    } > "${auth_file}"

    add_finding "${MODULE_NAME}" "INFO" \
        "User and group files snapshot collected" \
        "passwd, shadow, group, gshadow, and sudoers captured" \
        "output=${auth_file}"
    print_success "User/group files snapshot collected"
}

_snapshot_packages() {
    print_subheader "Snapshotting Installed Packages"

    local pkg_file="${_forensic_output_dir}/installed_packages.txt"
    {
        if command -v dpkg &>/dev/null; then
            echo "=== dpkg Packages ==="
            dpkg -l 2>/dev/null || echo "N/A"
        elif command -v rpm &>/dev/null; then
            echo "=== RPM Packages ==="
            rpm -qa --qf '%{NAME}-%{VERSION}-%{RELEASE}.%{ARCH}\n' 2>/dev/null || echo "N/A"
        elif command -v apk &>/dev/null; then
            echo "=== APK Packages ==="
            apk list --installed 2>/dev/null || echo "N/A"
        else
            echo "No supported package manager found"
        fi
        echo ""
        echo "=== Snap Packages ==="
        snap list 2>/dev/null || echo "N/A"
        echo ""
        echo "=== Flatpak Packages ==="
        flatpak list 2>/dev/null || echo "N/A"
    } > "${pkg_file}"

    add_finding "${MODULE_NAME}" "INFO" \
        "Installed packages snapshot collected" \
        "System package list captured" \
        "output=${pkg_file}"
    print_success "Installed packages snapshot collected"
}

_filesystem_metadata() {
    print_subheader "Filesystem Metadata Snapshot"

    local fs_file="${_forensic_output_dir}/filesystem_metadata.txt"
    {
        echo "=== File Counts by Directory ==="
        for dir in /etc /usr /var /home /tmp /opt; do
            if [[ -d "${dir}" ]]; then
                local count
                count="$(find "${dir}" -type f 2>/dev/null | wc -l || echo "0")"
                echo "${dir}: ${count} files"
            fi
        done
        echo ""
        echo "=== SUID Files ==="
        find / -xdev -type f -perm -4000 2>/dev/null || echo "N/A"
        echo ""
        echo "=== SGID Files ==="
        find / -xdev -type f -perm -2000 2>/dev/null || echo "N/A"
        echo ""
        echo "=== World-Writable Files (first 100) ==="
        find / -xdev -type f -perm -0002 2>/dev/null | head -100 || echo "N/A"
        echo ""
        echo "=== Recently Modified Files (last 24h, first 100) ==="
        find / -xdev -type f -mtime -1 2>/dev/null | head -100 || echo "N/A"
        echo ""
        echo "=== Files with Extended Attributes ==="
        getfacl -R -s /etc /home /usr /var 2>/dev/null | grep "^# file:" | head -50 || echo "N/A"
    } > "${fs_file}"

    add_finding "${MODULE_NAME}" "INFO" \
        "Filesystem metadata snapshot collected" \
        "File counts, SUID, SGID, world-writable, and recent files captured" \
        "output=${fs_file}"
    print_success "Filesystem metadata snapshot collected"
}

run() {
    print_header "Forensic Artifact Collection"

    _init_output_dir
    _collect_system_metadata
    _snapshot_processes
    _snapshot_network_connections
    _snapshot_listening_ports
    _snapshot_routing_table
    _snapshot_cron_jobs
    _snapshot_systemd
    _snapshot_environment
    _snapshot_kernel_modules
    _snapshot_mounts
    _snapshot_dns
    _snapshot_passwd_group
    _snapshot_packages
    _filesystem_metadata

    echo ""
    print_success "Forensic collection complete. Output directory: ${_forensic_output_dir}"
    print_info "Contents:"
    ls -la "${_forensic_output_dir}/" 2>/dev/null || true
}

if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    run
fi
