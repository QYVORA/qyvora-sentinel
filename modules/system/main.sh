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

readonly MODULE_NAME="system"
readonly MODULE_DESCRIPTION="System information and configuration audit"
readonly MODULE_VERSION="1.0.0"
readonly MODULE_SEVERITY_THRESHOLD="info"

_os_info() {
    local os_name="unknown"
    local os_version="unknown"
    local os_id="unknown"

    if [[ -f /etc/os-release ]]; then
        os_name=$(awk -F= '/^PRETTY_NAME=/{gsub(/"/, "", $2); print $2}' /etc/os-release)
        os_id=$(awk -F= '/^ID=/{gsub(/"/, "", $2); print $2}' /etc/os-release)
        os_version=$(awk -F= '/^VERSION_ID=/{gsub(/"/, "", $2); print $2}' /etc/os-release)
    fi

    add_finding "OS" "Operating System: ${os_name}" "info" \
        "id=${os_id} version=${os_version}"
    print_success "Detected OS: ${os_name} (${os_id} ${os_version})"
}

_kernel_info() {
    local kernel_version
    kernel_version=$(uname -r 2>/dev/null || echo "unknown")
    local kernel_arch
    kernel_arch=$(uname -m 2>/dev/null || echo "unknown")
    local kernel_release
    kernel_release=$(uname -r 2>/dev/null || echo "unknown")

    add_finding "kernel" "Kernel version: ${kernel_release}, arch: ${kernel_arch}" "info" \
        "version=${kernel_version} architecture=${kernel_arch}"
    print_success "Kernel: ${kernel_release} (${kernel_arch})"
}

_hostname_info() {
    local hostname_val
    hostname_val=$(hostname -f 2>/dev/null || hostname 2>/dev/null || echo "unknown")
    local domain_val
    domain_val=$(domainname 2>/dev/null || echo "none")

    add_finding "hostname" "Hostname: ${hostname_val}, domain: ${domain_val}" "info" \
        "hostname=${hostname_val} domain=${domain_val}"
    print_success "Hostname: ${hostname_val}, domain: ${domain_val}"
}

_uptime_info() {
    local uptime_output
    uptime_output=$(uptime -p 2>/dev/null || uptime 2>/dev/null || echo "unknown")

    add_finding "uptime" "System uptime: ${uptime_output}" "info" "uptime=${uptime_output}"
    print_success "Uptime: ${uptime_output}"
}

_boot_mode() {
    if [[ -d /sys/firmware/efi ]]; then
        add_finding "boot_mode" "Boot mode: UEFI" "info" "mode=UEFI"
        print_success "Boot mode: UEFI"
    else
        add_finding "boot_mode" "Boot mode: BIOS/Legacy" "info" "mode=BIOS"
        print_success "Boot mode: BIOS/Legacy"
    fi
}

_selinux_status() {
    local selinux_status="not_installed"

    if command -v getenforce &>/dev/null; then
        selinux_status=$(getenforce 2>/dev/null || echo "unknown")
    elif [[ -f /etc/selinux/config ]]; then
        selinux_status=$(awk -F= '/^SELINUX=/{print $2}' /etc/selinux/config 2>/dev/null || echo "unknown")
    fi

    case "${selinux_status}" in
        Enforcing)
            add_finding "selinux" "SELinux is enforcing" "info" "status=Enforcing"
            print_success "SELinux status: Enforcing"
            ;;
        Permissive)
            add_finding "selinux" "SELinux is permissive" "medium" "status=Permissive"
            print_warning "SELinux status: Permissive"
            ;;
        Disabled)
            add_finding "selinux" "SELinux is disabled" "medium" "status=Disabled"
            print_warning "SELinux status: Disabled"
            ;;
        not_installed)
            add_finding "selinux" "SELinux not installed" "info" "status=not_installed"
            print_success "SELinux not installed"
            ;;
        *)
            add_finding "selinux" "SELinux status: ${selinux_status}" "low" "status=${selinux_status}"
            print_warning "SELinux status: ${selinux_status}"
            ;;
    esac
}

_apparmor_status() {
    local aa_status="not_detected"

    if command -v aa-status &>/dev/null; then
        if aa-status --enabled &>/dev/null 2>&1; then
            local profiles_enforced profiles_complain
            profiles_enforced=$(aa-status 2>/dev/null | awk '/profiles are in enforce mode/{print $1}' || echo "0")
            profiles_complain=$(aa-status 2>/dev/null | awk '/profiles are in complain mode/{print $1}' || echo "0")
            aa_status="active"
            add_finding "apparmor" "AppArmor active: ${profiles_enforced} enforced, ${profiles_complain} complain" "info" \
                "status=active enforced=${profiles_enforced} complain=${profiles_complain}"
            print_success "AppArmor: active (${profiles_enforced} enforced, ${profiles_complain} complain)"
        else
            aa_status="installed_disabled"
            add_finding "apparmor" "AppArmor installed but disabled" "medium" "status=installed_disabled"
            print_warning "AppArmor: installed but disabled"
        fi
    elif [[ -d /sys/module/apparmor ]]; then
        aa_status="kernel_module_loaded"
        add_finding "apparmor" "AppArmor kernel module loaded (aa-status unavailable)" "info" \
            "status=kernel_module_loaded"
        print_success "AppArmor kernel module loaded"
    else
        add_finding "apparmor" "AppArmor not detected" "info" "status=not_detected"
        print_success "AppArmor: not detected"
    fi
}

_installed_shells() {
    if [[ -f /etc/shells ]]; then
        local shell_list
        shell_list=$(grep -v '^\s*#' /etc/shells 2>/dev/null | grep -v '^\s*$' || true)
        local shell_count
        shell_count=$(echo "${shell_list}" | grep -c . || echo "0")
        add_finding "shells" "Installed shells: ${shell_count} entries in /etc/shells" "info" \
            "count=${shell_count}"
        print_success "Installed shells: ${shell_count} entries in /etc/shells"
    else
        add_finding "shells" "/etc/shells not found" "low" "file=/etc/shells"
        print_warning "/etc/shells not found"
    fi
}

_aslr_check() {
    local aslr_value="unknown"

    if [[ -f /proc/sys/kernel/randomize_va_space ]]; then
        aslr_value=$(cat /proc/sys/kernel/randomize_va_space 2>/dev/null || echo "unknown")
    fi

    case "${aslr_value}" in
        0)
            add_finding "aslr" "ASLR is disabled (randomize_va_space=0)" "high" \
                "value=0 remediation=Enable ASLR: sysctl -w kernel.randomize_va_space=2"
            print_error "ASLR is DISABLED (randomize_va_space=0) - HIGH RISK"
            ;;
        1)
            add_finding "aslr" "ASLR is partial (randomize_va_space=1)" "medium" \
                "value=1 remediation=Enable full ASLR: sysctl -w kernel.randomize_va_space=2"
            print_warning "ASLR is partial (randomize_va_space=1)"
            ;;
        2)
            add_finding "aslr" "ASLR is fully enabled (randomize_va_space=2)" "info" \
                "value=2"
            print_success "ASLR is fully enabled (randomize_va_space=2)"
            ;;
        *)
            add_finding "aslr" "Cannot determine ASLR status" "low" "value=${aslr_value}"
            print_warning "Cannot determine ASLR status: ${aslr_value}"
            ;;
    esac
}

_core_dump_check() {
    local core_pattern="unknown"
    local ulimit_output="unknown"

    if [[ -f /proc/sys/kernel/core_pattern ]]; then
        core_pattern=$(cat /proc/sys/kernel/core_pattern 2>/dev/null || echo "unknown")
    fi

    ulimit_output=$(ulimit -c 2>/dev/null || echo "unknown")

    if [[ "${ulimit_output}" == "0" ]]; then
        add_finding "coredump" "Core dumps are disabled via ulimit" "info" \
            "ulimit_c=${ulimit_output} core_pattern=${core_pattern}"
        print_success "Core dumps disabled (ulimit -c 0)"
    else
        local severity="medium"
        local message="Core dumps enabled (ulimit -c ${ulimit_output}, pattern: ${core_pattern})"
        if [[ "${core_pattern}" == "core" ]] || [[ "${core_pattern}" == "*/core" ]]; then
            severity="low"
            message="${message} - core dumps written to current directory"
        fi
        add_finding "coredump" "${message}" "${severity}" \
            "ulimit_c=${ulimit_output} core_pattern=${core_pattern}"
        print_warning "${message}"
    fi
}

_ntp_check() {
    local ntp_active=false
    local chrony_active=false

    if command -v systemctl &>/dev/null; then
        if systemctl is-active --quiet chronyd 2>/dev/null; then
            chrony_active=true
        elif systemctl is-active --quiet chrony 2>/dev/null; then
            chrony_active=true
        elif systemctl is-active --quiet ntpd 2>/dev/null; then
            ntp_active=true
        elif systemctl is-active --quiet ntp 2>/dev/null; then
            ntp_active=true
        elif systemctl is-active --quiet systemd-timesyncd 2>/dev/null; then
            add_finding "ntp" "Time sync active: systemd-timesyncd" "info" "service=systemd-timesyncd"
            print_success "Time sync: systemd-timesyncd is active"
            return
        fi
    fi

    if [[ "${chrony_active}" == true ]]; then
        add_finding "ntp" "Time sync active: chrony" "info" "service=chrony"
        print_success "Time sync: chrony is active"
    elif [[ "${ntp_active}" == true ]]; then
        add_finding "ntp" "Time sync active: ntpd" "info" "service=ntpd"
        print_success "Time sync: ntpd is active"
    else
        add_finding "ntp" "No active time synchronization service detected" "medium" \
            "remediation=Install and configure chrony or ntpd"
        print_warning "No active time sync service detected"
    fi
}

_timezone_check() {
    local timezone="unknown"

    if [[ -L /etc/localtime ]]; then
        timezone=$(readlink -f /etc/localtime 2>/dev/null || echo "unknown")
    elif [[ -f /etc/timezone ]]; then
        timezone=$(cat /etc/timezone 2>/dev/null || echo "unknown")
    else
        timezone=$(timedatectl show --property=Timezone 2>/dev/null | awk -F= '{print $2}' || echo "unknown")
    fi

    add_finding "timezone" "System timezone: ${timezone}" "info" "timezone=${timezone}"
    print_success "Timezone: ${timezone}"
}

run() {
    print_header "System Information & Configuration Audit"

    _os_info
    _kernel_info
    _hostname_info
    _uptime_info
    _boot_mode
    _selinux_status
    _apparmor_status
    _installed_shells
    _aslr_check
    _core_dump_check
    _ntp_check
    _timezone_check
}

if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    run
fi
