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

readonly MODULE_NAME="kernel"
readonly MODULE_DESCRIPTION="Kernel and module security audit"
readonly MODULE_VERSION="1.0.0"
readonly MODULE_SEVERITY_THRESHOLD="info"

_loaded_modules() {
    print_subheader "Loaded Kernel Modules"

    if [[ ! -f /proc/modules ]]; then
        add_finding "kernel" "Cannot read /proc/modules" "low" \
            "file=/proc/modules" \
            "Ensure /proc is mounted."
        print_warning "Cannot read /proc/modules"
        return
    fi

    local modules
    modules=$(awk '{print $1}' /proc/modules 2>/dev/null || true)

    if [[ -z "${modules}" ]]; then
        add_finding "kernel" "No kernel modules loaded" "info" \
            "modules=count:0"
        print_success "No kernel modules loaded"
        return
    fi

    local count
    count=$(echo "${modules}" | grep -c . || echo "0")
    add_finding "kernel" "Kernel modules loaded: ${count}" "info" \
        "modules=count:${count}"
    print_success "Kernel modules loaded: ${count}"

    local suspicious_modules=("dvb" "firewire-core" "dvb-core" "cdc_ether" "usbnet" "cdc_ncm" "ax88179_178a")
    for sm in "${suspicious_modules[@]}"; do
        if echo "${modules}" | grep -q "^${sm}$"; then
            add_finding "kernel" "Potentially unnecessary module: ${sm}" "low" \
                "module=${sm}" \
                "Consider blacklisting unnecessary modules."
            print_warning "Potentially unnecessary module: ${sm}"
        fi
    done
}

_kernel_version_check() {
    print_subheader "Kernel Version"

    local kernel_version
    kernel_version=$(uname -r 2>/dev/null || echo "unknown")

    local kernel_release
    kernel_release=$(uname -v 2>/dev/null || echo "unknown")

    add_finding "kernel" "Kernel version: ${kernel_version}" "info" \
        "version=${kernel_version} release=${kernel_release}"
    print_success "Kernel version: ${kernel_version}"

    local major minor patch
    if [[ "${kernel_version}" =~ ^([0-9]+)\.([0-9]+)\.([0-9]+) ]]; then
        major="${BASH_REMATCH[1]}"
        minor="${BASH_REMATCH[2]}"
        patch="${BASH_REMATCH[3]}"

        if [[ "${major}" -lt 5 ]]; then
            add_finding "kernel" "Kernel is end-of-life (EOL): ${kernel_version}" "high" \
                "version=${kernel_version}" \
                "Upgrade to a supported kernel version."
            print_error "Kernel is EOL (pre-5.x): ${kernel_version}"
        elif [[ "${major}" -eq 5 && "${minor}" -lt 4 ]]; then
            add_finding "kernel" "Kernel may be approaching EOL: ${kernel_version}" "medium" \
                "version=${kernel_version}" \
                "Consider upgrading to a newer kernel."
            print_warning "Kernel may be approaching EOL: ${kernel_version}"
        fi
    fi
}

_sysctl_security_settings() {
    print_subheader "Sysctl Security Settings"

    local -A sysctl_checks=(
        ["net.ipv4.ip_forward"]="0:HIGH:IP forwarding disabled"
        ["net.ipv4.conf.all.accept_redirects"]="0:MEDIUM:ICMP redirects rejected"
        ["net.ipv4.conf.all.send_redirects"]="0:MEDIUM:ICMP redirects not sent"
        ["net.ipv4.conf.all.accept_source_route"]="0:MEDIUM:Source routing rejected"
        ["net.ipv4.conf.all.log_martians"]="1:INFO:Martian packets logged"
        ["net.ipv4.tcp_syncookies"]="1:INFO:SYN cookies enabled"
        ["net.ipv4.icmp_echo_ignore_broadcasts"]="1:INFO:Broadcast ICMP ignored"
        ["kernel.randomize_va_space"]="2:HIGH:ASLR fully enabled"
        ["kernel.dmesg_restrict"]="1:INFO:dmesg restricted"
        ["fs.suid_dumpable"]="0:MEDIUM:SUID dumps disabled"
        ["fs.protected_hardlinks"]="1:INFO:Hardlink protection enabled"
        ["fs.protected_symlinks"]="1:INFO:Symlink protection enabled"
    )

    local issues=0

    for setting in "${!sysctl_checks[@]}"; do
        local expected severity description
        IFS=':' read -r expected severity description <<< "${sysctl_checks[${setting}]}"

        local value
        if [[ -f "/proc/sys/${setting//\./\/}" ]]; then
            value=$(cat "/proc/sys/${setting//\./\/}" 2>/dev/null || echo "unknown")
        else
            value="not_available"
        fi

        if [[ "${value}" == "unknown" || "${value}" == "not_available" ]]; then
            print_finding "info" "  ${setting}: not available"
            continue
        fi

        if [[ "${value}" == "${expected}" ]]; then
            print_success "${setting} = ${value} (${description})"
        else
            issues=$((issues + 1))
            add_finding "kernel" "${setting} = ${value} (expected ${expected}): ${description}" "${severity}" \
                "setting=${setting} value=${value} expected=${expected}" \
                "Set sysctl -w ${setting}=${expected}"
            if [[ "${severity}" == "HIGH" ]]; then
                print_error "${setting} = ${value} (expected ${expected})"
            else
                print_warning "${setting} = ${value} (expected ${expected})"
            fi
        fi
    done

    if [[ "${issues}" -eq 0 ]]; then
        add_finding "kernel" "All sysctl security settings properly configured" "info" \
            "sysctl_issues=count:0"
    fi
}

_secure_boot() {
    print_subheader "Secure Boot Status"

    if [[ -d /sys/firmware/efi ]]; then
        if [[ -f /sys/firmware/efi/esrt/entries ]]; then
            local secure_boot_status
            if [[ -f /sys/kernel/security/secureboot ]]; then
                secure_boot_status=$(cat /sys/kernel/security/secureboot 2>/dev/null || echo "unknown")
                case "${secure_boot_status}" in
                    1)
                        add_finding "kernel" "Secure Boot: enabled" "info" \
                            "secure_boot=enabled"
                        print_success "Secure Boot: enabled"
                        ;;
                    *)
                        add_finding "kernel" "Secure Boot: not enabled" "medium" \
                            "secure_boot=disabled" \
                            "Enable Secure Boot in UEFI settings."
                        print_warning "Secure Boot: not enabled"
                        ;;
                esac
            else
                add_finding "kernel" "Secure Boot status cannot be determined" "info" \
                    "secure_boot=unknown"
                print_warning "Secure Boot status cannot be determined"
            fi
        fi
    else
        add_finding "kernel" "System not using UEFI (Secure Boot N/A)" "info" \
            "boot_mode=BIOS"
        print_success "System not using UEFI (Secure Boot not applicable)"
    fi
}

_kernel_lockdown() {
    print_subheader "Kernel Lockdown Mode"

    if [[ -f /sys/kernel/security/lockdown ]]; then
        local lockdown
        lockdown=$(cat /sys/kernel/security/lockdown 2>/dev/null || echo "unknown")

        case "${lockdown}" in
            *\[none\]*|*none*)
                add_finding "kernel" "Kernel lockdown: none" "low" \
                    "lockdown=none" \
                    "Consider enabling kernel lockdown for enhanced security."
                print_warning "Kernel lockdown: none"
                ;;
            *\[integrity\]*|*integrity*)
                add_finding "kernel" "Kernel lockdown: integrity" "info" \
                    "lockdown=integrity"
                print_success "Kernel lockdown: integrity"
                ;;
            *\[confidentiality\]*|*confidentiality*)
                add_finding "kernel" "Kernel lockdown: confidentiality" "info" \
                    "lockdown=confidentiality"
                print_success "Kernel lockdown: confidentiality"
                ;;
            *\[debug\]*|*debug*)
                add_finding "kernel" "Kernel lockdown: debug (insecure)" "high" \
                    "lockdown=debug" \
                    "Do not use debug lockdown in production."
                print_error "Kernel lockdown: debug (insecure)"
                ;;
            *)
                add_finding "kernel" "Kernel lockdown: ${lockdown}" "info" \
                    "lockdown=${lockdown}"
                print_finding "info" "  Kernel lockdown: ${lockdown}"
                ;;
        esac
    else
        add_finding "kernel" "Kernel lockdown not supported" "info" \
            "lockdown=not_supported"
        print_finding "info" "  Kernel lockdown: not supported"
    fi
}

_kernel_taint() {
    print_subheader "Kernel Taint Status"

    if [[ -f /proc/sys/kernel/tainted ]]; then
        local taint_value
        taint_value=$(cat /proc/sys/kernel/tainted 2>/dev/null || echo "unknown")

        if [[ "${taint_value}" == "0" ]]; then
            add_finding "kernel" "Kernel is not tainted" "info" \
                "tainted=0"
            print_success "Kernel is not tainted"
        else
            add_finding "kernel" "Kernel is tainted (value: ${taint_value})" "medium" \
                "tainted=${tainted_value}" \
                "Investigate kernel taint causes."
            print_warning "Kernel is tainted (value: ${taint_value})"

            local taint_flags=("G" "P" "D" "O" "W" "S" "M" "B" "C" "F" "L" "I" "J" "T" "X")
            local taint_descriptions=("Proprietary module" "Out-of-tree module" "Unsigned module" "Workaround applied" "SMP kernel running on UP" "Module not compiled for running kernel" "Bug workaround applied" "Staging driver" "User-requested" "Kernel has been live patched" "Auxiliary taint" "Experimental feature" "Default kernel taint" "In-kernel taint" "Xen hypervisor taint")

            for i in "${!taint_flags[@]}"; do
                local flag="${taint_flags[${i}]}"
                local desc="${taint_descriptions[${i}]}"
                if echo "${taint_value}" | grep -q "${flag}"; then
                    print_finding "info" "  Taint flag [${flag}]: ${desc}"
                fi
            done
        fi
    fi
}

_unsigned_modules() {
    print_subheader "Unsigned Module Check"

    if [[ -f /proc/modules ]]; then
        local unsigned_count=0

        while IFS= read -r line; do
            [[ -z "${line}" ]] && continue
            local module_name
            module_name=$(echo "${line}" | awk '{print $1}')

            if [[ -f "/sys/module/${module_name}/taint" ]]; then
                local taint
                taint=$(cat "/sys/module/${module_name}/taint" 2>/dev/null || true)
                if [[ "${taint}" == *"O"* ]]; then
                    unsigned_count=$((unsigned_count + 1))
                    print_finding "info" "  Unsigned/out-of-tree module: ${module_name}"
                fi
            fi
        done < /proc/modules

        if [[ "${unsigned_count}" -gt 0 ]]; then
            add_finding "kernel" "Unsigned/out-of-tree modules: ${unsigned_count}" "medium" \
                "unsigned_modules=count:${unsigned_count}" \
                "Use signed kernel modules when possible."
            print_warning "Unsigned/out-of-tree modules: ${unsigned_count}"
        else
            add_finding "kernel" "All modules are signed/in-tree" "info" \
                "unsigned_modules=count:0"
            print_success "All modules are signed/in-tree"
        fi
    fi
}

_proc_sys_kernel_settings() {
    print_subheader "/proc/sys/kernel Settings"

    local settings=(
        "/proc/sys/kernel/kptr_restrict"
        "/proc/sys/kernel/yama/ptrace_scope"
        "/proc/sys/kernel/unprivileged_bpf_disabled"
        "/proc/sys/kernel/perf_event_paranoid"
    )

    for setting in "${settings[@]}"; do
        if [[ -f "${setting}" ]]; then
            local value
            value=$(cat "${setting}" 2>/dev/null || echo "unknown")
            local setting_name
            setting_name=$(echo "${setting}" | sed 's|/proc/sys/||')

            case "${setting}" in
                */kptr_restrict)
                    if [[ "${value}" == "2" ]]; then
                        print_success "${setting_name} = ${value} (kptr fully restricted)"
                    elif [[ "${value}" == "1" ]]; then
                        print_warning "${setting_name} = ${value} (kptr partially restricted)"
                        add_finding "kernel" "${setting_name} = ${value} (should be 2)" "medium" \
                            "setting=${setting_name} value=${value}" \
                            "Set sysctl -w kernel.kptr_restrict=2"
                    else
                        print_error "${setting_name} = ${value} (kptr not restricted)"
                        add_finding "kernel" "${setting_name} = ${value} (kernel pointers exposed)" "high" \
                            "setting=${setting_name} value=${value}" \
                            "Set sysctl -w kernel.kptr_restrict=2"
                    fi
                    ;;
                */ptrace_scope)
                    if [[ "${value}" == "2" || "${value}" == "3" ]]; then
                        print_success "${setting_name} = ${value} (ptrace restricted)"
                    elif [[ "${value}" == "1" ]]; then
                        print_warning "${setting_name} = ${value} (ptrace parent-only)"
                    else
                        print_error "${setting_name} = ${value} (ptrace unrestricted)"
                        add_finding "kernel" "${setting_name} = ${value} (ptrace unrestricted)" "medium" \
                            "setting=${setting_name} value=${value}" \
                            "Set sysctl -w kernel.yama.ptrace_scope=2"
                    fi
                    ;;
                */unprivileged_bpf_disabled)
                    if [[ "${value}" == "1" || "${value}" == "2" ]]; then
                        print_success "${setting_name} = ${value} (BPF restricted)"
                    else
                        print_warning "${setting_name} = ${value} (BPF may be unrestricted)"
                        add_finding "kernel" "${setting_name} = ${value}" "low" \
                            "setting=${setting_name} value=${value}" \
                            "Set sysctl -w kernel.unprivileged_bpf_disabled=1"
                    fi
                    ;;
                */perf_event_paranoid)
                    if [[ "${value}" -le 2 ]] 2>/dev/null; then
                        print_success "${setting_name} = ${value} (perf restricted)"
                    elif [[ "${value}" -ge 3 ]] 2>/dev/null; then
                        print_success "${setting_name} = ${value} (perf fully restricted)"
                    else
                        print_warning "${setting_name} = ${value}"
                    fi
                    ;;
            esac
        else
            print_finding "info" "  ${setting}: not available"
        fi
    done
}

_run() {
    print_header "Kernel & Module Security Audit"

    _loaded_modules
    _kernel_version_check
    _sysctl_security_settings
    _secure_boot
    _kernel_lockdown
    _kernel_taint
    _unsigned_modules
    _proc_sys_kernel_settings
}

run() {
    _run
}

if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    _run
fi