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

readonly MODULE_NAME="timeline"
readonly MODULE_DESCRIPTION="System timeline and event analysis"
readonly MODULE_VERSION="1.0.0"
readonly MODULE_SEVERITY_THRESHOLD="info"

_timeline_output_dir=""

_init_timeline_dir() {
    local timestamp
    timestamp="$(date -u '+%Y%m%d_%H%M%S')"
    _timeline_output_dir="$(pwd)/reports/timeline_${timestamp}"

    if [[ ! -d "${_timeline_output_dir}" ]]; then
        mkdir -p "${_timeline_output_dir}"
    fi

    print_info "Timeline artifacts will be saved to: ${_timeline_output_dir}"
}

_recent_logins() {
    print_subheader "Recent Logins"

    local login_file="${_timeline_output_dir}/recent_logins.txt"
    {
        echo "=== Last Logins (last) ==="
        last -25 2>/dev/null || echo "N/A"
        echo ""
        echo "=== Failed Login Attempts (lastb) ==="
        lastb -25 2>/dev/null || echo "N/A or requires root"
        echo ""
        echo "=== Currently Logged In ==="
        w 2>/dev/null || who 2>/dev/null || echo "N/A"
    } > "${login_file}"

    local failed_count=0
    if command -v lastb &>/dev/null; then
        failed_count="$(lastb 2>/dev/null | grep -c "pts\|tty" || echo "0")"
    fi

    if [[ "${failed_count}" -gt 50 ]]; then
        add_finding "${MODULE_NAME}" "HIGH" \
            "High number of failed login attempts" \
            "${failed_count} failed login attempts recorded" \
            "failed_logins=${failed_count}" \
            "Investigate brute force attempts; consider fail2ban"
        print_error "Failed logins: ${failed_count}"
    elif [[ "${failed_count}" -gt 10 ]]; then
        add_finding "${MODULE_NAME}" "MEDIUM" \
            "Elevated failed login attempts" \
            "${failed_count} failed login attempts recorded" \
            "failed_logins=${failed_count}" \
            "Monitor for brute force activity"
        print_warning "Failed logins: ${failed_count}"
    else
        print_success "Failed login attempts: ${failed_count}"
    fi
}

_auth_log_analysis() {
    print_subheader "Authentication Log Analysis"

    local auth_file="${_timeline_output_dir}/auth_analysis.txt"
    {
        echo "=== /var/log/auth.log (last 100 lines) ==="
        tail -100 /var/log/auth.log 2>/dev/null || echo "N/A"
        echo ""
        echo "=== /var/log/secure (last 100 lines) ==="
        tail -100 /var/log/secure 2>/dev/null || echo "N/A"
        echo ""
        echo "=== Sudo Usage ==="
        grep "sudo:" /var/log/auth.log 2>/dev/null | tail -50 || echo "N/A"
        echo ""
        echo "=== SSH Session Opens ==="
        grep "sshd.*Accepted\|sshd.*Failed\|sshd.*session opened" /var/log/auth.log 2>/dev/null | tail -50 || echo "N/A"
    } > "${auth_file}"

    add_finding "${MODULE_NAME}" "INFO" \
        "Authentication log analysis collected" \
        "Auth logs and sudo usage captured" \
        "output=${auth_file}"
    print_success "Authentication log analysis collected"
}

_cron_timeline() {
    print_subheader "Cron Job Execution Timeline"

    local cron_file="${_timeline_output_dir}/cron_timeline.txt"
    {
        echo "=== Cron Daemon Logs ==="
        grep -i "cron" /var/log/syslog 2>/dev/null | tail -100 || \
        grep -i "cron" /var/log/cron 2>/dev/null | tail -100 || \
        journalctl -u cron --since "24 hours ago" 2>/dev/null | tail -100 || \
        echo "No cron logs available"
        echo ""
        echo "=== Cron Spool Files ==="
        for spool in /var/spool/cron/crontabs/*; do
            if [[ -f "${spool}" ]]; then
                echo "--- $(basename "${spool}") ---"
                cat "${spool}" 2>/dev/null || echo "N/A"
                echo ""
            fi
        done
    } > "${cron_file}"

    add_finding "${MODULE_NAME}" "INFO" \
        "Cron timeline collected" \
        "Cron daemon logs and spool files captured" \
        "output=${cron_file}"
    print_success "Cron timeline collected"
}

_service_timeline() {
    print_subheader "Systemd Service Timeline"

    local svc_file="${_timeline_output_dir}/service_timeline.txt"
    {
        echo "=== Recently Started Services ==="
        systemctl list-units --type=service --state=running --no-pager 2>/dev/null || echo "N/A"
        echo ""
        echo "=== Failed Services ==="
        systemctl list-units --type=service --state=failed --no-pager 2>/dev/null || echo "N/A"
        echo ""
        echo "=== Service Start Times ==="
        systemctl show --property=ActiveEnterTimestamp --type=service 2>/dev/null | sort -t= -k2 | tail -30 || echo "N/A"
        echo ""
        echo "=== Journal Errors (last 24h) ==="
        journalctl -p err --since "24 hours ago" --no-pager 2>/dev/null | tail -100 || echo "N/A"
    } > "${svc_file}"

    local failed_count
    failed_count="$(systemctl list-units --type=service --state=failed --no-pager 2>/dev/null | grep -c ".service" || echo "0")"

    if [[ "${failed_count}" -gt 0 ]]; then
        add_finding "${MODULE_NAME}" "MEDIUM" \
            "Failed systemd services detected" \
            "${failed_count} service(s) in failed state" \
            "failed_services=${failed_count}" \
            "Investigate failed services: systemctl status <service>"
        print_warning "Failed services: ${failed_count}"
    else
        print_success "No failed systemd services"
    fi
}

_file_modifications() {
    print_subheader "Recent File Modifications"

    local file_mod_file="${_timeline_output_dir}/file_modifications.txt"
    {
        echo "=== Recently Modified System Files (last 24h) ==="
        find /etc -type f -mtime -1 2>/dev/null | head -50 || echo "N/A"
        echo ""
        echo "=== Recently Modified Executables (last 7 days) ==="
        find /usr/bin /usr/sbin /usr/local/bin -type f -mtime -7 2>/dev/null | head -50 || echo "N/A"
        echo ""
        echo "=== Recently Modified Config Files (last 24h) ==="
        find /etc -name "*.conf" -o -name "*.cfg" -o -name "*.ini" 2>/dev/null | xargs ls -lt 2>/dev/null | head -30 || echo "N/A"
    } > "${file_mod_file}"

    add_finding "${MODULE_NAME}" "INFO" \
        "File modification timeline collected" \
        "Recent system and executable modifications captured" \
        "output=${file_mod_file}"
    print_success "File modification timeline collected"
}

_package_timeline() {
    print_subheader "Package Installation Timeline"

    local pkg_file="${_timeline_output_dir}/package_timeline.txt"
    {
        if command -v dpkg &>/dev/null; then
            echo "=== Recent dpkg Activity ==="
            grep " install " /var/log/dpkg.log 2>/dev/null | tail -50 || echo "N/A"
            echo ""
            echo "=== dpkg Log (last 50 lines) ==="
            tail -50 /var/log/dpkg.log 2>/dev/null || echo "N/A"
        fi
        if command -v rpm &>/dev/null; then
            echo "=== Recent RPM Activity ==="
            rpm -qa --last 2>/dev/null | head -50 || echo "N/A"
        fi
        if command -v yum &>/dev/null || command -v dnf &>/dev/null; then
            local pkg_cmd="yum"
            command -v dnf &>/dev/null && pkg_cmd="dnf"
            echo "=== Recent ${pkg_cmd} History ==="
            ${pkg_cmd} history 2>/dev/null | head -20 || echo "N/A"
        fi
    } > "${pkg_file}"

    add_finding "${MODULE_NAME}" "INFO" \
        "Package installation timeline collected" \
        "Recent package manager activity captured" \
        "output=${pkg_file}"
    print_success "Package timeline collected"
}

_network_timeline() {
    print_subheader "Network Connection Timeline"

    local net_file="${_timeline_output_dir}/network_timeline.txt"
    {
        echo "=== Current Connections ==="
        ss -tnpa 2>/dev/null | head -50 || netstat -tnpa 2>/dev/null | head -50 || echo "N/A"
        echo ""
        echo "=== Connection States Summary ==="
        ss -tan 2>/dev/null | awk 'NR>1 {print $1}' | sort | uniq -c | sort -rn || echo "N/A"
        echo ""
        echo "=== Firewall Log (recent) ==="
        dmesg 2>/dev/null | grep -i "DROP\|REJECT\|DROP" | tail -20 || echo "N/A"
    } > "${net_file}"

    add_finding "${MODULE_NAME}" "INFO" \
        "Network connection timeline collected" \
        "Current connections and state summary captured" \
        "output=${net_file}"
    print_success "Network timeline collected"
}

_boot_timeline() {
    print_subheader "Boot and Shutdown Timeline"

    local boot_file="${_timeline_output_dir}/boot_timeline.txt"
    {
        echo "=== System Uptime ==="
        uptime 2>/dev/null || echo "N/A"
        echo ""
        echo "=== Last Boot ==="
        last reboot 2>/dev/null | head -10 || echo "N/A"
        echo ""
        echo "=== Boot Time (dmesg) ==="
        dmesg 2>/dev/null | head -20 || echo "N/A"
        echo ""
        echo "=== Systemd Boot Targets ==="
        systemctl list-dependencies 2>/dev/null | head -30 || echo "N/A"
    } > "${boot_file}"

    add_finding "${MODULE_NAME}" "INFO" \
        "Boot timeline collected" \
        "Boot history and startup information captured" \
        "output=${boot_file}"
    print_success "Boot timeline collected"
}

_kernel_messages() {
    print_subheader "Kernel Messages Timeline"

    local kern_file="${_timeline_output_dir}/kernel_messages.txt"
    {
        echo "=== Kernel Ring Buffer (dmesg) ==="
        dmesg 2>/dev/null | tail -100 || echo "N/A"
        echo ""
        echo "=== Kernel Errors/Warnings ==="
        dmesg 2>/dev/null | grep -iE "error|warn|fail|panic|oops" | tail -50 || echo "N/A"
        echo ""
        echo "=== OOM Killer Events ==="
        dmesg 2>/dev/null | grep -i "oom\|out of memory\|killed process" | tail -20 || echo "N/A"
    } > "${kern_file}"

    local oom_count
    oom_count="$(dmesg 2>/dev/null | grep -ci "oom\|killed process" || echo "0")"

    if [[ "${oom_count}" -gt 0 ]]; then
        add_finding "${MODULE_NAME}" "HIGH" \
            "OOM killer events detected" \
            "${oom_count} out-of-memory events in kernel log" \
            "oom_events=${oom_count}" \
            "Investigate memory pressure; consider adding RAM"
        print_error "OOM events: ${oom_count}"
    else
        print_success "No OOM killer events detected"
    fi
}

run() {
    print_header "Timeline & Event Analysis"

    _init_timeline_dir
    _recent_logins
    _auth_log_analysis
    _cron_timeline
    _service_timeline
    _file_modifications
    _package_timeline
    _network_timeline
    _boot_timeline
    _kernel_messages

    echo ""
    print_success "Timeline collection complete. Output directory: ${_timeline_output_dir}"
    print_info "Contents:"
    ls -la "${_timeline_output_dir}/" 2>/dev/null || true
}

if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    run
fi
