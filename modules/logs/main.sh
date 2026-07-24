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
readonly MODULE_NAME="logs"
readonly MODULE_DESCRIPTION="Log analysis and anomaly detection"
readonly MODULE_VERSION="1.0.0"
readonly MODULE_SEVERITY_THRESHOLD="info"

readonly -a AUTH_LOG_PATHS=("/var/log/auth.log" "/var/log/secure")
readonly -a SYSLOG_PATHS=("/var/log/syslog" "/var/log/messages")
readonly -A FAILED_LOGIN_PATTERNS=(
    ["sshd"]="Failed password for"
    ["sshd_alt"]="authentication failure"
    ["login"]="FAILED LOGIN"
    ["su"]="su: FAILED"
    ["sudo"]="sudo.*authentication failure"
    ["pam"]="pam_unix.*authentication failure"
)

_auth_log_check() {
    print_subheader "Authentication Log Check"

    local auth_log=""
    for log_path in "${AUTH_LOG_PATHS[@]}"; do
        if [[ -f "${log_path}" ]]; then
            auth_log="${log_path}"
            break
        fi
    done

    if [[ -z "${auth_log}" ]]; then
        add_finding "logs" "Authentication log not found" "medium" \
            "paths=${AUTH_LOG_PATHS[*]}" \
            "Enable logging and ensure auth.log/secure exists."
        print_warning "Authentication log not found"
        return
    fi

    add_finding "logs" "Authentication log found: ${auth_log}" "info" \
        "file=${auth_log}"
    print_success "Authentication log: ${auth_log}"

    local log_size
    log_size=$(stat -c '%s' "${auth_log}" 2>/dev/null || echo "0")
    if [[ "${log_size}" -eq 0 ]]; then
        add_finding "logs" "Authentication log is empty" "medium" \
            "file=${auth_log} size=0" \
            "Check if logging is working properly."
        print_warning "Authentication log is empty"
    else
        local log_lines
        log_lines=$(wc -l < "${auth_log}" 2>/dev/null || echo "0")
        print_success "Authentication log: ${log_lines} lines"
    fi
}

_failed_logins() {
    print_subheader "Failed Login Attempts"

    local auth_log=""
    for log_path in "${AUTH_LOG_PATHS[@]}"; do
        if [[ -f "${log_path}" ]]; then
            auth_log="${log_path}"
            break
        fi
    done

    if [[ -z "${auth_log}" ]]; then
        return
    fi

    local failed_count=0
    local -A failed_users=()
    local -A failed_ips=()

    while IFS= read -r line; do
        [[ -z "${line}" ]] && continue

        failed_count=$((failed_count + 1))

        local user
        user=$(echo "${line}" | grep -oP 'for (?:invalid user )?\K\S+' | tail -1 || echo "unknown")
        failed_users["${user}"]=$(( ${failed_users["${user}"]:-0} + 1 ))

        local ip
        ip=$(echo "${line}" | grep -oP 'from \K[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+' || echo "unknown")
        if [[ "${ip}" != "unknown" ]]; then
            failed_ips["${ip}"]=$(( ${failed_ips["${ip}"]:-0} + 1 ))
        fi
    done < <(grep -i "failed password\|authentication failure" "${auth_log}" 2>/dev/null | tail -1000)

    if [[ "${failed_count}" -gt 0 ]]; then
        local severity="info"
        if [[ "${failed_count}" -gt 100 ]]; then
            severity="high"
        elif [[ "${failed_count}" -gt 20 ]]; then
            severity="medium"
        fi

        add_finding "logs" "Failed login attempts: ${failed_count}" "${severity}" \
            "failed_count=${failed_count} log=${auth_log}" \
            "Investigate failed attempts and consider fail2ban."
        print_finding "${severity}" "Failed login attempts: ${failed_count}"

        if [[ "${#failed_ips[@]}" -gt 0 ]]; then
            print_subheader "Top Failed IPs"
            local -a sorted_ips
            sorted_ips=$(for ip in "${!failed_ips[@]}"; do
                echo "${failed_ips[${ip}]} ${ip}"
            done | sort -rn | head -5)

            while IFS= read -r entry; do
                [[ -z "${entry}" ]] && continue
                local count ip_addr
                count=$(echo "${entry}" | awk '{print $1}')
                ip_addr=$(echo "${entry}" | awk '{print $2}')
                print_finding "info" "  ${ip_addr}: ${count} failures"
            done <<< "${sorted_ips}"
        fi

        if [[ "${#failed_users[@]}" -gt 0 ]]; then
            print_subheader "Top Failed Users"
            local -a sorted_users
            sorted_users=$(for user in "${!failed_users[@]}"; do
                echo "${failed_users[${user}]} ${user}"
            done | sort -rn | head -5)

            while IFS= read -r entry; do
                [[ -z "${entry}" ]] && continue
                local count username
                count=$(echo "${entry}" | awk '{print $1}')
                username=$(echo "${entry}" | awk '{print $2}')
                print_finding "info" "  ${username}: ${count} failures"
            done <<< "${sorted_users}"
        fi
    else
        add_finding "logs" "No failed login attempts found" "info" \
            "failed_count=0"
        print_success "No failed login attempts found"
    fi
}

_brute_force_success() {
    print_subheader "Brute Force Success Detection"

    local auth_log=""
    for log_path in "${AUTH_LOG_PATHS[@]}"; do
        if [[ -f "${log_path}" ]]; then
            auth_log="${log_path}"
            break
        fi
    done

    if [[ -z "${auth_log}" ]]; then
        return
    fi

    local suspicious_count=0

    while IFS= read -r line; do
        [[ -z "${line}" ]] && continue
        suspicious_count=$((suspicious_count + 1))
        print_finding "info" "  ${line}"
    done < <(
        {
            grep -B5 "Accepted password" "${auth_log}" 2>/dev/null | grep -B1 "Failed password" | tail -10 || true
            grep -B5 "Accepted publickey" "${auth_log}" 2>/dev/null | grep -B1 "Failed password" | tail -10 || true
        }
    )

    if [[ "${suspicious_count}" -gt 0 ]]; then
        add_finding "logs" "Possible brute force success: ${suspicious_count} events" "high" \
            "suspicious_logins=count:${suspicious_count}" \
            "Investigate these login events for compromise."
        print_error "Possible brute force success: ${suspicious_count} events"
    else
        add_finding "logs" "No suspicious login patterns detected" "info" \
            "brute_force_success=count:0"
        print_success "No suspicious login patterns detected"
    fi
}

_new_user_creation() {
    print_subheader "New User Creation Events"

    local auth_log=""
    for log_path in "${AUTH_LOG_PATHS[@]}"; do
        if [[ -f "${log_path}" ]]; then
            auth_log="${log_path}"
            break
        fi
    done

    if [[ -z "${auth_log}" ]]; then
        return
    fi

    local user_creations
    user_creations=$(grep -i "new user\|useradd\|adduser" "${auth_log}" 2>/dev/null | tail -20 || true)

    if [[ -n "${user_creations}" ]]; then
        local count
        count=$(echo "${user_creations}" | grep -c . || echo "0")
        add_finding "logs" "User creation events: ${count}" "info" \
            "user_creations=count:${count}" \
            "Review new user accounts."
        print_warning "User creation events: ${count}"

        while IFS= read -r line; do
            [[ -z "${line}" ]] && continue
            print_finding "info" "  ${line}"
        done <<< "${user_creations}"
    else
        add_finding "logs" "No user creation events found" "info" \
            "user_creations=count:0"
        print_success "No user creation events found"
    fi
}

_privilege_escalation() {
    print_subheader "Privilege Escalation Attempts"

    local auth_log=""
    for log_path in "${AUTH_LOG_PATHS[@]}"; do
        if [[ -f "${log_path}" ]]; then
            auth_log="${log_path}"
            break
        fi
    done

    if [[ -z "${auth_log}" ]]; then
        return
    fi

    local sudo_failures=0
    local su_attempts=0

    sudo_failures=$(grep -c "sudo.*authentication failure\|sudo.*not allowed\|sudo.*command not allowed" "${auth_log}" 2>/dev/null || echo "0")
    su_attempts=$(grep -c "su:.*FAILED\|su:.*authentication failure" "${auth_log}" 2>/dev/null || echo "0")

    if [[ "${sudo_failures}" -gt 0 ]]; then
        add_finding "logs" "Sudo authentication failures: ${sudo_failures}" "medium" \
            "sudo_failures=count:${sudo_failures}" \
            "Review sudo access and audit sudoers configuration."
        print_warning "Sudo authentication failures: ${sudo_failures}"

        grep -i "sudo.*authentication failure\|sudo.*not allowed" "${auth_log}" 2>/dev/null | tail -5 | while IFS= read -r line; do
            [[ -z "${line}" ]] && continue
            print_finding "info" "  ${line}"
        done
    fi

    if [[ "${su_attempts}" -gt 0 ]]; then
        add_finding "logs" "SU authentication failures: ${su_attempts}" "medium" \
            "su_failures=count:${su_attempts}" \
            "Review su access."
        print_warning "SU authentication failures: ${su_attempts}"

        grep -i "su:.*FAILED\|su:.*authentication failure" "${auth_log}" 2>/dev/null | tail -5 | while IFS= read -r line; do
            [[ -z "${line}" ]] && continue
            print_finding "info" "  ${line}"
        done
    fi

    if [[ "${sudo_failures}" -eq 0 && "${su_attempts}" -eq 0 ]]; then
        add_finding "logs" "No privilege escalation failures detected" "info" \
            "privilege_escalation=count:0"
        print_success "No privilege escalation failures detected"
    fi
}

_ssh_events() {
    print_subheader "SSH Connection Events"

    local auth_log=""
    for log_path in "${AUTH_LOG_PATHS[@]}"; do
        if [[ -f "${log_path}" ]]; then
            auth_log="${log_path}"
            break
        fi
    done

    if [[ -z "${auth_log}" ]]; then
        return
    fi

    local accepted=0
    local closed=0
    local invalid=0

    accepted=$(grep -c "Accepted" "${auth_log}" 2>/dev/null || echo "0")
    closed=$(grep -c "Connection closed\|Disconnected from" "${auth_log}" 2>/dev/null || echo "0")
    invalid=$(grep -c "Invalid user" "${auth_log}" 2>/dev/null || echo "0")

    add_finding "logs" "SSH events - Accepted: ${accepted}, Closed: ${closed}, Invalid: ${invalid}" "info" \
        "ssh_accepted=${accepted} ssh_closed=${closed} ssh_invalid=${invalid}"
    print_success "SSH events - Accepted: ${accepted}, Closed: ${closed}, Invalid: ${invalid}"

    if [[ "${invalid}" -gt 0 ]]; then
        local severity="info"
        if [[ "${invalid}" -gt 50 ]]; then
            severity="medium"
        fi
        add_finding "logs" "SSH invalid user attempts: ${invalid}" "${severity}" \
            "invalid_users=count:${invalid}" \
            "Consider disabling SSH for invalid users or using AllowUsers."
    fi
}

_cron_events() {
    print_subheader "Cron Execution Events"

    local syslog_path=""
    for log_path in "${SYSLOG_PATHS[@]}"; do
        if [[ -f "${log_path}" ]]; then
            syslog_path="${log_path}"
            break
        fi
    done

    if [[ -z "${syslog_path}" ]]; then
        if [[ -f /var/log/cron ]]; then
            syslog_path="/var/log/cron"
        elif [[ -f /var/log/cron.log ]]; then
            syslog_path="/var/log/cron.log"
        fi
    fi

    if [[ -z "${syslog_path}" ]]; then
        print_success "No syslog/cron log found for cron analysis"
        return
    fi

    local cron_count
    cron_count=$(grep -c "CRON\|cron" "${syslog_path}" 2>/dev/null || echo "0")

    if [[ "${cron_count}" -gt 0 ]]; then
        add_finding "logs" "Cron events: ${cron_count}" "info" \
            "cron_events=count:${cron_count}"
        print_success "Cron events: ${cron_count}"
    else
        print_success "No cron events found"
    fi
}

_log_tampering() {
    print_subheader "Log Tampering Detection"

    local tampering_found=false

    local log_dirs=("/var/log" "/var/log/journal")
    for log_dir in "${log_dirs[@]}"; do
        [[ -d "${log_dir}" ]] || continue

        local empty_logs
        empty_logs=$(find "${log_dir}" -maxdepth 2 -name "*.log" -empty 2>/dev/null || true)

        if [[ -n "${empty_logs}" ]]; then
            while IFS= read -r log_file; do
                [[ -z "${log_file}" ]] && continue
                local file_age
                file_age=$(stat -c '%Y' "${log_file}" 2>/dev/null || echo "0")
                local now
                now=$(date +%s)
                local age_hours=$(( (now - file_age) / 3600 ))

                if [[ "${age_hours}" -lt 24 ]]; then
                    tampering_found=true
                    add_finding "logs" "Recently emptied log file: ${log_file}" "high" \
                        "file=${log_file} age_hours=${age_hours}" \
                        "Investigate why this log file was emptied."
                    print_error "Recently emptied log: ${log_file}"
                fi
            done <<< "${empty_logs}"
        fi
    done

    local journal_size
    if command -v journalctl &>/dev/null; then
        journal_size=$(journalctl --disk-usage 2>/dev/null | grep -oP '[\d.]+[GMKB]+' || echo "unknown")

        if [[ "${journal_size}" == "0" || "${journal_size}" == "0B" ]]; then
            tampering_found=true
            add_finding "logs" "Journal log storage appears empty" "medium" \
                "journal_size=${journal_size}" \
                "Check if journald is configured properly."
            print_warning "Journal log storage appears empty"
        fi
    fi

    local last_logins
    last_logins=$(last -n 10 2>/dev/null | tail -n +2 || true)

    if [[ -n "${last_logins}" ]]; then
        local login_count
        login_count=$(echo "${last_logins}" | grep -c . || echo "0")
        add_finding "logs" "Last logins recorded: ${login_count}" "info" \
            "last_logins=count:${login_count}"
        print_success "Last logins recorded: ${login_count}"
    fi

    if [[ "${tampering_found}" == false ]]; then
        add_finding "logs" "No obvious log tampering detected" "info" \
            "log_tampering=not_detected"
        print_success "No obvious log tampering detected"
    fi
}

_syslog_security() {
    print_subheader "Syslog Security Events"

    local syslog_path=""
    for log_path in "${SYSLOG_PATHS[@]}"; do
        if [[ -f "${log_path}" ]]; then
            syslog_path="${log_path}"
            break
        fi
    done

    if [[ -z "${syslog_path}" ]]; then
        print_success "No syslog found for security event analysis"
        return
    fi

    local -A security_patterns=(
        ["kernel_panic"]="kernel panic\|BUG:\|Oops:"
        ["segfault"]="segfault at\|general protection fault"
        ["oom"]="Out of memory\|oom-kill"
        ["apparmor_denied"]="apparmor.*DENIED"
        ["selinux_denied"]="SELinux.*denied"
    )

    for event_type in "${!security_patterns[@]}"; do
        local pattern="${security_patterns[${event_type}]}"
        local count
        count=$(grep -ciE "${pattern}" "${syslog_path}" 2>/dev/null || echo "0")

        if [[ "${count}" -gt 0 ]]; then
            local severity="medium"
            if [[ "${event_type}" == "kernel_panic" || "${event_type}" == "oom" ]]; then
                severity="high"
            fi

            add_finding "logs" "${event_type}: ${count} events" "${severity}" \
                "event=${event_type} count=${count}" \
                "Investigate ${event_type} events for system stability."
            print_finding "${severity}" "${event_type}: ${count} events"

            grep -iE "${pattern}" "${syslog_path}" 2>/dev/null | tail -3 | while IFS= read -r line; do
                [[ -z "${line}" ]] && continue
                print_finding "info" "  ${line}"
            done
        fi
    done
}

_journalctl_critical() {
    print_subheader "Journal Critical Errors"

    if ! command -v journalctl &>/dev/null; then
        print_success "journalctl not available"
        return
    fi

    local critical_count
    critical_count=$(journalctl -p err..emerg --since "24 hours ago" --no-pager 2>/dev/null | grep -c . || echo "0")

    if [[ "${critical_count}" -gt 0 ]]; then
        local severity="info"
        if [[ "${critical_count}" -gt 50 ]]; then
            severity="medium"
        fi

        add_finding "logs" "Journal critical/emergency errors (24h): ${critical_count}" "${severity}" \
            "critical_errors=count:${critical_count}" \
            "Investigate critical journal errors."
        print_finding "${severity}" "Critical/emergency errors (24h): ${critical_count}"

        journalctl -p err..emerg --since "24 hours ago" --no-pager 2>/dev/null | tail -5 | while IFS= read -r line; do
            [[ -z "${line}" ]] && continue
            print_finding "info" "  ${line}"
        done
    else
        add_finding "logs" "No critical/emergency journal errors (24h)" "info" \
            "critical_errors=count:0"
        print_success "No critical/emergency journal errors (24h)"
    fi
}

_pam_failures() {
    print_subheader "PAM Authentication Failures"

    local auth_log=""
    for log_path in "${AUTH_LOG_PATHS[@]}"; do
        if [[ -f "${log_path}" ]]; then
            auth_log="${log_path}"
            break
        fi
    done

    if [[ -z "${auth_log}" ]]; then
        return
    fi

    local pam_failures=0
    pam_failures=$(grep -c "pam_unix.*authentication failure\|pam_.*autherror\|pam_.*authfail" "${auth_log}" 2>/dev/null || echo "0")

    if [[ "${pam_failures}" -gt 0 ]]; then
        local severity="info"
        if [[ "${pam_failures}" -gt 100 ]]; then
            severity="high"
        elif [[ "${pam_failures}" -gt 20 ]]; then
            severity="medium"
        fi

        add_finding "logs" "PAM authentication failures: ${pam_failures}" "${severity}" \
            "pam_failures=count:${pam_failures}" \
            "Review PAM configuration and authentication attempts."
        print_finding "${severity}" "PAM authentication failures: ${pam_failures}"
    else
        add_finding "logs" "No PAM authentication failures" "info" \
            "pam_failures=count:0"
        print_success "No PAM authentication failures"
    fi
}

_unusual_hours_logins() {
    print_subheader "Unusual Hours Logins"

    local auth_log=""
    for log_path in "${AUTH_LOG_PATHS[@]}"; do
        if [[ -f "${log_path}" ]]; then
            auth_log="${log_path}"
            break
        fi
    done

    if [[ -z "${auth_log}" ]]; then
        return
    fi

    local unusual_count=0

    while IFS= read -r line; do
        [[ -z "${line}" ]] && continue

        local hour
        hour=$(echo "${line}" | grep -oP '\d{2}:\d{2}:\d{2}' | head -1 | cut -d: -f1 || echo "")

        if [[ -n "${hour}" ]]; then
            if [[ "${hour}" -ge 0 && "${hour}" -lt 6 ]]; then
                unusual_count=$((unusual_count + 1))
                if [[ "${unusual_count}" -le 10 ]]; then
                    print_finding "info" "  Unusual login hour: ${line}"
                fi
            fi
        fi
    done < <(grep "Accepted\|session opened" "${auth_log}" 2>/dev/null | tail -1000)

    if [[ "${unusual_count}" -gt 0 ]]; then
        local severity="info"
        if [[ "${unusual_count}" -gt 20 ]]; then
            severity="medium"
        fi

        add_finding "logs" "Logins at unusual hours (00:00-06:00): ${unusual_count}" "${severity}" \
            "unusual_logins=count:${unusual_count}" \
            "Review late-night logins for suspicious activity."
        print_finding "${severity}" "Logins at unusual hours: ${unusual_count}"
    else
        add_finding "logs" "No unusual hours logins detected" "info" \
            "unusual_logins=count:0"
        print_success "No unusual hours logins detected"
    fi
}

_log_truncation_check() {
    print_subheader "Log File Truncation Check"

    local truncation_found=false

    if [[ -f /var/log/syslog ]]; then
        local syslog_size
        syslog_size=$(stat -c '%s' /var/log/syslog 2>/dev/null || echo "0")

        if [[ "${syslog_size}" -lt 100 && "${syslog_size}" -gt 0 ]]; then
            truncation_found=true
            add_finding "logs" "syslog appears truncated: ${syslog_size} bytes" "high" \
                "file=/var/log/syslog size=${syslog_size}" \
                "Investigate potential log tampering."
            print_error "syslog appears truncated: ${syslog_size} bytes"
        fi
    fi

    if [[ -f /var/log/messages ]]; then
        local messages_size
        messages_size=$(stat -c '%s' /var/log/messages 2>/dev/null || echo "0")

        if [[ "${messages_size}" -lt 100 && "${messages_size}" -gt 0 ]]; then
            truncation_found=true
            add_finding "logs" "messages appears truncated: ${messages_size} bytes" "high" \
                "file=/var/log/messages size=${messages_size}" \
                "Investigate potential log tampering."
            print_error "messages appears truncated: ${messages_size} bytes"
        fi
    fi

    local auth_log=""
    for log_path in "${AUTH_LOG_PATHS[@]}"; do
        if [[ -f "${log_path}" ]]; then
            local log_size
            log_size=$(stat -c '%s' "${log_path}" 2>/dev/null || echo "0")

            if [[ "${log_size}" -lt 100 && "${log_size}" -gt 0 ]]; then
                truncation_found=true
                add_finding "logs" "Authentication log appears truncated: ${log_path} (${log_size} bytes)" "high" \
                    "file=${log_path} size=${log_size}" \
                    "Investigate potential log tampering."
                print_error "Authentication log truncated: ${log_path}"
            fi
        fi
    done

    if [[ "${truncation_found}" == false ]]; then
        add_finding "logs" "No log truncation detected" "info" \
            "log_truncation=not_detected"
        print_success "No log truncation detected"
    fi
}

run() {
    print_header "Log Analysis & Anomaly Detection"

    _auth_log_check
    _failed_logins
    _brute_force_success
    _new_user_creation
    _privilege_escalation
    _ssh_events
    _cron_events
    _log_tampering
    _syslog_security
    _journalctl_critical
    _pam_failures
    _unusual_hours_logins
    _log_truncation_check
}

if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    run
fi