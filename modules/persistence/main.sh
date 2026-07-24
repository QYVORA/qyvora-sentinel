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

readonly MODULE_NAME="persistence"
readonly MODULE_DESCRIPTION="Persistence mechanism detection"
readonly MODULE_VERSION="1.0.0"
readonly MODULE_SEVERITY_THRESHOLD="info"

_user_cron() {
    print_header "User Cron Jobs"

    local found=false

    while IFS=: read -r username _ _ _ _ homedir shell; do
        [[ -z "${homedir}" ]] || [[ ! -d "${homedir}" ]] && continue

        local cron_output
        cron_output=$(crontab -l -u "${username}" 2>/dev/null || true)

        if [[ -n "${cron_output}" ]]; then
            local cron_lines
            cron_lines=$(echo "${cron_output}" | grep -v '^\s*#' | grep -v '^\s*$' || true)

            if [[ -n "${cron_lines}" ]]; then
                found=true
                local line_count
                line_count=$(echo "${cron_lines}" | wc -l)
                add_finding "user_cron" "User ${username}: ${line_count} cron entries" "info" \
                    "user=${username} entries=${line_count} source=crontab"
                print_success "User ${username}: ${line_count} cron entries"

                while IFS= read -r entry; do
                    [[ -z "${entry}" ]] && continue
                    print_finding "info" "  ${entry}"
                done <<< "${cron_lines}"
            fi
        fi
    done < /etc/passwd

    if [[ "${found}" == false ]]; then
        print_success "No user cron jobs found"
    fi
}

_system_cron() {
    print_header "System Cron Entries"

    local cron_files=()

    if [[ -f /etc/crontab ]]; then
        cron_files+=("/etc/crontab")
    fi

    while IFS= read -r -d '' file; do
        cron_files+=("${file}")
    done < <(find /etc/cron.d/ -maxdepth 1 -type f 2>/dev/null | tr '\n' '\0' || true)

    for period in daily hourly weekly monthly; do
        local cron_dir="/etc/cron.${period}"
        if [[ -d "${cron_dir}" ]]; then
            while IFS= read -r -d '' file; do
                cron_files+=("${file}")
            done < <(find "${cron_dir}" -maxdepth 1 -type f 2>/dev/null | tr '\n' '\0' || true)
        fi
    done

    local total_entries=0

    for cron_file in "${cron_files[@]}"; do
        [[ -f "${cron_file}" ]] || continue

        local entries
        entries=$(awk 'NF && !/^[[:space:]]*#/ && !/^[[:space:]]*$/' "${cron_file}" 2>/dev/null || true)

        if [[ -n "${entries}" ]]; then
            local count
            count=$(echo "${entries}" | grep -c . || echo "0")
            total_entries=$((total_entries + count))

            add_finding "system_cron" "System cron: ${cron_file} (${count} entries)" "info" \
                "file=${cron_file} entries=${count}"
            print_success "System cron: ${cron_file} (${count} entries)"

            while IFS= read -r entry; do
                [[ -z "${entry}" ]] && continue
                print_finding "info" "  ${entry}"
            done <<< "${entries}"
        fi
    done

    if [[ ${total_entries} -eq 0 ]]; then
        print_success "No system cron entries found"
    fi
}

_systemd_timers() {
    print_header "Systemd Timers"

    if command -v systemctl &>/dev/null; then
        local timers
        timers=$(systemctl list-timers --all --no-pager 2>/dev/null || true)

        if [[ -n "${timers}" ]]; then
            local count
            count=$(echo "${timers}" | tail -n +2 | grep -c . || echo "0")

            add_finding "systemd_timers" "Total systemd timers: ${count}" "info" "count=${count}"
            print_success "Systemd timers: ${count}"
        else
            print_success "No systemd timers found"
        fi
    else
        print_success "systemctl not available"
    fi
}

_systemd_services() {
    print_header "Enabled Systemd Services"

    if command -v systemctl &>/dev/null; then
        local services
        services=$(systemctl list-unit-files --type=service --state=enabled --no-pager 2>/dev/null || true)

        if [[ -n "${services}" ]]; then
            local count
            count=$(echo "${services}" | tail -n +2 | grep -c 'enabled' || echo "0")

            add_finding "systemd_services" "Enabled systemd services: ${count}" "info" "count=${count}"
            print_success "Enabled systemd services: ${count}"
        else
            print_success "No systemd services found"
        fi
    else
        print_success "systemctl not available"
    fi
}

_rc_local() {
    print_header "rc.local Persistence"

    local rc_locations=("/etc/rc.local" "/etc/rc.d/rc.local")

    for rc_file in "${rc_locations[@]}"; do
        if [[ -f "${rc_file}" ]]; then
            local content
            content=$(grep -v '^\s*#' "${rc_file}" 2>/dev/null | grep -v '^\s*$' || true)

            if [[ -n "${content}" ]]; then
                add_finding "rc_local" "Custom entries in ${rc_file}" "medium" \
                    "file=${rc_file} remediation=Review and remove unauthorized entries"
                print_warning "Custom entries in ${rc_file}"
            else
                print_success "${rc_file} exists but contains no custom entries"
            fi
        fi
    done
}

_init_d_scripts() {
    print_header "/etc/init.d/ Custom Scripts"

    if [[ -d /etc/init.d/ ]]; then
        local init_scripts
        init_scripts=$(find /etc/init.d/ -maxdepth 1 -type f -executable 2>/dev/null || true)

        if [[ -n "${init_scripts}" ]]; then
            local count=0
            while IFS= read -r script; do
                [[ -z "${script}" ]] && continue
                count=$((count + 1))
                print_finding "info" "  ${script}"
            done <<< "${init_scripts}"

            add_finding "init_d" "Scripts in /etc/init.d/: ${count}" "info" "count=${count}"
            print_success "Custom init scripts: ${count}"
        else
            print_success "No executable scripts in /etc/init.d/"
        fi
    else
        print_success "/etc/init.d/ does not exist"
    fi
}

_shell_startup_files() {
    print_header "Shell Startup File Audit"

    local suspicious_patterns=(
        'curl.*\|.*sh'
        'wget.*\|.*sh'
        'curl.*\|.*bash'
        'wget.*\|.*bash'
        'nc.*-e'
        'ncat.*-e'
        '/dev/tcp/'
        'base64.*-d'
        '\$\(.*\)'
        'eval\s'
        'python.*-c'
        'perl.*-e'
        'ruby.*-e'
        'mkfifo'
        'mknod'
        'nc\s'
        'ncat\s'
        'socat'
        'bash.*-i'
        '/dev/udp/'
        'telnet'
        'rm\s+-rf\s+/'
        'dd\s+if=.*of=/dev/'
    )

    local user_dirs=()
    while IFS=: read -r username _ _ _ _ homedir _; do
        [[ -d "${homedir}" ]] && user_dirs+=("${homedir}")
    done < /etc/passwd

    local startup_files=(
        ".bashrc" ".bash_profile" ".profile" ".zshrc" ".zshenv" ".login" ".cshrc"
    )

    local system_files=(
        "/etc/profile" "/etc/bash.bashrc" "/etc/zsh/zshrc" "/etc/zsh/zshenv"
    )

    while IFS= read -r -d '' file; do
        system_files+=("${file}")
    done < <(find /etc/profile.d/ -maxdepth 1 -type f 2>/dev/null | tr '\n' '\0' || true)

    local found_suspicious=false

    for user_dir in "${user_dirs[@]}"; do
        for sf in "${startup_files[@]}"; do
            local full_path="${user_dir}/${sf}"

            [[ -f "${full_path}" ]] || continue

            while IFS= read -r pattern; do
                [[ -z "${pattern}" ]] && continue

                local matches
                matches=$(grep -nE "${pattern}" "${full_path}" 2>/dev/null || true)

                if [[ -n "${matches}" ]]; then
                    found_suspicious=true
                    while IFS= read -r match_line; do
                        [[ -z "${match_line}" ]] && continue
                        add_finding "shell_startup" "Suspicious pattern in ${full_path}: ${match_line}" "high" \
                            "file=${full_path} pattern=${pattern} remediation=Review and remove if unauthorized"
                        print_error "Suspicious in ${full_path}: ${match_line}"
                    done <<< "${matches}"
                fi
            done <<< "$(printf '%s\n' "${suspicious_patterns[@]}")"
        done
    done

    for sys_file in "${system_files[@]}"; do
        [[ -f "${sys_file}" ]] || continue

        while IFS= read -r pattern; do
            [[ -z "${pattern}" ]] && continue

            local matches
            matches=$(grep -nE "${pattern}" "${sys_file}" 2>/dev/null || true)

            if [[ -n "${matches}" ]]; then
                found_suspicious=true
                while IFS= read -r match_line; do
                    [[ -z "${match_line}" ]] && continue
                    add_finding "shell_startup" "Suspicious pattern in ${sys_file}: ${match_line}" "high" \
                        "file=${sys_file} pattern=${pattern} remediation=Review and remove if unauthorized"
                    print_error "Suspicious in ${sys_file}: ${match_line}"
                done <<< "${matches}"
            fi
        done <<< "$(printf '%s\n' "${suspicious_patterns[@]}")"
    done

    if [[ "${found_suspicious}" == false ]]; then
        print_success "No suspicious patterns found in shell startup files"
    fi
}

_ld_preload() {
    print_header "LD_PRELOAD Persistence"

    if [[ -f /etc/ld.so.preload ]]; then
        local content
        content=$(grep -v '^\s*#' /etc/ld.so.preload 2>/dev/null | grep -v '^\s*$' || true)

        if [[ -n "${content}" ]]; then
            add_finding "ld_preload" "/etc/ld.so.preload has entries: ${content}" "critical" \
                "file=/etc/ld.so.preload entries=${content} remediation=Review and clear /etc/ld.so.preload if unauthorized"
            print_error "/etc/ld.so.preload contains entries: ${content} - CRITICAL"
        else
            print_success "/etc/ld.so.preload exists but is empty"
        fi
    else
        print_success "/etc/ld.so.preload does not exist"
    fi
}

_ld_so_conf() {
    print_header "LD Configuration (/etc/ld.so.conf.d/)"

    if [[ -d /etc/ld.so.conf.d/ ]]; then
        local conf_files
        conf_files=$(find /etc/ld.so.conf.d/ -maxdepth 1 -type f -name '*.conf' 2>/dev/null || true)

        if [[ -n "${conf_files}" ]]; then
            local count=0
            while IFS= read -r conf; do
                [[ -z "${conf}" ]] && continue
                count=$((count + 1))

                local content
                content=$(grep -v '^\s*#' "${conf}" 2>/dev/null | grep -v '^\s*$' || true)

                if [[ -n "${content}" ]]; then
                    print_finding "info" "  ${conf}: ${content}"
                fi
            done <<< "${conf_files}"

            add_finding "ld_conf" "/etc/ld.so.conf.d/ files: ${count}" "info" "count=${count}"
            print_success "LD config files: ${count}"
        else
            print_success "No .conf files in /etc/ld.so.conf.d/"
        fi
    fi
}

_etc_environment() {
    print_header "/etc/environment PATH Check"

    if [[ -f /etc/environment ]]; then
        local content
        content=$(grep -v '^\s*#' /etc/environment 2>/dev/null | grep -v '^\s*$' || true)

        if [[ -n "${content}" ]]; then
            if echo "${content}" | grep -qi 'PATH'; then
                add_finding "etc_env" "PATH manipulation in /etc/environment" "medium" \
                    "file=/etc/environment content=${content} remediation=Review PATH entries"
                print_warning "PATH manipulation in /etc/environment"
            else
                print_success "/etc/environment has entries but no PATH manipulation"
            fi
        else
            print_success "/etc/environment is empty"
        fi
    else
        print_success "/etc/environment does not exist"
    fi
}

_pam_config() {
    print_header "PAM Configuration"

    if [[ -d /etc/pam.d/ ]]; then
        local pam_files
        pam_files=$(find /etc/pam.d/ -maxdepth 1 -type f 2>/dev/null || true)

        local suspicious_modules=("pam_permit.so" "pam_rootok.so")
        local found_suspicious=false

        while IFS= read -r pam_file; do
            [[ -z "${pam_file}" ]] || [[ ! -f "${pam_file}" ]] && continue

            for module in "${suspicious_modules[@]}"; do
                local matches
                matches=$(grep -n "${module}" "${pam_file}" 2>/dev/null | grep -v '^\s*#' || true)

                if [[ -n "${matches}" ]]; then
                    found_suspicious=true
                    while IFS= read -r match_line; do
                        [[ -z "${match_line}" ]] && continue
                        add_finding "pam" "Suspicious PAM module in ${pam_file}: ${match_line}" "high" \
                            "file=${pam_file} module=${module} remediation=Review PAM configuration"
                        print_error "Suspicious PAM module in ${pam_file}: ${match_line}"
                    done <<< "${matches}"
                fi
            done
        done <<< "${pam_files}"

        if [[ "${found_suspicious}" == false ]]; then
            print_success "No suspicious PAM modules found"
        fi
    else
        print_success "/etc/pam.d/ does not exist"
    fi
}

_at_jobs() {
    print_header "AT Jobs"

    if command -v atq &>/dev/null; then
        local at_output
        at_output=$(atq 2>/dev/null || true)

        if [[ -n "${at_output}" ]]; then
            local count
            count=$(echo "${at_output}" | grep -c . || echo "0")
            add_finding "at_jobs" "Pending at jobs: ${count}" "info" \
                "count=${count} jobs=${at_output}"
            print_warning "Pending at jobs: ${count}"
        else
            print_success "No pending at jobs"
        fi
    else
        print_success "atq not available"
    fi
}

run() {
    print_header "Persistence Mechanism Detection"

    _user_cron
    _system_cron
    _systemd_timers
    _systemd_services
    _rc_local
    _init_d_scripts
    _shell_startup_files
    _ld_preload
    _ld_so_conf
    _etc_environment
    _pam_config
    _at_jobs
}

if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    run
fi
