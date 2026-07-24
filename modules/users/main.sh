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

readonly MODULE_NAME="users"
readonly MODULE_DESCRIPTION="User account and privilege audit"
readonly MODULE_VERSION="1.0.0"
readonly MODULE_SEVERITY_THRESHOLD="info"

_uid_zero_accounts() {
    print_header "UID 0 Accounts"

    local uid_zero_entries
    uid_zero_entries=$(awk -F: '$3 == 0 {print $1}' /etc/passwd 2>/dev/null || true)

    local count=0
    while IFS= read -r account; do
        [[ -z "${account}" ]] && continue
        count=$((count + 1))

        if [[ "${account}" == "root" ]]; then
            add_finding "uid0" "Root account has UID 0 (expected)" "info" "account=${account}"
            print_success "Root account: ${account} (UID 0 - expected)"
        else
            add_finding "uid0" "Non-root account with UID 0: ${account}" "critical" \
                "account=${account} remediation=Remove or change UID of ${account}"
            print_error "UID 0 account: ${account} - CRITICAL"
        fi
    done <<< "${uid_zero_entries}"

    if [[ ${count} -eq 0 ]]; then
        add_finding "uid0" "No UID 0 accounts found in /etc/passwd" "info" "count=0"
        print_success "No UID 0 accounts found"
    fi
}

_passwordless_sudo() {
    print_header "Passwordless Sudo Access"

    local sudoers_files=()

    if [[ -f /etc/sudoers ]]; then
        sudoers_files+=("/etc/sudoers")
    fi

    while IFS= read -r -d '' file; do
        sudoers_files+=("${file}")
    done < <(find /etc/sudoers.d/ -maxdepth 1 -type f -name '*.conf' -o -name '*.rules' 2>/dev/null | tr '\n' '\0' || true)

    local found=false

    for sudoers_file in "${sudoers_files[@]}"; do
        [[ -f "${sudoers_file}" ]] || continue

        local matches
        matches=$(awk '
            /^\s*#|^\s*$/ { next }
            /NOPASSWD/ { print FILENAME ":" NR ":" $0 }
        ' "${sudoers_file}" 2>/dev/null || true)

        while IFS= read -r match; do
            [[ -z "${match}" ]] && continue
            found=true
            add_finding "sudoers" "Passwordless sudo entry: ${match}" "high" \
                "file=${sudoers_file} remediation=Remove NOPASSWD entries or add password requirement"
            print_error "Passwordless sudo: ${match}"
        done <<< "${matches}"
    done

    if [[ "${found}" == false ]]; then
        add_finding "sudoers" "No passwordless sudo entries found" "info" "status=clean"
        print_success "No passwordless sudo entries found"
    fi
}

_empty_passwords() {
    print_header "Empty Password Accounts"

    local empty_pass
    empty_pass=$(awk -F: '($2 == "" || $2 == "!!" || $2 == "!") && $2 != "!" {print $1}' /etc/shadow 2>/dev/null || true)

    local found=false

    while IFS= read -r account; do
        [[ -z "${account}" ]] && continue

        local shell
        shell=$(awk -F: -v acct="${account}" '$1 == acct {print $7}' /etc/passwd 2>/dev/null || echo "")

        if [[ "${shell}" == "/sbin/nologin" ]] || [[ "${shell}" == "/bin/false" ]]; then
            add_finding "empty_password" "Locked/no-login account with empty password: ${account}" "low" \
                "account=${account} shell=${shell}"
            print_success "Account ${account}: empty password but shell is ${shell}"
        else
            found=true
            add_finding "empty_password" "Account with empty password: ${account}" "critical" \
                "account=${account} remediation=Set a password or lock account: passwd -l ${account}"
            print_error "EMPTY PASSWORD: ${account} - CRITICAL"
        fi
    done <<< "${empty_pass}"

    if [[ "${found}" == false ]]; then
        print_success "No accounts with empty passwords and login shells"
    fi
}

_locked_accounts() {
    print_header "Locked Accounts"

    local locked_count=0

    while IFS=: read -r username shadow rest; do
        if [[ "${shadow}" == "!"* ]] || [[ "${shadow}" == "*" ]]; then
            locked_count=$((locked_count + 1))
        fi
    done < <(cut -d: -f1,2 /etc/shadow 2>/dev/null || true)

    add_finding "locked_accounts" "Total locked accounts: ${locked_count}" "info" "count=${locked_count}"
    print_success "Locked accounts: ${locked_count}"
}

_ssh_keys_audit() {
    print_header "SSH Keys Per User"

    local found=false

    while IFS=: read -r username _ uid _ _ homedir shell; do
        [[ -z "${homedir}" ]] && continue
        [[ "${shell}" == "/sbin/nologin" || "${shell}" == "/bin/false" ]] && continue
        [[ ! -d "${homedir}/.ssh" ]] && continue

        local authorized_keys="${homedir}/.ssh/authorized_keys"

        if [[ -f "${authorized_keys}" ]]; then
            local key_count
            key_count=$(grep -c '^ssh-\|^ecdsa-\|^sk-' "${authorized_keys}" 2>/dev/null || echo "0")

            if [[ ${key_count} -gt 0 ]]; then
                found=true

                local perms
                perms=$(stat -c '%a' "${authorized_keys}" 2>/dev/null || echo "unknown")

                if [[ "${perms}" != "600" ]] && [[ "${perms}" != "400" ]] && [[ "${perms}" != "unknown" ]]; then
                    add_finding "ssh_keys" "User ${username}: authorized_keys has loose permissions (${perms})" "medium" \
                        "user=${username} file=${authorized_keys} permissions=${perms} remediation=chmod 600 ${authorized_keys}"
                    print_warning "User ${username}: authorized_keys permissions ${perms} (should be 600)"
                else
                    add_finding "ssh_keys" "User ${username}: ${key_count} authorized SSH key(s)" "info" \
                        "user=${username} key_count=${key_count} file=${authorized_keys}"
                    print_success "User ${username}: ${key_count} authorized key(s), permissions OK"
                fi
            fi
        fi

        local id_rsa="${homedir}/.ssh/id_rsa"
        local id_ed25519="${homedir}/.ssh/id_ed25519"
        local id_ecdsa="${homedir}/.ssh/id_ecdsa"
        local id_dsa="${homedir}/.ssh/id_dsa"

        for key_file in "${id_rsa}" "${id_ed25519}" "${id_ecdsa}" "${id_dsa}"; do
            if [[ -f "${key_file}" ]]; then
                local key_perms
                key_perms=$(stat -c '%a' "${key_file}" 2>/dev/null || echo "unknown")

                if [[ "${key_perms}" != "600" ]] && [[ "${key_perms}" != "400" ]] && [[ "${key_perms}" != "unknown" ]]; then
                    add_finding "ssh_keys" "User ${username}: private key ${key_file} has loose permissions (${key_perms})" "high" \
                        "user=${username} file=${key_file} permissions=${key_perms} remediation=chmod 600 ${key_file}"
                    print_error "User ${username}: ${key_file} permissions ${key_perms} - HIGH RISK"
                fi
            fi
        done
    done < /etc/passwd

    if [[ "${found}" == false ]]; then
        print_success "No users with authorized_keys found"
    fi
}

_home_dir_permissions() {
    print_header "Home Directory Permissions"

    local found=false

    while IFS=: read -r username _ uid _ _ homedir shell; do
        [[ -z "${homedir}" ]] && continue
        [[ "${homedir}" == "/nonexistent" || "${homedir}" == "/dev/null" ]] && continue
        [[ ! -d "${homedir}" ]] && continue

        local perms
        perms=$(stat -c '%a' "${homedir}" 2>/dev/null || echo "unknown")

        if [[ "${perms}" == "777" ]] || [[ "${perms}" == "776" ]] || [[ "${perms}" == "775" ]]; then
            found=true
            add_finding "home_perms" "User ${username}: home dir ${homedir} has loose permissions (${perms})" "medium" \
                "user=${username} dir=${homedir} permissions=${perms} remediation=chmod 750 ${homedir}"
            print_warning "User ${username}: ${homedir} permissions ${perms}"
        fi

        local owner
        owner=$(stat -c '%U' "${homedir}" 2>/dev/null || echo "unknown")

        if [[ "${owner}" != "${username}" ]] && [[ "${owner}" != "root" ]]; then
            found=true
            add_finding "home_perms" "User ${username}: home dir ${homedir} owned by ${owner}" "medium" \
                "user=${username} dir=${homedir} owner=${owner}"
            print_warning "User ${username}: ${homedir} owned by ${owner}"
        fi
    done < /etc/passwd

    if [[ "${found}" == false ]]; then
        print_success "Home directory permissions look reasonable"
    fi
}

_login_shells() {
    print_header "Users with Login Shells"

    local login_users=()
    local nologin_shells=("/sbin/nologin" "/bin/false" "/usr/sbin/nologin" "/bin/sync")

    while IFS=: read -r username _ _ _ _ homedir shell; do
        local is_nologin=false
        for noshell in "${nologin_shells[@]}"; do
            if [[ "${shell}" == "${noshell}" ]]; then
                is_nologin=true
                break
            fi
        done

        if [[ "${is_nologin}" == false ]] && [[ -n "${shell}" ]]; then
            login_users+=("${username} (${shell})")
        fi
    done < /etc/passwd

    local count=${#login_users[@]}
    add_finding "login_shells" "Users with login shells: ${count}" "info" "count=${count}"
    print_success "Users with login shells: ${count}"
}

_sensitive_groups() {
    print_header "Users in Sensitive Groups"

    local sensitive_groups=("wheel" "sudo" "docker" "root" "shadow" "staff")
    local found=false

    for group in "${sensitive_groups[@]}"; do
        local members
        members=$(getent group "${group}" 2>/dev/null | awk -F: '{print $4}' || echo "")

        if [[ -n "${members}" ]]; then
            found=true
            local member_list
            member_list=$(echo "${members}" | tr ',' ' ')
            add_finding "sensitive_groups" "Group '${group}' members: ${member_list}" "info" \
                "group=${group} members=${member_list}"
            print_success "Group '${group}': ${member_list}"
        fi
    done

    if [[ "${found}" == false ]]; then
        print_success "No users found in sensitive groups"
    fi
}

_password_aging() {
    print_header "Password Aging Policy"

    local found=false

    while IFS=: read -r username shadow rest; do
        local shell
        shell=$(awk -F: -v acct="${username}" '$1 == acct {print $7}' /etc/passwd 2>/dev/null || echo "")
        [[ "${shell}" == "/sbin/nologin" || "${shell}" == "/bin/false" ]] && continue

        local last_changed
        last_changed=$(echo "${shadow}" | awk -F: '{print $3}')

        if [[ -n "${last_changed}" ]] && [[ "${last_changed}" != "" ]] && [[ "${last_changed}" =~ ^[0-9]+$ ]]; then
            local now_days
            now_days=$(( $(date +%s) / 86400 ))
            local age_days=$(( now_days - last_changed ))

            local max_days
            max_days=$(echo "${shadow}" | awk -F: '{print $5}')

            if [[ -n "${max_days}" ]] && [[ "${max_days}" =~ ^[0-9]+$ ]] && [[ "${max_days}" -gt 0 ]]; then
                if [[ ${age_days} -gt ${max_days} ]]; then
                    found=true
                    add_finding "password_aging" "User ${username}: password expired (${age_days} days old, max ${max_days})" "medium" \
                        "user=${username} age_days=${age_days} max_days=${max_days}"
                    print_warning "User ${username}: password expired (${age_days}/${max_days} days)"
                fi
            fi
        fi
    done < <(awk -F: '{print $1 ":" $2 ":" $3 ":" $4 ":" $5 ":" $6 ":" $7}' /etc/shadow 2>/dev/null || true)

    if [[ "${found}" == false ]]; then
        print_success "No password aging issues detected"
    fi
}

_netrc_files() {
    print_header ".netrc Credential Files"

    local found=false

    while IFS=: read -r username _ uid _ _ homedir shell; do
        [[ -z "${homedir}" ]] || [[ ! -d "${homedir}" ]] && continue

        local netrc="${homedir}/.netrc"

        if [[ -f "${netrc}" ]]; then
            found=true
            add_finding "netrc" "User ${username}: .netrc file found at ${netrc}" "high" \
                "user=${username} file=${netrc} remediation=Remove .netrc and use a proper credential manager"
            print_error "User ${username}: .netrc found at ${netrc} - HIGH RISK"
        fi
    done < /etc/passwd

    if [[ -f /root/.netrc ]]; then
        found=true
        add_finding "netrc" "Root: .netrc file found at /root/.netrc" "high" \
            "user=root file=/root/.netrc remediation=Remove .netrc"
        print_error "Root: .netrc found - HIGH RISK"
    fi

    if [[ "${found}" == false ]]; then
        print_success "No .netrc files found"
    fi
}

_user_cron_entries() {
    print_header "Per-User Cron Entries"

    local found=false

    while IFS=: read -r username _ uid _ _ homedir shell; do
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
                add_finding "user_cron" "User ${username}: ${line_count} cron entry/entries" "info" \
                    "user=${username} entries=${line_count}"
                print_success "User ${username}: ${line_count} cron entries"
            fi
        fi
    done < /etc/passwd

    if [[ "${found}" == false ]]; then
        print_success "No per-user cron entries found"
    fi
}

run() {
    print_header "User Account & Privilege Audit"

    _uid_zero_accounts
    _passwordless_sudo
    _empty_passwords
    _locked_accounts
    _ssh_keys_audit
    _home_dir_permissions
    _login_shells
    _sensitive_groups
    _password_aging
    _netrc_files
    _user_cron_entries
}

if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    run
fi
