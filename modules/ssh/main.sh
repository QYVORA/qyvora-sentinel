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

readonly MODULE_NAME="ssh"
readonly MODULE_DESCRIPTION="SSH configuration audit"
readonly MODULE_VERSION="1.0.0"
readonly MODULE_SEVERITY_THRESHOLD="info"

readonly SSHD_CONFIG="/etc/ssh/sshd_config"

_sshd_config_value() {
    local key="$1"
    local config_file="${2:-${SSHD_CONFIG}}"
    local default="${3:-not_set}"

    local value
    value=$(awk -v key="${key}" '
        /^[[:space:]]*#/ { next }
        $1 == key { value=$2; exit }
    ' "${config_file}" 2>/dev/null || echo "${default}")

    if [[ -z "${value}" ]]; then
        value="${default}"
    fi

    echo "${value}"
}

_parse_sshd_config() {
    if [[ ! -f "${SSHD_CONFIG}" ]]; then
        print_error "SSHD config not found at ${SSHD_CONFIG}"
        return 1
    fi

    local include_files
    include_files=$(grep -v '^\s*#' "${SSHD_CONFIG}" 2>/dev/null | grep -i '^Include ' | awk '{print $2}' || true)

    while IFS= read -r inc_pattern; do
        [[ -z "${inc_pattern}" ]] && continue

        for inc_file in ${inc_pattern}; do
            [[ -f "${inc_file}" ]] || continue
        done
    done <<< "${include_files}"
}

_permit_root_login() {
    print_header "PermitRootLogin Check"

    local value
    value=$(_sshd_config_value "PermitRootLogin" "${SSHD_CONFIG}" "yes")

    case "${value}" in
        no)
            add_finding "sshd_rootlogin" "PermitRootLogin is set to 'no' (good)" "info" \
                "setting=PermitRootLogin value=no"
            print_success "PermitRootLogin: no (good)"
            ;;
        prohibit-password|prohibit-password*)
            add_finding "sshd_rootlogin" "PermitRootLogin is 'prohibit-password'" "info" \
                "setting=PermitRootLogin value=prohibit-password"
            print_success "PermitRootLogin: prohibit-password"
            ;;
        without-password*)
            add_finding "sshd_rootlogin" "PermitRootLogin is 'without-password'" "info" \
                "setting=PermitRootLogin value=without-password"
            print_success "PermitRootLogin: without-password"
            ;;
        yes|*)
            add_finding "sshd_rootlogin" "PermitRootLogin is '${value}' (insecure)" "high" \
                "setting=PermitRootLogin value=${value} remediation=Set 'PermitRootLogin no' in sshd_config"
            print_error "PermitRootLogin: ${value} - INSECURE"
            ;;
    esac
}

_password_authentication() {
    print_header "PasswordAuthentication Check"

    local value
    value=$(_sshd_config_value "PasswordAuthentication" "${SSHD_CONFIG}" "yes")

    if [[ "${value}" == "no" ]]; then
        add_finding "sshd_pwauth" "PasswordAuthentication is 'no' (good)" "info" \
            "setting=PasswordAuthentication value=no"
        print_success "PasswordAuthentication: no (good)"
    else
        add_finding "sshd_pwauth" "PasswordAuthentication is '${value}'" "medium" \
            "setting=PasswordAuthentication value=${value} remediation=Set 'PasswordAuthentication no' to use key-based auth only"
        print_warning "PasswordAuthentication: ${value}"
    fi
}

_pubkey_authentication() {
    print_header "PubkeyAuthentication Check"

    local value
    value=$(_sshd_config_value "PubkeyAuthentication" "${SSHD_CONFIG}" "yes")

    if [[ "${value}" == "yes" ]]; then
        add_finding "sshd_pubkey" "PubkeyAuthentication is enabled (good)" "info" \
            "setting=PubkeyAuthentication value=yes"
        print_success "PubkeyAuthentication: yes (good)"
    else
        add_finding "sshd_pubkey" "PubkeyAuthentication is '${value}'" "medium" \
            "setting=PubkeyAuthentication value=${value} remediation=Enable PubkeyAuthentication"
        print_warning "PubkeyAuthentication: ${value}"
    fi
}

_x11_forwarding() {
    print_header "X11Forwarding Check"

    local value
    value=$(_sshd_config_value "X11Forwarding" "${SSHD_CONFIG}" "no")

    if [[ "${value}" == "no" ]]; then
        add_finding "sshd_x11" "X11Forwarding is disabled (good)" "info" \
            "setting=X11Forwarding value=no"
        print_success "X11Forwarding: no (good)"
    else
        add_finding "sshd_x11" "X11Forwarding is '${value}'" "low" \
            "setting=X11Forwarding value=${value} remediation=Set 'X11Forwarding no' if not needed"
        print_warning "X11Forwarding: ${value}"
    fi
}

_max_auth_tries() {
    print_header "MaxAuthTries Check"

    local value
    value=$(_sshd_config_value "MaxAuthTries" "${SSHD_CONFIG}" "6")

    if [[ "${value}" =~ ^[0-9]+$ ]]; then
        if [[ ${value} -le 3 ]]; then
            add_finding "sshd_maxauth" "MaxAuthTries: ${value} (good)" "info" \
                "setting=MaxAuthTries value=${value}"
            print_success "MaxAuthTries: ${value} (good)"
        elif [[ ${value} -le 6 ]]; then
            add_finding "sshd_maxauth" "MaxAuthTries: ${value} (acceptable)" "info" \
                "setting=MaxAuthTries value=${value}"
            print_success "MaxAuthTries: ${value} (acceptable)"
        else
            add_finding "sshd_maxauth" "MaxAuthTries: ${value} (too high)" "medium" \
                "setting=MaxAuthTries value=${value} remediation=Set 'MaxAuthTries 3'"
            print_warning "MaxAuthTries: ${value} - consider lowering to 3"
        fi
    fi
}

_protocol_version() {
    print_header "Protocol Version Check"

    local value
    value=$(_sshd_config_value "Protocol" "${SSHD_CONFIG}" "2")

    if [[ "${value}" == "2" ]]; then
        add_finding "sshd_protocol" "Protocol version: 2 (good)" "info" \
            "setting=Protocol value=2"
        print_success "Protocol: 2 (good)"
    elif [[ "${value}" == "not_set" ]]; then
        add_finding "sshd_protocol" "Protocol not explicitly set (defaults to 2 in modern OpenSSH)" "info" \
            "setting=Protocol value=not_set"
        print_success "Protocol: not set (defaults to 2)"
    else
        add_finding "sshd_protocol" "Protocol version: ${value} (INSECURE)" "critical" \
            "setting=Protocol value=${value} remediation=Set 'Protocol 2' - Protocol 1 is insecure"
        print_error "Protocol: ${value} - INSECURE, Protocol 1 is deprecated"
    fi
}

_weak_algorithms() {
    print_header "Weak/Dangerous Algorithms Check"

    local weak_algorithms=(
        "aes128-cbc" "aes192-cbc" "aes256-cbc"
        "3des-cbc" "blowfish-cbc" "cast128-cbc"
        "arcfour" "arcfour128" "arcfour256"
        "diffie-hellman-group1-sha1" "diffie-hellman-group14-sha1"
    )

    local found_weak=false

    for config_file in "${SSHD_CONFIG}"; do
        [[ -f "${config_file}" ]] || continue

        local ciphers_line
        ciphers_line=$(_sshd_config_value "Ciphers" "${config_file}" "")
        local macs_line
        macs_line=$(_sshd_config_value "MACs" "${config_file}" "")
        local kex_line
        kex_line=$(_sshd_config_value "KexAlgorithms" "${config_file}" "")

        local all_algorithms="${ciphers_line} ${macs_line} ${kex_line}"

        for weak in "${weak_algorithms[@]}"; do
            if echo "${all_algorithms}" | grep -qi "${weak}"; then
                found_weak=true
                add_finding "sshd_weak_algo" "Weak algorithm enabled: ${weak}" "medium" \
                    "algorithm=${weak} remediation=Remove ${weak} from SSH configuration"
                print_warning "Weak algorithm: ${weak}"
            fi
        done
    done

    if [[ "${found_weak}" == false ]]; then
        print_success "No weak algorithms detected"
    fi
}

_host_key_permissions() {
    print_header "SSH Host Key Permissions"

    local key_types=("ssh_host_rsa_key" "ssh_host_dsa_key" "ssh_host_ecdsa_key" \
        "ssh_host_ed25519_key" "ssh_host_ecdsa_key" "ssh_host_dsa_key")

    local key_dir="/etc/ssh"
    local found=false

    for key_type in "${key_types[@]}"; do
        local key_file="${key_dir}/${key_type}"

        if [[ -f "${key_file}" ]]; then
            local perms
            perms=$(stat -c '%a' "${key_file}" 2>/dev/null || echo "unknown")
            local owner
            owner=$(stat -c '%U' "${key_file}" 2>/dev/null || echo "unknown")

            if [[ "${perms}" != "600" ]] && [[ "${perms}" != "400" ]] && [[ "${perms}" != "unknown" ]]; then
                found=true
                add_finding "sshd_hostkey" "Host key ${key_file} has permissions ${perms} (should be 600)" "medium" \
                    "file=${key_file} permissions=${perms} owner=${owner} remediation=chmod 600 ${key_file}"
                print_warning "Host key permissions: ${key_file} is ${perms} (should be 600)"
            fi

            if [[ "${owner}" != "root" ]] && [[ "${owner}" != "unknown" ]]; then
                found=true
                add_finding "sshd_hostkey" "Host key ${key_file} owned by ${owner} (should be root)" "medium" \
                    "file=${key_file} owner=${owner} remediation=chown root:root ${key_file}"
                print_warning "Host key owner: ${key_file} is owned by ${owner}"
            fi
        fi
    done

    if [[ "${found}" == false ]]; then
        print_success "Host key permissions look correct"
    fi
}

_authorized_keys_audit() {
    print_header "Authorized Keys for All Users"

    local found=false

    while IFS=: read -r username _ uid _ _ homedir shell; do
        [[ -z "${homedir}" ]] || [[ ! -d "${homedir}" ]] && continue

        local auth_keys="${homedir}/.ssh/authorized_keys"

        if [[ -f "${auth_keys}" ]]; then
            local key_count
            key_count=$(grep -c '^ssh-\|^ecdsa-\|^sk-' "${auth_keys}" 2>/dev/null || echo "0")

            if [[ ${key_count} -gt 0 ]]; then
                found=true
                add_finding "sshd_authkeys" "User ${username}: ${key_count} authorized key(s)" "info" \
                    "user=${username} count=${key_count} file=${auth_keys}"
                print_success "User ${username}: ${key_count} authorized key(s)"
            fi
        fi
    done < /etc/passwd

    if [[ "${found}" == false ]]; then
        print_success "No authorized_keys found for any user"
    fi
}

_ssh_agent_forwarding() {
    print_header "SSH Agent Forwarding"

    local value
    value=$(_sshd_config_value "AllowAgentForwarding" "${SSHD_CONFIG}" "yes")

    if [[ "${value}" == "no" ]]; then
        add_finding "sshd_agent_fwd" "SSH agent forwarding is disabled (good)" "info" \
            "setting=AllowAgentForwarding value=no"
        print_success "AllowAgentForwarding: no (good)"
    else
        add_finding "sshd_agent_fwd" "SSH agent forwarding is '${value}'" "low" \
            "setting=AllowAgentForwarding value=${value} remediation=Set 'AllowAgentForwarding no' if not needed"
        print_warning "AllowAgentForwarding: ${value}"
    fi
}

_user_ssh_configs() {
    print_header "User SSH Configurations"

    local found=false

    while IFS=: read -r username _ uid _ _ homedir shell; do
        [[ -z "${homedir}" ]] || [[ ! -d "${homedir}" ]] && continue

        local ssh_config="${homedir}/.ssh/config"

        if [[ -f "${ssh_config}" ]]; then
            local config_lines
            config_lines=$(grep -v '^\s*#' "${ssh_config}" 2>/dev/null | grep -v '^\s*$' || true)

            if [[ -n "${config_lines}" ]]; then
                found=true
                local line_count
                line_count=$(echo "${config_lines}" | wc -l)
                add_finding "sshd_user_config" "User ${username}: SSH config with ${line_count} entries" "info" \
                    "user=${username} entries=${line_count} file=${ssh_config}"
                print_success "User ${username}: SSH config (${line_count} entries)"
            fi
        fi
    done < /etc/passwd

    if [[ "${found}" == false ]]; then
        print_success "No user SSH config files found"
    fi
}

_known_hosts_entries() {
    print_header "Known Hosts Entries"

    local found=false

    while IFS=: read -r username _ uid _ _ homedir shell; do
        [[ -z "${homedir}" ]] || [[ ! -d "${homedir}" ]] && continue

        local known_hosts="${homedir}/.ssh/known_hosts"

        if [[ -f "${known_hosts}" ]]; then
            local entry_count
            entry_count=$(grep -cv '^\s*$' "${known_hosts}" 2>/dev/null || echo "0")

            if [[ ${entry_count} -gt 0 ]]; then
                found=true
                add_finding "sshd_known_hosts" "User ${username}: ${entry_count} known host(s)" "info" \
                    "user=${username} count=${entry_count} file=${known_hosts}"
                print_success "User ${username}: ${entry_count} known host(s)"
            fi
        fi
    done < /etc/passwd

    if [[ "${found}" == false ]]; then
        print_success "No known_hosts entries found"
    fi
}

_ssh_version() {
    print_header "SSH Version Check"

    local ssh_version
    ssh_version=$(ssh -V 2>&1 || echo "unknown")

    if [[ "${ssh_version}" != "unknown" ]]; then
        add_finding "sshd_version" "SSH version: ${ssh_version}" "info" \
            "version=${ssh_version}"
        print_success "SSH version: ${ssh_version}"

        if echo "${ssh_version}" | grep -qE 'OpenSSH_[1-6]\.'; then
            add_finding "sshd_version" "Outdated SSH version detected" "medium" \
                "version=${ssh_version} remediation=Update OpenSSH to the latest version"
            print_warning "Outdated SSH version detected"
        fi
    else
        add_finding "sshd_version" "Could not determine SSH version" "low" "version=unknown"
        print_warning "Could not determine SSH version"
    fi
}

_key_file_permissions() {
    print_header "SSH Key File Permissions"

    local found=false

    while IFS=: read -r username _ uid _ _ homedir shell; do
        [[ -z "${homedir}" ]] || [[ ! -d "${homedir}" ]] && continue
        [[ ! -d "${homedir}/.ssh" ]] && continue

        local key_files=("id_rsa" "id_ed25519" "id_ecdsa" "id_dsa" "id_xmss")

        for key_name in "${key_files[@]}"; do
            local key_file="${homedir}/.ssh/${key_name}"

            if [[ -f "${key_file}" ]]; then
                local perms
                perms=$(stat -c '%a' "${key_file}" 2>/dev/null || echo "unknown")

                if [[ "${perms}" != "600" ]] && [[ "${perms}" != "400" ]] && [[ "${perms}" != "unknown" ]]; then
                    found=true
                    add_finding "sshd_key_perms" "User ${username}: ${key_name} has permissions ${perms} (should be 600)" "high" \
                        "user=${username} file=${key_file} permissions=${perms} remediation=chmod 600 ${key_file}"
                    print_error "User ${username}: ${key_name} permissions ${perms} - HIGH RISK"
                fi
            fi
        done

        local pubkey_files=("id_rsa.pub" "id_ed25519.pub" "id_ecdsa.pub" "id_dsa.pub")

        for key_name in "${pubkey_files[@]}"; do
            local key_file="${homedir}/.ssh/${key_name}"

            if [[ -f "${key_file}" ]]; then
                local perms
                perms=$(stat -c '%a' "${key_file}" 2>/dev/null || echo "unknown")

                if [[ "${perms}" != "644" ]] && [[ "${perms}" != "600" ]] && [[ "${perms}" != "unknown" ]]; then
                    found=true
                    add_finding "sshd_key_perms" "User ${username}: ${key_name} has permissions ${perms} (should be 644)" "low" \
                        "user=${username} file=${key_file} permissions=${perms} remediation=chmod 644 ${key_file}"
                    print_warning "User ${username}: ${key_name} permissions ${perms}"
                fi
            fi
        done
    done < /etc/passwd

    if [[ "${found}" == false ]]; then
        print_success "SSH key file permissions look correct"
    fi
}

run() {
    print_header "SSH Configuration Audit"

    _parse_sshd_config
    _permit_root_login
    _password_authentication
    _pubkey_authentication
    _x11_forwarding
    _max_auth_tries
    _protocol_version
    _weak_algorithms
    _host_key_permissions
    _authorized_keys_audit
    _ssh_agent_forwarding
    _user_ssh_configs
    _known_hosts_entries
    _ssh_version
    _key_file_permissions
}

if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    run
fi
