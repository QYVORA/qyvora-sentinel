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

readonly MODULE_NAME="permissions"
readonly MODULE_DESCRIPTION="File and directory permission audit"
readonly MODULE_VERSION="1.0.0"
readonly MODULE_SEVERITY_THRESHOLD="info"

_etc_critical_file_permissions() {
    print_subheader "Critical /etc File Permissions"

    local -a critical_files=(
        "/etc/passwd"
        "/etc/shadow"
        "/etc/group"
        "/etc/gshadow"
        "/etc/sudoers"
        "/etc/ssh/sshd_config"
    )

    local -A expected_modes=(
        ["/etc/passwd"]="644"
        ["/etc/shadow"]="640"
        ["/etc/group"]="644"
        ["/etc/gshadow"]="640"
        ["/etc/sudoers"]="440"
        ["/etc/ssh/sshd_config"]="600"
    )

    local file
    for file in "${critical_files[@]}"; do
        if [[ ! -f "${file}" ]]; then
            continue
        fi

        local mode
        mode="$(stat -c '%a' "${file}" 2>/dev/null || echo "")"
        if [[ -z "${mode}" ]]; then
            continue
        fi

        local expected="${expected_modes[${file}]:-644}"
        if [[ "${mode}" != "${expected}" ]]; then
            add_finding "${MODULE_NAME}" "HIGH" \
                "Insecure permissions on ${file}" \
                "${file} has mode ${mode}, expected ${expected}" \
                "file=${file} current_mode=${mode} expected_mode=${expected}" \
                "chmod ${expected} ${file}" \
                "CIS Benchmark / DISA STIG"
            print_error "${file} permissions ${mode} (expected ${expected})"
        else
            print_success "${file} permissions ${mode} (correct)"
        fi
    done
}

_shadow_ownership() {
    print_subheader "Shadow File Ownership"

    local shadow_file="/etc/shadow"
    if [[ ! -f "${shadow_file}" ]]; then
        print_info "/etc/shadow not found, skipping"
        return
    fi

    local owner group
    owner="$(stat -c '%U' "${shadow_file}" 2>/dev/null || echo "")"
    group="$(stat -c '%G' "${shadow_file}" 2>/dev/null || echo "")"

    if [[ "${owner}" != "root" ]]; then
        add_finding "${MODULE_NAME}" "HIGH" \
            "Shadow file owned by non-root user" \
            "/etc/shadow owner is ${owner}, should be root" \
            "file=/etc/shadow owner=${owner} group=${group}" \
            "chown root:shadow /etc/shadow" \
            "CIS Benchmark 4.2.3"
        print_error "/etc/shadow owner: ${owner} (expected root)"
    else
        print_success "/etc/shadow owner: ${owner}"
    fi

    if [[ "${group}" != "shadow" && "${group}" != "root" ]]; then
        add_finding "${MODULE_NAME}" "MEDIUM" \
            "Shadow file has unexpected group" \
            "/etc/shadow group is ${group}, expected shadow or root" \
            "file=/etc/shadow owner=${owner} group=${group}" \
            "chown root:shadow /etc/shadow"
        print_warning "/etc/shadow group: ${group} (expected shadow or root)"
    else
        print_success "/etc/shadow group: ${group}"
    fi
}

_home_directory_permissions() {
    print_subheader "Home Directory Permissions"

    local found_issue=false

    while IFS=: read -r username _ uid _ _ homedir _; do
        [[ "${uid}" -lt 1000 && "${uid}" -ne 0 ]] && continue
        [[ "${username}" == "nobody" ]] && continue
        [[ ! -d "${homedir}" ]] && continue

        local perms
        perms="$(stat -c '%A' "${homedir}" 2>/dev/null || echo "")"
        if [[ -z "${perms}" ]]; then
            continue
        fi

        local mode
        mode="$(stat -c '%a' "${homedir}" 2>/dev/null || echo "")"
        local others_write=$(( 8#${mode} & 8#0002 ))

        if [[ "${others_write}" -ne 0 ]]; then
            add_finding "${MODULE_NAME}" "HIGH" \
                "Home directory world-writable" \
                "${homedir} (${username}) has world-writable permissions" \
                "user=${username} home=${homedir} mode=${mode}" \
                "chmod 755 ${homedir}"
            print_error "World-writable: ${homedir} (${username})"
            found_issue=true
        fi

        local owner
        owner="$(stat -c '%U' "${homedir}" 2>/dev/null || echo "")"
        if [[ "${owner}" != "${username}" ]]; then
            add_finding "${MODULE_NAME}" "MEDIUM" \
                "Home directory owned by wrong user" \
                "${homedir} owned by ${owner}, expected ${username}" \
                "user=${username} home=${homedir} owner=${owner}" \
                "chown ${username}:${username} ${homedir}"
            print_warning "Wrong owner: ${homedir} (${owner} != ${username})"
            found_issue=true
        fi
    done < /etc/passwd

    if [[ "${found_issue}" == false ]]; then
        print_success "All home directory permissions look correct"
    fi
}

_ssh_directory_permissions() {
    print_subheader "SSH Directory Permissions"

    local found_issue=false

    while IFS=: read -r username _ uid _ _ homedir _; do
        [[ "${uid}" -lt 1000 && "${uid}" -ne 0 ]] && continue
        [[ "${username}" == "nobody" ]] && continue

        local ssh_dir="${homedir}/.ssh"
        [[ ! -d "${ssh_dir}" ]] && continue

        local dir_mode
        dir_mode="$(stat -c '%a' "${ssh_dir}" 2>/dev/null || echo "")"
        if [[ -n "${dir_mode}" && "${dir_mode}" != "700" ]]; then
            add_finding "${MODULE_NAME}" "HIGH" \
                ".ssh directory has wrong permissions" \
                "${ssh_dir} has mode ${dir_mode}, expected 700" \
                "user=${username} dir=${ssh_dir} mode=${dir_mode}" \
                "chmod 700 ${ssh_dir}"
            print_error ".ssh dir ${ssh_dir}: ${dir_mode} (expected 700)"
            found_issue=true
        else
            print_success ".ssh dir ${ssh_dir}: ${dir_mode}"
        fi

        if [[ -f "${ssh_dir}/authorized_keys" ]]; then
            local ak_mode
            ak_mode="$(stat -c '%a' "${ssh_dir}/authorized_keys" 2>/dev/null || echo "")"
            if [[ -n "${ak_mode}" && "${ak_mode}" != "600" && "${ak_mode}" != "644" ]]; then
                add_finding "${MODULE_NAME}" "HIGH" \
                    "authorized_keys has wrong permissions" \
                    "${ssh_dir}/authorized_keys has mode ${ak_mode}, expected 600 or 644" \
                    "user=${username} file=${ssh_dir}/authorized_keys mode=${ak_mode}" \
                    "chmod 600 ${ssh_dir}/authorized_keys"
                print_error "authorized_keys ${ssh_dir}: ${ak_mode} (expected 600)"
                found_issue=true
            else
                print_success "authorized_keys ${ssh_dir}: ${ak_mode}"
            fi
        fi
    done < /etc/passwd

    if [[ "${found_issue}" == false ]]; then
        print_success "SSH directory permissions look correct"
    fi
}

_private_key_permissions() {
    print_subheader "Private Key Permissions"

    local found_issue=false

    while IFS=: read -r username _ uid _ _ homedir _; do
        [[ "${uid}" -lt 1000 && "${uid}" -ne 0 ]] && continue
        [[ "${username}" == "nobody" ]] && continue
        [[ ! -d "${homedir}/.ssh" ]] && continue

        local key_file
        for key_file in "${homedir}/.ssh/"*; do
            [[ ! -f "${key_file}" ]] && continue

            local is_private=false
            if head -1 "${key_file}" 2>/dev/null | grep -qE "BEGIN.*(RSA |DSA |EC |OPENSSH )?PRIVATE KEY"; then
                is_private=true
            fi
            if [[ "${key_file}" == *_key || "${key_file}" == *_rsa || "${key_file}" == *_dsa || "${key_file}" == *_ecdsa || "${key_file}" == *_ed25519 ]]; then
                is_private=true
            fi

            if [[ "${is_private}" == true ]]; then
                local key_mode
                key_mode="$(stat -c '%a' "${key_file}" 2>/dev/null || echo "")"
                if [[ -n "${key_mode}" && "${key_mode}" != "600" ]]; then
                    add_finding "${MODULE_NAME}" "HIGH" \
                        "Private key has insecure permissions" \
                        "${key_file} has mode ${key_mode}, expected 600" \
                        "user=${username} file=${key_file} mode=${key_mode}" \
                        "chmod 600 ${key_file}"
                    print_error "Private key ${key_file}: ${key_mode} (expected 600)"
                    found_issue=true
                fi
            fi
        done
    done < /etc/passwd

    if [[ "${found_issue}" == false ]]; then
        print_success "Private key permissions look correct"
    fi
}

_world_writable_in_path() {
    print_subheader "World-Writable Files in PATH Directories"

    local found_issue=false
    local IFS_BAK="${IFS}"
    IFS=':'
    local -a path_dirs=(${PATH})
    IFS="${IFS_BAK}"

    local dir
    for dir in "${path_dirs[@]}"; do
        [[ ! -d "${dir}" ]] && continue

        local ww_files
        ww_files="$(find "${dir}" -maxdepth 1 -type f -perm -0002 2>/dev/null || true)"
        if [[ -n "${ww_files}" ]]; then
            local file
            while IFS= read -r file; do
                [[ -z "${file}" ]] && continue
                add_finding "${MODULE_NAME}" "HIGH" \
                    "World-writable file in PATH" \
                    "${file} in ${dir} is world-writable" \
                    "file=${file} dir=${dir}" \
                    "chmod o-w ${file}"
                print_error "World-writable in PATH: ${file}"
                found_issue=true
            done <<< "${ww_files}"
        fi
    done

    if [[ "${found_issue}" == false ]]; then
        print_success "No world-writable files found in PATH directories"
    fi
}

_writable_etc_configs() {
    print_subheader "Writable Config Files in /etc"

    local found_issue=false
    local ww_configs
    ww_configs="$(find /etc -maxdepth 2 -type f -perm -0002 2>/dev/null || true)"

    if [[ -n "${ww_configs}" ]]; then
        local count=0
        local file
        while IFS= read -r file; do
            [[ -z "${file}" ]] && continue
            count=$((count + 1))
            if [[ ${count} -le 20 ]]; then
                add_finding "${MODULE_NAME}" "MEDIUM" \
                    "Writable config file in /etc" \
                    "${file} is world-writable" \
                    "file=${file}" \
                    "chmod o-w ${file}"
                print_warning "Writable config: ${file}"
            fi
            found_issue=true
        done <<< "${ww_configs}"

        if [[ ${count} -gt 20 ]]; then
            print_warning "... and $((count - 20)) more"
        fi
        add_finding "${MODULE_NAME}" "MEDIUM" \
            "Total writable config files in /etc" \
            "${count} world-writable files found in /etc" \
            "count=${count}" \
            "Review and restrict permissions"
    fi

    if [[ "${found_issue}" == false ]]; then
        print_success "No world-writable config files in /etc"
    fi
}

_tmp_sticky_bit() {
    print_subheader "/tmp Sticky Bit"

    local -a tmp_dirs=("/tmp" "/var/tmp")
    local dir
    for dir in "${tmp_dirs[@]}"; do
        [[ ! -d "${dir}" ]] && continue

        if is_sticky "${dir}"; then
            print_success "${dir} has sticky bit set"
        else
            add_finding "${MODULE_NAME}" "HIGH" \
                "Missing sticky bit on ${dir}" \
                "${dir} does not have the sticky bit set" \
                "dir=${dir}" \
                "chmod +t ${dir}"
            print_error "${dir} missing sticky bit"
        fi
    done
}

_acl_files() {
    print_subheader "Files with ACLs Set"

    if ! command -v getfacl &>/dev/null; then
        print_info "getfacl not available, skipping ACL check"
        return
    fi

    local found_issue=false
    local acl_files
    acl_files="$(getfacl -R -s /etc /home /usr /var 2>/dev/null | grep -E "^# file:" || true)"

    if [[ -n "${acl_files}" ]]; then
        local count=0
        local line
        while IFS= read -r line; do
            [[ -z "${line}" ]] && continue
            local filepath="${line#\# file: }"
            count=$((count + 1))
            if [[ ${count} -le 20 ]]; then
                local acl_output
                acl_output="$(getfacl "${filepath}" 2>/dev/null | grep -v "^#" | grep -v "^$" || true)"
                add_finding "${MODULE_NAME}" "MEDIUM" \
                    "File has ACLs set" \
                    "${filepath} has extended ACLs" \
                    "file=${filepath} acls=${acl_output}" \
                    "setfacl -b ${filepath}"
                print_warning "ACLs on: ${filepath}"
                found_issue=true
            fi
        done <<< "${acl_files}"

        if [[ ${count} -gt 20 ]]; then
            print_warning "... and $((count - 20)) more files with ACLs"
        fi
    fi

    if [[ "${found_issue}" == false ]]; then
        print_success "No files with unexpected ACLs found"
    fi
}

_capability_files() {
    print_subheader "Files with Capabilities"

    local cap_files
    cap_files="$(getcap -r / 2>/dev/null || true)"

    if [[ -n "${cap_files}" ]]; then
        local line
        while IFS= read -r line; do
            [[ -z "${line}" ]] && continue
            local filepath caps
            filepath="$(echo "${line}" | awk '{print $1}')"
            caps="$(echo "${line}" | awk '{for(i=2;i<=NF;i++) printf "%s ", $i; print ""}' | xargs)"

            if has_dangerous_capabilities "${filepath}"; then
                add_finding "${MODULE_NAME}" "HIGH" \
                    "File has dangerous capabilities" \
                    "${filepath} has capabilities: ${caps}" \
                    "file=${filepath} capabilities=${caps}" \
                    "setcap -r ${filepath}"
                print_error "Dangerous caps: ${filepath} (${caps})"
            else
                add_finding "${MODULE_NAME}" "LOW" \
                    "File has capabilities" \
                    "${filepath} has capabilities: ${caps}" \
                    "file=${filepath} capabilities=${caps}"
                print_warning "Capabilities: ${filepath} (${caps})"
            fi
        done <<< "${cap_files}"
    else
        print_success "No files with capabilities found"
    fi
}

_root_writable_files() {
    print_subheader "Writable Files Owned by Root"

    local found_issue=false
    local root_ww
    root_ww="$(find / -xdev -type f -user root -perm -0002 2>/dev/null || true)"

    if [[ -n "${root_ww}" ]]; then
        local count=0
        local file
        while IFS= read -r file; do
            [[ -z "${file}" ]] && continue
            count=$((count + 1))
            if [[ ${count} -le 20 ]]; then
                add_finding "${MODULE_NAME}" "MEDIUM" \
                    "Root-owned world-writable file" \
                    "${file} is owned by root but world-writable" \
                    "file=${file}" \
                    "chmod o-w ${file}"
                print_warning "Root writable: ${file}"
                found_issue=true
            fi
        done <<< "${root_ww}"

        if [[ ${count} -gt 20 ]]; then
            print_warning "... and $((count - 20)) more"
        fi
        add_finding "${MODULE_NAME}" "MEDIUM" \
            "Total root-owned world-writable files" \
            "${count} root-owned world-writable files found" \
            "count=${count}"
    fi

    if [[ "${found_issue}" == false ]]; then
        print_success "No root-owned world-writable files found"
    fi
}

_cron_permissions() {
    print_subheader "Cron File Permissions"

    local found_issue=false
    local cron_dirs=("/etc/cron.d" "/etc/cron.daily" "/etc/cron.hourly" "/etc/cron.weekly" "/etc/cron.monthly")

    local dir
    for dir in "${cron_dirs[@]}"; do
        [[ ! -d "${dir}" ]] && continue

        local cron_file
        for cron_file in "${dir}"/*; do
            [[ ! -f "${cron_file}" ]] && continue

            local mode
            mode="$(stat -c '%a' "${cron_file}" 2>/dev/null || echo "")"
            [[ -z "${mode}" ]] && continue

            local owner
            owner="$(stat -c '%U' "${cron_file}" 2>/dev/null || echo "")"

            if [[ "${owner}" != "root" ]]; then
                add_finding "${MODULE_NAME}" "HIGH" \
                    "Cron file not owned by root" \
                    "${cron_file} owned by ${owner}" \
                    "file=${cron_file} owner=${owner}" \
                    "chown root ${cron_file}"
                print_error "Cron not root: ${cron_file} (${owner})"
                found_issue=true
            fi

            local others_write=$(( 8#${mode} & 8#0002 ))
            if [[ "${others_write}" -ne 0 ]]; then
                add_finding "${MODULE_NAME}" "HIGH" \
                    "World-writable cron file" \
                    "${cron_file} is world-writable" \
                    "file=${cron_file} mode=${mode}" \
                    "chmod 644 ${cron_file}"
                print_error "World-writable cron: ${cron_file}"
                found_issue=true
            fi
        done
    done

    local cron_files=("/etc/crontab" "/etc/anacrontab")
    for cron_file in "${cron_files[@]}"; do
        [[ ! -f "${cron_file}" ]] && continue

        local mode
        mode="$(stat -c '%a' "${cron_file}" 2>/dev/null || echo "")"
        [[ -z "${mode}" ]] && continue

        local owner
        owner="$(stat -c '%U' "${cron_file}" 2>/dev/null || echo "")"

        if [[ "${owner}" != "root" ]]; then
            add_finding "${MODULE_NAME}" "HIGH" \
                "Cron file not owned by root" \
                "${cron_file} owned by ${owner}" \
                "file=${cron_file} owner=${owner}" \
                "chown root ${cron_file}"
            print_error "Cron not root: ${cron_file} (${owner})"
            found_issue=true
        fi
    done

    if [[ "${found_issue}" == false ]]; then
        print_success "Cron file permissions look correct"
    fi
}

run() {
    print_header "Permissions Audit"

    _etc_critical_file_permissions
    _shadow_ownership
    _home_directory_permissions
    _ssh_directory_permissions
    _private_key_permissions
    _world_writable_in_path
    _writable_etc_configs
    _tmp_sticky_bit
    _acl_files
    _capability_files
    _root_writable_files
    _cron_permissions
}

if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    run
fi
