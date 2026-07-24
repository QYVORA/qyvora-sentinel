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
readonly MODULE_NAME="filesystem"
readonly MODULE_DESCRIPTION="Filesystem permissions and artifact audit"
readonly MODULE_VERSION="1.0.0"
readonly MODULE_SEVERITY_THRESHOLD="info"

_suid_files() {
    print_header "SUID Files"

    local suid_files_found
    suid_files_found=$(find_suid_files 2>/dev/null || true)

    if [[ -n "${suid_files_found}" ]]; then
        local known_suid=("/usr/bin/passwd" "/usr/bin/sudo" "/usr/bin/su" "/usr/bin/chsh" \
            "/usr/bin/chfn" "/usr/bin/newgrp" "/usr/bin/gpasswd" "/usr/bin/mount" \
            "/usr/bin/umount" "/usr/bin/fusermount" "/usr/bin/fusermount3" \
            "/usr/lib/openssh/ssh-keysign" "/usr/lib/dbus-1.0/dbus-daemon-launch-helper" \
            "/usr/bin/crontab" "/usr/bin/at" "/usr/bin/wall" "/usr/bin/write" \
            "/usr/bin/pkexec" "/usr/bin/certutil" "/usr/bin/fakechroot" \
            "/usr/sbin/unix_chkpwd" "/usr/sbin/pam_timestamp_check")

        local count=0
        while IFS= read -r file; do
            [[ -z "${file}" ]] && continue
            count=$((count + 1))

            local is_known=false
            for known in "${known_suid[@]}"; do
                if [[ "${file}" == "${known}" ]]; then
                    is_known=true
                    break
                fi
            done

            if [[ "${is_known}" == false ]]; then
                add_finding "suid" "Unexpected SUID binary: ${file}" "medium" \
                    "file=${file} remediation=Review and remove SUID bit: chmod u-s ${file}"
                print_warning "Unexpected SUID: ${file}"
            fi
        done <<< "${suid_files_found}"

        add_finding "suid" "Total SUID files found: ${count}" "info" "count=${count}"
        print_success "SUID files found: ${count}"
    else
        add_finding "suid" "No SUID files found" "info" "count=0"
        print_success "No SUID files found"
    fi
}

_sgid_files() {
    print_header "SGID Files"

    local sgid_files
    sgid_files=$(find / -path /proc -prune -o -path /sys -prune -o -path /dev -prune -o -perm /2000 -type f -print 2>/dev/null || true)

    if [[ -n "${sgid_files}" ]]; then
        local known_sgid=("/usr/bin/wall" "/usr/bin/write" "/usr/bin/newgrp" "/usr/bin/chage" \
            "/usr/bin/gpasswd" "/usr/bin/ssh-agent")

        local count=0
        while IFS= read -r file; do
            [[ -z "${file}" ]] && continue
            count=$((count + 1))

            local is_known=false
            for known in "${known_sgid[@]}"; do
                if [[ "${file}" == "${known}" ]]; then
                    is_known=true
                    break
                fi
            done

            if [[ "${is_known}" == false ]]; then
                add_finding "sgid" "Unexpected SGID binary: ${file}" "medium" \
                    "file=${file} remediation=Review and remove SGID bit: chmod g-s ${file}"
                print_warning "Unexpected SGID: ${file}"
            fi
        done <<< "${sgid_files}"

        add_finding "sgid" "Total SGID files found: ${count}" "info" "count=${count}"
        print_success "SGID files found: ${count}"
    else
        add_finding "sgid" "No SGID files found" "info" "count=0"
        print_success "No SGID files found"
    fi
}

_world_writable_files() {
    print_header "World-Writable Files"

    local ww_files
    ww_files=$(find / -path /proc -prune -o -path /sys -prune -o -path /dev -prune -o \
        -path /run -prune -o -path /snap -prune -o -perm -o+w -type f -print 2>/dev/null || true)

    if [[ -n "${ww_files}" ]]; then
        local count=0
        while IFS= read -r file; do
            [[ -z "${file}" ]] && continue
            count=$((count + 1))

            if [[ ${count} -le 20 ]]; then
                add_finding "world_writable" "World-writable file: ${file}" "medium" \
                    "file=${file} remediation=chmod o-w ${file}"
                print_warning "World-writable: ${file}"
            fi
        done <<< "${ww_files}"

        local total
        total=$(echo "${ww_files}" | grep -c . || echo "0")

        if [[ ${total} -gt 20 ]]; then
            print_warning "... and $((total - 20)) more world-writable files"
        fi

        add_finding "world_writable" "Total world-writable files: ${total}" "medium" \
            "count=${total} remediation=Remove world-writable permission from sensitive files"
        print_warning "Total world-writable files: ${total}"
    else
        add_finding "world_writable" "No world-writable files found" "info" "count=0"
        print_success "No world-writable files found"
    fi
}

_world_writable_dirs() {
    print_header "World-Writable Directories"

    local ww_dirs
    ww_dirs=$(find / -path /proc -prune -o -path /sys -prune -o -path /dev -prune -o \
        -path /run -prune -o -path /snap -prune -o -perm -o+w -type d -print 2>/dev/null || true)

    if [[ -n "${ww_dirs}" ]]; then
        local count=0
        while IFS= read -r dir; do
            [[ -z "${dir}" ]] && continue
            count=$((count + 1))

            local has_sticky
            has_sticky=$(stat -c '%A' "${dir}" 2>/dev/null || echo "")

            if [[ "${has_sticky}" != *t ]]; then
                add_finding "world_writable_dir" "World-writable directory WITHOUT sticky bit: ${dir}" "high" \
                    "dir=${dir} remediation=chmod o-w ${dir} or chmod +t ${dir}"
                print_error "World-writable dir (no sticky bit): ${dir}"
            fi
        done <<< "${ww_dirs}"

        add_finding "world_writable_dir" "Total world-writable directories: ${count}" "info" "count=${count}"
        print_success "World-writable directories: ${count}"
    else
        print_success "No world-writable directories found"
    fi
}

_hidden_executables() {
    print_header "Hidden Executables"

    local hidden_execs
    hidden_execs=$(find / -path /proc -prune -o -path /sys -prune -o -path /dev -prune -o \
        -path /run -prune -o -name '.*' -type f -executable -print 2>/dev/null || true)

    if [[ -n "${hidden_execs}" ]]; then
        local count=0
        while IFS= read -r file; do
            [[ -z "${file}" ]] && continue
            count=$((count + 1))

            if [[ ${count} -le 20 ]]; then
                add_finding "hidden_exec" "Hidden executable: ${file}" "low" \
                    "file=${file} remediation=Review hidden executable and remove if unauthorized"
                print_warning "Hidden executable: ${file}"
            fi
        done <<< "${hidden_execs}"

        local total
        total=$(echo "${hidden_execs}" | grep -c . || echo "0")
        add_finding "hidden_exec" "Total hidden executables found: ${total}" "info" "count=${total}"
        print_success "Hidden executables: ${total}"
    else
        print_success "No hidden executables found"
    fi
}

_recently_modified_executables() {
    print_header "Recently Modified Executables (Last 7 Days)"

    local recent_execs
    recent_execs=$(find / -path /proc -prune -o -path /sys -prune -o -path /dev -prune -o \
        -path /run -prune -o -type f -executable -mtime -7 -print 2>/dev/null || true)

    if [[ -n "${recent_execs}" ]]; then
        local count=0
        while IFS= read -r file; do
            [[ -z "${file}" ]] && continue
            count=$((count + 1))

            if [[ ${count} -le 20 ]]; then
                local mod_date
                mod_date=$(stat -c '%y' "${file}" 2>/dev/null | cut -d. -f1 || echo "unknown")
                add_finding "recent_exec" "Recently modified executable: ${file} (${mod_date})" "low" \
                    "file=${file} modified=${mod_date} remediation=Review recently modified executable"
                print_warning "Recently modified: ${file} (${mod_date})"
            fi
        done <<< "${recent_execs}"

        local total
        total=$(echo "${recent_execs}" | grep -c . || echo "0")
        add_finding "recent_exec" "Total recently modified executables: ${total}" "info" "count=${total}"
        print_success "Recently modified executables: ${total}"
    else
        print_success "No recently modified executables found"
    fi
}

_broken_symlinks() {
    print_header "Broken Symlinks"

    local broken_links
    broken_links=$(find / -path /proc -prune -o -path /sys -prune -o -path /dev -prune -o \
        -path /run -prune -o -type l ! -exec test -e {} \; -print 2>/dev/null || true)

    if [[ -n "${broken_links}" ]]; then
        local count=0
        while IFS= read -r link; do
            [[ -z "${link}" ]] && continue
            count=$((count + 1))

            if [[ ${count} -le 20 ]]; then
                local target
                target=$(readlink "${link}" 2>/dev/null || echo "unknown")
                add_finding "broken_symlink" "Broken symlink: ${link} -> ${target}" "low" \
                    "file=${link} target=${target} remediation=Remove broken symlink: rm ${link}"
                print_warning "Broken symlink: ${link} -> ${target}"
            fi
        done <<< "${broken_links}"

        local total
        total=$(echo "${broken_links}" | grep -c . || echo "0")
        add_finding "broken_symlink" "Total broken symlinks: ${total}" "info" "count=${total}"
        print_success "Broken symlinks: ${total}"
    else
        print_success "No broken symlinks found"
    fi
}

_tmp_suspicious_files() {
    print_header "Suspicious Files in /tmp and /var/tmp"

    local found=false

    for tmp_dir in "/tmp" "/var/tmp"; do
        [[ -d "${tmp_dir}" ]] || continue

        local suspicious
        suspicious=$(find "${tmp_dir}" -maxdepth 3 \( -name '*.sh' -o -name '*.py' -o -name '*.pl' \
            -o -name '*.pl' -o -name '*.rb' -o -name '*.elf' -o -name '*.exe' \
            -o -type f -executable \) -print 2>/dev/null || true)

        if [[ -n "${suspicious}" ]]; then
            while IFS= read -r file; do
                [[ -z "${file}" ]] && continue
                found=true
                add_finding "tmp_suspicious" "Suspicious file in ${tmp_dir}: ${file}" "medium" \
                    "file=${file} remediation=Review and remove if unauthorized"
                print_warning "Suspicious in ${tmp_dir}: ${file}"
            done <<< "${suspicious}"
        fi
    done

    if [[ "${found}" == false ]]; then
        print_success "No suspicious files found in /tmp or /var/tmp"
    fi
}

_no_owner_files() {
    print_header "Files with No Owner"

    local no_owner
    no_owner=$(find / -path /proc -prune -o -path /sys -prune -o -path /dev -prune -o \
        -path /run -prune -o \( -nouser -o -nogroup \) -print 2>/dev/null || true)

    if [[ -n "${no_owner}" ]]; then
        local count=0
        while IFS= read -r file; do
            [[ -z "${file}" ]] && continue
            count=$((count + 1))

            if [[ ${count} -le 20 ]]; then
                add_finding "no_owner" "File with no owner: ${file}" "low" \
                    "file=${file} remediation=Assign correct ownership or remove"
                print_warning "No owner: ${file}"
            fi
        done <<< "${no_owner}"

        local total
        total=$(echo "${no_owner}" | grep -c . || echo "0")
        add_finding "no_owner" "Total files with no owner: ${total}" "info" "count=${total}"
        print_success "Files with no owner: ${total}"
    else
        print_success "No files without owner/group found"
    fi
}

_extended_attributes() {
    print_header "Files with Extended Attributes (Capabilities)"

    local cap_files
    cap_files=$(getcap -r / 2>/dev/null || true)

    if [[ -n "${cap_files}" ]]; then
        while IFS= read -r line; do
            [[ -z "${line}" ]] && continue

            local caps
            caps=$(echo "${line}" | awk '{print $2}')
            local filepath
            filepath=$(echo "${line}" | awk '{print $1}')

            local severity="low"
            if [[ "${caps}" == *"cap_setuid"* ]] || [[ "${caps}" == *"cap_setgid"* ]] || \
               [[ "${caps}" == *"cap_dac_override"* ]] || [[ "${caps}" == *"cap_sys_admin"* ]]; then
                severity="high"
                add_finding "capabilities" "File with dangerous capability: ${filepath} ${caps}" "high" \
                    "file=${filepath} capabilities=${caps} remediation=Remove capabilities: setcap -r ${filepath}"
                print_error "Dangerous capability: ${filepath} ${caps}"
            else
                add_finding "capabilities" "File with capabilities: ${filepath} ${caps}" "low" \
                    "file=${filepath} capabilities=${caps}"
                print_warning "Capability: ${filepath} ${caps}"
            fi
        done <<< "${cap_files}"
    else
        print_success "No files with capabilities found"
    fi
}

_large_files() {
    print_header "Large Files (>100MB)"

    local large_files
    large_files=$(find / -path /proc -prune -o -path /sys -prune -o -path /dev -prune -o \
        -path /run -prune -o -type f -size +100M -print 2>/dev/null || true)

    if [[ -n "${large_files}" ]]; then
        local count=0
        while IFS= read -r file; do
            [[ -z "${file}" ]] && continue
            count=$((count + 1))

            if [[ ${count} -le 20 ]]; then
                local size
                size=$(du -h "${file}" 2>/dev/null | cut -f1 || echo "unknown")
                add_finding "large_file" "Large file: ${file} (${size})" "info" \
                    "file=${file} size=${size}"
                print_warning "Large file: ${file} (${size})"
            fi
        done <<< "${large_files}"

        local total
        total=$(echo "${large_files}" | grep -c . || echo "0")
        add_finding "large_file" "Total large files (>100MB): ${total}" "info" "count=${total}"
        print_success "Large files: ${total}"
    else
        print_success "No files larger than 100MB found"
    fi
}

_suspicious_devices() {
    print_header "Suspicious Device Files in /dev"

    local suspicious_devs
    suspicious_devs=$(find /dev -maxdepth 2 -type c ! -name 'null' ! -name 'zero' ! -name 'random' \
        ! -name 'urandom' ! -name 'tty' ! -name 'console' ! -name 'ptmx' ! -name 'tun' \
        ! -name 'tty[0-9]*' ! -name 'pts/*' -print 2>/dev/null || true)

    if [[ -n "${suspicious_devs}" ]]; then
        local count=0
        while IFS= read -r dev; do
            [[ -z "${dev}" ]] && continue
            count=$((count + 1))

            if [[ ${count} -le 20 ]]; then
                add_finding "device" "Unusual device file: ${dev}" "low" \
                    "file=${dev} remediation=Review and remove if unauthorized"
                print_warning "Unusual device: ${dev}"
            fi
        done <<< "${suspicious_devs}"

        local total
        total=$(echo "${suspicious_devs}" | grep -c . || echo "0")
        add_finding "device" "Total unusual device files: ${total}" "info" "count=${total}"
        print_success "Unusual device files: ${total}"
    else
        print_success "No suspicious device files found"
    fi
}

run() {
    print_header "Filesystem Permissions & Artifact Audit"

    _suid_files
    _sgid_files
    _world_writable_files
    _world_writable_dirs
    _hidden_executables
    _recently_modified_executables
    _broken_symlinks
    _tmp_suspicious_files
    _no_owner_files
    _extended_attributes
    _large_files
    _suspicious_devices
}

if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    run
fi
