#!/usr/bin/env bash
# permissions.sh - File permission checking and analysis for QYVORA Sentinel.

# Source guard - prevent re-sourcing
if [[ "${_SENTINEL_LIB_LOADED:-}" == *"$(basename "${BASH_SOURCE[0]}")"* ]]; then
    return 0 2>/dev/null || true
fi
_SENTINEL_LIB_LOADED="${_SENTINEL_LIB_LOADED:-} $(basename "${BASH_SOURCE[0]}")"

set -Eeuo pipefail
IFS=$'\n\t'

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=logger.sh
source "${SCRIPT_DIR}/logger.sh"

check_file_permissions() {
    local -r path="${1}"

    if [[ ! -e "${path}" ]]; then
        log_error "Path does not exist: ${path}"
        return 1
    fi

    local mode
    mode="$(stat -c '%a' "${path}" 2>/dev/null || stat -f '%Lp' "${path}" 2>/dev/null)"

    local owner
    owner="$(stat -c '%U' "${path}" 2>/dev/null || stat -f '%Su' "${path}" 2>/dev/null)"

    local group
    group="$(stat -c '%G' "${path}" 2>/dev/null || stat -f '%Sg' "${path}" 2>/dev/null)"

    local perms
    perms="$(stat -c '%A' "${path}" 2>/dev/null || stat -f '%Sp' "${path}" 2>/dev/null)"

    printf 'path=%s\n' "${path}"
    printf 'mode=%s\n' "${mode}"
    printf 'owner=%s\n' "${owner}"
    printf 'group=%s\n' "${group}"
    printf 'perms=%s\n' "${perms}"
    printf 'suid=%s\n' "$(is_suid "${path}" && echo true || echo false)"
    printf 'sgid=%s\n' "$(is_sgid "${path}" && echo true || echo false)"
    printf 'sticky=%s\n' "$(is_sticky "${path}" && echo true || echo false)"
    printf 'world_writable=%s\n' "$(is_world_writable "${path}" && echo true || echo false)"
    printf 'symlink=%s\n' "$(is_symlink "${path}" && echo true || echo false)"
    printf 'broken_symlink=%s\n' "$(is_broken_symlink "${path}" && echo true || echo false)"
}

is_world_writable() {
    local -r path="${1}"

    if [[ ! -e "${path}" && ! -L "${path}" ]]; then
        return 1
    fi

    local mode
    mode="$(stat -c '%a' "${path}" 2>/dev/null || stat -f '%Lp' "${path}" 2>/dev/null)"

    # Last digit of octal mode represents others' permissions
    local others="${mode: -1}"

    # Check if write bit (2) is set for others
    if [[ $(( others & 2 )) -ne 0 ]]; then
        return 0
    fi

    return 1
}

is_suid() {
    local -r path="${1}"

    if [[ ! -e "${path}" && ! -L "${path}" ]]; then
        return 1
    fi

    local perms
    perms="$(stat -c '%A' "${path}" 2>/dev/null || stat -f '%Sp' "${path}" 2>/dev/null)"

    if [[ "${perms}" == *s* || "${perms}" == *S* ]]; then
        return 0
    fi

    local mode
    mode="$(stat -c '%a' "${path}" 2>/dev/null || stat -f '%Lp' "${path}" 2>/dev/null)"

    # Check setuid bit (4000)
    if [[ $(( 8#${mode} & 8#4000 )) -ne 0 ]]; then
        return 0
    fi

    return 1
}

is_sgid() {
    local -r path="${1}"

    if [[ ! -e "${path}" && ! -L "${path}" ]]; then
        return 1
    fi

    local perms
    perms="$(stat -c '%A' "${path}" 2>/dev/null || stat -f '%Sp' "${path}" 2>/dev/null)"

    if [[ "${perms}" == *s* || "${perms}" == *S* ]]; then
        # Distinguish between suid and sgid in the permissions string
        local group_perms="${perms:5:3}"
        if [[ "${group_perms}" == *s* || "${group_perms}" == *S* ]]; then
            return 0
        fi
    fi

    local mode
    mode="$(stat -c '%a' "${path}" 2>/dev/null || stat -f '%Lp' "${path}" 2>/dev/null)"

    # Check setgid bit (2000)
    if [[ $(( 8#${mode} & 8#2000 )) -ne 0 ]]; then
        return 0
    fi

    return 1
}

is_sticky() {
    local -r path="${1}"

    if [[ ! -e "${path}" && ! -L "${path}" ]]; then
        return 1
    fi

    local perms
    perms="$(stat -c '%A' "${path}" 2>/dev/null || stat -f '%Sp' "${path}" 2>/dev/null)"

    # Sticky bit shows as 't' or 'T' in others execute position
    if [[ "${perms}" == *t || "${perms}" == *T ]]; then
        return 0
    fi

    local mode
    mode="$(stat -c '%a' "${path}" 2>/dev/null || stat -f '%Lp' "${path}" 2>/dev/null)"

    # Check sticky bit (1000)
    if [[ $(( 8#${mode} & 8#1000 )) -ne 0 ]]; then
        return 0
    fi

    return 1
}

has_dangerous_capabilities() {
    local -r path="${1}"

    if [[ ! -f "${path}" ]]; then
        return 1
    fi

    if ! command -v getcap >/dev/null 2>&1; then
        return 1
    fi

    local caps
    caps="$(getcap "${path}" 2>/dev/null)" || return 1

    if [[ -z "${caps}" ]]; then
        return 1
    fi

    # Check for dangerous capabilities
    local dangerous_caps=(
        cap_setuid
        cap_setgid
        cap_dac_override
        cap_dac_read_search
        cap_sys_admin
        cap_sys_ptrace
        cap_net_admin
        cap_net_raw
        cap_sys_module
        cap_sys_rawio
    )

    local cap
    for cap in "${dangerous_caps[@]}"; do
        if [[ "${caps}" == *"${cap}"* ]]; then
            return 0
        fi
    done

    return 1
}

get_capabilities() {
    local -r path="${1}"

    if [[ ! -f "${path}" ]]; then
        printf ''
        return 1
    fi

    if ! command -v getcap >/dev/null 2>&1; then
        printf ''
        return 1
    fi

    getcap "${path}" 2>/dev/null || printf ''
}

check_directory_permissions() {
    local -r path="${1}"
    local -r max_depth="${2:-1}"

    if [[ ! -d "${path}" ]]; then
        log_error "Directory not found: ${path}"
        return 1
    fi

    local file
    local mode
    local issues=0

    while IFS= read -r -d '' file; do
        if [[ ! -e "${file}" ]]; then
            continue
        fi

        mode="$(stat -c '%a' "${file}" 2>/dev/null || stat -f '%Lp' "${file}" 2>/dev/null)"

        if is_world_writable "${file}"; then
            log_warning "World-writable: ${file} (${mode})"
            (( issues++ ))
        fi

        if is_suid "${file}"; then
            log_warning "SUID: ${file} (${mode})"
            (( issues++ ))
        fi

        if is_sgid "${file}"; then
            log_warning "SGID: ${file} (${mode})"
            (( issues++ ))
        fi

        if has_dangerous_capabilities "${file}"; then
            local caps
            caps="$(get_capabilities "${file}")"
            log_warning "Dangerous capabilities: ${file} (${caps})"
            (( issues++ ))
        fi
    done < <(find "${path}" -maxdepth "${max_depth}" -print0 2>/dev/null)

    printf '%s' "${issues}"
}

is_symlink() {
    local -r path="${1}"

    if [[ -L "${path}" ]]; then
        return 0
    fi

    return 1
}

is_broken_symlink() {
    local -r path="${1}"

    if [[ -L "${path}" && ! -e "${path}" ]]; then
        return 0
    fi

    return 1
}

check_sticky_bit() {
    local -r path="${1}"

    if is_sticky "${path}"; then
        return 0
    fi

    return 1
}

permission_string() {
    local -r mode="${1}"
    local result=""
    local octal="${mode}"

    # Pad to 4 digits if needed
    while [[ "${#octal}" -lt 4 ]]; do
        octal="0${octal}"
    done

    # Owner permissions
    local owner_digit="${octal:0:1}"
    case "${owner_digit}" in
        0) result+="---" ;;
        1) result+="--x" ;;
        2) result+="-w-" ;;
        3) result+="-wx" ;;
        4) result+="r--" ;;
        5) result+="r-x" ;;
        6) result+="rw-" ;;
        7) result+="rwx" ;;
        *) result+="---" ;;
    esac

    # Group permissions
    local group_digit="${octal:1:1}"
    case "${group_digit}" in
        0) result+="---" ;;
        1) result+="--x" ;;
        2) result+="-w-" ;;
        3) result+="-wx" ;;
        4) result+="r--" ;;
        5) result+="r-x" ;;
        6) result+="rw-" ;;
        7) result+="rwx" ;;
        *) result+="---" ;;
    esac

    # Others permissions
    local others_digit="${octal:2:1}"
    case "${others_digit}" in
        0) result+="---" ;;
        1) result+="--x" ;;
        2) result+="-w-" ;;
        3) result+="-wx" ;;
        4) result+="r--" ;;
        5) result+="r-x" ;;
        6) result+="rw-" ;;
        7) result+="rwx" ;;
        *) result+="---" ;;
    esac

    # Special bits
    local special_digit="${octal:3:1}"
    local owner_x="${result:2:1}"
    local group_x="${result:5:1}"
    local others_x="${result:8:1}"

    case "${special_digit}" in
        1)
            if [[ "${others_x}" == "x" ]]; then
                result="${result:0:8}t${result:9}"
            else
                result="${result:0:8}T${result:9}"
            fi
            ;;
        2)
            if [[ "${group_x}" == "x" ]]; then
                result="${result:0:5}s${result:6}"
            else
                result="${result:0:5}S${result:6}"
            fi
            ;;
        3)
            if [[ "${others_x}" == "x" ]]; then
                result="${result:0:8}t${result:9}"
            else
                result="${result:0:8}T${result:9}"
            fi
            if [[ "${group_x}" == "x" ]]; then
                result="${result:0:5}s${result:6}"
            else
                result="${result:0:5}S${result:6}"
            fi
            ;;
        4)
            if [[ "${owner_x}" == "x" ]]; then
                result="${result:0:2}s${result:3}"
            else
                result="${result:0:2}S${result:3}"
            fi
            ;;
        5)
            if [[ "${owner_x}" == "x" ]]; then
                result="${result:0:2}s${result:3}"
            else
                result="${result:0:2}S${result:3}"
            fi
            if [[ "${others_x}" == "x" ]]; then
                result="${result:0:8}t${result:9}"
            else
                result="${result:0:8}T${result:9}"
            fi
            ;;
        6)
            if [[ "${owner_x}" == "x" ]]; then
                result="${result:0:2}s${result:3}"
            else
                result="${result:0:2}S${result:3}"
            fi
            if [[ "${group_x}" == "x" ]]; then
                result="${result:0:5}s${result:6}"
            else
                result="${result:0:5}S${result:6}"
            fi
            ;;
        7)
            if [[ "${owner_x}" == "x" ]]; then
                result="${result:0:2}s${result:3}"
            else
                result="${result:0:2}S${result:3}"
            fi
            if [[ "${group_x}" == "x" ]]; then
                result="${result:0:5}s${result:6}"
            else
                result="${result:0:5}S${result:6}"
            fi
            if [[ "${others_x}" == "x" ]]; then
                result="${result:0:8}t${result:9}"
            else
                result="${result:0:8}T${result:9}"
            fi
            ;;
    esac

    printf '%s' "${result}"
}
