#!/usr/bin/env bash
# baseline.sh - Baseline system for tracking system state changes for QYVORA Sentinel.
# Captures file hashes, services, users, cron jobs, ports, packages, and kernel modules.

# Source guard - prevent re-sourcing
if [[ "${_SENTINEL_LIB_LOADED:-}" == *"$(basename "${BASH_SOURCE[0]}")"* ]]; then
    return 0 2>/dev/null || true
fi
_SENTINEL_LIB_LOADED="${_SENTINEL_LIB_LOADED:-} $(basename "${BASH_SOURCE[0]}")"

set -Eeuo pipefail
IFS=$'\n\t'

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=colors.sh
source "${SCRIPT_DIR}/colors.sh"
# shellcheck source=logger.sh
source "${SCRIPT_DIR}/logger.sh"
# shellcheck source=utils.sh
source "${SCRIPT_DIR}/utils.sh"
# shellcheck source=validation.sh
source "${SCRIPT_DIR}/validation.sh"
# shellcheck source=hashing.sh
source "${SCRIPT_DIR}/hashing.sh"

# --- Global State ---
SENTINEL_BASELINE_DIR="${SENTINEL_BASELINE_DIR:-}"

# Baseline sections (readonly)
readonly SENTINEL_BASELINE_SECTIONS=(
    "file_hashes"
    "services"
    "users"
    "cron"
    "ports"
    "packages"
    "kernel_modules"
    "system_config"
)

# --- Initialization ---

baseline_init() {
    SENTINEL_BASELINE_DIR="${SENTINEL_BASELINE_DIR:-$(pwd)/baselines}"

    if [[ ! -d "${SENTINEL_BASELINE_DIR}" ]]; then
        mkdir -p "${SENTINEL_BASELINE_DIR}"
    fi

    log_debug "Baseline system initialized. Directory: ${SENTINEL_BASELINE_DIR}"
}

# --- Capture Functions ---

baseline_capture_file_hashes() {
    local -r dirs="${1:-/etc /usr/bin /usr/sbin /bin /sbin}"
    local -a target_dirs
    local OLDIFS="${IFS}"
    IFS=' '
    read -ra target_dirs <<< "${dirs}"
    IFS="${OLDIFS}"

    local dir
    for dir in "${target_dirs[@]}"; do
        if [[ -d "${dir}" ]]; then
            find "${dir}" -maxdepth 1 -type f 2>/dev/null | while IFS= read -r file; do
                local hash
                hash="$(md5sum "${file}" 2>/dev/null | awk '{print $1}')" || continue
                local perms
                perms="$(stat -c '%a %u %G' "${file}" 2>/dev/null)" || perms="0000 root root"
                printf 'FILE|%s|%s|%s\n' "${file}" "${hash}" "${perms}"
            done
        fi
    done
}

baseline_capture_services() {
    if command -v systemctl &>/dev/null; then
        systemctl list-units --type=service --all --no-pager --no-legend 2>/dev/null | \
            awk '{print $1, $3, $4}' | while IFS=' ' read -r name load active; do
                printf 'SERVICE|%s|%s|%s\n' "${name}" "${load}" "${active}"
            done
    elif command -v service &>/dev/null; then
        service --status-all 2>/dev/null | while IFS= read -r line; do
            local status name
            status="$(printf '%s' "${line}" | awk '{print $1}')"
            name="$(printf '%s' "${line}" | awk '{print $2}')"
            printf 'SERVICE|%s|%s|%s\n' "${name}" "unknown" "${status}"
        done
    else
        log_warning "No service manager found for service capture."
    fi
}

baseline_capture_users() {
    if [[ -f /etc/passwd ]]; then
        while IFS=: read -r username _ uid gid gecos home shell; do
            printf 'USER|%s|%s|%s|%s|%s\n' "${username}" "${uid}" "${gid}" "${home}" "${shell}"
        done < /etc/passwd
    fi
}

baseline_capture_cron() {
    local cron_entries=()

    # System crontabs
    if [[ -f /etc/crontab ]]; then
        while IFS= read -r line; do
            case "${line}" in
                '#'*|'') continue ;;
            esac
            cron_entries+=("SYSTEM|${line}")
        done < /etc/crontab
    fi

    # Cron directories
    local cron_dir
    for cron_dir in /etc/cron.d /etc/cron.daily /etc/cron.hourly /etc/cron.weekly /etc/cron.monthly; do
        if [[ -d "${cron_dir}" ]]; then
            local cron_file
            for cron_file in "${cron_dir}"/*; do
                [[ -f "${cron_file}" ]] || continue
                while IFS= read -r line; do
                    case "${line}" in
                        '#'*|'') continue ;;
                    esac
                    cron_entries+=("FILE|${cron_file}|${line}")
                done < "${cron_file}"
            done
        fi
    done

    # User crontabs
    local user_cron_dir="/var/spool/cron/crontabs"
    if [[ ! -d "${user_cron_dir}" ]]; then
        user_cron_dir="/var/spool/cron"
    fi

    if [[ -d "${user_cron_dir}" ]]; then
        local user_cron
        for user_cron in "${user_cron_dir}"/*; do
            [[ -f "${user_cron}" ]] || continue
            local user
            user="$(basename "${user_cron}")"
            while IFS= read -r line; do
                case "${line}" in
                    '#'*|'') continue ;;
                esac
                cron_entries+=("USER|${user}|${line}")
            done < "${user_cron}"
        done
    fi

    printf '%s\n' "${cron_entries[@]+"${cron_entries[@]}"}"
}

baseline_capture_ports() {
    if command -v ss &>/dev/null; then
        ss -tulnp 2>/dev/null | tail -n +2 | while IFS= read -r line; do
            local proto local_addr
            proto="$(printf '%s' "${line}" | awk '{print $1}')"
            local_addr="$(printf '%s' "${line}" | awk '{print $5}')"
            local process
            process="$(printf '%s' "${line}" | grep -oP 'users:\(\(.+?\)\)' 2>/dev/null || echo 'N/A')"
            printf 'PORT|%s|%s|%s\n' "${proto}" "${local_addr}" "${process}"
        done
    elif command -v netstat &>/dev/null; then
        netstat -tulnp 2>/dev/null | grep -E '^tcp|^udp' | while IFS= read -r line; do
            local proto local_addr
            proto="$(printf '%s' "${line}" | awk '{print $1}')"
            local_addr="$(printf '%s' "${line}" | awk '{print $4}')"
            local process
            process="$(printf '%s' "${line}" | awk '{print $7}' || echo 'N/A')"
            printf 'PORT|%s|%s|%s\n' "${proto}" "${local_addr}" "${process}"
        done
    else
        log_warning "No port scanning tool available."
    fi
}

baseline_capture_packages() {
    local os_family
    os_family="$(get_os_family)"

    case "${os_family}" in
        debian)
            if command -v dpkg &>/dev/null; then
                dpkg -l 2>/dev/null | awk '/^ii/ {print $2 "|" $3 "|" $4}'
            fi
            ;;
        rhel)
            if command -v rpm &>/dev/null; then
                rpm -qa --queryformat '%{NAME}|%{VERSION}-%{RELEASE}|%{ARCH}\n' 2>/dev/null
            fi
            ;;
        arch)
            if command -v pacman &>/dev/null; then
                pacman -Q 2>/dev/null | awk '{print $1 "|" $2 "|pkg"}'
            fi
            ;;
        alpine)
            if command -v apk &>/dev/null; then
                apk list -I 2>/dev/null | awk '{print $1 "|" $2 "|apk"}'
            fi
            ;;
        *)
            log_warning "Unsupported OS family for package capture: ${os_family}"
            ;;
    esac
}

baseline_capture_kernel_modules() {
    if [[ -f /proc/modules ]]; then
        while IFS=' ' read -r name size refcount usedby; do
            printf 'MODULE|%s|%s|%s|%s\n' "${name}" "${size}" "${refcount}" "${usedby}"
        done < /proc/modules
    fi
}

baseline_capture_system_config() {
    local -a config_files=(
        "/etc/hostname"
        "/etc/hosts"
        "/etc/resolv.conf"
        "/etc/fstab"
        "/etc/sysctl.conf"
        "/etc/ssh/sshd_config"
        "/etc/sudoers"
    )

    local config_file
    for config_file in "${config_files[@]}"; do
        if [[ -f "${config_file}" ]]; then
            local hash
            hash="$(md5sum "${config_file}" 2>/dev/null | awk '{print $1}')"
            local perms
            perms="$(stat -c '%a' "${config_file}" 2>/dev/null || echo '0000')"
            printf 'CONFIG|%s|%s|%s\n' "${config_file}" "${hash}" "${perms}"
        fi
    done
}

# --- Baseline Create ---

baseline_create() {
    local -r name="${1}"
    local timestamp
    timestamp="$(date -u '+%Y-%m-%dT%H:%M:%SZ')"
    local hostname
    hostname="$(get_hostname 2>/dev/null || echo 'unknown')"
    local kernel
    kernel="$(uname -r 2>/dev/null || echo 'unknown')"

    log_info "Creating baseline snapshot: ${name}"

    local baseline_file="${SENTINEL_BASELINE_DIR}/${name}.baseline"

    {
        echo "HEADER|${name}|${timestamp}|${hostname}|${kernel}"
        echo ""
        echo "# File Hashes"
        echo "SECTION|file_hashes"
        baseline_capture_file_hashes
        echo ""
        echo "SECTION|services"
        baseline_capture_services
        echo ""
        echo "SECTION|users"
        baseline_capture_users
        echo ""
        echo "SECTION|cron"
        baseline_capture_cron
        echo ""
        echo "SECTION|ports"
        baseline_capture_ports
        echo ""
        echo "SECTION|packages"
        baseline_capture_packages
        echo ""
        echo "SECTION|kernel_modules"
        baseline_capture_kernel_modules
        echo ""
        echo "SECTION|system_config"
        baseline_capture_system_config
        echo ""
        echo "END|${timestamp}"
    } > "${baseline_file}"

    log_info "Baseline '${name}' saved to ${baseline_file}"
    printf '%s' "${baseline_file}"
}

# --- Baseline Save / Load ---

baseline_save() {
    local -r data="${1}"
    local -r name="${2}"
    local baseline_file="${SENTINEL_BASELINE_DIR}/${name}.baseline"

    printf '%s\n' "${data}" > "${baseline_file}"
    log_debug "Baseline data saved to ${baseline_file}"
}

baseline_load() {
    local -r name="${1}"
    local baseline_file="${SENTINEL_BASELINE_DIR}/${name}.baseline"

    if [[ ! -f "${baseline_file}" ]]; then
        log_error "Baseline not found: ${name} (${baseline_file})"
        return 1
    fi

    cat "${baseline_file}"
}

# --- Baseline List / Delete ---

baseline_list() {
    if [[ ! -d "${SENTINEL_BASELINE_DIR}" ]]; then
        log_warning "Baseline directory does not exist."
        return 0
    fi

    local count=0
    local baseline_file
    for baseline_file in "${SENTINEL_BASELINE_DIR}"/*.baseline; do
        [[ -f "${baseline_file}" ]] || continue

        local bname btimestamp bhostname
        bname="$(basename "${baseline_file}" .baseline)"
        btimestamp="$(head -1 "${baseline_file}" 2>/dev/null | awk -F'|' '{print $3}')"
        bhostname="$(head -1 "${baseline_file}" 2>/dev/null | awk -F'|' '{print $4}')"

        printf '%-30s  %-20s  %s\n' "${bname}" "${btimestamp:-unknown}" "${bhostname:-unknown}"
        (( count++ ))
    done

    if [[ "${count}" -eq 0 ]]; then
        log_info "No baselines found."
    else
        log_info "Total baselines: ${count}"
    fi
}

baseline_delete() {
    local -r name="${1}"
    local baseline_file="${SENTINEL_BASELINE_DIR}/${name}.baseline"

    if [[ ! -f "${baseline_file}" ]]; then
        log_error "Baseline not found: ${name}"
        return 1
    fi

    rm -f "${baseline_file}"
    log_info "Baseline '${name}' deleted."
}

# --- Baseline Diff ---

baseline_diff() {
    local -r old_name="${1}"
    local -r new_name="${2}"

    local old_file="${SENTINEL_BASELINE_DIR}/${old_name}.baseline"
    local new_file="${SENTINEL_BASELINE_DIR}/${new_name}.baseline"

    if [[ ! -f "${old_file}" ]]; then
        log_error "Old baseline not found: ${old_name}"
        return 1
    fi

    if [[ ! -f "${new_file}" ]]; then
        log_error "New baseline not found: ${new_name}"
        return 1
    fi

    log_info "Comparing baselines: ${old_name} -> ${new_name}"
    echo ""

    # Extract section data from both files
    local -A old_sections=()
    local -A new_sections=()
    local current_section=""

    while IFS= read -r line; do
        case "${line}" in
            SECTION\|*)
                current_section="$(printf '%s' "${line}" | cut -d'|' -f2)"
                old_sections["${current_section}"]=""
                ;;
            HEADER\|*|END\|*|'') continue ;;
            *)
                if [[ -n "${current_section}" ]]; then
                    old_sections["${current_section}"]+="${line}"$'\n'
                fi
                ;;
        esac
    done < "${old_file}"

    current_section=""
    while IFS= read -r line; do
        case "${line}" in
            SECTION\|*)
                current_section="$(printf '%s' "${line}" | cut -d'|' -f2)"
                new_sections["${current_section}"]=""
                ;;
            HEADER\|*|END\|*|'') continue ;;
            *)
                if [[ -n "${current_section}" ]]; then
                    new_sections["${current_section}"]+="${line}"$'\n'
                fi
                ;;
        esac
    done < "${new_file}"

    local total_added=0
    local total_removed=0
    local total_changed=0

    local section
    for section in "${SENTINEL_BASELINE_SECTIONS[@]+"${SENTINEL_BASELINE_SECTIONS[@]}"}"; do
        local old_data="${old_sections[${section}]:-}"
        local new_data="${new_sections[${section}]:-}"

        local added=0 removed=0 changed=0

        # Build associative arrays of entries for comparison
        declare -A old_entries=()
        declare -A new_entries=()

        if [[ -n "${old_data}" ]]; then
            while IFS= read -r entry; do
                [[ -z "${entry}" ]] && continue
                local key
                key="$(printf '%s' "${entry}" | cut -d'|' -f2)"
                old_entries["${key}"]="${entry}"
            done <<< "${old_data}"
        fi

        if [[ -n "${new_data}" ]]; then
            while IFS= read -r entry; do
                [[ -z "${entry}" ]] && continue
                local key
                key="$(printf '%s' "${entry}" | cut -d'|' -f2)"
                new_entries["${key}"]="${entry}"
            done <<< "${new_data}"
        fi

        # Find removed entries (in old but not in new)
        local key
        for key in "${!old_entries[@]+"${!old_entries[@]}"}"; do
            if [[ -z "${new_entries[${key}]:-}" ]]; then
                (( removed++ ))
            fi
        done

        # Find added and changed entries (in new)
        for key in "${!new_entries[@]+"${!new_entries[@]}"}"; do
            if [[ -z "${old_entries[${key}]:-}" ]]; then
                (( added++ ))
            elif [[ "${old_entries[${key}]}" != "${new_entries[${key}]}" ]]; then
                (( changed++ ))
            fi
        done

        if [[ $(( added + removed + changed )) -gt 0 ]]; then
            echo "Section: ${section}"
            echo "  Added:    ${added}"
            echo "  Removed:  ${removed}"
            echo "  Changed:  ${changed}"
            echo ""
        fi

        (( total_added += added ))
        (( total_removed += removed ))
        (( total_changed += changed ))

        unset old_entries
        unset new_entries
    done

    echo "================================================================"
    echo "TOTALS: Added=${total_added}  Removed=${total_removed}  Changed=${total_changed}"
    echo "================================================================"

    # Return 0 with differences reported
    if [[ $(( total_added + total_removed + total_changed )) -gt 0 ]]; then
        log_info "Differences found: ${total_added} added, ${total_removed} removed, ${total_changed} changed"
    else
        log_info "No differences found between baselines."
    fi
    return 0
}

baseline_compare() {
    local -r old_name="${1}"
    local -r new_name="${2}"

    baseline_diff "${old_name}" "${new_name}"
}
