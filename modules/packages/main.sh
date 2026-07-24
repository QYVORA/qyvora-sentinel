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

readonly MODULE_NAME="packages"
readonly MODULE_DESCRIPTION="Package management security audit"
readonly MODULE_VERSION="1.0.0"
readonly MODULE_SEVERITY_THRESHOLD="info"

readonly -a APT_PATHS=(
    "/etc/apt/sources.list"
    "/etc/apt/sources.list.d"
    "/etc/apt/apt.conf.d"
)

readonly -a YUM_PATHS=(
    "/etc/yum.repos.d"
    "/etc/yum.conf"
    "/etc/dnf/dnf.conf"
    "/etc/yum/vars"
)

readonly -a PACMAN_PATHS=(
    "/etc/pacman.conf"
    "/etc/pacman.d"
)

_detect_package_manager() {
    print_subheader "Package Manager Detection"

    local pm_name="unknown"
    local pm_version="unknown"

    if command -v apt &>/dev/null; then
        pm_name="apt"
        pm_version=$(apt --version 2>/dev/null | head -1 | awk '{print $2}' || echo "unknown")
    elif command -v dnf &>/dev/null; then
        pm_name="dnf"
        pm_version=$(dnf --version 2>/dev/null | head -1 | awk '{print $2}' || echo "unknown")
    elif command -v yum &>/dev/null; then
        pm_name="yum"
        pm_version=$(yum --version 2>/dev/null | head -1 || echo "unknown")
    elif command -v pacman &>/dev/null; then
        pm_name="pacman"
        pm_version=$(pacman --version 2>/dev/null | head -1 | awk '{print $3}' || echo "unknown")
    elif command -v zypper &>/dev/null; then
        pm_name="zypper"
        pm_version=$(zypper --version 2>/dev/null | awk '{print $2}' || echo "unknown")
    elif command -v apk &>/dev/null; then
        pm_name="apk"
        pm_version=$(apk --version 2>/dev/null || echo "unknown")
    fi

    if [[ "${pm_name}" == "unknown" ]]; then
        add_finding "packages" "No supported package manager found" "info" \
            "package_manager=not_found"
        print_warning "No supported package manager detected"
    else
        add_finding "packages" "Package manager: ${pm_name} ${pm_version}" "info" \
            "package_manager=${pm_name} version=${pm_version}"
        print_success "Package manager: ${pm_name} ${pm_version}"
    fi
}

_recently_installed() {
    print_subheader "Recently Installed Packages (Last 30 Days)"

    local pm_name="unknown"

    if command -v apt &>/dev/null; then
        pm_name="apt"
    elif command -v dnf &>/dev/null; then
        pm_name="dnf"
    elif command -v yum &>/dev/null; then
        pm_name="yum"
    elif command -v pacman &>/dev/null; then
        pm_name="pacman"
    elif command -v zypper &>/dev/null; then
        pm_name="zypper"
    fi

    local recent_packages=""
    local count=0

    case "${pm_name}" in
        apt)
            recent_packages=$(apt list --installed 2>/dev/null | tail -n +2 || true)
            count=$(echo "${recent_packages}" | grep -c . || echo "0")
            ;;
        dnf|yum)
            if command -v dnf &>/dev/null; then
                recent_packages=$(dnf list installed --installedsince="$(date -d '30 days ago' '+%Y-%m-%d' 2>/dev/null || date -v-30d '+%Y-%m-%d' 2>/dev/null || echo '2024-01-01')" 2>/dev/null | tail -n +2 || true)
            elif command -v yum &>/dev/null; then
                recent_packages=$(yum list installed 2>/dev/null | tail -n +2 || true)
            fi
            count=$(echo "${recent_packages}" | grep -c . || echo "0")
            ;;
        pacman)
            if [[ -d /var/log ]]; then
                recent_packages=$(grep -h "installed" /var/log/pacman.log 2>/dev/null | tail -20 || true)
                count=$(echo "${recent_packages}" | grep -c . || echo "0")
            fi
            ;;
    esac

    if [[ "${count}" -gt 0 ]]; then
        add_finding "packages" "Recently installed packages: ${count}" "info" \
            "recent_packages=count:${count}"
        print_success "Recently installed packages: ${count}"

        local display_count=10
        local shown=0
        while IFS= read -r pkg; do
            [[ -z "${pkg}" ]] && continue
            shown=$((shown + 1))
            if [[ "${shown}" -le "${display_count}" ]]; then
                print_finding "info" "  ${pkg}"
            fi
        done <<< "${recent_packages}"

        if [[ "${count}" -gt "${display_count}" ]]; then
            print_finding "info" "  ... and $((count - display_count)) more"
        fi
    else
        print_success "Unable to determine recently installed packages"
    fi
}

_security_updates() {
    print_subheader "Available Security Updates"

    local pm_name="unknown"

    if command -v apt &>/dev/null; then
        pm_name="apt"
    elif command -v dnf &>/dev/null; then
        pm_name="dnf"
    elif command -v yum &>/dev/null; then
        pm_name="yum"
    elif command -v pacman &>/dev/null; then
        pm_name="pacman"
    elif command -v zypper &>/dev/null; then
        pm_name="zypper"
    fi

    case "${pm_name}" in
        apt)
            local updates
            updates=$(apt list --upgradable 2>/dev/null | grep -i secur || true)
            local count
            count=$(echo "${updates}" | grep -c . || echo "0")

            if [[ "${count}" -gt 0 ]]; then
                add_finding "packages" "Pending security updates: ${count}" "high" \
                    "security_updates=count:${count}" \
                    "Apply security updates: apt upgrade"
                print_warning "Pending security updates: ${count}"

                while IFS= read -r pkg; do
                    [[ -z "${pkg}" ]] && continue
                    print_finding "info" "  ${pkg}"
                done <<< "${updates}"
            else
                add_finding "packages" "No pending security updates" "info" \
                    "security_updates=count:0"
                print_success "No pending security updates"
            fi
            ;;
        dnf)
            local security_updates
            security_updates=$(dnf check-update --security 2>/dev/null | tail -n +3 || true)
            local count
            count=$(echo "${security_updates}" | grep -c . || echo "0")

            if [[ "${count}" -gt 0 ]]; then
                add_finding "packages" "Pending security updates: ${count}" "high" \
                    "security_updates=count:${count}" \
                    "Apply security updates: dnf update --security"
                print_warning "Pending security updates: ${count}"
            else
                add_finding "packages" "No pending security updates" "info" \
                    "security_updates=count:0"
                print_success "No pending security updates"
            fi
            ;;
        yum)
            local security_updates
            security_updates=$(yum check-update --security 2>/dev/null | tail -n +3 || true)
            local count
            count=$(echo "${security_updates}" | grep -c . || echo "0")

            if [[ "${count}" -gt 0 ]]; then
                add_finding "packages" "Pending security updates: ${count}" "high" \
                    "security_updates=count:${count}" \
                    "Apply security updates: yum update --security"
                print_warning "Pending security updates: ${count}"
            else
                add_finding "packages" "No pending security updates" "info" \
                    "security_updates=count:0"
                print_success "No pending security updates"
            fi
            ;;
        zypper)
            local security_updates
            security_updates=$(zypper list-updates --security 2>/dev/null | tail -n +4 || true)
            local count
            count=$(echo "${security_updates}" | grep -c . || echo "0")

            if [[ "${count}" -gt 0 ]]; then
                add_finding "packages" "Pending security updates: ${count}" "high" \
                    "security_updates=count:${count}" \
                    "Apply security updates: zypper update"
                print_warning "Pending security updates: ${count}"
            else
                add_finding "packages" "No pending security updates" "info" \
                    "security_updates=count:0"
                print_success "No pending security updates"
            fi
            ;;
        *)
            print_warning "Cannot check security updates for unknown package manager"
            ;;
    esac
}

_third_party_repos() {
    print_subheader "Third-Party Repository Check"

    local repos_found=0
    local suspicious_repos=()

    if [[ -f /etc/apt/sources.list ]]; then
        while IFS= read -r line; do
            [[ -z "${line}" ]] && continue
            [[ "${line}" =~ ^#.*$ ]] && continue
            [[ "${line}" =~ ^deb[[:space:]] ]] || continue

            repos_found=$((repos_found + 1))

            local repo_url
            repo_url=$(echo "${line}" | awk '{print $2}' | sed 's|/.*||')

            local official_repos=("deb.debian.org" "archive.ubuntu.com" "security.ubuntu.com" "ports.ubuntu.com")
            local is_official=false

            for official in "${official_repos[@]}"; do
                if [[ "${repo_url}" == *"${official}"* ]]; then
                    is_official=true
                    break
                fi
            done

            if [[ "${is_official}" == false ]]; then
                suspicious_repos+=("${line}")
            fi
        done < /etc/apt/sources.list
    fi

    if [[ -d /etc/apt/sources.list.d ]]; then
        for sources_file in /etc/apt/sources.list.d/*.list /etc/apt/sources.list.d/*.sources; do
            [[ -f "${sources_file}" ]] || continue
            while IFS= read -r line; do
                [[ -z "${line}" ]] && continue
                [[ "${line}" =~ ^#.*$ ]] && continue
                [[ "${line}" =~ ^deb[[:space:]] ]] || continue

                repos_found=$((repos_found + 1))
                suspicious_repos+=("${line}")
            done < "${sources_file}"
        done
    fi

    if [[ -d /etc/yum.repos.d ]]; then
        for repo_file in /etc/yum.repos.d/*.repo; do
            [[ -f "${repo_file}" ]] || continue
            local enabled
            enabled=$(grep -E '^enabled\s*=\s*1' "${repo_file}" 2>/dev/null || true)

            if [[ -n "${enabled}" ]]; then
                repos_found=$((repos_found + 1))

                local baseurl
                baseurl=$(grep -E '^baseurl\s*=' "${repo_file}" 2>/dev/null | head -1 | awk -F= '{print $2}' | sed 's/^[[:space:]]*//' || true)

                if [[ -n "${baseurl}" ]] && [[ "${baseurl}" != *"rpm.org"* ]] && [[ "${baseurl}" != *"centos.org"* ]] && [[ "${baseurl}" != *"redhat.com"* ]] && [[ "${baseurl}" != *"fedoraproject.org"* ]]; then
                    suspicious_repos+=("${repo_file}: ${baseurl}")
                fi
            fi
        done
    fi

    if [[ -f /etc/pacman.conf ]]; then
        while IFS= read -r line; do
            [[ -z "${line}" ]] && continue
            [[ "${line}" =~ ^#.*$ ]] && continue
            [[ "${line}" =~ ^\[.*\] ]] && continue
            [[ "${line}" =~ ^Server ]] || continue

            repos_found=$((repos_found + 1))
            suspicious_repos+=("${line}")
        done < /etc/pacman.conf
    fi

    add_finding "packages" "Total repositories configured: ${repos_found}" "info" \
        "repositories=count:${repos_found}"
    print_success "Total repositories: ${repos_found}"

    if [[ "${#suspicious_repos[@]}" -gt 0 ]]; then
        add_finding "packages" "Third-party repositories: ${#suspicious_repos[@]}" "low" \
            "third_party_repos=count:${#suspicious_repos[@]}" \
            "Review third-party repositories for trustworthiness."
        print_warning "Third-party repositories: ${#suspicious_repos[@]}"

        for repo in "${suspicious_repos[@]}"; do
            print_finding "info" "  ${repo}"
        done
    fi
}

_signature_verification() {
    print_subheader "Package Signature Verification"

    if command -v apt-key &>/dev/null; then
        local keys
        keys=$(apt-key list 2>/dev/null | grep -c "pub\|sub" || echo "0")

        if [[ "${keys}" -gt 0 ]]; then
            add_finding "packages" "GPG keys for apt: ${keys}" "info" \
                "gpg_keys=count:${keys}"
            print_success "GPG keys for apt: ${keys}"
        fi
    fi

    if command -v rpm &>/dev/null; then
        local rpm_keys
        rpm_keys=$(rpm -qa gpg-pubkey 2>/dev/null | wc -l || echo "0")

        if [[ "${rpm_keys}" -gt 0 ]]; then
            add_finding "packages" "RPM GPG keys: ${rpm_keys}" "info" \
                "rpm_keys=count:${rpm_keys}"
            print_success "RPM GPG keys: ${rpm_keys}"
        fi
    fi

    if command -v pacman &>/dev/null; then
        if [[ -d /etc/pacman.d/gnupg ]]; then
            local pacman_keys
            pacman_keys=$(pacman-key --list-keys 2>/dev/null | grep -c "pub\|sub" || echo "0")

            if [[ "${pacman_keys}" -gt 0 ]]; then
                add_finding "packages" "Pacman GPG keys: ${pacman_keys}" "info" \
                    "pacman_keys=count:${pacman_keys}"
                print_success "Pacman GPG keys: ${pacman_keys}"
            fi
        fi
    fi
}

_package_integrity() {
    print_subheader "Package Database Integrity"

    if command -v debsums &>/dev/null; then
        local modified
        modified=$(debsums --changed 2>/dev/null || true)

        if [[ -n "${modified}" ]]; then
            local count
            count=$(echo "${modified}" | grep -c . || echo "0")
            add_finding "packages" "Modified packages detected: ${count}" "high" \
                "modified_packages=count:${count}" \
                "Investigate modified package files."
            print_error "Modified packages detected: ${count}"

            while IFS= read -r pkg; do
                [[ -z "${pkg}" ]] && continue
                print_finding "info" "  ${pkg}"
            done <<< "${modified}"
        else
            add_finding "packages" "No modified packages detected (debsums)" "info" \
                "modified_packages=count:0"
            print_success "No modified packages detected"
        fi
    elif command -v rpm &>/dev/null; then
        local rpm_verify
        rpm_verify=$(rpm -Va 2>/dev/null | grep -v "^$" | grep -c "^..5" || echo "0")

        if [[ "${rpm_verify}" -gt 0 ]]; then
            add_finding "packages" "RPM packages with modified files: ${rpm_verify}" "high" \
                "modified_packages=count:${rpm_verify}" \
                "Investigate modified package files."
            print_error "RPM packages with modified files: ${rpm_verify}"
        else
            add_finding "packages" "RPM package integrity OK" "info" \
                "rpm_verify=status:ok"
            print_success "RPM package integrity OK"
        fi
    elif command -v pacman &>/dev/null; then
        local pacman_verify
        pacman_verify=$(pacman -Qk 2>/dev/null | grep -c "warning" || echo "0")

        if [[ "${pacman_verify}" -gt 0 ]]; then
            add_finding "packages" "Pacman package issues: ${pacman_verify}" "high" \
                "package_issues=count:${pacman_verify}" \
                "Reinstall affected packages."
            print_error "Pacman package issues: ${pacman_verify}"
        else
            add_finding "packages" "Pacman package integrity OK" "info" \
                "pacman_verify=status:ok"
            print_success "Pacman package integrity OK"
        fi
    else
        add_finding "packages" "No integrity checking tool available" "info" \
            "integrity_check=not_available" \
            "Install debsums, rpm, or use pacman -Qk."
        print_warning "No integrity checking tool available"
    fi
}

_orphaned_packages() {
    print_subheader "Orphaned Packages"

    if command -v apt &>/dev/null; then
        local orphans
        orphans=$(apt-mark showmanual 2>/dev/null | while read -r pkg; do
            apt-cache rdepends --installed "${pkg}" 2>/dev/null | grep -c "^  ${pkg}$" || echo "0"
        done | grep -c "^0$" || echo "0")

        if [[ "${orphans}" -gt 0 ]]; then
            add_finding "packages" "Potentially orphaned packages: ${orphans}" "low" \
                "orphaned_packages=count:${orphans}" \
                "Review and remove unnecessary packages."
            print_warning "Potentially orphaned packages: ${orphans}"
        else
            add_finding "packages" "No obviously orphaned packages" "info" \
                "orphaned_packages=count:0"
            print_success "No obviously orphaned packages"
        fi
    elif command -v pacman &>/dev/null; then
        local orphans
        orphans=$(pacman -Qdtq 2>/dev/null || true)

        if [[ -n "${orphans}" ]]; then
            local count
            count=$(echo "${orphans}" | grep -c . || echo "0")
            add_finding "packages" "Orphaned packages: ${count}" "low" \
                "orphaned_packages=count:${count}" \
                "Remove with: pacman -Rns \$(pacman -Qdtq)"
            print_warning "Orphaned packages: ${count}"
        else
            add_finding "packages" "No orphaned packages" "info" \
                "orphaned_packages=count:0"
            print_success "No orphaned packages"
        fi
    elif command -v dnf &>/dev/null; then
        local orphans
        orphans=$(dnf repoquery --extras --installed 2>/dev/null || true)

        if [[ -n "${orphans}" ]]; then
            local count
            count=$(echo "${orphans}" | grep -c . || echo "0")
            add_finding "packages" "Potentially orphaned packages: ${count}" "low" \
                "orphaned_packages=count:${count}" \
                "Review and remove unnecessary packages."
            print_warning "Potentially orphaned packages: ${count}"
        else
            add_finding "packages" "No obviously orphaned packages" "info" \
                "orphaned_packages=count:0"
            print_success "No obviously orphaned packages"
        fi
    fi
}

_manually_installed() {
    print_subheader "Manually Installed Packages"

    if command -v apt &>/dev/null; then
        local manual
        manual=$(apt-mark showmanual 2>/dev/null || true)

        if [[ -n "${manual}" ]]; then
            local count
            count=$(echo "${manual}" | grep -c . || echo "0")
            add_finding "packages" "Manually installed packages: ${count}" "info" \
                "manual_packages=count:${count}"
            print_success "Manually installed packages: ${count}"
        fi
    elif command -v pacman &>/dev/null; then
        local explicit
        explicit=$(pacman -Qe 2>/dev/null || true)

        if [[ -n "${explicit}" ]]; then
            local count
            count=$(echo "${explicit}" | grep -c . || echo "0")
            add_finding "packages" "Explicitly installed packages: ${count}" "info" \
                "explicit_packages=count:${count}"
            print_success "Explicitly installed packages: ${count}"
        fi
    fi
}

_sources_list_check() {
    print_subheader "Repository Configuration Files"

    local files_checked=0

    for sources_file in /etc/apt/sources.list /etc/apt/sources.list.d/*.list /etc/apt/sources.list.d/*.sources; do
        [[ -f "${sources_file}" ]] || continue
        files_checked=$((files_checked + 1))

        local has_unsigned
        has_unsigned=$(grep -E '^deb\s+[^[]+\s+[a-z]+\s+[^ ]*$' "${sources_file}" 2>/dev/null | grep -v "trusty\|xenial\|bionic\|focal\|jammy" || true)

        if [[ -n "${has_unsigned}" ]]; then
            add_finding "packages" "Repository without explicit signing: ${sources_file}" "low" \
                "file=${sources_file}" \
                "Add [signed-by=/path/to/key.gpg] to repository entries."
            print_warning "Repository without signing: ${sources_file}"
        fi
    done

    for repo_file in /etc/yum.repos.d/*.repo /etc/yum.conf; do
        [[ -f "${repo_file}" ]] || continue
        files_checked=$((files_checked + 1))

        local gpgcheck
        gpgcheck=$(grep -E "^gpgcheck\s*=\s*0" "${repo_file}" 2>/dev/null || true)

        if [[ -n "${gpgcheck}" ]]; then
            add_finding "packages" "GPG check disabled: ${repo_file}" "high" \
                "file=${repo_file}" \
                "Enable GPG check: gpgcheck=1"
            print_error "GPG check disabled: ${repo_file}"
        fi
    done

    if [[ -f /etc/pacman.conf ]]; then
        files_checked=$((files_checked + 1))

        local siglevel
        siglevel=$(grep -E '^SigLevel\s*=\s*Never' /etc/pacman.conf 2>/dev/null || true)

        if [[ -n "${siglevel}" ]]; then
            add_finding "packages" "Pacman signature verification disabled" "high" \
                "file=/etc/pacman.conf" \
                "Enable signature verification: SigLevel = Required DatabaseOptional"
            print_error "Pacman signature verification disabled"
        fi
    fi

    if [[ "${files_checked}" -gt 0 ]]; then
        add_finding "packages" "Repository files checked: ${files_checked}" "info" \
            "repo_files=count:${files_checked}"
        print_success "Repository files checked: ${files_checked}"
    fi
}

_gpg_key_trust() {
    print_subheader "GPG Key Trust"

    if command -v apt-key &>/dev/null; then
        local keys
        keys=$(apt-key list 2>/dev/null | grep -E "^\s*[0-9a-f]{8}" | head -5 || true)

        if [[ -n "${keys}" ]]; then
            print_finding "info" "  Sample apt GPG keys:"
            while IFS= read -r key; do
                [[ -z "${key}" ]] && continue
                print_finding "info" "    ${key}"
            done <<< "${keys}"
        fi
    fi

    if command -v gpg &>/dev/null; then
        local gpg_home="${HOME}/.gnupg"
        if [[ -d "${gpg_home}" ]]; then
            local trusted_keys
            trusted_keys=$(gpg --homedir "${gpg_home}" --list-keys 2>/dev/null | grep -c "^pub" || echo "0")

            if [[ "${trusted_keys}" -gt 0 ]]; then
                add_finding "packages" "User GPG keys: ${trusted_keys}" "info" \
                    "user_gpg_keys=count:${trusted_keys}"
                print_success "User GPG keys: ${trusted_keys}"
            fi
        fi
    fi
}

_database_integrity() {
    print_subheader "Package Database Integrity"

    if command -v apt &>/dev/null; then
        if apt-cache policy &>/dev/null 2>&1; then
            add_finding "packages" "APT package cache: OK" "info" \
                "apt_cache=status:ok"
            print_success "APT package cache: OK"
        else
            add_finding "packages" "APT package cache may be corrupted" "high" \
                "apt_cache=status:error" \
                "Run: apt clean && apt update"
            print_error "APT package cache may be corrupted"
        fi
    fi

    if command -v rpm &>/dev/null; then
        local rpmdb
        rpmdb --rebuilddb 2>/dev/null && {
            add_finding "packages" "RPM database: OK" "info" \
                "rpmdb=status:ok"
            print_success "RPM database: OK"
        } || {
            add_finding "packages" "RPM database rebuild failed" "high" \
                "rpmdb=status:error" \
                "Investigate RPM database corruption."
            print_error "RPM database rebuild failed"
        }
    fi

    if command -v pacman &>/dev/null; then
        if [[ -d /var/lib/pacman/local ]]; then
            local db_files
            db_files=$(find /var/lib/pacman/local -name "desc" 2>/dev/null | wc -l || echo "0")

            if [[ "${db_files}" -gt 0 ]]; then
                add_finding "packages" "Pacman database: ${db_files} packages indexed" "info" \
                    "pacman_db=count:${db_files}"
                print_success "Pacman database: ${db_files} packages indexed"
            fi
        fi
    fi
}

run() {
    print_header "Package Management Security Audit"

    _detect_package_manager
    _recently_installed
    _security_updates
    _third_party_repos
    _signature_verification
    _package_integrity
    _orphaned_packages
    _manually_installed
    _sources_list_check
    _gpg_key_trust
    _database_integrity
}

if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    run
fi