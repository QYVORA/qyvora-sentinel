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

MODULE_NAME="browser"
MODULE_DESCRIPTION="Browser artifact audit"
MODULE_VERSION="1.0.0"
MODULE_SEVERITY_THRESHOLD="low"

readonly -A BROWSER_NAMES=(
    ["chrome"]="Google Chrome"
    ["chromium"]="Chromium"
    ["firefox"]="Mozilla Firefox"
    ["edge"]="Microsoft Edge"
    ["opera"]="Opera"
    ["brave"]="Brave Browser"
)

readonly -a CREDENTIAL_FILES=(
    "logins.json"
    "signons.sqlite"
    "Login Data"
    "Login Data-journal"
    "cookies.sqlite"
    "Cookies"
    "formhistory.sqlite"
    "formhistory.json"
)

readonly -a SYNC_CONFIGS=(
    "Sync Data"
    "sync_config.json"
    "SyncSetup"
)

readonly -a CERTIFICATE_FILES=(
    "cert8.db"
    "cert9.db"
    "key4.db"
    "secmod.db"
)

declare -a HOME_DIRS=()
declare -i findings_count=0

run() {
    print_header "Browser Artifact Audit" "${MODULE_DESCRIPTION}"

    local start_time
    start_time=$(date +%s)

    initialize_home_dirs
    detect_browsers
    check_credential_files
    check_cookie_databases
    check_browser_extensions
    check_download_history
    check_profile_directories
    check_form_data
    check_sync_configurations
    check_browser_certificates
    check_bookmarks
    check_history_databases
    check_cached_credentials

    local end_time
    end_time=$(date +%s)
    local elapsed=$(( end_time - start_time ))

    print_success "Browser scan completed. Findings: ${findings_count} (${elapsed}s)"
    return 0
}

initialize_home_dirs() {
    HOME_DIRS=("${HOME}")
    local users_dir="/home"
    if [[ -d "${users_dir}" ]]; then
        while IFS= read -r userdir; do
            [[ -d "${userdir}" ]] && HOME_DIRS+=("${userdir}")
        done < <(find "${users_dir}" -mindepth 1 -maxdepth 1 -type d 2>/dev/null || true)
    fi
}

detect_browsers() {
    print_header "Detecting Installed Browsers"

    for browser in "${!BROWSER_NAMES[@]}"; do
        local browser_found=0
        local locations=()

        case "${browser}" in
            chrome)
                locations=("/usr/bin/google-chrome" "/usr/bin/google-chrome-stable"
                           "/opt/google/chrome/chrome" "/usr/bin/chrome")
                ;;
            chromium)
                locations=("/usr/bin/chromium" "/usr/bin/chromium-browser"
                           "/snap/bin/chromium")
                ;;
            firefox)
                locations=("/usr/bin/firefox" "/usr/lib/firefox/firefox"
                           "/snap/bin/firefox" "/usr/bin/firefox-esr")
                ;;
            edge)
                locations=("/usr/bin/microsoft-edge" "/usr/bin/microsoft-edge-stable")
                ;;
            opera)
                locations=("/usr/bin/opera" "/usr/bin/opera-stable")
                ;;
            brave)
                locations=("/usr/bin/brave-browser" "/usr/bin/brave-browser-stable"
                           "/opt/brave.com/brave/brave-browser")
                ;;
        esac

        for loc in "${locations[@]}"; do
            if [[ -f "${loc}" || -L "${loc}" ]]; then
                print_finding "info" "Browser installed" "${BROWSER_NAMES[$browser]} found at: ${loc}"
                ((findings_count++)) || true
                browser_found=1
                break
            fi
        done

        if [[ "${browser_found}" -eq 0 ]]; then
            local bin_loc
            bin_loc=$(command -v "${browser}" 2>/dev/null || true)
            if [[ -n "${bin_loc}" ]]; then
                print_finding "info" "Browser installed" "${BROWSER_NAMES[$browser]} found at: ${bin_loc}"
                ((findings_count++)) || true
            fi
        fi
    done
}

check_credential_files() {
    print_header "Checking for Stored Credentials"

    for home_dir in "${HOME_DIRS[@]}"; do
        [[ -d "${home_dir}" ]] || continue

        local firefox_profiles="${home_dir}/.mozilla/firefox"
        if [[ -d "${firefox_profiles}" ]]; then
            while IFS= read -r cred_file; do
                [[ -f "${cred_file}" ]] || continue
                local size
                size=$(stat -f%z "${cred_file}" 2>/dev/null || stat -c%s "${cred_file}" 2>/dev/null || echo 0)

                if [[ "${size}" -gt 0 ]]; then
                    add_finding "${MODULE_NAME}" "Stored browser credentials" "high" \
                        "Firefox credential file with data: ${cred_file} (${size} bytes)" "${cred_file}"
                    ((findings_count++)) || true
                fi
            done < <(find "${firefox_profiles}" \( -name "logins.json" -o -name "signons.sqlite" \) 2>/dev/null || true)
        fi

        local chrome_profiles="${home_dir}/.config/google-chrome/Default"
        local chromium_profiles="${home_dir}/.config/chromium/Default"

        for profile_dir in "${chrome_profiles}" "${chromium_profiles}"; do
            [[ -d "${profile_dir}" ]] || continue
            local login_data="${profile_dir}/Login Data"
            if [[ -f "${login_data}" ]]; then
                local size
                size=$(stat -c%s "${login_data}" 2>/dev/null || echo 0)

                if [[ "${size}" -gt 100 ]]; then
                    add_finding "${MODULE_NAME}" "Stored browser credentials" "high" \
                        "Chrome/Chromium login data found: ${login_data} (${size} bytes)" "${login_data}"
                    ((findings_count++)) || true
                fi
            fi
        done
    done
}

check_cookie_databases() {
    print_header "Checking for Cookie Databases"

    for home_dir in "${HOME_DIRS[@]}"; do
        [[ -d "${home_dir}" ]] || continue

        local firefox_cookies
        firefox_cookies=$(find "${home_dir}/.mozilla/firefox" -name "cookies.sqlite" 2>/dev/null || true)

        if [[ -n "${firefox_cookies}" ]]; then
            while IFS= read -r cookie; do
                local size
                size=$(stat -c%s "${cookie}" 2>/dev/null || echo 0)
                if [[ "${size}" -gt 1000 ]]; then
                    add_finding "${MODULE_NAME}" "Browser cookies database" "medium" \
                        "Firefox cookies database: ${cookie} (${size} bytes)" "${cookie}"
                    ((findings_count++)) || true
                fi
            done <<< "${firefox_cookies}"
        fi

        local chrome_cookies
        chrome_cookies=$(find "${home_dir}/.config" \( -path "*/google-chrome/*/Cookies" -o -path "*/chromium/*/Cookies" \) 2>/dev/null || true)

        if [[ -n "${chrome_cookies}" ]]; then
            while IFS= read -r cookie; do
                local size
                size=$(stat -c%s "${cookie}" 2>/dev/null || echo 0)
                if [[ "${size}" -gt 1000 ]]; then
                    add_finding "${MODULE_NAME}" "Browser cookies database" "medium" \
                        "Chrome/Chromium cookies: ${cookie} (${size} bytes)" "${cookie}"
                    ((findings_count++)) || true
                fi
            done <<< "${chrome_cookies}"
        fi
    done
}

check_browser_extensions() {
    print_header "Checking Browser Extensions"

    for home_dir in "${HOME_DIRS[@]}"; do
        [[ -d "${home_dir}" ]] || continue

        local firefox_ext="${home_dir}/.mozilla/firefox"
        local chrome_ext="${home_dir}/.config/google-chrome/Default/Extensions"
        local chromium_ext="${home_dir}/.config/chromium/Default/Extensions"

        for ext_dir in "${firefox_ext}" "${chrome_ext}" "${chromium_ext}"; do
            [[ -d "${ext_dir}" ]] || continue

            local extension_count
            extension_count=$(find "${ext_dir}" -mindepth 1 -maxdepth 2 -type d 2>/dev/null | wc -l || echo 0)

            if [[ "${extension_count}" -gt 0 ]]; then
                local suspicious_exts
                suspicious_exts=$(find "${ext_dir}" -mindepth 1 -maxdepth 2 -type d 2>/dev/null | \
                    grep -iE "(password|keylog|remote|access|admin|inject|proxy|vpn|crypto|mine)" 2>/dev/null || true)

                if [[ -n "${suspicious_exts}" ]]; then
                    while IFS= read -r ext; do
                        add_finding "${MODULE_NAME}" "Suspicious browser extension" "medium" \
                            "Potentially suspicious extension: ${ext}" "${ext}"
                        ((findings_count++)) || true
                    done <<< "${suspicious_exts}"
                fi
            fi
        done
    done
}

check_download_history() {
    print_header "Checking Download History"

    for home_dir in "${HOME_DIRS[@]}"; do
        [[ -d "${home_dir}" ]] || continue

        local firefox_downloads="${home_dir}/.mozilla/firefox/*/downloads.sqlite"
        local chrome_downloads="${home_dir}/.config/google-chrome/Default/Downloads"

        for dl_pattern in "${firefox_downloads}" "${chrome_downloads}"; do
            for dl_file in ${dl_pattern}; do
                [[ -f "${dl_file}" ]] || continue
                local size
                size=$(stat -c%s "${dl_file}" 2>/dev/null || echo 0)

                if [[ "${size}" -gt 100 ]]; then
                    add_finding "${MODULE_NAME}" "Download history found" "info" \
                        "Download history database: ${dl_file}" "${dl_file}"
                    ((findings_count++)) || true
                fi
            done
        done
    done
}

check_profile_directories() {
    print_header "Checking Browser Profiles"

    for home_dir in "${HOME_DIRS[@]}"; do
        [[ -d "${home_dir}" ]] || continue

        local profile_locations=(
            "${home_dir}/.mozilla/firefox"
            "${home_dir}/.config/google-chrome"
            "${home_dir}/.config/chromium"
            "${home_dir}/.config/microsoft-edge"
            "${home_dir}/.config/opera"
            "${home_dir}/.config/BraveSoftware/Brave-Browser"
        )

        for profile_loc in "${profile_locations[@]}"; do
            [[ -d "${profile_loc}" ]] || continue

            local profile_count
            profile_count=$(find "${profile_loc}" -mindepth 1 -maxdepth 2 -type d 2>/dev/null | wc -l || echo 0)

            if [[ "${profile_count}" -gt 0 ]]; then
                local sizes
                sizes=$(du -sh "${profile_loc}" 2>/dev/null | awk '{print $1}' || echo "unknown")

                add_finding "${MODULE_NAME}" "Browser profile found" "info" \
                    "Browser profile directory: ${profile_loc} (${sizes}, ${profile_count} items)" "${profile_loc}"
                ((findings_count++)) || true
            fi
        done
    done
}

check_form_data() {
    print_header "Checking for Saved Form Data"

    for home_dir in "${HOME_DIRS[@]}"; do
        [[ -d "${home_dir}" ]] || continue

        local firefox_form="${home_dir}/.mozilla/firefox/*/formhistory.sqlite"
        local chrome_form="${home_dir}/.config/google-chrome/Default/Web Data"

        for form_pattern in "${firefox_form}" "${chrome_form}"; do
            for form_file in ${form_pattern}; do
                [[ -f "${form_file}" ]] || continue
                local size
                size=$(stat -c%s "${form_file}" 2>/dev/null || echo 0)

                if [[ "${size}" -gt 500 ]]; then
                    add_finding "${MODULE_NAME}" "Saved form data" "medium" \
                        "Browser form data database: ${form_file} (${size} bytes)" "${form_file}"
                    ((findings_count++)) || true
                fi
            done
        done
    done
}

check_sync_configurations() {
    print_header "Checking Browser Sync Configurations"

    for home_dir in "${HOME_DIRS[@]}"; do
        [[ -d "${home_dir}" ]] || continue

        local chrome_sync="${home_dir}/.config/google-chrome/Default"
        local firefox_sync="${home_dir}/.mozilla/firefox"

        for sync_pattern in "${chrome_sync}/Sync Data" "${firefox_sync}/weave"; do
            for sync_dir in ${sync_pattern}; do
                [[ -d "${sync_dir}" ]] || continue

                add_finding "${MODULE_NAME}" "Browser sync configured" "info" \
                    "Browser synchronization data found: ${sync_dir}" "${sync_dir}"
                ((findings_count++)) || true
            done
        done
    done
}

check_browser_certificates() {
    print_header "Checking Browser Certificates"

    for home_dir in "${HOME_DIRS[@]}"; do
        [[ -d "${home_dir}" ]] || continue

        for cert_file in "${CERTIFICATE_FILES[@]}"; do
            local cert_locations
            cert_locations=$(find "${home_dir}/.mozilla/firefox" \
                -name "${cert_file}" -type f 2>/dev/null || true)

            if [[ -n "${cert_locations}" ]]; then
                while IFS= read -r cert; do
                    local size
                    size=$(stat -c%s "${cert}" 2>/dev/null || echo 0)
                    if [[ "${size}" -gt 0 ]]; then
                        add_finding "${MODULE_NAME}" "Browser certificate store" "info" \
                            "Certificate store found: ${cert}" "${cert}"
                        ((findings_count++)) || true
                    fi
                done <<< "${cert_locations}"
            fi
        done
    done
}

check_bookmarks() {
    print_header "Checking Browser Bookmarks"

    for home_dir in "${HOME_DIRS[@]}"; do
        [[ -d "${home_dir}" ]] || continue

        local firefox_bookmarks="${home_dir}/.mozilla/firefox/*/places.sqlite"
        local chrome_bookmarks="${home_dir}/.config/google-chrome/Default/Bookmarks"

        for bm_pattern in "${firefox_bookmarks}" "${chrome_bookmarks}"; do
            for bm_file in ${bm_pattern}; do
                [[ -f "${bm_file}" ]] || continue

                if [[ "${bm_file}" == *Bookmarks* ]]; then
                    local suspicious_urls
                    suspicious_urls=$(grep -oE '"url":\s*"[^"]*"' "${bm_file}" 2>/dev/null | \
                        grep -iE "(pastebin|pastebin\.com|hastebin|ghostbin|rentry|hack|exploit|dark|onion|tor)" 2>/dev/null || true)

                    if [[ -n "${suspicious_urls}" ]]; then
                        while IFS= read -r url; do
                            add_finding "${MODULE_NAME}" "Suspicious bookmark URL" "medium" \
                                "Suspicious URL in bookmarks: ${url}" "${bm_file}"
                            ((findings_count++)) || true
                        done <<< "${suspicious_urls}"
                    fi
                fi
            done
        done
    done
}

check_history_databases() {
    print_header "Checking Browser History"

    for home_dir in "${HOME_DIRS[@]}"; do
        [[ -d "${home_dir}" ]] || continue

        local firefox_history="${home_dir}/.mozilla/firefox/*/places.sqlite"
        local chrome_history="${home_dir}/.config/google-chrome/Default/History"

        for hist_pattern in "${firefox_history}" "${chrome_history}"; do
            for hist_file in ${hist_pattern}; do
                [[ -f "${hist_file}" ]] || continue
                local size
                size=$(stat -c%s "${hist_file}" 2>/dev/null || echo 0)

                if [[ "${size}" -gt 10000 ]]; then
                    add_finding "${MODULE_NAME}" "Browser history database" "info" \
                        "Browser history with data: ${hist_file} (${size} bytes)" "${hist_file}"
                    ((findings_count++)) || true
                fi
            done
        done
    done
}

check_cached_credentials() {
    print_header "Checking for Cached Credentials"

    for home_dir in "${HOME_DIRS[@]}"; do
        [[ -d "${home_dir}" ]] || continue

        local credential_dirs=(
            "${home_dir}/.mozilla/nss"
            "${home_dir}/.cache/google-chrome/Service Worker/CacheStorage"
            "${home_dir}/.cache/chromium/Service Worker/CacheStorage"
        )

        for cred_dir in "${credential_dirs[@]}"; do
            [[ -d "${cred_dir}" ]] || continue

            local cred_files
            cred_files=$(find "${cred_dir}" -type f -name "*.json" 2>/dev/null | head -20 || true)

            if [[ -n "${cred_files}" ]]; then
                local suspicious_creds
                suspicious_creds=$(echo "${cred_files}" | \
                    grep -iE "(password|credential|token|auth|session|login)" 2>/dev/null || true)

                if [[ -n "${suspicious_creds}" ]]; then
                    while IFS= read -r cred; do
                        add_finding "${MODULE_NAME}" "Cached credential file" "medium" \
                            "Potential cached credential: ${cred}" "${cred}"
                        ((findings_count++)) || true
                    done <<< "${suspicious_creds}"
                fi
            fi
        done
    done
}

if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    run "$@"
fi
