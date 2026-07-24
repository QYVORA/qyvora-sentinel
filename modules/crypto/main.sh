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

MODULE_NAME="crypto"
MODULE_DESCRIPTION="Cryptocurrency mining detection"
MODULE_VERSION="1.0.0"
MODULE_SEVERITY_THRESHOLD="medium"

readonly -a MINING_SOFTWARE=(
    "xmrig" "xmr-stak" "minerd" "minergate" "ethminer"
    "cgminer" "bfgminer" "cpuminer" "cpuminer-opt"
    "minerg" "sgminer" "polaris" "claymore"
    "phoenix" "gminer" "t-rex" "lolminer" "nbminer"
    "kawpow" "randomx" "cryptonight"
)

readonly -a MINING_POOL_PATTERNS=(
    "stratum\+tcp" "stratum\+ssl"
    "nicehash" "miningpoolhub" "nanopool"
    "ethermine" "flypool" "flexpool"
    "f2pool" "pool.minexmr" "moneropool"
    "pool.hashvault" "supportxmr" "xmrpool"
)

readonly -a GPU_MINING_TOOLS=(
    "nvidia-smi" "nvidia-settings" "nvidia-detect"
    "rocm-smi" "amdgpu-pro"
)

readonly -a CRYPTO_EXTENSIONS=(
    "wallet" "dat"
)

readonly -A KNOWN_MINING_PORTS=(
    ["3333"]="Stratum mining"
    ["4444"]="Stratum mining"
    ["5555"]="Stratum mining"
    ["7777"]="Stratum mining"
    ["8888"]="Stratum mining"
    ["9999"]="Stratum mining"
    ["14433"]="Stratum mining"
    ["45560"]="XMR mining"
)

readonly SCAN_DIRS=("/etc" "/usr/bin" "/usr/sbin" "/opt" "/home" "/tmp" "/var/tmp" "/dev/shm" "/root" "/srv")

declare -i findings_count=0

run() {
    print_header "Cryptocurrency Mining Detection" "${MODULE_DESCRIPTION}"

    local start_time
    start_time=$(date +%s)

    search_mining_software
    search_wallet_files
    search_mining_configs
    check_mining_processes
    check_cron_jobs
    check_gpu_tools
    check_cpu_usage
    search_mining_urls
    check_hidden_processes
    check_mining_connections
    search_tmp_mining

    local end_time
    end_time=$(date +%s)
    local elapsed=$(( end_time - start_time ))

    print_success "Crypto scan completed. Findings: ${findings_count} (${elapsed}s)"
    return 0
}

search_mining_software() {
    print_header "Searching for Mining Software"

    for software in "${MINING_SOFTWARE[@]}"; do
        local locations
        locations=$(find_files_by_name "${software}" "${SCAN_DIRS[@]}" 2>/dev/null || true)

        if [[ -n "${locations}" ]]; then
            while IFS= read -r location; do
                add_finding "${MODULE_NAME}" "Mining software detected" "critical" \
                    "Found ${software} at: ${location}" "${location}"
                ((findings_count++)) || true
            done <<< "${locations}"
        fi
    done
}

search_wallet_files() {
    print_header "Searching for Wallet Files"

    local crypto_dirs
    crypto_dirs=$(find_files_by_name "*.wallet" "${SCAN_DIRS[@]}" 2>/dev/null || true)

    if [[ -n "${crypto_dirs}" ]]; then
        while IFS= read -r wallet; do
            add_finding "${MODULE_NAME}" "Wallet file found" "high" \
                "Wallet file detected: ${wallet}" "${wallet}"
            ((findings_count++)) || true
        done <<< "${crypto_dirs}"
    fi

    for ext in "${CRYPTO_EXTENSIONS[@]}"; do
        local dat_files
        dat_files=$(find_files_by_extension "${ext}" "${SCAN_DIRS[@]}" 2>/dev/null || true)

        if [[ -n "${dat_files}" ]]; then
            while IFS= read -r datfile; do
                local basename
                basename=$(basename "${datfile}" 2>/dev/null || continue)
                if [[ "${basename}" =~ (wallet|crypto|bitcoin|monero|ethereum|blockchain) ]]; then
                    add_finding "${MODULE_NAME}" "Cryptocurrency data file" "high" \
                        "Potential crypto data file: ${datfile}" "${datfile}"
                    ((findings_count++)) || true
                fi
            done <<< "${dat_files}"
        fi
    done
}

search_mining_configs() {
    print_header "Searching for Mining Pool Configurations"

    local config_files
    config_files=$(grep_files_by_pattern \
        "stratum\+tcp\|stratum\+ssl\|mining.*pool\|pool.*stratum\|coinhive\|cryptoloot" \
        "${SCAN_DIRS[@]}" 2>/dev/null || true)

    if [[ -n "${config_files}" ]]; then
        while IFS= read -r config; do
            add_finding "${MODULE_NAME}" "Mining pool configuration" "high" \
                "Mining pool config found: ${config}" "${config}"
            ((findings_count++)) || true
        done <<< "${config_files}"
    fi

    local webshells
    webshells=$(grep_files_by_pattern \
        "coinhive\.min\.js\|crypto-loot\|coinimp\|authedmine" \
        "${SCAN_DIRS[@]}" 2>/dev/null || true)

    if [[ -n "${webshells}" ]]; then
        while IFS= read -r shell; do
            add_finding "${MODULE_NAME}" "Browser-based mining script" "critical" \
                "In-browser mining script detected: ${shell}" "${shell}"
            ((findings_count++)) || true
        done <<< "${webshells}"
    fi
}

check_mining_processes() {
    print_header "Checking for Mining Processes"

    local processes
    processes=$(find_processes_by_name "xmrig\|minerd\|cpuminer\|cgminer\|bfgminer\|ethminer\|sgminer" 2>/dev/null || true)

    if [[ -n "${processes}" ]]; then
        while IFS= read -r proc; do
            add_finding "${MODULE_NAME}" "Mining process active" "critical" \
                "Mining process detected: ${proc}" ""
            ((findings_count++)) || true
        done <<< "${processes}"
    fi

    local hidden_procs
    hidden_procs=$(find_hidden_processes 2>/dev/null || true)

    if [[ -n "${hidden_procs}" ]]; then
        while IFS= read -r proc; do
            local proc_name
            proc_name=$(echo "${proc}" | awk '{print $NF}' 2>/dev/null || continue)
            if [[ "${proc_name}" =~ (xmr|mine|coin|crypto|strat) ]]; then
                add_finding "${MODULE_NAME}" "Hidden mining process" "critical" \
                    "Possible hidden mining process: ${proc}" ""
                ((findings_count++)) || true
            fi
        done <<< "${hidden_procs}"
    fi
}

check_cron_jobs() {
    print_header "Checking Cron Jobs for Mining"

    local cron_dirs=("/etc/cron.d" "/etc/cron.daily" "/etc/cron.hourly"
                     "/etc/cron.weekly" "/etc/cron.monthly" "/var/spool/cron/crontabs")

    for crondir in "${cron_dirs[@]}"; do
        [[ -d "${crondir}" ]] || continue

        local cron_files
        cron_files=$(find "${crondir}" -type f 2>/dev/null || true)

        if [[ -n "${cron_files}" ]]; then
            while IFS= read -r cronfile; do
                [[ -f "${cronfile}" ]] || continue

                local mining_cron
                mining_cron=$(grep_files_by_pattern \
                    "stratum\|minerd\|xmrig\|nicehash\|miningpoolhub\|pool\.minexmr\|coinhive" \
                    "$(dirname "${cronfile}")" 2>/dev/null || true)

                if [[ -n "${mining_cron}" ]]; then
                    add_finding "${MODULE_NAME}" "Mining cron job" "critical" \
                        "Mining-related cron job: ${cronfile}" "${cronfile}"
                    ((findings_count++)) || true
                fi
            done <<< "${cron_files}"
        fi
    done

    local user_crons
    user_crons=$(get_user_crontabs 2>/dev/null || true)

    if [[ -n "${user_crons}" ]]; then
        while IFS= read -r cron; do
            if [[ "${cron}" =~ (xmrig|minerd|stratum|nicehash|miningpool) ]]; then
                add_finding "${MODULE_NAME}" "Mining in user crontab" "critical" \
                    "Mining reference in user crontab: ${cron}" ""
                ((findings_count++)) || true
            fi
        done <<< "${user_crons}"
    fi
}

check_gpu_tools() {
    print_header "Checking GPU Mining Tools"

    for tool in "${GPU_MINING_TOOLS[@]}"; do
        local locations
        locations=$(find_files_by_name "${tool}" "/usr/bin" "/usr/sbin" "/usr/local/bin" 2>/dev/null || true)

        if [[ -n "${locations}" ]]; then
            while IFS= read -r loc; do
                if [[ "${tool}" =~ (rocm|amdgpu) ]]; then
                    add_finding "${MODULE_NAME}" "GPU compute tool installed" "low" \
                        "GPU compute tool found (may indicate GPU mining): ${tool} at ${loc}" "${loc}"
                    ((findings_count++)) || true
                fi
            done <<< "${locations}"
        fi
    done
}

check_cpu_usage() {
    print_header "Checking High CPU Usage Processes"

    local high_cpu
    high_cpu=$(get_high_cpu_processes 90 2>/dev/null || true)

    if [[ -n "${high_cpu}" ]]; then
        while IFS= read -r line; do
            local proc_name cpu_usage
            proc_name=$(echo "${line}" | awk '{print $11}' 2>/dev/null || continue)
            cpu_usage=$(echo "${line}" | awk '{print $3}' 2>/dev/null || continue)

            local suspicious=0
            for miner in xmrig minerd cpuminer; do
                if [[ "${proc_name}" == *"${miner}"* ]]; then
                    suspicious=1
                    break
                fi
            done

            if [[ "${suspicious}" -eq 1 ]]; then
                add_finding "${MODULE_NAME}" "High CPU mining process" "critical" \
                    "Process ${proc_name} using ${cpu_usage}% CPU (possible miner)" ""
                ((findings_count++)) || true
            elif [[ "${proc_name}" =~ (/proc/self|/dev/shm|/tmp) ]]; then
                add_finding "${MODULE_NAME}" "Suspicious high CPU process" "high" \
                    "Process ${proc_name} using ${cpu_usage}% CPU from suspicious path" ""
                ((findings_count++)) || true
            fi
        done <<< "${high_cpu}"
    fi
}

search_mining_urls() {
    print_header "Searching for Mining URLs in Configs"

    local mining_urls
    mining_urls=$(grep_files_by_pattern \
        "pool\.minexmr\|nicehash\.com\|f2pool\.com\|ethermine\.org\|nanopool\.org\|moneropool\.com\|coinhive\.com\|crypto-loot\.com\|authedmine\.com" \
        "${SCAN_DIRS[@]}" 2>/dev/null || true)

    if [[ -n "${mining_urls}" ]]; then
        while IFS= read -r url_line; do
            add_finding "${MODULE_NAME}" "Mining URL in configuration" "high" \
                "Mining pool URL reference: ${url_line}" ""
            ((findings_count++)) || true
        done <<< "${mining_urls}"
    fi

    local proxy_mining
    proxy_mining=$(grep_files_by_pattern \
        "coinhive\.min\.js\|coinhive\.proxy\.min\.js\|authedmine\.min\.js" \
        "/var/www" "/srv" "/opt" "/home" 2>/dev/null || true)

    if [[ -n "${proxy_mining}" ]]; then
        while IFS= read -r pm; do
            add_finding "${MODULE_NAME}" "Web-based mining proxy" "critical" \
                "Browser mining proxy detected: ${pm}" "${pm}"
            ((findings_count++)) || true
        done <<< "${proxy_mining}"
    fi
}

check_hidden_processes() {
    print_header "Checking for Hidden Mining Processes"

    local ps_output
    ps_output=$(ps aux 2>/dev/null || true)

    if [[ -z "${ps_output}" ]]; then
        return
    fi

    while IFS= read -r line; do
        local proc_path
        proc_path=$(echo "${line}" | awk '{print $11}' 2>/dev/null || continue)

        if [[ -z "${proc_path}" || "${proc_path}" =~ ^\[.*\]$ ]]; then
            continue
        fi

        local basename
        basename=$(basename "${proc_path}" 2>/dev/null || continue)

        if [[ -f "/proc/${line%% *}/exe" ]]; then
            local real_path
            real_path=$(readlink -f "/proc/${line%% *}/exe" 2>/dev/null || continue)

            if [[ "${real_path}" != "${proc_path}" && ! "${real_path}" =~ (system|usr|lib) ]]; then
                add_finding "${MODULE_NAME}" "Process path mismatch" "high" \
                    "Process ${basename} running from ${real_path} (expected ${proc_path})" "${real_path}"
                ((findings_count++)) || true
            fi
        fi
    done <<< "${ps_output}"
}

check_mining_connections() {
    print_header "Checking Network Connections for Mining"

    local connections
    connections=$(get_active_connections 2>/dev/null || true)

    if [[ -z "${connections}" ]]; then
        return
    fi

    while IFS= read -r conn; do
        local remote_port remote_addr
        remote_port=$(echo "${conn}" | awk '{print $5}' | rev | cut -d: -f1 | rev 2>/dev/null || continue)
        remote_addr=$(echo "${conn}" | awk '{print $5}' | rev | cut -d: -f2- | rev 2>/dev/null || continue)

        if [[ -v "KNOWN_MINING_PORTS[${remote_port}]" ]]; then
            add_finding "${MODULE_NAME}" "Connection on mining port" "high" \
                "Outbound connection to ${remote_addr}:${remote_port} (known mining port)" ""
            ((findings_count++)) || true
        fi
    done <<< "${connections}"
}

search_tmp_mining() {
    print_header "Searching Temp Directories for Mining"

    local tmp_dirs=("/tmp" "/dev/shm" "/var/tmp")

    for tmpdir in "${tmp_dirs[@]}"; do
        [[ -d "${tmpdir}" ]] || continue

        local tmp_mining
        tmp_mining=$(find "${tmpdir}" \
            \( -name "*xmrig*" -o -name "*minerd*" -o -name "*miner*" \
            -o -name "*crypto*" -o -name "*stratum*" \) \
            -type f 2>/dev/null || true)

        if [[ -n "${tmp_mining}" ]]; then
            while IFS= read -r item; do
                add_finding "${MODULE_NAME}" "Mining artifact in temp directory" "critical" \
                    "Mining-related file in ${tmpdir}: ${item}" "${item}"
                ((findings_count++)) || true
            done <<< "${tmp_mining}"
        fi

        local executables
        executables=$(find "${tmpdir}" -type f -executable \
            -newer "/etc/hostname" -mtime -1 2>/dev/null || true)

        if [[ -n "${executables}" ]]; then
            while IFS= read -r exe; do
                add_finding "${MODULE_NAME}" "Recent executable in temp" "medium" \
                    "Recently created executable in ${tmpdir}: ${exe}" "${exe}"
                ((findings_count++)) || true
            done <<< "${executables}"
        fi
    done
}

find_files_by_name() {
    local name="$1"
    shift
    local dirs=("$@")

    local result=""
    for dir in "${dirs[@]}"; do
        [[ -d "${dir}" ]] || continue
        local found
        found=$(find "${dir}" -name "*${name}*" -type f 2>/dev/null || true)
        if [[ -n "${found}" ]]; then
            if [[ -z "${result}" ]]; then
                result="${found}"
            else
                result="${result}"$'\n'"${found}"
            fi
        fi
    done
    echo "${result}"
}

find_files_by_extension() {
    local ext="$1"
    shift
    local dirs=("$@")

    local result=""
    for dir in "${dirs[@]}"; do
        [[ -d "${dir}" ]] || continue
        local found
        found=$(find "${dir}" -name "*.${ext}" -type f 2>/dev/null || true)
        if [[ -n "${found}" ]]; then
            if [[ -z "${result}" ]]; then
                result="${found}"
            else
                result="${result}"$'\n'"${found}"
            fi
        fi
    done
    echo "${result}"
}

grep_files_by_pattern() {
    local pattern="$1"
    shift
    local dirs=("$@")

    local result=""
    for dir in "${dirs[@]}"; do
        [[ -d "${dir}" ]] || continue
        local found
        found=$(grep -rlE "${pattern}" "${dir}" 2>/dev/null || true)
        if [[ -n "${found}" ]]; then
            if [[ -z "${result}" ]]; then
                result="${found}"
            else
                result="${result}"$'\n'"${found}"
            fi
        fi
    done
    echo "${result}"
}

find_processes_by_name() {
    local pattern="$1"
    ps aux 2>/dev/null | grep -E "${pattern}" | grep -v grep || true
}

find_hidden_processes() {
    ps aux 2>/dev/null | awk '{print $2}' | while read -r pid; do
        if [[ -d "/proc/${pid}" && -L "/proc/${pid}/exe" ]]; then
            local exe_path
            exe_path=$(readlink -f "/proc/${pid}/exe" 2>/dev/null || continue)
            local cmdline
            cmdline=$(tr '\0' ' ' < "/proc/${pid}/cmdline" 2>/dev/null || continue)
            if [[ -n "${cmdline}" ]]; then
                echo "${cmdline}"
            fi
        fi
    done
}

find_high_cpu_processes() {
    local threshold="${1:-90}"
    ps aux 2>/dev/null | awk -v thresh="${threshold}" '$3 >= thresh {print}'
}

get_high_cpu_processes() {
    local threshold="${1:-90}"
    ps aux 2>/dev/null | awk -v thresh="${threshold}" '$3 >= thresh {print}'
}

get_active_connections() {
    ss -tunap 2>/dev/null | tail -n +2 || netstat -tunap 2>/dev/null | tail -n +3 || true
}

get_user_crontabs() {
    local result=""
    if [[ -d "/var/spool/cron/crontabs" ]]; then
        for user_cron in /var/spool/cron/crontabs/*; do
            [[ -f "${user_cron}" ]] || continue
            local content
            content=$(cat "${user_cron}" 2>/dev/null || true)
            if [[ -n "${content}" ]]; then
                if [[ -z "${result}" ]]; then
                    result="${content}"
                else
                    result="${result}"$'\n'"${content}"
                fi
            fi
        done
    fi
    echo "${result}"
}

if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    run "$@"
fi
