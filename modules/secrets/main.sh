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

MODULE_NAME="secrets"
MODULE_DESCRIPTION="Secrets and credential discovery"
MODULE_VERSION="1.0.0"
MODULE_SEVERITY_THRESHOLD="medium"

readonly -a SSH_KEY_NAMES=(
    "id_rsa" "id_ecdsa" "id_ed25519" "id_dsa"
    "id_xmss" "id_dilithium"
)

readonly -a PRIVATE_KEY_EXTENSIONS=(
    "pem" "key" "p12" "pfx" "ppk"
)

readonly -a CLOUD_ENV_PATTERNS=(
    "AWS_ACCESS_KEY_ID"
    "AWS_SECRET_ACCESS_KEY"
    "AWS_SESSION_TOKEN"
    "AZURE_CLIENT_ID"
    "AZURE_CLIENT_SECRET"
    "AZURE_TENANT_ID"
    "GCLOUD_SERVICE_KEY"
    "GOOGLE_APPLICATION_CREDENTIALS"
)

readonly -a TOKEN_ENV_PATTERNS=(
    "GITHUB_TOKEN"
    "GITLAB_TOKEN"
    "NPM_TOKEN"
    "PYPI_TOKEN"
    "DOCKER_TOKEN"
    "SLACK_TOKEN"
    "DISCORD_TOKEN"
)

readonly -a SECRETS_SEARCH_DIRS=(
    "/etc" "/usr/bin" "/usr/sbin" "/opt" "/home"
    "/root" "/srv" "/var/www" "/tmp" "/var/tmp"
)

declare -i findings_count=0

run() {
    print_header "Secrets and Credential Discovery" "${MODULE_DESCRIPTION}"

    local start_time
    start_time=$(date +%s)

    check_aws_credentials
    check_azure_credentials
    check_gcp_credentials
    check_github_tokens
    check_gitlab_tokens
    check_ssh_keys
    check_api_keys_in_configs
    check_env_files
    check_kubernetes_secrets
    check_hardcoded_passwords
    check_private_key_files
    check_database_connection_strings
    check_jwt_tokens
    check_package_manager_tokens

    local end_time
    end_time=$(date +%s)
    local elapsed=$(( end_time - start_time ))

    print_success "Secrets scan completed. Findings: ${findings_count} (${elapsed}s)"
    return 0
}

check_aws_credentials() {
    print_header "Checking AWS Credentials"

    local aws_creds
    aws_creds=$(find /home /root -name "credentials" -path "*aws*" -type f 2>/dev/null || true)

    if [[ -n "${aws_creds}" ]]; then
        while IFS= read -r cred; do
            local content
            content=$(cat "${cred}" 2>/dev/null || true)

            if [[ "${content}" =~ aws_access_key_id || "${content}" =~ aws_secret_access_key ]]; then
                local has_secret
                has_secret=$(echo "${content}" | grep -c "aws_secret_access_key" 2>/dev/null || echo 0)

                if [[ "${has_secret}" -gt 0 ]]; then
                    add_finding "${MODULE_NAME}" "AWS credentials file" "critical" \
                        "AWS credentials with access key and secret: ${cred}" "${cred}"
                    ((findings_count++)) || true
                fi
            fi
        done <<< "${aws_creds}"
    fi

    local aws_config
    aws_config=$(find /home /root -name "config" -path "*aws*" -type f 2>/dev/null || true)

    if [[ -n "${aws_config}" ]]; then
        while IFS= read -r cfg; do
            local content
            content=$(cat "${cfg}" 2>/dev/null || true)
            if [[ "${content}" =~ (access_key|secret_key|session_token) ]]; then
                add_finding "${MODULE_NAME}" "AWS config with credentials" "high" \
                    "AWS config with embedded credentials: ${cfg}" "${cfg}"
                ((findings_count++)) || true
            fi
        done <<< "${aws_config}"
    fi

    check_env_vars "AWS" "${CLOUD_ENV_PATTERNS[@]}"
}

check_azure_credentials() {
    print_header "Checking Azure Credentials"

    local azure_files
    azure_files=$(find /home /root -path "*azure*" -type f 2>/dev/null || true)

    if [[ -n "${azure_files}" ]]; then
        while IFS= read -r azure_file; do
            local basename
            basename=$(basename "${azure_file}" 2>/dev/null || continue)

            if [[ "${basename}" =~ (credentials|profile|config|token) ]]; then
                local content
                content=$(cat "${azure_file}" 2>/dev/null || true)

                if [[ "${content}" =~ (client_id|client_secret|tenant_id|access_token) ]]; then
                    add_finding "${MODULE_NAME}" "Azure credentials file" "critical" \
                        "Azure credentials detected: ${azure_file}" "${azure_file}"
                    ((findings_count++)) || true
                fi
            fi
        done <<< "${azure_files}"
    fi

    check_env_vars "AZURE" "AZURE_CLIENT_ID" "AZURE_CLIENT_SECRET"
}

check_gcp_credentials() {
    print_header "Checking GCP Credentials"

    local gcp_creds
    gcp_creds=$(find /home /root -path "*gcloud*" -type f 2>/dev/null || true)

    if [[ -n "${gcp_creds}" ]]; then
        while IFS= read -r gcp_file; do
            local basename
            basename=$(basename "${gcp_file}" 2>/dev/null || continue)

            if [[ "${basename}" =~ (application_default_credentials|credentials.db|access_tokens) ]]; then
                add_finding "${MODULE_NAME}" "GCP credentials file" "critical" \
                    "GCP credentials detected: ${gcp_file}" "${gcp_file}"
                ((findings_count++)) || true
            fi
        done <<< "${gcp_creds}"
    fi

    local gcp_sa
    gcp_sa=$(find /home /root -name "*.json" -path "*gcloud*" -type f 2>/dev/null || true)

    if [[ -n "${gcp_sa}" ]]; then
        while IFS= read -r sa_file; do
            local content
            content=$(cat "${sa_file}" 2>/dev/null || true)
            if [[ "${content}" =~ "private_key" && "${content}" =~ "service_account" ]]; then
                add_finding "${MODULE_NAME}" "GCP service account key" "critical" \
                    "GCP service account key: ${sa_file}" "${sa_file}"
                ((findings_count++)) || true
            fi
        done <<< "${gcp_sa}"
    fi
}

check_github_tokens() {
    print_header "Checking GitHub Tokens"

    local gitconfigs
    gitconfigs=$(find /home /root -name ".gitconfig" -type f 2>/dev/null || true)

    if [[ -n "${gitconfigs}" ]]; then
        while IFS= read -r gitcfg; do
            local content
            content=$(cat "${gitcfg}" 2>/dev/null || true)

            if [[ "${content}" =~ (github\.com|x-access-token) ]]; then
                local credential_helper
                credential_helper=$(echo "${content}" | grep -A2 "credential" | grep "helper" 2>/dev/null || true)

                if [[ -n "${credential_helper}" ]]; then
                    add_finding "${MODULE_NAME}" "Git credential helper configured" "high" \
                        "GitHub credential helper found in: ${gitcfg}" "${gitcfg}"
                    ((findings_count++)) || true
                fi
            fi
        done <<< "${gitconfigs}"
    fi

    local github_creds
    github_creds=$(find /home /root -path "*github*" -name "*token*" -type f 2>/dev/null || true)

    if [[ -n "${github_creds}" ]]; then
        while IFS= read -r gh_cred; do
            add_finding "${MODULE_NAME}" "GitHub token file" "high" \
                "GitHub token file found: ${gh_cred}" "${gh_cred}"
            ((findings_count++)) || true
        done <<< "${github_creds}"
    fi

    check_env_vars "GITHUB" "GITHUB_TOKEN"
}

check_gitlab_tokens() {
    print_header "Checking GitLab Tokens"

    local gitlab_cis
    gitlab_cis=$(find /home /root /srv -name ".gitlab-ci.yml" -type f 2>/dev/null || true)

    if [[ -n "${gitlab_cis}" ]]; then
        while IFS= read -r ci_file; do
            local content
            content=$(cat "${ci_file}" 2>/dev/null || true)

            if [[ "${content}" =~ (PRIVATE_TOKEN|CI_JOB_TOKEN|GITLAB_TOKEN) ]]; then
                local has_value
                has_value=$(echo "${content}" | grep -E "(PRIVATE_TOKEN|CI_JOB_TOKEN|GITLAB_TOKEN):" | grep -v '""' | grep -v "''" 2>/dev/null || true)

                if [[ -n "${has_value}" ]]; then
                    add_finding "${MODULE_NAME}" "GitLab CI token exposed" "high" \
                        "GitLab token in CI config: ${ci_file}" "${ci_file}"
                    ((findings_count++)) || true
                fi
            fi
        done <<< "${gitlab_cis}"
    fi

    check_env_vars "GITLAB" "GITLAB_TOKEN"
}

check_ssh_keys() {
    print_header "Checking SSH Private Keys"

    for home_dir in /home/* /root; do
        [[ -d "${home_dir}/.ssh" ]] || continue

        for key_name in "${SSH_KEY_NAMES[@]}"; do
            local key_path="${home_dir}/.ssh/${key_name}"
            if [[ -f "${key_path}" ]]; then
                local content
                content=$(head -1 "${key_path}" 2>/dev/null || true)

                if [[ "${content}" =~ PRIVATE ]]; then
                    add_finding "${MODULE_NAME}" "SSH private key" "critical" \
                        "Unencrypted SSH private key: ${key_path}" "${key_path}"
                    ((findings_count++)) || true
                else
                    add_finding "${MODULE_NAME}" "SSH key file" "medium" \
                        "SSH key file found (may be encrypted): ${key_path}" "${key_path}"
                    ((findings_count++)) || true
                fi
            fi
        done

        local other_keys
        other_keys=$(find "${home_dir}/.ssh" -name "*.pub" -prune -o -type f -print 2>/dev/null || true)

        if [[ -n "${other_keys}" ]]; then
            while IFS= read -r keyfile; do
                [[ -f "${keyfile}" ]] || continue
                local first_line
                first_line=$(head -1 "${keyfile}" 2>/dev/null || continue)

                if [[ "${first_line}" =~ PRIVATE || "${first_line}" =~ "BEGIN" ]]; then
                    local basename
                    basename=$(basename "${keyfile}" 2>/dev/null || continue)

                    if [[ "${basename}" != "${key_name}"* ]]; then
                        add_finding "${MODULE_NAME}" "SSH key file" "high" \
                            "SSH key found: ${keyfile}" "${keyfile}"
                        ((findings_count++)) || true
                    fi
                fi
            done <<< "${other_keys}"
        fi
    done
}

check_api_keys_in_configs() {
    print_header "Checking for API Keys in Configs"

    local api_key_patterns=(
        "api[_-]?key\s*[:=]\s*['\"][A-Za-z0-9+/=_-]{20,}['\"]"
        "apikey\s*[:=]\s*['\"][A-Za-z0-9+/=_-]{20,}['\"]"
        "secret[_-]?key\s*[:=]\s*['\"][A-Za-z0-9+/=_-]{20,}['\"]"
        "access[_-]?key\s*[:=]\s*['\"][A-Za-z0-9+/=_-]{20,}['\"]"
        "auth[_-]?token\s*[:=]\s*['\"][A-Za-z0-9+/=_-]{20,}['\"]"
        "client[_-]?secret\s*[:=]\s*['\"][A-Za-z0-9+/=_-]{20,}['\"]"
    )

    local config_dirs=("/etc" "/home" "/root" "/opt" "/srv" "/var/www")

    for pattern in "${api_key_patterns[@]}"; do
        local found
        found=$(grep_files_pattern "${pattern}" "${config_dirs[@]}" 2>/dev/null || true)

        if [[ -n "${found}" ]]; then
            while IFS= read -r match; do
                local file
                file=$(echo "${match}" | cut -d: -f1 2>/dev/null || continue)

                if [[ -f "${file}" ]]; then
                    local basename
                    basename=$(basename "${file}" 2>/dev/null || continue)

                    if [[ ! "${basename}" =~ (README|LICENSE|CHANGELOG|\.md$) ]]; then
                        add_finding "${MODULE_NAME}" "API key in configuration" "high" \
                            "Potential API key found in: ${file}" "${file}"
                        ((findings_count++)) || true
                    fi
                fi
            done <<< "${found}"
        fi
    done
}

check_env_files() {
    print_header "Checking .env Files"

    local env_files
    env_files=$(find /home /root /srv /var/www /opt -name ".env" -type f 2>/dev/null || true)

    if [[ -n "${env_files}" ]]; then
        while IFS= read -r envfile; do
            local content
            content=$(cat "${envfile}" 2>/dev/null || true)

            local has_secrets
            has_secrets=$(echo "${content}" | grep -ciE "(password|secret|token|key|credential)" 2>/dev/null || echo 0)

            if [[ "${has_secrets}" -gt 0 ]]; then
                add_finding "${MODULE_NAME}" "Environment file with secrets" "high" \
                    ".env file with ${has_secrets} potential secrets: ${envfile}" "${envfile}"
                ((findings_count++)) || true
            fi
        done <<< "${env_files}"
    fi
}

check_kubernetes_secrets() {
    print_header "Checking Kubernetes Secrets"

    local k8s_secrets
    k8s_secrets=$(find /home /root /srv /opt -name "*.yaml" -o -name "*.yml" 2>/dev/null | \
        xargs grep -l "kind:\s*Secret" 2>/dev/null || true)

    if [[ -n "${k8s_secrets}" ]]; then
        while IFS= read -r secret_file; do
            add_finding "${MODULE_NAME}" "Kubernetes secret manifest" "high" \
                "K8s secret manifest found: ${secret_file}" "${secret_file}"
            ((findings_count++)) || true
        done <<< "${k8s_secrets}"
    fi

    local k8s_configs
    k8s_configs=$(find /home /root -name "kubeconfig" -o -name ".kube/config" 2>/dev/null || true)

    if [[ -n "${k8s_configs}" ]]; then
        while IFS= read -r kcfg; do
            [[ -f "${kcfg}" ]] || continue
            local content
            content=$(cat "${kcfg}" 2>/dev/null || true)

            if [[ "${content}" =~ (client-certificate|client-key|token|password) ]]; then
                add_finding "${MODULE_NAME}" "Kubernetes config with credentials" "critical" \
                    "Kubernetes config with embedded credentials: ${kcfg}" "${kcfg}"
                ((findings_count++)) || true
            fi
        done <<< "${k8s_configs}"
    fi
}

check_hardcoded_passwords() {
    print_header "Checking for Hardcoded Passwords"

    local password_patterns=(
        "password\s*=\s*['\"][^'\"]{4,}['\"]"
        "passwd\s*=\s*['\"][^'\"]{4,}['\"]"
        "pwd\s*=\s*['\"][^'\"]{4,}['\"]"
        "PASSWORD\s*=\s*[\"'][^\"']{4,}[\"']"
    )

    local script_dirs=("/usr/local/bin" "/opt" "/home" "/srv" "/var/www")

    for pattern in "${password_patterns[@]}"; do
        local found
        found=$(grep_files_pattern "${pattern}" "${script_dirs[@]}" 2>/dev/null || true)

        if [[ -n "${found}" ]]; then
            while IFS= read -r match; do
                local file
                file=$(echo "${match}" | cut -d: -f1 2>/dev/null || continue)

                if [[ -f "${file}" ]]; then
                    local ext
                    ext="${file##*.}"

                    if [[ "${ext}" =~ (sh|bash|py|pl|rb|php|js) ]]; then
                        add_finding "${MODULE_NAME}" "Hardcoded password in script" "high" \
                            "Password found in script: ${file}" "${file}"
                        ((findings_count++)) || true
                    fi
                fi
            done <<< "${found}"
        fi
    done
}

check_private_key_files() {
    print_header "Checking for Private Key Files"

    for ext in "${PRIVATE_KEY_EXTENSIONS[@]}"; do
        local key_files
        key_files=$(find /home /root /etc /srv /opt -name "*.${ext}" -type f 2>/dev/null || true)

        if [[ -n "${key_files}" ]]; then
            while IFS= read -r keyfile; do
                local content
                content=$(head -5 "${keyfile}" 2>/dev/null || continue)

                if [[ "${content}" =~ "PRIVATE KEY" || "${content}" =~ "PRIVATE" ]]; then
                    add_finding "${MODULE_NAME}" "Private key file" "critical" \
                        "Private key found: ${keyfile}" "${keyfile}"
                    ((findings_count++)) || true
                else
                    add_finding "${MODULE_NAME}" "Key file" "medium" \
                        "Key file found (may not be private): ${keyfile}" "${keyfile}"
                    ((findings_count++)) || true
                fi
            done <<< "${key_files}"
        fi
    done
}

check_database_connection_strings() {
    print_header "Checking Database Connection Strings"

    local db_patterns=(
        "mysql://[^[:space:]]*:[^[:space:]]*@"
        "postgresql://[^[:space:]]*:[^[:space:]]*@"
        "mongodb://[^[:space:]]*:[^[:space:]]*@"
        "redis://[^[:space:]]*:[^[:space:]]*@"
        "amqp://[^[:space:]]*:[^[:space:]]*@"
        "DATABASE_URL\s*=\s*['\"]?[^'\"]*:[^'\"]*@"
        "DB_PASSWORD\s*=\s*['\"][^'\"]+['\"]"
    )

    local config_dirs=("/etc" "/home" "/root" "/opt" "/srv" "/var/www")

    for pattern in "${db_patterns[@]}"; do
        local found
        found=$(grep_files_pattern "${pattern}" "${config_dirs[@]}" 2>/dev/null || true)

        if [[ -n "${found}" ]]; then
            while IFS= read -r match; do
                local file
                file=$(echo "${match}" | cut -d: -f1 2>/dev/null || continue)

                if [[ -f "${file}" ]]; then
                    add_finding "${MODULE_NAME}" "Database connection string" "high" \
                        "Database connection with credentials: ${file}" "${file}"
                    ((findings_count++)) || true
                fi
            done <<< "${found}"
        fi
    done
}

check_jwt_tokens() {
    print_header "Checking for JWT Tokens"

    local jwt_pattern="eyJ[A-Za-z0-9+/=_-]*\.eyJ[A-Za-z0-9+/=_-]*\.[A-Za-z0-9+/=_-]*"

    local config_dirs=("/etc" "/home" "/root" "/opt" "/srv" "/var/www")

    local found
    found=$(grep_files_pattern "${jwt_pattern}" "${config_dirs[@]}" 2>/dev/null || true)

    if [[ -n "${found}" ]]; then
        while IFS= read -r match; do
            local file
            file=$(echo "${match}" | cut -d: -f1 2>/dev/null || continue)

            if [[ -f "${file}" ]]; then
                local ext
                ext="${file##*.}"

                if [[ "${ext}" =~ (env|cfg|conf|config|json|yaml|yml|ini|properties) ]]; then
                    add_finding "${MODULE_NAME}" "JWT token in config" "high" \
                        "JWT token found in: ${file}" "${file}"
                    ((findings_count++)) || true
                fi
            fi
        done <<< "${found}"
    fi
}

check_package_manager_tokens() {
    print_header "Checking Package Manager Tokens"

    local npmrc_files
    npmrc_files=$(find /home /root -name ".npmrc" -type f 2>/dev/null || true)

    if [[ -n "${npmrc_files}" ]]; then
        while IFS= read -r npmrc; do
            local content
            content=$(cat "${npmrc}" 2>/dev/null || true)

            if [[ "${content}" =~ (//registry\.npmjs\.org/:_authToken|_auth=) ]]; then
                add_finding "${MODULE_NAME}" "NPM authentication token" "high" \
                    "NPM token found in: ${npmrc}" "${npmrc}"
                ((findings_count++)) || true
            fi
        done <<< "${npmrc_files}"
    fi

    local pypirc_files
    pypirc_files=$(find /home /root -name ".pypirc" -type f 2>/dev/null || true)

    if [[ -n "${pypirc_files}" ]]; then
        while IFS= read -r pypirc; do
            local content
            content=$(cat "${pypirc}" 2>/dev/null || true)

            if [[ "${content}" =~ password ]]; then
                add_finding "${MODULE_NAME}" "PyPI credentials" "high" \
                    "PyPI credentials found in: ${pypirc}" "${pypirc}"
                ((findings_count++)) || true
            fi
        done <<< "${pypirc_files}"
    fi

    local docker_configs
    docker_configs=$(find /home /root -path "*docker*config*" -type f 2>/dev/null || true)

    if [[ -n "${docker_configs}" ]]; then
        while IFS= read -r dcfg; do
            local content
            content=$(cat "${dcfg}" 2>/dev/null || true)

            if [[ "${content}" =~ "auth" && "${content}" =~ "username" ]]; then
                add_finding "${MODULE_NAME}" "Docker registry credentials" "high" \
                    "Docker registry auth found in: ${dcfg}" "${dcfg}"
                ((findings_count++)) || true
            fi
        done <<< "${docker_configs}"
    fi
}

check_env_vars() {
    local prefix="$1"
    shift
    local vars=("$@")

    for var in "${vars[@]}"; do
        local value="${!var:-}"
        if [[ -n "${value}" ]]; then
            add_finding "${MODULE_NAME}" "Environment variable with secret" "high" \
                "${prefix} credential in environment variable: ${var}" ""
            ((findings_count++)) || true
        fi
    done
}

grep_files_pattern() {
    local pattern="$1"
    shift
    local dirs=("$@")

    local result=""
    for dir in "${dirs[@]}"; do
        [[ -d "${dir}" ]] || continue
        local found
        found=$(grep -rlE "${pattern}" "${dir}" 2>/dev/null | head -100 || true)
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

if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    run "$@"
fi
