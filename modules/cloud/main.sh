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
readonly MODULE_NAME="cloud"
readonly MODULE_DESCRIPTION="Cloud configuration audit"
readonly MODULE_VERSION="1.0.0"
readonly MODULE_SEVERITY_THRESHOLD="info"

_detect_cloud_provider() {
    print_subheader "Cloud Provider Detection"

    local provider="unknown"

    if [[ -f /sys/class/dmi/id/sys_vendor ]]; then
        local sys_vendor
        sys_vendor="$(cat /sys/class/dmi/id/sys_vendor 2>/dev/null || echo "")"
        if [[ "${sys_vendor}" == *"Amazon"* ]]; then
            provider="AWS"
        elif [[ "${sys_vendor}" == *"Microsoft"* ]]; then
            provider="Azure"
        elif [[ "${sys_vendor}" == *"Google"* ]]; then
            provider="GCP"
        elif [[ "${sys_vendor}" == *"DigitalOcean"* ]]; then
            provider="DigitalOcean"
        elif [[ "${sys_vendor}" == *"Linode"* ]]; then
            provider="Linode"
        elif [[ "${sys_vendor}" == *"Vultr"* ]]; then
            provider="Vultr"
        elif [[ "${sys_vendor}" == *"Oracle"* ]]; then
            provider="Oracle Cloud"
        fi
    fi

    if [[ -f /sys/class/dmi/id/product_name ]]; then
        local product_name
        product_name="$(cat /sys/class/dmi/id/product_name 2>/dev/null || echo "")"
        if [[ "${product_name}" == *"Amazon"* || "${product_name}" == *"Elastic"* ]]; then
            provider="AWS"
        elif [[ "${product_name}" == *"Virtual Machine"* ]]; then
            [[ "${provider}" == "unknown" ]] && provider="Azure/Hyper-V"
        elif [[ "${product_name}" == *"Google Compute Engine"* ]]; then
            provider="GCP"
        fi
    fi

    if [[ -f /etc/cloud/cloud.cfg.d/00-default.cfg ]] || [[ -d /etc/cloud ]]; then
        print_info "cloud-init detected"
    fi

    if [[ "${provider}" != "unknown" ]]; then
        add_finding "${MODULE_NAME}" "INFO" \
            "Cloud provider detected" \
            "System appears to be running on ${provider}" \
            "provider=${provider}"
        print_success "Cloud provider: ${provider}"
    else
        print_info "No cloud provider detected via DMI"
    fi
}

_aws_cli_config() {
    print_subheader "AWS CLI Configuration"

    if ! command -v aws &>/dev/null; then
        print_info "AWS CLI not installed"
        return
    fi

    print_success "AWS CLI found: $(aws --version 2>/dev/null || echo "unknown")"

    local aws_dir="${HOME}/.aws"
    if [[ -d "${aws_dir}" ]]; then
        local config_file="${aws_dir}/config"
        local credentials_file="${aws_dir}/credentials"

        if [[ -f "${config_file}" ]]; then
            local config_perms
            config_perms="$(stat -c '%a' "${config_file}" 2>/dev/null || echo "")"
            if [[ -n "${config_perms}" && "${config_perms}" != "600" ]]; then
                add_finding "${MODULE_NAME}" "MEDIUM" \
                    "AWS config file has loose permissions" \
                    "${config_file} has mode ${config_perms}, expected 600" \
                    "file=${config_file} mode=${config_perms}" \
                    "chmod 600 ${config_file}"
                print_warning "AWS config permissions: ${config_perms}"
            else
                print_success "AWS config permissions: ${config_perms}"
            fi
        fi

        if [[ -f "${credentials_file}" ]]; then
            local creds_perms
            creds_perms="$(stat -c '%a' "${credentials_file}" 2>/dev/null || echo "")"
            if [[ -n "${creds_perms}" && "${creds_perms}" != "600" ]]; then
                add_finding "${MODULE_NAME}" "HIGH" \
                    "AWS credentials file has loose permissions" \
                    "${credentials_file} has mode ${creds_perms}, expected 600" \
                    "file=${credentials_file} mode=${creds_perms}" \
                    "chmod 600 ${credentials_file}"
                print_error "AWS credentials permissions: ${creds_perms}"
            else
                print_success "AWS credentials permissions: ${creds_perms}"
            fi

            if grep -qE "aws_access_key_id|aws_secret_access_key" "${credentials_file}" 2>/dev/null; then
                add_finding "${MODULE_NAME}" "HIGH" \
                    "AWS credentials stored in plain text" \
                    "Static AWS credentials found in ${credentials_file}" \
                    "file=${credentials_file}" \
                    "Use IAM roles or AWS SSO instead of static credentials"
                print_error "Static AWS credentials detected"
            fi
        fi
    fi

    local env_keys
    env_keys="$(env 2>/dev/null | grep -iE "AWS_ACCESS_KEY|AWS_SECRET_KEY|AWS_SESSION_TOKEN" || true)"
    if [[ -n "${env_keys}" ]]; then
        add_finding "${MODULE_NAME}" "MEDIUM" \
            "AWS credentials in environment variables" \
            "AWS credentials found in environment" \
            "Use IAM roles or instance profiles instead"
        print_warning "AWS credentials in environment"
    fi
}

_azure_cli_config() {
    print_subheader "Azure CLI Configuration"

    if ! command -v az &>/dev/null; then
        print_info "Azure CLI not installed"
        return
    fi

    print_success "Azure CLI found: $(az version 2>/dev/null | head -1 || echo "unknown")"

    local azure_dir="${HOME}/.azure"
    if [[ -d "${azure_dir}" ]]; then
        local access_tokens="${azure_dir}/accessTokens.json"
        local azure_profile="${azure_dir}/azureProfile.json"

        if [[ -f "${access_tokens}" ]]; then
            local token_perms
            token_perms="$(stat -c '%a' "${access_tokens}" 2>/dev/null || echo "")"
            if [[ -n "${token_perms}" && "${token_perms}" != "600" ]]; then
                add_finding "${MODULE_NAME}" "HIGH" \
                    "Azure access tokens file has loose permissions" \
                    "${access_tokens} has mode ${token_perms}" \
                    "file=${access_tokens} mode=${token_perms}" \
                    "chmod 600 ${access_tokens}"
                print_error "Azure tokens permissions: ${token_perms}"
            else
                print_success "Azure tokens file permissions: ${token_perms}"
            fi

            if [[ -s "${access_tokens}" ]]; then
                add_finding "${MODULE_NAME}" "HIGH" \
                    "Azure access tokens stored on disk" \
                    "Access tokens file is non-empty" \
                    "file=${access_tokens}" \
                    "Use managed identity or Azure AD authentication"
                print_error "Azure access tokens present on disk"
            fi
        fi

        if [[ -f "${azure_profile}" ]]; then
            print_info "Azure profile found: ${azure_profile}"
        fi
    fi
}

_gcp_cli_config() {
    print_subheader "GCP CLI Configuration"

    if ! command -v gcloud &>/dev/null; then
        print_info "gcloud CLI not installed"
        return
    fi

    print_success "gcloud found: $(gcloud --version 2>/dev/null | head -1 || echo "unknown")"

    local gcp_dir="${HOME}/.config/gcloud"
    if [[ -d "${gcp_dir}" ]]; then
        local creds_file="${gcp_dir}/credentials.db"
        local adc_file="${HOME}/.config/gcloud/application_default_credentials.json"

        if [[ -f "${creds_file}" ]]; then
            local creds_perms
            creds_perms="$(stat -c '%a' "${creds_file}" 2>/dev/null || echo "")"
            print_success "GCP credentials file permissions: ${creds_perms}"
        fi

        if [[ -f "${adc_file}" ]]; then
            local adc_perms
            adc_perms="$(stat -c '%a' "${adc_file}" 2>/dev/null || echo "")"
            if [[ -n "${adc_perms}" && "${adc_perms}" != "600" ]]; then
                add_finding "${MODULE_NAME}" "HIGH" \
                    "GCP ADC file has loose permissions" \
                    "${adc_file} has mode ${adc_perms}" \
                    "file=${adc_file} mode=${adc_perms}" \
                    "chmod 600 ${adc_file}"
                print_error "GCP ADC permissions: ${adc_perms}"
            else
                print_success "GCP ADC file permissions: ${adc_perms}"
            fi
        fi
    fi
}

_metadata_endpoint() {
    print_subheader "Cloud Metadata Endpoint"

    local metadata_ip="169.254.169.254"
    local timeout_sec=3

    if curl -s --connect-timeout "${timeout_sec}" -m "${timeout_sec}" "http://${metadata_ip}/latest/meta-data/" >/dev/null 2>&1; then
        add_finding "${MODULE_NAME}" "HIGH" \
            "Cloud metadata endpoint accessible" \
            "Instance metadata at ${metadata_ip} is reachable without IMDSv2" \
            "endpoint=${metadata_ip}" \
            "Enable IMDSv2 and restrict metadata access with iptables"
        print_error "Metadata endpoint accessible (IMDSv1): ${metadata_ip}"

        local metadata_content
        metadata_content="$(curl -s --connect-timeout "${timeout_sec}" -m "${timeout_sec}" "http://${metadata_ip}/latest/meta-data/" 2>/dev/null || true)"
        if [[ -n "${metadata_content}" ]]; then
            print_info "Metadata keys available (sample):"
            echo "${metadata_content}" | head -10
        fi
    elif curl -s --connect-timeout "${timeout_sec}" -m "${timeout_sec}" \
        -H "X-aws-ec2-metadata-token-ttl-seconds: 21600" \
        -X PUT "http://${metadata_ip}/latest/api/token" >/dev/null 2>&1; then
        print_success "Metadata endpoint requires IMDSv2 (good)"
    else
        print_success "Metadata endpoint not reachable (or not on cloud)"
    fi
}

_cloud_init_config() {
    print_subheader "cloud-init Configuration"

    if [[ ! -d /etc/cloud ]]; then
        print_info "cloud-init not found"
        return
    fi

    local cloud_cfg="/etc/cloud/cloud.cfg"
    if [[ -f "${cloud_cfg}" ]]; then
        if grep -qi "password:" "${cloud_cfg}" 2>/dev/null; then
            add_finding "${MODULE_NAME}" "HIGH" \
                "cloud-init contains password configuration" \
                "Password found in ${cloud_cfg}" \
                "file=${cloud_cfg}" \
                "Remove plaintext passwords from cloud-init config"
            print_error "Password in cloud-init config"
        else
            print_success "No passwords found in cloud-init config"
        fi

        if grep -qi "ssh_authorized_keys:" "${cloud_cfg}" 2>/dev/null; then
            print_info "SSH authorized keys configured via cloud-init"
        fi
    fi

    local cloud_init_log="/var/log/cloud-init.log"
    if [[ -f "${cloud_init_log}" ]]; then
        print_info "cloud-init log available: ${cloud_init_log}"
    fi
}

_cloud_agent_processes() {
    print_subheader "Cloud Agent Processes"

    local -A agent_names=(
        ["amazon-cloudwatch-agent"]="AWS CloudWatch Agent"
        ["awsagent"]="AWS SSM Agent"
        ["sshd"]="SSH Daemon"
        ["waagent"]="Azure Linux Agent"
        ["google_accounts_daemon"]="GCP Account Daemon"
        ["google-ip-forwarding-daemon"]="GCP IP Forwarding"
        ["google_daemon"]="GCP Daemon"
        ["do-agent"]="DigitalOcean Agent"
    )

    local found_any=false
    local proc_name
    for proc_name in "${!agent_names[@]}"; do
        if pgrep -x "${proc_name}" &>/dev/null; then
            local pid
            pid="$(pgrep -x "${proc_name}" 2>/dev/null | head -1 || echo "")"
            print_info "Cloud agent running: ${agent_names[${proc_name}]} (${proc_name}, PID ${pid})"
            found_any=true
        fi
    done

    if [[ "${found_any}" == false ]]; then
        print_info "No known cloud agent processes detected"
    fi
}

_cloud_env_tokens() {
    print_subheader "Cloud Access Tokens in Environment"

    local -a token_patterns=(
        "AWS_ACCESS_KEY_ID"
        "AWS_SECRET_ACCESS_KEY"
        "AWS_SESSION_TOKEN"
        "AZURE_CLIENT_ID"
        "AZURE_CLIENT_SECRET"
        "AZURE_TENANT_ID"
        "GOOGLE_APPLICATION_CREDENTIALS"
        "GCLOUD_PROJECT"
        "DIGITALOCEAN_TOKEN"
        "DIGITALOCEAN_ACCESS_TOKEN"
        "TF_VAR_"
        "OCI_COMPARTMENT"
        "ARM_SUBSCRIPTION_ID"
        "ARM_CLIENT_ID"
        "ARM_CLIENT_SECRET"
    )

    local found_issue=false
    local pattern
    for pattern in "${token_patterns[@]}"; do
        local matches
        matches="$(env 2>/dev/null | grep -i "^${pattern}" || true)"
        if [[ -n "${matches}" ]]; then
            local key="${matches%%=*}"
            add_finding "${MODULE_NAME}" "MEDIUM" \
                "Cloud token in environment variable" \
                "${key} is set in the environment" \
                "variable=${key}" \
                "Use IAM roles, instance profiles, or workload identity instead of env tokens"
            print_warning "Cloud token in env: ${key}"
            found_issue=true
        fi
    done

    if [[ "${found_issue}" == false ]]; then
        print_success "No cloud tokens found in environment"
    fi
}

_cloud_config_credentials() {
    print_subheader "Cloud Config Files with Embedded Credentials"

    local found_issue=false

    local -a config_paths=(
        "${HOME}/.aws/config"
        "${HOME}/.aws/credentials"
        "${HOME}/.azure/accessTokens.json"
        "${HOME}/.azure/azureProfile.json"
        "${HOME}/.config/gcloud/credentials.db"
        "${HOME}/.config/gcloud/application_default_credentials.json"
        "${HOME}/.docker/config.json"
        "${HOME}/.kube/config"
        "/etc/kubernetes/admin.conf"
    )

    local config_path
    for config_path in "${config_paths[@]}"; do
        if [[ -f "${config_path}" ]]; then
            local perms
            perms="$(stat -c '%a' "${config_path}" 2>/dev/null || echo "")"
            if [[ -n "${perms}" && "${perms}" != "600" && "${perms}" != "400" ]]; then
                add_finding "${MODULE_NAME}" "MEDIUM" \
                    "Cloud config file has loose permissions" \
                    "${config_path} has mode ${perms}" \
                    "file=${config_path} mode=${perms}" \
                    "chmod 600 ${config_path}"
                print_warning "Loose permissions: ${config_path} (${perms})"
                found_issue=true
            fi
        fi
    done

    if [[ "${found_issue}" == false ]]; then
        print_success "Cloud config files have appropriate permissions"
    fi
}

_container_registry_credentials() {
    print_subheader "Container Registry Credentials"

    local found_issue=false

    local -a cred_files=(
        "${HOME}/.docker/config.json"
        "${HOME}/.docker/dockercfg"
        "${HOME}/.docker/config.json"
        "/run/secrets/dockerconfigjson"
        "${HOME}/.kube/config"
    )

    local cred_file
    for cred_file in "${cred_files[@]}"; do
        if [[ -f "${cred_file}" ]]; then
            if grep -qiE "auth|password|token|credential" "${cred_file}" 2>/dev/null; then
                local perms
                perms="$(stat -c '%a' "${cred_file}" 2>/dev/null || echo "")"
                if [[ -n "${perms}" && "${perms}" != "600" && "${perms}" != "400" ]]; then
                    add_finding "${MODULE_NAME}" "HIGH" \
                        "Container registry credentials with loose permissions" \
                        "${cred_file} has mode ${perms}" \
                        "file=${cred_file} mode=${perms}" \
                        "chmod 600 ${cred_file}"
                    print_error "Registry creds loose: ${cred_file} (${perms})"
                    found_issue=true
                else
                    print_info "Registry credentials found: ${cred_file} (${perms})"
                fi
            fi
        fi
    done

    if [[ "${found_issue}" == false ]]; then
        print_success "Container registry credentials look secure"
    fi
}

_cloud_ssh_keys() {
    print_subheader "Cloud SSH Key Management Artifacts"

    local found_issue=false

    local -a key_locations=(
        "/etc/ssh/sshd_config"
        "${HOME}/.ssh/authorized_keys"
        "/root/.ssh/authorized_keys"
    )

    local key_loc
    for key_loc in "${key_locations[@]}"; do
        if [[ -f "${key_loc}" ]]; then
            if grep -qi "cloud\|aws\|azure\|gcp\|do-" "${key_loc}" 2>/dev/null; then
                print_info "Cloud-managed SSH key found in: ${key_loc}"
            fi
        fi
    done

    local metadata_keys
    metadata_keys="$(curl -s --connect-timeout 2 -m 2 "http://169.254.169.254/latest/meta-data/public-keys/" 2>/dev/null || true)"
    if [[ -n "${metadata_keys}" ]]; then
        print_info "Cloud-managed SSH keys available via metadata"
    fi

    if [[ "${found_issue}" == false ]]; then
        print_success "SSH key management artifacts reviewed"
    fi
}

run() {
    print_header "Cloud Configuration Audit"

    _detect_cloud_provider
    _aws_cli_config
    _azure_cli_config
    _gcp_cli_config
    _metadata_endpoint
    _cloud_init_config
    _cloud_agent_processes
    _cloud_env_tokens
    _cloud_config_credentials
    _container_registry_credentials
    _cloud_ssh_keys
}

if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    run
fi
