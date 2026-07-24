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

readonly MODULE_NAME="kubernetes"
readonly MODULE_DESCRIPTION="Kubernetes security audit"
readonly MODULE_VERSION="1.0.0"
readonly MODULE_SEVERITY_THRESHOLD="info"

_kubectl_available() {
    print_subheader "kubectl Availability"

    if ! command -v kubectl &>/dev/null; then
        add_finding "kubernetes" "kubectl not found" "info" \
            "kubectl=not_found" \
            "Install kubectl for Kubernetes security auditing."
        print_warning "kubectl not found"
        return 1
    fi

    local kubectl_version
    kubectl_version=$(kubectl version --client --short 2>/dev/null | awk '{print $3}' || echo "unknown")

    add_finding "kubernetes" "kubectl available: ${kubectl_version}" "info" \
        "kubectl=version:${kubectl_version}"
    print_success "kubectl available: ${kubectl_version}"
    return 0
}

_cluster_info() {
    print_subheader "Cluster Info"

    if ! command -v kubectl &>/dev/null; then
        return
    fi

    if ! kubectl cluster-info &>/dev/null 2>&1; then
        add_finding "kubernetes" "Cannot access cluster info" "low" \
            "cluster=access_denied" \
            "Ensure kubeconfig is properly configured."
        print_warning "Cannot access cluster info - check kubeconfig"
        return
    fi

    local cluster_info
    cluster_info=$(kubectl cluster-info 2>/dev/null | head -1 || echo "unknown")

    add_finding "kubernetes" "Cluster accessible: ${cluster_info}" "info" \
        "cluster=${cluster_info}"
    print_success "Cluster accessible"

    local server
    server=$(kubectl cluster-info 2>/dev/null | grep "Kubernetes control plane" | awk '{print $NF}' || echo "unknown")
    if [[ "${server}" != "unknown" ]]; then
        print_finding "info" "  API Server: ${server}"
    fi
}

_namespaces() {
    print_subheader "Namespaces"

    if ! command -v kubectl &>/dev/null; then
        return
    fi

    if ! kubectl get namespaces &>/dev/null 2>&1; then
        print_warning "Cannot list namespaces"
        return
    fi

    local namespaces
    namespaces=$(kubectl get namespaces -o name 2>/dev/null | sed 's/namespace\///' || true)

    if [[ -z "${namespaces}" ]]; then
        add_finding "kubernetes" "No namespaces found" "info" \
            "namespaces=count:0"
        print_success "No namespaces found"
        return
    fi

    local count
    count=$(echo "${namespaces}" | grep -c . || echo "0")
    add_finding "kubernetes" "Namespaces: ${count}" "info" \
        "namespaces=count:${count}"
    print_success "Namespaces: ${count}"

    while IFS= read -r ns; do
        [[ -z "${ns}" ]] && continue
        print_finding "info" "  ${ns}"
    done <<< "${namespaces}"
}

_privileged_pods() {
    print_subheader "Privileged Pod Check"

    if ! command -v kubectl &>/dev/null; then
        return
    fi

    if ! kubectl get pods --all-namespaces &>/dev/null 2>&1; then
        print_warning "Cannot list pods"
        return
    fi

    local pods
    pods=$(kubectl get pods --all-namespaces -o json 2>/dev/null || echo "{}")

    if [[ "${pods}" == "{}" ]]; then
        add_finding "kubernetes" "No pods found" "info" \
            "pods=count:0"
        print_success "No pods found"
        return
    fi

    local privileged_count=0

    while IFS= read -r line; do
        [[ -z "${line}" ]] && continue

        local ns name
        ns=$(echo "${line}" | jq -r '.metadata.namespace' 2>/dev/null || continue)
        name=$(echo "${line}" | jq -r '.metadata.name' 2>/dev/null || continue)

        local containers
        containers=$(echo "${line}" | jq -c '.spec.containers[]?.securityContext.privileged // false' 2>/dev/null || true)

        while IFS= read -r priv; do
            if [[ "${priv}" == "true" ]]; then
                privileged_count=$((privileged_count + 1))
                add_finding "kubernetes" "Privileged pod: ${ns}/${name}" "critical" \
                    "pod=${ns}/${name} privileged=true" \
                    "Remove privileged flag and use specific capabilities."
                print_error "Privileged pod: ${ns}/${name}"
                break
            fi
        done <<< "${containers}"
    done <<< "$(echo "${pods}" | jq -c '.items[]' 2>/dev/null)"

    if [[ "${privileged_count}" -eq 0 ]]; then
        add_finding "kubernetes" "No privileged pods running" "info" \
            "privileged_pods=count:0"
        print_success "No privileged pods running"
    fi
}

_root_pods() {
    print_subheader "Root Pod Check"

    if ! command -v kubectl &>/dev/null; then
        return
    fi

    if ! kubectl get pods --all-namespaces &>/dev/null 2>&1; then
        return
    fi

    local pods
    pods=$(kubectl get pods --all-namespaces -o json 2>/dev/null || echo "{}")

    if [[ "${pods}" == "{}" ]]; then
        return
    fi

    local root_count=0

    while IFS= read -r line; do
        [[ -z "${line}" ]] && continue

        local ns name
        ns=$(echo "${line}" | jq -r '.metadata.namespace' 2>/dev/null || continue)
        name=$(echo "${line}" | jq -r '.metadata.name' 2>/dev/null || continue)

        local run_as_non_root
        run_as_non_root=$(echo "${line}" | jq -r '.spec.containers[]?.securityContext.runAsNonRoot // false' 2>/dev/null || echo "false")

        if [[ "${run_as_non_root}" != "true" ]]; then
            root_count=$((root_count + 1))
            add_finding "kubernetes" "Pod not explicitly running as non-root: ${ns}/${name}" "medium" \
                "pod=${ns}/${name} runAsNonRoot=${run_as_non_root}" \
                "Set securityContext.runAsNonRoot: true in pod spec."
            print_warning "Pod not running as non-root: ${ns}/${name}"
        fi
    done <<< "$(echo "${pods}" | jq -c '.items[]' 2>/dev/null)"

    if [[ "${root_count}" -eq 0 ]]; then
        add_finding "kubernetes" "All pods configured for non-root" "info" \
            "root_pods=count:0"
        print_success "All pods configured to run as non-root"
    fi
}

_host_pid_network_ipc() {
    print_subheader "hostPID/hostNetwork/hostIPC Check"

    if ! command -v kubectl &>/dev/null; then
        return
    fi

    if ! kubectl get pods --all-namespaces &>/dev/null 2>&1; then
        return
    fi

    local pods
    pods=$(kubectl get pods --all-namespaces -o json 2>/dev/null || echo "{}")

    if [[ "${pods}" == "{}" ]]; then
        return
    fi

    local issues_found=false

    while IFS= read -r line; do
        [[ -z "${line}" ]] && continue

        local ns name
        ns=$(echo "${line}" | jq -r '.metadata.namespace' 2>/dev/null || continue)
        name=$(echo "${line}" | jq -r '.metadata.name' 2>/dev/null || continue)

        local host_pid host_network host_ipc
        host_pid=$(echo "${line}" | jq -r '.spec.hostPID // false' 2>/dev/null || echo "false")
        host_network=$(echo "${line}" | jq -r '.spec.hostNetwork // false' 2>/dev/null || echo "false")
        host_ipc=$(echo "${line}" | jq -r '.spec.hostIPC // false' 2>/dev/null || echo "false")

        if [[ "${host_pid}" == "true" ]]; then
            issues_found=true
            add_finding "kubernetes" "Pod uses hostPID: ${ns}/${name}" "high" \
                "pod=${ns}/${name} hostPID=true" \
                "Remove hostPID: true from pod spec."
            print_error "hostPID enabled: ${ns}/${name}"
        fi

        if [[ "${host_network}" == "true" ]]; then
            issues_found=true
            add_finding "kubernetes" "Pod uses hostNetwork: ${ns}/${name}" "high" \
                "pod=${ns}/${name} hostNetwork=true" \
                "Remove hostNetwork: true from pod spec."
            print_error "hostNetwork enabled: ${ns}/${name}"
        fi

        if [[ "${host_ipc}" == "true" ]]; then
            issues_found=true
            add_finding "kubernetes" "Pod uses hostIPC: ${ns}/${name}" "high" \
                "pod=${ns}/${name} hostIPC=true" \
                "Remove hostIPC: true from pod spec."
            print_error "hostIPC enabled: ${ns}/${name}"
        fi
    done <<< "$(echo "${pods}" | jq -c '.items[]' 2>/dev/null)"

    if [[ "${issues_found}" == false ]]; then
        add_finding "kubernetes" "No pods using hostPID/hostNetwork/hostIPC" "info" \
            "host_namespace=count:0"
        print_success "No pods using hostPID/hostNetwork/hostIPC"
    fi
}

_host_path_mounts() {
    print_subheader "HostPath Mount Check"

    if ! command -v kubectl &>/dev/null; then
        return
    fi

    if ! kubectl get pods --all-namespaces &>/dev/null 2>&1; then
        return
    fi

    local pods
    pods=$(kubectl get pods --all-namespaces -o json 2>/dev/null || echo "{}")

    if [[ "${pods}" == "{}" ]]; then
        return
    fi

    local mount_count=0

    while IFS= read -r line; do
        [[ -z "${line}" ]] && continue

        local ns name
        ns=$(echo "${line}" | jq -r '.metadata.namespace' 2>/dev/null || continue)
        name=$(echo "${line}" | jq -r '.metadata.name' 2>/dev/null || continue)

        local host_paths
        host_paths=$(echo "${line}" | jq -r '.spec.volumes[]?.hostPath.path // empty' 2>/dev/null || true)

        while IFS= read -r hp; do
            [[ -z "${hp}" ]] && continue
            mount_count=$((mount_count + 1))
            print_finding "info" "  ${ns}/${name}: hostPath=${hp}"
        done <<< "${host_paths}"
    done <<< "$(echo "${pods}" | jq -c '.items[]' 2>/dev/null)"

    if [[ "${mount_count}" -gt 0 ]]; then
        add_finding "kubernetes" "HostPath mounts found: ${mount_count}" "medium" \
            "hostpath_mounts=count:${mount_count}" \
            "Minimize HostPath mounts. Use PersistentVolumes when possible."
        print_warning "HostPath mounts found: ${mount_count}"
    else
        add_finding "kubernetes" "No HostPath mounts detected" "info" \
            "hostpath_mounts=count:0"
        print_success "No HostPath mounts detected"
    fi
}

_rbac_check() {
    print_subheader "RBAC Configuration"

    if ! command -v kubectl &>/dev/null; then
        return
    fi

    if ! kubectl get clusterrolebindings &>/dev/null 2>&1; then
        print_warning "Cannot access RBAC configuration"
        return
    fi

    local cluster_role_bindings
    cluster_role_bindings=$(kubectl get clusterrolebindings -o json 2>/dev/null || echo "{}")

    if [[ "${cluster_role_bindings}" == "{}" ]]; then
        add_finding "kubernetes" "Cannot retrieve RBAC configuration" "low" \
            "rbac=access_denied"
        print_warning "Cannot retrieve RBAC configuration"
        return
    fi

    local crb_count
    crb_count=$(echo "${cluster_role_bindings}" | jq '.items | length' 2>/dev/null || echo "0")
    add_finding "kubernetes" "ClusterRoleBindings: ${crb_count}" "info" \
        "clusterrolebindings=count:${crb_count}"
    print_success "ClusterRoleBindings: ${crb_count}"

    local cluster_admin_count
    cluster_admin_count=$(echo "${cluster_role_bindings}" | jq '[.items[] | select(.roleRef.name == "cluster-admin")] | length' 2>/dev/null || echo "0")

    if [[ "${cluster_admin_count}" -gt 0 ]]; then
        add_finding "kubernetes" "ClusterRoleBindings with cluster-admin: ${cluster_admin_count}" "medium" \
            "cluster_admin_bindings=count:${cluster_admin_count}" \
            "Minimize cluster-admin bindings. Use least-privilege access."
        print_warning "Cluster-admin bindings: ${cluster_admin_count}"
    fi

    local service_accounts
    service_accounts=$(kubectl get clusterrolebindings -o json 2>/dev/null | jq -r '.items[]? | select(.subjects[]?.kind == "ServiceAccount") | "\(.metadata.name): \(.subjects[] | select(.kind == "ServiceAccount") | "\(.namespace)/\(.name)")"' 2>/dev/null || true)

    if [[ -n "${service_accounts}" ]]; then
        while IFS= read -r sa; do
            [[ -z "${sa}" ]] && continue
            print_finding "info" "  ServiceAccount binding: ${sa}"
        done <<< "${service_accounts}"
    fi
}

_service_account_token() {
    print_subheader "Service Account Token Automounting"

    if ! command -v kubectl &>/dev/null; then
        return
    fi

    if ! kubectl get serviceaccounts --all-namespaces &>/dev/null 2>&1; then
        print_warning "Cannot list service accounts"
        return
    fi

    local pods
    pods=$(kubectl get pods --all-namespaces -o json 2>/dev/null || echo "{}")

    if [[ "${pods}" == "{}" ]]; then
        return
    fi

    local auto_mount_count=0

    while IFS= read -r line; do
        [[ -z "${line}" ]] && continue

        local ns name
        ns=$(echo "${line}" | jq -r '.metadata.namespace' 2>/dev/null || continue)
        name=$(echo "${line}" | jq -r '.metadata.name' 2>/dev/null || continue)

        local automount
        automount=$(echo "${line}" | jq -r '.spec.automountServiceAccountToken // true' 2>/dev/null || echo "true")

        if [[ "${automount}" == "true" ]]; then
            auto_mount_count=$((auto_mount_count + 1))
        fi
    done <<< "$(echo "${pods}" | jq -c '.items[]' 2>/dev/null)"

    if [[ "${auto_mount_count}" -gt 0 ]]; then
        add_finding "kubernetes" "Pods with automountServiceAccountToken enabled: ${auto_mount_count}" "low" \
            "automount_tokens=count:${auto_mount_count}" \
            "Set automountServiceAccountToken: false when token is not needed."
        print_warning "Pods with auto-mounted tokens: ${auto_mount_count}"
    else
        add_finding "kubernetes" "No auto-mounted service account tokens" "info" \
            "automount_tokens=count:0"
        print_success "No auto-mounted service account tokens"
    fi
}

_dangerous_capabilities() {
    print_subheader "Container Capabilities Check"

    if ! command -v kubectl &>/dev/null; then
        return
    fi

    if ! kubectl get pods --all-namespaces &>/dev/null 2>&1; then
        return
    fi

    local pods
    pods=$(kubectl get pods --all-namespaces -o json 2>/dev/null || echo "{}")

    if [[ "${pods}" == "{}" ]]; then
        return
    fi

    local dangerous_caps=("SYS_ADMIN" "NET_ADMIN" "SYS_PTRACE" "SYS_MODULE" "SYS_RAWIO" "MKNOD" "AUDIT_WRITE" "SETFCAP")
    local cap_found=false

    while IFS= read -r line; do
        [[ -z "${line}" ]] && continue

        local ns name
        ns=$(echo "${line}" | jq -r '.metadata.namespace' 2>/dev/null || continue)
        name=$(echo "${line}" | jq -r '.metadata.name' 2>/dev/null || continue)

        local adds
        adds=$(echo "${line}" | jq -c '.spec.containers[]?.securityContext.capabilities.add[]? // empty' 2>/dev/null || true)

        while IFS= read -r cap; do
            [[ -z "${cap}" ]] && continue
            for dc in "${dangerous_caps[@]}"; do
                if [[ "${cap}" == "${dc}" ]]; then
                    cap_found=true
                    add_finding "kubernetes" "Dangerous capability ${dc} in pod: ${ns}/${name}" "high" \
                        "pod=${ns}/${name} capability=${dc}" \
                        "Remove unnecessary capabilities."
                    print_error "Pod ${ns}/${name} has capability: ${dc}"
                fi
            done
        done <<< "${adds}"
    done <<< "$(echo "${pods}" | jq -c '.items[]' 2>/dev/null)"

    if [[ "${cap_found}" == false ]]; then
        add_finding "kubernetes" "No dangerous capabilities detected" "info" \
            "dangerous_caps=count:0"
        print_success "No dangerous capabilities detected"
    fi
}

_secrets_check() {
    print_subheader "Secrets (Names Only)"

    if ! command -v kubectl &>/dev/null; then
        return
    fi

    if ! kubectl get secrets --all-namespaces &>/dev/null 2>&1; then
        print_warning "Cannot list secrets"
        return
    fi

    local secrets
    secrets=$(kubectl get secrets --all-namespaces -o json 2>/dev/null || echo "{}")

    if [[ "${secrets}" == "{}" ]]; then
        add_finding "kubernetes" "No secrets found" "info" \
            "secrets=count:0"
        print_success "No secrets found"
        return
    fi

    local secret_count
    secret_count=$(echo "${secrets}" | jq '.items | length' 2>/dev/null || echo "0")
    add_finding "kubernetes" "Secrets found: ${secret_count} (names only, values not exposed)" "info" \
        "secrets=count:${secret_count}"
    print_success "Secrets found: ${secret_count} (names only)"

    while IFS= read -r line; do
        [[ -z "${line}" ]] && continue
        local ns name
        ns=$(echo "${line}" | jq -r '.metadata.namespace' 2>/dev/null || continue)
        name=$(echo "${line}" | jq -r '.metadata.name' 2>/dev/null || continue)
        print_finding "info" "  ${ns}/${name}"
    done <<< "$(echo "${secrets}" | jq -c '.items[]' 2>/dev/null)"
}

_network_policies() {
    print_subheader "Network Policies"

    if ! command -v kubectl &>/dev/null; then
        return
    fi

    if ! kubectl get networkpolicies --all-namespaces &>/dev/null 2>&1; then
        add_finding "kubernetes" "Cannot list network policies (CRD may not be installed)" "low" \
            "network_policies=not_accessible" \
            "Install a CNI that supports NetworkPolicy."
        print_warning "Cannot list network policies"
        return
    fi

    local policies
    policies=$(kubectl get networkpolicies --all-namespaces -o json 2>/dev/null || echo "{}")

    local policy_count
    policy_count=$(echo "${policies}" | jq '.items | length' 2>/dev/null || echo "0")

    if [[ "${policy_count}" -eq 0 ]]; then
        add_finding "kubernetes" "No network policies defined" "medium" \
            "network_policies=count:0" \
            "Define NetworkPolicies to restrict pod-to-pod communication."
        print_warning "No network policies defined"
    else
        add_finding "kubernetes" "Network policies: ${policy_count}" "info" \
            "network_policies=count:${policy_count}"
        print_success "Network policies: ${policy_count}"
    fi
}

_pod_security_policies() {
    print_subheader "Pod Security Policies/Standards"

    if ! command -v kubectl &>/dev/null; then
        return
    fi

    local psp_count=0
    if kubectl get podsecuritypolicies &>/dev/null 2>&1; then
        psp_count=$(kubectl get podsecuritypolicies -o name 2>/dev/null | wc -l || echo "0")
    fi

    local psa_count=0
    if kubectl get namespaces -o json 2>/dev/null | jq -e '.items[].metadata.labels["pod-security.kubernetes.io/enforce"]' &>/dev/null 2>&1; then
        psa_count=$(kubectl get namespaces -o json 2>/dev/null | jq '[.items[] | select(.metadata.labels["pod-security.kubernetes.io/enforce"])] | length' 2>/dev/null || echo "0")
    fi

    if [[ "${psp_count}" -eq 0 && "${psa_count}" -eq 0 ]]; then
        add_finding "kubernetes" "No Pod Security Policies or Standards enforced" "medium" \
            "psp=count:0 psa=count:0" \
            "Enable Pod Security Admission or PSPs to restrict pod security."
        print_warning "No Pod Security Policies/Standards enforced"
    else
        add_finding "kubernetes" "PSPs: ${psp_count}, PSA-enforced namespaces: ${psa_count}" "info" \
            "psp=count:${psp_count} psa=count:${psa_count}"
        print_success "PSPs: ${psp_count}, PSA-enforced namespaces: ${psa_count}"
    fi
}

_exposed_services() {
    print_subheader "Exposed Services"

    if ! command -v kubectl &>/dev/null; then
        return
    fi

    if ! kubectl get services --all-namespaces &>/dev/null 2>&1; then
        print_warning "Cannot list services"
        return
    fi

    local services
    services=$(kubectl get services --all-namespaces -o json 2>/dev/null || echo "{}")

    if [[ "${services}" == "{}" ]]; then
        add_finding "kubernetes" "No services found" "info" \
            "services=count:0"
        print_success "No services found"
        return
    fi

    local service_count
    service_count=$(echo "${services}" | jq '.items | length' 2>/dev/null || echo "0")
    add_finding "kubernetes" "Services: ${service_count}" "info" \
        "services=count:${service_count}"
    print_success "Services: ${service_count}"

    while IFS= read -r line; do
        [[ -z "${line}" ]] && continue
        local ns name stype
        ns=$(echo "${line}" | jq -r '.metadata.namespace' 2>/dev/null || continue)
        name=$(echo "${line}" | jq -r '.metadata.name' 2>/dev/null || continue)
        stype=$(echo "${line}" | jq -r '.spec.type' 2>/dev/null || echo "unknown")

        if [[ "${stype}" == "LoadBalancer" || "${stype}" == "NodePort" ]]; then
            add_finding "kubernetes" "Externally exposed service: ${ns}/${name} (${stype})" "medium" \
                "service=${ns}/${name} type=${stype}" \
                "Use ClusterIP for internal-only services."
            print_warning "Exposed service: ${ns}/${name} (${stype})"
        else
            print_finding "info" "  ${ns}/${name} (${stype})"
        fi
    done <<< "$(echo "${services}" | jq -c '.items[]' 2>/dev/null)"
}

run() {
    print_header "Kubernetes Security Audit"

    if ! _kubectl_available; then
        return
    fi

    _cluster_info
    _namespaces
    _privileged_pods
    _root_pods
    _host_pid_network_ipc
    _host_path_mounts
    _rbac_check
    _service_account_token
    _dangerous_capabilities
    _secrets_check
    _network_policies
    _pod_security_policies
    _exposed_services
}

if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    run
fi