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

readonly MODULE_NAME="containers"
readonly MODULE_DESCRIPTION="Container runtime audit"
readonly MODULE_VERSION="1.0.0"
readonly MODULE_SEVERITY_THRESHOLD="info"

_detect_runtimes() {
    print_subheader "Detecting Container Runtimes"

    local -A runtimes=()
    local runtime_binaries=("docker" "podman" "lxc-start" "containerd" "crio" "crictl" "nerdctl")

    for binary in "${runtime_binaries[@]}"; do
        if command -v "${binary}" &>/dev/null; then
            runtimes["${binary}"]="found"
            print_success "Runtime found: ${binary}"
        fi
    done

    if [[ "${#runtimes[@]}" -eq 0 ]]; then
        print_info "No container runtimes detected"
    else
        add_finding "${MODULE_NAME}" "INFO" \
            "Container runtimes detected" \
            "Found ${#runtimes[@]} container runtime(s): ${!runtimes[*]}" \
            "runtimes=${!runtimes[*]}"
    fi

    if [[ -S /var/run/docker.sock ]]; then
        local sock_perms
        sock_perms="$(stat -c '%a' /var/run/docker.sock 2>/dev/null || echo "")"
        local sock_owner
        sock_owner="$(stat -c '%U' /var/run/docker.sock 2>/dev/null || echo "")"

        if [[ "${sock_owner}" != "root" ]]; then
            add_finding "${MODULE_NAME}" "HIGH" \
                "Docker socket owned by non-root" \
                "/var/run/docker.sock owned by ${sock_owner}" \
                "socket=/var/run/docker.sock owner=${sock_owner}" \
                "Ensure docker socket is owned by root:docker"
            print_error "Docker socket owner: ${sock_owner}"
        fi

        if [[ -n "${sock_perms}" ]]; then
            local group_write=$(( 8#${sock_perms} & 8#0020 ))
            if [[ "${group_write}" -ne 0 ]]; then
                print_info "Docker socket group-writable (perms: ${sock_perms})"
            fi
        fi
    fi
}

_list_running_containers() {
    print_subheader "Running Containers"

    local found=false

    if command -v docker &>/dev/null; then
        local docker_containers
        docker_containers="$(docker ps --format '{{.ID}}\t{{.Image}}\t{{.Status}}\t{{.Names}}' 2>/dev/null || true)"
        if [[ -n "${docker_containers}" ]]; then
            print_table_header "CONTAINER ID" "IMAGE" "STATUS" "NAME"
            local line
            while IFS= read -r line; do
                [[ -z "${line}" ]] && continue
                local cid image status name
                cid="$(echo "${line}" | cut -f1)"
                image="$(echo "${line}" | cut -f2)"
                status="$(echo "${line}" | cut -f3)"
                name="$(echo "${line}" | cut -f4)"
                print_table_row "${cid}" "${image}" "${status}" "${name}"
                found=true
            done <<< "${docker_containers}"
        fi
    fi

    if command -v podman &>/dev/null; then
        local podman_containers
        podman_containers="$(podman ps --format '{{.ID}}\t{{.Image}}\t{{.Status}}\t{{.Names}}' 2>/dev/null || true)"
        if [[ -n "${podman_containers}" ]]; then
            print_info "Podman containers:"
            local line
            while IFS= read -r line; do
                [[ -z "${line}" ]] && continue
                echo "  ${line}"
                found=true
            done <<< "${podman_containers}"
        fi
    fi

    if [[ "${found}" == false ]]; then
        print_success "No running containers found"
    fi
}

_container_isolation() {
    print_subheader "Container Isolation Settings"

    if ! command -v docker &>/dev/null; then
        print_info "Docker not available, skipping isolation check"
        return
    fi

    local container_ids
    container_ids="$(docker ps -q 2>/dev/null || true)"
    if [[ -z "${container_ids}" ]]; then
        print_info "No running Docker containers"
        return
    fi

    local found_issue=false
    local cid
    while IFS= read -r cid; do
        [[ -z "${cid}" ]] && continue

        local inspect
        inspect="$(docker inspect "${cid}" 2>/dev/null || true)"
        [[ -z "${inspect}" ]] && continue

        local name
        name="$(echo "${inspect}" | grep -oP '"Name":\s*"\K[^"]+' | head -1 || echo "${cid}")"

        local pid_mode
        pid_mode="$(echo "${inspect}" | grep -oP '"PidMode":\s*"\K[^"]+' || echo "")"
        if [[ "${pid_mode}" == "host" ]]; then
            add_finding "${MODULE_NAME}" "HIGH" \
                "Container uses host PID namespace" \
                "${name} (CID: ${cid}) shares host PID namespace" \
                "container=${cid} name=${name} pid_mode=host" \
                "Remove --pid=host from container configuration"
            print_error "Host PID namespace: ${name}"
            found_issue=true
        fi

        local net_mode
        net_mode="$(echo "${inspect}" | grep -oP '"NetworkMode":\s*"\K[^"]+' || echo "")"
        if [[ "${net_mode}" == "host" ]]; then
            add_finding "${MODULE_NAME}" "HIGH" \
                "Container uses host network namespace" \
                "${name} (CID: ${cid}) shares host network namespace" \
                "container=${cid} name=${name} network_mode=host" \
                "Use bridge networking instead of --network=host"
            print_error "Host network namespace: ${name}"
            found_issue=true
        fi

        local privileged
        privileged="$(echo "${inspect}" | grep -oP '"Privileged":\s*\K(true|false)' || echo "false")"
        if [[ "${privileged}" == "true" ]]; then
            add_finding "${MODULE_NAME}" "CRITICAL" \
                "Privileged container detected" \
                "${name} (CID: ${cid}) is running in privileged mode" \
                "container=${cid} name=${name} privileged=true" \
                "Remove --privileged flag; use specific capabilities instead"
            print_error "PRIVILEGED container: ${name}"
            found_issue=true
        fi
    done <<< "${container_ids}"

    if [[ "${found_issue}" == false ]]; then
        print_success "Container isolation settings look acceptable"
    fi
}

_privileged_containers() {
    print_subheader "Privileged and Escalated Containers"

    if ! command -v docker &>/dev/null; then
        return
    fi

    local container_ids
    container_ids="$(docker ps -q 2>/dev/null || true)"
    if [[ -z "${container_ids}" ]]; then
        return
    fi

    local found_issue=false
    local cid
    while IFS= read -r cid; do
        [[ -z "${cid}" ]] && continue

        local inspect
        inspect="$(docker inspect "${cid}" 2>/dev/null || true)"
        [[ -z "${inspect}" ]] && continue

        local name
        name="$(echo "${inspect}" | grep -oP '"Name":\s*"\K[^"]+' | head -1 || echo "${cid}")"

        local caps_add
        caps_add="$(echo "${inspect}" | grep -oP '"CapAdd":\s*\[[^\]]*\]' || echo "[]")"
        if [[ "${caps_add}" != *"[]"* && -n "${caps_add}" ]]; then
            add_finding "${MODULE_NAME}" "HIGH" \
                "Container has additional capabilities" \
                "${name} (CID: ${cid}) has CapAdd: ${caps_add}" \
                "container=${cid} name=${name} caps_add=${caps_add}" \
                "Remove unnecessary capabilities; use principle of least privilege"
            print_warning "Extra caps: ${name} - ${caps_add}"
            found_issue=true
        fi

        local security_opt
        security_opt="$(echo "${inspect}" | grep -oP '"SecurityOpt":\s*\[[^\]]*\]' || echo "[]")"
        if [[ "${security_opt}" == *"apparmor=unconfined"* || "${security_opt}" == *"seccomp=unconfined"* ]]; then
            add_finding "${MODULE_NAME}" "HIGH" \
                "Container has security profiles disabled" \
                "${name} (CID: ${cid}) has security opt: ${security_opt}" \
                "container=${cid} name=${name} security_opt=${security_opt}" \
                "Enable AppArmor/SELinux and seccomp profiles"
            print_error "Security profiles disabled: ${name}"
            found_issue=true
        fi
    done <<< "${container_ids}"

    if [[ "${found_issue}" == false ]]; then
        print_success "No privileged or escalated containers found"
    fi
}

_host_namespace_access() {
    print_subheader "Host Namespace Access"

    if ! command -v docker &>/dev/null; then
        return
    fi

    local container_ids
    container_ids="$(docker ps -q 2>/dev/null || true)"
    if [[ -z "${container_ids}" ]]; then
        return
    fi

    local found_issue=false
    local cid
    while IFS= read -r cid; do
        [[ -z "${cid}" ]] && continue

        local inspect
        inspect="$(docker inspect "${cid}" 2>/dev/null || true)"
        [[ -z "${inspect}" ]] && continue

        local name
        name="$(echo "${inspect}" | grep -oP '"Name":\s*"\K[^"]+' | head -1 || echo "${cid}")"

        local uts_mode
        uts_mode="$(echo "${inspect}" | grep -oP '"UtsMode":\s*"\K[^"]+' || echo "")"
        if [[ "${uts_mode}" == "host" ]]; then
            add_finding "${MODULE_NAME}" "HIGH" \
                "Container shares host UTS namespace" \
                "${name} shares host UTS namespace" \
                "container=${cid} name=${name}" \
                "Remove --uts=host"
            print_error "Host UTS namespace: ${name}"
            found_issue=true
        fi

        local ipc_mode
        ipc_mode="$(echo "${inspect}" | grep -oP '"IpcMode":\s*"\K[^"]+' || echo "")"
        if [[ "${ipc_mode}" == "host" ]]; then
            add_finding "${MODULE_NAME}" "HIGH" \
                "Container shares host IPC namespace" \
                "${name} shares host IPC namespace" \
                "container=${cid} name=${name}" \
                "Remove --ipc=host"
            print_error "Host IPC namespace: ${name}"
            found_issue=true
        fi

        local user_mode
        user_mode="$(echo "${inspect}" | grep -oP '"UsernsMode":\s*"\K[^"]+' || echo "")"
        if [[ "${user_mode}" == "host" ]]; then
            add_finding "${MODULE_NAME}" "MEDIUM" \
                "Container shares host user namespace" \
                "${name} shares host user namespace" \
                "container=${cid} name=${name}" \
                "Use user namespace remapping"
            print_warning "Host user namespace: ${name}"
            found_issue=true
        fi
    done <<< "${container_ids}"

    if [[ "${found_issue}" == false ]]; then
        print_success "No host namespace sharing detected"
    fi
}

_container_escape_indicators() {
    print_subheader "Container Escape Indicators"

    if ! command -v docker &>/dev/null; then
        return
    fi

    local container_ids
    container_ids="$(docker ps -q 2>/dev/null || true)"
    if [[ -z "${container_ids}" ]]; then
        return
    fi

    local found_issue=false
    local cid
    while IFS= read -r cid; do
        [[ -z "${cid}" ]] && continue

        local inspect
        inspect="$(docker inspect "${cid}" 2>/dev/null || true)"
        [[ -z "${inspect}" ]] && continue

        local name
        name="$(echo "${inspect}" | grep -oP '"Name":\s*"\K[^"]+' | head -1 || echo "${cid}")"

        local mounts
        mounts="$(echo "${inspect}" | grep -oP '"Source":\s*"\K[^"]+' || true)"

        local dangerous_mounts=("/" "/etc" "/var/run/docker.sock" "/proc" "/sys" "/dev")
        local mount
        while IFS= read -r mount; do
            [[ -z "${mount}" ]] && continue
            for dangerous in "${dangerous_mounts[@]}"; do
                if [[ "${mount}" == "${dangerous}" || "${mount}" == "${dangerous}/"* ]]; then
                    add_finding "${MODULE_NAME}" "CRITICAL" \
                        "Dangerous volume mount detected" \
                        "${name} (CID: ${cid}) mounts ${mount}" \
                        "container=${cid} name=${name} mount=${mount}" \
                        "Remove dangerous volume mount: ${mount}"
                    print_error "DANGEROUS MOUNT: ${name} -> ${mount}"
                    found_issue=true
                    break
                fi
            done
        done <<< "${mounts}"
    done <<< "${container_ids}"

    if [[ "${found_issue}" == false ]]; then
        print_success "No container escape indicators found"
    fi
}

_image_trust() {
    print_subheader "Container Image Trust"

    if ! command -v docker &>/dev/null; then
        return
    fi

    local container_ids
    container_ids="$(docker ps -q 2>/dev/null || true)"
    if [[ -z "${container_ids}" ]]; then
        return
    fi

    local found_issue=false
    local cid
    while IFS= read -r cid; do
        [[ -z "${cid}" ]] && continue

        local image
        image="$(docker inspect --format '{{.Config.Image}}' "${cid}" 2>/dev/null || true)"
        [[ -z "${image}" ]] && continue

        local name
        name="$(docker inspect --format '{{.Name}}' "${cid}" 2>/dev/null | sed 's|^/||' || echo "${cid}")"

        if [[ "${image}" != *":"* ]]; then
            add_finding "${MODULE_NAME}" "MEDIUM" \
                "Container using latest tag" \
                "${name} uses image ${image} (implicitly :latest)" \
                "container=${cid} name=${name} image=${image}" \
                "Pin images to specific version tags or digests"
            print_warning "Latest tag: ${name} (${image})"
            found_issue=true
        fi

        if [[ "${image}" == docker.io/library/* ]] || [[ "${image}" != */* && "${image}" != *"."* ]]; then
            add_finding "${MODULE_NAME}" "LOW" \
                "Container using official Docker Hub image" \
                "${name} uses image ${image}" \
                "container=${cid} name=${name} image=${image}" \
                "Verify image integrity; use private registry for production"
            print_info "Official image: ${name} (${image})"
        fi
    done <<< "${container_ids}"

    if [[ "${found_issue}" == false ]]; then
        print_success "Image trust settings look acceptable"
    fi
}

_resource_limits() {
    print_subheader "Container Resource Limits"

    if ! command -v docker &>/dev/null; then
        return
    fi

    local container_ids
    container_ids="$(docker ps -q 2>/dev/null || true)"
    if [[ -z "${container_ids}" ]]; then
        return
    fi

    local found_issue=false
    local cid
    while IFS= read -r cid; do
        [[ -z "${cid}" ]] && continue

        local inspect
        inspect="$(docker inspect "${cid}" 2>/dev/null || true)"
        [[ -z "${inspect}" ]] && continue

        local name
        name="$(echo "${inspect}" | grep -oP '"Name":\s*"\K[^"]+' | head -1 || echo "${cid}")"

        local memory_limit
        memory_limit="$(echo "${inspect}" | grep -oP '"Memory":\s*\K[0-9]+' || echo "0")"
        if [[ "${memory_limit}" -eq 0 ]]; then
            add_finding "${MODULE_NAME}" "MEDIUM" \
                "Container has no memory limit" \
                "${name} (CID: ${cid}) has no memory limit set" \
                "container=${cid} name=${name}" \
                "Set memory limit with --memory flag"
            print_warning "No memory limit: ${name}"
            found_issue=true
        fi

        local cpu_limit
        cpu_limit="$(echo "${inspect}" | grep -oP '"NanoCpus":\s*\K[0-9]+' || echo "0")"
        local cpu_quota
        cpu_quota="$(echo "${inspect}" | grep -oP '"CpuQuota":\s*\K[0-9]+' || echo "0")"
        if [[ "${cpu_limit}" -eq 0 && "${cpu_quota}" -eq 0 ]]; then
            add_finding "${MODULE_NAME}" "LOW" \
                "Container has no CPU limit" \
                "${name} (CID: ${cid}) has no CPU limit set" \
                "container=${cid} name=${name}" \
                "Set CPU limit with --cpus flag"
            print_info "No CPU limit: ${name}"
        fi
    done <<< "${container_ids}"

    if [[ "${found_issue}" == false ]]; then
        print_success "Container resource limits configured"
    fi
}

_container_networking() {
    print_subheader "Container Networking"

    if ! command -v docker &>/dev/null; then
        return
    fi

    local networks
    networks="$(docker network ls --format '{{.Name}}\t{{.Driver}}' 2>/dev/null || true)"
    if [[ -n "${networks}" ]]; then
        print_info "Docker networks:"
        local line
        while IFS= read -r line; do
            [[ -z "${line}" ]] && continue
            local net_name net_driver
            net_name="$(echo "${line}" | cut -f1)"
            net_driver="$(echo "${line}" | cut -f2)"
            echo "  ${net_name} (${net_driver})"

            if [[ "${net_name}" == "host" ]]; then
                add_finding "${MODULE_NAME}" "MEDIUM" \
                    "Docker host network in use" \
                    "Container(s) using host network mode" \
                    "network=host" \
                    "Use bridge networking to isolate containers"
                print_warning "Host network detected"
            fi
        done <<< "${networks}"
    fi
}

_runtime_socket_exposure() {
    print_subheader "Container Runtime Socket Exposure"

    local found_issue=false

    local -a socket_paths=(
        "/var/run/docker.sock"
        "/run/docker.sock"
        "/var/run/containerd/containerd.sock"
        "/run/containerd/containerd.sock"
        "/var/run/crio/crio.sock"
        "/run/crio/crio.sock"
    )

    local sock
    for sock in "${socket_paths[@]}"; do
        if [[ -S "${sock}" ]]; then
            local perms owner
            perms="$(stat -c '%A' "${sock}" 2>/dev/null || echo "")"
            owner="$(stat -c '%U' "${sock}" 2>/dev/null || echo "")"

            if [[ "${owner}" != "root" ]]; then
                add_finding "${MODULE_NAME}" "CRITICAL" \
                    "Container runtime socket not owned by root" \
                    "${sock} owned by ${owner}" \
                    "socket=${sock} owner=${owner}" \
                    "Ensure socket is owned by root"
                print_error "Socket not root-owned: ${sock}"
                found_issue=true
            fi

            if [[ -n "${perms}" ]]; then
                local group_write=$(( 8#$(stat -c '%a' "${sock}" 2>/dev/null || echo 0) & 8#0020 ))
                if [[ "${group_write}" -ne 0 ]]; then
                    print_info "Socket group-writable: ${sock} (${perms})"
                fi
            fi

            print_info "Runtime socket: ${sock} (${perms}, owner: ${owner})"
        fi
    done

    if [[ "${found_issue}" == false ]]; then
        print_success "Runtime sockets have appropriate ownership"
    fi
}

_rootless_config() {
    print_subheader "Rootless Container Configuration"

    if command -v docker &>/dev/null; then
        local docker_info
        docker_info="$(docker info 2>/dev/null || true)"

        if echo "${docker_info}" | grep -qi "rootless"; then
            print_success "Docker is running in rootless mode"
        else
            local docker_userns
            docker_userns="$(echo "${docker_info}" | grep -oP 'User Namespace:\s*\K.*' || echo "")"
            if [[ "${docker_userns}" == *"enabled"* ]]; then
                print_success "User namespace remapping enabled"
            else
                add_finding "${MODULE_NAME}" "LOW" \
                    "Docker running as root without user namespace remapping" \
                    "Docker daemon running as root without userns-remap" \
                    "Enable user namespace remapping for better isolation" \
                    "Configure userns-remap in /etc/docker/daemon.json"
                print_warning "Docker running as root without userns-remap"
            fi
        fi
    fi

    if command -v podman &>/dev/null; then
        if podman info 2>/dev/null | grep -qi "rootless"; then
            print_success "Podman running in rootless mode"
        fi
    fi
}

_container_logging() {
    print_subheader "Container Logging Configuration"

    if ! command -v docker &>/dev/null; then
        return
    fi

    local container_ids
    container_ids="$(docker ps -q 2>/dev/null || true)"
    if [[ -z "${container_ids}" ]]; then
        return
    fi

    local cid
    while IFS= read -r cid; do
        [[ -z "${cid}" ]] && continue

        local name
        name="$(docker inspect --format '{{.Name}}' "${cid}" 2>/dev/null | sed 's|^/||' || echo "${cid}")"

        local log_driver
        log_driver="$(docker inspect --format '{{.LogConfig.Type}}' "${cid}" 2>/dev/null || echo "unknown")"

        if [[ "${log_driver}" == "none" ]]; then
            add_finding "${MODULE_NAME}" "MEDIUM" \
                "Container logging disabled" \
                "${name} (CID: ${cid}) has log driver: none" \
                "container=${cid} name=${name} log_driver=none" \
                "Enable logging for forensic capability"
            print_warning "Logging disabled: ${name}"
        fi
    done <<< "${container_ids}"

    print_success "Container logging configuration reviewed"
}

run() {
    print_header "Container Runtime Audit"

    _detect_runtimes
    _list_running_containers
    _container_isolation
    _privileged_containers
    _host_namespace_access
    _container_escape_indicators
    _image_trust
    _resource_limits
    _container_networking
    _runtime_socket_exposure
    _rootless_config
    _container_logging
}

if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    run
fi
