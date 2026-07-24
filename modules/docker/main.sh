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

readonly MODULE_NAME="docker"
readonly MODULE_DESCRIPTION="Docker security audit"
readonly MODULE_VERSION="1.0.0"
readonly MODULE_SEVERITY_THRESHOLD="info"

_docker_daemon_running() {
    print_subheader "Docker Daemon Status"

    if ! command -v docker &>/dev/null; then
        add_finding "docker" "Docker not installed" "info" \
            "docker_cli=not_found" \
            "Docker is not installed on this system."
        print_warning "Docker CLI not found - Docker may not be installed"
        return
    fi

    if ! docker info &>/dev/null 2>&1; then
        add_finding "docker" "Docker daemon is not running" "medium" \
            "daemon=status:stopped" \
            "Start Docker: systemctl start docker"
        print_error "Docker daemon is not running"
        return
    fi

    add_finding "docker" "Docker daemon is running" "info" \
        "daemon=status:running"
    print_success "Docker daemon is running"
}

_docker_version() {
    print_subheader "Docker Version"

    if ! command -v docker &>/dev/null; then
        return
    fi

    local docker_version
    docker_version=$(docker version --format '{{.Server.Version}}' 2>/dev/null || echo "unknown")

    if [[ "${docker_version}" == "unknown" ]]; then
        docker_version=$(docker --version 2>/dev/null | awk '{print $3}' | tr -d ',' || echo "unknown")
    fi

    add_finding "docker" "Docker version: ${docker_version}" "info" \
        "version=${docker_version}"
    print_success "Docker version: ${docker_version}"
}

_running_containers() {
    print_subheader "Running Containers"

    if ! command -v docker &>/dev/null; then
        return
    fi

    if ! docker info &>/dev/null 2>&1; then
        return
    fi

    local containers
    containers=$(docker ps --format '{{.ID}} {{.Names}} {{.Image}} {{.Status}}' 2>/dev/null || true)

    if [[ -z "${containers}" ]]; then
        add_finding "docker" "No running containers" "info" \
            "containers=count:0"
        print_success "No running containers"
        return
    fi

    local count
    count=$(echo "${containers}" | grep -c . || echo "0")
    add_finding "docker" "Running containers: ${count}" "info" \
        "containers=count:${count}"
    print_success "Running containers: ${count}"

    while IFS= read -r line; do
        [[ -z "${line}" ]] && continue
        local name image status
        name=$(echo "${line}" | awk '{print $2}')
        image=$(echo "${line}" | awk '{print $3}')
        status=$(echo "${line}" | awk '{$1=$2=$3=""; print $0}' | sed 's/^[[:space:]]*//')
        print_finding "info" "  ${name} [${image}] - ${status}"
    done <<< "${containers}"
}

_all_containers() {
    print_subheader "All Containers (Including Stopped)"

    if ! command -v docker &>/dev/null; then
        return
    fi

    if ! docker info &>/dev/null 2>&1; then
        return
    fi

    local containers
    containers=$(docker ps -a --format '{{.ID}} {{.Names}} {{.Image}} {{.Status}}' 2>/dev/null || true)

    if [[ -z "${containers}" ]]; then
        add_finding "docker" "No containers found" "info" \
            "containers=count:0"
        print_success "No containers found"
        return
    fi

    local total_count
    total_count=$(echo "${containers}" | grep -c . || echo "0")
    local stopped_count
    stopped_count=$(echo "${containers}" | grep -ci "exited\|created" || echo "0")

    add_finding "docker" "Total containers: ${total_count} (${stopped_count} stopped)" "info" \
        "containers=total:${total_count} stopped:${stopped_count}"
    print_success "Total containers: ${total_count} (${stopped_count} stopped)"
}

_privileged_containers() {
    print_subheader "Privileged Container Check"

    if ! command -v docker &>/dev/null; then
        return
    fi

    if ! docker info &>/dev/null 2>&1; then
        return
    fi

    local container_ids
    container_ids=$(docker ps -q 2>/dev/null || true)

    if [[ -z "${container_ids}" ]]; then
        print_success "No running containers to check"
        return
    fi

    local privileged_found=false

    while IFS= read -r cid; do
        [[ -z "${cid}" ]] && continue

        local name
        name=$(docker inspect --format '{{.Name}}' "${cid}" 2>/dev/null | sed 's/^\///' || echo "${cid}")

        local privileged
        privileged=$(docker inspect --format '{{.HostConfig.Privileged}}' "${cid}" 2>/dev/null || echo "unknown")

        if [[ "${privileged}" == "true" ]]; then
            privileged_found=true
            add_finding "docker" "Privileged container: ${name}" "critical" \
                "container=${name} privileged=true" \
                "Remove --privileged flag or use specific capabilities."
            print_error "PRIVILEGED container: ${name}"
        fi
    done <<< "${container_ids}"

    if [[ "${privileged_found}" == false ]]; then
        add_finding "docker" "No privileged containers running" "info" \
            "privileged=count:0"
        print_success "No privileged containers running"
    fi
}

_root_containers() {
    print_subheader "Root Container Check"

    if ! command -v docker &>/dev/null; then
        return
    fi

    if ! docker info &>/dev/null 2>&1; then
        return
    fi

    local container_ids
    container_ids=$(docker ps -q 2>/dev/null || true)

    if [[ -z "${container_ids}" ]]; then
        print_success "No running containers to check"
        return
    fi

    local root_count=0

    while IFS= read -r cid; do
        [[ -z "${cid}" ]] && continue

        local name
        name=$(docker inspect --format '{{.Name}}' "${cid}" 2>/dev/null | sed 's/^\///' || echo "${cid}")

        local user
        user=$(docker inspect --format '{{.Config.User}}' "${cid}" 2>/dev/null || echo "")

        if [[ -z "${user}" || "${user}" == "root" || "${user}" == "0" ]]; then
            root_count=$((root_count + 1))
            add_finding "docker" "Container running as root: ${name}" "medium" \
                "container=${name} user=${user:-root}" \
                "Run container with non-root user: --user <uid>:<gid>"
            print_warning "Container running as root: ${name}"
        fi
    done <<< "${container_ids}"

    if [[ "${root_count}" -eq 0 ]]; then
        add_finding "docker" "No containers running as root" "info" \
            "root_containers=count:0"
        print_success "No containers running as root"
    fi
}

_host_mounts() {
    print_subheader "Host Mount Check"

    if ! command -v docker &>/dev/null; then
        return
    fi

    if ! docker info &>/dev/null 2>&1; then
        return
    fi

    local container_ids
    container_ids=$(docker ps -q 2>/dev/null || true)

    if [[ -z "${container_ids}" ]]; then
        print_success "No running containers to check"
        return
    fi

    local dangerous_paths=("/proc" "/sys" "/etc" "/var/run/docker.sock")
    local mount_found=false

    while IFS= read -r cid; do
        [[ -z "${cid}" ]] && continue

        local name
        name=$(docker inspect --format '{{.Name}}' "${cid}" 2>/dev/null | sed 's/^\///' || echo "${cid}")

        local mounts
        mounts=$(docker inspect --format '{{range .Mounts}}{{.Source}} -> {{.Destination}}{{"\n"}}{{end}}' "${cid}" 2>/dev/null || true)

        if [[ -z "${mounts}" ]]; then
            continue
        fi

        while IFS= read -r mount_line; do
            [[ -z "${mount_line}" ]] && continue
            local source
            source=$(echo "${mount_line}" | awk -F' -> ' '{print $1}')

            for dp in "${dangerous_paths[@]}"; do
                if [[ "${source}" == "${dp}" || "${source}" == "${dp}"* ]]; then
                    mount_found=true
                    add_finding "docker" "Dangerous host mount in ${name}: ${mount_line}" "high" \
                        "container=${name} mount=${mount_line}" \
                        "Avoid mounting sensitive host paths into containers."
                    print_error "Dangerous mount in ${name}: ${mount_line}"
                fi
            done
        done <<< "${mounts}"
    done <<< "${container_ids}"

    if [[ "${mount_found}" == false ]]; then
        add_finding "docker" "No dangerous host mounts detected" "info" \
            "dangerous_mounts=count:0"
        print_success "No dangerous host mounts detected"
    fi
}

_docker_socket_exposed() {
    print_subheader "Docker Socket Exposure"

    local socket_path="/var/run/docker.sock"

    if [[ -S "${socket_path}" ]]; then
        local socket_perms
        socket_perms=$(stat -c '%a %U %G' "${socket_path}" 2>/dev/null || echo "unknown")

        add_finding "docker" "Docker socket found: ${socket_path} (${socket_perms})" "info" \
            "socket=${socket_path} permissions=${socket_perms}"
        print_success "Docker socket: ${socket_path} (${socket_perms})"

        local container_ids
        container_ids=$(docker ps -q 2>/dev/null || true)

        if [[ -n "${container_ids}" ]]; then
            while IFS= read -r cid; do
                [[ -z "${cid}" ]] && continue

                local name
                name=$(docker inspect --format '{{.Name}}' "${cid}" 2>/dev/null | sed 's/^\///' || echo "${cid}")

                local sock_mounted
                sock_mounted=$(docker inspect --format '{{range .Mounts}}{{.Source}} {{end}}' "${cid}" 2>/dev/null || true)

                if echo "${sock_mounted}" | grep -q "${socket_path}"; then
                    add_finding "docker" "Docker socket mounted in container: ${name}" "critical" \
                        "container=${name} socket=${socket_path}" \
                        "Never mount the Docker socket in containers unless absolutely necessary."
                    print_error "Docker socket mounted in container: ${name}"
                fi
            done <<< "${container_ids}"
        fi
    else
        add_finding "docker" "Docker socket not found" "info" \
            "socket=not_found"
        print_success "Docker socket not found at ${socket_path}"
    fi
}

_daemon_configuration() {
    print_subheader "Docker Daemon Configuration"

    local daemon_json="/etc/docker/daemon.json"

    if [[ ! -f "${daemon_json}" ]]; then
        add_finding "docker" "No daemon.json configuration file found" "medium" \
            "file=${daemon_json}" \
            "Create /etc/docker/daemon.json with security-hardened settings."
        print_warning "No daemon.json found at ${daemon_json}"
        return
    fi

    add_finding "docker" "daemon.json found: ${daemon_json}" "info" \
        "file=${daemon_json}"
    print_success "daemon.json found"

    if command -v jq &>/dev/null; then
        local live_restore
        live_restore=$(jq -r '.["live-restore"] // "not_set"' "${daemon_json}" 2>/dev/null || echo "not_set")

        if [[ "${live_restore}" == "true" ]]; then
            print_success "live-restore: enabled"
        elif [[ "${live_restore}" == "not_set" ]]; then
            print_warning "live-restore: not configured"
        fi

        local userns
        userns=$(jq -r '.["userns-remap"] // "not_set"' "${daemon_json}" 2>/dev/null || echo "not_set")

        if [[ "${userns}" == "not_set" ]]; then
            print_warning "userns-remap: not configured (containers share host namespace)"
        else
            print_success "userns-remap: ${userns}"
        fi

        local icc
        icc=$(jq -r '.["icc"] // "not_set"' "${daemon_json}" 2>/dev/null || echo "not_set")

        if [[ "${icc}" == "false" ]]; then
            print_success "icc (inter-container communication): disabled"
        else
            print_warning "icc (inter-container communication): enabled or not set"
        fi

        local no_new_privileges
        no_new_privileges=$(jq -r '.["no-new-privileges"] // "not_set"' "${daemon_json}" 2>/dev/null || echo "not_set")

        if [[ "${no_new_privileges}" == "true" ]]; then
            print_success "no-new-privileges: enabled"
        else
            print_warning "no-new-privileges: not enforced"
        fi

        local log_driver
        log_driver=$(jq -r '.["log-driver"] // "not_set"' "${daemon_json}" 2>/dev/null || echo "not_set")

        if [[ "${log_driver}" != "not_set" ]]; then
            print_success "log-driver: ${log_driver}"
        fi
    else
        print_warning "jq not available - cannot parse daemon.json"
    fi
}

_vulnerability_check() {
    print_subheader "Image Vulnerability Check"

    if ! command -v docker &>/dev/null; then
        return
    fi

    if ! docker info &>/dev/null 2>&1; then
        return
    fi

    local images
    images=$(docker images --format '{{.Repository}}:{{.Tag}}' 2>/dev/null | grep -v '<none>' | sort -u || true)

    if [[ -z "${images}" ]]; then
        add_finding "docker" "No images found" "info" \
            "images=count:0"
        print_success "No Docker images found"
        return
    fi

    local image_count
    image_count=$(echo "${images}" | grep -c . || echo "0")
    add_finding "docker" "Docker images: ${image_count}" "info" \
        "images=count:${image_count}"
    print_success "Docker images: ${image_count}"

    local latest_count=0
    while IFS= read -r image; do
        [[ -z "${image}" ]] && continue
        if [[ "${image}" == *":latest" ]]; then
            latest_count=$((latest_count + 1))
            print_warning "Image using 'latest' tag: ${image}"
        fi
    done <<< "${images}"

    if [[ "${latest_count}" -gt 0 ]]; then
        add_finding "docker" "Images using 'latest' tag: ${latest_count}" "medium" \
            "latest_tag_count=${latest_count}" \
            "Pin images to specific versions/tags for reproducibility and security."
    fi
}

_docker_network() {
    print_subheader "Docker Network Configuration"

    if ! command -v docker &>/dev/null; then
        return
    fi

    if ! docker info &>/dev/null 2>&1; then
        return
    fi

    local networks
    networks=$(docker network ls --format '{{.Name}} {{.Driver}}' 2>/dev/null || true)

    if [[ -z "${networks}" ]]; then
        print_success "No Docker networks found"
        return
    fi

    local count
    count=$(echo "${networks}" | grep -c . || echo "0")
    add_finding "docker" "Docker networks: ${count}" "info" \
        "networks=count:${count}"
    print_success "Docker networks: ${count}"

    while IFS= read -r line; do
        [[ -z "${line}" ]] && continue
        local name driver
        name=$(echo "${line}" | awk '{print $1}')
        driver=$(echo "${line}" | awk '{print $2}')
        print_finding "info" "  ${name} (${driver})"
    done <<< "${networks}"
}

_dangerous_capabilities() {
    print_subheader "Container Capabilities Check"

    if ! command -v docker &>/dev/null; then
        return
    fi

    if ! docker info &>/dev/null 2>&1; then
        return
    fi

    local container_ids
    container_ids=$(docker ps -q 2>/dev/null || true)

    if [[ -z "${container_ids}" ]]; then
        print_success "No running containers to check"
        return
    fi

    local dangerous_caps=("SYS_ADMIN" "NET_ADMIN" "SYS_PTRACE" "SYS_MODULE" "SYS_RAWIO" "MKNOD" "AUDIT_WRITE" "SETFCAP")
    local cap_found=false

    while IFS= read -r cid; do
        [[ -z "${cid}" ]] && continue

        local name
        name=$(docker inspect --format '{{.Name}}' "${cid}" 2>/dev/null | sed 's/^\///' || echo "${cid}")

        local cap_add
        cap_add=$(docker inspect --format '{{.HostConfig.CapAdd}}' "${cid}" 2>/dev/null || echo "[]")

        if [[ "${cap_add}" == "[]" || -z "${cap_add}" ]]; then
            continue
        fi

        for dc in "${dangerous_caps[@]}"; do
            if echo "${cap_add}" | grep -qi "${dc}"; then
                cap_found=true
                add_finding "docker" "Dangerous capability ${dc} in container: ${name}" "high" \
                    "container=${name} capability=${dc}" \
                    "Remove unnecessary capabilities with --cap-drop."
                print_error "Container ${name} has capability: ${dc}"
            fi
        done
    done <<< "${container_ids}"

    if [[ "${cap_found}" == false ]]; then
        add_finding "docker" "No dangerous capabilities detected" "info" \
            "dangerous_caps=count:0"
        print_success "No dangerous capabilities detected"
    fi
}

_docker_socket_permissions() {
    print_subheader "Docker Socket Permissions"

    local socket_path="/var/run/docker.sock"

    if [[ ! -S "${socket_path}" ]]; then
        print_success "Docker socket not found"
        return
    fi

    local perms owner group
    perms=$(stat -c '%a' "${socket_path}" 2>/dev/null || echo "unknown")
    owner=$(stat -c '%U' "${socket_path}" 2>/dev/null || echo "unknown")
    group=$(stat -c '%G' "${socket_path}" 2>/dev/null || echo "unknown")

    if [[ "${perms}" == "666" || "${perms}" == "777" ]]; then
        add_finding "docker" "Docker socket world-writable: ${perms}" "critical" \
            "socket=${socket_path} permissions=${perms} owner=${owner} group=${group}" \
            "Restrict Docker socket permissions to root:docker (660)."
        print_error "Docker socket is world-writable: ${perms}"
    elif [[ "${perms}" == "660" || "${perms}" == "600" ]]; then
        add_finding "docker" "Docker socket permissions OK: ${perms}" "info" \
            "socket=${socket_path} permissions=${perms} owner=${owner} group=${group}"
        print_success "Docker socket permissions OK: ${perms}"
    else
        add_finding "docker" "Docker socket permissions unusual: ${perms}" "medium" \
            "socket=${socket_path} permissions=${perms} owner=${owner} group=${group}" \
            "Review Docker socket permissions."
        print_warning "Docker socket permissions unusual: ${perms}"
    fi
}

_docker_group_check() {
    print_subheader "Docker Group Membership"

    if ! getent group docker &>/dev/null 2>&1; then
        print_warning "docker group does not exist"
        return
    fi

    local docker_members
    docker_members=$(getent group docker 2>/dev/null | awk -F: '{print $4}' || true)

    if [[ -z "${docker_members}" ]]; then
        add_finding "docker" "No users in docker group" "info" \
            "docker_group=empty"
        print_success "No non-root users in docker group"
        return
    fi

    local member_count
    member_count=$(echo "${docker_members}" | tr ',' '\n' | grep -c . || echo "0")

    add_finding "docker" "Users in docker group: ${member_count}" "info" \
        "docker_group=members:${member_count}"
    print_success "Users in docker group: ${member_count}"

    while IFS= read -r member; do
        [[ -z "${member}" ]] && continue
        print_finding "info" "  ${member}"
    done <<< "$(echo "${docker_members}" | tr ',' '\n')"

    add_finding "docker" "Docker group membership grants root-equivalent access" "low" \
        "docker_group=warning" \
        "Minimize docker group membership. Use rootless Docker when possible."
    print_warning "Docker group membership grants root-equivalent access"
}

run() {
    print_header "Docker Security Audit"

    _docker_daemon_running
    _docker_version
    _running_containers
    _all_containers
    _privileged_containers
    _root_containers
    _host_mounts
    _docker_socket_exposed
    _daemon_configuration
    _vulnerability_check
    _docker_network
    _dangerous_capabilities
    _docker_socket_permissions
    _docker_group_check
}

if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    run
fi