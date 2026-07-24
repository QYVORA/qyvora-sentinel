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

readonly MODULE_NAME="network"
readonly MODULE_DESCRIPTION="Network configuration and connection audit"
readonly MODULE_VERSION="1.0.0"
readonly MODULE_SEVERITY_THRESHOLD="info"

_listening_ports() {
    print_header "Listening Ports"

    local ss_output
    if command -v ss &>/dev/null; then
        ss_output=$(ss -tlnp 2>/dev/null || true)
    elif command -v netstat &>/dev/null; then
        ss_output=$(netstat -tlnp 2>/dev/null || true)
    else
        print_success "Neither ss nor netstat available"
        return
    fi

    if [[ -n "${ss_output}" ]]; then
        local count
        count=$(echo "${ss_output}" | tail -n +2 | grep -c . || echo "0")

        add_finding "listening_ports" "Total listening ports: ${count}" "info" "count=${count}"
        print_success "Listening ports: ${count}"

        while IFS= read -r line; do
            [[ -z "${line}" ]] && continue
            print_finding "info" "  ${line}"
        done <<< "$(echo "${ss_output}" | tail -n +2)"
    else
        print_success "No listening ports found"
    fi
}

_established_connections() {
    print_header "Established Connections"

    local ss_output
    if command -v ss &>/dev/null; then
        ss_output=$(ss -tnp state established 2>/dev/null || true)
    elif command -v netstat &>/dev/null; then
        ss_output=$(netstat -tnp 2>/dev/null | grep ESTABLISHED || true)
    else
        print_success "Neither ss nor netstat available"
        return
    fi

    if [[ -n "${ss_output}" ]]; then
        local count
        count=$(echo "${ss_output}" | tail -n +2 | grep -c . || echo "0")

        add_finding "established" "Total established connections: ${count}" "info" "count=${count}"
        print_success "Established connections: ${count}"

        while IFS= read -r line; do
            [[ -z "${line}" ]] && continue
            print_finding "info" "  ${line}"
        done <<< "$(echo "${ss_output}" | tail -n +2)"
    else
        print_success "No established connections"
    fi
}

_dns_config() {
    print_header "DNS Configuration"

    if [[ -f /etc/resolv.conf ]]; then
        local nameservers
        nameservers=$(grep -v '^\s*#' /etc/resolv.conf 2>/dev/null | grep nameserver || true)

        if [[ -n "${nameservers}" ]]; then
            while IFS= read -r ns; do
                [[ -z "${ns}" ]] && continue
                print_finding "info" "  ${ns}"
            done <<< "${nameservers}"

            local ns_count
            ns_count=$(echo "${nameservers}" | grep -c . || echo "0")
            add_finding "dns" "DNS nameservers: ${ns_count}" "info" "count=${ns_count} config=/etc/resolv.conf"
            print_success "DNS nameservers: ${ns_count}"
        else
            print_success "No nameservers in /etc/resolv.conf"
        fi

        local domain
        domain=$(grep -v '^\s*#' /etc/resolv.conf 2>/dev/null | grep domain || true)
        if [[ -n "${domain}" ]]; then
            print_finding "info" "  ${domain}"
        fi
    else
        print_success "/etc/resolv.conf not found"
    fi
}

_hosts_file() {
    print_header "/etc/hosts Entries"

    if [[ -f /etc/hosts ]]; then
        local entries
        entries=$(grep -v '^\s*#' /etc/hosts 2>/dev/null | grep -v '^\s*$' | grep -v '^\s*::1' | grep -v '^\s*127.0.0.1' || true)

        if [[ -n "${entries}" ]]; then
            while IFS= read -r entry; do
                [[ -z "${entry}" ]] && continue
                print_finding "info" "  ${entry}"
            done <<< "${entries}"

            local count
            count=$(echo "${entries}" | grep -c . || echo "0")
            add_finding "hosts" "Custom /etc/hosts entries: ${count}" "info" "count=${count}"
            print_success "Custom hosts entries: ${count}"
        else
            print_success "No custom /etc/hosts entries"
        fi
    fi
}

_routing_table() {
    print_header "Routing Table"

    if command -v ip &>/dev/null; then
        local routes
        routes=$(ip route show 2>/dev/null || true)

        if [[ -n "${routes}" ]]; then
            local count
            count=$(echo "${routes}" | grep -c . || echo "0")
            add_finding "routing" "Routing table entries: ${count}" "info" "count=${count}"
            print_success "Routing table entries: ${count}"

            while IFS= read -r route; do
                [[ -z "${route}" ]] && continue
                print_finding "info" "  ${route}"
            done <<< "${routes}"
        fi
    elif command -v route &>/dev/null; then
        local routes
        routes=$(route -n 2>/dev/null || true)

        if [[ -n "${routes}" ]]; then
            local count
            count=$(echo "${routes}" | tail -n +3 | grep -c . || echo "0")
            add_finding "routing" "Routing table entries: ${count}" "info" "count=${count}"
            print_success "Routing table entries: ${count}"
        fi
    else
        print_success "No routing command available"
    fi
}

_network_interfaces() {
    print_header "Network Interfaces"

    if command -v ip &>/dev/null; then
        local interfaces
        interfaces=$(ip -o link show 2>/dev/null || true)

        if [[ -n "${interfaces}" ]]; then
            local count=0
            while IFS= read -r iface; do
                [[ -z "${iface}" ]] && continue
                count=$((count + 1))

                local name
                name=$(echo "${iface}" | awk -F': ' '{print $2}' || true)
                local state
                state=$(echo "${iface}" | awk '{print $NF}' || true)

                if [[ "${state}" == "UP" ]]; then
                    print_finding "info" "  ${name}: UP"
                fi
            done <<< "${interfaces}"

            add_finding "interfaces" "Network interfaces: ${count}" "info" "count=${count}"
            print_success "Network interfaces: ${count}"
        fi
    else
        print_success "ip command not available"
    fi
}

_vpn_interfaces() {
    print_header "VPN Interfaces"

    local vpn_found=false

    if command -v ip &>/dev/null; then
        local vpn_ifaces
        vpn_ifaces=$(ip -o link show 2>/dev/null | grep -E 'tun|tap|wg' || true)

        if [[ -n "${vpn_ifaces}" ]]; then
            vpn_found=true
            while IFS= read -r iface; do
                [[ -z "${iface}" ]] && continue
                local name
                name=$(echo "${iface}" | awk -F': ' '{print $2}' || true)
                local state
                state=$(echo "${iface}" | awk '{print $NF}' || true)

                add_finding "vpn" "VPN interface detected: ${name} (${state})" "info" \
                    "interface=${name} state=${state}"
                print_success "VPN interface: ${name} (${state})"
            done <<< "${vpn_ifaces}"
        fi
    fi

    if [[ "${vpn_found}" == false ]]; then
        print_success "No VPN interfaces detected"
    fi
}

_firewall_status() {
    print_header "Firewall Status"

    local found_firewall=false

    if command -v iptables &>/dev/null; then
        local iptables_rules
        iptables_rules=$(iptables -L -n --line-numbers 2>/dev/null || true)

        if [[ -n "${iptables_rules}" ]]; then
            local rule_count
            rule_count=$(echo "${iptables_rules}" | grep -cE '^\s*[0-9]+' || echo "0")

            if [[ ${rule_count} -gt 0 ]]; then
                found_firewall=true
                add_finding "firewall" "iptables active with ${rule_count} rules" "info" \
                    "tool=iptables rules=${rule_count}"
                print_success "iptables: ${rule_count} active rules"
            fi
        fi
    fi

    if command -v nft &>/dev/null; then
        local nft_output
        nft_output=$(nft list ruleset 2>/dev/null || true)

        if [[ -n "${nft_output}" ]]; then
            found_firewall=true
            local nft_rules
            nft_rules=$(echo "${nft_output}" | grep -cE '^\s*(rule|chain)' || echo "0")
            add_finding "firewall" "nftables active with ${nft_rules} rule/chain entries" "info" \
                "tool=nftables entries=${nft_rules}"
            print_success "nftables: ${nft_rules} rule/chain entries"
        fi
    fi

    if command -v ufw &>/dev/null; then
        local ufw_status
        ufw_status=$(ufw status 2>/dev/null || true)

        if echo "${ufw_status}" | grep -qi 'active'; then
            found_firewall=true
            local ufw_rules
            ufw_rules=$(echo "${ufw_status}" | grep -cE '^\s*[0-9]+/tcp|^\s*[0-9]+/udp' || echo "0")
            add_finding "firewall" "UFW active with ${ufw_rules} rules" "info" \
                "tool=ufw rules=${ufw_rules}"
            print_success "UFW: ${ufw_rules} rules active"
        fi
    fi

    if command -v firewall-cmd &>/dev/null; then
        local firewalld
        firewalld=$(firewall-cmd --state 2>/dev/null || true)

        if [[ "${firewalld}" == "running" ]]; then
            found_firewall=true
            local zones
            zones=$(firewall-cmd --get-active-zones 2>/dev/null || true)
            add_finding "firewall" "firewalld active" "info" \
                "tool=firewalld zones=${zones}"
            print_success "firewalld: active"
        fi
    fi

    if [[ "${found_firewall}" == false ]]; then
        add_finding "firewall" "No active firewall detected" "medium" \
            "remediation=Install and configure a firewall (iptables, nftables, ufw, or firewalld)"
        print_warning "No active firewall detected - MEDIUM RISK"
    fi
}

_reverse_shell_detection() {
    print_header "Potential Reverse Shells"

    local suspicious_procs
    suspicious_procs=$(ps aux 2>/dev/null | grep -E 'nc\s.*-e|ncat\s.*-e|socat|bash.*-i.*>&|perl.*socket|python.*socket|ruby.*socket|php.*socket' | grep -v grep || true)

    if [[ -n "${suspicious_procs}" ]]; then
        while IFS= read -r proc; do
            [[ -z "${proc}" ]] && continue
            add_finding "reverse_shell" "Potential reverse shell: ${proc}" "critical" \
                "process=${proc} remediation=Investigate and terminate suspicious process"
            print_error "Potential reverse shell: ${proc}"
        done <<< "${suspicious_procs}"
    else
        print_success "No potential reverse shell processes detected"
    fi
}

_ssh_tunnels() {
    print_header "SSH Tunnels"

    local ssh_tunnels
    ssh_tunnels=$(ss -tnp 2>/dev/null | grep -E 'ssh|sshd' | grep -v 'LISTEN' || true)

    if [[ -n "${ssh_tunnels}" ]]; then
        while IFS= read -r tunnel; do
            [[ -z "${tunnel}" ]] && continue
            add_finding "ssh_tunnel" "SSH tunnel detected: ${tunnel}" "info" \
                "connection=${tunnel}"
            print_warning "SSH tunnel: ${tunnel}"
        done <<< "${ssh_tunnels}"
    else
        print_success "No active SSH tunnels detected"
    fi
}

_proxy_settings() {
    print_header "Proxy Settings"

    local found_proxy=false

    local proxy_vars=("http_proxy" "https_proxy" "HTTP_PROXY" "HTTPS_PROXY" "all_proxy" "ALL_PROXY" "no_proxy")

    for var in "${proxy_vars[@]}"; do
        local value="${!var:-}"
        if [[ -n "${value}" ]]; then
            found_proxy=true
            add_finding "proxy" "Environment variable ${var}=${value}" "info" \
                "variable=${var} value=${value}"
            print_success "${var}=${value}"
        fi
    done

    local proxy_files=("/etc/environment" "/etc/profile" "/etc/apt/apt.conf.d/*" "/etc/yum.conf")

    for pf in "${proxy_files[@]}"; do
        for f in ${pf}; do
            [[ -f "${f}" ]] || continue
            local proxy_lines
            proxy_lines=$(grep -i proxy "${f}" 2>/dev/null | grep -v '^\s*#' || true)

            if [[ -n "${proxy_lines}" ]]; then
                found_proxy=true
                add_finding "proxy" "Proxy config in ${f}: ${proxy_lines}" "info" \
                    "file=${f} content=${proxy_lines}"
                print_success "Proxy in ${f}"
            fi
        done
    done

    if [[ "${found_proxy}" == false ]]; then
        print_success "No proxy settings detected"
    fi
}

_arp_cache() {
    print_header "ARP Cache"

    if command -v arp &>/dev/null; then
        local arp_output
        arp_output=$(arp -a 2>/dev/null || true)

        if [[ -n "${arp_output}" ]]; then
            local count
            count=$(echo "${arp_output}" | grep -c . || echo "0")
            add_finding "arp" "ARP cache entries: ${count}" "info" "count=${count}"
            print_success "ARP entries: ${count}"
        else
            print_success "ARP cache is empty"
        fi
    elif command -v ip &>/dev/null; then
        local ip_arp
        ip_arp=$(ip neigh show 2>/dev/null || true)

        if [[ -n "${ip_arp}" ]]; then
            local count
            count=$(echo "${ip_arp}" | grep -c . || echo "0")
            add_finding "arp" "ARP/neighbor cache entries: ${count}" "info" "count=${count}"
            print_success "ARP/neighbor entries: ${count}"
        else
            print_success "ARP/neighbor cache is empty"
        fi
    else
        print_success "No ARP command available"
    fi
}

_packet_filter_rules() {
    print_header "Packet Filtering Rules"

    local found_rules=false

    if command -v iptables &>/dev/null; then
        local iptables_output
        iptables_output=$(iptables -L -n -v 2>/dev/null || true)

        if [[ -n "${iptables_output}" ]]; then
            local total_rules
            total_rules=$(echo "${iptables_output}" | grep -cE '^\s+[0-9]+' || echo "0")

            if [[ ${total_rules} -gt 0 ]]; then
                found_rules=true
                local drop_count
                drop_count=$(echo "${iptables_output}" | grep -c 'DROP' || echo "0")
                local reject_count
                reject_count=$(echo "${iptables_output}" | grep -c 'REJECT' || echo "0")

                add_finding "packet_filter" "iptables: ${total_rules} rules (${drop_count} DROP, ${reject_count} REJECT)" "info" \
                    "rules=${total_rules} drop=${drop_count} reject=${reject_count}"
                print_success "iptables packet filter: ${total_rules} rules"

                if [[ ${drop_count} -eq 0 ]] && [[ ${reject_count} -eq 0 ]]; then
                    print_warning "No DROP or REJECT rules in iptables"
                fi
            fi
        fi
    fi

    if command -v nft &>/dev/null; then
        local nft_output
        nft_output=$(nft list ruleset 2>/dev/null || true)

        if [[ -n "${nft_output}" ]]; then
            local nft_rules
            nft_rules=$(echo "${nft_output}" | grep -cE '^\s*(rule|filter)' || echo "0")

            if [[ ${nft_rules} -gt 0 ]]; then
                found_rules=true
                add_finding "packet_filter" "nftables: ${nft_rules} filter rules" "info" \
                    "rules=${nft_rules}"
                print_success "nftables packet filter: ${nft_rules} rules"
            fi
        fi
    fi

    if [[ "${found_rules}" == false ]]; then
        print_success "No packet filter rules found"
    fi
}

run() {
    print_header "Network Configuration & Connection Audit"

    _listening_ports
    _established_connections
    _dns_config
    _hosts_file
    _routing_table
    _network_interfaces
    _vpn_interfaces
    _firewall_status
    _reverse_shell_detection
    _ssh_tunnels
    _proxy_settings
    _arp_cache
    _packet_filter_rules
}

if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    run
fi
