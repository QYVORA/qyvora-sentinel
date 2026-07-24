#!/usr/bin/env bash
# network.sh - Network inspection and analysis for QYVORA Sentinel
# Provides functions for examining listening ports, active connections, DNS
# configuration, firewall status, VPN detection, and reverse shell identification.

# Source guard - prevent re-sourcing
if [[ "${_SENTINEL_LIB_LOADED:-}" == *"$(basename "${BASH_SOURCE[0]}")"* ]]; then
    return 0 2>/dev/null || true
fi
_SENTINEL_LIB_LOADED="${_SENTINEL_LIB_LOADED:-} $(basename "${BASH_SOURCE[0]}")"

set -Eeuo pipefail
IFS=$'\n\t'

# Timeout for external network lookups (seconds)
readonly SENTINEL_NET_TIMEOUT=5

# Reverse shell indicators for connection analysis
readonly SENTINEL_REVERSE_SHELL_PATTERNS="bash -i|/dev/tcp|/dev/udp|nc -e|ncat -e|socat.*exec|python.*pty.spawn|perl.*socket|ruby.*socket|php.*fsockopen"

# list_listening_ports - List all TCP/UDP listening ports with associated process info
list_listening_ports() {
    if command -v ss &>/dev/null; then
        ss -tulnp 2>/dev/null || true
    elif command -v netstat &>/dev/null; then
        netstat -tulnp 2>/dev/null || true
    else
        echo "Neither ss nor netstat available" >&2
        return 1
    fi
}

# list_established_connections - List all established TCP connections
list_established_connections() {
    if command -v ss &>/dev/null; then
        ss -tnp state established 2>/dev/null || true
    elif command -v netstat &>/dev/null; then
        netstat -tnp 2>/dev/null | grep ESTABLISHED || true
    else
        echo "Neither ss nor netstat available" >&2
        return 1
    fi
}

# list_dns_config - Read and display DNS resolver configuration
list_dns_config() {
    local resolv_conf="/etc/resolv.conf"
    if [[ -r "${resolv_conf}" ]]; then
        cat "${resolv_conf}"
    else
        echo "Cannot read ${resolv_conf}" >&2
        return 1
    fi
}

# list_routes - Display the kernel routing table
list_routes() {
    if command -v ip &>/dev/null; then
        ip route show 2>/dev/null || true
    elif command -v route &>/dev/null; then
        route -n 2>/dev/null || true
    elif command -v netstat &>/dev/null; then
        netstat -rn 2>/dev/null || true
    else
        echo "No routing command available" >&2
        return 1
    fi
}

# list_interfaces - Show network interfaces and their configurations
list_interfaces() {
    if command -v ip &>/dev/null; then
        ip -br addr show 2>/dev/null || true
    elif command -v ifconfig &>/dev/null; then
        ifconfig -a 2>/dev/null || true
    else
        echo "No interface command available" >&2
        return 1
    fi
}

# detect_vpn - Detect active VPN connections (TUN/TAP interfaces and related processes)
detect_vpn() {
    local found=0

    # Check for TUN/TAP interfaces
    if [[ -d /sys/class/net ]]; then
        local iface
        for iface in /sys/class/net/*; do
            iface="${iface##*/}"
            local iface_type=""
            if [[ -f "/sys/class/net/${iface}/type" ]]; then
                iface_type="$(cat "/sys/class/net/${iface}/type" 2>/dev/null || echo "")"
            fi
            if [[ "${iface}" == tun* || "${iface}" == tap* || "${iface}" == wg* || "${iface}" == ppp* ]]; then
                echo "VPN interface detected: ${iface}"
                found=1
            fi
        done
    fi

    # Check for VPN processes
    local vpn_procs
    vpn_procs="$(ps -eo comm --no-headers 2>/dev/null | grep -iE "openvpn|wireguard|openconnect|strongswan|ipsec|xl2tpd|pptpd|pptp|vpn" || true)"
    if [[ -n "${vpn_procs}" ]]; then
        echo "VPN processes found:"
        echo "${vpn_procs}"
        found=1
    fi

    if [[ "${found}" -eq 0 ]]; then
        echo "No VPN connections detected"
    fi
}

# check_firewall - Check if any firewall is active (iptables, nftables, ufw, firewalld)
check_firewall() {
    local status="inactive"

    # Check ufw
    if command -v ufw &>/dev/null; then
        local ufw_status
        ufw_status="$(ufw status 2>/dev/null || echo "inactive")"
        echo "UFW: ${ufw_status}"
        if echo "${ufw_status}" | grep -qi "active"; then
            status="active"
        fi
    fi

    # Check firewalld
    if command -v firewall-cmd &>/dev/null; then
        local fwd_status
        fwd_status="$(firewall-cmd --state 2>/dev/null || echo "not running")"
        echo "Firewalld: ${fwd_status}"
        if [[ "${fwd_status}" == "running" ]]; then
            status="active"
        fi
    fi

    # Check nftables
    if command -v nft &>/dev/null; then
        local nft_rules
        nft_rules="$(nft list ruleset 2>/dev/null || echo "")"
        if [[ -n "${nft_rules}" ]]; then
            echo "nftables: active (rules present)"
            status="active"
        else
            echo "nftables: no rules loaded"
        fi
    fi

    # Check iptables
    if command -v iptables &>/dev/null; then
        local ipt_rules
        ipt_rules="$(iptables -S 2>/dev/null | grep -v "^-P" | head -20 || echo "")"
        if [[ -n "${ipt_rules}" ]]; then
            echo "iptables: active (custom rules present)"
            status="active"
        else
            echo "iptables: default policy only"
        fi
    fi

    echo "Overall firewall status: ${status}"
}

# get_hosts_file - Read /etc/hosts
get_hosts_file() {
    local hosts_file="/etc/hosts"
    if [[ -r "${hosts_file}" ]]; then
        cat "${hosts_file}"
    else
        echo "Cannot read ${hosts_file}" >&2
        return 1
    fi
}

# detect_reverse_shells - Detect connections that look like reverse shells
detect_reverse_shells() {
    local found=0

    # Check established connections for suspicious destinations
    if command -v ss &>/dev/null; then
        local connections
        connections="$(ss -tnp state established 2>/dev/null || true)"
        if [[ -n "${connections}" ]]; then
            echo "${connections}" | while IFS= read -r line; do
                local dst_port
                dst_port="$(echo "${line}" | awk '{print $5}' | rev | cut -d: -f1 | rev)"
                if [[ "${dst_port}" =~ ^(4444|5555|6666|7777|8888|9999|1234|31337|1337|4432|4433)$ ]]; then
                    echo "SUSPICIOUS: ${line}"
                fi
            done
            found=1
        fi
    fi

    # Check for processes with known reverse shell command patterns
    local suspicious
    suspicious="$(ps -eo pid,comm,args --no-headers 2>/dev/null | grep -iE "${SENTINEL_REVERSE_SHELL_PATTERNS}" || true)"
    if [[ -n "${suspicious}" ]]; then
        echo "Processes with reverse shell indicators:"
        echo "${suspicious}"
        found=1
    fi

    if [[ "${found}" -eq 0 ]]; then
        echo "No reverse shells detected"
    fi
}

# detect_tunnels - Detect SSH tunnels or other port forwarding
detect_tunnels() {
    local found=0

    # Check for SSH tunnel processes
    local ssh_tunnels
    ssh_tunnels="$(ps -eo pid,comm,args --no-headers 2>/dev/null | grep -E "ssh.*-[LR]|ssh.*-W|ssh.*-N" || true)"
    if [[ -n "${ssh_tunnels}" ]]; then
        echo "SSH tunnel processes:"
        echo "${ssh_tunnels}"
        found=1
    fi

    # Check for listening ports on non-standard high ports that might be tunnels
    if command -v ss &>/dev/null; then
        local listeners
        listeners="$(ss -tlnp 2>/dev/null | awk 'NR>1 {print $4}' | rev | cut -d: -f1 | rev | sort -n || true)"
        if [[ -n "${listeners}" ]]; then
            echo "Listening ports: $(echo "${listeners}" | tr '\n' ' ')"
        fi
    fi

    if [[ "${found}" -eq 0 ]]; then
        echo "No tunnels detected"
    fi
}

# check_dns_resolution - Test DNS resolution for a given domain
check_dns_resolution() {
    local domain="${1:-}"
    if [[ -z "${domain}" ]]; then
        echo "Usage: check_dns_resolution <domain>" >&2
        return 1
    fi

    echo "Testing DNS resolution for: ${domain}"

    if command -v host &>/dev/null; then
        host "${domain}" 2>&1 || true
    elif command -v dig &>/dev/null; then
        dig +short "${domain}" 2>&1 || true
    elif command -v nslookup &>/dev/null; then
        nslookup "${domain}" 2>&1 || true
    else
        # Fallback: try getent
        getent hosts "${domain}" 2>&1 || true
    fi
}

# get_external_ip - Get the public/external IP address with timeout
get_external_ip() {
    local ip=""
    local services=("https://ifconfig.me" "https://api.ipify.org" "https://icanhazip.com")

    for service in "${services[@]}"; do
        ip="$(curl -s --max-time "${SENTINEL_NET_TIMEOUT}" "${service}" 2>/dev/null || true)"
        if [[ -n "${ip}" && "${ip}" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
            echo "${ip}"
            return 0
        fi
    done

    # Fallback to local interfaces
    ip="$(ip -4 addr show scope global 2>/dev/null | grep -oP '(?<=inet\s)\d+(\.\d+){3}' | head -1 || true)"
    if [[ -n "${ip}" ]]; then
        echo "${ip} (local)"
    else
        echo "Unable to determine external IP" >&2
        return 1
    fi
}
