#!/usr/bin/env bash
# install.sh - Standalone installer for QYVORA Sentinel
set -Eeuo pipefail
IFS=$'\n\t'

readonly INSTALLER_VERSION="1.0.0"
readonly SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# Default installation paths
PREFIX="${PREFIX:-/usr/local}"
BINDIR="${PREFIX}/bin"
LIBDIR="${PREFIX}/share/sentinel"
CONFDIR="/etc/sentinel"
DOCDIR="${PREFIX}/share/doc/sentinel"

# Colors (minimal, self-contained)
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
BOLD='\033[1m'
RESET='\033[0m'

info()    { printf "${GREEN}  ✔ %s${RESET}\n" "$1"; }
warn()    { printf "${YELLOW}  ⚠ %s${RESET}\n" "$1"; }
error()   { printf "${RED}  ✖ %s${RESET}\n" "$1" >&2; }
header()  { echo ""; echo -e "${BOLD}  $1${RESET}"; echo ""; }

usage() {
    cat <<EOF
Usage: $0 [OPTIONS]

Install QYVORA Sentinel on this system.

Options:
  --prefix DIR    Installation prefix (default: /usr/local)
  --confdir DIR   Configuration directory (default: /etc/sentinel)
  --destdir DIR   Staging directory for packaging
  --help          Show this help message

Examples:
  sudo ./install.sh
  sudo ./install.sh --prefix /opt/sentinel
  DESTDIR=/tmp/pkg ./install.sh
EOF
}

check_root() {
    if [[ "${EUID}" -ne 0 && -z "${DESTDIR:-}" ]]; then
        error "This installer must be run as root (or with sudo)."
        echo ""
        echo "  Try: sudo $0"
        exit 1
    fi
}

detect_system() {
    if [[ -f "${SCRIPT_DIR}/Makefile" ]]; then
        USE_MAKEFILE=1
    else
        USE_MAKEFILE=0
    fi
}

install_with_make() {
    header "Installing via Makefile"
    make install PREFIX="${PREFIX}" CONFDIR="${CONFDIR}" DESTDIR="${DESTDIR:-}"
}

install_manually() {
    header "Installing QYVORA Sentinel manually"

    # Create directories
    info "Creating installation directories..."
    mkdir -p "${DESTDIR:-}${BINDIR}"
    mkdir -p "${DESTDIR:-}${LIBDIR}/lib"
    mkdir -p "${DESTDIR:-}${LIBDIR}/modules"
    mkdir -p "${DESTDIR:-}${LIBDIR}/plugins"
    mkdir -p "${DESTDIR:-}${LIBDIR}/assets"
    mkdir -p "${DESTDIR:-}${CONFDIR}"
    mkdir -p "${DESTDIR:-}${DOCDIR}"

    # Install main binary
    info "Installing sentinel binary..."
    install -m 755 "${SCRIPT_DIR}/sentinel" "${DESTDIR:-}${BINDIR}/sentinel"

    # Install libraries
    info "Installing library files..."
    if [[ -d "${SCRIPT_DIR}/lib" ]]; then
        cp -r "${SCRIPT_DIR}/lib/"* "${DESTDIR:-}${LIBDIR}/lib/"
    fi

    # Install modules
    info "Installing modules..."
    if [[ -d "${SCRIPT_DIR}/modules" ]]; then
        cp -r "${SCRIPT_DIR}/modules/"* "${DESTDIR:-}${LIBDIR}/modules/"
    fi

    # Install plugins (optional)
    if [[ -d "${SCRIPT_DIR}/plugins" ]]; then
        info "Installing plugins..."
        cp -r "${SCRIPT_DIR}/plugins/"* "${DESTDIR:-}${LIBDIR}/plugins/" 2>/dev/null || true
    fi

    # Install assets (optional)
    if [[ -d "${SCRIPT_DIR}/assets" ]]; then
        info "Installing assets..."
        cp -r "${SCRIPT_DIR}/assets/"* "${DESTDIR:-}${LIBDIR}/assets/" 2>/dev/null || true
    fi

    # Install configs (don't overwrite existing)
    info "Installing configuration files..."
    if [[ -d "${SCRIPT_DIR}/configs" ]]; then
        for conf in "${SCRIPT_DIR}/configs/"*.conf; do
            [[ ! -f "${conf}" ]] && continue
            local confname
            confname="$(basename "${conf}")"
            if [[ ! -f "${DESTDIR:-}${CONFDIR}/${confname}" ]]; then
                install -m 644 "${conf}" "${DESTDIR:-}${CONFDIR}/"
                info "Installed ${confname}"
            else
                warn "Skipping ${confname} (already exists)"
            fi
        done
    fi

    # Install docs
    if [[ -d "${SCRIPT_DIR}/docs" ]]; then
        info "Installing documentation..."
        cp -r "${SCRIPT_DIR}/docs/"* "${DESTDIR:-}${DOCDIR}/" 2>/dev/null || true
    fi
}

create_log_directories() {
    header "Creating log directories"

    if [[ -z "${DESTDIR:-}" ]]; then
        mkdir -p /var/log/sentinel/reports
        info "Created /var/log/sentinel/reports"
    fi
}

set_permissions() {
    header "Setting permissions"

    if [[ -z "${DESTDIR:-}" ]]; then
        chmod 755 "${BINDIR}/sentinel" 2>/dev/null || true
        info "Set sentinel binary permissions"
    fi
}

print_success() {
    header "Installation Complete"
    echo "  QYVORA Sentinel has been installed successfully."
    echo ""
    echo "  Binary:   ${BINDIR}/sentinel"
    echo "  Library:  ${LIBDIR}/lib/"
    echo "  Modules:  ${LIBDIR}/modules/"
    echo "  Config:   ${CONFDIR}/"
    echo "  Docs:     ${DOCDIR}/"
    echo ""
    echo "  Get started:"
    echo "    sentinel help"
    echo "    sentinel doctor"
    echo "    sentinel scan"
    echo ""
}

# --- Main ---
main() {
    while [[ $# -gt 0 ]]; do
        case "$1" in
            --prefix)   PREFIX="$2"; shift 2 ;;
            --confdir)  CONFDIR="$2"; shift 2 ;;
            --destdir)  DESTDIR="$2"; shift 2 ;;
            --help|-h)  usage; exit 0 ;;
            *)          error "Unknown option: $1"; usage; exit 1 ;;
        esac
    done

    # Re-derive paths from PREFIX
    BINDIR="${PREFIX}/bin"
    LIBDIR="${PREFIX}/share/sentinel"
    DOCDIR="${PREFIX}/share/doc/sentinel"

    echo ""
    echo -e "${BOLD}  QYVORA Sentinel Installer v${INSTALLER_VERSION}${RESET}"
    echo ""

    check_root
    detect_system

    if [[ "${USE_MAKEFILE}" -eq 1 ]]; then
        install_with_make
    else
        install_manually
    fi

    create_log_directories
    set_permissions
    print_success
}

main "$@"
