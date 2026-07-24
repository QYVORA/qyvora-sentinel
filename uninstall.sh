#!/usr/bin/env bash
# uninstall.sh - Uninstaller for QYVORA Sentinel
set -Eeuo pipefail
IFS=$'\n\t'

readonly UNINSTALLER_VERSION="1.0.0"

PREFIX="${PREFIX:-/usr/local}"
BINDIR="${PREFIX}/bin"
LIBDIR="${PREFIX}/share/sentinel"
CONFDIR="/etc/sentinel"
DOCDIR="${PREFIX}/share/doc/sentinel"

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
BOLD='\033[1m'
RESET='\033[0m'

info()    { printf "${GREEN}  ✔ %s${RESET}\n" "$1"; }
warn()    { printf "${YELLOW}  ⚠ %s${RESET}\n" "$1"; }
error()   { printf "${RED}  ✖ %s${RESET}\n" "$1" >&2; }

usage() {
    cat <<EOF
Usage: $0 [OPTIONS]

Uninstall QYVORA Sentinel from this system.

Options:
  --prefix DIR    Installation prefix (default: /usr/local)
  --confdir DIR   Configuration directory (default: /etc/sentinel)
  --yes           Skip confirmation prompt
  --help          Show this help message

Note: Configuration files in CONFDIR are preserved by default.
      Use --yes to skip the confirmation prompt.
EOF
}

check_root() {
    if [[ "${EUID}" -ne 0 ]]; then
        error "This uninstaller must be run as root (or with sudo)."
        echo ""
        echo "  Try: sudo $0"
        exit 1
    fi
}

confirm_uninstall() {
    local skip_confirm="${1:-false}"

    if [[ "${skip_confirm}" == "true" ]]; then
        return 0
    fi

    echo ""
    echo "  This will remove:"
    echo "    - ${BINDIR}/sentinel"
    echo "    - ${LIBDIR}/"
    echo "    - ${DOCDIR}/"
    echo ""
    echo "  Preserved:"
    echo "    - ${CONFDIR}/ (configuration files)"
    echo ""

    read -r -p "  Continue with uninstall? [y/N] " answer
    case "${answer}" in
        [yY][eE][sS]|[yY]) return 0 ;;
        *) echo "  Uninstall cancelled."; exit 0 ;;
    esac
}

do_uninstall() {
    echo ""
    echo -e "${BOLD}  Uninstalling QYVORA Sentinel...${RESET}"
    echo ""

    # Remove binary
    if [[ -f "${BINDIR}/sentinel" ]]; then
        rm -f "${BINDIR}/sentinel"
        info "Removed ${BINDIR}/sentinel"
    else
        warn "Binary not found: ${BINDIR}/sentinel"
    fi

    # Remove library directory
    if [[ -d "${LIBDIR}" ]]; then
        rm -rf "${LIBDIR}"
        info "Removed ${LIBDIR}/"
    else
        warn "Library directory not found: ${LIBDIR}"
    fi

    # Remove doc directory
    if [[ -d "${DOCDIR}" ]]; then
        rm -rf "${DOCDIR}"
        info "Removed ${DOCDIR}/"
    else
        warn "Doc directory not found: ${DOCDIR}"
    fi

    echo ""
    echo -e "${GREEN}${BOLD}  Uninstall complete.${RESET}"
    echo ""
    echo "  Note: Configuration files in ${CONFDIR}/ were preserved."
    echo "  To remove them: sudo rm -rf ${CONFDIR}"
    echo ""
}

main() {
    local skip_confirm="false"

    while [[ $# -gt 0 ]]; do
        case "$1" in
            --prefix)   PREFIX="$2"; shift 2 ;;
            --confdir)  CONFDIR="$2"; shift 2 ;;
            --yes|-y)   skip_confirm="true"; shift ;;
            --help|-h)  usage; exit 0 ;;
            *)          error "Unknown option: $1"; usage; exit 1 ;;
        esac
    done

    BINDIR="${PREFIX}/bin"
    LIBDIR="${PREFIX}/share/sentinel"
    DOCDIR="${PREFIX}/share/doc/sentinel"

    echo ""
    echo -e "${BOLD}  QYVORA Sentinel Uninstaller v${UNINSTALLER_VERSION}${RESET}"

    check_root
    confirm_uninstall "${skip_confirm}"
    do_uninstall
}

main "$@"
