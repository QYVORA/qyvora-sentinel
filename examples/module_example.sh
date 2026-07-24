#!/usr/bin/env bash
# Template for creating a new QYVORA Sentinel scan module
# Copy this file to modules/your_module_name/main.sh

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
readonly MODULE_NAME="example"
readonly MODULE_DESCRIPTION="Example module template"
readonly MODULE_VERSION="0.1.0"
readonly MODULE_SEVERITY_THRESHOLD="INFO"

check_example_1() {
    print_subheader "Check 1 Description"
    
    # Your check logic here
    local result
    result="some_value"
    
    if [[ "${result}" == "bad_value" ]]; then
        add_finding \
            "${MODULE_NAME}" \
            "MEDIUM" \
            "Finding Title" \
            "Description of the finding" \
            "Evidence: ${result}" \
            "How to fix this issue" \
            "https://reference.url"
        print_warning "Finding detected"
    else
        print_success "Check passed"
    fi
}

run() {
    print_header "${MODULE_NAME} Scan"
    log_info "Starting ${MODULE_NAME} module"
    
    check_example_1
    
    log_info "${MODULE_NAME} module complete"
}
