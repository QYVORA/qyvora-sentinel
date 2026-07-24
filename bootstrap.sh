#!/usr/bin/env bash
# bootstrap.sh - Development environment bootstrap for QYVORA Sentinel
set -Eeuo pipefail
IFS=$'\n\t'

readonly BOOTSTRAP_VERSION="1.0.0"
readonly SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
CYAN='\033[0;36m'
BOLD='\033[1m'
RESET='\033[0m'

pass() { printf "  ${GREEN}✔${RESET} %s\n" "$1"; }
fail() { printf "  ${RED}✖${RESET} %s\n" "$1"; }
warn() { printf "  ${YELLOW}⚠${RESET} %s\n" "$1"; }
info() { printf "  ${CYAN}●${RESET} %s\n" "$1"; }

header() {
    echo ""
    echo -e "${BOLD}  ── $1 ──${RESET}"
    echo ""
}

# --- Check required tools ---
check_required() {
    header "Checking Required Tools"

    local errors=0

    # Bash 4+
    if [[ "${BASH_VERSINFO[0]}" -ge 4 ]]; then
        pass "Bash ${BASH_VERSION}"
    else
        fail "Bash 4+ required (found: ${BASH_VERSION})"
        errors=$((errors + 1))
    fi

    # git
    if command -v git &>/dev/null; then
        pass "git $(git --version | awk '{print $3}')"
    else
        fail "git not found"
        errors=$((errors + 1))
    fi

    # shellcheck
    if command -v shellcheck &>/dev/null; then
        pass "shellcheck $(shellcheck --version | grep 'version:' | awk '{print $2}')"
    else
        warn "shellcheck not found (install: apt install shellcheck)"
    fi

    # shfmt
    if command -v shfmt &>/dev/null; then
        pass "shfmt $(shfmt --version 2>/dev/null || echo 'installed')"
    else
        warn "shfmt not found (install: go install mvdan.cc/sh/v3/cmd/shfmt@latest)"
    fi

    # make
    if command -v make &>/dev/null; then
        pass "make"
    else
        warn "make not found (optional but recommended)"
    fi

    return ${errors}
}

# --- Run checks ---
run_checks() {
    header "Running Code Quality Checks"

    if command -v make &>/dev/null; then
        info "Running make check..."
        if make check; then
            pass "All checks passed"
        else
            warn "Some checks had issues (see above)"
        fi
    else
        warn "Skipping checks (make not available)"
    fi
}

# --- Run tests ---
run_tests() {
    header "Running Test Suite"

    if command -v make &>/dev/null; then
        info "Running make test..."
        if make test; then
            pass "All tests passed"
        else
            fail "Some tests failed"
            return 1
        fi
    else
        info "Running tests manually..."
        local failed=0
        for t in tests/unit/test_*.sh; do
            [[ ! -f "${t}" ]] && continue
            bash "${t}" || failed=$((failed + 1))
        done
        for t in tests/integration/test_*.sh; do
            [[ ! -f "${t}" ]] && continue
            bash "${t}" || failed=$((failed + 1))
        done
        if [[ "${failed}" -gt 0 ]]; then
            fail "Some tests failed (${failed} test file(s) failed)"
            return 1
        fi
        pass "All tests passed"
    fi
}

# --- Initialize git repo ---
init_git() {
    header "Initializing Git Repository"

    if [[ -d "${SCRIPT_DIR}/.git" ]]; then
        pass "Git repository already initialized"
    else
        info "Initializing git repository..."
        git init "${SCRIPT_DIR}"
        pass "Git repository initialized"
    fi
}

# --- Set up pre-commit hooks ---
setup_hooks() {
    header "Setting Up Pre-commit Hooks"

    local hooks_dir="${SCRIPT_DIR}/.git/hooks"
    local hook_file="${hooks_dir}/pre-commit"

    if [[ ! -d "${SCRIPT_DIR}/.git" ]]; then
        warn "No git repository found, skipping hooks"
        return 0
    fi

    if [[ -f "${hook_file}" ]]; then
        pass "Pre-commit hook already exists"
    else
        cat > "${hook_file}" <<'HOOK'
#!/usr/bin/env bash
# Pre-commit hook for QYVORA Sentinel

set -euo pipefail

echo "Running pre-commit checks..."

# Run shellcheck
if command -v shellcheck &>/dev/null; then
    echo "  Running ShellCheck..."
    changed_files=$(git diff --cached --name-only --diff-filter=ACM | grep -E '\.(sh)$' || true)
    if [[ -n "${changed_files}" ]]; then
        echo "${changed_files}" | xargs shellcheck --severity=warning || {
            echo "ShellCheck failed. Fix issues before committing."
            exit 1
        }
    fi
fi

# Run format check
if command -v shfmt &>/dev/null; then
    echo "  Running format check..."
    changed_files=$(git diff --cached --name-only --diff-filter=ACM | grep -E '\.(sh)$' || true)
    if [[ -n "${changed_files}" ]]; then
        echo "${changed_files}" | xargs shfmt -d -i 4 -bn || {
            echo "Format check failed. Run 'make format' before committing."
            exit 1
        }
    fi
fi

echo "Pre-commit checks passed."
HOOK
        chmod +x "${hook_file}"
        pass "Pre-commit hook installed"
    fi
}

# --- Print dev environment status ---
print_status() {
    header "Development Environment Status"

    echo "  Project:   QYVORA Sentinel"
    echo "  Location:  ${SCRIPT_DIR}"
    echo "  Bash:      ${BASH_VERSION}"
    echo "  OS:        $(uname -s) $(uname -r)"
    echo "  Arch:      $(uname -m)"
    echo "  User:      $(whoami)"
    echo "  Date:      $(date -u '+%Y-%m-%d %H:%M:%S UTC')"
    echo ""

    # Count project files
    local lib_count module_count test_count
    lib_count=$(find "${SCRIPT_DIR}/lib" -name '*.sh' 2>/dev/null | wc -l)
    module_count=$(find "${SCRIPT_DIR}/modules" -name 'main.sh' 2>/dev/null | wc -l)
    test_count=$(find "${SCRIPT_DIR}/tests" -name 'test_*.sh' 2>/dev/null | wc -l)

    echo "  Libraries:     ${lib_count}"
    echo "  Modules:       ${module_count}"
    echo "  Test files:    ${test_count}"
    echo ""

    if [[ -d "${SCRIPT_DIR}/.git" ]]; then
        local branch
        branch="$(git -C "${SCRIPT_DIR}" rev-parse --abbrev-ref HEAD 2>/dev/null || echo 'unknown')"
        local commit_count
        commit_count="$(git -C "${SCRIPT_DIR}" rev-list --count HEAD 2>/dev/null || echo '0')"
        echo "  Git branch:   ${branch}"
        echo "  Git commits:  ${commit_count}"
    else
        echo "  Git:          not initialized"
    fi
    echo ""
}

# --- Main ---
main() {
    echo ""
    echo -e "${BOLD}  QYVORA Sentinel Development Bootstrap v${BOOTSTRAP_VERSION}${RESET}"
    echo ""

    check_required || {
        echo ""
        echo "  Fix missing required tools and re-run this script."
        exit 1
    }

    init_git
    setup_hooks
    run_checks
    run_tests
    print_status

    echo -e "${GREEN}${BOLD}  Bootstrap complete!${RESET}"
    echo ""
    echo "  Quick start:"
    echo "    make test          Run all tests"
    echo "    make lint          Run ShellCheck"
    echo "    make check         Run all checks"
    echo "    sentinel help      Show sentinel usage"
    echo "    sentinel scan      Run a security scan"
    echo ""
}

main "$@"
