# QYVORA Sentinel - Coding Standards

> Coding conventions for the QYVORA Sentinel codebase. All contributions must follow these standards.

## Bash Strict Mode

Every script and library file must begin with:

```bash
#!/usr/bin/env bash
set -Eeuo pipefail
IFS=$'\n\t'
```

| Flag | Purpose |
|------|---------|
| `-E` | ERR trap is inherited by functions, subshells, and commands |
| `-e` | Exit immediately if a command exits with non-zero status |
| `-u` | Treat unset variables as an error |
| `-o pipefail` | Return the exit status of the last failed command in a pipeline |
| `IFS=$'\n\t'` | Safe word splitting (newline and tab only) |

**Exceptions:**
- The main `sentinel` script temporarily disables `-e` and `-E` during library sourcing and re-enables them after
- `set +E` is applied after library sourcing to prevent ERR trap propagation into functions using `|| true` guards
- Individual commands may use `|| true` or `|| exit_code=$?` to handle expected failures

## Variable Naming

### Prefix Convention

All global variables must use the `SENTINEL_` prefix:

```bash
# Correct
SENTINEL_LOG_LEVEL="info"
declare -ga SENTINEL_FINDINGS=()
declare -gA SENTINEL_CONFIG=()

# Wrong
log_level="info"          # Missing prefix, may conflict
findings=()               # Missing prefix
```

### Style Rules

| Rule | Example | Description |
|------|---------|-------------|
| `snake_case` | `SENTINEL_MODULE_DIR` | All global variables |
| `UPPER_SNAKE_CASE` | `SENTINEL_LOG_LEVEL_DEBUG` | Constants and readonly values |
| `lower_snake_case` | `local module_name` | Local variables |
| `_prefix` | `_internal_helper` | Private/internal functions |
| `readonly` | `readonly NAME="value"` | All constants must be readonly |

### Local Variables

All function-local variables must use `local`:

```bash
my_function() {
    local -r input="${1}"          # readonly local
    local result=""                # mutable local
    local -a items=()              # local array
    local -A mapping=()            # local associative array

    result="$(some_command "${input}")"
    echo "${result}"
}
```

**Never** use globals inside functions without declaring them local first (unless the function intentionally modifies global state).

### Readonly Variables

Use `readonly` for all constants:

```bash
readonly SENTINEL_VERSION="1.0.0"
readonly SENTINEL_SEVERITY_ORDER=(
    [INFO]=1
    [LOW]=2
    [MEDIUM]=3
    [HIGH]=4
    [CRITICAL]=5
)
```

## Function Naming

### Conventions

| Pattern | Example | Usage |
|---------|---------|-------|
| `snake_case` | `get_os_family` | All functions |
| `_underscore_prefix` | `_calculate_risk_score` | Private helper functions |
| `module_prefix` | `config_get`, `plugin_load` | Library public API |
| `cmd_` prefix | `cmd_scan`, `cmd_baseline` | CLI subcommand handlers |

### Guidelines

- Use descriptive, verb-first names: `validate_port`, `find_suid_files`, `calculate_risk_score`
- Avoid abbreviations unless universally understood (`cmd`, `dir`, `env`, `tmp`)
- Keep names under 40 characters
- Functions that return values via stdout should not also print to the terminal

## Error Handling Patterns

### Command Failures

```bash
# Pattern 1: Expected failure, continue
local result
result=$(dangerous_command 2>/dev/null || true)

# Pattern 2: Capture exit code
local exit_code=0
some_command || exit_code=$?
if [[ "${exit_code}" -ne 0 ]]; then
    log_warning "Command failed with exit code ${exit_code}"
fi

# Pattern 3: Required command
if ! command_exists "required-tool"; then
    log_error "Required tool not found: required-tool"
    return 1
fi

# Pattern 4: Function that may fail
if ! validate_path "${config_file}"; then
    log_error "Invalid config file: ${config_file}"
    exit 1
fi
```

### Error Messages

Error messages go to stderr:

```bash
echo "ERROR: Invalid option" >&2
log_error "Something went wrong"
print_error "User-facing error message"
```

### Trap Handlers

Main script traps:

```bash
trap '_cleanup' EXIT              # Always runs on exit
trap '_on_error ${LINENO} $?' ERR  # On unhandled error
trap '_on_signal INT'  INT        # Ctrl+C
trap '_on_signal TERM' TERM       # Kill signal
trap '_on_signal HUP'  HUP        # Hangup
```

Cleanup function pattern:

```bash
_cleanup() {
    local exit_code=$?
    # Remove temp files
    if [[ -d "${SENTINEL_TEMP_DIR:-}" ]]; then
        rm -rf "${SENTINEL_TEMP_DIR}" 2>/dev/null || true
    fi
    exit "${exit_code}"
}
```

## ShellCheck Compliance

All code must pass ShellCheck without warnings. The `.shellcheckrc` file configures project-wide directives.

### Required Practices

```bash
# Always quote variable expansions
echo "${variable}"              # Correct
echo ${variable}                # Wrong

# Use [[ ]] for tests, not [ ]
if [[ "${value}" == "yes" ]]; then  # Correct
if [ "${value}" = "yes" ]; then     # Wrong (less safe)

# Use $() for command substitution, not backticks
result=$(command)               # Correct
result=`command`                # Wrong

# Use arrays for lists
declare -a items=("one" "two")  # Correct
items="one two"                 # Wrong (word splitting issues)

# Guard against ShellCheck SC1090 (dynamic source)
# shellcheck source=path/to/file.sh
source "${file}"
```

### ShellCheck Directives

Use inline directives only when absolutely necessary:

```bash
# shellcheck disable=SC1090  # Can't follow non-constant source
source "${dynamic_path}"

# shellcheck disable=SC2086  # Intentional word splitting
some_command ${unquoted_var}
```

## shfmt Formatting Rules

All code must be formatted with `shfmt` using these settings (from `.editorconfig`):

```ini
[*.sh]
indent_style = space
indent_size = 4
```

### Formatting Rules

| Rule | Example |
|------|---------|
| 4-space indentation | No tabs |
| `then` on same line as `if` | `if [[ x ]]; then` |
| `do` on same line as `for`/`while` | `for i in 1 2; do` |
| Case patterns on own lines | Each `)` on its own line |
| Function `()` on same line | `my_func() {` |

### Example

```bash
# Correct formatting
if [[ -f "${file}" ]]; then
    while IFS= read -r line; do
        case "${line}" in
            INFO|LOW)
                echo "Low severity"
                ;;
            MEDIUM|HIGH|CRITICAL)
                echo "High severity"
                ;;
        esac
    done < "${file}"
fi

# Wrong formatting
if [[ -f "${file}" ]]
then
    while IFS= read -r line
    do
        case "${line}" in
            INFO|LOW) echo "Low severity";;
            MEDIUM|HIGH|CRITICAL) echo "High severity";;
        esac
    done < "${file}"
fi
```

## File Header Requirements

Every `.sh` file must have a header comment:

```bash
#!/usr/bin/env bash
# filename.sh - Brief description of purpose for QYVORA Sentinel
```

For library files, include a longer description:

```bash
#!/usr/bin/env bash
# filename.sh - Detailed description of the module's purpose and capabilities.
# This library provides X, Y, and Z functionality for the QYVORA Sentinel framework.
```

## Documentation Requirements

### Inline Comments

- Use comments to explain **why**, not **what** (the code should be self-explanatory)
- No trailing comments on the same line as code (unless very short)
- Use `# --- Section Name ---` for major code sections:

```bash
# ---------------------------------------------------------------------------
# Module discovery and loading
# ---------------------------------------------------------------------------
_discover_modules() {
    ...
}
```

### Function Documentation

Public functions in library files should have a brief comment:

```bash
# validate_port - Validate a port number (1-65535)
validate_port() {
    local -r port="${1:-}"
    ...
}
```

### Comment Style

```bash
# Single-line comment
# Multi-line comments use one # per line
# each line starts with #

# For TODO/FIXME/HACK/NOTE annotations:
# TODO: Add support for parallel execution
# FIXME: This breaks with filenames containing newlines
# NOTE: Requires bash 4.0+
```

## Anti-Patterns to Avoid

### 1. Unquoted Variables

```bash
# Wrong - word splitting and glob expansion
rm ${tmpfile}
echo ${PATH}

# Correct
rm "${tmpfile}"
echo "${PATH}"
```

### 2. Missing Error Handling

```bash
# Wrong - ignores errors silently
command_that_may_fail

# Correct - explicit error handling
command_that_may_fail || log_warning "Command failed"
```

### 3. Unsafe Eval

```bash
# Wrong - arbitrary code execution
eval "${user_input}"

# Correct - use case statements or associative arrays
case "${user_input}" in
    option1) do_something ;;
    option2) do_other ;;
esac
```

### 4. Unnecessary Subshells

```bash
# Wrong - unnecessary subshell
result=$(echo "${variable}" | awk '{print $1}')

# Correct - direct parameter expansion
result="${variable%% *}"
```

### 5. Parsing `ls` Output

```bash
# Wrong - breaks on filenames with spaces
for file in $(ls); do ...

# Correct - use glob or find
for file in *.txt; do ...
while IFS= read -r file; do ... < <(find /path -type f)
```

### 6. Using `echo` for Return Values

```bash
# Wrong - echo may interpret escape sequences
echo "${value}"

# Correct - printf is safer
printf '%s' "${value}"
```

### 7. Missing Double Brackets

```bash
# Wrong - [ ] is less safe than [[ ]]
if [ "$var" = "value" ]; then

# Correct
if [[ "${var}" == "value" ]]; then
```

### 8. Global Variable Leakage

```bash
# Wrong - pollutes global namespace
my_function() {
    result="value"          # Creates/overwrites global
}

# Correct - explicitly declare locals
my_function() {
    local result="value"    # Function-scoped
}
```

### 9. Hardcoded Paths

```bash
# Wrong - assumes specific paths
config="/etc/myapp/config.conf"

# Correct - use SCRIPT_DIR or configurable paths
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
config="${SCRIPT_DIR}/../etc/config.conf"
```

### 10. Ignoring Signals

```bash
# Wrong - no cleanup on interrupt
while read -r file; do
    process_file "${file}"
done < <(find / -type f)

# Correct - signal handling
trap cleanup EXIT
trap 'exit 130' INT TERM
while read -r file; do
    process_file "${file}"
done < <(find / -type f)
```

## Testing Conventions

### Test File Structure

```
tests/
├── unit/
│   ├── test_colors.sh
│   ├── test_config.sh
│   ├── test_framework.sh
│   ├── test_hashing.sh
│   ├── test_permissions.sh
│   ├── test_reporting.sh
│   ├── test_utils.sh
│   └── test_validation.sh
└── integration/
    ├── test_sentinel_help.sh
    └── test_module_loading.sh
```

### Running Tests

```bash
# Run all tests
make test

# Run specific test
bash tests/unit/test_colors.sh
```

### Module Standalone Execution

Every module must include a standalone guard:

```bash
if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    run
fi
```
