# Contributing to QYVORA Sentinel

Thank you for your interest in contributing to QYVORA Sentinel. This guide covers everything you need to get started.

## Development Setup

### Prerequisites

- Linux (Debian/Ubuntu, RHEL/Fedora, or Arch-based)
- Bash 4.0+
- GNU Make
- ShellCheck (for linting)
- shfmt (for formatting)
- Bats or similar test framework

### Clone and configure

```bash
git clone https://github.com/qyvora/qyvora-sentinel.git
cd qyvora-sentinel
make dev-setup
```

This installs development dependencies and symlinks the `sentinel` CLI to `/usr/local/bin` for live development.

### Project structure

```
bin/            CLI entrypoint
lib/core/       Engine: module loader, scheduler, reporter
lib/utils/      Shared utilities (logging, output, validation)
lib/api/        Module API and hook definitions
modules/        Individual security audit modules
plugins/        Plugin interface
signatures/     IOC signature definitions
tests/          Test suites
configs/        Configuration files
```

## Coding Standards

### Shell scripting rules

1. **Strict mode** — Every script must begin with:
   ```bash
   set -euo pipefail
   ```

2. **ShellCheck compliance** — All code must pass ShellCheck with zero warnings. Run before committing:
   ```bash
   shellcheck -s bash bin/* lib/**/*.sh modules/**/*.sh
   ```

3. **shfmt formatting** — All code must be formatted with shfmt:
   ```bash
   shfmt -i 4 -bn -ci -sr bin/ lib/ modules/
   ```

4. **Naming conventions:**
   - Functions: `lower_snake_case`
   - Variables: `LOWER_SNAKE_CASE`
   - Constants: `UPPER_SNAKE_CASE`
   - Module directories: `lower-kebab-case`

5. **Quoting** — Always double-quote variable expansions. Use `"${var}"` syntax.

6. **Error handling** — Use `log_error` and appropriate exit codes. Never silently swallow errors.

### Module structure

Every module must follow this layout:

```
modules/<module-name>/
├── manifest.json        # Module metadata and configuration
├── main.sh              # Entry point (run function)
├── checks/              # Individual check implementations
└── tests/               # Module-specific tests
```

A minimal `manifest.json`:

```json
{
  "name": "module-name",
  "version": "0.1.0",
  "category": "posture",
  "description": "Brief description",
  "author": "Your Name",
  "severity_levels": ["info", "low", "medium", "high", "critical"],
  "dependencies": [],
  "enabled_by_default": true
}
```

### Commit messages

Use [Conventional Commits](https://www.conventionalcommits.org/):

```
<type>(<scope>): <description>

Types: feat, fix, docs, style, refactor, test, chore, ci
Scope: module name, library area, or general
```

Examples:
- `feat(ssh-hardening): add modern key exchange algorithm check`
- `fix(module-loader): handle modules with missing manifest`
- `docs(readme): update module list`

## Pull Request Process

1. **Fork and branch** from `main`:
   ```bash
   git checkout -b feat/my-feature
   ```

2. **Write code** following the standards above.

3. **Write tests** for any new functionality. Run the full suite:
   ```bash
   make test
   ```

4. **Lint and format:**
   ```bash
   make lint
   make format
   ```

5. **Update documentation** if your change affects the CLI interface, module API, or public behavior.

6. **Open a PR** against `main`. Include:
   - A clear description of the change
   - Reference to any related issues
   - Test results (paste output or screenshot)

7. **Code review** — At least one maintainer approval is required. Address all feedback.

8. **Merge** — Maintainers will squash-merge after approval and green CI.

## Module Development

### Creating a new module

1. Copy the template:
   ```bash
   make scaffold-module NAME=my-new-module
   ```

2. Implement your checks in `checks/`. Each check function should:
   - Accept no arguments and read config from the module context
   - Return a standardized result object via `result_report`
   - Exit 0 on success, non-zero on failure

3. Register checks in `main.sh`:
   ```bash
   run() {
       check_example_one
       check_example_two
   }
   ```

4. Test in isolation:
   ```bash
   sentinel scan --module my-new-module --verbose
   ```

### Check function signature

```bash
check_example() {
    local result
    result=$(command_to_perform_check)

    if [[ "${result}" -eq 0 ]]; then
        result_report \
            --check "check_example" \
            --severity "info" \
            --status "pass" \
            --message "Check passed"
    else
        result_report \
            --check "check_example" \
            --severity "medium" \
            --status "fail" \
            --message "Check failed: description"
    fi
}
```

## Testing

### Running tests

```bash
make test                  # Run all tests
make test-module NAME=x    # Run tests for a specific module
make test-coverage         # Run with coverage report
```

### Writing tests

Tests live in `tests/` (project-level) or `modules/<name>/tests/` (module-level). Use the Bats test framework:

```bash
#!/usr/bin/env bats

setup() {
    source lib/core/module_api.sh
}

@test "check_example produces valid output" {
    run check_example
    [[ "$status" -eq 0 ]]
    [[ "$output" == *"pass"* ]]
}
```

### Test requirements

- All new modules must include at least one test per check function
- Existing tests must not be broken by your changes
- Coverage for new code should target 80%+

## Reporting Issues

Open an issue on GitHub with:

- **Type**: Bug, Feature Request, Security Report, or Question
- **Environment**: OS, kernel version, Bash version, Sentinel version
- **Steps to reproduce** (for bugs)
- **Expected vs actual behavior**

## Code of Conduct

All contributors must follow the [Code of Conduct](CODE_OF_CONDUCT.md).
