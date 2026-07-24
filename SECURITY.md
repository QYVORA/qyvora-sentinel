# Security Policy

## Supported Versions

| Version | Supported          |
|---------|--------------------|
| 0.1.x   | :white_check_mark: |
| < 0.1   | :x:                |

Only the latest release in the 0.1.x line receives security patches. Running `sentinel version` will show your current version.

## Reporting a Vulnerability

**Do not open a public GitHub issue for security vulnerabilities.**

### How to report

Send an email to **security@qyvora.io** with:

1. **Description** of the vulnerability
2. **Steps to reproduce** or a proof of concept
3. **Affected component** (module, library, CLI, etc.)
4. **Severity assessment** if available (CVSS score or your estimate)
5. **Suggested fix** if you have one

### What to expect

| Stage | Timeline |
|-------|----------|
| Acknowledgment | Within 48 hours |
| Triage and assessment | Within 5 business days |
| Fix development | Within 30 days for critical, 90 days for others |
| Public disclosure | After fix is released, coordinated with reporter |

### Disclosure policy

We follow a **coordinated disclosure** model:

1. Reporter submits vulnerability privately via email.
2. Maintainer acknowledges receipt and begins triage.
3. A fix is developed and tested in a private branch.
4. A security advisory is prepared for release alongside the patch.
5. The reporter is credited in the advisory unless they prefer anonymity.

We ask that reporters:

- Allow reasonable time for a fix before any public disclosure.
- Avoid exploiting the vulnerability beyond what is necessary to demonstrate it.
- Do not access or modify data that does not belong to you.

## Scope

This policy covers the QYVORA Sentinel project itself, including:

- The `sentinel` CLI binary and its bundled libraries
- Official modules shipped in `modules/`
- The plugin API and its documented interface
- Installation scripts (`Makefile`, `make install`)

**Out of scope:**

- Third-party plugins or modules not distributed by this project
- Vulnerabilities in dependencies (report these to the respective upstream)
- Issues in the user's system configuration that Sentinel detects

## Security Best Practices for Users

- Always run Sentinel with the minimum privileges required for the task.
- Do not run untrusted third-party modules without review.
- Verify GPG signatures on release tarballs when available.
- Keep Sentinel updated to the latest release.
- Review generated reports and do not blindly trust automated remediation suggestions.
