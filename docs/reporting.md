# QYVORA Sentinel - Reporting System

> Documentation for the multi-format reporting pipeline, finding structure, risk score calculation, and integration options.

## Report Formats

Sentinel generates reports in four formats. All formats include identical data; only the presentation differs.

### Text

**Function:** `generate_report_text()`

Plain-text format suitable for terminal display and log files. Uses box-drawing characters for headers and consistent indentation.

```
============================================================
       QYVORA SENTINEL - SECURITY AUDIT REPORT
============================================================

EXECUTIVE SUMMARY
================================================================
Host:             webserver-01
Scan Date:        2026-07-22 14:30:00 UTC
Scan Duration:    45s
Total Findings:   12
Risk Score:       42/100
...
```

**Usage:**

```bash
sentinel report --text                    # To stdout
sentinel scan --text -o report.txt        # To file
generate_report_text "/path/to/report.txt"  # Library function
```

### JSON

**Function:** `generate_report_json()`

Machine-readable JSON with full metadata for each finding. Ideal for SIEM integration, automated processing, and API consumption.

```json
{
  "report_type": "QYVORA Sentinel Security Audit Report",
  "version": "1.0",
  "generated_at": "2026-07-22T14:30:45Z",
  "hostname": "webserver-01",
  "total_findings": 12,
  "risk_score": 42,
  "severity_breakdown": {
    "critical": 0,
    "high": 2,
    "medium": 4,
    "low": 3,
    "info": 3
  },
  "findings": [
    {
      "id": 1,
      "module": "ssh",
      "severity": "HIGH",
      "title": "Root login permitted via SSH",
      "description": "PermitRootLogin is set to 'yes' in sshd_config",
      "evidence": "PermitRootLogin yes",
      "recommendation": "Set PermitRootLogin to 'no' in /etc/ssh/sshd_config",
      "reference": "CIS Ubuntu 20.04 - 5.2.10"
    }
  ]
}
```

**Usage:**

```bash
sentinel report --json
sentinel scan --json -o results.json
generate_report_json "/path/to/results.json"
```

### Markdown

**Function:** `generate_report_markdown()`

GitHub-flavored Markdown with tables, severity badges, and code blocks. Ideal for documentation systems, wikis, and code review tools.

```markdown
# QYVORA Sentinel - Security Audit Report

**Generated:** 2026-07-22 14:30:00 UTC
**Host:** webserver-01
**Risk Score:** 42/100

## Executive Summary

| Metric | Value |
|--------|-------|
| Hostname | webserver-01 |
| Total Findings | 12 |
| Risk Score | 42/100 |

### Severity Breakdown

| Severity | Count |
|----------|-------|
| CRITICAL | 0 |
| HIGH | 2 |
| MEDIUM | 4 |
| LOW | 3 |
| INFO | 3 |

## Findings

### F-1 [HIGH] - Root login permitted via SSH

- **Module:** ssh
- **Severity:** HIGH
- **Description:** PermitRootLogin is set to 'yes' in sshd_config
- **Evidence:**
  ```
  PermitRootLogin yes
  ```
- **Recommendation:** Set PermitRootLogin to 'no' in /etc/ssh/sshd_config
```

**Usage:**

```bash
sentinel report --markdown
sentinel scan --markdown -o audit.md
generate_report_markdown "/path/to/audit.md"
```

### HTML

**Function:** `generate_report_html()`

Self-contained HTML with embedded CSS. Responsive layout with card-based findings, color-coded severity badges, and professional styling. No external dependencies.

**Features:**

- Gradient header with product branding
- Summary cards with key metrics
- Color-coded severity badges (CRITICAL/HIGH/MEDIUM/LOW/INFO)
- Table-based breakdowns
- Card layout for individual findings
- Evidence boxes with monospace formatting
- Recommendation callouts
- Responsive design for various screen sizes

**Risk score colors:**

| Score | Color | Label |
|-------|-------|-------|
| 0-20 | Green (#27ae60) | MINIMAL |
| 21-40 | Orange (#e67e22) | LOW |
| 41-60 | Yellow (#f39c12) | MEDIUM |
| 61-80 | Red (#e74c3c) | HIGH |
| 81-100 | Dark Red (#c0392b) | CRITICAL |

**Usage:**

```bash
sentinel report --html
sentinel scan --html -o report.html
generate_report_html "/path/to/report.html"
```

## Finding Structure

Each finding contains seven fields:

| Field | Required | Description | Example |
|-------|----------|-------------|---------|
| `id` | Auto | Sequential integer identifier | `1` |
| `module` | Yes | Source module or plugin name | `ssh` |
| `severity` | Yes | Severity level | `HIGH` |
| `title` | Yes | Short, descriptive title | "Root login permitted via SSH" |
| `description` | Yes | Detailed explanation | "PermitRootLogin is set to 'yes' in /etc/ssh/sshd_config" |
| `evidence` | No | Raw data supporting the finding | "PermitRootLogin yes" |
| `recommendation` | No | Remediation guidance | "Set PermitRootLogin to 'no'" |
| `reference` | No | External standard or documentation | "CIS Ubuntu 20.04 - 5.2.10" |

### Adding Findings (Module API)

```bash
add_finding "module_name" "SEVERITY" "Title" "Description" ["evidence"] ["recommendation"] ["reference"]
```

**Parameters:**

1. **module** (`string`) - Module identifier
2. **severity** (`string`) - One of: `INFO`, `LOW`, `MEDIUM`, `HIGH`, `CRITICAL`
3. **title** (`string`) - Short description of the finding
4. **description** (`string`) - Full explanation
5. **evidence** (`string`, optional) - Command output, file content, or other proof
6. **recommendation** (`string`, optional) - Steps to remediate
7. **reference** (`string`, optional) - URL, CVE, CIS benchmark, etc.

### Severity Levels

| Level | Numeric Value | When to Use |
|-------|---------------|-------------|
| `INFO` | 0 | Informational observations, system state |
| `LOW` | 3 | Minor security concerns, hardening suggestions |
| `MEDIUM` | 8 | Security misconfigurations with impact |
| `HIGH` | 15 | Significant risks requiring prompt action |
| `CRITICAL` | 25 | Critical vulnerabilities, active compromise indicators |

## Risk Score Calculation

### Formula

The risk score is calculated as a weighted sum normalized to 0-100:

```
total_weighted = (critical_count × 25) + (high_count × 15) + (medium_count × 8) + (low_count × 3) + (info_count × 0)
max_possible = total_findings × 25
score = (total_weighted × 100) / max_possible
if score > 100: score = 100
```

If there are no findings, the score is 0.

### Risk Level Mapping

| Score Range | Risk Level | Color | Description |
|-------------|------------|-------|-------------|
| 0-20 | MINIMAL | Green | System is well-configured |
| 21-40 | LOW | Orange | Minor issues to address |
| 41-60 | MEDIUM | Yellow | Security improvements needed |
| 61-80 | HIGH | Red | Significant risks present |
| 81-100 | CRITICAL | Dark Red | Immediate action required |

### Configuration

Risk score weights are configurable in `configs/severity.conf`:

```ini
[scoring]
CRITICAL = 25
HIGH = 15
MEDIUM = 8
LOW = 3
INFO = 0
```

And threshold boundaries in `configs/sentinel.conf`:

```ini
[risk]
critical_weight = 25
high_weight = 15
medium_weight = 8
low_weight = 3
info_weight = 0
excellent_max = 20
good_max = 40
moderate_max = 60
high_risk_max = 80
```

## Report Sections

All report formats include the following sections:

### 1. Executive Summary

- Hostname
- Scan date and time (UTC)
- Scan duration
- Total findings count
- Risk score (0-100)
- Severity breakdown (count per level)

### 2. System Overview

- Hostname
- Kernel version
- Architecture
- Operating system
- Uptime

### 3. Severity Breakdown

Tabular count of findings per severity level, with percentages in HTML format.

### 4. Module Breakdown

Count of findings per source module, allowing identification of the most affected areas.

### 5. Findings Detail

Each finding rendered with all seven fields. In HTML, findings are displayed as cards with severity badges. In Markdown, findings are subsections with bullet-point metadata.

### 6. Prioritized Recommendations

Findings grouped by severity and priority:

1. **Priority 1 - Immediate Action Required** (CRITICAL)
2. **Priority 2 - Urgent** (HIGH)
3. **Priority 3 - Plan Remediation** (MEDIUM)
4. **Priority 4 - Low Risk** (LOW)
5. **Priority 5 - Informational** (INFO)

### 7. Appendix

Scan metadata including:
- Scanner version
- Report generation timestamp
- Hostname
- Scan start/end times
- Duration
- Total findings
- Risk score
- Module breakdown

## Customizing Reports

### Output to File

```bash
sentinel scan --html -o /var/log/audit.html
sentinel scan --json -o /var/log/audit.json
sentinel scan --markdown -o /var/log/audit.md
```

### Regenerate from Saved Scan

```bash
# Find the latest scan file
ls -t reports/scan-*.json | head -1

# Regenerate as HTML
sentinel report --html -o new-report.html
```

### Combining with Other Tools

```bash
# Pipe JSON to jq for custom processing
sentinel scan --json -q | jq '.findings[] | select(.severity == "HIGH")'

# Count critical findings
sentinel scan --json -q | jq '.severity_breakdown.critical'

# Extract just SSH findings
sentinel scan --json -q | jq '[.findings[] | select(.module == "ssh")]'
```

## Report Storage Locations

| Path | Description |
|------|-------------|
| `reports/scan-YYYYMMDDTHHMMSSZ.json` | Raw scan results (JSON) |
| `--output PATH` | User-specified report output |
| `/var/log/sentinel/reports/` | Configured report directory (when set in config) |

### Configurable Report Directory

In `configs/sentinel.conf`:

```ini
[output]
output_dir = /var/log/sentinel/reports
```

The framework ensures the report directory exists before writing.

## Integrating with SIEM

### JSON Schema

The JSON report follows this structure for SIEM ingestion:

```json
{
  "report_type": "QYVORA Sentinel Security Audit Report",
  "version": "1.0",
  "generated_at": "ISO-8601 timestamp",
  "hostname": "string",
  "scan_start": "ISO-8601 timestamp",
  "scan_end": "ISO-8601 timestamp",
  "scan_duration": "e.g., 45s",
  "total_findings": "integer",
  "risk_score": "integer (0-100)",
  "severity_breakdown": {
    "critical": "integer",
    "high": "integer",
    "medium": "integer",
    "low": "integer",
    "info": "integer"
  },
  "findings": [
    {
      "id": "integer",
      "module": "string",
      "severity": "INFO|LOW|MEDIUM|HIGH|CRITICAL",
      "title": "string",
      "description": "string",
      "evidence": "string",
      "recommendation": "string",
      "reference": "string"
    }
  ]
}
```

### Common SIEM Integration Patterns

**Scheduled scans with forwarding:**

```bash
#!/bin/bash
# /etc/cron.daily/sentinel-scan.sh

SCAN_DIR="/var/log/sentinel/scans"
SIEM_FORWARD="/opt/scripts/forward-to-siem.sh"

mkdir -p "${SCAN_DIR}"

# Run scan
sentinel scan --json -q -o "${SCAN_DIR}/scan-$(date +%Y%m%d).json"

# Forward to SIEM
if [[ -x "${SIEM_FORWARD}" ]]; then
    "${SIEM_FORWARD}" "${SCAN_DIR}/scan-$(date +%Y%m%d).json"
fi

# Clean old scans (keep 30 days)
find "${SCAN_DIR}" -name "scan-*.json" -mtime +30 -delete
```

**Alerting on critical findings:**

```bash
#!/bin/bash
# Alert on critical findings

RESULTS=$(sentinel scan --json -q)
CRITICAL=$(echo "${RESULTS}" | jq '.severity_breakdown.critical')

if [[ "${CRITICAL}" -gt 0 ]]; then
    echo "${RESULTS}" | jq -r '.findings[] | select(.severity == "CRITICAL") | "[CRITICAL] \(.module): \(.title)"' | \
        mail -s "CRITICAL Security Findings - $(hostname)" admin@example.com
fi
```

## Automated Reporting

### Cron-Based Weekly Reports

```bash
# /etc/cron.weekly/sentinel-report
#!/bin/bash
REPORT_DIR="/var/log/sentinel/reports"
mkdir -p "${REPORT_DIR}"

sentinel scan --html -o "${REPORT_DIR}/weekly-$(date +%Y%m%d).html"
```

### Integration with Monitoring Systems

The JSON output is designed for consumption by:

- **Grafana** - Parse with JSON datasource
- **ELK Stack** - Filebeat monitors `reports/` directory
- **Splunk** - Universal forwarder on report files
- **Custom dashboards** - Direct JSON API consumption
