#!/usr/bin/env bash
# Full security audit example
# Usage: ./full_audit.sh

set -Eeuo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SENTINEL="${SCRIPT_DIR}/../sentinel"
TIMESTAMP="$(date +%Y%m%d_%H%M%S)"

echo "=== QYVORA Sentinel Full Audit ==="
echo "Started: $(date)"
echo ""

# Create baseline first
echo "Creating baseline..."
"${SENTINEL}" baseline

# Run full scan with all output formats
echo "Running full scan..."
"${SENTINEL}" scan \
    --text \
    --json \
    --markdown \
    --html \
    --output "./reports/audit_${TIMESTAMP}"

# Generate report
echo "Generating reports..."
"${SENTINEL}" report

# Compare with baseline
echo "Comparing with baseline..."
"${SENTINEL}" compare

echo ""
echo "Audit complete! Reports saved to ./reports/"
echo "Finished: $(date)"
