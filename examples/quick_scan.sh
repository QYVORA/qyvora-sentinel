#!/usr/bin/env bash
# Quick security scan example
# Usage: ./quick_scan.sh

set -Eeuo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SENTINEL="${SCRIPT_DIR}/../sentinel"

echo "Running quick security scan..."
"${SENTINEL}" scan --severity MEDIUM --text --output "./reports/quick_scan_$(date +%Y%m%d_%H%M%S).txt"

echo "Scan complete!"
