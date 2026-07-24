#!/usr/bin/env bash
set -Eeuo pipefail
IFS=$'\n\t'

PLUGIN_NAME="example"
PLUGIN_VERSION="1.0.0"
PLUGIN_AUTHOR="QYVORA Project"
PLUGIN_DESCRIPTION="Example plugin demonstrating the plugin interface"

run() {
    echo "Example plugin running..."
    echo "Arguments: $*"
    # Plugin can use sentinel libraries if loaded
    # Can call add_finding, print_header, etc.
    return 0
}
