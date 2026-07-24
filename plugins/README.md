# QYVORA Sentinel Plugins

Plugins extend Sentinel's scanning capabilities with custom checks.

## Plugin Interface

Each plugin is a Bash script that exports:
- `PLUGIN_NAME` - Unique identifier
- `PLUGIN_VERSION` - Semantic version
- `PLUGIN_AUTHOR` - Author name
- `PLUGIN_DESCRIPTION` - Brief description
- `run()` - Entry point function

## Creating a Plugin

1. Copy `example_plugin.sh` to `your_plugin.sh`
2. Update metadata variables
3. Implement the `run()` function

## Minimal Example

```bash
#!/usr/bin/env bash
set -Eeuo pipefail

PLUGIN_NAME="my_check"
PLUGIN_VERSION="1.0.0"
PLUGIN_AUTHOR="Your Name"
PLUGIN_DESCRIPTION="Checks for X"

run() {
    echo "Running my check..."
    # Your logic here
    return 0
}
```

## Usage

Plugins are loaded by Sentinel automatically from this directory. Place your `.sh` files here and they will be available as scan modules.