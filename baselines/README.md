# QYVORA Sentinel Baselines

Baselines capture known-good system state for drift detection.

## How It Works

1. **Create**: Run `sentinel baseline` to snapshot current system state
2. **Store**: Baselines saved as timestamped JSON files
3. **Compare**: Run `sentinel compare` to detect changes since baseline

## What's Captured

- File integrity hashes
- Running services
- Open ports
- User accounts
- Package versions
- System configuration

## Workflow

```bash
# Create initial baseline
sentinel baseline

# Make changes to system...

# Detect what changed
sentinel compare
```

## Files

- `baseline_YYYYMMDD_HHMMSS.json` - Timestamped snapshots
- `latest.json` - Symlink to most recent baseline