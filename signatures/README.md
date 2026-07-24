# QYVORA Sentinel Signatures

This directory stores IOC (Indicators of Compromise) signature databases.

## Contents (Future)

- `hashes/` - Known malicious file hashes (MD5, SHA1, SHA256)
- `malware/` - Malware family names and aliases
- `ips/` - Known malicious IP addresses
- `domains/` - Suspicious domain patterns
- `yara/` - YARA rules for file scanning

## Format

Signature files use simple line-based formats for fast lookup:

```
# hashes/sha256.txt
e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
5d41402abc4b2a76b9719d911017c592
```

## Usage

Sentinel compares system state against these signatures during scans. Update signatures regularly for accurate detection.