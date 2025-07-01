# ransomwatch - Ransomware Intelligence Tool

A Python tool for ransomware threat intelligence and security research.

![Python Version](https://img.shields.io/badge/python-3.8%2B-blue)
![PyPI version](https://img.shields.io/pypi/v/ransomwatch.svg)
![License](https://img.shields.io/badge/license-MIT-green)

## 🚀 Quick Start

```bash
# Install from PyPI (recommended)
pip install ransomwatch

# Set API token (get from ransomware.live)
export RANSOMWATCH_API_TOKEN="your-token-here"

# Use it
ransomwatch groups
ransomwatch recent -l 10
ransomwatch info --group lockbit
ransomwatch stats
```

## Commands

| Command | Description | Example |
|---------|-------------|---------|
| `groups` | List active ransomware groups | `ransomwatch groups` |
| `recent` | Show recent victims | `ransomwatch recent -l 20` |
| `info` | Get group details | `ransomwatch info --group akira` |
| `stats` | Show statistics | `ransomwatch stats` |

## Options

```bash
--json                      # JSON output for automation
--verbose                   # Debug logging
--timeout N                 # Request timeout (default: 10s)
--rate-limit-per-minute N   # API rate limiting
```

## Output Examples

### Groups
```
[+] Found 45 active groups:
================================================================================

 1. 🔴 lockbit3
    └─ Victims: 1,247

 2. 🔴 alphv
    └─ Also known as: blackcat
    └─ Victims: 892
```

### Recent Victims
```
[+] Recent victims (10):
====================================================================================================

 1. ..... Corporation
    ┌─ Group:     lockbit3
    ├─ Date:      2024-01-15 14:30
    ├─ Country:   United States
    └─ Details:   Manufacturing company...
```

## Automation

```bash
# JSON output for scripts
ransomwatch --json groups > groups.json
ransomwatch --json recent -l 50 > victims.json

# Daily reports
DATE=$(date +%Y-%m-%d)
ransomwatch --json stats > "stats_${DATE}.json"

# Integration with jq
ransomwatch --json groups | jq '.groups[] | select(.victims > 100)'
```

## Installation Methods

### Method 1: PyPI Install (Recommended)
```bash
pip install ransomwatch
ransomwatch --help
```

### Method 2: Development Install
```bash
git clone https://github.com/yannickboog/ransomwatch.git
cd ransomwatch
pip install -e .
ransomwatch --help
```

### Method 3: Direct Usage
```bash
git clone https://github.com/yannickboog/ransomwatch.git
cd ransomwatch
pip install -r requirements.txt
python3 -m ransomwatch --help
```

## 🔑 API Token

1. Get token from [ransomware.live](https://ransomware.live)
2. Set environment variable:
   ```bash
   export RANSOMWATCH_API_TOKEN="your-token"
   ```
3. For permanent setup:
   ```bash
   echo 'export RANSOMWATCH_API_TOKEN="your-token"' >> ~/.bashrc
   ```

## Troubleshooting

| Error | Solution |
|-------|----------|
| "No API token provided" | `export RANSOMWATCH_API_TOKEN="token"` |
| "Request timed out" | `ransomwatch --timeout 30 groups` |
| "Invalid command" | Use: `groups`, `recent`, `info`, `stats` |

## Requirements

- Python 3.8+
- API token from ransomware.live

## 💰 Support

If this tool helped you, consider supporting development:

**Bitcoin**: `bc1qmmr6hqlqs097l4ehgyccu8aulk68hmpn3rwkn8`

## License

MIT License - see LICENSE file for details.

---

**For legitimate security research and threat intelligence purposes only.**