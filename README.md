# ransomwatch - Ransomware Intelligence Tool

A Python tool for ransomware threat intelligence and security research.

![Python Version](https://img.shields.io/badge/python-3.8%2B-blue)
![PyPI version](https://img.shields.io/pypi/v/ransomwatch.svg)
![License](https://img.shields.io/badge/license-MIT-green)

## Legal Notice & Ethical Use

**For legitimate security research and threat intelligence only.** All data is sourced exclusively via read-only API queries to [ransomware.live](https://ransomware.live) -- no direct interaction with ransomware infrastructure.

This tool must **not** be used for:

- Targeting, extorting, or further victimizing affected organizations
- Interfering with law enforcement investigations or incident response
- Any purpose that violates applicable laws (GDPR, CCPA, computer fraud statutes)

By using this tool, you agree to comply with all applicable laws in your jurisdiction.

---

## Quick Start

```bash
pip install ransomwatch
export RANSOMWATCH_API_TOKEN="your-token-here"
ransomwatch groups
```

Get your API token from [ransomware.live](https://www.ransomware.live).

## Commands

| Command | Description | Example |
|---------|-------------|---------|
| `groups` | List active ransomware groups with risk levels | `ransomwatch groups` |
| `recent` | Show recent ransomware incidents | `ransomwatch recent -l 20` |
| `info` | Get detailed threat actor intelligence | `ransomwatch info --group akira` |
| `stats` | Show threat landscape statistics | `ransomwatch stats` |
| `validate` | Validate API key | `ransomwatch validate` |
| `sectors` | List industry sectors impacted | `ransomwatch sectors` |
| `csirt` | Get CSIRT/CERT contacts by country | `ransomwatch csirt --country US` |
| `victims` | List ransomware victims with filters | `ransomwatch victims --country US` |
| `iocs` | Show indicators of compromise | `ransomwatch iocs --group Akira` |
| `yara` | Show YARA detection rules | `ransomwatch yara --group Akira` |
| `8k` | Show SEC 8-K cybersecurity filings | `ransomwatch 8k --year 2025` |

All commands support `--json` for machine-readable output and `--verbose` for debug logging. See `ransomwatch --help` for all options.

## Installation

```bash
# PyPI (recommended)
pip install ransomwatch

# Development
git clone https://github.com/yannickboog/ransomwatch.git
cd ransomwatch
pip install -e .
```

## Requirements

- Python 3.8+
- API token from ransomware.live

## License

MIT License - see LICENSE file for details.

---

Data source: [ransomware.live](https://ransomware.live)
