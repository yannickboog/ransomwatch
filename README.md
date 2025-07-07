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
ransomwatch info --group ransomhub
ransomwatch stats
```

## Commands

| Command | Description | Example |
|---------|-------------|---------|
| `groups` | List active ransomware groups with risk levels | `ransomwatch groups` |
| `recent` | Show recent ransomware incidents | `ransomwatch recent -l 20` |
| `info` | Get detailed threat actor intelligence | `ransomwatch info --group akira` |
| `stats` | Show threat landscape statistics | `ransomwatch stats` |

## Options

```bash
--json                      # JSON output for automation
--verbose                   # Debug logging
--timeout N                 # Request timeout (default: 10s)
--rate-limit-per-minute N   # API rate limiting
```

## Output Examples

### Ransomware Groups Analysis
```
RANSOMWARE GROUP ANALYSIS
Active Groups: 271
====================================
  1. [CRITICAL] lockbit3
     Victim Count: 2,016

  2. [CRITICAL] clop
     Victim Count: 1,012

  3. [CRITICAL] alphv
     Alternative Name: blackcat
     Victim Count: 731

  4. [HIGH]     play
     Victim Count: 93

  5. [MEDIUM]   akira
     Victim Count: 45

  6. [LOW]      chaos
     Victim Count: 10

   ...

====================================
SUMMARY: 271 Groups | 8,234 Total Victims
RISK BREAKDOWN: Critical: 15 | High: 28 | Medium: 84 | Low: 144
```

### Recent Ransomware Incidents
```
RECENT RANSOMWARE INCIDENTS
Displaying: 10 most recent cases
====================================
  1. VICTIM: ...
     Threat Actor: lockbit3
     Discovery Date: 2024-01-01 20:15
     Location: United States
     Website: www.example.com
     Details: ...

  2. VICTIM: ...
     Threat Actor: alphv
     Discovery Date: 2023-01-01 08:15
     Location: Canada
     Details: ...

   ...

====================================
TOTAL INCIDENTS DISPLAYED: 10
```

### Threat Actor Intelligence Report
```
THREAT ACTOR INTELLIGENCE REPORT
====================================
PRIMARY IDENTIFIER: lockbit3
THREAT CLASSIFICATION: CRITICAL
CONFIRMED VICTIMS: 2,016

OPERATIONAL TIMELINE:
Initial Detection: 2019-09-01
Most Recent Activity: 2024-01-15

TACTICS, TECHNIQUES & PROCEDURES (TTPs):

   ...

====================================
```

## Automation & Integration

```bash
# JSON output
ransomwatch --json groups > threat_groups.json
ransomwatch --json recent -l 100 > incidents.json

# Daily threat intelligence reports
DATE=$(date +%Y-%m-%d)
ransomwatch --json stats > "threat_landscape_${DATE}.json"

# Filter high-risk groups with jq
ransomwatch --json groups | jq '.groups[] | select(.victims > 100) | {name: .group, victims: .victims, threat_level: "CRITICAL"}'

# Generate reports
ransomwatch groups > daily_threat_brief.txt
ransomwatch recent -l 20 > recent_incidents.txt
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

### Linux/macOS

#### Temporary (current session only)
```bash
export RANSOMWATCH_API_TOKEN="your-token"
```

#### For permanent setup on Linux/macOS:
```bash
echo 'export RANSOMWATCH_API_TOKEN="your-token"' >> ~/.bashrc
```

### Windows

#### Temporary (current session only)
**CMD:**
```cmd
set RANSOMWATCH_API_TOKEN=your-token
```

**PowerShell:**
```powershell
$env:RANSOMWATCH_API_TOKEN = "your-token"
```

#### Permanent (for all new sessions)
**CMD - For current user:**
```cmd
setx RANSOMWATCH_API_TOKEN "your-token"
```

**CMD - For all users (as Administrator):**
```cmd
setx RANSOMWATCH_API_TOKEN "your-token" /M
```

**PowerShell - For current user:**
```powershell
[Environment]::SetEnvironmentVariable("RANSOMWATCH_API_TOKEN", "your-token", "User")
```

**PowerShell - For all users (as Administrator):**
```powershell
[Environment]::SetEnvironmentVariable("RANSOMWATCH_API_TOKEN", "your-token", "Machine")
```

## Troubleshooting

| Error | Solution |
|-------|----------|
| "No API token provided" | Linux/macOS: `export RANSOMWATCH_API_TOKEN="token"`<br>Windows CMD: `set RANSOMWATCH_API_TOKEN=token`<br>Windows PowerShell: `$env:RANSOMWATCH_API_TOKEN = "token"` |
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