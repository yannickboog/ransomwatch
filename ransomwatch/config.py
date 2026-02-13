from __future__ import annotations

from importlib.metadata import version, PackageNotFoundError

try:
    _version = version("ransomwatch")
except PackageNotFoundError:
    _version = "unknown"

DEFAULT_TIMEOUT = 10

API_BASE = "https://api-pro.ransomware.live"
API_ENDPOINTS = {
    "groups": "/groups",
    "recent": "/victims/recent",
    "stats": "/stats",
    "victims": "/victims/",
    "victims_search": "/victims/search",
    "victim": "/victim",
    "iocs": "/iocs",
    "negotiations": "/negotiations",
    "ransomnotes": "/ransomnotes",
    "sectors": "/listsectors",
    "yara": "/yara",
    "8k": "/8k",
    "validate": "/validate",
    "csirt": "/csirt",
}

USER_AGENT = f"ransomwatch/{_version}"

RETRY_TOTAL = 3
RETRY_BACKOFF_FACTOR = 1
RETRY_STATUS_FORCELIST = [500, 502, 503, 504]

DEFAULT_REQUESTS_PER_MINUTE = 30
DEFAULT_REQUESTS_PER_SECOND = 2
MIN_REQUEST_INTERVAL = 0.5
MAX_REQUESTS_PER_MINUTE = 60
RATE_LIMIT_WINDOW = 60

RISK_THRESHOLD_CRITICAL = 100
RISK_THRESHOLD_HIGH = 50
RISK_THRESHOLD_MEDIUM = 10

MAX_DISPLAY_TTPS = 8
MAX_DISPLAY_TECHNIQUES = 3

TERMINAL_WIDTH_COMPACT = 50
TERMINAL_WIDTH_NARROW = 60

ACTIVITY_THRESHOLD_HIGH = 50
ACTIVITY_THRESHOLD_MODERATE = 20
