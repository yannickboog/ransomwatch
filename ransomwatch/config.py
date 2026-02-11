"""Configuration settings"""

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
    "stats": "/stats"
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