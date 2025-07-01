"""Configuration settings"""

DEFAULT_TIMEOUT = 10

API_BASE = "https://api-pro.ransomware.live"
API_ENDPOINTS = {
    "groups": "/groups",
    "recent": "/victims/recent",
    "stats": "/stats"
}

# TODO: Use generic User-Agent to avoid detection/blocking
USER_AGENT = "ransomwatch/1.0"

RETRY_TOTAL = 3
RETRY_BACKOFF_FACTOR = 1
RETRY_STATUS_FORCELIST = [500, 502, 503, 504]

DEFAULT_REQUESTS_PER_MINUTE = 30
DEFAULT_REQUESTS_PER_SECOND = 2
MIN_REQUEST_INTERVAL = 0.5
MAX_REQUESTS_PER_MINUTE = 60
RATE_LIMIT_WINDOW = 60 