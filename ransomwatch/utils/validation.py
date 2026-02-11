from __future__ import annotations

import re
from typing import Any, Optional, Set
from urllib.parse import urlparse

from .sanitization import (
    safe_log_debug,
    safe_log_error,
    sanitize_exception_for_logging,
)

ALLOWED_COMMANDS: Set[str] = {"groups", "recent", "info", "stats"}
ALLOWED_GROUP_NAME_CHARS = re.compile(r'^[a-z0-9\-]{1,50}$')
MIN_TIMEOUT = 1
MAX_TIMEOUT = 300
MIN_LIMIT = 1
MAX_LIMIT = 1000

ALLOWED_DOMAINS: Set[str] = {"api-pro.ransomware.live"}
ALLOWED_SCHEMES: Set[str] = {"https"}

PRIVATE_NETWORK_PATTERNS = [
    'localhost', '127.0.0.1', '0.0.0.0', '::1',
    '192.168.', '10.',
    '172.16.', '172.17.', '172.18.', '172.19.',
    '172.20.', '172.21.', '172.22.', '172.23.',
    '172.24.', '172.25.', '172.26.', '172.27.',
    '172.28.', '172.29.', '172.30.', '172.31.',
]

DANGEROUS_CHARS = ['<', '>', '&', '"', "'", '/', '\\', '..', '\0']


def validate_url(url: str) -> bool:
    try:
        parsed = urlparse(url)
        if parsed.scheme not in ALLOWED_SCHEMES:
            safe_log_error("Invalid URL scheme. Only HTTPS allowed.")
            return False
        if parsed.netloc not in ALLOWED_DOMAINS:
            safe_log_error("Invalid domain. Only approved domains allowed.")
            return False
        if any(p in parsed.netloc.lower() for p in PRIVATE_NETWORK_PATTERNS):
            safe_log_error("Suspicious domain detected.")
            return False
        return True
    except Exception as e:
        safe_log_error("URL validation error occurred.")
        safe_log_debug(f"URL validation exception details: {sanitize_exception_for_logging(e)}")
        return False


def validate_command(command: str) -> bool:
    if not isinstance(command, str):
        safe_log_error("Command must be a string")
        return False
    if command not in ALLOWED_COMMANDS:
        safe_log_error("Invalid command provided")
        safe_log_debug(f"Attempted command: {command[:20]}...")
        return False
    return True


def validate_timeout(timeout: Any) -> bool:
    if not isinstance(timeout, int):
        safe_log_error("Timeout must be an integer")
        return False
    if timeout < MIN_TIMEOUT:
        safe_log_error(f"Timeout must be at least {MIN_TIMEOUT} second")
        return False
    if timeout > MAX_TIMEOUT:
        safe_log_error(f"Timeout cannot exceed {MAX_TIMEOUT} seconds")
        return False
    return True


def validate_limit(limit: Any) -> bool:
    if not isinstance(limit, int):
        safe_log_error("Limit must be an integer")
        return False
    if limit < MIN_LIMIT:
        safe_log_error(f"Limit must be at least {MIN_LIMIT}")
        return False
    if limit > MAX_LIMIT:
        safe_log_error(f"Limit cannot exceed {MAX_LIMIT}")
        return False
    return True


def validate_group_name(name: str) -> bool:
    if not isinstance(name, str):
        safe_log_error("Group name must be a string")
        return False
    if not name:
        safe_log_error("Group name cannot be empty")
        return False
    if len(name) > 100:
        safe_log_error("Group name too long (max 100 characters)")
        return False
    if any(char in name for char in DANGEROUS_CHARS):
        safe_log_error("Group name contains invalid characters")
        return False
    return True


def normalize_group_name(name: str) -> Optional[str]:
    if not validate_group_name(name):
        return None
    normalized = name.lower().strip()
    normalized = re.sub(r'[^a-z0-9\-]', '', normalized)
    if not normalized:
        safe_log_error("Group name becomes empty after normalization")
        return None
    if not ALLOWED_GROUP_NAME_CHARS.match(normalized):
        safe_log_error("Normalized group name contains invalid characters")
        return None
    return normalized


def validate_api_response(data: Any, expected_field: str, expected_type=None) -> Optional[Any]:
    if not data:
        safe_log_error("No data received from API.")
        return None
    if not isinstance(data, dict):
        safe_log_error("Invalid data format received from API (expected JSON object).")
        return None
    if expected_field not in data:
        safe_log_error("Missing expected field in API response.")
        safe_log_debug(f"Expected field: {expected_field}")
        return None
    field_data = data[expected_field]
    if expected_type and not isinstance(field_data, expected_type):
        safe_log_error("Invalid data format in API response.")
        safe_log_debug(f"Expected type: {expected_type}, got: {type(field_data)}")
        return None
    return field_data
