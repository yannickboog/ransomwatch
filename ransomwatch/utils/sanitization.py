from __future__ import annotations

import logging
import os
import re
from urllib.parse import urlparse

logger = logging.getLogger(__name__)

SENSITIVE_PATTERNS = [
    (re.compile(r'api[_-]?key[=:]\s*[^\s&]+', re.IGNORECASE), '[API_KEY_REDACTED]'),
    (re.compile(r'token[=:]\s*[^\s&]+', re.IGNORECASE), '[TOKEN_REDACTED]'),
    (re.compile(r'password[=:]\s*[^\s&]+', re.IGNORECASE), '[PASSWORD_REDACTED]'),
    (re.compile(r'secret[=:]\s*[^\s&]+', re.IGNORECASE), '[SECRET_REDACTED]'),
    (re.compile(r'X-API-KEY:\s*[^\s]+', re.IGNORECASE), 'X-API-KEY: [REDACTED]'),
    (re.compile(r'Authorization:\s*[^\s]+', re.IGNORECASE), 'Authorization: [REDACTED]'),
]


def sanitize_for_logging(message: str) -> str:
    if not isinstance(message, str):
        return str(message)
    sanitized = message
    for pattern, replacement in SENSITIVE_PATTERNS:
        sanitized = pattern.sub(replacement, sanitized)
    return sanitized


def sanitize_url_for_logging(url: str) -> str:
    try:
        parsed = urlparse(url)
        safe_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"
        if parsed.query:
            safe_url += "?[QUERY_REDACTED]"
        return safe_url
    except Exception:
        return "[URL_PARSING_ERROR]"


def sanitize_exception_for_logging(exception: Exception) -> str:
    exc_str = str(exception)
    sanitized = sanitize_for_logging(exc_str)
    if "403" in sanitized or "401" in sanitized:
        return "Authentication/Authorization error"
    elif "404" in sanitized:
        return "Resource not found"
    elif "timeout" in sanitized.lower():
        return "Request timeout"
    elif "connection" in sanitized.lower():
        return "Connection error"
    return "API request failed"


def safe_log_error(message: str, *args, **kwargs):
    sanitized_message = sanitize_for_logging(message)
    logger.error(sanitized_message, *args, **kwargs)


def safe_log_debug(message: str, *args, **kwargs):
    if os.environ.get('RANSOMWATCH_DEBUG') or logger.getEffectiveLevel() <= logging.DEBUG:
        sanitized_message = sanitize_for_logging(message)
        logger.debug(sanitized_message, *args, **kwargs)


def safe_log_info(message: str, *args, **kwargs):
    sanitized_message = sanitize_for_logging(message)
    logger.info(sanitized_message, *args, **kwargs)
