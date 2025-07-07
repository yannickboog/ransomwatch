"""Utility functions"""

import re
import logging
import os
import time
import threading
from typing import Dict, Optional, Any, Set, List, Union
from urllib.parse import urlparse
from collections import deque
import shutil

logger = logging.getLogger(__name__)

ALLOWED_COMMANDS: Set[str] = {"groups", "recent", "info", "stats"}
ALLOWED_GROUP_NAME_CHARS = re.compile(r'^[a-z0-9\-]{1,50}$')
MIN_TIMEOUT = 1
MAX_TIMEOUT = 300
MIN_LIMIT = 1
MAX_LIMIT = 1000

ALLOWED_DOMAINS: Set[str] = {"api-pro.ransomware.live"}
ALLOWED_SCHEMES: Set[str] = {"https"}
SENSITIVE_PATTERNS = [
    (re.compile(r'api[_-]?key[=:]\s*[^\s&]+', re.IGNORECASE), '[API_KEY_REDACTED]'),
    (re.compile(r'token[=:]\s*[^\s&]+', re.IGNORECASE), '[TOKEN_REDACTED]'),
    (re.compile(r'password[=:]\s*[^\s&]+', re.IGNORECASE), '[PASSWORD_REDACTED]'),
    (re.compile(r'secret[=:]\s*[^\s&]+', re.IGNORECASE), '[SECRET_REDACTED]'),
    (re.compile(r'X-API-KEY:\s*[^\s]+', re.IGNORECASE), 'X-API-KEY: [REDACTED]'),
    (re.compile(r'Authorization:\s*[^\s]+', re.IGNORECASE), 'Authorization: [REDACTED]'),
]


class RateLimiter:
    """Thread-safe client-side rate limiter for API requests"""
    
    def __init__(self, requests_per_minute: int = 30, requests_per_second: int = 2, 
                 min_interval: float = 0.5):
        self.requests_per_minute = min(requests_per_minute, 60)
        self.requests_per_second = min(requests_per_second, 10)
        self.min_interval = max(min_interval, 0.1)
        
        self._lock = threading.Lock()
        self._request_times: deque = deque()
        self._last_request_time = 0.0
        
        safe_log_debug(f"Rate limiter initialized: {self.requests_per_minute}/min, "
                      f"{self.requests_per_second}/sec, min interval: {self.min_interval}s")
    
    def wait_if_needed(self) -> float:
        """Wait if necessary to respect rate limits. Returns actual wait time."""
        # TODO: Make rate limits configurable per endpoint
        # FIXME: This might be too conservative for some use cases
        with self._lock:
            current_time = time.time()
            wait_time = 0.0
            
            while self._request_times and current_time - self._request_times[0] > 60:
                self._request_times.popleft()
            
            if len(self._request_times) >= self.requests_per_minute:
                oldest_request = self._request_times[0]
                wait_for_minute = 60 - (current_time - oldest_request)
                if wait_for_minute > 0:
                    wait_time = max(wait_time, wait_for_minute)
            
            recent_requests = sum(1 for t in self._request_times if current_time - t < 1)
            if recent_requests >= self.requests_per_second:
                wait_time = max(wait_time, 1.0)
            
            time_since_last = current_time - self._last_request_time
            if time_since_last < self.min_interval:
                wait_time = max(wait_time, self.min_interval - time_since_last)
            
            if wait_time > 0:
                safe_log_debug(f"Rate limiting: waiting {wait_time:.2f}s")
                time.sleep(wait_time)
                current_time = time.time()
            
            self._request_times.append(current_time)
            self._last_request_time = current_time
            
            return wait_time
    
    def get_stats(self) -> Dict[str, Any]:
        """Get current rate limiter statistics"""
        with self._lock:
            current_time = time.time()
            while self._request_times and current_time - self._request_times[0] > 60:
                self._request_times.popleft()
            
            recent_requests = sum(1 for t in self._request_times if current_time - t < 1)
            
            return {
                "requests_last_minute": len(self._request_times),
                "requests_last_second": recent_requests,
                "max_requests_per_minute": self.requests_per_minute,
                "max_requests_per_second": self.requests_per_second,
                "min_interval": self.min_interval,
                "time_since_last_request": current_time - self._last_request_time
            }


def sanitize_for_logging(message: str) -> str:
    """Remove sensitive information from log messages"""
    if not isinstance(message, str):
        return str(message)
    
    sanitized = message
    
    for pattern, replacement in SENSITIVE_PATTERNS:
        sanitized = pattern.sub(replacement, sanitized)
    
    return sanitized


def sanitize_url_for_logging(url: str) -> str:
    """Sanitize URL for safe logging by removing sensitive query parameters"""
    try:
        parsed = urlparse(url)
        safe_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"
        if parsed.query:
            safe_url += "?[QUERY_REDACTED]"
        return safe_url
    except Exception:
        return "[URL_PARSING_ERROR]"


def sanitize_exception_for_logging(exception: Exception) -> str:
    """Sanitize exception messages to remove sensitive information"""
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
    else:
        return "API request failed"


def safe_log_error(message: str, *args, **kwargs):
    """Safely log error messages with automatic sanitization"""
    sanitized_message = sanitize_for_logging(message)
    logger.error(sanitized_message, *args, **kwargs)


def safe_log_debug(message: str, *args, **kwargs):
    """Safely log debug messages with automatic sanitization"""
    if os.environ.get('RANSOMWATCH_DEBUG') or logger.getEffectiveLevel() <= logging.DEBUG:
        sanitized_message = sanitize_for_logging(message)
        logger.debug(sanitized_message, *args, **kwargs)


def safe_log_info(message: str, *args, **kwargs):
    """Safely log info messages with automatic sanitization"""
    sanitized_message = sanitize_for_logging(message)
    logger.info(sanitized_message, *args, **kwargs)


def validate_url(url: str) -> bool:
    """Validate URL against allowed domains and schemes"""
    try:
        parsed = urlparse(url)
        
        if parsed.scheme not in ALLOWED_SCHEMES:
            safe_log_error("Invalid URL scheme. Only HTTPS allowed.")
            return False
        
        if parsed.netloc not in ALLOWED_DOMAINS:
            safe_log_error("Invalid domain. Only approved domains allowed.")
            return False
        
        if any(suspicious in parsed.netloc.lower() for suspicious in [
            'localhost', '127.0.0.1', '0.0.0.0', '::1',
            '192.168.', '10.', '172.16.', '172.17.', '172.18.', '172.19.',
            '172.20.', '172.21.', '172.22.', '172.23.', '172.24.', '172.25.',
            '172.26.', '172.27.', '172.28.', '172.29.', '172.30.', '172.31.'
        ]):
            safe_log_error("Suspicious domain detected.")
            return False
        
        return True
        
    except Exception as e:
        safe_log_error("URL validation error occurred.")
        safe_log_debug(f"URL validation exception details: {sanitize_exception_for_logging(e)}")
        return False


def validate_command(command: str) -> bool:
    """Validate command against strict whitelist"""
    if not isinstance(command, str):
        safe_log_error("Command must be a string")
        return False
    
    if command not in ALLOWED_COMMANDS:
        safe_log_error("Invalid command provided")
        safe_log_debug(f"Attempted command: {command[:20]}...")
        return False
    
    return True


def validate_timeout(timeout: Any) -> bool:
    """Validate timeout with strict numeric rules"""
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
    """Validate limit with strict numeric rules"""
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
    """Strict validation for group names"""
    if not isinstance(name, str):
        safe_log_error("Group name must be a string")
        return False
    
    if not name:
        safe_log_error("Group name cannot be empty")
        return False
    
    if len(name) > 100:
        safe_log_error("Group name too long (max 100 characters)")
        return False
    
    if any(char in name for char in ['<', '>', '&', '"', "'", '/', '\\', '..', '\0']):
        safe_log_error("Group name contains invalid characters")
        return False
    
    return True


def normalize_group_name(name: str) -> Optional[str]:
    """Normalize group name with strict validation"""
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
    """Validate API response and extract expected field"""
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


def get_terminal_width(min_width: int = 20, max_width: int = 120) -> int:
    """Get current terminal width with safe fallbacks"""
    try:
        size = shutil.get_terminal_size(fallback=(80, 24))
        width = size.columns
        
        if width < 30:
            return max(min_width, width - 2)
        
        return max(min_width, min(width, max_width))
    except Exception:
        return 80


def create_separator(char: str = "=", width: Optional[int] = None, style: str = "full") -> str:
    """Create terminal separator line with adaptive width"""
    if not isinstance(char, str) or len(char) != 1:
        char = "="
    
    if width is None:
        width = get_terminal_width()
    
    if width < 25:
        if style == "full":
            return char * max(10, width)
        elif style == "padded":
            return char * max(8, width - 2)
        else:
            return char * max(6, width // 2)
    
    if style == "padded":
        width = max(15, width - 4)
    elif style == "short":
        width = max(15, int(width * 0.67))
    
    return char * width


def format_title(title: str, width: Optional[int] = None) -> str:
    """Format title with dynamic centering"""
    if not isinstance(title, str):
        title = str(title)
    
    if width is None:
        width = get_terminal_width()
    
    if width < 25:
        if len(title) > width:
            return title[:max(5, width-3)] + "..."
        return title
    
    if len(title) >= width - 4:
        title = title[:width-7] + "..."
    
    return title.center(width)


def create_box_line(content: str, width: Optional[int] = None, align: str = "left") -> str:
    """Create box-style line with content alignment"""
    if not isinstance(content, str):
        content = str(content)
    
    if align not in ["left", "right", "center"]:
        align = "left"
    
    if width is None:
        width = get_terminal_width()
    
    if width < 20:
        if len(content) > width:
            return content[:max(5, width-3)] + "..."
        return content
    
    content_width = width - 4
    
    if len(content) > content_width:
        content = content[:content_width-3] + "..."
    
    if align == "center":
        content = content.center(content_width)
    elif align == "right":
        content = content.rjust(content_width)
    else:
        content = content.ljust(content_width)
    
    return f"| {content} |" 