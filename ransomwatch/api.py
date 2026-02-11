from __future__ import annotations

import json
import logging
from typing import Any, Dict, Optional
from urllib.parse import quote, urljoin

import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

from .config import (
    API_BASE,
    API_ENDPOINTS,
    DEFAULT_REQUESTS_PER_MINUTE,
    DEFAULT_REQUESTS_PER_SECOND,
    DEFAULT_TIMEOUT,
    MIN_REQUEST_INTERVAL,
    RETRY_BACKOFF_FACTOR,
    RETRY_STATUS_FORCELIST,
    RETRY_TOTAL,
    USER_AGENT,
)
from .utils import (
    RateLimiter,
    normalize_group_name,
    safe_log_debug,
    safe_log_error,
    sanitize_exception_for_logging,
    sanitize_url_for_logging,
    validate_url,
)

logger = logging.getLogger(__name__)


class RansomWatchAPI:
    def __init__(
        self,
        api_token: str,
        timeout: int = DEFAULT_TIMEOUT,
        requests_per_minute: int = DEFAULT_REQUESTS_PER_MINUTE,
        requests_per_second: int = DEFAULT_REQUESTS_PER_SECOND,
        min_interval: float = MIN_REQUEST_INTERVAL,
    ):
        self.session = requests.Session()
        self.timeout = timeout

        clean_token = api_token.strip()
        self.session.headers.update({
            "User-Agent": USER_AGENT,
            "X-API-KEY": clean_token,
        })

        self.rate_limiter = RateLimiter(
            requests_per_minute=requests_per_minute,
            requests_per_second=requests_per_second,
            min_interval=min_interval,
        )

        retries = Retry(
            total=RETRY_TOTAL,
            backoff_factor=RETRY_BACKOFF_FACTOR,
            status_forcelist=RETRY_STATUS_FORCELIST,
            allowed_methods=["GET"],
        )
        self.session.mount("https://", HTTPAdapter(max_retries=retries))
        self.session.mount("http://", HTTPAdapter(max_retries=retries))

    def _build_url(self, endpoint: str, path_component: Optional[str] = None) -> str:
        if not endpoint.startswith('/'):
            endpoint = '/' + endpoint
        url = urljoin(API_BASE, endpoint)
        if path_component is not None:
            safe_component = quote(path_component, safe='')
            url = urljoin(url + '/', safe_component)
        return url

    def _make_request(self, endpoint: str, path_component: Optional[str] = None) -> Optional[Dict]:
        try:
            url = self._build_url(endpoint, path_component)
            if not validate_url(url):
                safe_log_error("URL validation failed for API request")
                safe_log_debug(f"Failed URL: {sanitize_url_for_logging(url)}")
                return None
            wait_time = self.rate_limiter.wait_if_needed()
            if wait_time > 0:
                safe_log_debug(f"Rate limited: waited {wait_time:.2f}s before request")
            safe_log_debug(f"Making request to: {sanitize_url_for_logging(url)} (timeout: {self.timeout}s)")
            response = self.session.get(url, timeout=self.timeout)
            response.raise_for_status()
            safe_log_debug(f"Request successful: {response.status_code}")
            return response.json()
        except requests.exceptions.Timeout:
            safe_log_error(f"Request timed out after {self.timeout} seconds")
            safe_log_error("Try increasing the timeout with --timeout option")
            return None
        except requests.exceptions.ConnectionError:
            safe_log_error("Connection failed - check your internet connection")
            return None
        except requests.RequestException as e:
            safe_log_error("API request failed")
            safe_log_debug(f"API Error details: {sanitize_exception_for_logging(e)}")
            return None
        except json.JSONDecodeError:
            safe_log_error("Invalid JSON response from API")
            return None

    def get_groups(self) -> Optional[Dict]:
        return self._make_request(API_ENDPOINTS["groups"])

    def get_recent_victims(self) -> Optional[Dict]:
        return self._make_request(API_ENDPOINTS["recent"])

    def get_group_info(self, group_name: str) -> Optional[Dict]:
        normalized_name = normalize_group_name(group_name)
        if normalized_name is None:
            safe_log_error("Group name failed validation")
            safe_debug_input = group_name[:20].replace('<', '[').replace('>', ']').replace('&', '[AMP]')
            safe_log_debug(f"Original input (sanitized): {safe_debug_input}...")
            return None
        safe_log_debug(f"Fetching info for group: {normalized_name}")
        if normalized_name != group_name.lower().strip():
            safe_log_debug("Normalized group name from input")
        data = self._make_request("/groups", normalized_name)
        if not data:
            safe_log_error("Requested group not found")
            safe_log_debug(f"Searched for: {normalized_name}")
            return None
        if not isinstance(data, dict):
            safe_log_error("Invalid group data format received from API.")
            return None
        return data

    def get_stats(self) -> Optional[Dict]:
        return self._make_request(API_ENDPOINTS["stats"])

    def get_rate_limit_stats(self) -> Dict[str, Any]:
        return self.rate_limiter.get_stats()
