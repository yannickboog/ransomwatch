from __future__ import annotations

import json
import logging
from typing import Any, Dict, List, Optional
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
from .exceptions import (
    APIError,
    AuthenticationError,
    NotFoundError,
    RateLimitError,
    ValidationError,
)
from .utils import (
    RateLimiter,
    normalize_group_name,
    safe_log_debug,
    safe_log_error,
    sanitize_exception_for_logging,
    sanitize_url_for_logging,
    validate_country_code,
    validate_month,
    validate_search_query,
    validate_url,
    validate_year,
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

    def _make_request(
        self,
        endpoint: str,
        path_component: Optional[str] = None,
        params: Optional[Dict[str, Any]] = None,
    ) -> Dict:
        url = self._build_url(endpoint, path_component)
        if not validate_url(url):
            safe_log_debug(f"Failed URL: {sanitize_url_for_logging(url)}")
            raise ValidationError(f"URL validation failed for API request")
        wait_time = self.rate_limiter.wait_if_needed()
        if wait_time > 0:
            safe_log_debug(f"Rate limited: waited {wait_time:.2f}s before request")
        safe_log_debug(f"Making request to: {sanitize_url_for_logging(url)} (timeout: {self.timeout}s)")
        try:
            response = self.session.get(url, timeout=self.timeout, params=params)
        except requests.exceptions.Timeout:
            raise APIError(f"Request timed out after {self.timeout} seconds. Try increasing with --timeout")
        except requests.exceptions.ConnectionError:
            raise APIError("Connection failed - check your internet connection")
        except requests.RequestException as e:
            safe_log_debug(f"API Error details: {sanitize_exception_for_logging(e)}")
            raise APIError("API request failed") from e

        if response.status_code == 401:
            raise AuthenticationError("Invalid API token")
        if response.status_code == 404:
            raise NotFoundError("Resource not found")
        if response.status_code == 429:
            raise RateLimitError("API rate limit exceeded")
        if response.status_code >= 400:
            raise APIError(f"API returned status {response.status_code}")

        try:
            data = response.json()
        except json.JSONDecodeError:
            raise APIError("Invalid JSON response from API")

        safe_log_debug(f"Request successful: {response.status_code}")
        return data

    def get_groups(self) -> Dict:
        return self._make_request(API_ENDPOINTS["groups"])

    def get_recent_victims(self) -> Dict:
        return self._make_request(API_ENDPOINTS["recent"])

    def get_group_info(self, group_name: str) -> Dict:
        normalized_name = normalize_group_name(group_name)
        if normalized_name is None:
            raise ValidationError(f"Group name failed validation")
        safe_log_debug(f"Fetching info for group: {normalized_name}")
        if normalized_name != group_name.lower().strip():
            safe_log_debug("Normalized group name from input")
        data = self._make_request("/groups", normalized_name)
        if not data or not isinstance(data, dict):
            raise NotFoundError(f"Group not found: {normalized_name}")
        return data

    def get_stats(self) -> Dict:
        return self._make_request(API_ENDPOINTS["stats"])

    def get_rate_limit_stats(self) -> Dict[str, Any]:
        return self.rate_limiter.get_stats()

    def _validate_group(self, group_name: str) -> str:
        from .utils import validate_group_name
        if not validate_group_name(group_name):
            raise ValidationError(f"Group name failed validation")
        return group_name.strip()

    def _build_params(self, **kwargs: Any) -> Optional[Dict[str, Any]]:
        params = {k: v for k, v in kwargs.items() if v is not None}
        return params or None

    # --- Victims ---

    def get_victims(
        self,
        group: Optional[str] = None,
        sector: Optional[str] = None,
        country: Optional[str] = None,
        year: Optional[int] = None,
        month: Optional[int] = None,
        date: Optional[str] = None,
    ) -> Dict:
        if country and not validate_country_code(country):
            raise ValidationError("Invalid country code")
        if year is not None and not validate_year(year):
            raise ValidationError("Invalid year")
        if month is not None and not validate_month(month):
            raise ValidationError("Invalid month")
        params = self._build_params(
            group=group, sector=sector, country=country,
            year=year, month=month, date=date,
        )
        return self._make_request(API_ENDPOINTS["victims"], params=params)

    def search_victims(
        self,
        q: Optional[str] = None,
        group: Optional[str] = None,
        sector: Optional[str] = None,
        country: Optional[str] = None,
        order: Optional[str] = None,
    ) -> Dict:
        if q is not None and not validate_search_query(q):
            raise ValidationError("Invalid search query")
        if country and not validate_country_code(country):
            raise ValidationError("Invalid country code")
        params = self._build_params(
            q=q, group=group, sector=sector, country=country, order=order,
        )
        return self._make_request(API_ENDPOINTS["victims_search"], params=params)

    def get_victim(self, victim_id: str) -> Dict:
        if not victim_id or not isinstance(victim_id, str):
            raise ValidationError("Victim ID must be a non-empty string")
        return self._make_request(API_ENDPOINTS["victim"], victim_id)

    # --- IOCs ---

    def get_ioc_groups(self, type: Optional[str] = None) -> Dict:
        params = self._build_params(type=type)
        return self._make_request(API_ENDPOINTS["iocs"], params=params)

    def get_group_iocs(self, group: str, type: Optional[str] = None) -> Dict:
        normalized = self._validate_group(group)
        params = self._build_params(type=type)
        return self._make_request(API_ENDPOINTS["iocs"], normalized, params=params)


    # --- CSIRT ---

    def get_csirt(self, country: str) -> Dict:
        if not validate_country_code(country):
            raise ValidationError("Invalid country code")
        return self._make_request(API_ENDPOINTS["csirt"], country)

    # --- Sectors ---

    def get_sectors(self) -> Dict:
        return self._make_request(API_ENDPOINTS["sectors"])

    # --- YARA ---

    def get_yara_groups(self) -> Dict:
        return self._make_request(API_ENDPOINTS["yara"])

    def get_group_yara(self, group: str) -> Dict:
        normalized = self._validate_group(group)
        return self._make_request(API_ENDPOINTS["yara"], normalized)

    # --- 8K Filings ---

    def get_8k_filings(
        self,
        ticker: Optional[str] = None,
        cik: Optional[str] = None,
        year: Optional[int] = None,
        month: Optional[int] = None,
        item105: Optional[bool] = None,
        item801: Optional[bool] = None,
    ) -> Dict:
        if year is not None and not validate_year(year):
            raise ValidationError("Invalid year")
        if month is not None and not validate_month(month):
            raise ValidationError("Invalid month")
        params = self._build_params(
            ticker=ticker, cik=cik, year=year, month=month,
            item105=item105, item801=item801,
        )
        return self._make_request(API_ENDPOINTS["8k"], params=params)

    # --- Validate ---

    def validate_key(self) -> Dict:
        return self._make_request(API_ENDPOINTS["validate"])
