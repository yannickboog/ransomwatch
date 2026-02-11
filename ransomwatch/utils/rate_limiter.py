from __future__ import annotations

import threading
import time
from collections import deque
from typing import Any, Dict

from .sanitization import safe_log_debug


class RateLimiter:
    def __init__(
        self,
        requests_per_minute: int = 30,
        requests_per_second: int = 2,
        min_interval: float = 0.5,
    ):
        self.requests_per_minute = min(requests_per_minute, 60)
        self.requests_per_second = min(requests_per_second, 10)
        self.min_interval = max(min_interval, 0.1)
        self._lock = threading.Lock()
        self._request_times: deque = deque()
        self._last_request_time = 0.0
        safe_log_debug(
            f"Rate limiter initialized: {self.requests_per_minute}/min, "
            f"{self.requests_per_second}/sec, min interval: {self.min_interval}s"
        )

    def wait_if_needed(self) -> float:
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
                "time_since_last_request": current_time - self._last_request_time,
            }
