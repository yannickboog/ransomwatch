from __future__ import annotations


class RansomWatchError(Exception):
    pass


class APIError(RansomWatchError):
    pass


class AuthenticationError(APIError):
    pass


class RateLimitError(APIError):
    pass


class NotFoundError(APIError):
    pass


class ValidationError(RansomWatchError):
    pass


class ConfigurationError(RansomWatchError):
    pass
