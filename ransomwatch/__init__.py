"""
ransomwatch - Ransomware Intelligence Tool
Designed for threat intelligence, security research, and situational awareness.
Author: Yannick Boog
"""

from .api import RansomWatchAPI
from .logic import RansomWatchLogic
from .cli import RansomWatchCLI, main
from .utils import normalize_group_name, validate_api_response

__version__ = "1.1.1"
__author__ = "Yannick Boog"
__all__ = [
    "RansomWatchAPI",
    "RansomWatchLogic", 
    "RansomWatchCLI",
    "main",
    "normalize_group_name",
    "validate_api_response"
] 