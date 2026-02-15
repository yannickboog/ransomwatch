from __future__ import annotations

import argparse
import logging
import os
import sys
from typing import Optional

from rich.console import Console

from .api import RansomWatchAPI
from .exceptions import RansomWatchError
from .config import (
    DEFAULT_REQUESTS_PER_MINUTE,
    DEFAULT_REQUESTS_PER_SECOND,
    DEFAULT_TIMEOUT,
    MIN_REQUEST_INTERVAL,
)
from .logic import RansomWatchLogic
from .rendering import RichRenderer
from .utils import (
    safe_log_debug,
    safe_log_error,
    safe_log_info,
    validate_command,
    validate_country_code,
    validate_group_name,
    validate_limit,
    validate_timeout,
)

logging.basicConfig(level=logging.INFO, format='[%(levelname)s] %(message)s')
logger = logging.getLogger(__name__)


class RansomWatchCLI:
    def __init__(self):
        self.parser = self._create_parser()
        self.api: Optional[RansomWatchAPI] = None
        self.logic: Optional[RansomWatchLogic] = None
        self.console: Optional[Console] = None
        self._show_status = False

    def _create_parser(self) -> argparse.ArgumentParser:
        parser = argparse.ArgumentParser(
            prog="ransomwatch",
            description="ransomwatch - Ransomware Intelligence Tool",
            formatter_class=argparse.RawDescriptionHelpFormatter,
            epilog=(
                "examples:\n"
                "  ransomwatch groups\n"
                "  ransomwatch recent -l 20\n"
                "  ransomwatch info --group lockbit3\n"
                "  ransomwatch stats\n"
                "  ransomwatch validate\n"
                "  ransomwatch sectors\n"
                "  ransomwatch csirt --country US\n"
                "  ransomwatch iocs\n"
                "  ransomwatch iocs --group lockbit3\n"
                "  ransomwatch yara\n"
                "  ransomwatch yara --group akira\n"
                "  ransomwatch victims --country US\n"
                "  ransomwatch 8k --year 2025"
            ),
        )

        parser.add_argument('--verbose', action='store_true',
                            help='Enable debug logging')
        parser.add_argument('--timeout', type=int, default=DEFAULT_TIMEOUT,
                            help=f'Timeout in seconds (default: {DEFAULT_TIMEOUT})')
        parser.add_argument('--json', action='store_true',
                            help='Output as JSON')
        parser.add_argument('--no-color', action='store_true',
                            help='Disable colored output')
        parser.add_argument('--rate-limit-per-minute', type=int,
                            default=DEFAULT_REQUESTS_PER_MINUTE,
                            help=f'Max requests per minute (default: {DEFAULT_REQUESTS_PER_MINUTE})')
        parser.add_argument('--rate-limit-per-second', type=int,
                            default=DEFAULT_REQUESTS_PER_SECOND,
                            help=f'Max requests per second (default: {DEFAULT_REQUESTS_PER_SECOND})')
        parser.add_argument('--min-interval', type=float,
                            default=MIN_REQUEST_INTERVAL,
                            help=f'Min seconds between requests (default: {MIN_REQUEST_INTERVAL})')

        subparsers = parser.add_subparsers(dest="command", help="Available commands")

        subparsers.add_parser("groups", help="List active ransomware groups")

        recent_parser = subparsers.add_parser("recent", help="Show recent victims")
        recent_parser.add_argument('-l', '--limit', type=int, default=10,
                                   help='Number of victims (default: 10)')

        info_parser = subparsers.add_parser("info", help="Get group details")
        info_parser.add_argument('--group', type=str, required=True,
                                 help='Group name (case-insensitive)')

        subparsers.add_parser("stats", help="Show statistics")

        subparsers.add_parser("validate", help="Validate API key")

        subparsers.add_parser("sectors", help="List industry sectors")

        csirt_parser = subparsers.add_parser("csirt", help="Get CSIRT/CERT info for a country")
        csirt_parser.add_argument('--country', type=str, required=True,
                                  help='ISO country code (e.g. US, DE)')

        iocs_parser = subparsers.add_parser("iocs", help="Show indicators of compromise")
        iocs_parser.add_argument('--group', type=str, default=None,
                                 help='Filter by group name')
        iocs_parser.add_argument('--type', type=str, default=None,
                                 help='Filter by IOC type (e.g. md5, sha256, ip, url)')

        yara_parser = subparsers.add_parser("yara", help="Show YARA detection rules")
        yara_parser.add_argument('--group', type=str, default=None,
                                 help='Filter by group name')

        victims_parser = subparsers.add_parser("victims", help="List ransomware victims")
        victims_parser.add_argument('--group', type=str, default=None,
                                    help='Filter by group name')
        victims_parser.add_argument('--country', type=str, default=None,
                                    help='Filter by ISO country code')
        victims_parser.add_argument('--sector', type=str, default=None,
                                    help='Filter by sector')
        victims_parser.add_argument('--year', type=int, default=None,
                                    help='Filter by year')

        filing_parser = subparsers.add_parser("8k", help="Show SEC 8-K cybersecurity filings")
        filing_parser.add_argument('--ticker', type=str, default=None,
                                   help='Filter by stock ticker')
        filing_parser.add_argument('--year', type=int, default=None,
                                   help='Filter by year')

        return parser

    def _validate_args(self, args) -> bool:
        if not validate_command(args.command):
            return False
        if not validate_timeout(args.timeout):
            return False
        if args.rate_limit_per_minute <= 0 or args.rate_limit_per_minute > 60:
            safe_log_error("Rate limit per minute must be between 1 and 60")
            return False
        if args.rate_limit_per_second <= 0 or args.rate_limit_per_second > 10:
            safe_log_error("Rate limit per second must be between 1 and 10")
            return False
        if args.min_interval < 0.1 or args.min_interval > 60:
            safe_log_error("Minimum interval must be between 0.1 and 60 seconds")
            return False
        if args.command == "recent":
            if not validate_limit(args.limit):
                return False
        if args.command in ("iocs", "yara", "victims") and getattr(args, "group", None):
            if not validate_group_name(args.group):
                return False
        if args.command in ("victims", "csirt") and getattr(args, "country", None):
            if not validate_country_code(args.country):
                return False
        return True

    def _setup_logging(self, verbose: bool, json_output: bool):
        if verbose:
            logging.getLogger().setLevel(logging.DEBUG)
            safe_log_debug("Verbose logging enabled")
        if json_output and not verbose:
            logging.getLogger().setLevel(logging.WARNING)

    def _get_api_token(self) -> Optional[str]:
        api_token = os.environ.get('RANSOMWATCH_API_TOKEN')
        if not api_token:
            safe_log_error("No API token provided. Set the RANSOMWATCH_API_TOKEN environment variable.")
            safe_log_error("Example: export RANSOMWATCH_API_TOKEN=your_token")
            safe_log_error("Security: API tokens are only accepted via environment variables.")
            return None
        return api_token

    def _fetch(self, message: str, fetch_fn):
        try:
            if self._show_status:
                with self.console.status(f"[bold]{message}"):
                    return fetch_fn()
            return fetch_fn()
        except RansomWatchError as e:
            safe_log_error(str(e))
            return None

    def run(self, args: Optional[list] = None) -> int:
        parsed_args = self.parser.parse_args(args)
        if not parsed_args.command:
            self.parser.print_help()
            return 1
        if not self._validate_args(parsed_args):
            return 1

        self._setup_logging(parsed_args.verbose, parsed_args.json)

        api_token = self._get_api_token()
        if not api_token:
            return 1

        self.console = Console(no_color=parsed_args.no_color)
        self._show_status = not parsed_args.json and not parsed_args.verbose
        renderer = RichRenderer(self.console)

        self.api = RansomWatchAPI(
            api_token=api_token,
            timeout=parsed_args.timeout,
            requests_per_minute=parsed_args.rate_limit_per_minute,
            requests_per_second=parsed_args.rate_limit_per_second,
            min_interval=parsed_args.min_interval,
        )
        self.logic = RansomWatchLogic(renderer=renderer, json_output=parsed_args.json)

        if parsed_args.verbose:
            safe_log_debug(f"Using timeout: {parsed_args.timeout}s")
            safe_log_debug(f"JSON output: {'enabled' if parsed_args.json else 'disabled'}")
            safe_log_debug(
                f"Rate limits: {parsed_args.rate_limit_per_minute}/min, "
                f"{parsed_args.rate_limit_per_second}/sec, min: {parsed_args.min_interval}s"
            )

        return self._execute_command(parsed_args)

    def _execute_command(self, args) -> int:
        if not validate_command(args.command):
            safe_log_error("Command validation failed in execution")
            safe_debug_cmd = str(args.command)[:15].replace('<', '[').replace('>', ']')
            safe_log_debug(f"Invalid command attempted: {safe_debug_cmd}...")
            return 1

        commands = {
            "groups": self._cmd_groups,
            "recent": lambda: self._cmd_recent(args.limit),
            "info": lambda: self._cmd_info(args.group),
            "stats": self._cmd_stats,
            "validate": self._cmd_validate,
            "sectors": self._cmd_sectors,
            "csirt": lambda: self._cmd_csirt(args.country),
            "iocs": lambda: self._cmd_iocs(getattr(args, "group", None), getattr(args, "type", None)),
            "yara": lambda: self._cmd_yara(getattr(args, "group", None)),
            "victims": lambda: self._cmd_victims(
                getattr(args, "group", None), getattr(args, "country", None),
                getattr(args, "sector", None), getattr(args, "year", None),
            ),
            "8k": lambda: self._cmd_8k(getattr(args, "ticker", None), getattr(args, "year", None)),
        }

        handler = commands.get(args.command)
        if handler is None:
            safe_log_error("Unexpected command bypass detected")
            return 1

        return handler()

    def _cmd_groups(self) -> int:
        if self.logic is None or self.api is None:
            safe_log_error("API or logic not initialized")
            return 1
        data = self._fetch("Fetching ransomware groups...", self.api.get_groups)
        if data is None:
            return 1
        return self.logic.format_groups(data)

    def _cmd_recent(self, limit: int) -> int:
        if self.logic is None or self.api is None:
            safe_log_error("API or logic not initialized")
            return 1
        data = self._fetch(f"Fetching {limit} recent victims...", self.api.get_recent_victims)
        if data is None:
            return 1
        return self.logic.format_recent_victims(data, limit)

    def _cmd_info(self, group_name: str) -> int:
        if self.logic is None or self.api is None:
            safe_log_error("API or logic not initialized")
            return 1
        if not validate_group_name(group_name):
            safe_log_error("Group name validation failed")
            safe_debug_input = group_name[:20].replace('<', '[').replace('>', ']').replace('&', '[AMP]')
            safe_log_debug(f"Invalid group name (truncated): {safe_debug_input}...")
            return 1
        data = self._fetch("Fetching group information...", lambda: self.api.get_group_info(group_name))
        if data is None:
            return 1
        return self.logic.format_group_info(data, group_name)

    def _cmd_stats(self) -> int:
        if self.logic is None or self.api is None:
            safe_log_error("API or logic not initialized")
            return 1
        data = self._fetch("Fetching statistics...", self.api.get_stats)
        if data is None:
            return 1
        return self.logic.format_stats(data)

    def _cmd_validate(self) -> int:
        if self.logic is None or self.api is None:
            safe_log_error("API or logic not initialized")
            return 1
        data = self._fetch("Validating API key...", self.api.validate_key)
        if data is None:
            return 1
        return self.logic.format_validate(data)

    def _cmd_sectors(self) -> int:
        if self.logic is None or self.api is None:
            safe_log_error("API or logic not initialized")
            return 1
        data = self._fetch("Fetching sectors...", self.api.get_sectors)
        if data is None:
            return 1
        return self.logic.format_sectors(data)

    def _cmd_csirt(self, country: str) -> int:
        if self.logic is None or self.api is None:
            safe_log_error("API or logic not initialized")
            return 1
        if not validate_country_code(country):
            return 1
        data = self._fetch(f"Fetching CSIRT info for {country}...", lambda: self.api.get_csirt(country))
        if data is None:
            return 1
        return self.logic.format_csirt(data)

    def _cmd_iocs(self, group: Optional[str] = None, ioc_type: Optional[str] = None) -> int:
        if self.logic is None or self.api is None:
            safe_log_error("API or logic not initialized")
            return 1
        if group:
            data = self._fetch(f"Fetching IOCs for {group}...", lambda: self.api.get_group_iocs(group, type=ioc_type))
        else:
            data = self._fetch("Fetching IOC groups...", lambda: self.api.get_ioc_groups(type=ioc_type))
        if data is None:
            return 1
        return self.logic.format_iocs(data, group or "")

    def _cmd_yara(self, group: Optional[str] = None) -> int:
        if self.logic is None or self.api is None:
            safe_log_error("API or logic not initialized")
            return 1
        if group:
            data = self._fetch(f"Fetching YARA rules for {group}...", lambda: self.api.get_group_yara(group))
        else:
            data = self._fetch("Fetching YARA groups...", self.api.get_yara_groups)
        if data is None:
            return 1
        return self.logic.format_yara(data, group or "")

    def _cmd_victims(
        self,
        group: Optional[str] = None,
        country: Optional[str] = None,
        sector: Optional[str] = None,
        year: Optional[int] = None,
    ) -> int:
        if self.logic is None or self.api is None:
            safe_log_error("API or logic not initialized")
            return 1
        data = self._fetch("Fetching victims...", lambda: self.api.get_victims(
            group=group, country=country, sector=sector, year=year,
        ))
        if data is None:
            return 1
        filters_parts = []
        if group:
            filters_parts.append(f"group={group}")
        if country:
            filters_parts.append(f"country={country}")
        if sector:
            filters_parts.append(f"sector={sector}")
        if year:
            filters_parts.append(f"year={year}")
        return self.logic.format_victims_list(data, ", ".join(filters_parts))

    def _cmd_8k(self, ticker: Optional[str] = None, year: Optional[int] = None) -> int:
        if self.logic is None or self.api is None:
            safe_log_error("API or logic not initialized")
            return 1
        data = self._fetch("Fetching SEC 8-K filings...", lambda: self.api.get_8k_filings(
            ticker=ticker, year=year,
        ))
        if data is None:
            return 1
        return self.logic.format_8k(data)

def main(args: Optional[list] = None) -> int:
    cli = RansomWatchCLI()
    return cli.run(args)
