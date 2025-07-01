"""Command line interface"""

import argparse
import logging
import sys
import os
from typing import Optional

from .config import (
    DEFAULT_TIMEOUT, DEFAULT_REQUESTS_PER_MINUTE, 
    DEFAULT_REQUESTS_PER_SECOND, MIN_REQUEST_INTERVAL
)
from .api import RansomWatchAPI
from .logic import RansomWatchLogic
from .utils import (
    validate_command, validate_timeout, validate_limit, validate_group_name,
    safe_log_error, safe_log_debug, safe_log_info
)

logging.basicConfig(level=logging.INFO, format='[%(levelname)s] %(message)s')
logger = logging.getLogger(__name__)


class RansomWatchCLI:
    """Command line interface for ransomwatch"""
    
    def __init__(self):
        self.parser = self._create_parser()
        self.api: Optional[RansomWatchAPI] = None
        self.logic: Optional[RansomWatchLogic] = None
    
    def _create_parser(self) -> argparse.ArgumentParser:
        """Create and configure the argument parser"""
        parser = argparse.ArgumentParser(
            prog="ransomwatch",
            description="ransomwatch - Ransomware Intelligence Tool",
            formatter_class=argparse.RawDescriptionHelpFormatter,
            epilog="""
examples:
  ransomwatch groups
  ransomwatch recent -l 20
  ransomwatch info --group lockbit3
  ransomwatch stats
  ransomwatch --rate-limit-per-minute 10 groups
            """
        )
        
        parser.add_argument('--verbose', action='store_true', 
                          help='Enable debug logging')
        parser.add_argument('--timeout', type=int, default=DEFAULT_TIMEOUT, 
                          help=f'Timeout in seconds (default: {DEFAULT_TIMEOUT})')
        parser.add_argument('--json', action='store_true', 
                          help='Output as JSON')
        
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
        recent_parser.add_argument(
            '-l', '--limit',
            type=int,
            default=10,
            help='Number of victims (default: 10)'
        )
        
        info_parser = subparsers.add_parser("info", help="Get group details")
        info_parser.add_argument('--group', type=str, required=True, 
                               help='Group name (case-insensitive)')
        
        subparsers.add_parser("stats", help="Show statistics")
        
        return parser
    
    def _validate_args(self, args) -> bool:
        """Validate command line arguments with strict whitelist validation"""
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
        
        return True
    
    def _setup_logging(self, verbose: bool, json_output: bool):
        """Configure logging based on CLI arguments"""
        if verbose:
            logging.getLogger().setLevel(logging.DEBUG)
            safe_log_debug("Verbose logging enabled")
        
        if json_output and not verbose:
            logging.getLogger().setLevel(logging.WARNING)
    
    def _get_api_token(self) -> Optional[str]:
        """Get API token from environment variable only"""
        # TODO: Support config file for token storage
        api_token = os.environ.get('RANSOMWATCH_API_TOKEN')
        if not api_token:
            safe_log_error("No API token provided. Set the RANSOMWATCH_API_TOKEN environment variable.")
            safe_log_error("Example: export RANSOMWATCH_API_TOKEN=your_token")
            safe_log_error("Security: API tokens are only accepted via environment variables.")
            return None
        return api_token
    
    def run(self, args: Optional[list] = None) -> int:
        """Run the CLI with given arguments"""
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
        
        self.api = RansomWatchAPI(
            api_token=api_token, 
            timeout=parsed_args.timeout,
            requests_per_minute=parsed_args.rate_limit_per_minute,
            requests_per_second=parsed_args.rate_limit_per_second,
            min_interval=parsed_args.min_interval
        )
        self.logic = RansomWatchLogic(json_output=parsed_args.json)
        
        if parsed_args.verbose:
            safe_log_debug(f"Using timeout: {parsed_args.timeout}s")
            safe_log_debug(f"JSON output: {'enabled' if parsed_args.json else 'disabled'}")
            safe_log_debug(f"Rate limits: {parsed_args.rate_limit_per_minute}/min, "
                          f"{parsed_args.rate_limit_per_second}/sec, min: {parsed_args.min_interval}s")
        
        return self._execute_command(parsed_args)
    
    def _execute_command(self, args) -> int:
        """Execute the specified command with additional safety validation"""
        if not validate_command(args.command):
            safe_log_error("Command validation failed in execution")
            safe_debug_cmd = str(args.command)[:15].replace('<', '[').replace('>', ']')
            safe_log_debug(f"Invalid command attempted: {safe_debug_cmd}...")
            return 1
        
        if args.command == "groups":
            return self._cmd_groups()
        elif args.command == "recent":
            return self._cmd_recent(args.limit)
        elif args.command == "info":
            return self._cmd_info(args.group)
        elif args.command == "stats":
            return self._cmd_stats()
        else:
            safe_log_error("Unexpected command bypass detected")
            safe_debug_cmd = str(args.command)[:15].replace('<', '[').replace('>', ']')
            safe_log_debug(f"Bypassed command: {safe_debug_cmd}...")
            return 1
    
    def _cmd_groups(self) -> int:
        """Execute groups command"""
        if self.logic is None or self.api is None:
            safe_log_error("API or logic not initialized")
            return 1
            
        if not self.logic.json_output:
            safe_log_info("Fetching ransomware groups...")
        
        data = self.api.get_groups()
        if data is None:
            return 1
        
        return self.logic.format_groups(data)
    
    def _cmd_recent(self, limit: int) -> int:
        """Execute recent command"""
        if self.logic is None or self.api is None:
            safe_log_error("API or logic not initialized")
            return 1
            
        if not self.logic.json_output:
            safe_log_info(f"Fetching {limit} recent victims...")
        
        data = self.api.get_recent_victims()
        if data is None:
            return 1
        
        return self.logic.format_recent_victims(data, limit)
    
    def _cmd_info(self, group_name: str) -> int:
        """Execute info command"""
        if self.logic is None or self.api is None:
            safe_log_error("API or logic not initialized")
            return 1
        
        if not validate_group_name(group_name):
            safe_log_error("Group name validation failed")
            safe_debug_input = group_name[:20].replace('<', '[').replace('>', ']').replace('&', '[AMP]')
            safe_log_debug(f"Invalid group name (truncated): {safe_debug_input}...")
            return 1
            
        if not self.logic.json_output:
            safe_log_info("Fetching group information...")
        
        data = self.api.get_group_info(group_name)
        if data is None:
            return 1
        
        return self.logic.format_group_info(data, group_name)
    
    def _cmd_stats(self) -> int:
        """Execute stats command"""
        if self.logic is None or self.api is None:
            safe_log_error("API or logic not initialized")
            return 1
            
        if not self.logic.json_output:
            safe_log_info("Fetching statistics...")
        
        data = self.api.get_stats()
        if data is None:
            return 1
        
        return self.logic.format_stats(data)


def main(args: Optional[list] = None) -> int:
    """Main entry point for the CLI"""
    cli = RansomWatchCLI()
    return cli.run(args) 