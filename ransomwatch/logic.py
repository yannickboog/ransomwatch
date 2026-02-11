from __future__ import annotations

import json
import logging
from datetime import datetime
from textwrap import shorten
from typing import Dict

from .config import (
    MAX_DISPLAY_TECHNIQUES,
    MAX_DISPLAY_TTPS,
    TERMINAL_WIDTH_COMPACT,
    TERMINAL_WIDTH_NARROW,
)
from .models import RansomwareGroup, Stats, Victim
from .utils import get_terminal_width, validate_api_response

logger = logging.getLogger(__name__)


class RansomWatchLogic:
    def __init__(self, json_output: bool = False):
        self.json_output = json_output

    def format_groups(self, data: Dict) -> int:
        groups_raw = validate_api_response(data, "groups", list)
        if groups_raw is None:
            return 1
        if self.json_output:
            print(json.dumps(data, indent=2))
            return 0

        groups = [RansomwareGroup.from_dict(g) for g in groups_raw]
        term_width = get_terminal_width()

        print(f"\nRANSOMWARE GROUP ANALYSIS")
        print(f"Active Groups: {len(groups)}")

        sorted_groups = sorted(groups, key=lambda x: x.victims, reverse=True)

        for i, group in enumerate(sorted_groups, 1):
            if term_width < TERMINAL_WIDTH_COMPACT:
                name_truncated = group.name[:max(15, term_width - 15)] if len(group.name) > term_width - 15 else group.name
                print(f"{i:3d}. {group.risk_label} {name_truncated}")
                print(f"     Victims: {group.victims:,}")
            else:
                print(f"{i:3d}. {group.risk_label} {group.name}")
                if group.altname and group.altname != group.name:
                    print(f"     Alternative Name: {group.altname}")
                print(f"     Victim Count: {group.victims:,}")
                if i < len(sorted_groups):
                    print()

        print()
        total_victims = sum(g.victims for g in groups)
        print(f"SUMMARY: {len(groups)} Groups | {total_victims:,} Total Victims")

        from .models import RiskLevel
        critical = sum(1 for g in groups if g.risk_level == RiskLevel.CRITICAL)
        high = sum(1 for g in groups if g.risk_level == RiskLevel.HIGH)
        medium = sum(1 for g in groups if g.risk_level == RiskLevel.MEDIUM)
        low = sum(1 for g in groups if g.risk_level == RiskLevel.LOW)

        print(f"RISK BREAKDOWN: Critical: {critical} | High: {high} | Medium: {medium} | Low: {low}")
        return 0

    def format_recent_victims(self, data: Dict, limit: int) -> int:
        victims_data = validate_api_response(data, "victims", list)
        if victims_data is None:
            return 1
        if self.json_output:
            limited_data = {"victims": victims_data[:limit]}
            print(json.dumps(limited_data, indent=2))
            return 0

        victims = [Victim.from_dict(v) for v in victims_data[:limit]]
        term_width = get_terminal_width()
        description_width = max(30, term_width - 35)

        print(f"\nRECENT RANSOMWARE INCIDENTS")
        print(f"Displaying: {len(victims)} most recent cases")

        for i, victim in enumerate(victims, 1):
            formatted_date, formatted_time = self._parse_date(victim.discovered)

            if term_width < TERMINAL_WIDTH_NARROW:
                company_truncated = victim.name[:max(20, term_width - 15)] if len(victim.name) > term_width - 15 else victim.name
                print(f"{i:3d}. {company_truncated}")
                print(f"     Group: {victim.group}")
                print(f"     Date: {formatted_date}")
                print(f"     Country: {victim.country}")
            else:
                print(f"{i:3d}. VICTIM: {victim.name}")
                print(f"     Threat Actor: {victim.group}")
                print(f"     Discovery Date: {formatted_date} {formatted_time}")
                print(f"     Location: {victim.country}")
                if victim.website:
                    print(f"     Website: {victim.website}")
                print(f"     Details: {shorten(victim.description, width=description_width, placeholder='...')}")
                if i < len(victims):
                    print()

        print()
        print(f"TOTAL INCIDENTS DISPLAYED: {len(victims)}")
        return 0

    def format_group_info(self, data: Dict, group_name: str) -> int:
        if self.json_output:
            print(json.dumps(data, indent=2))
            return 0

        group = RansomwareGroup.from_dict(data)
        term_width = get_terminal_width()

        print(f"\nTHREAT ACTOR INTELLIGENCE REPORT")

        if term_width < TERMINAL_WIDTH_COMPACT:
            self._print_group_header_compact(group, term_width)
        else:
            self._print_group_header(group)

        self._print_timeline(group, term_width)
        self._print_ttps(group, term_width)
        self._print_tools(group, term_width)
        self._print_description(group, term_width)

        print()
        print(f"REPORT GENERATED: Intelligence Database Query Complete")
        return 0

    def format_stats(self, data: Dict) -> int:
        stats_raw = validate_api_response(data, "stats", dict)
        if stats_raw is None:
            return 1
        if self.json_output:
            print(json.dumps(data, indent=2))
            return 0

        stats = Stats.from_dict(data)

        print(f"\nRANSOMWARE THREAT LANDSCAPE STATISTICS")

        print(f"\nOVERVIEW:")
        print(f"  Active Threat Groups: {stats.groups:,}")
        print(f"  Confirmed Victims: {stats.victims:,}")
        print(f"  Press Reports: {stats.press:,}")

        if stats.last_update:
            print(f"\nDATA CURRENCY:")
            print(f"  Last Updated: {stats.last_update}")

        if stats.groups > 0 and stats.victims > 0:
            print(f"\nSTATISTICAL ANALYSIS:")
            print(f"  Average Victims per Group: {stats.avg_victims_per_group:.1f}")
            print(f"  Overall Threat Activity: {stats.activity_level}")

        print()
        print(f"ANALYSIS COMPLETE")
        return 0

    def _parse_date(self, date_str: str) -> tuple[str, str]:
        try:
            if date_str != "Unknown":
                date_obj = datetime.fromisoformat(date_str.replace('Z', '+00:00'))
                return date_obj.strftime("%Y-%m-%d"), date_obj.strftime("%H:%M")
            return "Unknown", ""
        except (ValueError, TypeError):
            return str(date_str)[:10] if date_str else "Unknown", ""

    def _print_group_header_compact(self, group: RansomwareGroup, term_width: int):
        name_truncated = group.name[:max(15, term_width - 10)] if len(group.name) > term_width - 10 else group.name
        print(f"\nGROUP NAME: {name_truncated}")
        if group.altname and group.altname != group.name:
            altname_truncated = group.altname[:max(15, term_width - 10)] if len(group.altname) > term_width - 10 else group.altname
            print(f"ALIAS: {altname_truncated}")
        print(f"THREAT LEVEL: {group.risk_level.value}")
        print(f"VICTIM COUNT: {group.victims:,}")

    def _print_group_header(self, group: RansomwareGroup):
        print(f"\nPRIMARY IDENTIFIER: {group.name}")
        if group.altname and group.altname != group.name:
            print(f"ALTERNATIVE NAMES: {group.altname}")
        print(f"THREAT CLASSIFICATION: {group.risk_level.value}")
        print(f"CONFIRMED VICTIMS: {group.victims:,}")

    def _print_timeline(self, group: RansomwareGroup, term_width: int):
        if not group.first_seen and not group.last_seen:
            return
        if term_width < TERMINAL_WIDTH_COMPACT:
            print(f"\nACTIVITY TIMELINE:")
            if group.first_seen:
                print(f"First Observed: {group.first_seen}")
            if group.last_seen:
                print(f"Last Activity: {group.last_seen}")
        else:
            print(f"\nOPERATIONAL TIMELINE:")
            if group.first_seen:
                print(f"Initial Detection: {group.first_seen}")
            if group.last_seen:
                print(f"Most Recent Activity: {group.last_seen}")

    def _print_ttps(self, group: RansomwareGroup, term_width: int):
        if not group.ttps:
            return
        if term_width < TERMINAL_WIDTH_COMPACT:
            print(f"\nTACTICS & TECHNIQUES: [Expand terminal for details]")
            return

        print(f"\nTACTICS, TECHNIQUES & PROCEDURES (TTPs):")
        displayed_ttps = group.ttps[:MAX_DISPLAY_TTPS]

        for i, ttp in enumerate(displayed_ttps, 1):
            print(f"  {i}. TACTIC: {ttp.tactic_name} ({ttp.tactic_id})")
            displayed_techniques = ttp.techniques[:MAX_DISPLAY_TECHNIQUES]

            for tech in displayed_techniques:
                detail_width = max(60, term_width - 25)
                if tech.details and isinstance(tech.details, str):
                    shortened_details = shorten(tech.details.strip(), width=detail_width, placeholder="...")
                else:
                    shortened_details = "No details available"
                print(f"     - TECHNIQUE: {tech.name} ({tech.id})")
                print(f"       DESCRIPTION: {shortened_details}")

            if len(ttp.techniques) > MAX_DISPLAY_TECHNIQUES:
                print(f"     ... and {len(ttp.techniques) - MAX_DISPLAY_TECHNIQUES} additional techniques")

        if len(group.ttps) > MAX_DISPLAY_TTPS:
            print(f"  ... and {len(group.ttps) - MAX_DISPLAY_TTPS} additional TTPs")

    def _print_tools(self, group: RansomwareGroup, term_width: int):
        if not group.tools:
            return
        if term_width < TERMINAL_WIDTH_COMPACT:
            print(f"\nTOOLS: [Expand terminal for details]")
            return

        print(f"\nKNOWN TOOLS & MALWARE:")
        if isinstance(group.tools, dict):
            for category, items in group.tools.items():
                print(f"  {category.upper()}:")
                if isinstance(items, list):
                    for tool in items:
                        if tool:
                            print(f"    - {tool}")
                elif items:
                    print(f"    - {items}")
        elif isinstance(group.tools, list):
            valid_tools = [tool for tool in group.tools if tool]
            for i, tool in enumerate(valid_tools[:MAX_DISPLAY_TTPS], 1):
                print(f"  {i}. {tool}")
            if len(valid_tools) > MAX_DISPLAY_TTPS:
                print(f"  ... and {len(valid_tools) - MAX_DISPLAY_TTPS} additional tools")
        else:
            print(f"  TOOLS: {group.tools}")

    def _print_description(self, group: RansomwareGroup, term_width: int):
        if not group.description or not isinstance(group.description, str) or not group.description.strip():
            if term_width >= TERMINAL_WIDTH_COMPACT:
                print(f"  No detailed assessment available")
            return
        if term_width < TERMINAL_WIDTH_COMPACT:
            desc_width = max(25, term_width - 5)
            print(f"\nDESCRIPTION:")
            print(f"{shorten(group.description, width=desc_width, placeholder='...')}")
        else:
            desc_width = max(80, term_width - 15)
            print(f"\nTHREAT ASSESSMENT:")
            print(f"  {shorten(group.description, width=desc_width, placeholder='...')}")
