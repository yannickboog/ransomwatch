"""Business logic and data formatting"""

import json
import logging
from datetime import datetime
from textwrap import shorten
from typing import Dict, List, Optional

from .utils import validate_api_response

logger = logging.getLogger(__name__)


class RansomWatchLogic:
    """Business logic for processing and formatting ransomware data"""
    
    def __init__(self, json_output: bool = False):
        self.json_output = json_output
    
    def format_groups(self, data: Dict) -> int:
        """Format and display ransomware groups"""
        groups = validate_api_response(data, "groups", list)
        if groups is None:
            return 1
        
        if self.json_output:
            print(json.dumps(data, indent=2))
            return 0
        
        print(f"\n[+] Found {len(groups)} active groups:")
        print("=" * 80)
        
        sorted_groups = sorted(groups, key=lambda x: x.get("victims", 0), reverse=True)
        
        for i, group in enumerate(sorted_groups, 1):
            name = group.get("group", "Unknown")
            altname = group.get("altname", "")
            victims = group.get("victims", 0)
            
            if victims > 100:
                indicator = "🔴"
            elif victims > 50:
                indicator = "🟡"
            elif victims > 10:
                indicator = "🟢"
            else:
                indicator = "⚪"
            
            print(f"\n{i:2d}. {indicator} {name}")
            if altname and altname != name:
                print(f"    └─ Also known as: {altname}")
            print(f"    └─ Victims: {victims:,}")
        
        print(f"\n{'=' * 80}")
        total_victims = sum(group.get("victims", 0) for group in groups)
        print(f"Total groups: {len(groups)} | Total victims: {total_victims:,}")
        return 0
    
    def format_recent_victims(self, data: Dict, limit: int) -> int:
        """Format and display recent victims"""
        # TODO: Add filtering by country/group
        victims_data = validate_api_response(data, "victims", list)
        if victims_data is None:
            return 1
        
        if self.json_output:
            limited_data = {"victims": victims_data[:limit]}
            print(json.dumps(limited_data, indent=2))
            return 0
        
        victims = victims_data[:limit]
        print(f"\n[+] Recent victims ({len(victims)}):")
        print("=" * 100)
        
        for i, victim in enumerate(victims, 1):
            company = victim.get("victim", "Unknown")
            group = victim.get("group", "Unknown")
            date = victim.get("discovered", "Unknown")
            description = victim.get("description", "No details")
            website = victim.get("website", "No website")
            country = victim.get("country", "Unknown")
            
            try:
                if date != "Unknown":
                    date_obj = datetime.fromisoformat(date.replace('Z', '+00:00'))
                    formatted_date = date_obj.strftime("%Y-%m-%d %H:%M")
                else:
                    formatted_date = "Unknown"
            except (ValueError, TypeError):
                formatted_date = date
            
            print(f"\n{i:2d}. {company}")
            print(f"    ┌─ Group:     {group}")
            print(f"    ├─ Date:      {formatted_date}")
            print(f"    ├─ Country:   {country}")
            if website and website != "No website":
                print(f"    ├─ Website:   {website}")
            print(f"    └─ Details:   {shorten(description, width=80, placeholder='...')}")
        
        print(f"\n{'=' * 100}")
        print(f"Total: {len(victims)} recent victims displayed")
        return 0
    
    def format_group_info(self, group: Dict, group_name: str) -> int:
        """Format and display detailed group information"""
        if self.json_output:
            print(json.dumps(group, indent=2))
            return 0
        
        print(f"\n[+] Group Information:")
        print("=" * 60)
        
        name = group.get("group", group_name)
        altname = group.get("altname", "")
        victims = group.get("victims", 0)
        
        print(f"\n🔍 {name}")
        if altname and altname != name:
            print(f"    └─ Also known as: {altname}")
        print(f"    └─ Total victims: {victims:,}")
        
        if "first_seen" in group or "last_seen" in group:
            print(f"\n📅 Activity Period:")
            if "first_seen" in group:
                print(f"    ├─ First seen: {group['first_seen']}")
            if "last_seen" in group:
                print(f"    └─ Last seen: {group['last_seen']}")
        
        if "ttps" in group and group["ttps"]:
            print(f"\n🎯 TTPs (Tactics, Techniques, Procedures):")
            ttps = group["ttps"]
            if isinstance(ttps, list):
                valid_ttps = [ttp for ttp in ttps if ttp]
                for i, ttp in enumerate(valid_ttps[:5], 1):
                    print(f"    {i}. {ttp}")
                if len(valid_ttps) > 5:
                    print(f"    ... and {len(valid_ttps) - 5} more")
            else:
                print(f"    └─ {ttps}")
        
        if "tools" in group and group["tools"]:
            print(f"\n🛠️  Tools:")
            tools = group["tools"]
            if isinstance(tools, dict):
                for category, items in tools.items():
                    print(f"    {category}:")
                    if isinstance(items, list):
                        for tool in items:
                            if tool:
                                print(f"      - {tool}")
                    else:
                        if items:
                            print(f"      - {items}")
            elif isinstance(tools, list):
                valid_tools = [tool for tool in tools if tool]
                for i, tool in enumerate(valid_tools[:5], 1):
                    print(f"    {i}. {tool}")
                if len(valid_tools) > 5:
                    print(f"    ... and {len(valid_tools) - 5} more")
            else:
                print(f"    └─ {tools}")
        
        if "description" in group and group["description"]:
            print(f"\n📝 Description:")
            desc = group["description"]
            if isinstance(desc, str) and desc.strip():
                print(f"    └─ {shorten(desc, width=200, placeholder='...')}")
            else:
                print(f"    └─ No valid description available")
        
        print(f"\n{'=' * 60}")
        return 0
    
    def format_stats(self, data: Dict) -> int:
        """Format and display statistics"""
        stats = validate_api_response(data, "stats", dict)
        if stats is None:
            return 1
        
        if self.json_output:
            print(json.dumps(data, indent=2))
            return 0
        
        print(f"\n[+] Ransomware Statistics:")
        print("=" * 50)
        
        groups = stats.get('groups', 0)
        victims = stats.get('victims', 0)
        press = stats.get('press', 0)
        
        print(f"\n📊 Overview:")
        print(f"    ┌─ Total Groups:     {groups:,}")
        print(f"    ├─ Total Victims:    {victims:,}")
        print(f"    └─ Press Mentions:   {press:,}")
        
        if data and isinstance(data, dict) and "last_update" in data:
            print(f"\n🕒 Last Update: {data['last_update']}")
        
        if groups > 0 and victims > 0:
            avg_victims = victims / groups
            print(f"\n📈 Metrics:")
            print(f"    └─ Average victims per group: {avg_victims:.1f}")
        
        print(f"\n{'=' * 50}")
        return 0 