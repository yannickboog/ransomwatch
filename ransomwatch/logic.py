"""Business logic and data formatting"""

import json
import logging
from datetime import datetime
from textwrap import shorten
from typing import Dict, List, Optional

from .utils import validate_api_response, create_separator, format_title, get_terminal_width

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
        
        term_width = get_terminal_width()
        
        print(f"\nRANSOMWARE GROUP ANALYSIS")
        print(f"Active Groups: {len(groups)}")
        
        sorted_groups = sorted(groups, key=lambda x: x.get("victims", 0), reverse=True)
        
        for i, group in enumerate(sorted_groups, 1):
            name = group.get("group", "Unknown")
            altname = group.get("altname", "")
            victims = group.get("victims", 0)
            
            if victims > 100:
                risk_level = "[CRITICAL]"
            elif victims > 50:
                risk_level = "[HIGH]    "
            elif victims > 10:
                risk_level = "[MEDIUM]  "
            else:
                risk_level = "[LOW]     "
            
            if term_width < 50:
                name_truncated = name[:max(15, term_width-15)] if len(name) > term_width-15 else name
                print(f"{i:3d}. {risk_level} {name_truncated}")
                print(f"     Victims: {victims:,}")
            else:
                print(f"{i:3d}. {risk_level} {name}")
                if altname and altname != name:
                    print(f"     Alternative Name: {altname}")
                print(f"     Victim Count: {victims:,}")
                if i < len(sorted_groups):
                    print()
        
        print()
        total_victims = sum(group.get("victims", 0) for group in groups)
        print(f"SUMMARY: {len(groups)} Groups | {total_victims:,} Total Victims")
        
        critical = sum(1 for g in groups if g.get("victims", 0) > 100)
        high = sum(1 for g in groups if 50 < g.get("victims", 0) <= 100)
        medium = sum(1 for g in groups if 10 < g.get("victims", 0) <= 50)
        low = sum(1 for g in groups if g.get("victims", 0) <= 10)
        
        print(f"RISK BREAKDOWN: Critical: {critical} | High: {high} | Medium: {medium} | Low: {low}")
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
        term_width = get_terminal_width()
        
        print(f"\nRECENT RANSOMWARE INCIDENTS")
        print(f"Displaying: {len(victims)} most recent cases")
        
        description_width = max(30, term_width - 35)
        
        for i, victim in enumerate(victims, 1):
            company = victim.get("victim", "Unknown")
            group = victim.get("group", "Unknown")
            date = victim.get("discovered", "Unknown")
            description = victim.get("description") or "No details available"
            website = victim.get("website", "")
            country = victim.get("country", "Unknown")
            
            try:
                if date != "Unknown":
                    date_obj = datetime.fromisoformat(date.replace('Z', '+00:00'))
                    formatted_date = date_obj.strftime("%Y-%m-%d")
                    formatted_time = date_obj.strftime("%H:%M")
                else:
                    formatted_date = "Unknown"
                    formatted_time = ""
            except (ValueError, TypeError):
                formatted_date = str(date)[:10] if date else "Unknown"
                formatted_time = ""
            
            if term_width < 60:
                company_truncated = company[:max(20, term_width-15)] if len(company) > term_width-15 else company
                print(f"{i:3d}. {company_truncated}")
                print(f"     Group: {group}")
                print(f"     Date: {formatted_date}")
                print(f"     Country: {country}")
            else:
                print(f"{i:3d}. VICTIM: {company}")
                print(f"     Threat Actor: {group}")
                print(f"     Discovery Date: {formatted_date} {formatted_time}")
                print(f"     Location: {country}")
                if website:
                    print(f"     Website: {website}")
                print(f"     Details: {shorten(description, width=description_width, placeholder='...')}")
                if i < len(victims):
                    print()
        
        print()
        print(f"TOTAL INCIDENTS DISPLAYED: {len(victims)}")
        return 0
    
    def format_group_info(self, group: Dict, group_name: str) -> int:
        """Format and display detailed group information"""
        if self.json_output:
            print(json.dumps(group, indent=2))
            return 0
        
        term_width = get_terminal_width()
        
        print(f"\nTHREAT ACTOR INTELLIGENCE REPORT")
        
        name = group.get("group", group_name)
        altname = group.get("altname", "")
        victims = group.get("victims", 0)
        
        if victims > 100:
            threat_level = "CRITICAL"
        elif victims > 50:
            threat_level = "HIGH"
        elif victims > 10:
            threat_level = "MEDIUM"
        else:
            threat_level = "LOW"
        
        if term_width < 50:
            name_truncated = name[:max(15, term_width-10)] if len(name) > term_width-10 else name
            print(f"\nGROUP NAME: {name_truncated}")
            if altname and altname != name:
                altname_truncated = altname[:max(15, term_width-10)] if len(altname) > term_width-10 else altname
                print(f"ALIAS: {altname_truncated}")
            print(f"THREAT LEVEL: {threat_level}")
            print(f"VICTIM COUNT: {victims:,}")
        else:
            print(f"\nPRIMARY IDENTIFIER: {name}")
            if altname and altname != name:
                print(f"ALTERNATIVE NAMES: {altname}")
            print(f"THREAT CLASSIFICATION: {threat_level}")
            print(f"CONFIRMED VICTIMS: {victims:,}")
        
        if "first_seen" in group or "last_seen" in group:
            if term_width < 50:
                print(f"\nACTIVITY TIMELINE:")
                if "first_seen" in group:
                    print(f"First Observed: {group['first_seen']}")
                if "last_seen" in group:
                    print(f"Last Activity: {group['last_seen']}")
            else:
                print(f"\nOPERATIONAL TIMELINE:")
                if "first_seen" in group:
                    print(f"Initial Detection: {group['first_seen']}")
                if "last_seen" in group:
                    print(f"Most Recent Activity: {group['last_seen']}")
        
        if "ttps" in group and group["ttps"]:
            if term_width < 50:
                print(f"\nTACTICS & TECHNIQUES: [Expand terminal for details]")
            else:
                print(f"\nTACTICS, TECHNIQUES & PROCEDURES (TTPs):")
                ttps = group["ttps"]
                if isinstance(ttps, list):
                    displayed_ttps = ttps[:8]
                    for i, ttp in enumerate(displayed_ttps, 1):
                        try:
                            if isinstance(ttp, dict):
                                tactic_name = ttp.get("tactic_name", "Unknown")
                                tactic_id = ttp.get("tactic_id", "")
                                print(f"  {i}. TACTIC: {tactic_name} ({tactic_id})")
                                techniques = ttp.get("techniques", [])
                                if isinstance(techniques, list):
                                    displayed_techniques = techniques[:3]
                                    for tech in displayed_techniques:
                                        try:
                                            if isinstance(tech, dict):
                                                tech_name = tech.get("technique_name", "Unknown")
                                                tech_id = tech.get("technique_id", "")
                                                details = tech.get("technique_details", "")
                                                if details and isinstance(details, str):
                                                    detail_width = max(60, term_width - 25)
                                                    shortened_details = shorten(details.strip(), width=detail_width, placeholder="...")
                                                else:
                                                    shortened_details = "No details available"
                                                print(f"     - TECHNIQUE: {tech_name} ({tech_id})")
                                                print(f"       DESCRIPTION: {shortened_details}")
                                            else:
                                                display_width = max(60, term_width - 25)
                                                tech_str = str(tech)[:display_width]
                                                print(f"     - {tech_str}...")
                                        except Exception as e:
                                            print(f"     - [Error processing technique data]")
                                            logger.debug(f"TTP technique error: {e}")
                                    if len(techniques) > 3:
                                        print(f"     ... and {len(techniques) - 3} additional techniques")
                                else:
                                    display_width = max(60, term_width - 25)
                                    tech_str = str(techniques)[:display_width]
                                    print(f"     TECHNIQUES: {tech_str}...")
                            else:
                                display_width = max(60, term_width - 25)
                                ttp_str = str(ttp)[:display_width]
                                print(f"  {i}. {ttp_str}...")
                        except Exception as e:
                            print(f"  {i}. [Error processing TTP data]")
                            logger.debug(f"TTP error: {e}")
                    
                    if len(ttps) > 8:
                        print(f"  ... and {len(ttps) - 8} additional TTPs")
                else:
                    try:
                        display_width = max(80, term_width - 15)
                        ttps_str = str(ttps)[:display_width]
                        print(f"  TTP DATA: {ttps_str}...")
                    except Exception:
                        print(f"  [TTP data format not supported]")
        
        if "tools" in group and group["tools"]:
            if term_width < 50:
                print(f"\nTOOLS: [Expand terminal for details]")
            else:
                print(f"\nKNOWN TOOLS & MALWARE:")
                tools = group["tools"]
                if isinstance(tools, dict):
                    for category, items in tools.items():
                        print(f"  {category.upper()}:")
                        if isinstance(items, list):
                            for tool in items:
                                if tool:
                                    print(f"    - {tool}")
                        else:
                            if items:
                                print(f"    - {items}")
                elif isinstance(tools, list):
                    valid_tools = [tool for tool in tools if tool]
                    for i, tool in enumerate(valid_tools[:8], 1):
                        print(f"  {i}. {tool}")
                    if len(valid_tools) > 8:
                        print(f"  ... and {len(valid_tools) - 8} additional tools")
                else:
                    print(f"  TOOLS: {tools}")
        
        if "description" in group and group["description"]:
            desc = group["description"]
            if isinstance(desc, str) and desc.strip():
                if term_width < 50:
                    print(f"\nDESCRIPTION:")
                    desc_width = max(25, term_width - 5)
                    print(f"{shorten(desc, width=desc_width, placeholder='...')}")
                else:
                    print(f"\nTHREAT ASSESSMENT:")
                    desc_width = max(80, term_width - 15)
                    print(f"  {shorten(desc, width=desc_width, placeholder='...')}")
            else:
                if term_width >= 50:
                    print(f"  No detailed assessment available")
        
        print()
        print(f"REPORT GENERATED: Intelligence Database Query Complete")
        return 0
    
    def format_stats(self, data: Dict) -> int:
        """Format and display statistics"""
        stats = validate_api_response(data, "stats", dict)
        if stats is None:
            return 1
        
        if self.json_output:
            print(json.dumps(data, indent=2))
            return 0
        
        print(f"\nRANSOMWARE THREAT LANDSCAPE STATISTICS")
        
        groups = stats.get('groups', 0)
        victims = stats.get('victims', 0)
        press = stats.get('press', 0)
        
        print(f"\nOVERVIEW:")
        print(f"  Active Threat Groups: {groups:,}")
        print(f"  Confirmed Victims: {victims:,}")
        print(f"  Press Reports: {press:,}")
        
        if data and isinstance(data, dict) and "last_update" in data:
            print(f"\nDATA CURRENCY:")
            print(f"  Last Updated: {data['last_update']}")
        
        if groups > 0 and victims > 0:
            avg_victims = victims / groups
            print(f"\nSTATISTICAL ANALYSIS:")
            print(f"  Average Victims per Group: {avg_victims:.1f}")
            
            if avg_victims > 50:
                activity_level = "HIGH"
            elif avg_victims > 20:
                activity_level = "MODERATE"
            else:
                activity_level = "LOW"
            
            print(f"  Overall Threat Activity: {activity_level}")
        
        print()
        print(f"ANALYSIS COMPLETE")
        return 0 
