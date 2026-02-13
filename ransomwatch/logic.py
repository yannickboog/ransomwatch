from __future__ import annotations

import json
from typing import Any, Dict, List, Union

from .models import CSIRT, RansomwareGroup, Sector, Stats, Victim
from .rendering import RichRenderer
from .utils import validate_api_response


class RansomWatchLogic:
    def __init__(self, renderer: RichRenderer, json_output: bool = False):
        self.renderer = renderer
        self.json_output = json_output

    def format_groups(self, data: Dict) -> int:
        groups_raw = validate_api_response(data, "groups", list)
        if groups_raw is None:
            return 1
        if self.json_output:
            print(json.dumps(data, indent=2))
            return 0
        groups = [RansomwareGroup.from_dict(g) for g in groups_raw]
        self.renderer.render_groups(groups)
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
        self.renderer.render_victims(victims)
        return 0

    def format_group_info(self, data: Dict, group_name: str) -> int:
        if self.json_output:
            print(json.dumps(data, indent=2))
            return 0
        group = RansomwareGroup.from_dict(data)
        self.renderer.render_group_info(group)
        return 0

    def format_stats(self, data: Dict) -> int:
        stats_raw = validate_api_response(data, "stats", dict)
        if stats_raw is None:
            return 1
        if self.json_output:
            print(json.dumps(data, indent=2))
            return 0
        stats = Stats.from_dict(data)
        self.renderer.render_stats(stats)
        return 0

    def format_validate(self, data: Union[Dict, Any]) -> int:
        if not data or not isinstance(data, dict):
            return 1
        if self.json_output:
            print(json.dumps(data, indent=2))
            return 0
        self.renderer.render_validate(data)
        return 0

    def format_sectors(self, data: Union[Dict, List, Any]) -> int:
        if data is None:
            return 1
        if self.json_output:
            print(json.dumps(data, indent=2))
            return 0
        if isinstance(data, dict):
            sectors_raw = data.get("sectors", [])
        elif isinstance(data, list):
            sectors_raw = data
        else:
            return 1
        if not isinstance(sectors_raw, list):
            return 1
        sectors = [Sector.from_dict(s) for s in sectors_raw]
        self.renderer.render_sectors(sectors)
        return 0

    def format_csirt(self, data: Union[Dict, Any]) -> int:
        if not data or not isinstance(data, dict):
            return 1
        if self.json_output:
            print(json.dumps(data, indent=2))
            return 0
        results = data.get("results", [])
        if not isinstance(results, list):
            return 1
        csirts = [CSIRT.from_dict(r) for r in results]
        self.renderer.render_csirt(csirts, data.get("country", ""))
        return 0

