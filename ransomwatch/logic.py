from __future__ import annotations

import json
from typing import Any, Dict, List, Union

from .models import CSIRT, Filing8K, IOC, IOCGroup, RansomwareGroup, Sector, Stats, Victim, YaraGroup, YaraRule
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

    def _extract_list(self, data: Any) -> list:
        if isinstance(data, list):
            return data
        if isinstance(data, dict):
            for value in data.values():
                if isinstance(value, list):
                    return value
        return []

    def format_iocs(self, data: Any, group: str = "") -> int:
        if data is None:
            return 1
        if self.json_output:
            print(json.dumps(data, indent=2))
            return 0
        if group:
            iocs = self._flatten_iocs(data, group)
            self.renderer.render_iocs(iocs, group)
        else:
            items = self._extract_list(data)
            ioc_groups = [IOCGroup.from_dict(i) for i in items]
            self.renderer.render_ioc_groups(ioc_groups)
        return 0

    def _flatten_iocs(self, data: Any, group: str) -> list:
        if not isinstance(data, dict):
            return []
        iocs_raw = data.get("iocs", {})
        if not isinstance(iocs_raw, dict):
            return []
        result = []
        for ioc_type, values in iocs_raw.items():
            if isinstance(values, list):
                for value in values:
                    result.append(IOC(type=ioc_type, value=str(value), group=group, details=""))
        return result

    def format_yara(self, data: Any, group: str = "") -> int:
        if data is None:
            return 1
        if self.json_output:
            print(json.dumps(data, indent=2))
            return 0
        items = self._extract_list(data)
        if group:
            rules = [YaraRule.from_dict(r) for r in items]
            self.renderer.render_yara_rules(rules, group)
        else:
            yara_groups = [YaraGroup.from_dict(g) for g in items]
            self.renderer.render_yara_groups(yara_groups)
        return 0

    def format_victims_list(self, data: Any, filters: str = "") -> int:
        if data is None:
            return 1
        if self.json_output:
            print(json.dumps(data, indent=2))
            return 0
        items = self._extract_list(data)
        victims = [Victim.from_dict(v) for v in items]
        self.renderer.render_victims_list(victims, filters)
        return 0

    def format_8k(self, data: Any) -> int:
        if data is None:
            return 1
        if self.json_output:
            print(json.dumps(data, indent=2))
            return 0
        items = self._extract_list(data)
        filings = [Filing8K.from_dict(f) for f in items]
        self.renderer.render_8k_filings(filings)
        return 0

