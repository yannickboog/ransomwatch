from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any, List, Union

from .config import (
    RISK_THRESHOLD_CRITICAL,
    RISK_THRESHOLD_HIGH,
    RISK_THRESHOLD_MEDIUM,
)


class RiskLevel(Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"


@dataclass
class Technique:
    name: str
    id: str
    details: str

    @classmethod
    def from_dict(cls, data: Any) -> Technique:
        if not isinstance(data, dict):
            return cls(name=str(data), id="", details="")
        return cls(
            name=data.get("technique_name", "Unknown"),
            id=data.get("technique_id", ""),
            details=data.get("technique_details", ""),
        )


@dataclass
class TTP:
    tactic_name: str
    tactic_id: str
    techniques: list[Technique] = field(default_factory=list)

    @classmethod
    def from_dict(cls, data: Any) -> TTP:
        if not isinstance(data, dict):
            return cls(tactic_name=str(data), tactic_id="", techniques=[])
        techniques_raw = data.get("techniques", [])
        techniques = []
        if isinstance(techniques_raw, list):
            techniques = [Technique.from_dict(t) for t in techniques_raw]
        return cls(
            tactic_name=data.get("tactic_name", "Unknown"),
            tactic_id=data.get("tactic_id", ""),
            techniques=techniques,
        )


@dataclass
class RansomwareGroup:
    name: str
    altname: str
    victims: int
    first_seen: str
    last_seen: str
    ttps: list[TTP] = field(default_factory=list)
    tools: Union[list, dict] = field(default_factory=list)
    description: str = ""

    @property
    def risk_level(self) -> RiskLevel:
        if self.victims > RISK_THRESHOLD_CRITICAL:
            return RiskLevel.CRITICAL
        if self.victims > RISK_THRESHOLD_HIGH:
            return RiskLevel.HIGH
        if self.victims > RISK_THRESHOLD_MEDIUM:
            return RiskLevel.MEDIUM
        return RiskLevel.LOW

    @property
    def risk_label(self) -> str:
        labels = {
            RiskLevel.CRITICAL: "[CRITICAL]",
            RiskLevel.HIGH: "[HIGH]    ",
            RiskLevel.MEDIUM: "[MEDIUM]  ",
            RiskLevel.LOW: "[LOW]     ",
        }
        return labels[self.risk_level]

    @classmethod
    def from_dict(cls, data: dict) -> RansomwareGroup:
        ttps_raw = data.get("ttps", [])
        ttps = []
        if isinstance(ttps_raw, list):
            ttps = [TTP.from_dict(t) for t in ttps_raw]
        return cls(
            name=data.get("group", "Unknown"),
            altname=data.get("altname", ""),
            victims=data.get("victims", 0),
            first_seen=data.get("first_seen", ""),
            last_seen=data.get("last_seen", ""),
            ttps=ttps,
            tools=data.get("tools", []),
            description=data.get("description", ""),
        )


@dataclass
class Victim:
    name: str
    group: str
    discovered: str
    country: str
    description: str

    @classmethod
    def from_dict(cls, data: dict) -> Victim:
        return cls(
            name=data.get("victim", "Unknown"),
            group=data.get("group", "Unknown"),
            discovered=data.get("discovered", "Unknown"),
            country=data.get("country", "Unknown"),
            description=data.get("description") or "No details available",
        )


@dataclass
class Stats:
    groups: int
    victims: int
    press: int
    last_update: str

    @property
    def avg_victims_per_group(self) -> float:
        if self.groups == 0:
            return 0.0
        return self.victims / self.groups

    @property
    def activity_level(self) -> str:
        from .config import ACTIVITY_THRESHOLD_HIGH, ACTIVITY_THRESHOLD_MODERATE

        avg = self.avg_victims_per_group
        if avg > ACTIVITY_THRESHOLD_HIGH:
            return "HIGH"
        if avg > ACTIVITY_THRESHOLD_MODERATE:
            return "MODERATE"
        return "LOW"

    @classmethod
    def from_dict(cls, data: dict) -> Stats:
        stats = data.get("stats", {})
        if not isinstance(stats, dict):
            stats = {}
        return cls(
            groups=stats.get("groups", 0),
            victims=stats.get("victims", 0),
            press=stats.get("press", 0),
            last_update=data.get("last_update", ""),
        )


@dataclass
class VictimDetail:
    name: str
    group: str
    discovered: str
    country: str
    description: str
    sector: str
    enrichment: dict = field(default_factory=dict)

    @classmethod
    def from_dict(cls, data: Any) -> VictimDetail:
        if not isinstance(data, dict):
            data = {}
        enrichment = data.get("enrichment", {})
        if not isinstance(enrichment, dict):
            enrichment = {}
        return cls(
            name=data.get("victim", "Unknown"),
            group=data.get("group", "Unknown"),
            discovered=data.get("discovered", "Unknown"),
            country=data.get("country", "Unknown"),
            description=data.get("description") or "No details available",
            sector=data.get("sector", ""),
            enrichment=enrichment,
        )


@dataclass
class IOCGroup:
    group: str
    ioc_types: List[str] = field(default_factory=list)
    ioc_count: int = 0

    @classmethod
    def from_dict(cls, data: Any) -> IOCGroup:
        if not isinstance(data, dict):
            data = {}
        ioc_types_raw = data.get("ioc_types", {})
        if isinstance(ioc_types_raw, dict):
            ioc_types = list(ioc_types_raw.keys())
            ioc_count = sum(ioc_types_raw.values())
        elif isinstance(ioc_types_raw, list):
            ioc_types = ioc_types_raw
            ioc_count = 0
        else:
            ioc_types = []
            ioc_count = 0
        return cls(
            group=data.get("group", "Unknown"),
            ioc_types=ioc_types,
            ioc_count=ioc_count,
        )


@dataclass
class IOC:
    type: str
    value: str
    group: str
    details: str

    @classmethod
    def from_dict(cls, data: Any) -> IOC:
        if not isinstance(data, dict):
            data = {}
        return cls(
            type=data.get("type", ""),
            value=data.get("value", ""),
            group=data.get("group", ""),
            details=data.get("details", ""),
        )



@dataclass
class CSIRT:
    team: str
    full_name: str
    country: str
    email: str
    website: str
    constituency: list = field(default_factory=list)
    source: str = ""

    @classmethod
    def from_dict(cls, data: Any) -> CSIRT:
        if not isinstance(data, dict):
            data = {}
        constituency = data.get("constituency", [])
        if not isinstance(constituency, list):
            constituency = []
        return cls(
            team=data.get("team", ""),
            full_name=data.get("team-full", ""),
            country=data.get("country", ""),
            email=data.get("email", ""),
            website=data.get("website") or "",
            constituency=constituency,
            source=data.get("source", ""),
        )


@dataclass
class Sector:
    name: str
    victim_count: int = 0

    @classmethod
    def from_dict(cls, data: Any) -> Sector:
        if not isinstance(data, dict):
            data = {}
        return cls(
            name=data.get("sector", "Unknown"),
            victim_count=data.get("count", 0),
        )


@dataclass
class YaraGroup:
    group: str
    rule_count: int = 0

    @classmethod
    def from_dict(cls, data: Any) -> YaraGroup:
        if not isinstance(data, dict):
            data = {}
        return cls(
            group=data.get("group", "Unknown"),
            rule_count=data.get("yara_count", 0),
        )


@dataclass
class YaraRule:
    group: str
    filename: str
    content: str

    @classmethod
    def from_dict(cls, data: Any) -> YaraRule:
        if not isinstance(data, dict):
            data = {}
        return cls(
            group=data.get("group", ""),
            filename=data.get("filename", ""),
            content=data.get("content", ""),
        )


@dataclass
class Filing8K:
    ticker: str
    cik: str
    filing_date: str
    item_type: str
    description: str

    @classmethod
    def from_dict(cls, data: Any) -> Filing8K:
        if not isinstance(data, dict):
            data = {}
        items = []
        if data.get("item105"):
            items.append("1.05")
        if data.get("item801"):
            items.append("8.01")
        return cls(
            ticker=data.get("stockticker", ""),
            cik=data.get("cik", ""),
            filing_date=data.get("file_date", ""),
            item_type=", ".join(items),
            description=data.get("company", ""),
        )
