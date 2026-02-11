from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Union

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
    website: str
    description: str

    @classmethod
    def from_dict(cls, data: dict) -> Victim:
        return cls(
            name=data.get("victim", "Unknown"),
            group=data.get("group", "Unknown"),
            discovered=data.get("discovered", "Unknown"),
            country=data.get("country", "Unknown"),
            website=data.get("website", ""),
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
