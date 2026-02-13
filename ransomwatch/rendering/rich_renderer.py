from __future__ import annotations

from textwrap import shorten

from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text
from rich.tree import Tree

from ..config import MAX_DISPLAY_TECHNIQUES, MAX_DISPLAY_TTPS
from ..models import CSIRT, RansomwareGroup, RiskLevel, Sector, Stats, Victim


RISK_STYLES = {
    RiskLevel.CRITICAL: "bold red",
    RiskLevel.HIGH: "red",
    RiskLevel.MEDIUM: "yellow",
    RiskLevel.LOW: "green",
}


class RichRenderer:
    def __init__(self, console: Console):
        self.console = console

    def render_groups(self, groups: list[RansomwareGroup]) -> None:
        sorted_groups = sorted(groups, key=lambda g: g.victims, reverse=True)

        table = Table(
            title=f"RANSOMWARE GROUP ANALYSIS\nActive Groups: {len(groups)}",
            show_header=True,
            header_style="bold",
            title_style="bold",
            border_style="dim",
        )
        table.add_column("Rank", style="dim", width=6, justify="right")
        table.add_column("Risk", width=10)
        table.add_column("Group", style="bold")
        table.add_column("Alt Name", style="dim")
        table.add_column("Victims", justify="right")

        for i, group in enumerate(sorted_groups, 1):
            risk_text = Text(group.risk_level.value, style=RISK_STYLES[group.risk_level])
            altname = group.altname if group.altname and group.altname != group.name else ""
            table.add_row(str(i), risk_text, group.name, altname, f"{group.victims:,}")

        self.console.print()
        self.console.print(table)

        total_victims = sum(g.victims for g in groups)
        critical = sum(1 for g in groups if g.risk_level == RiskLevel.CRITICAL)
        high = sum(1 for g in groups if g.risk_level == RiskLevel.HIGH)
        medium = sum(1 for g in groups if g.risk_level == RiskLevel.MEDIUM)
        low = sum(1 for g in groups if g.risk_level == RiskLevel.LOW)

        summary = Text()
        summary.append(f"SUMMARY: {len(groups)} Groups | {total_victims:,} Total Victims\n", style="bold")
        summary.append("RISK BREAKDOWN: ", style="bold")
        summary.append(f"Critical: {critical}", style="bold red")
        summary.append(" | ")
        summary.append(f"High: {high}", style="red")
        summary.append(" | ")
        summary.append(f"Medium: {medium}", style="yellow")
        summary.append(" | ")
        summary.append(f"Low: {low}", style="green")

        self.console.print(summary)

    def render_victims(self, victims: list[Victim]) -> None:
        table = Table(
            title=f"RECENT RANSOMWARE INCIDENTS\nDisplaying: {len(victims)} most recent cases",
            show_header=True,
            header_style="bold",
            title_style="bold",
            border_style="dim",
        )
        table.add_column("#", style="dim", width=4, justify="right")
        table.add_column("Victim", style="bold", max_width=30)
        table.add_column("Threat Actor", style="red")
        table.add_column("Date", width=12)
        table.add_column("Location", width=8)
        table.add_column("Website", style="dim", max_width=25)
        table.add_column("Details", max_width=40)

        for i, victim in enumerate(victims, 1):
            date_str = self._format_date(victim.discovered)
            details = shorten(victim.description, width=40, placeholder="...")
            table.add_row(
                str(i),
                victim.name,
                victim.group,
                date_str,
                victim.country,
                victim.website or "-",
                details,
            )

        self.console.print()
        self.console.print(table)
        self.console.print(f"\n[bold]TOTAL INCIDENTS DISPLAYED: {len(victims)}[/bold]")

    def render_group_info(self, group: RansomwareGroup) -> None:
        risk_style = RISK_STYLES[group.risk_level]

        header_lines = []
        header_lines.append(f"[bold]PRIMARY IDENTIFIER:[/bold] {group.name}")
        if group.altname and group.altname != group.name:
            header_lines.append(f"[bold]ALTERNATIVE NAMES:[/bold]  {group.altname}")
        header_lines.append(f"[bold]THREAT CLASSIFICATION:[/bold] [{risk_style}]{group.risk_level.value}[/{risk_style}]")
        header_lines.append(f"[bold]CONFIRMED VICTIMS:[/bold]    {group.victims:,}")

        if group.first_seen or group.last_seen:
            header_lines.append("")
            header_lines.append("[bold]OPERATIONAL TIMELINE[/bold]")
            if group.first_seen:
                header_lines.append(f"  Initial Detection:     {group.first_seen}")
            if group.last_seen:
                header_lines.append(f"  Most Recent Activity:  {group.last_seen}")

        panel = Panel(
            "\n".join(header_lines),
            title="[bold]THREAT ACTOR INTELLIGENCE REPORT[/bold]",
            border_style=risk_style,
            padding=(1, 2),
        )
        self.console.print()
        self.console.print(panel)

        self._render_ttps(group)
        self._render_tools(group)
        self._render_description(group)

        self.console.print(f"\n[dim]REPORT GENERATED: Intelligence Database Query Complete[/dim]")

    def render_stats(self, stats: Stats) -> None:
        activity_styles = {"HIGH": "bold red", "MODERATE": "yellow", "LOW": "green"}
        activity_style = activity_styles.get(stats.activity_level, "")

        lines = []
        lines.append("[bold]OVERVIEW[/bold]")
        lines.append(f"  Active Threat Groups:  {stats.groups:,}")
        lines.append(f"  Confirmed Victims:     {stats.victims:,}")
        lines.append(f"  Press Reports:         {stats.press:,}")

        if stats.groups > 0 and stats.victims > 0:
            lines.append("")
            lines.append("[bold]STATISTICAL ANALYSIS[/bold]")
            lines.append(f"  Average Victims/Group: {stats.avg_victims_per_group:.1f}")
            lines.append(f"  Threat Activity Level: [{activity_style}]{stats.activity_level}[/{activity_style}]")

        if stats.last_update:
            lines.append("")
            lines.append("[bold]DATA CURRENCY[/bold]")
            lines.append(f"  Last Updated:          {stats.last_update}")

        panel = Panel(
            "\n".join(lines),
            title="[bold]RANSOMWARE THREAT LANDSCAPE STATISTICS[/bold]",
            border_style="blue",
            padding=(1, 2),
        )
        self.console.print()
        self.console.print(panel)
        self.console.print(f"\n[dim]ANALYSIS COMPLETE[/dim]")

    def render_validate(self, data: dict) -> None:
        valid = data.get("status") == "valid"
        status_style = "bold green" if valid else "bold red"
        status_text = "VALID" if valid else "INVALID"

        lines = []
        lines.append(f"[bold]API KEY STATUS:[/bold] [{status_style}]{status_text}[/{status_style}]")
        for key, value in data.items():
            if key != "status":
                lines.append(f"  {key}: {value}")

        panel = Panel(
            "\n".join(lines),
            title="[bold]API KEY VALIDATION[/bold]",
            border_style="green" if valid else "red",
            padding=(1, 2),
        )
        self.console.print()
        self.console.print(panel)

    def render_sectors(self, sectors: list[Sector]) -> None:
        sorted_sectors = sorted(sectors, key=lambda s: s.victim_count, reverse=True)

        table = Table(
            title=f"INDUSTRY SECTORS\nTracked Sectors: {len(sectors)}",
            show_header=True,
            header_style="bold",
            title_style="bold",
            border_style="dim",
        )
        table.add_column("#", style="dim", width=4, justify="right")
        table.add_column("Sector", style="bold")
        table.add_column("Victims", justify="right")

        for i, sector in enumerate(sorted_sectors, 1):
            table.add_row(str(i), sector.name, f"{sector.victim_count:,}")

        self.console.print()
        self.console.print(table)

    def render_csirt(self, csirts: list[CSIRT], country: str = "") -> None:
        title_suffix = f" - {country}" if country else ""
        table = Table(
            title=f"CSIRT / CERT TEAMS{title_suffix}\nTeams: {len(csirts)}",
            show_header=True,
            header_style="bold",
            title_style="bold",
            border_style="dim",
        )
        table.add_column("#", style="dim", width=4, justify="right")
        table.add_column("Team", style="bold")
        table.add_column("Full Name", max_width=40)
        table.add_column("Country", width=8)
        table.add_column("Email", max_width=30)
        table.add_column("Website", style="dim", max_width=30)

        for i, csirt in enumerate(csirts, 1):
            table.add_row(
                str(i),
                csirt.team,
                shorten(csirt.full_name, width=40, placeholder="...") if csirt.full_name else "-",
                csirt.country,
                csirt.email or "-",
                csirt.website or "-",
            )

        self.console.print()
        self.console.print(table)

    def _render_ttps(self, group: RansomwareGroup) -> None:
        if not group.ttps:
            return

        self.console.print(f"\n[bold]TACTICS, TECHNIQUES & PROCEDURES (TTPs)[/bold]")

        for i, ttp in enumerate(group.ttps[:MAX_DISPLAY_TTPS], 1):
            tree = Tree(f"[bold]{i}. {ttp.tactic_name}[/bold] [dim]({ttp.tactic_id})[/dim]")

            for tech in ttp.techniques[:MAX_DISPLAY_TECHNIQUES]:
                detail = ""
                if tech.details and isinstance(tech.details, str):
                    detail = f"\n[dim]{shorten(tech.details.strip(), width=80, placeholder='...')}[/dim]"
                tree.add(f"[bold]{tech.name}[/bold] [dim]({tech.id})[/dim]{detail}")

            if len(ttp.techniques) > MAX_DISPLAY_TECHNIQUES:
                tree.add(f"[dim]... and {len(ttp.techniques) - MAX_DISPLAY_TECHNIQUES} additional techniques[/dim]")

            self.console.print(tree)

        if len(group.ttps) > MAX_DISPLAY_TTPS:
            self.console.print(f"[dim]  ... and {len(group.ttps) - MAX_DISPLAY_TTPS} additional TTPs[/dim]")

    def _render_tools(self, group: RansomwareGroup) -> None:
        if not group.tools:
            return

        self.console.print(f"\n[bold]KNOWN TOOLS & MALWARE[/bold]")

        if isinstance(group.tools, dict):
            tree = Tree("[bold]Tools[/bold]")
            for category, items in group.tools.items():
                branch = tree.add(f"[bold]{category}[/bold]")
                if isinstance(items, list):
                    for tool in items:
                        if tool:
                            branch.add(str(tool))
                elif items:
                    branch.add(str(items))
            self.console.print(tree)
        elif isinstance(group.tools, list):
            valid_tools = [t for t in group.tools if t]
            for i, tool in enumerate(valid_tools[:MAX_DISPLAY_TTPS], 1):
                self.console.print(f"  {i}. {tool}")
            if len(valid_tools) > MAX_DISPLAY_TTPS:
                self.console.print(f"[dim]  ... and {len(valid_tools) - MAX_DISPLAY_TTPS} additional tools[/dim]")

    def _render_description(self, group: RansomwareGroup) -> None:
        if not group.description or not isinstance(group.description, str) or not group.description.strip():
            return
        self.console.print(f"\n[bold]THREAT ASSESSMENT[/bold]")
        self.console.print(f"  {group.description}")

    def _format_date(self, date_str: str) -> str:
        if date_str == "Unknown":
            return "Unknown"
        try:
            from datetime import datetime
            date_obj = datetime.fromisoformat(date_str.replace('Z', '+00:00'))
            return date_obj.strftime("%Y-%m-%d")
        except (ValueError, TypeError):
            return str(date_str)[:10] if date_str else "Unknown"
