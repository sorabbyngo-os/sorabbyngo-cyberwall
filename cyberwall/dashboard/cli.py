"""
Sorabbyngo Cyberwall — CLI Dashboard
Uses Rich for terminal UI; ANSI fallback if Rich not installed.
Run standalone: python -m cyberwall.dashboard.cli
"""
from __future__ import annotations

import asyncio
import logging
import time
from collections import deque
from typing import TYPE_CHECKING, Optional

log = logging.getLogger("cyberwall.dashboard.cli")

if TYPE_CHECKING:
    from cyberwall.core.event_bus import EventBus, ThreatEvent
    from cyberwall.siem.engine import SIEMEngine

_ANSI = {
    "CRITICAL": "\033[91m", "HIGH": "\033[31m", "MEDIUM": "\033[33m",
    "LOW": "\033[32m",      "INFO": "\033[90m",  "RESET": "\033[0m",
    "BOLD": "\033[1m",      "CYAN": "\033[36m",
}
LEVEL_COLORS = {
    "CRITICAL": "bold red", "HIGH": "red",
    "MEDIUM": "yellow",     "LOW": "green", "INFO": "dim",
}


def _rich_available() -> bool:
    try:
        import rich  # noqa
        return True
    except ImportError:
        return False


class CLIDashboard:
    REFRESH_HZ = 4

    def __init__(self, bus, siem=None, max_events: int = 100):
        self._bus   = bus
        self._siem  = siem
        self._events: deque = deque(maxlen=max_events)
        self._running = False
        self._rich  = _rich_available()
        self._stats = {
            "total": 0, "critical": 0, "high": 0,
            "blocked": 0, "start": time.time(),
        }
        bus.subscribe("*", self._on_event)

    async def _on_event(self, event) -> None:
        self._events.appendleft(event)
        self._stats["total"] += 1
        lvl = event.level.name
        if lvl == "CRITICAL":  self._stats["critical"] += 1
        elif lvl == "HIGH":    self._stats["high"]     += 1
        if event.blocked:      self._stats["blocked"]  += 1

    async def start(self) -> None:
        self._running = True
        if self._rich:
            await self._start_rich()
        else:
            await self._start_ansi()

    async def _start_rich(self) -> None:
        from rich.console import Console
        from rich.live import Live
        from rich.table import Table
        from rich.panel import Panel
        from rich.layout import Layout
        from rich.text import Text
        from rich import box

        console = Console()

        def _header():
            uptime = int(time.time() - self._stats["start"])
            h, m, s = uptime // 3600, (uptime % 3600) // 60, uptime % 60
            return Panel(
                Text(
                    f"  SORABBYNGO CYBERWALL  |  uptime {h:02d}:{m:02d}:{s:02d}  |  "
                    f"[bold red]{self._stats['critical']}[/] CRIT  "
                    f"[red]{self._stats['high']}[/] HIGH  "
                    f"[green]{self._stats['total']}[/] total",
                    justify="center",
                ),
                style="bold cyan",
            )

        def _stats_panel():
            t = Table(box=box.SIMPLE_HEAVY, show_header=False, padding=(0,2), expand=True)
            t.add_column("label", style="dim", width=20)
            t.add_column("value", style="bold white")
            t.add_column("label", style="dim", width=20)
            t.add_column("value", style="bold white")
            siem = self._siem.stats() if self._siem else {}
            t.add_row("Events ingested", str(self._stats["total"]),
                      "Open incidents",  str(siem.get("open_incidents","—")))
            t.add_row("IPs blocked",     str(self._stats["blocked"]),
                      "DPA unnotified",  str(siem.get("dpa_unnotified","—")))
            t.add_row("Quantum logging",
                      "[green]ON[/]" if siem.get("quantum_logging") else "[red]OFF[/]",
                      "Tracked actors",  str(siem.get("tracked_actors","—")))
            return Panel(t, title="[bold]Stats", border_style="blue")

        def _events_panel():
            t = Table(box=box.SIMPLE, expand=True, show_header=True,
                      header_style="bold dim")
            t.add_column("Level",  width=10)
            t.add_column("Type",   width=22)
            t.add_column("Source", width=18)
            t.add_column("Description", ratio=1)
            t.add_column("Time",   width=9)
            for ev in list(self._events)[:30]:
                lvl   = ev.level.name
                color = LEVEL_COLORS.get(lvl, "white")
                ts    = time.strftime("%H:%M:%S", time.localtime(ev.timestamp))
                blk   = " [BLOCK]" if ev.blocked else ""
                t.add_row(
                    f"[{color}]{lvl}[/]", ev.threat_type[:22],
                    (ev.source or "")[:18],
                    f"{ev.description[:60]}{blk}", ts,
                )
            return Panel(t, title="[bold]Live Events", border_style="cyan")

        def _siem_panel():
            t = Table(box=box.SIMPLE, expand=True, show_header=True,
                      header_style="bold dim")
            t.add_column("Sev", width=8)
            t.add_column("Rule", ratio=1)
            t.add_column("IPs", width=6)
            if self._siem:
                for inc in self._siem.get_incidents()[:15]:
                    c = LEVEL_COLORS.get(inc.severity, "white")
                    t.add_row(f"[{c}]{inc.severity[:4]}[/]",
                              inc.rule_name[:24], str(len(inc.source_ips)))
            return Panel(t, title="[bold]Incidents", border_style="red")

        layout = Layout()
        layout.split_column(
            Layout(name="header", size=3),
            Layout(name="stats",  size=5),
            Layout(name="body"),
        )
        layout["body"].split_row(
            Layout(name="events", ratio=2),
            Layout(name="siem",   ratio=1),
        )
        with Live(layout, console=console, refresh_per_second=self.REFRESH_HZ, screen=True):
            while self._running:
                layout["header"].update(_header())
                layout["stats"].update(_stats_panel())
                layout["body"]["events"].update(_events_panel())
                layout["body"]["siem"].update(_siem_panel())
                await asyncio.sleep(1 / self.REFRESH_HZ)

    async def _start_ansi(self) -> None:
        import sys
        while self._running:
            lines = [
                f"{_ANSI['BOLD']}{_ANSI['CYAN']}=== SORABBYNGO CYBERWALL ==={_ANSI['RESET']}",
                f"Events:{self._stats['total']}  "
                f"{_ANSI['CRITICAL']}CRIT:{self._stats['critical']}{_ANSI['RESET']}  "
                f"Blocked:{self._stats['blocked']}",
                "",
            ]
            for ev in list(self._events)[:20]:
                lvl = ev.level.name
                c   = _ANSI.get(lvl, "")
                ts  = time.strftime("%H:%M:%S", time.localtime(ev.timestamp))
                blk = " [BLOCKED]" if ev.blocked else ""
                lines.append(
                    f"{c}[{lvl:8}]{_ANSI['RESET']} {ts} "
                    f"{ev.threat_type:<24} {ev.description[:60]}{blk}"
                )
            sys.stdout.write("\033[2J\033[H" + "\n".join(lines) + "\n")
            sys.stdout.flush()
            await asyncio.sleep(1 / self.REFRESH_HZ)

    def stop(self) -> None:
        self._running = False


async def _demo():
    import random
    from cyberwall.core.event_bus import EventBus, ThreatEvent, ThreatLevel
    bus  = EventBus()
    dash = CLIDashboard(bus)
    TYPES  = ["malware_detected","port_scan","file_tamper","data_exfil",
               "auth_failure","rootkit","tor_c2","syscall_anomaly"]
    async def emit():
        await bus.start()
        while True:
            await bus.publish(ThreatEvent(
                source=f"node-{random.randint(1,5)}",
                threat_type=random.choice(TYPES),
                description="Demo threat event",
                level=random.choice(list(ThreatLevel)),
                score=round(random.uniform(1,10),1),
                blocked=random.random() > 0.7,
            ))
            await asyncio.sleep(random.uniform(0.2, 1.5))
    asyncio.create_task(emit())
    await dash.start()

if __name__ == "__main__":
    asyncio.run(_demo())
