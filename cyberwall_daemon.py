#!/usr/bin/env python3
"""
Sorabbyngo Cyberwall — Main Daemon  (patched v2)

Changes over v1:
  - Scoring via EventBus middleware (not monkey-patch)
  - DeepScanner properly injected into MalwareScanner
  - ResponseEngine uses TTL-aware block logic from FirewallEngine
  - _acted set replaced by FirewallEngine._is_blocked() (TTL-expiring)
  - Tracker eviction task added
  - All tasks named for easier debugging

Usage:
    sudo python3 cyberwall_daemon.py
    sudo python3 cyberwall_daemon.py --config configs/cyberwall.yaml
    sudo python3 cyberwall_daemon.py --monitor-only
    python3 cyberwall_daemon.py --monitor-only --no-root-checks
"""
import asyncio
import argparse
import logging
import os
import signal
import sys
from pathlib import Path

# ── Logging ────────────────────────────────────────────────────────────────────
LOG_DIR = Path("/var/log/sorabbyngo")
try:
    LOG_DIR.mkdir(parents=True, exist_ok=True)
    log_file = logging.FileHandler(LOG_DIR / "cyberwall.log")
except PermissionError:
    log_file = logging.FileHandler("/tmp/cyberwall.log")

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s — %(message)s",
    handlers=[logging.StreamHandler(sys.stdout), log_file],
)
logger = logging.getLogger("cyberwall")

# ── Imports ────────────────────────────────────────────────────────────────────
from cyberwall.core.event_bus import EventBus, ThreatEvent, ThreatLevel
from cyberwall.core.threat_scorer import scoring_middleware, get_tracker
from cyberwall.core.policy_engine import PolicyEngine
from cyberwall.firewall.engine import FirewallEngine
from cyberwall.firewall.ebpf import EBPFManager
from cyberwall.malware.scanner import MalwareScanner
from cyberwall.malware.syscall_watcher import SyscallWatcher
from cyberwall.malware.deep_scanner import DeepScanner
from cyberwall.sentinel_bridge.bridge import SentinelBridge
from cyberwall.ai.analyzer import AIAnalyzer
from cyberwall.dashboard.server import DashboardServer

BANNER = """
╔══════════════════════════════════════════════════════════╗
║       Sorabbyngo Cyberwall — AI Defence Layer  v2        ║
║       Firewall · Malware · eBPF · Sentinel · AI          ║
║       Rhythm of Digital Life                             ║
╚══════════════════════════════════════════════════════════╝
"""


# ── Response Engine ────────────────────────────────────────────────────────────

class ResponseEngine:
    """
    Automated response to threat events.
    Delegates IP block state to FirewallEngine (TTL-aware).
    """

    def __init__(
        self,
        bus:      EventBus,
        policy:   PolicyEngine,
        firewall: FirewallEngine,
        ebpf:     EBPFManager,
        malware:  MalwareScanner,
    ):
        self.policy   = policy
        self.firewall = firewall
        self.ebpf     = ebpf
        self.malware  = malware
        bus.subscribe("*", self.on_event)

    async def on_event(self, event: ThreatEvent):
        # ── Auto-block ─────────────────────────────────────────────────────────
        if self.policy.should_block(event):
            src_ip = event.data.get("src_ip")
            if src_ip:
                blocked = await self.firewall.block_ip(
                    src_ip,
                    reason=event.threat_type,
                    level=event.level,
                )
                if blocked:
                    self.ebpf.block_ip(src_ip)
                    event.blocked = True

        # ── Auto-quarantine ────────────────────────────────────────────────────
        if self.policy.should_quarantine(event):
            path = event.data.get("path")
            if path:
                ok = await self.malware.quarantine(path)
                if ok:
                    event.quarantined = True


# ── Status Reporter ────────────────────────────────────────────────────────────

class StatusReporter:
    def __init__(
        self,
        bus:          EventBus,
        ebpf:         EBPFManager,
        deep_scanner: DeepScanner,
        firewall:     FirewallEngine,
        interval:     int = 60,
    ):
        self.bus          = bus
        self.ebpf         = ebpf
        self.deep_scanner = deep_scanner
        self.firewall     = firewall
        self.interval     = interval
        self._running     = False
        self._events_seen = 0
        bus.subscribe("*", self._count)

    async def _count(self, event: ThreatEvent):
        self._events_seen += 1

    async def start(self):
        self._running = True
        while self._running:
            await asyncio.sleep(self.interval)
            self._report()

    def _report(self):
        ebpf_stats  = self.ebpf.stats()
        scan_stats  = self.deep_scanner.stats()
        bus_stats   = {}
        logger.info(
            f"STATUS | events={self._events_seen} | "
            f"blocked_ips={self.firewall.blocked_count()} | "
            f"connections={self.firewall.connection_count()} | "
            f"ebpf={self.ebpf.is_active()} | "
            f"dropped={ebpf_stats.get('dropped', 'n/a')} | "
            f"signatures={scan_stats.get('hash_signatures', 0)} | "
            f"yara={scan_stats.get('yara_active', False)} | "
            f"tracker_size={get_tracker().size()}"
        )

    def stop(self):
        self._running = False


# ── Tracker Eviction Task ──────────────────────────────────────────────────────

async def tracker_eviction_task():
    """Periodically evict stale repeat-offender entries."""
    tracker = get_tracker()
    while True:
        await asyncio.sleep(120)
        tracker.evict_expired()


# ── Main ───────────────────────────────────────────────────────────────────────

async def main(
    config_path:    str  = None,
    monitor_only:   bool = False,
    no_root_checks: bool = False,
):
    print(BANNER)

    if not monitor_only and os.geteuid() != 0 and not no_root_checks:
        logger.error("Cyberwall firewall requires root. Use --monitor-only or sudo.")
        sys.exit(1)

    # ── Core ──────────────────────────────────────────────────────────────────
    bus    = EventBus()
    policy = PolicyEngine(config_path)

    # Scoring via middleware — clean, no monkey-patch
    bus.add_middleware(scoring_middleware)

    # ── Components ────────────────────────────────────────────────────────────
    nats_url     = policy.get("nats", "url", default="nats://localhost:4222")
    firewall     = FirewallEngine(bus, policy)
    ebpf         = EBPFManager(bus, policy)
    deep_scanner = DeepScanner(bus)

    # DeepScanner injected into MalwareScanner — no stub comment needed
    malware_scanner  = MalwareScanner(bus, policy, deep_scanner=deep_scanner)
    syscall_watcher  = SyscallWatcher(bus)
    sentinel_bridge  = SentinelBridge(bus, policy, nats_url=nats_url)
    ai_analyzer      = AIAnalyzer(bus, policy)
    response_engine  = ResponseEngine(bus, policy, firewall, ebpf, malware_scanner)
    status_reporter  = StatusReporter(bus, ebpf, deep_scanner, firewall)

    # ── eBPF setup ────────────────────────────────────────────────────────────
    if not monitor_only:
        ebpf_active = ebpf.setup()
        if ebpf_active:
            logger.info("eBPF XDP active — kernel-level packet filtering enabled")
        else:
            logger.info("eBPF unavailable — nftables firewall active")
    else:
        logger.warning("Monitor-only mode — no firewall rules applied")

    # ── Wire file_tamper → deep scanner ──────────────────────────────────────
    async def _on_file_tamper(event: ThreatEvent):
        if event.threat_type == "file_tamper":
            path = event.data.get("path", "")
            if path:
                await deep_scanner.scan(path)

    bus.subscribe("file_tamper", _on_file_tamper)

    # ── Tasks ─────────────────────────────────────────────────────────────────
    # Dashboard
    if not args.no_dashboard:
        dashboard = DashboardServer(bus, port=args.dashboard_port)
        logger.info(f"Dashboard: http://localhost:{args.dashboard_port}")
    else:
        dashboard = None

    tasks = [
        asyncio.create_task(bus.run(),               name="event_bus"),
        asyncio.create_task(sentinel_bridge.start(), name="sentinel_bridge"),
        asyncio.create_task(ai_analyzer.start(),     name="ai_analyzer"),
        asyncio.create_task(malware_scanner.start(), name="malware_scanner"),
        asyncio.create_task(syscall_watcher.start(), name="syscall_watcher"),
        asyncio.create_task(status_reporter.start(), name="status_reporter"),
        asyncio.create_task(tracker_eviction_task(), name="tracker_eviction"),
    ]
    if dashboard:
        tasks.append(asyncio.create_task(dashboard.start(), name="dashboard"))

    if not monitor_only:
        tasks.append(asyncio.create_task(firewall.start(), name="firewall"))
        if ebpf.is_active():
            tasks.append(asyncio.create_task(ebpf.start(), name="ebpf"))

    # ── Graceful shutdown ─────────────────────────────────────────────────────
    loop = asyncio.get_event_loop()

    def _shutdown():
        logger.info("Shutdown signal received")
        ebpf.stop()
        status_reporter.stop()
        async def _graceful_stop():
            await sentinel_bridge.stop()
            for t in tasks:
                t.cancel()
        asyncio.ensure_future(_graceful_stop())

    for sig in (signal.SIGINT, signal.SIGTERM):
        loop.add_signal_handler(sig, _shutdown)

    logger.info(
        f"Cyberwall online | monitor_only={monitor_only} | "
        f"ebpf={ebpf.is_active()} | signatures={deep_scanner.hash_db.count()}"
    )

    try:
        await asyncio.gather(*tasks, return_exceptions=True)
    finally:
        ebpf.stop()
        logger.info("Cyberwall stopped.")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Sorabbyngo Cyberwall Daemon")
    parser.add_argument("--config",         default=None,        help="Config YAML path")
    parser.add_argument("--monitor-only",   action="store_true", help="No firewall rules")
    parser.add_argument("--no-root-checks", action="store_true", help="Skip root check (dev)")
    parser.add_argument("--dashboard",      action="store_true", default=True, help="Enable threat dashboard (default: on)")
    parser.add_argument("--dashboard-port", type=int, default=8888, help="Dashboard port (default: 8888)")
    parser.add_argument("--no-dashboard",   action="store_true", help="Disable dashboard")
    args = parser.parse_args()

    asyncio.run(main(
        config_path=args.config,
        monitor_only=args.monitor_only,
        no_root_checks=args.no_root_checks,
    ))
