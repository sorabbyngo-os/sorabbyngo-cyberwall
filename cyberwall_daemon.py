#!/usr/bin/env python3
"""
Sorabbyngo Cyberwall — Main Daemon
Full integration: firewall + eBPF + malware + deep scanner + sentinel bridge + AI

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

# ── Logging ───────────────────────────────────────────────────────────────────

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

# ── Imports ───────────────────────────────────────────────────────────────────

from cyberwall.core.event_bus import EventBus, ThreatEvent, ThreatLevel
from cyberwall.core.threat_scorer import score_event
from cyberwall.core.policy_engine import PolicyEngine
from cyberwall.firewall.engine import FirewallEngine
from cyberwall.firewall.ebpf import EBPFManager
from cyberwall.malware.scanner import MalwareScanner
from cyberwall.malware.syscall_watcher import SyscallWatcher
from cyberwall.malware.deep_scanner import DeepScanner
from cyberwall.sentinel_bridge.bridge import SentinelBridge
from cyberwall.ai.analyzer import AIAnalyzer

BANNER = """
╔══════════════════════════════════════════════════════════╗
║       Sorabbyngo Cyberwall — AI Defence Layer            ║
║       Firewall · Malware · eBPF · Sentinel · AI          ║
║       Rhythm of Digital Life                             ║
╚══════════════════════════════════════════════════════════╝
"""

# ── Response Engine ───────────────────────────────────────────────────────────

class ResponseEngine:
    """
    Listens to all threat events and takes automated action:
    - Block IPs via firewall + eBPF
    - Quarantine files via malware scanner
    - Log all decisions
    """
    def __init__(
        self,
        bus: EventBus,
        policy: PolicyEngine,
        firewall: FirewallEngine,
        ebpf: EBPFManager,
        malware: MalwareScanner,
    ):
        self.policy  = policy
        self.firewall = firewall
        self.ebpf    = ebpf
        self.malware = malware
        self._acted: set = set()   # deduplicate actions

        bus.subscribe("*", self.on_event)

    async def on_event(self, event: ThreatEvent):
        # ── Auto-block ────────────────────────────────────────────────────────
        if self.policy.should_block(event):
            src_ip = event.data.get("src_ip")
            if src_ip and src_ip not in self._acted:
                self._acted.add(src_ip)
                await self.firewall.block_ip(src_ip, reason=event.threat_type)
                self.ebpf.block_ip(src_ip)
                event.blocked = True
                logger.warning(f"AUTO-BLOCK {src_ip} [{event.threat_type}]")

        # ── Auto-quarantine ───────────────────────────────────────────────────
        if self.policy.should_quarantine(event):
            path = event.data.get("path")
            if path:
                quarantined = await self.malware.quarantine(path)
                if quarantined:
                    event.quarantined = True
                    logger.warning(f"AUTO-QUARANTINE {path} [{event.threat_type}]")


# ── Status Reporter ───────────────────────────────────────────────────────────

class StatusReporter:
    """Periodic stats dump to logger and NATS."""
    def __init__(
        self,
        bus: EventBus,
        ebpf: EBPFManager,
        deep_scanner: DeepScanner,
        interval: int = 60,
    ):
        self.bus          = bus
        self.ebpf         = ebpf
        self.deep_scanner = deep_scanner
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
        ebpf_stats   = self.ebpf.stats()
        scan_stats   = self.deep_scanner.stats()
        logger.info(
            f"STATUS | events={self._events_seen} | "
            f"ebpf_active={self.ebpf.is_active()} | "
            f"ebpf_dropped={ebpf_stats.get('dropped', 'n/a')} | "
            f"signatures={scan_stats.get('hash_signatures', 0)} | "
            f"yara={scan_stats.get('yara_active', False)}"
        )

    def stop(self):
        self._running = False


# ── Main ──────────────────────────────────────────────────────────────────────

async def main(
    config_path: str = None,
    monitor_only: bool = False,
    no_root_checks: bool = False,
):
    print(BANNER)

    if not monitor_only and os.geteuid() != 0 and not no_root_checks:
        logger.error("Cyberwall firewall requires root. Use --monitor-only or sudo.")
        sys.exit(1)

    # ── Core ──────────────────────────────────────────────────────────────────
    bus    = EventBus()
    policy = PolicyEngine(config_path)

    # Scoring middleware — every event scored before dispatch
    _orig_publish = bus.publish
    async def _scored_publish(event: ThreatEvent):
        score_event(event)
        await _orig_publish(event)
    bus.publish = _scored_publish

    # ── Components ────────────────────────────────────────────────────────────
    nats_url        = policy.get("nats", "url", default="nats://localhost:4222")
    firewall        = FirewallEngine(bus, policy)
    ebpf            = EBPFManager(bus, policy)
    malware_scanner = MalwareScanner(bus, policy)
    syscall_watcher = SyscallWatcher(bus)
    deep_scanner    = DeepScanner(bus)
    sentinel_bridge = SentinelBridge(bus, policy, nats_url=nats_url)
    ai_analyzer     = AIAnalyzer(bus, policy)
    response_engine = ResponseEngine(bus, policy, firewall, ebpf, malware_scanner)
    status_reporter = StatusReporter(bus, ebpf, deep_scanner)

    # ── eBPF setup ────────────────────────────────────────────────────────────
    if not monitor_only:
        ebpf_active = ebpf.setup()
        if ebpf_active:
            logger.info("eBPF XDP active — kernel-level packet filtering enabled")
        else:
            logger.info("eBPF unavailable — nftables firewall active")
    else:
        logger.warning("Monitor-only mode — no firewall rules applied")

    # ── Wire MalwareScanner → DeepScanner ────────────────────────────────────
    # Patch scanner to use deep scanner on file changes
    _orig_scan = malware_scanner._scan_files
    async def _deep_scan_files():
        await _orig_scan()
        # DeepScanner runs independently via its own event subscription
    malware_scanner._scan_files = _deep_scan_files

    # DeepScanner subscribes to file_tamper events for deep analysis
    async def _on_file_tamper(event: ThreatEvent):
        if event.threat_type == "file_tamper":
            path = event.data.get("path", "")
            if path:
                await deep_scanner.scan(path)
    bus.subscribe("file_tamper", _on_file_tamper)

    # ── Tasks ─────────────────────────────────────────────────────────────────
    tasks = [
        asyncio.create_task(bus.run(),               name="event_bus"),
        asyncio.create_task(sentinel_bridge.start(), name="sentinel_bridge"),
        asyncio.create_task(ai_analyzer.start(),     name="ai_analyzer"),
        asyncio.create_task(malware_scanner.start(), name="malware_scanner"),
        asyncio.create_task(syscall_watcher.start(), name="syscall_watcher"),
        asyncio.create_task(status_reporter.start(), name="status_reporter"),
    ]

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
        for t in tasks:
            t.cancel()

    for sig in (signal.SIGINT, signal.SIGTERM):
        loop.add_signal_handler(sig, _shutdown)

    logger.info(
        f"Cyberwall online | "
        f"monitor_only={monitor_only} | "
        f"ebpf={ebpf.is_active()} | "
        f"signatures={deep_scanner.hash_db.count()}"
    )

    try:
        await asyncio.gather(*tasks, return_exceptions=True)
    finally:
        await sentinel_bridge.stop()
        ebpf.stop()
        logger.info("Cyberwall stopped.")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Sorabbyngo Cyberwall Daemon")
    parser.add_argument("--config",          default=None,  help="Config YAML path")
    parser.add_argument("--monitor-only",    action="store_true", help="No firewall rules")
    parser.add_argument("--no-root-checks",  action="store_true", help="Skip root check (dev)")
    args = parser.parse_args()

    asyncio.run(main(
        config_path=args.config,
        monitor_only=args.monitor_only,
        no_root_checks=args.no_root_checks,
    ))
