#!/usr/bin/env python3
"""
Sorabbyngo Cyberwall — Main Daemon
Entry point. Starts all engines and wires them together.

Usage:
    sudo python3 cyberwall_daemon.py
    sudo python3 cyberwall_daemon.py --config configs/cyberwall.yaml
    sudo python3 cyberwall_daemon.py --monitor-only
"""
import asyncio
import argparse
import logging
import signal
import sys
import os

from cyberwall.core.event_bus import EventBus, ThreatEvent, ThreatLevel
from cyberwall.core.threat_scorer import score_event
from cyberwall.core.policy_engine import PolicyEngine
from cyberwall.firewall.engine import FirewallEngine
from cyberwall.malware.scanner import MalwareScanner
from cyberwall.malware.syscall_watcher import SyscallWatcher
from cyberwall.sentinel_bridge.bridge import SentinelBridge
from cyberwall.ai.analyzer import AIAnalyzer

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s — %(message)s",
    handlers=[
        logging.StreamHandler(sys.stdout),
        logging.FileHandler("/var/log/sorabbyngo/cyberwall.log")
            if os.path.exists("/var/log/sorabbyngo") else logging.StreamHandler(),
    ]
)
logger = logging.getLogger("cyberwall")

BANNER = """
╔══════════════════════════════════════════════════════════╗
║       Sorabbyngo Cyberwall — AI Defence Layer            ║
║       Rhythm of Digital Life                             ║
╚══════════════════════════════════════════════════════════╝
"""


async def main(config_path: str = None, monitor_only: bool = False):
    print(BANNER)

    # Core
    bus    = EventBus()
    policy = PolicyEngine(config_path)

    # Wire scoring into the bus — every event gets scored before dispatch
    original_publish = bus.publish
    async def scored_publish(event: ThreatEvent):
        score_event(event)
        await original_publish(event)
    bus.publish = scored_publish

    # Components
    sentinel_bridge = SentinelBridge(bus, policy)
    ai_analyzer     = AIAnalyzer(bus, policy)
    malware_scanner = MalwareScanner(bus, policy)
    syscall_watcher = SyscallWatcher(bus)

    tasks = [
        asyncio.create_task(bus.run(),              name="event_bus"),
        asyncio.create_task(sentinel_bridge.start(), name="sentinel_bridge"),
        asyncio.create_task(ai_analyzer.start(),    name="ai_analyzer"),
        asyncio.create_task(malware_scanner.start(), name="malware_scanner"),
        asyncio.create_task(syscall_watcher.start(), name="syscall_watcher"),
    ]

    if not monitor_only:
        firewall = FirewallEngine(bus, policy)
        tasks.append(asyncio.create_task(firewall.start(), name="firewall"))
        logger.info("Firewall engine active")
    else:
        logger.warning("Monitor-only mode — no firewall rules applied")

    logger.info("Cyberwall online. All systems active.")

    # Graceful shutdown
    loop = asyncio.get_event_loop()
    for sig in (signal.SIGINT, signal.SIGTERM):
        loop.add_signal_handler(sig, lambda: [t.cancel() for t in tasks])

    try:
        await asyncio.gather(*tasks)
    except asyncio.CancelledError:
        logger.info("Cyberwall shutting down gracefully...")
    finally:
        await sentinel_bridge.stop()
        logger.info("Cyberwall stopped.")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Sorabbyngo Cyberwall Daemon")
    parser.add_argument("--config",       default=None, help="Path to config YAML")
    parser.add_argument("--monitor-only", action="store_true", help="No firewall rules, monitor only")
    args = parser.parse_args()

    asyncio.run(main(config_path=args.config, monitor_only=args.monitor_only))

# ── eBPF integration patch ────────────────────────────────────────────────────
# Import and wire EBPFManager into the firewall engine at startup.
# Add this to the main() function after FirewallEngine is created.
#
# from cyberwall.firewall.ebpf import EBPFManager
# ebpf = EBPFManager(bus, policy)
# ebpf.setup()
# tasks.append(asyncio.create_task(ebpf.start(), name="ebpf"))
#
# This is intentionally a comment block — full integration
# happens in the next daemon refactor (see ADR-002).
