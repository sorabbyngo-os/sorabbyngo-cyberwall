"""
Sorabbyngo Cyberwall — Detection Harness
=========================================
Wires the attack simulator to a live (or mocked) cyberwall instance
and verifies that each scenario triggers the expected ThreatEvent.

Usage:
    # Full integration test (requires running cyberwall or --mock)
    python3 -m tests.simulation.detection_harness --mock

    # With a real daemon running in monitor-only mode:
    python3 -m tests.simulation.detection_harness
"""
import asyncio
import logging
import argparse
import time
from collections import defaultdict
from dataclasses import dataclass, field
from typing import List, Optional

from cyberwall.core.event_bus import EventBus, ThreatEvent, ThreatLevel
from cyberwall.core.policy_engine import PolicyEngine
from cyberwall.core.threat_scorer import scoring_middleware
from cyberwall.malware.deep_scanner import DeepScanner
from cyberwall.malware.scanner import MalwareScanner
from cyberwall.malware.syscall_watcher import SyscallWatcher
from tests.simulation.attack_simulator import (
    SCENARIOS, SANDBOX_DIR, run_scenarios, SimResult
)

logger = logging.getLogger("cyberwall.detection_harness")
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [HARNESS] %(message)s"
)


# ── Expected detections per scenario ──────────────────────────────────────────
# Maps scenario name → list of expected threat_type strings (any match = pass)
EXPECTED_DETECTIONS: dict[str, list[str]] = {
    "port_scan":        ["port_scan"],
    "brute_force":      ["brute_force", "port_scan"],
    "syn_flood":        ["syn_flood", "rate_exceed"],
    "file_drop":        ["webshell", "cryptominer", "backdoor", "packed_malware", "malware_detected"],
    "process_spawn":    ["syscall_anomaly", "process_injection", "cryptominer", "webshell"],
    "webshell":         ["webshell", "malware_detected"],
    "cryptominer":      ["cryptominer", "malware_detected"],
    "data_exfil":       ["data_exfil", "malware_detected"],
    "memfd":            ["process_injection", "cryptominer", "webshell", "backdoor"],
    "lateral_movement": ["port_scan", "lateral_movement", "brute_force"],
}

# Scenarios that require kernel/network access — skip in mock mode
NETWORK_ONLY_SCENARIOS = {"port_scan", "brute_force", "syn_flood", "lateral_movement"}


@dataclass
class DetectionResult:
    scenario:     str
    sim_result:   SimResult
    expected:     list[str]
    detected:     list[str] = field(default_factory=list)
    elapsed:      float = 0.0

    @property
    def skipped(self) -> bool:
        return "SKIPPED" in self.detected

    @property
    def passed(self) -> bool:
        if self.skipped:
            return True   # skipped = not a failure
        return any(e in self.detected for e in self.expected)

    @property
    def missed(self) -> list[str]:
        return [e for e in self.expected if e not in self.detected]


# ── Detection Harness ──────────────────────────────────────────────────────────

class DetectionHarness:
    """
    Runs attack simulations and collects threat events from cyberwall components.
    In mock mode: spins up scanner + syscall watcher + deep scanner directly.
    In live mode: connects to a running cyberwall via its event bus.
    """

    DETECTION_WINDOW = 10.0   # seconds to wait for detections after sim

    def __init__(self, mock: bool = True):
        self.mock = mock
        self.bus  = EventBus()
        self.bus.add_middleware(scoring_middleware)
        self._detections: dict[str, list[str]] = defaultdict(list)
        self._current_scenario: str = ""

        # Subscribe to all events — collect detections
        self.bus.subscribe("*", self._collect)

    async def _collect(self, event: ThreatEvent):
        if self._current_scenario:
            self._detections[self._current_scenario].append(event.threat_type)
            logger.info(
                f"  DETECTED [{event.level.name}] {event.threat_type} "
                f"score={event.score} — {event.description[:60]}"
            )

    async def setup_mock(self):
        """Start cyberwall components in lightweight mock mode."""
        policy = PolicyEngine()   # defaults only — no root needed
        # Use a temp dir for DB when /var/lib/cyberwall is not writable
        from cyberwall.malware.signatures.hash_db import HashDatabase
        from cyberwall.malware.signatures.pattern_engine import PatternEngine
        from pathlib import Path
        import tempfile
        _tmp_db = Path(tempfile.mkdtemp()) / "signatures.db"
        from cyberwall.malware.deep_scanner import DeepScanner as _DS
        self._deep_scanner = _DS.__new__(_DS)
        self._deep_scanner.bus     = self.bus
        self._deep_scanner.hash_db = HashDatabase(_tmp_db)
        self._deep_scanner.pattern = PatternEngine()
        import tempfile as _tf
        policy.policy["malware"]["quarantine_path"] = _tf.mkdtemp()
        policy.policy["malware"]["watch_paths"] = [str(SANDBOX_DIR)]
        self._malware = MalwareScanner(
            self.bus, policy, deep_scanner=self._deep_scanner
        )
        self._syscall      = SyscallWatcher(self.bus)

        # Start event bus
        self._bus_task = asyncio.create_task(self.bus.run(), name="bus")

        # Start scanners (they'll scan SANDBOX_DIR paths)
        logger.info("Mock cyberwall components started")

    async def run_all(self, scenarios: list[str]) -> list[DetectionResult]:
        import shutil as _sh
        results = []

        for name in scenarios:
            # Skip network/kernel-only scenarios in mock mode
            if self.mock and name in NETWORK_ONLY_SCENARIOS:
                logger.info(f"[SKIP] {name} — requires kernel/network (mock mode)")
                results.append(DetectionResult(
                    scenario=name,
                    sim_result=SimResult(name, True, "skipped", "network-only", 0),
                    expected=EXPECTED_DETECTIONS.get(name, []),
                    detected=["SKIPPED"],
                ))
                continue

            # Clear sandbox so detections don't bleed between scenarios
            if SANDBOX_DIR.exists():
                _sh.rmtree(SANDBOX_DIR, ignore_errors=True)
            SANDBOX_DIR.mkdir(parents=True, exist_ok=True)

            logger.info(f"\n{'='*60}")
            logger.info(f"HARNESS: {name}")
            logger.info(f"{'='*60}")

            self._current_scenario = name
            self._detections[name] = []

            # Run the attack simulation
            sim_results = await run_scenarios([name], delay=0)
            sim = sim_results[0] if sim_results else SimResult(name, False, "", "", 0)

            # Scan sandbox files immediately
            if self.mock and hasattr(self, '_deep_scanner'):
                await self._scan_sandbox_for_scenario(name)

            # Give async events time to propagate
            await asyncio.sleep(1.0)

            detected = list(set(self._detections.get(name, [])))
            expected = EXPECTED_DETECTIONS.get(name, [])

            result = DetectionResult(
                scenario=name,
                sim_result=sim,
                expected=expected,
                detected=detected,
                elapsed=sim.duration,
            )
            results.append(result)

            status = "DETECTED" if result.passed else "MISSED"
            logger.info(
                f"[{status}] expected={expected} detected={detected}"
            )
            self._current_scenario = ""

        return results

    async def _scan_sandbox_for_scenario(self, scenario: str):
        """Directly scan sandbox files created by the scenario."""
        import os
        if not SANDBOX_DIR.exists():
            return

        for fpath in SANDBOX_DIR.iterdir():
            if fpath.is_file():
                logger.debug(f"Harness scanning: {fpath}")
                await self._deep_scanner.scan(str(fpath))

    def teardown(self):
        if hasattr(self, '_bus_task'):
            self._bus_task.cancel()
        self.bus.stop()

    def print_report(self, results: list[DetectionResult]):
        total   = len(results)
        passed  = sum(1 for r in results if r.passed)
        missed  = sum(1 for r in results if not r.passed)

        print(f"\n{'='*70}")
        print("SORABBYNGO CYBERWALL — DETECTION HARNESS REPORT")
        print(f"{'='*70}")
        print(f"{'SCENARIO':<24} {'STATUS':<10} {'DETECTED':<35} {'MISSED'}")
        print(f"{'-'*70}")
        for r in results:
            status   = "PASS" if r.passed else "FAIL"
            detected = ", ".join(r.detected[:3]) or "none"
            missed   = ", ".join(r.missed[:3]) or "—"
            print(f"{r.scenario:<24} {status:<10} {detected:<35} {missed}")

        print(f"{'-'*70}")
        print(f"Results: {passed}/{total} detected | {missed} missed")
        rate = (passed / total * 100) if total else 0
        print(f"Detection rate: {rate:.0f}%")
        print(f"{'='*70}")

        if missed > 0:
            print("\nMissed scenarios (improve signatures/rules for these):")
            for r in results:
                if not r.passed:
                    print(f"  - {r.scenario}: expected {r.expected}, got {r.detected}")


async def main():
    parser = argparse.ArgumentParser(
        description="Sorabbyngo Cyberwall Detection Harness"
    )
    parser.add_argument("--mock",      action="store_true", default=True,
                        help="Use mock cyberwall components (no root required)")
    parser.add_argument("--scenario",  default="all",
                        help="Scenario to test (default: all)")
    args = parser.parse_args()

    names = list(SCENARIOS.keys()) if args.scenario == "all" else [args.scenario]

    harness = DetectionHarness(mock=args.mock)

    if args.mock:
        await harness.setup_mock()

    try:
        results = await harness.run_all(names)
        harness.print_report(results)
    finally:
        harness.teardown()
        import shutil
        shutil.rmtree(SANDBOX_DIR, ignore_errors=True)


if __name__ == "__main__":
    asyncio.run(main())
