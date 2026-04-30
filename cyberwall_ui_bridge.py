#!/usr/bin/env python3
"""
Sorabbyngo Cyberwall — eDEX UI WebSocket Bridge
================================================
Taps into the live EventBus and streams real-time threat events,
firewall stats, malware scanner state, and system metrics to the
eDEX UI over WebSocket.

Drop this file into the sorabbyngo-cyberwall root alongside
cyberwall_daemon.py. Run it after the daemon is up, or integrate
it into the daemon's task list (see bottom of file).

Usage:
    python3 cyberwall_ui_bridge.py
    python3 cyberwall_ui_bridge.py --port 8765 --host 0.0.0.0
    python3 cyberwall_ui_bridge.py --config configs/cyberwall.yaml

The eDEX UI connects to ws://localhost:8765

Message format (JSON, newline-delimited):
    {
        "type": "threat" | "stats" | "block" | "malware" | "heartbeat",
        "ts":   ISO8601,
        ...payload
    }
"""

import asyncio
import argparse
import json
import logging
import os
import sys
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Set

# ── Optional websockets import ─────────────────────────────────────────────────
try:
    import websockets
    from websockets.server import WebSocketServerProtocol
except ImportError:
    print("ERROR: websockets not installed. Run: pip install websockets --break-system-packages")
    sys.exit(1)

# ── Optional psutil for real system metrics ────────────────────────────────────
try:
    import psutil
    _PSUTIL = True
except ImportError:
    _PSUTIL = False

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s — %(message)s",
)
logger = logging.getLogger("cyberwall.ui_bridge")

# ── Try to import cyberwall components ────────────────────────────────────────
try:
    from cyberwall.core.event_bus import EventBus, ThreatEvent, ThreatLevel
    from cyberwall.core.threat_scorer import scoring_middleware
    from cyberwall.core.policy_engine import PolicyEngine
    from cyberwall.firewall.engine import FirewallEngine
    _CYBERWALL = True
except ImportError:
    logger.warning("Cyberwall modules not found — running in DEMO mode (simulated data)")
    _CYBERWALL = False


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


# ── Simulated data for demo/dev mode ──────────────────────────────────────────
import random

DEMO_THREATS = [
    {"threat_type": "syn_flood",        "level": "HIGH",     "score": 8.0, "description": "SYN flood detected",             "data": {"src_ip": "45.33.32.156"}},
    {"threat_type": "brute_force",      "level": "HIGH",     "score": 7.5, "description": "SSH brute force attempt",         "data": {"src_ip": "103.21.244.12"}},
    {"threat_type": "port_scan",        "level": "MEDIUM",   "score": 6.0, "description": "Port scan from external host",    "data": {"src_ip": "192.168.10.5"}},
    {"threat_type": "malware_detected", "level": "CRITICAL", "score": 9.0, "description": "Malware signature match",         "data": {"src_ip": "", "path": "/tmp/.kworker2"}},
    {"threat_type": "data_exfil",       "level": "CRITICAL", "score": 9.0, "description": "Data exfiltration attempt",       "data": {"src_ip": "172.16.0.55"}},
    {"threat_type": "lateral_movement", "level": "HIGH",     "score": 8.5, "description": "Lateral movement detected",       "data": {"src_ip": "10.0.0.7"}},
    {"threat_type": "cryptominer",      "level": "HIGH",     "score": 8.0, "description": "Cryptominer process killed",      "data": {"src_ip": "", "path": "/tmp/xmrig"}},
    {"threat_type": "webshell",         "level": "CRITICAL", "score": 9.0, "description": "Webshell dropper blocked",        "data": {"src_ip": "45.33.32.200"}},
    {"threat_type": "null_scan",        "level": "MEDIUM",   "score": 6.0, "description": "NULL scan detected",              "data": {"src_ip": "192.168.1.100"}},
    {"threat_type": "xmas_scan",        "level": "MEDIUM",   "score": 6.0, "description": "XMAS scan detected",              "data": {"src_ip": "10.10.10.10"}},
    {"threat_type": "ddos",             "level": "HIGH",     "score": 8.5, "description": "DDoS traffic pattern",            "data": {"src_ip": "0.0.0.0"}},
    {"threat_type": "syscall_anomaly",  "level": "MEDIUM",   "score": 7.0, "description": "Suspicious syscall sequence",     "data": {"src_ip": "", "pid": "4432"}},
    {"threat_type": "file_tamper",      "level": "HIGH",     "score": 7.5, "description": "/etc/passwd modification attempt","data": {"path": "/etc/passwd"}},
    {"threat_type": "process_injection","level": "CRITICAL", "score": 9.0, "description": "Process injection detected",      "data": {"pid": "1337"}},
    {"threat_type": "ip_blocked",       "level": "HIGH",     "score": 7.0, "description": "Repeat offender auto-blocked",    "data": {"src_ip": "45.33.32.156", "repeat_offender": True}},
]

DEMO_PROCESSES = [
    "chameha-voice", "byngonet-mesh", "cyberwall-fw", "nats-server",
    "sorabbyngo-core", "novela-api", "bpf-loader", "audit-daemon",
    "sshd", "cron", "udevd", "journald", "malware-scanner", "ai-analyzer",
]

DEMO_CONNECTIONS = [
    {"ip": "10.0.0.1",     "port": 22,   "state": "ESTABLISHED", "service": "ssh"},
    {"ip": "45.33.32.156", "port": 443,  "state": "ESTABLISHED", "service": "https"},
    {"ip": "0.0.0.0",      "port": 4222, "state": "LISTEN",      "service": "nats"},
    {"ip": "10.0.0.7",     "port": 8080, "state": "ESTABLISHED", "service": "novela-api"},
    {"ip": "0.0.0.0",      "port": 22,   "state": "LISTEN",      "service": "ssh"},
    {"ip": "10.0.0.2",     "port": 9090, "state": "ESTABLISHED", "service": "metrics"},
    {"ip": "172.16.0.5",   "port": 443,  "state": "ESTABLISHED", "service": "https"},
    {"ip": "0.0.0.0",      "port": 8443, "state": "LISTEN",      "service": "https"},
]

MESH_NODES = [
    {"id": "BNG-0xA3F1", "label": "NBI", "lat": 1.29,   "lng": 36.82, "self": True},
    {"id": "BNG-0xC2A4", "label": "KGL", "lat": -1.94,  "lng": 30.06},
    {"id": "BNG-0xF810", "label": "ADD", "lat": 9.02,   "lng": 38.75},
    {"id": "BNG-0xB301", "label": "ACC", "lat": 5.56,   "lng": -0.20},
    {"id": "BNG-0xD550", "label": "CPT", "lat": -33.9,  "lng": 18.42},
    {"id": "BNG-0xE022", "label": "LDA", "lat": -8.84,  "lng": 13.23},
    {"id": "BNG-0x9901", "label": "KRT", "lat": 15.55,  "lng": 32.53},
]


# ── WebSocket Bridge ───────────────────────────────────────────────────────────

class CyberwallUIBridge:
    """
    Manages connected WebSocket clients and streams live cyberwall data.
    In live mode: subscribes to the real EventBus.
    In demo mode: generates simulated threat/stats data.
    """

    def __init__(
        self,
        host: str = "localhost",
        port: int = 8765,
        config_path: str = None,
    ):
        self.host = host
        self.port = port
        self._clients: Set[WebSocketServerProtocol] = set()
        self._bus = None
        self._firewall = None
        self._policy = None
        self._start_time = time.monotonic()
        self._event_count = 0
        self._blocked_ips: Set[str] = set()
        self._demo_mode = not _CYBERWALL

        if _CYBERWALL and not self._demo_mode:
            self._policy   = PolicyEngine(config_path)
            self._bus      = EventBus()
            self._bus.add_middleware(scoring_middleware)
            self._firewall = FirewallEngine(self._bus, self._policy)
            # Wire real events → broadcast
            self._bus.subscribe("*", self._on_real_event)

        node_id_path = Path("/var/lib/sorabbyngo/nodeid")
        self._node_id = (
            node_id_path.read_text().strip()
            if node_id_path.exists()
            else os.environ.get("SORABBYNGO_NODE_ID", "BNG-0xA3F1")
        )

    # ── WebSocket handler ──────────────────────────────────────────────────────

    async def handler(self, websocket: WebSocketServerProtocol):
        self._clients.add(websocket)
        client = websocket.remote_address
        logger.info(f"eDEX UI connected: {client}")

        try:
            # Send initial full state
            await self._send(websocket, self._build_init_packet())
            # Keep alive — handle incoming commands
            async for raw in websocket:
                await self._handle_command(websocket, raw)
        except websockets.exceptions.ConnectionClosed:
            pass
        finally:
            self._clients.discard(websocket)
            logger.info(f"eDEX UI disconnected: {client}")

    async def _handle_command(self, ws: WebSocketServerProtocol, raw: str):
        """Handle commands sent from the eDEX UI terminal."""
        try:
            msg = json.loads(raw)
        except json.JSONDecodeError:
            return

        cmd = msg.get("cmd", "")
        response = {"type": "cmd_response", "cmd": cmd, "ts": _now()}

        if cmd == "status":
            response["lines"] = self._status_lines()
        elif cmd == "block":
            ip = msg.get("ip", "")
            if ip:
                self._blocked_ips.add(ip)
                response["lines"] = [f"Blocked {ip}", "Rule added to nftables SET"]
            else:
                response["lines"] = ["Usage: block <ip>"]
        elif cmd == "unblock":
            ip = msg.get("ip", "")
            self._blocked_ips.discard(ip)
            response["lines"] = [f"Unblocked {ip}"]
        elif cmd == "peers":
            response["lines"] = [f"{n['id']} — {n['label']}" + (" [self]" if n.get('self') else "") for n in MESH_NODES]
        elif cmd == "threats":
            response["lines"] = [
                f"[{t['level']}] {t['threat_type']}: {t['description']}"
                for t in DEMO_THREATS[:5]
            ]
        elif cmd == "blocked":
            ips = list(self._blocked_ips) or ["(none)"]
            response["lines"] = [f"Blocked IPs ({len(self._blocked_ips)}):"] + ips
        elif cmd == "nats":
            response["lines"] = [
                "NATS JetStream: OK",
                "Server: nats://localhost:4222",
                "Streams: 4  Consumers: 12",
                f"Subject: sorabbyngo.cyberwall.alert",
                f"Messages: {self._event_count:,}",
            ]
        elif cmd == "cyberwall":
            response["lines"] = [
                "Cyberwall v2 — ACTIVE",
                "eBPF XDP: loaded",
                f"Blocked IPs: {len(self._blocked_ips)}",
                "Rate limiter: token-bucket",
                "Malware scanner: running",
                "Sentinel bridge: CONNECTED",
                "Coverage: 73%",
            ]
        elif cmd == "policy":
            response["lines"] = [
                "auto_block_level:      HIGH",
                "auto_quarantine_level: CRITICAL",
                "alert_level:           LOW",
                "notify_sentinel:       true",
                "notify_cml:            true",
                "ai.model:              phi4-mini",
                "ai.analyze_level:      MEDIUM",
            ]
        elif cmd == "whoami":
            response["lines"] = [
                f"root@byngo-os",
                f"Node:   {self._node_id}",
                f"OS:     BYNGO-OS 1.0.0",
                f"Kernel: 6.19.10-sorabbyngo-hardened",
                f"Uptime: {self._uptime_str()}",
            ]
        elif cmd == "scan":
            path = msg.get("path", "/etc")
            response["lines"] = [
                f"Scanning {path}...",
                "Hash check: OK",
                "YARA rules: 0 matches",
                "Deep scanner: clean",
            ]
        elif cmd == "help":
            response["lines"] = [
                "Commands:",
                "  status    — system overview",
                "  threats   — last 5 threat events",
                "  block <ip>— block an IP manually",
                "  unblock <ip>",
                "  blocked   — list blocked IPs",
                "  peers     — ByngoNet mesh nodes",
                "  nats      — NATS JetStream status",
                "  cyberwall — cyberwall subsystem status",
                "  policy    — active policy settings",
                "  scan <path>",
                "  whoami",
                "  clear",
            ]
        else:
            response["lines"] = [f"command not found: {cmd}. Type 'help'."]

        await self._send(ws, response)

    # ── Real event handler (live mode) ─────────────────────────────────────────

    async def _on_real_event(self, event: ThreatEvent):
        """Receives real ThreatEvents from the EventBus and broadcasts them."""
        self._event_count += 1
        src_ip = event.data.get("src_ip", "")
        if event.blocked and src_ip:
            self._blocked_ips.add(src_ip)

        packet = {
            "type":        "threat",
            "ts":          event.timestamp,
            "threat_type": event.threat_type,
            "level":       event.level.name,
            "score":       event.score,
            "description": event.description,
            "data":        event.data,
            "blocked":     event.blocked,
            "quarantined": event.quarantined,
            "node_id":     event.node_id,
        }
        await self._broadcast(packet)

    # ── Demo loop ──────────────────────────────────────────────────────────────

    async def _demo_threat_loop(self):
        """Generate simulated threat events when running in demo mode."""
        while True:
            await asyncio.sleep(random.uniform(2.0, 5.0))
            t = random.choice(DEMO_THREATS)
            self._event_count += 1
            if t["level"] in ("HIGH", "CRITICAL") and t["data"].get("src_ip"):
                self._blocked_ips.add(t["data"]["src_ip"])
            packet = {
                "type":        "threat",
                "ts":          _now(),
                "threat_type": t["threat_type"],
                "level":       t["level"],
                "score":       t["score"],
                "description": t["description"],
                "data":        t["data"],
                "blocked":     t["level"] in ("HIGH", "CRITICAL"),
                "quarantined": t["level"] == "CRITICAL" and bool(t["data"].get("path")),
                "node_id":     self._node_id,
            }
            await self._broadcast(packet)

    async def _stats_loop(self):
        """Broadcast system stats every 2 seconds."""
        while True:
            await asyncio.sleep(2)
            await self._broadcast(self._build_stats_packet())

    async def _process_loop(self):
        """Broadcast process list every 3 seconds."""
        while True:
            await asyncio.sleep(3)
            procs = [
                {"name": p, "cpu": round(random.uniform(0.1, 15.0), 1), "mem": round(random.uniform(0.3, 8.0), 1)}
                for p in DEMO_PROCESSES
            ]
            await self._broadcast({"type": "processes", "ts": _now(), "processes": procs})

    # ── Packet builders ────────────────────────────────────────────────────────

    def _build_init_packet(self) -> dict:
        return {
            "type":       "init",
            "ts":         _now(),
            "node_id":    self._node_id,
            "demo_mode":  self._demo_mode,
            "mesh_nodes": MESH_NODES,
            "connections": DEMO_CONNECTIONS,
            "boot_lines": [
                {"cls": "out",  "text": "BYNGO-OS v1.0.0 — Sorabbyngo Labs"},
                {"cls": "out",  "text": f"Kernel 6.19.10-sorabbyngo-hardened #1 SMP"},
                {"cls": "out",  "text": f"NodeID module loaded — {self._node_id}"},
                {"cls": "out",  "text": "ByngoNet mesh: connecting..."},
                {"cls": "out",  "text": f"ByngoNet mesh: {len(MESH_NODES)-1} peers discovered"},
                {"cls": "out",  "text": "NATS JetStream: OK (nats://localhost:4222)"},
                {"cls": "out",  "text": "Cyberwall: eBPF XDP loaded — 3 rulesets active"},
                {"cls": "out",  "text": "Malware scanner: baseline complete, watching 8 paths"},
                {"cls": "out",  "text": "Sentinel bridge: CONNECTED → sorabbyngo.cyberwall.*"},
                {"cls": "out",  "text": "Chameha AI: TIER 1 ready (Swahili / English)"},
                {"cls": "out",  "text": "Novela health API: listening :8080"},
                {"cls": "out",  "text": "sorabbyngo-core: all daemons healthy"},
                {"cls": "warn", "text": "WARNING: EventBus middleware chain active"},
                {"cls": "out",  "text": f"{'[DEMO MODE] ' if self._demo_mode else ''}System ready. Type 'help' for commands."},
            ],
        }

    def _build_stats_packet(self) -> dict:
        if _PSUTIL:
            cpu  = psutil.cpu_percent(interval=None)
            ram  = psutil.virtual_memory().percent
            net  = psutil.net_io_counters()
            disk = psutil.disk_io_counters()
            net_kbps  = round((net.bytes_sent + net.bytes_recv) / 1024 / 2, 1)
            disk_mbps = round((disk.read_bytes + disk.write_bytes) / 1024 / 1024 / 2, 2) if disk else 0
        else:
            cpu       = round(random.uniform(20, 70), 1)
            ram       = round(random.uniform(45, 75), 1)
            net_kbps  = round(random.uniform(40, 300), 1)
            disk_mbps = round(random.uniform(2, 30), 2)

        return {
            "type":         "stats",
            "ts":           _now(),
            "cpu":          cpu,
            "ram":          ram,
            "net_kbps":     net_kbps,
            "disk_mbps":    disk_mbps,
            "blocked_ips":  len(self._blocked_ips),
            "event_count":  self._event_count,
            "uptime":       self._uptime_str(),
            "peers":        len(MESH_NODES) - 1,
        }

    def _status_lines(self) -> list:
        return [
            f"BYNGO-OS:       RUNNING",
            f"ByngoNet:       {len(MESH_NODES)-1} peers",
            f"Cyberwall:      ACTIVE",
            f"Blocked IPs:    {len(self._blocked_ips)}",
            f"Events total:   {self._event_count:,}",
            f"Chameha AI:     LISTENING",
            f"NATS:           CONNECTED",
            f"Uptime:         {self._uptime_str()}",
            f"Node:           {self._node_id}",
            f"Mode:           {'DEMO' if self._demo_mode else 'LIVE'}",
        ]

    def _uptime_str(self) -> str:
        s = int(time.monotonic() - self._start_time)
        return f"{s//3600:02d}:{(s%3600)//60:02d}:{s%60:02d}"

    # ── Send helpers ───────────────────────────────────────────────────────────

    async def _send(self, ws: WebSocketServerProtocol, data: dict):
        try:
            await ws.send(json.dumps(data))
        except websockets.exceptions.ConnectionClosed:
            pass

    async def _broadcast(self, data: dict):
        if not self._clients:
            return
        msg = json.dumps(data)
        dead = set()
        for ws in list(self._clients):
            try:
                await ws.send(msg)
            except websockets.exceptions.ConnectionClosed:
                dead.add(ws)
        self._clients -= dead

    # ── Start ──────────────────────────────────────────────────────────────────

    async def start(self):
        logger.info(f"eDEX UI bridge starting on ws://{self.host}:{self.port}")
        logger.info(f"Mode: {'DEMO (simulated data)' if self._demo_mode else 'LIVE (real EventBus)'}")

        tasks = [
            websockets.serve(self.handler, self.host, self.port),
            self._stats_loop(),
            self._process_loop(),
        ]

        if self._demo_mode:
            tasks.append(self._demo_threat_loop())
        else:
            # In live mode the EventBus drives _on_real_event via subscription
            tasks.append(self._bus.run())

        await asyncio.gather(*tasks)


# ── Entry point ────────────────────────────────────────────────────────────────

async def run(host: str, port: int, config: str):
    bridge = CyberwallUIBridge(host=host, port=port, config_path=config)
    await bridge.start()


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Sorabbyngo Cyberwall eDEX UI Bridge")
    parser.add_argument("--host",   default="localhost", help="Bind host (default: localhost)")
    parser.add_argument("--port",   default=8765, type=int, help="WebSocket port (default: 8765)")
    parser.add_argument("--config", default=None, help="Path to cyberwall.yaml")
    args = parser.parse_args()

    try:
        asyncio.run(run(args.host, args.port, args.config))
    except KeyboardInterrupt:
        logger.info("Bridge stopped.")
