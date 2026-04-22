"""
Sorabbyngo Cyberwall — Sentinel Bridge
Publishes threat events to NATS for Sentinel and CML consumption.
"""
import asyncio
import json
import logging
import os
from typing import Optional

try:
    import nats
    NATS_AVAILABLE = True
except ImportError:
    NATS_AVAILABLE = False

from cyberwall.core.event_bus import EventBus, ThreatEvent, ThreatLevel
from cyberwall.core.policy_engine import PolicyEngine

logger = logging.getLogger("cyberwall.sentinel_bridge")

SUBJECTS = {
    "alert":         "sorabbyngo.cyberwall.alert",
    "block":         "sorabbyngo.cyberwall.block",
    "status":        "sorabbyngo.cyberwall.status",
    "cml_request":   "sorabbyngo.cml.filter.request",
    "policy_reload": "sorabbyngo.cyberwall.policy.reload",
}


class SentinelBridge:
    def __init__(self, bus: EventBus, policy: PolicyEngine, nats_url: str = "nats://localhost:4222"):
        self.bus      = bus
        self.policy   = policy
        self.nats_url = nats_url
        self._nc: Optional[object] = None
        self._running = False
        self._node_id = self._read_node_id()

        # Subscribe to all events
        bus.subscribe("*", self.on_event)

    def _read_node_id(self) -> str:
        try:
            with open("/var/lib/sorabbyngo/nodeid") as f:
                return f.read().strip()
        except FileNotFoundError:
            return os.environ.get("SORABBYNGO_NODE_ID", "unknown")

    async def start(self):
        self._running = True
        if NATS_AVAILABLE:
            await self._connect()
        else:
            logger.warning("nats-py not installed — running in log-only mode")
        await self._heartbeat_loop()

    async def _connect(self):
        try:
            self._nc = await nats.connect(
                self.nats_url,
                name=f"cyberwall-{self._node_id[:8]}",
                reconnect_time_wait=2,
                max_reconnect_attempts=10,
            )
            logger.info(f"Connected to NATS at {self.nats_url}")
            await self._subscribe_policy_reload()
        except Exception as e:
            logger.error(f"NATS connection failed: {e} — running in log-only mode")
            self._nc = None

    async def _subscribe_policy_reload(self):
        if not self._nc:
            return
        async def _handler(msg):
            logger.info("Policy reload requested via NATS")
            # Signal policy engine to reload
        await self._nc.subscribe(SUBJECTS["policy_reload"], cb=_handler)

    async def on_event(self, event: ThreatEvent):
        """Called for every threat event from the event bus."""
        event.node_id = self._node_id

        if self.policy.should_alert(event):
            await self._publish(SUBJECTS["alert"], event.to_dict())

        if event.blocked:
            await self._publish(SUBJECTS["block"], event.to_dict())

        if self.policy.get("response", "notify_cml") and event.level >= ThreatLevel.HIGH:
            await self._send_to_cml(event)

    async def _send_to_cml(self, event: ThreatEvent):
        """Forward high-threat events through CML safety layer."""
        payload = {
            "request_id":  f"cw-{event.timestamp}-{event.score}",
            "text":        f"CYBERWALL ALERT: {event.threat_type} — {event.description}",
            "component":   "cyberwall",
            "action":      "threat_alert",
            "threat_level": event.level.name,
        }
        await self._publish(SUBJECTS["cml_request"], payload)

    async def _publish(self, subject: str, data: dict):
        msg = json.dumps(data).encode()
        if self._nc:
            try:
                await self._nc.publish(subject, msg)
            except Exception as e:
                logger.error(f"NATS publish error on {subject}: {e}")
        logger.info(f"[{subject}] {data.get('threat_type','status')} | {data.get('level','')}")

    async def _heartbeat_loop(self):
        while self._running:
            await self._publish(SUBJECTS["status"], {
                "node_id": self._node_id,
                "status":  "online",
                "service": "cyberwall",
            })
            await asyncio.sleep(30)

    async def stop(self):
        self._running = False
        if self._nc:
            await self._nc.close()
