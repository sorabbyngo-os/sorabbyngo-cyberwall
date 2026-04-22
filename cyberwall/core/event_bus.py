"""
Sorabbyngo Cyberwall — Core Event Bus
Internal pub/sub for all cyberwall components.
"""
import asyncio
import logging
from dataclasses import dataclass, field
from typing import Callable, Dict, List, Any
from enum import IntEnum
from datetime import datetime, timezone

logger = logging.getLogger("cyberwall.core.event_bus")


class ThreatLevel(IntEnum):
    INFO     = 1
    LOW      = 3
    MEDIUM   = 5
    HIGH     = 7
    CRITICAL = 9


@dataclass
class ThreatEvent:
    source:      str                        # firewall | malware | syscall | ai
    threat_type: str                        # port_scan | malware | anomaly | etc
    level:       ThreatLevel
    score:       float                      # 0.0 – 10.0
    description: str
    data:        Dict[str, Any] = field(default_factory=dict)
    timestamp:   str            = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    node_id:     str            = ""
    blocked:     bool           = False
    quarantined: bool           = False

    def to_dict(self) -> dict:
        return {
            "source":      self.source,
            "threat_type": self.threat_type,
            "level":       self.level.name,
            "score":       self.score,
            "description": self.description,
            "data":        self.data,
            "timestamp":   self.timestamp,
            "node_id":     self.node_id,
            "blocked":     self.blocked,
            "quarantined": self.quarantined,
        }


class EventBus:
    """Internal async event bus — connects firewall, malware, AI, and sentinel bridge."""

    def __init__(self):
        self._subscribers: Dict[str, List[Callable]] = {}
        self._queue: asyncio.Queue = asyncio.Queue()
        self._running = False

    def subscribe(self, event_type: str, handler: Callable):
        self._subscribers.setdefault(event_type, []).append(handler)
        logger.debug(f"Subscribed {handler.__name__} to {event_type}")

    async def publish(self, event: ThreatEvent):
        await self._queue.put(event)

    async def run(self):
        self._running = True
        logger.info("EventBus running")
        while self._running:
            try:
                event = await asyncio.wait_for(self._queue.get(), timeout=1.0)
                await self._dispatch(event)
            except asyncio.TimeoutError:
                continue
            except Exception as e:
                logger.error(f"EventBus dispatch error: {e}")

    async def _dispatch(self, event: ThreatEvent):
        handlers = (
            self._subscribers.get(event.threat_type, []) +
            self._subscribers.get("*", [])
        )
        for handler in handlers:
            try:
                await handler(event)
            except Exception as e:
                logger.error(f"Handler {handler.__name__} error: {e}")

    def stop(self):
        self._running = False
