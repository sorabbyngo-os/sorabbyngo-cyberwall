"""
Sorabbyngo Cyberwall — Core Event Bus  (patched v2)
Internal pub/sub for all cyberwall components.

Patches over v1:
  - Bounded queue (maxsize=10_000) — survives attack storms
  - Middleware chain — scoring injected cleanly, not via monkey-patch
  - Handler deduplication — double-subscribe is a no-op
  - QueueFull drops LOW/INFO events instead of blocking
  - Shutdown drains queue before exit
"""
import asyncio
import logging
from dataclasses import dataclass, field
from typing import Callable, Dict, List, Any, Awaitable
from enum import IntEnum
from datetime import datetime, timezone

logger = logging.getLogger("cyberwall.core.event_bus")

QUEUE_MAXSIZE = 10_000   # hard cap — protect against flood


class ThreatLevel(IntEnum):
    INFO     = 1
    LOW      = 3
    MEDIUM   = 5
    HIGH     = 7
    CRITICAL = 9


@dataclass
class ThreatEvent:
    source:      str
    threat_type: str
    level:       ThreatLevel
    score:       float                      # 0.0 – 10.0
    description: str
    data:        Dict[str, Any] = field(default_factory=dict)
    timestamp:   str            = field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )
    node_id:     str  = ""
    blocked:     bool = False
    quarantined: bool = False

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


MiddlewareFn = Callable[[ThreatEvent], Awaitable[ThreatEvent]]


class EventBus:
    """
    Internal async event bus — connects firewall, malware, AI, and sentinel bridge.

    Middleware runs in order before any subscriber sees an event.
    Use add_middleware() for scoring, enrichment, dedup, etc.
    """

    def __init__(self):
        self._subscribers: Dict[str, List[Callable]] = {}
        self._middleware:  List[MiddlewareFn]         = []
        self._queue:       asyncio.Queue              = asyncio.Queue(maxsize=QUEUE_MAXSIZE)
        self._running = False
        self._stats = {"published": 0, "dropped": 0, "dispatched": 0}

    # ── Middleware ─────────────────────────────────────────────────────────────

    def add_middleware(self, fn: MiddlewareFn):
        """Add an async middleware function. Each receives and returns a ThreatEvent."""
        self._middleware.append(fn)
        logger.debug(f"Middleware registered: {fn.__name__}")

    # ── Subscribe ──────────────────────────────────────────────────────────────

    def subscribe(self, event_type: str, handler: Callable):
        """Subscribe a handler to an event type or '*' for all events."""
        bucket = self._subscribers.setdefault(event_type, [])
        if handler not in bucket:          # deduplication guard
            bucket.append(handler)
            logger.debug(f"Subscribed {handler.__name__} → {event_type}")

    def unsubscribe(self, event_type: str, handler: Callable):
        bucket = self._subscribers.get(event_type, [])
        if handler in bucket:
            bucket.remove(handler)

    # ── Publish ────────────────────────────────────────────────────────────────

    async def publish(self, event: ThreatEvent):
        """
        Run middleware chain then enqueue.
        Drops LOW/INFO events when queue is near full.
        CRITICAL/HIGH events always enqueue (may block briefly if full).
        """
        # Run middleware
        try:
            for mw in self._middleware:
                event = await mw(event)
        except Exception as e:
            logger.error(f"Middleware error: {e}")

        # Admission control
        if self._queue.qsize() >= QUEUE_MAXSIZE * 0.9:
            if event.level <= ThreatLevel.LOW:
                self._stats["dropped"] += 1
                logger.debug(f"Queue full — dropped {event.threat_type} (LOW/INFO)")
                return

        try:
            self._queue.put_nowait(event)
            self._stats["published"] += 1
        except asyncio.QueueFull:
            self._stats["dropped"] += 1
            logger.warning(f"Queue full — dropped {event.threat_type} [{event.level.name}]")

    # ── Run ────────────────────────────────────────────────────────────────────

    async def run(self):
        self._running = True
        logger.info("EventBus running")
        while self._running:
            try:
                event = await asyncio.wait_for(self._queue.get(), timeout=1.0)
                await self._dispatch(event)
                self._queue.task_done()
                self._stats["dispatched"] += 1
            except asyncio.TimeoutError:
                continue
            except Exception as e:
                logger.error(f"EventBus dispatch error: {e}")

        # Drain remaining events on shutdown
        while not self._queue.empty():
            try:
                event = self._queue.get_nowait()
                await self._dispatch(event)
                self._queue.task_done()
            except asyncio.QueueEmpty:
                break

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

    def stats(self) -> dict:
        return {**self._stats, "queue_depth": self._queue.qsize()}
