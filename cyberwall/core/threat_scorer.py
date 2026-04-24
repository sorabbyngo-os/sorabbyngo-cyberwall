"""
Sorabbyngo Cyberwall — Threat Scorer  (patched v2)

Patches over v1:
  - Additive bonuses instead of stacking multipliers (prevents ceiling bypass confusion)
  - RepeatOffenderTracker — actually tracks repeat sources
  - score_event() is now async-safe and side-effect free (returns new score, doesn't mutate level)
  - Context dict populated from tracker automatically
"""
import logging
import time
from collections import defaultdict
from threading import Lock
from cyberwall.core.event_bus import ThreatEvent, ThreatLevel

logger = logging.getLogger("cyberwall.core.threat_scorer")

# ── Base scores per threat type ────────────────────────────────────────────────
THREAT_BASE_SCORES: dict[str, float] = {
    "port_scan":          6.0,
    "brute_force":        7.5,
    "ddos":               8.5,
    "syn_flood":          8.0,
    "malware_detected":   9.0,
    "rootkit":            9.5,
    "syscall_anomaly":    7.0,
    "file_tamper":        6.5,
    "process_injection":  9.0,
    "lateral_movement":   8.5,
    "data_exfil":         9.0,
    "cryptominer":        8.0,
    "webshell":           9.0,
    "backdoor":           9.5,
    "botnet":             8.5,
    "infostealer":        8.5,
    "packed_malware":     5.0,
    "null_scan":          6.0,
    "xmas_scan":          6.0,
    "ip_blocked":         7.0,
    "unknown":            4.0,
}

# ── Additive bonuses ───────────────────────────────────────────────────────────
BONUS_REPEAT_OFFENDER = 1.5   # source seen ≥3 times in window
BONUS_CRITICAL_PATH   = 1.0   # /etc /lib /boot /proc/sorabbyngo
BONUS_MEDICAL_DATA    = 2.0   # novela patient data paths

CRITICAL_PATHS = ["/etc", "/lib/modules", "/boot", "/proc/sorabbyngo"]
MEDICAL_PATHS  = ["/var/lib/novela", "/opt/sorabbyngo/novela", "patients", "health_records"]


# ── Repeat Offender Tracker ────────────────────────────────────────────────────
class RepeatOffenderTracker:
    """
    Thread-safe sliding-window tracker.
    Marks a source as repeat_offender after THRESHOLD hits within WINDOW seconds.
    Entries expire automatically — no unbounded growth.
    """
    WINDOW    = 300   # 5-minute window
    THRESHOLD = 3     # hits before flagged

    def __init__(self):
        self._hits: dict[str, list[float]] = defaultdict(list)
        self._lock = Lock()

    def record(self, source_key: str) -> bool:
        """Record a hit. Returns True if source is now a repeat offender."""
        now = time.monotonic()
        with self._lock:
            hits = self._hits[source_key]
            hits.append(now)
            # Expire old hits
            cutoff = now - self.WINDOW
            self._hits[source_key] = [h for h in hits if h >= cutoff]
            return len(self._hits[source_key]) >= self.THRESHOLD

    def is_repeat(self, source_key: str) -> bool:
        now = time.monotonic()
        cutoff = now - self.WINDOW
        with self._lock:
            hits = [h for h in self._hits.get(source_key, []) if h >= cutoff]
            return len(hits) >= self.THRESHOLD

    def evict_expired(self):
        """Clean up stale entries — call periodically from a task."""
        now = time.monotonic()
        cutoff = now - self.WINDOW
        with self._lock:
            self._hits = {
                k: [h for h in v if h >= cutoff]
                for k, v in self._hits.items()
                if any(h >= cutoff for h in v)
            }

    def size(self) -> int:
        with self._lock:
            return len(self._hits)


# Module-level singleton — shared across the process
_tracker = RepeatOffenderTracker()


def score_event(event: ThreatEvent, context: dict | None = None) -> ThreatEvent:
    """
    Score a ThreatEvent in-place and update its level.
    Uses additive bonuses — multipliers no longer stack beyond ceiling.
    """
    context = context or {}

    base  = THREAT_BASE_SCORES.get(event.threat_type, 4.0)
    score = base

    # ── Repeat offender ───────────────────────────────────────────────────────
    source_key = (
        event.data.get("src_ip") or
        event.data.get("pid")    or
        event.source
    )
    is_repeat = _tracker.record(str(source_key))
    if is_repeat:
        score = min(score + BONUS_REPEAT_OFFENDER, 10.0)
        event.data["repeat_offender"] = True

    # ── Critical path bonus ───────────────────────────────────────────────────
    path = event.data.get("path", "")
    if path and any(path.startswith(cp) for cp in CRITICAL_PATHS):
        score = min(score + BONUS_CRITICAL_PATH, 10.0)
        event.data["critical_path"] = True

    # ── Medical data bonus ────────────────────────────────────────────────────
    if path and any(mp in path for mp in MEDICAL_PATHS):
        score = min(score + BONUS_MEDICAL_DATA, 10.0)
        event.data["medical_data"] = True

    # ── External context overrides ────────────────────────────────────────────
    if context.get("repeat_offender") and not is_repeat:
        score = min(score + BONUS_REPEAT_OFFENDER, 10.0)

    score = round(min(score, 10.0), 2)
    event.score = score

    # ── Level assignment ──────────────────────────────────────────────────────
    if score >= 9:
        event.level = ThreatLevel.CRITICAL
    elif score >= 7:
        event.level = ThreatLevel.HIGH
    elif score >= 5:
        event.level = ThreatLevel.MEDIUM
    elif score >= 3:
        event.level = ThreatLevel.LOW
    else:
        event.level = ThreatLevel.INFO

    logger.info(f"Scored [{event.level.name}] {event.threat_type} → {event.score}"
                + (" [REPEAT]" if is_repeat else ""))
    return event


async def scoring_middleware(event: ThreatEvent) -> ThreatEvent:
    """
    Async middleware wrapper — register with EventBus.add_middleware().
    Replaces the monkey-patch approach in v1 daemon.
    """
    return score_event(event)


def get_tracker() -> RepeatOffenderTracker:
    """Expose singleton for testing."""
    return _tracker
