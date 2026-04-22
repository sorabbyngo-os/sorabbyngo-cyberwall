"""
Sorabbyngo Cyberwall — Threat Scorer
Scores incoming events and decides action level.
"""
import logging
from cyberwall.core.event_bus import ThreatEvent, ThreatLevel

logger = logging.getLogger("cyberwall.core.threat_scorer")

# Base scores per threat type
THREAT_BASE_SCORES = {
    "port_scan":          6.0,
    "brute_force":        7.5,
    "ddos":               8.5,
    "malware_detected":   9.0,
    "rootkit":            9.5,
    "syscall_anomaly":    7.0,
    "file_tamper":        8.0,
    "process_injection":  9.0,
    "lateral_movement":   8.5,
    "data_exfil":         9.0,
    "unknown":            4.0,
}

# Multipliers
REPEAT_MULTIPLIER   = 1.3   # same source seen before
CRITICAL_PATH_BONUS = 1.5   # /etc /lib /boot /proc/sorabbyngo
MEDICAL_DATA_BONUS  = 2.0   # novela patient data paths


def score_event(event: ThreatEvent, context: dict = None) -> ThreatEvent:
    context = context or {}
    base  = THREAT_BASE_SCORES.get(event.threat_type, 4.0)
    score = base

    if context.get("repeat_offender"):
        score *= REPEAT_MULTIPLIER

    path = event.data.get("path", "")
    if any(p in path for p in ["/etc", "/lib/modules", "/boot", "/proc/sorabbyngo"]):
        score *= CRITICAL_PATH_BONUS

    if any(p in path for p in ["/var/lib/novela", "/opt/sorabbyngo/novela", "patients"]):
        score *= MEDICAL_DATA_BONUS

    score = min(score, 10.0)
    event.score = round(score, 2)

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

    logger.info(f"Scored [{event.level.name}] {event.threat_type} → {event.score}")
    return event
