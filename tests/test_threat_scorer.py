"""
Tests — ThreatScorer
"""
import pytest
from cyberwall.core.event_bus import ThreatEvent, ThreatLevel
from cyberwall.core.threat_scorer import score_event, THREAT_BASE_SCORES


def make_event(threat_type: str, data: dict = None) -> ThreatEvent:
    return ThreatEvent(
        source="test",
        threat_type=threat_type,
        level=ThreatLevel.INFO,
        score=0.0,
        description=f"Test {threat_type}",
        data=data or {},
    )


def test_base_score_port_scan():
    evt = score_event(make_event("port_scan"))
    assert evt.score == THREAT_BASE_SCORES["port_scan"]
    assert evt.level == ThreatLevel.MEDIUM


def test_base_score_malware():
    evt = score_event(make_event("malware_detected"))
    assert evt.score == THREAT_BASE_SCORES["malware_detected"]
    assert evt.level == ThreatLevel.CRITICAL


def test_critical_path_multiplier():
    evt = score_event(make_event("file_tamper", {"path": "/etc/passwd"}))
    assert evt.score > THREAT_BASE_SCORES["file_tamper"]
    assert evt.level >= ThreatLevel.HIGH


def test_medical_data_multiplier():
    evt = score_event(make_event("data_exfil", {"path": "/var/lib/novela/patients"}))
    assert evt.score == 10.0   # capped at 10
    assert evt.level == ThreatLevel.CRITICAL


def test_repeat_offender_multiplier():
    evt = score_event(make_event("port_scan"), context={"repeat_offender": True})
    base = THREAT_BASE_SCORES["port_scan"]
    assert evt.score > base


def test_score_capped_at_10():
    evt = score_event(
        make_event("malware_detected", {"path": "/var/lib/novela/patients"}),
        context={"repeat_offender": True}
    )
    assert evt.score <= 10.0


def test_unknown_threat_type():
    evt = score_event(make_event("something_new"))
    # Base is 4.0; repeat-offender bonus (+1.5) may apply if tracker has prior hits
    assert evt.score >= THREAT_BASE_SCORES["unknown"], (
        f"score {evt.score} below base {THREAT_BASE_SCORES['unknown']}"
    )
    assert evt.score <= 10.0
    assert evt.level >= ThreatLevel.LOW


@pytest.mark.parametrize("threat_type,min_level", [
    ("port_scan",       ThreatLevel.MEDIUM),
    ("brute_force",     ThreatLevel.HIGH),
    ("ddos",            ThreatLevel.HIGH),
    ("malware_detected",ThreatLevel.CRITICAL),
    ("rootkit",         ThreatLevel.CRITICAL),
])
def test_level_assignment(threat_type, min_level):
    evt = score_event(make_event(threat_type))
    assert evt.level >= min_level, (
        f"{threat_type}: expected >= {min_level.name}, got {evt.level.name} (score={evt.score})"
    )
