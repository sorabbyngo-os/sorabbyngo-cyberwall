"""
Tests — PolicyEngine
"""
import pytest
import tempfile
import yaml
from cyberwall.core.event_bus import ThreatEvent, ThreatLevel
from cyberwall.core.policy_engine import PolicyEngine, DEFAULT_POLICY


def make_event(level: ThreatLevel, score: float = 5.0) -> ThreatEvent:
    return ThreatEvent(
        source="test",
        threat_type="port_scan",
        level=level,
        score=score,
        description="Test",
    )


def test_default_policy_loads():
    p = PolicyEngine()
    assert p.get("firewall", "default_input") == "drop"
    assert p.get("response", "notify_sentinel") is True


def test_custom_config_overrides():
    config = {
        "firewall": {"default_input": "accept"},
        "response": {"auto_block_level": "CRITICAL"},
    }
    with tempfile.NamedTemporaryFile(
        mode="w", suffix=".yaml", delete=False
    ) as f:
        yaml.dump(config, f)
        path = f.name

    p = PolicyEngine(path)
    assert p.get("firewall", "default_input") == "accept"
    assert p.get("response", "auto_block_level") == "CRITICAL"
    # Non-overridden values still have defaults
    assert p.get("response", "notify_cml") is True


def test_should_block_high():
    p   = PolicyEngine()
    evt = make_event(ThreatLevel.HIGH, 7.0)
    assert p.should_block(evt) is True


def test_should_not_block_medium():
    p   = PolicyEngine()
    evt = make_event(ThreatLevel.MEDIUM, 5.0)
    assert p.should_block(evt) is False


def test_should_quarantine_critical_only():
    p = PolicyEngine()
    assert p.should_quarantine(make_event(ThreatLevel.CRITICAL)) is True
    assert p.should_quarantine(make_event(ThreatLevel.HIGH))     is False


def test_should_alert_low_and_above():
    p = PolicyEngine()
    assert p.should_alert(make_event(ThreatLevel.LOW))      is True
    assert p.should_alert(make_event(ThreatLevel.MEDIUM))   is True
    assert p.should_alert(make_event(ThreatLevel.HIGH))     is True
    assert p.should_alert(make_event(ThreatLevel.CRITICAL)) is True
    assert p.should_alert(make_event(ThreatLevel.INFO))     is False


def test_should_ai_analyze_medium_and_above():
    p = PolicyEngine()
    assert p.should_ai_analyze(make_event(ThreatLevel.MEDIUM))   is True
    assert p.should_ai_analyze(make_event(ThreatLevel.HIGH))     is True
    assert p.should_ai_analyze(make_event(ThreatLevel.LOW))      is False


def test_ai_disabled():
    config = {"ai": {"enabled": False}}
    with tempfile.NamedTemporaryFile(
        mode="w", suffix=".yaml", delete=False
    ) as f:
        yaml.dump(config, f)
        path = f.name
    p = PolicyEngine(path)
    assert p.should_ai_analyze(make_event(ThreatLevel.CRITICAL)) is False


def test_get_missing_key_returns_default():
    p = PolicyEngine()
    assert p.get("nonexistent", "key", default="fallback") == "fallback"
