"""
Tests for AIAnalyzer and identity-core SUID integration.
Covers the 0% ai/analyzer.py gap and identity bridge.
"""
import asyncio
import json
import pytest
from unittest.mock import patch, MagicMock
from cyberwall.core.event_bus import EventBus, ThreatEvent, ThreatLevel
from cyberwall.core.policy_engine import PolicyEngine
from cyberwall.ai.analyzer import AIAnalyzer


@pytest.fixture
def bus():
    return EventBus()

@pytest.fixture
def policy():
    return PolicyEngine()

@pytest.fixture
def analyzer(bus, policy):
    return AIAnalyzer(bus, policy)


# ── AIAnalyzer Tests ──────────────────────────────────────────────────────────

class TestAIAnalyzer:

    def test_rule_based_fallback_critical(self, analyzer):
        event = ThreatEvent(
            source="test", threat_type="malware_detected",
            level=ThreatLevel.CRITICAL, score=9.5,
            description="test"
        )
        result = analyzer._rule_based_fallback(event)
        assert result["severity"] == "CRITICAL"
        assert result["source"]   == "rule_based_fallback"

    def test_rule_based_fallback_high(self, analyzer):
        event = ThreatEvent(
            source="test", threat_type="port_scan",
            level=ThreatLevel.HIGH, score=7.5,
            description="test"
        )
        result = analyzer._rule_based_fallback(event)
        assert result["severity"] == "HIGH"
        assert result["recommended_action"] == "block"

    def test_rule_based_fallback_low(self, analyzer):
        event = ThreatEvent(
            source="test", threat_type="unknown",
            level=ThreatLevel.LOW, score=2.0,
            description="test"
        )
        result = analyzer._rule_based_fallback(event)
        assert result["severity"] == "INFO"
        assert result["recommended_action"] == "monitor"

    def test_rule_based_all_levels(self, analyzer):
        cases = [
            (9.5, "CRITICAL"), (7.5, "HIGH"), (5.5, "MEDIUM"),
            (3.5, "LOW"),      (1.0, "INFO"),
        ]
        for score, expected in cases:
            event = ThreatEvent(
                source="test", threat_type="unknown",
                level=ThreatLevel.INFO, score=score,
                description="test"
            )
            result = analyzer._rule_based_fallback(event)
            assert result["severity"] == expected

    @pytest.mark.asyncio
    async def test_enqueue_skips_low_events(self, analyzer, policy):
        policy.policy["ai"]["analyze_level"] = "HIGH"
        event = ThreatEvent(
            source="test", threat_type="port_scan",
            level=ThreatLevel.LOW, score=3.0,
            description="test"
        )
        await analyzer._enqueue(event)
        assert analyzer._queue.empty()

    @pytest.mark.asyncio
    async def test_enqueue_accepts_high_events(self, analyzer, policy):
        policy.policy["ai"]["analyze_level"] = "HIGH"
        event = ThreatEvent(
            source="test", threat_type="malware_detected",
            level=ThreatLevel.HIGH, score=8.0,
            description="test"
        )
        await analyzer._enqueue(event)
        assert not analyzer._queue.empty()

    @pytest.mark.asyncio
    async def test_analyze_uses_fallback_when_ollama_down(self, analyzer):
        event = ThreatEvent(
            source="test", threat_type="port_scan",
            level=ThreatLevel.MEDIUM, score=6.0,
            description="test"
        )
        result = await analyzer._analyze(event)
        assert result is not None
        assert "severity" in result
        assert "summary"  in result

    @pytest.mark.asyncio
    async def test_analyze_uses_ollama_when_available(self, analyzer):
        mock_response = json.dumps({
            "severity": "HIGH",
            "summary":  "Port scan from external IP",
            "attack_vector": "network",
            "recommended_action": "block",
            "false_positive_probability": 0.1,
        })
        ollama_resp = json.dumps({"response": mock_response}).encode()

        def mock_post(req):
            return ollama_resp.decode()

        event = ThreatEvent(
            source="test", threat_type="port_scan",
            level=ThreatLevel.HIGH, score=7.0,
            description="test"
        )
        with patch.object(analyzer, "_http_post", return_value=ollama_resp.decode()):
            result = await analyzer._analyze(event)
        assert result["severity"] == "HIGH"
        assert result["false_positive_probability"] == 0.1

    @pytest.mark.asyncio
    async def test_analyze_handles_malformed_json(self, analyzer):
        event = ThreatEvent(
            source="test", threat_type="port_scan",
            level=ThreatLevel.MEDIUM, score=5.0,
            description="test"
        )
        with patch.object(analyzer, "_http_post", return_value="not json at all"):
            result = await analyzer._analyze(event)
        # Should fall back to rule-based
        assert result is not None
        assert "severity" in result

    @pytest.mark.asyncio
    async def test_ai_disabled_skips_analysis(self, bus, policy):
        policy.policy["ai"]["enabled"] = False
        analyzer = AIAnalyzer(bus, policy)
        event = ThreatEvent(
            source="test", threat_type="malware_detected",
            level=ThreatLevel.CRITICAL, score=9.5,
            description="test"
        )
        await analyzer._enqueue(event)
        assert analyzer._queue.empty()

    def test_stop_sets_running_false(self, analyzer):
        analyzer._running = True
        analyzer.stop()
        assert analyzer._running is False


# ── SUID Integration Tests ────────────────────────────────────────────────────

class TestSUIDIntegration:
    """
    Tests verifying identity-core SUID integration with cyberwall.
    Cyberwall uses SUIDs for incident IDs, audit entries, and entity tracing.
    """

    def test_suid_available(self):
        try:
            from suid.generator import SUID
            from suid.registry.prefixes import PREFIX
            available = True
        except ImportError:
            available = False
        assert available, "identity-core must be installed"

    def test_incident_suid_generated(self):
        from suid.generator import SUID
        from suid.registry.prefixes import PREFIX
        incident_id = SUID.generate(PREFIX.INCIDENT, "KE047")
        assert incident_id.startswith("INC-")
        assert "KE047" in incident_id

    def test_audit_suid_for_block_event(self):
        from suid.generator import SUID
        from suid.registry.prefixes import PREFIX
        from suid.audit.logger import AuditLogger
        from suid.validator import validate

        # Simulate cyberwall blocking an IP — create audit entry
        incident_id = SUID.generate(PREFIX.INCIDENT, "KE047")
        audit_entry = AuditLogger.log(
            action="VERIFY",
            entity_id=incident_id,
            metadata={"src_ip": "192.168.1.100", "threat_type": "port_scan"},
            region="KE047",
        )
        assert validate(audit_entry["audit_id"]) is True
        assert audit_entry["action"] == "VERIFY"

    def test_threat_event_can_carry_suid(self):
        from suid.generator import SUID
        from suid.registry.prefixes import PREFIX

        incident_id = SUID.generate(PREFIX.INCIDENT, "KE045")
        event = ThreatEvent(
            source="cyberwall",
            threat_type="malware_detected",
            level=ThreatLevel.CRITICAL,
            score=9.5,
            description="Malware detected",
            data={"incident_suid": incident_id, "src_ip": "10.0.0.1"},
        )
        assert event.data["incident_suid"].startswith("INC-")

    def test_forensic_report_for_incident(self):
        from suid.generator import SUID
        from suid.registry.prefixes import PREFIX
        from suid.forensics.extractor import ForensicExtractor

        incident_id = SUID.generate(PREFIX.INCIDENT, "KE047")
        report = ForensicExtractor.entity_report(incident_id)
        assert report["entity_type"]    == "Security Incident"
        assert report["origin_country"] == "Kenya"
        assert report["tampered"]       is False

    def test_tamper_detection_on_incident_id(self):
        from suid.generator import SUID
        from suid.registry.prefixes import PREFIX
        from suid.validator import is_tampered

        incident_id = SUID.generate(PREFIX.INCIDENT, "KE045")
        parts = incident_id.split("-")
        parts[3] = "XXXXXX"
        tampered = "-".join(parts)
        assert is_tampered(tampered) is True
        assert is_tampered(incident_id) is False

    def test_law_enforcement_summary_for_incidents(self):
        from suid.generator import SUID
        from suid.registry.prefixes import PREFIX
        from suid.forensics.extractor import ForensicExtractor

        incidents = [SUID.generate(PREFIX.INCIDENT, "KE047") for _ in range(5)]
        report = ForensicExtractor.law_enforcement_summary(
            suids=incidents,
            case_number="CW/2026/001",
            requesting_authority="Sorabbyngo Security Team",
            authorized_by="Sorabbyngo Labs CTO",
        )
        assert report["summary"]["total_ids"]  == 5
        assert report["summary"]["valid_ids"]  == 5
        assert report["summary"]["tampered_ids"] == 0
        assert "Security Incident" in report["breakdown"]["by_entity_type"]

    def test_suid_batch_for_audit_trail(self):
        from suid.generator import SUID
        from suid.registry.prefixes import PREFIX
        from suid.validator import validate

        # Generate audit IDs for a series of cyberwall events
        audit_ids = SUID.batch(PREFIX.AUDIT, "KE047", count=10)
        assert len(audit_ids) == 10
        assert all(validate(aid) for aid in audit_ids)
        assert all(aid.startswith("AUD-") for aid in audit_ids)
