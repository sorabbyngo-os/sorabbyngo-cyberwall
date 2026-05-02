"""
Tests for SIEM engine, quantum suite, and CLI dashboard.
"""
from __future__ import annotations
import asyncio, base64, json, os, time, tempfile
from pathlib import Path
from unittest.mock import MagicMock
import pytest
from cyberwall.core.event_bus import EventBus, ThreatEvent, ThreatLevel


def _ev(threat_type="malware_detected", level=ThreatLevel.HIGH,
        score=7.5, source_ip="10.0.0.1", blocked=False):
    return ThreatEvent(
        source="test", threat_type=threat_type,
        description=f"Test {threat_type}", level=level, score=score,
        blocked=blocked, data={"src_ip": source_ip}, node_id="test-node",
    )

# ── SyslogParser ──────────────────────────────────────────────────────────────
class TestSyslogParser:
    @pytest.fixture
    def parser(self):
        from cyberwall.siem.engine import SyslogParser
        return SyslogParser()

    def test_parse_cef(self, parser):
        raw = "CEF:0|Cisco|ASA|9.0|106023|Deny|8|src=192.168.1.100 dst=10.0.0.1"
        ev = parser.parse(raw)
        assert ev is not None
        assert ev.level == ThreatLevel.HIGH

    def test_parse_cef_critical(self, parser):
        ev = parser.parse("CEF:0|V|P|1.0|S|Attack|10|src=1.2.3.4")
        assert ev is not None and ev.level == ThreatLevel.CRITICAL

    def test_parse_cef_low(self, parser):
        ev = parser.parse("CEF:0|V|P|1.0|S|Info|3|src=1.2.3.4")
        assert ev is not None and ev.level == ThreatLevel.LOW

    def test_parse_rfc5424(self, parser):
        raw = "<34>1 2024-01-01T00:00:00Z host1 sshd 1234 ID47 - Failed password"
        ev = parser.parse(raw)
        assert ev is not None
        assert ev.level in (ThreatLevel.CRITICAL, ThreatLevel.HIGH)

    def test_parse_rfc5424_info(self, parser):
        raw = "<191>1 2024-01-01T00:00:00Z host1 cron 999 - - Job started"
        ev = parser.parse(raw)
        assert ev is not None and ev.level == ThreatLevel.INFO

    def test_parse_garbage_returns_none(self, parser):
        assert parser.parse("not a valid log line") is None

    def test_parse_empty_returns_none(self, parser):
        assert parser.parse("") is None


# ── CorrelationRule matching ───────────────────────────────────────────────────
class TestCorrelationRule:
    def test_match_eq(self):
        from cyberwall.siem.engine import _match_condition
        ev = _ev("port_scan")
        assert _match_condition(ev, {"field":"threat_type","op":"eq","value":"port_scan"})
        assert not _match_condition(ev, {"field":"threat_type","op":"eq","value":"malware"})

    def test_match_in(self):
        from cyberwall.siem.engine import _match_condition
        ev = _ev("port_scan")
        assert _match_condition(ev, {"field":"threat_type","op":"in","value":["port_scan","malware"]})

    def test_match_contains(self):
        from cyberwall.siem.engine import _match_condition
        assert _match_condition(_ev(), {"field":"description","op":"contains","value":"Test"})

    def test_match_gt(self):
        from cyberwall.siem.engine import _match_condition
        ev = _ev(score=8.0)
        assert _match_condition(ev, {"field":"score","op":"gt","value":7.0})
        assert not _match_condition(ev, {"field":"score","op":"gt","value":9.0})

    def test_match_gte(self):
        from cyberwall.siem.engine import _match_condition
        assert _match_condition(_ev(score=8.0), {"field":"score","op":"gte","value":8.0})

    def test_event_matches_rule(self):
        from cyberwall.siem.engine import CorrelationRule, _event_matches_rule
        rule = CorrelationRule(
            name="t", description="t",
            conditions=[{"field":"threat_type","op":"eq","value":"malware_detected"}]
        )
        assert _event_matches_rule(_ev("malware_detected"), rule)
        assert not _event_matches_rule(_ev("port_scan"), rule)


# ── SIEMEngine ────────────────────────────────────────────────────────────────
class TestSIEMEngine:
    @pytest.fixture
    def siem(self, tmp_path):
        from cyberwall.siem.engine import SIEMEngine, CorrelationRule
        bus = EventBus()
        rules = [
            CorrelationRule(name="thresh", description="3 in 60s",
                conditions=[{"field":"threat_type","op":"eq","value":"auth_failure"}],
                window_s=60, threshold=3, severity="HIGH"),
            CorrelationRule(name="dpa_test", description="DPA",
                conditions=[{"field":"threat_type","op":"eq","value":"data_exfil"}],
                window_s=1, threshold=1, severity="CRITICAL", action="dpa_notify",
                tags=["dpa_2019"]),
        ]
        return SIEMEngine(bus=bus, log_dir=tmp_path/"siem", rules=rules)

    @pytest.mark.asyncio
    async def test_event_ingested(self, siem):
        await siem._on_event(_ev("auth_failure"))
        assert siem._stats["events_ingested"] == 1

    @pytest.mark.asyncio
    async def test_incident_created_after_threshold(self, siem):
        for _ in range(3):
            await siem._on_event(_ev("auth_failure"))
        assert siem._stats["incidents_created"] >= 1

    @pytest.mark.asyncio
    async def test_incident_deduplication(self, siem):
        for _ in range(6):
            await siem._on_event(_ev("auth_failure"))
        assert len(siem.get_incidents()) == 1

    @pytest.mark.asyncio
    async def test_dpa_breach_recorded(self, siem):
        await siem._on_event(_ev("data_exfil", level=ThreatLevel.CRITICAL))
        assert siem._stats["dpa_breaches"] >= 1
        recs = siem.get_dpa_records()
        assert len(recs) >= 1 and recs[0].event_type == "data_exfil"

    @pytest.mark.asyncio
    async def test_dpa_deadline_hours(self, siem):
        from cyberwall.siem.engine import DPAAuditRecord, DPA_BREACH_NOTIFY_HOURS
        rec = DPAAuditRecord(ts=time.time(), event_type="data_exfil",
            source_ip="1.2.3.4", data_category="personal",
            description="test", incident_id="abc")
        assert 0 < rec.hours_until_deadline() <= DPA_BREACH_NOTIFY_HOURS

    @pytest.mark.asyncio
    async def test_ingest_raw_cef(self, siem):
        ev = await siem.ingest_raw("CEF:0|Vendor|IDS|1.0|001|Attack|9|src=5.5.5.5")
        assert ev is not None
        assert siem._stats["events_ingested"] >= 1

    @pytest.mark.asyncio
    async def test_actor_tracking(self, siem):
        await siem._on_event(_ev("port_scan", source_ip="1.2.3.4"))
        await siem._on_event(_ev("malware_detected", source_ip="1.2.3.4"))
        assert len(siem.get_actor_timeline("1.2.3.4")) == 2

    def test_stats_keys(self, siem):
        for k in ("events_ingested","incidents_created","dpa_breaches",
                  "open_incidents","tracked_actors","uptime_s"):
            assert k in siem.stats()

    def test_on_incident_callback(self, tmp_path):
        from cyberwall.siem.engine import SIEMEngine, CorrelationRule
        fired = []
        bus   = EventBus()
        rules = [CorrelationRule(name="cb", description="cb",
            conditions=[{"field":"threat_type","op":"eq","value":"rootkit"}],
            window_s=60, threshold=1, severity="CRITICAL")]
        siem  = SIEMEngine(bus=bus, log_dir=tmp_path/"s2", rules=rules,
                           on_incident=fired.append)
        asyncio.get_event_loop().run_until_complete(siem._on_event(_ev("rootkit")))
        assert len(fired) == 1 and fired[0].rule_name == "cb"

    def test_classify_data_medical(self, siem):
        assert siem._classify_data(_ev("patient_data_access")) == "medical"

    def test_classify_data_personal(self, siem):
        assert siem._classify_data(_ev("data_exfil")) == "personal"


# ── SPHINCSPlus ───────────────────────────────────────────────────────────────
class TestSPHINCSPlus:
    @pytest.fixture
    def sph(self):
        from cyberwall.quantum.suite import SPHINCSPlus
        return SPHINCSPlus()

    def test_keygen_returns_bytes(self, sph):
        pk, sk = sph.keygen()
        assert isinstance(pk, bytes) and len(pk) > 0
        assert isinstance(sk, bytes) and len(sk) > 0

    def test_sign_returns_bytes(self, sph):
        pk, sk = sph.keygen()
        assert isinstance(sph.sign(sk, b"hello"), bytes)

    def test_verify_valid(self, sph):
        pk, sk = sph.keygen()
        msg = b"Kenya DPA 2019 audit"
        sig = sph.sign(sk, msg)
        assert sph.verify(pk, msg, sig)

    def test_different_keys_different_sigs(self, sph):
        _, sk1 = sph.keygen()
        _, sk2 = sph.keygen()
        assert sph.sign(sk1, b"msg") != sph.sign(sk2, b"msg")

    def test_stats(self, sph):
        s = sph.stats()
        assert "variant" in s and "active" in s

    def test_sign_empty_message(self, sph):
        _, sk = sph.keygen()
        assert len(sph.sign(sk, b"")) > 0

    def test_sign_large_message(self, sph):
        _, sk = sph.keygen()
        assert len(sph.sign(sk, os.urandom(10_000))) > 0


# ── HybridTLS ─────────────────────────────────────────────────────────────────
class TestHybridTLS:
    def test_handshake_same_secret(self):
        from cyberwall.quantum.suite import HybridTLS
        c, s  = HybridTLS(), HybridTLS()
        hello = c.client_hello()
        reply, ss_srv = s.server_finish(hello)
        ss_cli = c.client_finish(reply)
        assert ss_cli == ss_srv

    def test_shared_secret_32_bytes(self):
        from cyberwall.quantum.suite import HybridTLS
        c, s  = HybridTLS(), HybridTLS()
        hello = c.client_hello()
        _, ss = s.server_finish(hello)
        assert len(ss) == 32

    def test_different_sessions_differ(self):
        from cyberwall.quantum.suite import HybridTLS
        c1,s1 = HybridTLS(),HybridTLS()
        c2,s2 = HybridTLS(),HybridTLS()
        h1=c1.client_hello(); r1,ss1=s1.server_finish(h1); c1.client_finish(r1)
        h2=c2.client_hello(); r2,ss2=s2.server_finish(h2); c2.client_finish(r2)
        assert ss1 != ss2

    def test_client_hello_structure(self):
        from cyberwall.quantum.suite import HybridTLS
        hello = HybridTLS().client_hello()
        d = json.loads(hello)
        assert "kyber_pk" in d and "x25519_pk" in d and "nonce" in d

    def test_kdf_deterministic(self):
        from cyberwall.quantum.suite import HybridTLS
        ss1 = HybridTLS._kdf(b"a"*32, b"b"*32, b"n"*32)
        ss2 = HybridTLS._kdf(b"a"*32, b"b"*32, b"n"*32)
        assert ss1 == ss2

    def test_kdf_different_inputs(self):
        from cyberwall.quantum.suite import HybridTLS
        assert HybridTLS._kdf(b"a"*32, b"b"*32, b"n"*32) != HybridTLS._kdf(b"x"*32, b"b"*32, b"n"*32)


# ── QuantumVault ──────────────────────────────────────────────────────────────
class TestQuantumVault:
    @pytest.fixture
    def vault(self):
        from cyberwall.quantum.suite import QuantumVault
        return QuantumVault()

    def test_seal_unseal_roundtrip(self, vault):
        data = {"api_key": "secret-12345", "user": "admin"}
        out  = vault.unseal(vault.seal(data))
        assert out is not None
        assert out["api_key"] == "secret-12345"

    def test_seal_returns_string(self, vault):
        assert isinstance(vault.seal({"x":1}), str)

    def test_different_data_different_tokens(self, vault):
        assert vault.seal({"a":1}) != vault.seal({"b":2})

    def test_invalid_token_returns_none(self, vault):
        assert vault.unseal("not-valid-base64!!!") is None

    def test_empty_token_returns_none(self, vault):
        assert vault.unseal("") is None

    def test_rotate_keys(self, vault):
        pk1, _ = vault.rotate_keys()
        pk2, _ = vault.rotate_keys()
        assert pk1 != pk2

    def test_seal_complex_data(self, vault):
        data = {"incidents":[{"id":"abc"}], "tags":["dpa","breach"]}
        out  = vault.unseal(vault.seal(data))
        assert out is not None and out["tags"] == ["dpa","breach"]


# ── QuantumAuditLog ───────────────────────────────────────────────────────────
class TestQuantumAuditLog:
    @pytest.fixture
    def audit_log(self, tmp_path):
        from cyberwall.quantum.suite import QuantumAuditLog
        log = QuantumAuditLog(tmp_path / "audit.qlog")
        yield log
        log.close()

    def test_append_returns_hash(self, audit_log):
        h = audit_log.append({"event":"login"})
        assert isinstance(h, bytes) and len(h) == 32

    def test_sequential_hashes_differ(self, audit_log):
        h1 = audit_log.append({"event":"a"})
        h2 = audit_log.append({"event":"b"})
        assert h1 != h2

    def test_file_written(self, audit_log, tmp_path):
        audit_log.append({"event":"test"})
        assert len(list(tmp_path.glob("*.qlog"))) == 1

    def test_file_contains_json(self, audit_log, tmp_path):
        audit_log.append({"action":"DPA audit"})
        audit_log.close()
        entry = json.loads((tmp_path/"audit.qlog").read_text().strip().splitlines()[0])
        assert "seq" in entry and "hash" in entry and "payload" in entry

    def test_chain_linkage(self, audit_log, tmp_path):
        for i in range(3):
            audit_log.append({"n": i})
        audit_log.close()
        lines   = (tmp_path/"audit.qlog").read_text().strip().splitlines()
        entries = [json.loads(l) for l in lines]
        assert entries[1]["prev"] == entries[0]["hash"]
        assert entries[2]["prev"] == entries[1]["hash"]

    def test_public_key(self, audit_log):
        pk = audit_log.public_key()
        assert pk is None or isinstance(pk, bytes)


# ── CLIDashboard ──────────────────────────────────────────────────────────────
class TestCLIDashboard:
    @pytest.fixture
    def dash(self):
        from cyberwall.dashboard.cli import CLIDashboard
        bus = EventBus()
        return CLIDashboard(bus, max_events=50)

    @pytest.mark.asyncio
    async def test_event_counted(self, dash):
        await dash._on_event(_ev("malware_detected", level=ThreatLevel.HIGH))
        assert dash._stats["total"] == 1 and dash._stats["high"] == 1

    @pytest.mark.asyncio
    async def test_critical_counted(self, dash):
        await dash._on_event(_ev("rootkit", level=ThreatLevel.CRITICAL))
        assert dash._stats["critical"] == 1

    @pytest.mark.asyncio
    async def test_blocked_counted(self, dash):
        await dash._on_event(_ev(blocked=True))
        assert dash._stats["blocked"] == 1

    @pytest.mark.asyncio
    async def test_events_stored(self, dash):
        for _ in range(5):
            await dash._on_event(_ev())
        assert len(dash._events) == 5

    @pytest.mark.asyncio
    async def test_max_events_respected(self, dash):
        for _ in range(60):
            await dash._on_event(_ev())
        assert len(dash._events) <= 50

    def test_stop(self, dash):
        dash._running = True
        dash.stop()
        assert not dash._running

    @pytest.mark.asyncio
    async def test_multiple_levels(self, dash):
        for lvl in ThreatLevel:
            await dash._on_event(_ev(level=lvl))
        assert dash._stats["total"] == len(list(ThreatLevel))
        assert dash._stats["critical"] == 1


# ── QuantumLogStore ───────────────────────────────────────────────────────────
class TestQuantumLogStore:
    @pytest.fixture
    def store(self, tmp_path):
        from cyberwall.siem.engine import QuantumLogStore
        s = QuantumLogStore(tmp_path / "test.qlog")
        yield s
        s.close()

    def test_write_record(self, store, tmp_path):
        store.write({"event":"test","level":"HIGH"})
        assert len((tmp_path/"test.qlog").read_bytes()) > 0

    def test_multiple_writes(self, store, tmp_path):
        for i in range(5):
            store.write({"seq": i})
        lines = (tmp_path/"test.qlog").read_bytes().strip().splitlines()
        assert len(lines) == 5

    def test_close_idempotent(self, store):
        store.close()
        store.close()
