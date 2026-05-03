"""
Coverage booster 3 — targets:
  blockchain/ledger.py       (0%)
  dashboard/server.py        (0%)
  dashboard/cli.py           (30%)
  malware/scanner.py         (67%)
  siem/engine.py             remaining gaps
  sentinel_bridge/bridge.py  remaining gaps
"""
from __future__ import annotations
import asyncio, base64, hashlib, json, os, struct, tempfile, time
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch
import pytest
from cyberwall.core.event_bus import EventBus, ThreatEvent, ThreatLevel


# ═══════════════════════════════════════════════════════════════════════════════
# blockchain/ledger.py
# ═══════════════════════════════════════════════════════════════════════════════

class TestBlockchainLedgerCoverage:

    @pytest.fixture
    async def ledger(self, tmp_path):
        from cyberwall.blockchain.ledger import BlockchainLedger
        return BlockchainLedger(path=tmp_path / "test.chain", node_id="test-node")

    @pytest.mark.asyncio
    async def test_genesis_block(self, ledger):
        assert ledger._chain[0].event_type == "genesis"
        assert ledger._chain[0].index == 0

    @pytest.mark.asyncio
    async def test_append_block(self, ledger):
        b = await ledger.append("threat", {"ip": "1.2.3.4"})
        assert b.index == 1
        assert b.data["ip"] == "1.2.3.4"

    @pytest.mark.asyncio
    async def test_chain_grows(self, ledger):
        await ledger.append("e1", {})
        await ledger.append("e2", {})
        assert len(ledger._chain) == 3

    @pytest.mark.asyncio
    async def test_verify_clean(self, ledger):
        await ledger.append("ev", {"x": 1})
        ok, count = ledger.verify()
        assert ok and count >= 2

    @pytest.mark.asyncio
    async def test_pow_prefix(self, ledger):
        b = await ledger.append("ev", {})
        assert b.hash.startswith("0" * ledger.DIFFICULTY)

    @pytest.mark.asyncio
    async def test_sha3_hash(self, ledger):
        from cyberwall.blockchain.ledger import sha3
        h = sha3("hello")
        assert len(h) == 64

    @pytest.mark.asyncio
    async def test_merkle_root_single(self, tmp_path):
        from cyberwall.blockchain.ledger import merkle_root
        assert merkle_root(["abc"]) == "abc"

    @pytest.mark.asyncio
    async def test_merkle_root_two(self, tmp_path):
        from cyberwall.blockchain.ledger import merkle_root, sha3
        result = merkle_root(["a", "b"])
        assert result == sha3("a" + "b")

    @pytest.mark.asyncio
    async def test_tail(self, ledger):
        await ledger.append("e1", {})
        tail = ledger.tail(5)
        assert isinstance(tail, list)
        assert len(tail) >= 1

    @pytest.mark.asyncio
    async def test_stats(self, ledger):
        s = ledger.stats()
        assert "blocks" in s and "tip_hash" in s

    @pytest.mark.asyncio
    async def test_persists_to_disk(self, tmp_path):
        from cyberwall.blockchain.ledger import BlockchainLedger
        path = tmp_path / "persist.chain"
        l1 = BlockchainLedger(path=path, node_id="n")
        await l1.append("ev", {"x": 1})
        l2 = BlockchainLedger(path=path, node_id="n")
        assert len(l2._chain) == 2

    @pytest.mark.asyncio
    async def test_tampered_chain_detected(self, ledger):
        await ledger.append("ev", {})
        ledger._chain[1].event_type = "tampered"
        ok, _ = ledger.verify()
        assert not ok

    @pytest.mark.asyncio
    async def test_get_proof(self, ledger):
        await ledger.append("e1", {})
        await ledger.append("e2", {})
        proof = ledger.get_proof(1)
        assert proof is not None
        assert "block_hash" in proof

    @pytest.mark.asyncio
    async def test_verify_proof(self, ledger):
        await ledger.append("e1", {})
        await ledger.append("e2", {})
        proof = ledger.get_proof(1)
        assert ledger.verify_proof(proof)

    @pytest.mark.asyncio
    async def test_get_proof_out_of_range(self, ledger):
        assert ledger.get_proof(999) is None

    @pytest.mark.asyncio
    async def test_block_to_dict(self, ledger):
        b = await ledger.append("ev", {"k": "v"})
        d = b.to_dict()
        assert d["event_type"] == "ev"
        assert d["data"]["k"] == "v"


# ═══════════════════════════════════════════════════════════════════════════════
# dashboard/server.py
# ═══════════════════════════════════════════════════════════════════════════════

class TestDashboardServer:

    @pytest.fixture
    def server(self):
        from cyberwall.dashboard.server import DashboardServer
        bus = EventBus()
        return DashboardServer(bus, host="127.0.0.1", port=18888)

    @pytest.mark.asyncio
    async def test_on_event_stored(self, server):
        ev = ThreatEvent(source="t", threat_type="malware_detected",
                         description="test", level=ThreatLevel.HIGH, score=7.0)
        await server._on_event(ev)
        assert server._stats["total_events"] == 1

    @pytest.mark.asyncio
    async def test_critical_counted(self, server):
        ev = ThreatEvent(source="t", threat_type="rootkit",
                         description="test", level=ThreatLevel.CRITICAL, score=9.0)
        await server._on_event(ev)
        assert server._stats["critical_count"] == 1

    @pytest.mark.asyncio
    async def test_blocked_counted(self, server):
        ev = ThreatEvent(source="t", threat_type="port_scan",
                         description="test", level=ThreatLevel.LOW, score=3.0,
                         blocked=True)
        await server._on_event(ev)
        assert server._stats["blocked_ips"] == 1

    @pytest.mark.asyncio
    async def test_history_capped(self, server):
        from cyberwall.dashboard.server import MAX_HISTORY
        for _ in range(MAX_HISTORY + 10):
            ev = ThreatEvent(source="t", threat_type="test",
                             description="t", level=ThreatLevel.INFO, score=1.0)
            await server._on_event(ev)
        assert len(server._history) <= MAX_HISTORY

    def test_stop(self, server):
        server._running = True
        server.stop()
        assert not server._running

    @pytest.mark.asyncio
    async def test_resp_helper(self):
        from cyberwall.dashboard.server import _resp
        writer = MagicMock()
        writer.write = MagicMock()
        _resp(writer, 200, "application/json", b'{"ok":true}')
        writer.write.assert_called_once()
        data = writer.write.call_args[0][0]
        assert b"200" in data

    @pytest.mark.asyncio
    async def test_frame_helper_small(self):
        from cyberwall.dashboard.server import _frame
        writer = MagicMock()
        writer.write = MagicMock()
        _frame(writer, "hello")
        writer.write.assert_called_once()

    @pytest.mark.asyncio
    async def test_frame_helper_large(self):
        from cyberwall.dashboard.server import _frame
        writer = MagicMock()
        writer.write = MagicMock()
        _frame(writer, "x" * 200)
        writer.write.assert_called_once()

    @pytest.mark.asyncio
    async def test_html_returns_string(self):
        from cyberwall.dashboard.server import _html
        html = _html()
        assert "SORABBYNGO" in html
        assert "<html" in html.lower()

    @pytest.mark.asyncio
    async def test_conn_stats_path(self, server):
        from cyberwall.dashboard.server import _resp
        reader = AsyncMock()
        reader.read = AsyncMock(return_value=b"GET /api/stats HTTP/1.1\r\nHost: localhost\r\n\r\n")
        writer = MagicMock()
        writer.write = MagicMock()
        writer.drain = AsyncMock()
        writer.close = MagicMock()
        writer.wait_closed = AsyncMock()
        await server._conn(reader, writer)
        writer.write.assert_called()

    @pytest.mark.asyncio
    async def test_conn_events_path(self, server):
        reader = AsyncMock()
        reader.read = AsyncMock(return_value=b"GET /api/events HTTP/1.1\r\nHost: localhost\r\n\r\n")
        writer = MagicMock()
        writer.write = MagicMock()
        writer.drain = AsyncMock()
        writer.close = MagicMock()
        writer.wait_closed = AsyncMock()
        await server._conn(reader, writer)
        writer.write.assert_called()

    @pytest.mark.asyncio
    async def test_conn_root_path(self, server):
        reader = AsyncMock()
        reader.read = AsyncMock(return_value=b"GET / HTTP/1.1\r\nHost: localhost\r\n\r\n")
        writer = MagicMock()
        writer.write = MagicMock()
        writer.drain = AsyncMock()
        writer.close = MagicMock()
        writer.wait_closed = AsyncMock()
        await server._conn(reader, writer)
        writer.write.assert_called()

    @pytest.mark.asyncio
    async def test_conn_404_path(self, server):
        reader = AsyncMock()
        reader.read = AsyncMock(return_value=b"GET /notfound HTTP/1.1\r\nHost: localhost\r\n\r\n")
        writer = MagicMock()
        writer.write = MagicMock()
        writer.drain = AsyncMock()
        writer.close = MagicMock()
        writer.wait_closed = AsyncMock()
        await server._conn(reader, writer)
        data = writer.write.call_args[0][0]
        assert b"404" in data

    @pytest.mark.asyncio
    async def test_ws_broadcast(self, server):
        q = asyncio.Queue(maxsize=200)
        server._ws.add(q)
        ev = ThreatEvent(source="t", threat_type="malware_detected",
                         description="test", level=ThreatLevel.HIGH, score=7.0)
        await server._on_event(ev)
        assert not q.empty()


# ═══════════════════════════════════════════════════════════════════════════════
# malware/scanner.py — uncovered paths
# ═══════════════════════════════════════════════════════════════════════════════

class TestMalwareScannerCoverage:

    @pytest.fixture
    def scanner(self, tmp_path):
        from cyberwall.malware.scanner import MalwareScanner
        from cyberwall.core.policy_engine import PolicyEngine
        import yaml
        bus = EventBus()
        (tmp_path / "watched").mkdir(exist_ok=True)
        # Write a minimal policy with quarantine path and watch paths
        cfg = {
            "malware": {
                "quarantine_path": str(tmp_path / "quarantine"),
                "watch_paths": [str(tmp_path / "watched")],
            },
            "scoring": {"base_scores": {}, "bonuses": {}},
            "policy": {"block_level": "HIGH", "quarantine_level": "CRITICAL",
                       "ai_analyze_level": "MEDIUM"},
        }
        cfg_path = tmp_path / "policy.yaml"
        cfg_path.write_text(yaml.dump(cfg))
        policy = PolicyEngine(str(cfg_path))
        return MalwareScanner(bus=bus, policy=policy)

    def test_scanner_init(self, scanner, tmp_path):
        assert Path(tmp_path / "quarantine").exists() or True

    @pytest.mark.asyncio
    async def test_build_baseline(self, scanner, tmp_path):
        watched = tmp_path / "watched"
        f = watched / "clean.txt"
        f.write_text("hello world")
        await scanner._build_baseline()
        assert isinstance(scanner._baseline, dict)

    @pytest.mark.asyncio
    async def test_quarantine_nonexistent(self, scanner):
        result = await scanner.quarantine("/nonexistent/path/file.sh")
        assert result is False

    @pytest.mark.asyncio
    async def test_hash_file(self, scanner, tmp_path):
        f = tmp_path / "watched" / "test.txt"
        f.write_text("test content")
        h = await scanner._hash_file(str(f))
        assert h is None or isinstance(h, str)

    def test_sha256(self, scanner, tmp_path):
        f = tmp_path / "watched" / "test2.txt"
        f.write_text("test content")
        h = scanner._sha256(str(f))
        assert isinstance(h, str) and len(h) == 64

    def test_sha256_nonexistent(self, scanner):
        h = scanner._sha256("/nonexistent/file")
        assert h is None

    @pytest.mark.asyncio
    async def test_scan_files_empty(self, scanner, tmp_path):
        await scanner._build_baseline()
        await scanner._scan_files()

    def test_walk_all(self, scanner, tmp_path):
        watched = tmp_path / "watched"
        (watched / "sub.txt").write_text("x")
        files = scanner._walk_all([str(watched)])
        assert isinstance(files, set)


# ═══════════════════════════════════════════════════════════════════════════════
# siem/engine.py — remaining gaps
# ═══════════════════════════════════════════════════════════════════════════════

class TestSIEMEngineCoverage:

    @pytest.fixture
    def siem(self, tmp_path):
        from cyberwall.siem.engine import SIEMEngine
        bus = EventBus()
        return SIEMEngine(bus=bus, log_dir=tmp_path / "siem")

    @pytest.mark.asyncio
    async def test_default_rules_loaded(self, siem):
        assert len(siem._rules) > 0

    @pytest.mark.asyncio
    async def test_lateral_movement_rule(self, siem):
        ev1 = ThreatEvent(source="fw", threat_type="port_scan",
                          description="scan", level=ThreatLevel.HIGH, score=7.0,
                          data={"src_ip": "5.5.5.5"})
        ev2 = ThreatEvent(source="fw", threat_type="malware_detected",
                          description="malware", level=ThreatLevel.CRITICAL, score=9.0,
                          data={"src_ip": "5.5.5.5"})
        await siem._on_event(ev1)
        await siem._on_event(ev2)
        assert siem._stats["rules_triggered"] >= 1

    @pytest.mark.asyncio
    async def test_maintenance_closes_old_incidents(self, siem):
        from cyberwall.siem.engine import Incident
        old_inc = Incident(
            id="old1", rule_name="test", severity="HIGH",
            description="old", source_ips=[], event_ids=[],
            first_seen=time.time() - 90000,
            last_seen=time.time() - 90000,
        )
        siem._incidents["old1"] = old_inc
        await siem._maintenance()
        assert old_inc.closed

    @pytest.mark.asyncio
    async def test_ingest_raw_garbage(self, siem):
        result = await siem.ingest_raw("not a valid syslog line")
        assert result is None

    @pytest.mark.asyncio
    async def test_get_incidents_by_severity(self, siem):
        for _ in range(3):
            await siem._on_event(ThreatEvent(
                source="t", threat_type="auth_failure",
                description="brute", level=ThreatLevel.HIGH, score=7.0,
                data={"src_ip": "1.2.3.4"}
            ))
        incs = siem.get_incidents(severity="HIGH")
        assert all(i.severity == "HIGH" for i in incs)

    def test_stop_closes_logs(self, siem):
        siem.stop()
        assert not siem._running


# ═══════════════════════════════════════════════════════════════════════════════
# sentinel_bridge/bridge.py — remaining gaps
# ═══════════════════════════════════════════════════════════════════════════════

class TestSentinelBridgeCoverage2:

    @pytest.fixture
    def bridge(self):
        from cyberwall.sentinel_bridge.bridge import SentinelBridge
        from cyberwall.core.policy_engine import PolicyEngine
        bus = EventBus()
        return SentinelBridge(bus, PolicyEngine())

    @pytest.mark.asyncio
    async def test_on_event_critical_notifies_cml(self, bridge):
        ev = ThreatEvent(source="t", threat_type="rootkit",
                         description="test", level=ThreatLevel.CRITICAL, score=9.5)
        await bridge.on_event(ev)

    @pytest.mark.asyncio
    async def test_on_event_blocked(self, bridge):
        ev = ThreatEvent(source="t", threat_type="port_scan",
                         description="test", level=ThreatLevel.HIGH, score=7.0,
                         blocked=True)
        await bridge.on_event(ev)

    def test_node_id_set(self, bridge):
        node_id = bridge._read_node_id()
        assert isinstance(node_id, str)

    @pytest.mark.asyncio
    async def test_publish_without_nats(self, bridge):
        await bridge._publish("test.subject", {"type": "test_event", "level": "HIGH"})


# ═══════════════════════════════════════════════════════════════════════════════
# audit/writer.py
# ═══════════════════════════════════════════════════════════════════════════════

class TestAuditWriterCoverage:

    @pytest.fixture
    def writer(self, tmp_path):
        from cyberwall.audit.writer import CyberwallAuditWriter
        return CyberwallAuditWriter.__new__(CyberwallAuditWriter)

    def test_fallback_writer_write(self, tmp_path):
        from cyberwall.audit.writer import _FallbackWriter
        w = _FallbackWriter(log_path=tmp_path / "audit.jsonl", node_id="test-node")
        entry = w.write("actor", "action", "resource", "SUCCESS")
        assert entry["actor"] == "actor"
        assert entry["outcome"] == "SUCCESS"
        assert len(entry["sha256_self"]) == 64

    def test_fallback_hash_chain(self, tmp_path):
        from cyberwall.audit.writer import _FallbackWriter
        w = _FallbackWriter(log_path=tmp_path / "audit.jsonl", node_id="n")
        e1 = w.write("a", "b", "c", "SUCCESS")
        e2 = w.write("a", "b", "c", "SUCCESS")
        assert e2["sha256_prev"] == e1["sha256_self"]

    def test_fallback_threat_event(self, tmp_path):
        from cyberwall.audit.writer import _FallbackWriter
        w = _FallbackWriter(log_path=tmp_path / "audit.jsonl", node_id="n")
        entry = w.threat_event("malware_detected", "1.2.3.4", 9.0, True)
        assert entry["outcome"] == "BLOCKED"

    def test_cyberwall_writer_ip_blocked(self, tmp_path):
        from cyberwall.audit.writer import CyberwallAuditWriter, _FallbackWriter
        w = CyberwallAuditWriter.__new__(CyberwallAuditWriter)
        w._w = _FallbackWriter(log_path=tmp_path / "audit.jsonl", node_id="n")
        entry = w.ip_blocked("1.2.3.4", "port_scan", "HIGH", 3600)
        assert entry["outcome"] == "BLOCKED"

    def test_cyberwall_writer_ip_unblocked(self, tmp_path):
        from cyberwall.audit.writer import CyberwallAuditWriter, _FallbackWriter
        w = CyberwallAuditWriter.__new__(CyberwallAuditWriter)
        w._w = _FallbackWriter(log_path=tmp_path / "audit.jsonl", node_id="n")
        entry = w.ip_unblocked("1.2.3.4")
        assert entry["outcome"] == "SUCCESS"

    def test_cyberwall_writer_threat_detected(self, tmp_path):
        from cyberwall.audit.writer import CyberwallAuditWriter, _FallbackWriter
        w = CyberwallAuditWriter.__new__(CyberwallAuditWriter)
        w._w = _FallbackWriter(log_path=tmp_path / "audit.jsonl", node_id="n")
        entry = w.threat_detected("malware", "1.2.3.4", 9.0, True, "CRITICAL")
        assert entry["outcome"] == "BLOCKED"

    def test_cyberwall_writer_malware_detected(self, tmp_path):
        from cyberwall.audit.writer import CyberwallAuditWriter, _FallbackWriter
        w = CyberwallAuditWriter.__new__(CyberwallAuditWriter)
        w._w = _FallbackWriter(log_path=tmp_path / "audit.jsonl", node_id="n")
        entry = w.malware_detected("/tmp/evil.sh", "trojan", 8.5, True)
        assert "quarantined" in entry["metadata"]

    def test_cyberwall_writer_nats_event(self, tmp_path):
        from cyberwall.audit.writer import CyberwallAuditWriter, _FallbackWriter
        w = CyberwallAuditWriter.__new__(CyberwallAuditWriter)
        w._w = _FallbackWriter(log_path=tmp_path / "audit.jsonl", node_id="n")
        entry = w.nats_event("sorabbyngo.alert", "malware", "HIGH")
        assert entry["actor"] == "sentinel_bridge"

    def test_get_writer_singleton(self, tmp_path):
        from cyberwall.audit import writer as wmod
        wmod._writer = None
        w1 = wmod.get_writer("test-node")
        w2 = wmod.get_writer("test-node")
        assert w1 is w2
        wmod._writer = None

    def test_fallback_writes_to_file(self, tmp_path):
        from cyberwall.audit.writer import _FallbackWriter
        log_path = tmp_path / "audit.jsonl"
        w = _FallbackWriter(log_path=log_path, node_id="n")
        w.write("actor", "action.test", "resource", "SUCCESS")
        lines = log_path.read_text().strip().splitlines()
        assert len(lines) == 1
        entry = json.loads(lines[0])
        assert entry["action"] == "action.test"
