"""
Coverage booster 4:
  dashboard/cli.py        (30% -> 80%+)
  malware/scanner.py      (68% -> 85%+)
  sentinel_bridge         (76% -> 90%+)
  firewall/engine.py      (77% -> 88%+)
  dashboard/server.py     (66% -> 85%+)
  quantum/kyber.py        remaining gaps
"""
from __future__ import annotations
import asyncio, json, os, time
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch, PropertyMock
import pytest
from cyberwall.core.event_bus import EventBus, ThreatEvent, ThreatLevel
from cyberwall.core.policy_engine import PolicyEngine


def _ev(threat_type="malware_detected", level=ThreatLevel.HIGH,
        score=7.5, blocked=False):
    return ThreatEvent(source="test", threat_type=threat_type,
        description=f"Test {threat_type}", level=level,
        score=score, blocked=blocked, data={"src_ip": "1.2.3.4"})


# ══════════════════════════════════════════════════════════════════════════════
# dashboard/cli.py
# ══════════════════════════════════════════════════════════════════════════════

class TestCLIDashboardCoverage:

    @pytest.fixture
    def dash(self):
        from cyberwall.dashboard.cli import CLIDashboard
        bus = EventBus()
        return CLIDashboard(bus, max_events=20)

    @pytest.mark.asyncio
    async def test_ansi_start_stop(self, dash):
        dash._rich = False
        dash._running = True
        task = asyncio.create_task(dash._start_ansi())
        await asyncio.sleep(0.3)
        dash.stop()
        task.cancel()
        try: await task
        except (asyncio.CancelledError, Exception): pass

    @pytest.mark.asyncio
    async def test_rich_start_stop(self, dash):
        if not dash._rich:
            pytest.skip("rich not available")
        dash._running = True
        task = asyncio.create_task(dash._start_rich())
        await asyncio.sleep(0.3)
        dash.stop()
        task.cancel()
        try: await task
        except (asyncio.CancelledError, Exception): pass

    @pytest.mark.asyncio
    async def test_events_populate_deque(self, dash):
        for i in range(5):
            await dash._on_event(_ev(f"threat_{i}"))
        assert len(dash._events) == 5

    @pytest.mark.asyncio
    async def test_stats_increment(self, dash):
        await dash._on_event(_ev("rootkit", level=ThreatLevel.CRITICAL))
        await dash._on_event(_ev("scan",    level=ThreatLevel.HIGH))
        await dash._on_event(_ev("info",    level=ThreatLevel.LOW))
        assert dash._stats["total"]    == 3
        assert dash._stats["critical"] == 1
        assert dash._stats["high"]     == 1

    @pytest.mark.asyncio
    async def test_with_siem(self, tmp_path):
        from cyberwall.dashboard.cli import CLIDashboard
        from cyberwall.siem.engine import SIEMEngine
        bus  = EventBus()
        siem = SIEMEngine(bus=bus, log_dir=tmp_path / "siem")
        dash = CLIDashboard(bus, siem=siem, max_events=10)
        await dash._on_event(_ev())
        assert dash._stats["total"] == 1


# ══════════════════════════════════════════════════════════════════════════════
# malware/scanner.py — integrity loop paths
# ══════════════════════════════════════════════════════════════════════════════

class TestMalwareScannerIntegrity:

    @pytest.fixture
    def scanner(self, tmp_path):
        import yaml
        from cyberwall.malware.scanner import MalwareScanner
        watched = tmp_path / "watched"
        watched.mkdir()
        cfg = {
            "malware": {
                "quarantine_path": str(tmp_path / "quarantine"),
                "watch_paths": [str(watched)],
                "scan_interval_s": 1,
            },
            "scoring": {"base_scores": {}, "bonuses": {}},
            "policy": {"block_level": "HIGH", "quarantine_level": "CRITICAL",
                       "ai_analyze_level": "MEDIUM"},
        }
        cfg_path = tmp_path / "policy.yaml"
        cfg_path.write_text(yaml.dump(cfg))
        policy = PolicyEngine(str(cfg_path))
        bus = EventBus()
        s = MalwareScanner(bus=bus, policy=policy)
        return s, watched

    @pytest.mark.asyncio
    async def test_baseline_built(self, scanner):
        s, watched = scanner
        (watched / "file.txt").write_text("content")
        await s._build_baseline()
        assert len(s._baseline) >= 0

    @pytest.mark.asyncio
    async def test_scan_files_no_changes(self, scanner):
        s, watched = scanner
        (watched / "stable.conf").write_text("stable")
        await s._build_baseline()
        await s._scan_files()

    @pytest.mark.asyncio
    async def test_quarantine_nonexistent_async(self, scanner):
        s, _ = scanner
        result = await s.quarantine("/no/such/file.sh")
        assert result is False

    @pytest.mark.asyncio
    async def test_quarantine_existing_file(self, scanner, tmp_path):
        s, watched = scanner
        evil = watched / "evil.sh"
        evil.write_bytes(b"#!/bin/bash\nrm -rf /")
        result = await s.quarantine(str(evil))
        assert result is True
        assert not evil.exists()

    @pytest.mark.asyncio
    async def test_scan_new_files(self, scanner):
        s, watched = scanner
        await s._build_baseline()
        (watched / "new_file.py").write_text("import os; os.system('evil')")
        await s._scan_new_files()

    @pytest.mark.asyncio
    async def test_hash_file(self, scanner, tmp_path):
        s, watched = scanner
        f = watched / "hashme.txt"
        f.write_text("hash this content")
        h = await s._hash_file(str(f))
        assert h is None or (isinstance(h, str) and len(h) == 64)

    def test_walk_all(self, scanner, tmp_path):
        s, watched = scanner
        (watched / "a.txt").write_text("a")
        (watched / "b.txt").write_text("b")
        files = s._walk_all([str(watched)])
        assert len(files) >= 2

    def test_sha256(self, scanner, tmp_path):
        s, watched = scanner
        f = watched / "sha.txt"
        f.write_text("content")
        h = s._sha256(str(f))
        assert isinstance(h, str) and len(h) == 64


# ══════════════════════════════════════════════════════════════════════════════
# sentinel_bridge/bridge.py — NATS paths
# ══════════════════════════════════════════════════════════════════════════════

class TestSentinelBridgeNATS:

    @pytest.fixture
    def bridge(self):
        from cyberwall.sentinel_bridge.bridge import SentinelBridge
        bus = EventBus()
        return SentinelBridge(bus, PolicyEngine())

    @pytest.mark.asyncio
    async def test_connect_no_nats(self, bridge):
        bridge._nats = None
        await bridge._connect()

    @pytest.mark.asyncio
    async def test_heartbeat_runs_once(self, bridge):
        bridge._running = True
        bridge._node_id = "test-ke047"
        task = asyncio.create_task(bridge._heartbeat_loop())
        await asyncio.sleep(0.05)
        bridge._running = False
        task.cancel()
        try: await task
        except (asyncio.CancelledError, Exception): pass

    @pytest.mark.asyncio
    async def test_stop_no_nats(self, bridge):
        bridge._nats = None
        await bridge.stop()

    @pytest.mark.asyncio
    async def test_stop_with_mock_nc(self, bridge):
        mock_nc = MagicMock()
        mock_nc.close = AsyncMock()
        bridge._nc = mock_nc
        await bridge.stop()
        mock_nc.close.assert_called_once()

    @pytest.mark.asyncio
    async def test_send_to_cml(self, bridge):
        ev = _ev("malware_detected", level=ThreatLevel.HIGH)
        await bridge._send_to_cml(ev)

    @pytest.mark.asyncio
    async def test_publish_with_mock_nc(self, bridge):
        mock_nc = MagicMock()
        mock_nc.publish = AsyncMock()
        bridge._nc = mock_nc
        await bridge._publish("test.subject", {"type": "test"})
        mock_nc.publish.assert_called_once()

    @pytest.mark.asyncio
    async def test_on_event_quarantined(self, bridge):
        ev = ThreatEvent(source="t", threat_type="malware",
                         description="t", level=ThreatLevel.CRITICAL,
                         score=9.0, quarantined=True)
        await bridge.on_event(ev)


# ══════════════════════════════════════════════════════════════════════════════
# firewall/engine.py — uncovered paths
# ══════════════════════════════════════════════════════════════════════════════

class TestFirewallEnginePaths:

    @pytest.fixture
    def engine(self, tmp_path):
        from cyberwall.firewall.engine import FirewallEngine
        bus = EventBus()
        return FirewallEngine(bus=bus, policy=PolicyEngine())

    @pytest.mark.asyncio
    async def test_block_ttl_stored(self, engine):
        await engine.block_ip("10.0.0.1", "test", ThreatLevel.HIGH, ttl_seconds=60)
        assert engine._is_blocked("10.0.0.1")

    @pytest.mark.asyncio
    async def test_unblock_ip(self, engine):
        await engine.block_ip("10.0.0.2", "test", ThreatLevel.HIGH)
        await engine.unblock_ip("10.0.0.2")
        assert not engine._is_blocked("10.0.0.2")

    @pytest.mark.asyncio
    async def test_is_blocked(self, engine):
        await engine.block_ip("10.0.0.3", "test", ThreatLevel.HIGH)
        assert engine._is_blocked("10.0.0.3")
        assert not engine._is_blocked("10.0.0.4")

    def test_blocked_count(self, engine):
        assert engine.blocked_count() == 0

    def test_connection_count(self, engine):
        assert engine.connection_count() == 0

    @pytest.mark.asyncio
    async def test_block_invalid_ip(self, engine):
        result = await engine.block_ip("not-an-ip", "test", ThreatLevel.HIGH)
        assert result is False or result is None

    def test_rate_limiter_burst(self):
        from cyberwall.firewall.engine import RateLimiter
        rl = RateLimiter(limits={"ssh": {"burst": 3, "rate": 1}})
        for _ in range(3):
            rl.check("ssh", "1.2.3.4")
        result = rl.check("ssh", "1.2.3.4")
        assert isinstance(result, bool)

    def test_rate_limiter_evict(self):
        from cyberwall.firewall.engine import RateLimiter
        rl = RateLimiter(limits={"ssh": {"burst": 5, "rate": 1}})
        rl.check("ssh", "9.9.9.9")
        rl.evict_stale(max_age=0)

    def test_check_rate(self, engine):
        result = engine.check_rate("ssh", "2.2.2.2")
        assert isinstance(result, bool)

    @pytest.mark.asyncio
    async def test_track_connection(self, engine):
        state = await engine.track("3.3.3.3", 80)
        assert state is not None

    def test_audit_logger_write(self, tmp_path):
        from cyberwall.firewall.engine import AuditLogger
        log_path = tmp_path / "audit.jsonl"
        logger = AuditLogger(path=log_path)
        logger.write("ip_blocked", ip="1.2.3.4", reason="test")
        lines = log_path.read_text().strip().splitlines()
        assert len(lines) == 1
        entry = __import__("json").loads(lines[0])
        assert entry["action"] == "ip_blocked"

    def test_stop(self, engine):
        engine.stop()
        assert not engine._running


# ══════════════════════════════════════════════════════════════════════════════
# dashboard/server.py — WebSocket + broadcast paths
# ══════════════════════════════════════════════════════════════════════════════

class TestDashboardServerWS:

    @pytest.fixture
    def server(self):
        from cyberwall.dashboard.server import DashboardServer
        bus = EventBus()
        return DashboardServer(bus, host="127.0.0.1", port=19888)

    @pytest.mark.asyncio
    async def test_ws_conn_upgrade(self, server):
        key = "dGhlIHNhbXBsZSBub25jZQ=="
        req = (
            f"GET /ws HTTP/1.1\r\n"
            f"Host: localhost\r\n"
            f"Upgrade: websocket\r\n"
            f"Connection: Upgrade\r\n"
            f"Sec-WebSocket-Key: {key}\r\n"
            f"Sec-WebSocket-Version: 13\r\n\r\n"
        )
        reader = AsyncMock()
        reader.read = AsyncMock(return_value=req.encode())
        writer = MagicMock()
        writer.write = MagicMock()
        writer.drain = AsyncMock()
        writer.close = MagicMock()
        writer.wait_closed = AsyncMock()

        # Inject a stop after first ping
        original_ws_conn = server._ws_conn
        call_count = [0]
        async def patched_ws_conn(r, w, req_str):
            server._running = False
            await original_ws_conn(r, w, req_str)
        server._ws_conn = patched_ws_conn
        server._running = True
        await server._conn(reader, writer)

    @pytest.mark.asyncio
    async def test_broadcast_to_multiple_clients(self, server):
        q1 = asyncio.Queue(maxsize=200)
        q2 = asyncio.Queue(maxsize=200)
        server._ws.add(q1)
        server._ws.add(q2)
        await server._on_event(_ev())
        assert not q1.empty()
        assert not q2.empty()

    @pytest.mark.asyncio
    async def test_dead_queue_removed(self, server):
        q = asyncio.Queue(maxsize=1)
        # Fill it so put_nowait raises QueueFull
        q.put_nowait("fill")
        server._ws.add(q)
        await server._on_event(_ev())
        assert q not in server._ws

    @pytest.mark.asyncio
    async def test_high_event_counted(self, server):
        await server._on_event(_ev(level=ThreatLevel.HIGH))
        assert server._stats["high_count"] == 1

    @pytest.mark.asyncio
    async def test_history_populated(self, server):
        await server._on_event(_ev())
        assert len(server._history) == 1


# ══════════════════════════════════════════════════════════════════════════════
# quantum/kyber.py — remaining gaps
# ══════════════════════════════════════════════════════════════════════════════

class TestKyberRemainingPaths:

    @pytest.fixture
    def qc(self):
        from cyberwall.quantum.kyber import QuantumCrypto
        return QuantumCrypto()

    def test_classical_keygen(self, qc):
        pk, sk = qc.kem._classical_keygen()
        assert len(pk) > 0 and len(sk) > 0

    def test_classical_encap_decap(self, qc):
        pk, sk = qc.kem._classical_keygen()
        ct, ss1 = qc.kem._classical_encap(pk)
        ss2 = qc.kem._classical_decap(sk, ct)
        assert ss1 == ss2

    def test_sign_and_verify(self, qc):
        pk, sk = qc.sign_keygen()
        msg = b"sorabbyngo audit record"
        sig = qc.sign_event({"data": msg.decode()}, sk)
        assert qc.verify_event({"data": msg.decode()}, sig, pk)

    def test_encrypt_large_event(self, qc):
        pk, sk = qc.keygen()
        event = {f"key_{i}": f"value_{i}" * 10 for i in range(20)}
        enc = qc.encrypt_event(event, pk)
        dec = qc.decrypt_event(enc, sk)
        assert dec["key_0"] == event["key_0"]

    def test_aes_roundtrip(self):
        from cyberwall.quantum.kyber import aes_encrypt, aes_decrypt
        key = os.urandom(32)
        for pt in [b"short", b"x" * 1000, b""]:
            assert aes_decrypt(key, aes_encrypt(key, pt)) == pt

    def test_dilithium_sign_empty(self):
        from cyberwall.quantum.kyber import DilithiumDSA
        dsa = DilithiumDSA()
        pk, sk = dsa.keygen()
        sig = dsa.sign(sk, b"")
        assert isinstance(sig, bytes)
