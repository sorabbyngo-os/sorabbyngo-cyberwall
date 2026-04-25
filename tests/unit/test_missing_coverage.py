"""
Sorabbyngo Cyberwall — Missing Coverage Tests
Covers: AIAnalyzer, EBPFLoader/EBPFManager, SentinelBridge (NATS paths),
        FirewallEngine (block/unblock/rate), SyscallWatcher (proc scan)
"""
import asyncio
import json
import os
import tempfile
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch, PropertyMock
import pytest

from cyberwall.core.event_bus import EventBus, ThreatEvent, ThreatLevel
from cyberwall.core.policy_engine import PolicyEngine
from cyberwall.ai.analyzer import AIAnalyzer
from cyberwall.firewall.ebpf.bpf_loader import EBPFLoader
from cyberwall.firewall.ebpf.ebpf_manager import EBPFManager
from cyberwall.sentinel_bridge.bridge import SentinelBridge
from cyberwall.malware.syscall_watcher import SyscallWatcher
from cyberwall.firewall.engine import FirewallEngine, RateLimiter


# ══════════════════════════════════════════════════════════════════════════════
# Shared fixtures
# ══════════════════════════════════════════════════════════════════════════════

@pytest.fixture
def bus():
    return EventBus()


@pytest.fixture
def policy():
    return PolicyEngine()


@pytest.fixture
def make_event():
    def _make(
        threat_type="port_scan",
        level=ThreatLevel.MEDIUM,
        score=5.0,
        src_ip="1.2.3.4",
        path=None,
    ):
        data = {"src_ip": src_ip}
        if path:
            data["path"] = path
        return ThreatEvent(
            source="test",
            threat_type=threat_type,
            level=level,
            score=score,
            description=f"test {threat_type}",
            data=data,
        )
    return _make


# ══════════════════════════════════════════════════════════════════════════════
# AIAnalyzer
# ══════════════════════════════════════════════════════════════════════════════

class TestAIAnalyzer:
    @pytest.fixture
    def analyzer(self, bus, policy):
        return AIAnalyzer(bus, policy)

    def test_init(self, analyzer):
        assert analyzer._queue is not None
        assert analyzer.model == "phi4-mini"
        assert not analyzer._running

    async def test_enqueue_skips_low_events(self, analyzer, make_event):
        event = make_event(level=ThreatLevel.LOW, score=3.0)
        await analyzer._enqueue(event)
        assert analyzer._queue.empty()

    async def test_enqueue_accepts_medium_events(self, analyzer, make_event):
        event = make_event(level=ThreatLevel.MEDIUM, score=5.0)
        await analyzer._enqueue(event)
        assert analyzer._queue.qsize() == 1

    async def test_enqueue_accepts_critical_events(self, analyzer, make_event):
        event = make_event(level=ThreatLevel.CRITICAL, score=9.5)
        await analyzer._enqueue(event)
        assert analyzer._queue.qsize() == 1

    async def test_analyze_returns_dict_on_success(self, analyzer, make_event):
        event = make_event(level=ThreatLevel.HIGH, score=8.0)
        mock_response = json.dumps({
            "response": json.dumps({
                "severity": "HIGH",
                "summary": "Port scan detected",
                "attack_vector": "port_scan",
                "recommended_action": "block",
                "false_positive_probability": 0.1,
            })
        }).encode()

        with patch.object(analyzer, "_http_post", return_value=mock_response.decode()):
            result = await analyzer._analyze(event)

        assert result["severity"] == "HIGH"
        assert result["attack_vector"] == "port_scan"
        assert "false_positive_probability" in result

    async def test_analyze_falls_back_when_ollama_down(self, analyzer, make_event):
        import urllib.error
        event = make_event(level=ThreatLevel.HIGH, score=8.0)

        with patch.object(
            analyzer, "_http_post",
            side_effect=urllib.error.URLError("connection refused")
        ):
            result = await analyzer._analyze(event)

        assert result["source"] == "rule_based_fallback"
        assert result["severity"] == "HIGH"
        assert result["recommended_action"] == "block"

    async def test_analyze_falls_back_on_json_error(self, analyzer, make_event):
        event = make_event(level=ThreatLevel.MEDIUM, score=5.0)

        with patch.object(analyzer, "_http_post", return_value='{"response": "not json"}'):
            result = await analyzer._analyze(event)

        assert result["source"] == "rule_based_fallback"

    def test_rule_based_fallback_critical(self, analyzer, make_event):
        event = make_event(level=ThreatLevel.CRITICAL, score=9.5)
        result = analyzer._rule_based_fallback(event)
        assert result["severity"] == "CRITICAL"
        assert result["recommended_action"] == "block"

    def test_rule_based_fallback_low(self, analyzer, make_event):
        event = make_event(level=ThreatLevel.LOW, score=2.0)
        result = analyzer._rule_based_fallback(event)
        assert result["severity"] == "INFO"
        assert result["recommended_action"] == "monitor"

    def test_rule_based_fallback_medium(self, analyzer, make_event):
        event = make_event(level=ThreatLevel.MEDIUM, score=5.5)
        result = analyzer._rule_based_fallback(event)
        assert result["severity"] == "MEDIUM"

    def test_stop(self, analyzer):
        analyzer._running = True
        analyzer.stop()
        assert not analyzer._running


# ══════════════════════════════════════════════════════════════════════════════
# EBPFLoader
# ══════════════════════════════════════════════════════════════════════════════

class TestEBPFLoader:
    @pytest.fixture
    def loader(self, bus):
        return EBPFLoader(bus, interface="eth0")

    def test_init(self, loader):
        assert loader.interface == "eth0"
        assert not loader._loaded
        assert not loader._running

    def test_load_fails_without_root(self, loader):
        with patch("os.geteuid", return_value=1000):
            result = loader.load()
        assert result is False
        assert not loader._loaded

    def test_load_fails_without_bcc(self, loader):
        with patch("os.geteuid", return_value=0):
            with patch.dict("sys.modules", {"bcc": None}):
                result = loader.load()
        assert result is False

    def test_load_fails_if_no_bpf_file(self, loader):
        with patch("os.geteuid", return_value=0):
            with patch(
                "cyberwall.firewall.ebpf.bpf_loader.BPF_PROGRAM",
                Path("/nonexistent/bpf_program.c")
            ):
                result = loader.load()
        assert result is False

    def test_block_ip_when_not_loaded(self, loader):
        result = loader.block_ip("1.2.3.4")
        assert result is False

    def test_unblock_ip_when_not_loaded(self, loader):
        result = loader.unblock_ip("1.2.3.4")
        assert result is False

    def test_get_stats_returns_dict(self, loader):
        stats = loader.get_stats()
        assert isinstance(stats, dict)

    def test_stop_when_not_loaded(self, loader):
        loader.stop()  # should not raise
        assert not loader._loaded

    async def test_start_returns_immediately_if_not_loaded(self, loader):
        loader._loaded = False
        await asyncio.wait_for(loader.start(), timeout=0.5)  # should return fast

    def test_block_ip_with_mock_bpf(self, loader):
        mock_bpf = MagicMock()
        mock_map = MagicMock()
        mock_key = MagicMock()
        mock_bpf.__getitem__ = MagicMock(return_value=mock_map)
        mock_map.Key = MagicMock(return_value=mock_key)
        loader._bpf = mock_bpf
        loader._loaded = True

        result = loader.block_ip("192.168.1.1")
        assert result is True

    def test_unblock_ip_with_mock_bpf(self, loader):
        mock_bpf = MagicMock()
        mock_map = MagicMock()
        mock_key = MagicMock()
        mock_bpf.__getitem__ = MagicMock(return_value=mock_map)
        mock_map.Key = MagicMock(return_value=mock_key)
        loader._bpf = mock_bpf
        loader._loaded = True

        result = loader.unblock_ip("192.168.1.1")
        assert result is True

    def test_stop_removes_xdp(self, loader):
        mock_bpf = MagicMock()
        loader._bpf = mock_bpf
        loader._loaded = True
        loader.stop()
        mock_bpf.remove_xdp.assert_called_once_with("eth0", 0)
        assert not loader._loaded


# ══════════════════════════════════════════════════════════════════════════════
# EBPFManager
# ══════════════════════════════════════════════════════════════════════════════

class TestEBPFManager:
    @pytest.fixture
    def manager(self, bus, policy):
        return EBPFManager(bus, policy)

    def test_init(self, manager):
        assert not manager._active
        assert manager.loader is not None

    def test_setup_returns_false_without_root(self, manager):
        with patch("os.geteuid", return_value=1000):
            result = manager.setup()
        assert result is False
        assert not manager.is_active()

    def test_block_ip_when_inactive(self, manager):
        result = manager.block_ip("1.2.3.4")
        assert result is False

    def test_unblock_ip_when_inactive(self, manager):
        manager.unblock_ip("1.2.3.4")  # should not raise

    def test_stats_when_inactive(self, manager):
        stats = manager.stats()
        assert isinstance(stats, dict)

    def test_is_active_default_false(self, manager):
        assert not manager.is_active()

    def test_stop_when_inactive(self, manager):
        manager.stop()  # should not raise

    def test_block_ip_when_active(self, manager):
        manager._active = True
        with patch.object(manager.loader, "block_ip", return_value=True) as mock:
            result = manager.block_ip("10.0.0.1")
        assert result is True
        mock.assert_called_once_with("10.0.0.1")

    def test_unblock_ip_when_active(self, manager):
        manager._active = True
        with patch.object(manager.loader, "unblock_ip", return_value=True) as mock:
            manager.unblock_ip("10.0.0.1")
        mock.assert_called_once_with("10.0.0.1")


# ══════════════════════════════════════════════════════════════════════════════
# SentinelBridge — NATS paths
# ══════════════════════════════════════════════════════════════════════════════

class TestSentinelBridgeNATS:
    @pytest.fixture
    def bridge(self, bus, policy):
        with patch(
            "cyberwall.sentinel_bridge.bridge.NATS_AVAILABLE", True
        ):
            b = SentinelBridge(bus, policy, nats_url="nats://localhost:4222")
        return b

    def test_node_id_from_env(self):
        from cyberwall.core.event_bus import EventBus
        from cyberwall.core.policy_engine import PolicyEngine
        from cyberwall.sentinel_bridge.bridge import SentinelBridge
        bus = EventBus()
        policy = PolicyEngine()
        with patch.dict(os.environ, {"SORABBYNGO_NODE_ID": "test-node-123"}),              patch("builtins.open", side_effect=FileNotFoundError):
            b = SentinelBridge(bus, policy, nats_url="nats://localhost:4222")
            assert b._node_id == "test-node-123"

    async def test_publish_logs_when_no_nats(self, bridge, make_event):
        bridge._nc = None
        event = make_event(level=ThreatLevel.HIGH, score=8.0)
        # Should not raise — logs only
        await bridge._publish("sorabbyngo.cyberwall.alert", event.to_dict())

    async def test_on_event_publishes_alert_on_high(self, bridge, make_event):
        bridge._nc = None
        event = make_event(level=ThreatLevel.HIGH, score=8.0)
        with patch.object(bridge, "_publish", new_callable=AsyncMock) as mock_pub:
            await bridge.on_event(event)
        subjects = [call.args[0] for call in mock_pub.call_args_list]
        assert "sorabbyngo.cyberwall.alert" in subjects

    async def test_on_event_publishes_block_when_blocked(self, bridge, make_event):
        bridge._nc = None
        event = make_event(level=ThreatLevel.HIGH, score=8.0)
        event.blocked = True
        with patch.object(bridge, "_publish", new_callable=AsyncMock) as mock_pub:
            await bridge.on_event(event)
        subjects = [call.args[0] for call in mock_pub.call_args_list]
        assert "sorabbyngo.cyberwall.block" in subjects

    async def test_on_event_sends_to_cml_on_high(self, bridge, make_event):
        bridge._nc = None
        event = make_event(level=ThreatLevel.HIGH, score=8.0)
        with patch.object(bridge, "_send_to_cml", new_callable=AsyncMock) as mock_cml:
            await bridge.on_event(event)
        mock_cml.assert_called_once_with(event)

    async def test_cml_payload_structure(self, bridge, make_event):
        bridge._nc = None
        event = make_event(level=ThreatLevel.HIGH, score=8.0)
        published = []

        async def capture(subject, data):
            published.append((subject, data))

        with patch.object(bridge, "_publish", side_effect=capture):
            await bridge._send_to_cml(event)

        assert len(published) == 1
        subject, payload = published[0]
        assert subject == "sorabbyngo.cml.filter.request"
        assert "threat_level" in payload
        assert payload["component"] == "cyberwall"

    async def test_stop_with_no_nats(self, bridge):
        bridge._nc = None
        await bridge.stop()  # should not raise

    async def test_stop_closes_nats_connection(self, bridge):
        mock_nc = AsyncMock()
        bridge._nc = mock_nc
        await bridge.stop()
        mock_nc.close.assert_called_once()


# ══════════════════════════════════════════════════════════════════════════════
# SyscallWatcher — proc scan paths
# ══════════════════════════════════════════════════════════════════════════════

class TestSyscallWatcherProc:
    @pytest.fixture
    def watcher(self, bus):
        return SyscallWatcher(bus)

    async def test_check_pid_detects_memfd(self, watcher):
        events = []
        async def capture(event):
            events.append(event)
        watcher.bus.subscribe("*", capture)

        maps_content = "/memfd:malware (deleted)\n"
        with patch("builtins.open", MagicMock(
            return_value=MagicMock(
                __enter__=MagicMock(return_value=MagicMock(read=MagicMock(return_value=maps_content))),
                __exit__=MagicMock(return_value=False)
            )
        )):
            await watcher._check_pid("1234")

        assert len(events) > 0 or "1234" in watcher._alerted

    async def test_check_pid_detects_deleted_exe(self, watcher):
        maps_content = "/usr/bin/sshd (deleted)\n"
        events = []
        async def capture(e): events.append(e)
        watcher.bus.subscribe("*", capture)

        with patch("builtins.open", MagicMock(
            return_value=MagicMock(
                __enter__=MagicMock(return_value=MagicMock(read=MagicMock(return_value=maps_content))),
                __exit__=MagicMock(return_value=False)
            )
        )):
            await watcher._check_pid("5678")

        assert len(events) > 0 or "5678" in watcher._alerted

    async def test_check_pid_skips_already_alerted(self, watcher):
        watcher._alerted.add("9999")
        events = []
        async def capture(e): events.append(e)
        watcher.bus.subscribe("*", capture)
        await watcher._check_pid("9999")
        assert len(events) == 0

    async def test_scan_proc_handles_permission_error(self, watcher):
        with patch("os.listdir", side_effect=PermissionError):
            await watcher._scan_proc()  # should not raise

    def test_stop_clears_alerted(self, watcher):
        watcher._alerted = {"123", "456"}
        watcher.stop()
        assert len(watcher._alerted) == 0
        assert not watcher._running

    async def test_emit_publishes_event(self, watcher):
        events = []
        async def capture(e): events.append(e)

        async def run_bus():
            await watcher.bus.run()

        task = asyncio.create_task(run_bus())
        watcher.bus.subscribe("*", capture)

        await watcher._emit("1234", "process_injection", "test", {"pid": "1234"})
        await asyncio.sleep(0.05)
        task.cancel()

        assert any(e.threat_type == "process_injection" for e in events)


# ══════════════════════════════════════════════════════════════════════════════
# FirewallEngine — block/unblock/rate limit paths
# ══════════════════════════════════════════════════════════════════════════════

class TestFirewallEngineCoverage:
    @pytest.fixture
    def engine(self, bus, policy):
        return FirewallEngine(bus, policy)

    def test_init(self, engine):
        assert engine._rate is not None
        assert engine._audit is not None
        assert engine.blocked_count() == 0

    async def test_block_invalid_ip(self, engine):
        result = await engine.block_ip("not-an-ip")
        assert result is False

    async def test_block_ip_idempotent(self, engine):
        with patch.object(engine, "_nft_run", new_callable=AsyncMock, return_value=True):
            await engine.block_ip("1.2.3.4")
            await engine.block_ip("1.2.3.4")  # second call — idempotent
        assert engine.blocked_count() == 1

    async def test_block_ip_adds_to_blocked(self, engine):
        with patch.object(engine, "_nft_run", new_callable=AsyncMock, return_value=True):
            result = await engine.block_ip("10.0.0.1", reason="test")
        assert engine._is_blocked("10.0.0.1")

    async def test_unblock_ip_removes_from_blocked(self, engine):
        engine._add_to_blocked("10.0.0.2")
        with patch.object(engine, "_nft_run", new_callable=AsyncMock, return_value=True):
            await engine.unblock_ip("10.0.0.2")
        assert not engine._is_blocked("10.0.0.2")

    def test_check_rate_allows_first_request(self, engine):
        result = engine.check_rate("ssh", "1.2.3.4")
        assert result is True

    def test_check_rate_blocks_after_burst(self, engine):
        # Exhaust the SSH burst (10)
        for _ in range(15):
            engine.check_rate("ssh", "9.9.9.9")
        result = engine.check_rate("ssh", "9.9.9.9")
        assert result is False

    async def test_track_creates_connection_state(self, engine):
        state = await engine.track("192.168.1.1", 443)
        assert state.src_ip == "192.168.1.1"
        assert 443 in state.port_hits

    async def test_track_detects_port_scan(self, engine):
        with patch.object(engine, "block_ip", new_callable=AsyncMock) as mock_block:
            for port in range(21):
                await engine.track("172.16.0.1", port)
        mock_block.assert_called()

    def test_nft_run_handles_missing_binary(self, engine):
        async def run():
            return await engine._nft_run("nft list tables")
        # Should return False gracefully if nft not found or no root
        result = asyncio.get_event_loop().run_until_complete(run())
        assert isinstance(result, bool)

    def test_stop(self, engine):
        engine.stop()
        assert not engine._running


# ══════════════════════════════════════════════════════════════════════════════
# RateLimiter
# ══════════════════════════════════════════════════════════════════════════════

class TestRateLimiterCoverage:
    @pytest.fixture
    def limiter(self):
        return RateLimiter({
            "ssh":  {"limit": "5/minute",   "burst": 5},
            "http": {"limit": "60/minute",  "burst": 10},
        })

    def test_allows_within_burst(self, limiter):
        for _ in range(5):
            assert limiter.check("ssh", "1.1.1.1") is True

    def test_blocks_after_burst(self, limiter):
        for _ in range(6):
            limiter.check("ssh", "2.2.2.2")
        assert limiter.check("ssh", "2.2.2.2") is False

    def test_different_ips_independent(self, limiter):
        for _ in range(6):
            limiter.check("ssh", "3.3.3.3")
        # Different IP should still be allowed
        assert limiter.check("ssh", "4.4.4.4") is True

    def test_unknown_service_uses_default(self, limiter):
        result = limiter.check("unknown_service", "5.5.5.5")
        assert result is True

    def test_evict_stale_buckets(self, limiter):
        limiter.check("ssh", "6.6.6.6")
        assert len(limiter._buckets) > 0
        limiter.evict_stale(max_age=0)
        assert len(limiter._buckets) == 0
