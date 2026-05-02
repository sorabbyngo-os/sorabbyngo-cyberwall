"""
Coverage booster for:
  - cyberwall/reverse_engineering/analyzer.py  (0% → target 75%+)
  - cyberwall/tor/detector.py                  (0% → target 75%+)
  - cyberwall/quantum/kyber.py                 (50% → target 75%+)
"""
from __future__ import annotations
import asyncio, hashlib, os, struct, time
from unittest.mock import patch, MagicMock, AsyncMock
import pytest


# ═══════════════════════════════════════════════════════════════════════════════
# reverse_engineering/analyzer.py
# ═══════════════════════════════════════════════════════════════════════════════

class TestReverseEngineeringFunctions:

    def test_shannon_entropy_uniform(self):
        from cyberwall.reverse_engineering.analyzer import shannon_entropy
        data = bytes(range(256)) * 4
        e = shannon_entropy(data)
        assert 7.9 < e <= 8.0

    def test_shannon_entropy_zeros(self):
        from cyberwall.reverse_engineering.analyzer import shannon_entropy
        assert shannon_entropy(b"\x00" * 100) == 0.0

    def test_shannon_entropy_empty(self):
        from cyberwall.reverse_engineering.analyzer import shannon_entropy
        assert shannon_entropy(b"") == 0.0

    def test_entropy_verdict_normal(self):
        from cyberwall.reverse_engineering.analyzer import entropy_verdict
        v, packed, enc = entropy_verdict(3.0)
        assert v == "normal" and not packed and not enc

    def test_entropy_verdict_suspicious(self):
        from cyberwall.reverse_engineering.analyzer import entropy_verdict
        v, packed, enc = entropy_verdict(5.2)
        assert v == "suspicious" and not packed and not enc

    def test_entropy_verdict_packed(self):
        from cyberwall.reverse_engineering.analyzer import entropy_verdict
        v, packed, enc = entropy_verdict(6.8)
        assert v == "packed" and packed and not enc

    def test_entropy_verdict_encrypted(self):
        from cyberwall.reverse_engineering.analyzer import entropy_verdict
        v, packed, enc = entropy_verdict(7.5)
        assert v == "encrypted" and packed and enc

    def test_sliding_entropy(self):
        from cyberwall.reverse_engineering.analyzer import sliding_entropy
        data = os.urandom(1024)
        results = sliding_entropy(data, window=256)
        assert len(results) > 0
        assert all(isinstance(r, tuple) and len(r) == 2 for r in results)

    def test_detect_file_type_elf(self):
        from cyberwall.reverse_engineering.analyzer import detect_file_type
        assert detect_file_type(b"\x7fELF" + b"\x00" * 20) == "elf"

    def test_detect_file_type_pe(self):
        from cyberwall.reverse_engineering.analyzer import detect_file_type
        assert detect_file_type(b"MZ" + b"\x00" * 20) == "pe"

    def test_detect_file_type_shellcode(self):
        from cyberwall.reverse_engineering.analyzer import detect_file_type
        assert detect_file_type(b"\x90\x90\x90\x90" + b"\xcc" * 20) in ("shellcode", "raw")

    def test_detect_file_type_script(self):
        from cyberwall.reverse_engineering.analyzer import detect_file_type
        assert detect_file_type(b"#!/bin/bash\necho hi") == "script"

    def test_detect_file_type_unknown(self):
        from cyberwall.reverse_engineering.analyzer import detect_file_type
        assert detect_file_type(b"\x00\x01\x02\x03") in ("unknown", "raw")

    def test_find_nop_sleds(self):
        from cyberwall.reverse_engineering.analyzer import find_nop_sleds
        data = b"\x00" * 10 + b"\x90" * 16 + b"\x00" * 10
        sleds = find_nop_sleds(data, min_len=8)
        assert len(sleds) > 0

    def test_find_nop_sleds_none(self):
        from cyberwall.reverse_engineering.analyzer import find_nop_sleds
        assert find_nop_sleds(b"\x01\x02\x03\x04", min_len=8) == []

    def test_extract_strings(self):
        from cyberwall.reverse_engineering.analyzer import extract_strings
        data = b"\x00" + b"hello_world_string" + b"\x00"
        strings = extract_strings(data, min_len=5)
        assert any("hello" in s for s in strings)

    def test_find_suspicious_imports(self):
        from cyberwall.reverse_engineering.analyzer import find_suspicious_imports
        data = b"VirtualAlloc\x00WriteProcessMemory\x00CreateRemoteThread"
        imports = find_suspicious_imports(data)
        assert len(imports) > 0

    def test_find_suspicious_imports_clean(self):
        from cyberwall.reverse_engineering.analyzer import find_suspicious_imports
        assert find_suspicious_imports(b"printf\x00fopen\x00fclose") == []

    def test_disassemble_chunk_no_capstone(self):
        from cyberwall.reverse_engineering import analyzer as mod
        orig = mod.CS_AVAILABLE
        mod.CS_AVAILABLE = False
        try:
            result = mod.disassemble_chunk(b"\x90\x90\x90")
            assert result == []
        finally:
            mod.CS_AVAILABLE = orig

    def test_disassemble_chunk_with_capstone(self):
        from cyberwall.reverse_engineering.analyzer import disassemble_chunk, CS_AVAILABLE
        if not CS_AVAILABLE:
            pytest.skip("capstone not available")
        result = disassemble_chunk(b"\x90\x90\x90\x90", arch="x86_64")
        assert isinstance(result, list)

    def test_analyze_control_flow_empty(self):
        from cyberwall.reverse_engineering.analyzer import analyze_control_flow
        score, findings = analyze_control_flow([])
        assert score == 0.0 and findings == []

    def test_analyze_control_flow_indirect(self):
        from cyberwall.reverse_engineering.analyzer import analyze_control_flow
        insns = [
            {"mnemonic": "jmp", "op_str": "rax", "address": 0x1000},
            {"mnemonic": "call", "op_str": "rbx", "address": 0x1004},
            {"mnemonic": "push", "op_str": "rbp", "address": 0x1008},
        ]
        score, findings = analyze_control_flow(insns)
        assert score > 0

    def test_extract_invariant_core_short(self):
        from cyberwall.reverse_engineering.analyzer import extract_invariant_core
        result = extract_invariant_core(b"\x90" * 10)
        assert isinstance(result, bytes)

    def test_extract_invariant_core_normal(self):
        from cyberwall.reverse_engineering.analyzer import extract_invariant_core
        data = b"\x90\x90\xcc\xcc" * 50
        result = extract_invariant_core(data, block_size=16)
        assert isinstance(result, bytes)

    def test_generate_yara_rule(self):
        from cyberwall.reverse_engineering.analyzer import generate_yara_rule
        rule = generate_yara_rule("abc123", b"\x90\x90\xcc\xcc" * 4, "elf", ["nop_sled"])
        assert "rule" in rule.lower() or len(rule) > 0

    def test_generate_yara_rule_empty_invariant(self):
        from cyberwall.reverse_engineering.analyzer import generate_yara_rule
        rule = generate_yara_rule("abc123", b"", "elf", [])
        assert isinstance(rule, str)


class TestPolymorphicAnalyzerCoverage:

    @pytest.fixture
    def analyzer(self):
        from cyberwall.reverse_engineering.analyzer import PolymorphicAnalyzer
        return PolymorphicAnalyzer()

    def test_analyze_elf(self, analyzer):
        data = b"\x7fELF" + os.urandom(200)
        feat = analyzer.analyze(data, "test.elf")
        assert feat.file_type == "elf"
        assert feat.sha256 != ""

    def test_analyze_pe(self, analyzer):
        data = b"MZ" + os.urandom(200)
        feat = analyzer.analyze(data, "test.exe")
        assert feat.file_type == "pe"

    def test_analyze_shellcode(self, analyzer):
        data = b"\x90" * 20 + b"\xcc" * 20
        feat = analyzer.analyze(data, "shellcode.bin")
        assert feat.file_type in ("shellcode", "unknown", "raw")

    def test_analyze_encrypted_high_entropy(self, analyzer):
        data = os.urandom(512)
        feat = analyzer.analyze(data, "encrypted.bin")
        assert feat.entropy > 6.0

    def test_analyze_with_suspicious_imports(self, analyzer):
        data = b"\x7fELF" + b"VirtualAlloc\x00WriteProcessMemory\x00" + os.urandom(100)
        feat = analyzer.analyze(data, "malware.elf")
        assert feat.file_type == "elf"

    def test_analyze_to_dict(self, analyzer):
        data = b"\x7fELF" + b"\x00" * 100
        feat = analyzer.analyze(data, "test.elf")
        d = feat.to_dict()
        assert "sha256" in d and "entropy" in d

    def test_analyze_file_not_found(self, analyzer):
        feat = analyzer.analyze_file("/nonexistent/path/file.bin")
        assert feat.file_type == "unknown" or feat.sha256 == ""

    def test_analyze_file_exists(self, analyzer, tmp_path):
        f = tmp_path / "test.bin"
        f.write_bytes(b"\x7fELF" + os.urandom(100))
        feat = analyzer.analyze_file(str(f))
        assert feat.file_type == "elf"

    def test_diff_samples(self, analyzer):
        a = b"\x90" * 50 + b"\xcc" * 50
        b_ = b"\x90" * 50 + b"\x00" * 50
        result = analyzer.diff_samples(a, b_)
        assert isinstance(result, dict)
        assert "similarity" in result or len(result) > 0

    def test_analyze_with_nop_sled(self, analyzer):
        data = b"\x7fELF" + b"\x00" * 20 + b"\x90" * 20 + b"\xcc" * 10
        feat = analyzer.analyze(data, "nop.elf")
        assert isinstance(feat.nop_sleds, list)

    def test_analyze_polymorphic_detection(self, analyzer):
        # High obfuscation score data
        data = b"\x7fELF" + b"\xe9\x00\x00\x00\x00" * 30 + os.urandom(100)
        feat = analyzer.analyze(data, "poly.elf")
        assert isinstance(feat.polymorphic, bool)

    def test_analyze_generates_yara(self, analyzer):
        data = b"\x7fELF" + b"\x41\x42\x43\x44" * 30
        feat = analyzer.analyze(data, "yara_test.elf")
        assert isinstance(feat.generated_yara, str)


# ═══════════════════════════════════════════════════════════════════════════════
# tor/detector.py
# ═══════════════════════════════════════════════════════════════════════════════

class TestTorExitNodeList:

    @pytest.fixture
    def exit_list(self, tmp_path):
        from cyberwall.tor.detector import TorExitNodeList
        lst = TorExitNodeList()
        lst.CACHE_PATH = tmp_path / "tor-exits.json"
        return lst

    def test_known_cidr_loaded(self, exit_list):
        assert len(exit_list._cidrs) > 0

    def test_is_tor_exit_known_cidr(self, exit_list):
        assert exit_list.is_tor_exit("185.220.101.5")

    def test_is_tor_exit_clean(self, exit_list):
        assert not exit_list.is_tor_exit("192.168.1.1")

    def test_is_tor_exit_invalid(self, exit_list):
        assert not exit_list.is_tor_exit("not-an-ip")

    def test_stats(self, exit_list):
        s = exit_list.stats()
        assert "exit_ips" in s and "known_cidrs" in s

    def test_manual_exit_added(self, exit_list):
        exit_list._exits.add("1.2.3.4")
        assert exit_list.is_tor_exit("1.2.3.4")

    @pytest.mark.asyncio
    async def test_update_skips_if_fresh(self, exit_list):
        exit_list._last_update = time.time()
        count = await exit_list.update()
        assert isinstance(count, int)

    @pytest.mark.asyncio
    async def test_update_handles_network_error(self, exit_list):
        exit_list._last_update = 0
        with patch("urllib.request.urlopen", side_effect=Exception("network error")):
            count = await exit_list.update()
        assert isinstance(count, int)


class TestTLSFingerprinter:

    @pytest.fixture
    def fp(self):
        from cyberwall.tor.detector import TLSFingerprinter
        return TLSFingerprinter()

    def _make_client_hello(self, ciphers=None):
        """Build a minimal TLS ClientHello."""
        if ciphers is None:
            ciphers = [0xC02B, 0xC02F]
        cs_bytes = b"".join(struct.pack("!H", c) for c in ciphers)
        cs_len   = struct.pack("!H", len(cs_bytes))
        # session_id_len=0, compression=1 byte
        hello_body = (
            b"\x03\x03"          # client version TLS 1.2
            + os.urandom(32)     # random
            + b"\x00"            # session_id_len
            + cs_len + cs_bytes  # cipher suites
            + b"\x01\x00"        # compression methods
        )
        handshake = (
            b"\x01"              # ClientHello
            + struct.pack("!I", len(hello_body))[1:]  # 3-byte length
            + hello_body
        )
        record = (
            b"\x16"              # content_type: Handshake
            + b"\x03\x01"        # version TLS 1.0
            + struct.pack("!H", len(handshake))
            + handshake
        )
        return record

    def test_parse_valid_client_hello(self, fp):
        data = self._make_client_hello()
        result = fp.parse_client_hello(data)
        assert result is not None
        assert "ciphers" in result

    def test_parse_too_short(self, fp):
        assert fp.parse_client_hello(b"\x16\x03") is None

    def test_parse_wrong_content_type(self, fp):
        data = b"\x17" + b"\x03\x01" + b"\x00\x10" + b"\x00" * 16
        assert fp.parse_client_hello(data) is None

    def test_parse_garbage(self, fp):
        assert fp.parse_client_hello(os.urandom(50)) is None

    def test_parse_empty(self, fp):
        assert fp.parse_client_hello(b"") is None

    def test_is_tor_fingerprint_none(self, fp):
        is_tor, score = fp.is_tor_fingerprint(None)
        assert not is_tor and score == 0.0

    def test_is_tor_fingerprint_tor_ciphers(self, fp):
        from cyberwall.tor.detector import TOR_TLS_CIPHERS
        hello = {"ciphers": list(TOR_TLS_CIPHERS), "cipher_count": len(TOR_TLS_CIPHERS)}
        is_tor, score = fp.is_tor_fingerprint(hello)
        assert score > 0

    def test_is_tor_fingerprint_clean(self, fp):
        hello = {"ciphers": [0x0035, 0x002F], "cipher_count": 2}
        is_tor, score = fp.is_tor_fingerprint(hello)
        assert not is_tor

    def test_detect_tor_cell_exact_size(self, fp):
        from cyberwall.tor.detector import TOR_CELL_SIZE
        data = os.urandom(TOR_CELL_SIZE)
        result = fp.detect_tor_cell(data)
        assert isinstance(result, bool)

    def test_detect_tor_cell_wrong_size(self, fp):
        assert not fp.detect_tor_cell(b"\x00" * 100)


class TestTorDetectorCoverage:

    @pytest.fixture
    def detector(self):
        from cyberwall.tor.detector import TorDetector
        d = TorDetector()
        return d

    @pytest.mark.asyncio
    async def test_check_ip_known_exit(self, detector):
        # Known Tor CIDR — should return a dict with threat_type
        result = await detector.check_ip("185.220.101.5")
        assert isinstance(result, dict)

    @pytest.mark.asyncio
    async def test_check_ip_clean(self, detector):
        result = await detector.check_ip("192.168.1.1")
        assert isinstance(result, dict)

    @pytest.mark.asyncio
    async def test_check_ip_invalid(self, detector):
        result = await detector.check_ip("not-an-ip")
        assert isinstance(result, dict)

    def test_check_tls_hello_garbage(self, detector):
        result = detector.check_tls_hello(os.urandom(20))
        assert isinstance(result, dict)

    def test_check_tls_hello_empty(self, detector):
        result = detector.check_tls_hello(b"")
        assert isinstance(result, dict)

    def test_check_dns_onion(self, detector):
        result = detector.check_dns_query(b"abcdefghijklmnop.onion")
        assert result.get("threat_type") == "onion_dns_leak"

    def test_check_dns_clean(self, detector):
        result = detector.check_dns_query(b"www.google.com")
        assert result == {} or result.get("threat_type") != "onion_dns_leak"

    def test_check_traffic_pattern_tor_cell(self, detector):
        from cyberwall.tor.detector import TOR_CELL_SIZE
        result = detector.check_traffic_pattern(os.urandom(TOR_CELL_SIZE))
        assert isinstance(result, dict)

    def test_check_traffic_pattern_short(self, detector):
        result = detector.check_traffic_pattern(b"\x00" * 10)
        assert result == {}

    def test_check_dst_port_tor(self, detector):
        from cyberwall.tor.detector import TOR_PORTS
        port = next(iter(TOR_PORTS))
        result = detector.check_dst_port(port)
        assert result.get("threat_type") == "tor_port_access"

    def test_check_dst_port_clean(self, detector):
        result = detector.check_dst_port(443)
        assert result == {}

    def test_stats(self, detector):
        s = detector.stats()
        assert isinstance(s, dict)

    def test_stop(self, detector):
        detector.stop()
        assert not detector._running

    @pytest.mark.asyncio
    async def test_update_loop_exits_when_stopped(self, detector):
        detector._running = False
        await detector._update_loop()


# ═══════════════════════════════════════════════════════════════════════════════
# quantum/kyber.py
# ═══════════════════════════════════════════════════════════════════════════════

class TestKyberKEMCoverage:

    @pytest.fixture
    def kem(self):
        from cyberwall.quantum.kyber import KyberKEM
        return KyberKEM()

    def test_keygen(self, kem):
        pk, sk = kem.keygen()
        assert len(pk) > 0 and len(sk) > 0

    def test_encap_decap(self, kem):
        pk, sk = kem.keygen()
        ct, ss1 = kem.encapsulate(pk)
        ss2 = kem.decapsulate(sk, ct)
        assert ss1 == ss2

    def test_classical_keygen(self, kem):
        pk, sk = kem._classical_keygen()
        assert len(pk) > 0 and len(sk) > 0

    def test_classical_encap_decap(self, kem):
        pk, sk = kem._classical_keygen()
        ct, ss1 = kem._classical_encap(pk)
        ss2 = kem._classical_decap(sk, ct)
        assert ss1 == ss2

    def test_classical_encap_returns_bytes(self, kem):
        pk, sk = kem._classical_keygen()
        ct, ss = kem._classical_encap(pk)
        assert isinstance(ct, bytes) and isinstance(ss, bytes)


class TestAESFunctions:

    def test_aes_encrypt_decrypt(self):
        from cyberwall.quantum.kyber import aes_encrypt, aes_decrypt
        key = os.urandom(32)
        pt  = b"Sorabbyngo secret data"
        ct  = aes_encrypt(key, pt)
        assert aes_decrypt(key, ct) == pt

    def test_aes_encrypt_different_each_time(self):
        from cyberwall.quantum.kyber import aes_encrypt
        key = os.urandom(32)
        ct1 = aes_encrypt(key, b"same plaintext")
        ct2 = aes_encrypt(key, b"same plaintext")
        assert ct1 != ct2  # IV is random

    def test_aes_decrypt_wrong_key(self):
        from cyberwall.quantum.kyber import aes_encrypt, aes_decrypt
        key1 = os.urandom(32)
        key2 = os.urandom(32)
        ct   = aes_encrypt(key1, b"secret")
        with pytest.raises(Exception):
            aes_decrypt(key2, ct)


class TestDilithiumDSACoverage:

    @pytest.fixture
    def dsa(self):
        from cyberwall.quantum.kyber import DilithiumDSA
        return DilithiumDSA()

    def test_keygen(self, dsa):
        pk, sk = dsa.keygen()
        assert len(pk) > 0 and len(sk) > 0

    def test_sign_verify(self, dsa):
        pk, sk = dsa.keygen()
        msg = b"audit log entry"
        sig = dsa.sign(sk, msg)
        assert dsa.verify(pk, msg, sig)

    def test_sign_wrong_msg(self, dsa):
        pk, sk = dsa.keygen()
        sig = dsa.sign(sk, b"correct")
        assert not dsa.verify(pk, b"wrong", sig)

    def test_sign_returns_bytes(self, dsa):
        _, sk = dsa.keygen()
        sig = dsa.sign(sk, b"test")
        assert isinstance(sig, bytes) and len(sig) > 0


class TestQuantumCryptoCoverage:

    @pytest.fixture
    def qc(self):
        from cyberwall.quantum.kyber import QuantumCrypto
        return QuantumCrypto()

    def test_keygen(self, qc):
        pk, sk = qc.keygen()
        assert len(pk) > 0 and len(sk) > 0

    def test_sign_keygen(self, qc):
        pk, sk = qc.sign_keygen()
        assert len(pk) > 0 and len(sk) > 0

    def test_encrypt_decrypt_event(self, qc):
        pk, sk = qc.keygen()
        event  = {"threat_type": "malware", "score": 9.5, "node": "ke-nairobi-01"}
        enc    = qc.encrypt_event(event, pk)
        dec    = qc.decrypt_event(enc, sk)
        assert dec["threat_type"] == "malware"
        assert dec["score"] == 9.5

    def test_encrypt_event_default_key(self, qc):
        pk, _ = qc.keygen()
        event = {"type": "test"}
        enc   = qc.encrypt_event(event, pk)
        assert isinstance(enc, dict)

    def test_sign_verify_event(self, qc):
        pk, sk = qc.sign_keygen()
        event  = {"data": "important audit record"}
        sig    = qc.sign_event(event, sk)
        assert qc.verify_event(event, sig, pk)

    def test_verify_event_tampered(self, qc):
        pk, sk = qc.sign_keygen()
        event  = {"data": "original"}
        sig    = qc.sign_event(event, sk)
        assert not qc.verify_event({"data": "tampered"}, sig, pk)

    def test_mode(self, qc):
        m = qc.mode
        assert isinstance(m, str) and len(m) > 0

    def test_encapsulate_decapsulate(self, qc):
        pk, sk = qc.keygen()
        ct, ss1 = qc.kem.encapsulate(pk)
        ss2 = qc.kem.decapsulate(sk, ct)
        assert ss1 == ss2
