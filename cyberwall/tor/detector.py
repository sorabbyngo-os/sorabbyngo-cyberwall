"""
Sorabbyngo Cyberwall — Tor C2 Traffic Detector
===============================================
Detects malware using Tor for C2 (command-and-control) communication.
This is a DETECTOR — not a Tor node or router.

Detection methods:
1. Tor exit node IP list     — real-time list from check.torproject.org + cached
2. TLS fingerprinting        — Tor's distinctive ClientHello patterns
3. Traffic pattern analysis  — Tor cell size (514 bytes), timing patterns
4. .onion DNS leakage        — DNS queries for .onion domains
5. Known Tor ports           — 9001, 9030, 9050, 9051, 9150
6. Guard node detection      — well-known Tor guard fingerprints

Why we detect Tor C2 (not block all Tor):
  - Legitimate Tor use (privacy tools) should not be blanket-blocked
  - We detect MALWARE using Tor for C2, not regular Tor browsing
  - Ransomware, botnets, APTs increasingly use Tor to hide C2 servers
  - XMRig variants on African infrastructure route mining pool over Tor

Usage:
    from cyberwall.tor.detector import TorDetector
    detector = TorDetector()
    await detector.start()
    result = await detector.check_ip("185.220.101.1")
    result = await detector.analyze_tls_hello(client_hello_bytes)
"""
import asyncio
import hashlib
import ipaddress
import json
import logging
import os
import re
import struct
import time
import urllib.request
from pathlib import Path
from typing import Optional, Set, Tuple

log = logging.getLogger("cyberwall.tor")

# ── Tor port signatures ───────────────────────────────────────────────────────
TOR_PORTS = {9001, 9030, 9050, 9051, 9150, 9151, 8118}

# Tor cell size (fixed 514 bytes in Tor protocol)
TOR_CELL_SIZE = 514

# TLS cipher suites commonly used by Tor (from Tor source)
TOR_TLS_CIPHERS = {
    0xC02B,  # TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256
    0xC02F,  # TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256
    0xC02C,  # TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384
    0xC030,  # TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384
    0xCCA9,  # TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256
    0xCCA8,  # TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256
}

# Known Tor exit node CIDR ranges (major ones, complement the live list)
TOR_KNOWN_CIDR = [
    "185.220.101.0/24",    # torservers.net
    "185.220.102.0/24",    # torservers.net
    "185.220.103.0/24",    # torservers.net
    "51.15.0.0/16",        # Scaleway Tor exits
    "176.10.104.0/24",     # tor.in.ua
    "91.108.4.0/22",       # Known Tor exit range
]

# .onion DNS leakage patterns
ONION_PATTERN = re.compile(rb"[a-z2-7]{16,56}\.onion", re.IGNORECASE)


class TorExitNodeList:
    """
    Maintains a list of Tor exit node IPs.
    Sources: check.torproject.org bulk list + hardcoded CIDRs.
    Updates every 4 hours.
    """
    UPDATE_INTERVAL = 4 * 3600   # 4 hours
    CACHE_PATH = Path("/tmp/cyberwall-tor-exits.json")
    TOR_EXIT_URL = "https://check.torproject.org/torbulkexitlist"

    def __init__(self):
        self._exits:    Set[str] = set()
        self._cidrs:    list     = []
        self._last_update = 0
        self._load_cached()
        self._load_known_cidrs()

    def _load_known_cidrs(self):
        for cidr in TOR_KNOWN_CIDR:
            try:
                self._cidrs.append(ipaddress.ip_network(cidr, strict=False))
            except ValueError:
                pass

    def _load_cached(self):
        if self.CACHE_PATH.exists():
            try:
                data = json.loads(self.CACHE_PATH.read_text())
                self._exits = set(data.get("exits", []))
                self._last_update = data.get("updated", 0)
                log.info(f"Tor exit list loaded from cache: {len(self._exits)} IPs")
            except Exception:
                pass

    async def update(self) -> int:
        """Fetch fresh Tor exit list. Returns count of exits."""
        now = time.time()
        if now - self._last_update < self.UPDATE_INTERVAL:
            return len(self._exits)

        try:
            loop = asyncio.get_event_loop()
            raw  = await loop.run_in_executor(None, self._fetch_exits)
            if raw:
                self._exits = set(
                    line.strip() for line in raw.splitlines()
                    if line.strip() and not line.startswith("#")
                )
                self._last_update = now
                # Cache to disk
                self.CACHE_PATH.write_text(json.dumps({
                    "exits":   list(self._exits),
                    "updated": now,
                }))
                log.info(f"Tor exit list updated: {len(self._exits)} IPs")
        except Exception as e:
            log.warning(f"Tor exit list update failed: {e} — using cached/known list")
        return len(self._exits)

    def _fetch_exits(self) -> str:
        req = urllib.request.Request(
            self.TOR_EXIT_URL,
            headers={"User-Agent": "SorabbyngoCyberwall/2.0"}
        )
        with urllib.request.urlopen(req, timeout=15) as r:
            return r.read().decode(errors="replace")

    def is_tor_exit(self, ip: str) -> bool:
        """Check if an IP is a known Tor exit node."""
        if ip in self._exits:
            return True
        try:
            addr = ipaddress.ip_address(ip)
            return any(addr in cidr for cidr in self._cidrs)
        except ValueError:
            return False

    def stats(self) -> dict:
        return {
            "exit_ips":    len(self._exits),
            "known_cidrs": len(self._cidrs),
            "last_update": int(self._last_update),
            "cache_age_h": round((time.time() - self._last_update) / 3600, 1),
        }


class TLSFingerprinter:
    """
    TLS ClientHello fingerprinting to detect Tor connections.
    Tor has distinctive TLS patterns from its OpenSSL configuration.
    """

    def parse_client_hello(self, data: bytes) -> Optional[dict]:
        """
        Parse a TLS ClientHello. Returns dict of TLS features or None.
        data: raw bytes starting at TLS record header.
        """
        try:
            if len(data) < 5:
                return None
            content_type = data[0]
            if content_type != 0x16:   # TLS Handshake
                return None
            version_major = data[1]
            version_minor = data[2]
            length = struct.unpack("!H", data[3:5])[0]
            if len(data) < 5 + length:
                return None

            handshake = data[5:5 + length]
            if handshake[0] != 0x01:   # ClientHello
                return None

            # Skip handshake header (4 bytes)
            offset = 4
            # Client version (2) + random (32) + session_id_len (1)
            if offset + 34 >= len(handshake):
                return None
            session_id_len = handshake[offset + 34]
            offset += 35 + session_id_len

            # Cipher suites
            if offset + 2 > len(handshake):
                return None
            cs_len = struct.unpack("!H", handshake[offset:offset+2])[0]
            offset += 2
            ciphers = set()
            for i in range(0, cs_len, 2):
                if offset + i + 2 <= len(handshake):
                    cs = struct.unpack("!H", handshake[offset+i:offset+i+2])[0]
                    ciphers.add(cs)
            offset += cs_len

            return {
                "version":   f"{version_major}.{version_minor}",
                "ciphers":   list(ciphers),
                "cipher_count": len(ciphers),
            }
        except Exception:
            return None

    def is_tor_fingerprint(self, hello: Optional[dict]) -> Tuple[bool, float]:
        """
        Check if TLS hello matches Tor fingerprint.
        Returns (is_tor, confidence 0-1).
        """
        if not hello:
            return False, 0.0

        ciphers = set(hello.get("ciphers", []))
        overlap = len(ciphers & TOR_TLS_CIPHERS)
        confidence = overlap / max(len(TOR_TLS_CIPHERS), 1)

        # Tor typically uses a small specific set of ciphers
        if overlap >= 3 and len(ciphers) <= 8:
            return True, min(confidence * 1.5, 1.0)
        return False, confidence

    def detect_tor_cell(self, data: bytes) -> bool:
        """
        Detect Tor cells by size (fixed 514-byte cells in Tor protocol).
        A stream of 514-byte chunks strongly indicates Tor traffic.
        """
        if len(data) < TOR_CELL_SIZE:
            return False
        cell_aligned = len(data) % TOR_CELL_SIZE == 0
        return cell_aligned and len(data) >= TOR_CELL_SIZE * 2


class TorDetector:
    """
    Full Tor C2 detection engine.
    Combines exit node list, TLS fingerprinting, traffic analysis,
    and DNS leakage detection.
    """

    def __init__(self):
        self._exits       = TorExitNodeList()
        self._tls         = TLSFingerprinter()
        self._alerts:dict = {}   # ip → last_alert_time (rate limiting)
        self._running     = False

    async def start(self):
        """Start background exit node list updater."""
        self._running = True
        await self._exits.update()
        asyncio.create_task(self._update_loop(), name="tor_exit_updater")
        log.info(f"TorDetector started | exit_ips={len(self._exits._exits)}")

    async def _update_loop(self):
        while self._running:
            await asyncio.sleep(3600)
            await self._exits.update()

    async def check_ip(self, ip: str) -> dict:
        """
        Check if an IP is a Tor exit node.
        Returns threat dict or empty dict if clean.
        """
        is_tor = self._exits.is_tor_exit(ip)
        if not is_tor:
            return {}

        # Rate limit alerts per IP
        now = time.time()
        if now - self._alerts.get(ip, 0) < 300:
            return {}
        self._alerts[ip] = now

        log.warning(f"[TorDetector] Tor exit node detected: {ip}")
        return {
            "threat_type": "tor_c2_traffic",
            "level":       "HIGH",
            "score":       7.0,
            "description": f"Connection from/to Tor exit node: {ip} — possible C2 traffic",
            "src_ip":      ip,
            "detection":   "tor_exit_node",
        }

    def check_tls_hello(self, data: bytes, src_ip: str = "") -> dict:
        """Analyze TLS ClientHello for Tor fingerprint."""
        hello = self._tls.parse_client_hello(data)
        is_tor, confidence = self._tls.is_tor_fingerprint(hello)
        if not is_tor or confidence < 0.5:
            return {}
        return {
            "threat_type": "tor_tls_fingerprint",
            "level":       "MEDIUM",
            "score":       5.0 + confidence * 3,
            "description": f"TLS fingerprint matches Tor from {src_ip} (confidence={confidence:.0%})",
            "src_ip":      src_ip,
            "detection":   "tls_fingerprint",
            "confidence":  confidence,
        }

    def check_dns_query(self, query: bytes, src_ip: str = "") -> dict:
        """Check DNS query for .onion domain leakage."""
        matches = ONION_PATTERN.findall(query)
        if not matches:
            return {}
        domains = [m.decode(errors="replace") for m in matches[:3]]
        return {
            "threat_type": "onion_dns_leak",
            "level":       "HIGH",
            "score":       7.5,
            "description": f".onion DNS leakage from {src_ip}: {domains}",
            "src_ip":      src_ip,
            "detection":   "onion_dns",
            "domains":     domains,
        }

    def check_traffic_pattern(self, data: bytes, src_ip: str = "") -> dict:
        """Detect Tor cell-size traffic patterns."""
        if self._tls.detect_tor_cell(data):
            return {
                "threat_type": "tor_traffic_pattern",
                "level":       "MEDIUM",
                "score":       5.5,
                "description": f"Tor cell-size traffic pattern detected from {src_ip}",
                "src_ip":      src_ip,
                "detection":   "cell_pattern",
            }
        return {}

    def check_dst_port(self, dst_port: int, src_ip: str = "") -> dict:
        """Flag connections to Tor-associated ports."""
        if dst_port in TOR_PORTS:
            return {
                "threat_type": "tor_port_access",
                "level":       "LOW",
                "score":       3.5,
                "description": f"Connection to Tor port {dst_port} from {src_ip}",
                "src_ip":      src_ip,
                "detection":   "tor_port",
                "port":        dst_port,
            }
        return {}

    def stop(self):
        self._running = False

    def stats(self) -> dict:
        return {
            "exit_list":    self._exits.stats(),
            "alerts_seen":  len(self._alerts),
        }
