"""
Sorabbyngo Cyberwall — Audit Writer Bridge
Wraps sorabbyngo-security/audit/audit_writer.py for use inside cyberwall.
Falls back to plain JSONL if the security repo is not available.
"""
import hashlib
import json
import logging
import os
import sys
import threading
from datetime import datetime, timezone
from pathlib import Path

logger = logging.getLogger("cyberwall.audit")

# Try to import the canonical audit writer from sorabbyngo-security
_SECURITY_PATHS = [
    Path(__file__).parent.parent.parent.parent / "sorabbyngo-security" / "audit",
    Path.home() / "sorabbyngo-security" / "audit",
    Path("/opt/sorabbyngo/security/audit"),
]

_AuditWriter = None
for _p in _SECURITY_PATHS:
    if (_p / "audit_writer.py").exists():
        if str(_p) not in sys.path:
            sys.path.insert(0, str(_p))
        try:
            from audit_writer import AuditWriter as _AuditWriter
            logger.info(f"Using canonical AuditWriter from {_p}")
            break
        except ImportError:
            pass

if _AuditWriter is None:
    logger.warning("sorabbyngo-security AuditWriter not found — using fallback")


class _FallbackWriter:
    """Plain JSONL fallback when security repo is not available."""
    def __init__(self, log_path=None, node_id=None):
        self._node_id = node_id or os.environ.get("SORABBYNGO_NODE_ID", "unknown")
        self._lock = threading.Lock()
        self._prev = "0" * 64
        if log_path is None:
            for candidate in [
                Path("/var/log/sorabbyngo/cyberwall-audit.jsonl"),
                Path("/tmp/cyberwall-audit.jsonl"),
            ]:
                try:
                    candidate.parent.mkdir(parents=True, exist_ok=True)
                    candidate.touch()
                    log_path = candidate
                    break
                except Exception:
                    continue
        self._path = log_path

    @staticmethod
    def _hash(e):
        return hashlib.sha256(
            json.dumps({k: v for k, v in e.items() if k != "sha256_self"},
                       sort_keys=True).encode()
        ).hexdigest()

    def write(self, actor, action, resource, outcome, metadata=None, service=None):
        with self._lock:
            e = {
                "ts": datetime.now(timezone.utc).isoformat(),
                "node_id": self._node_id,
                "service": service or "cyberwall",
                "actor": actor,
                "action": action,
                "resource": resource,
                "outcome": outcome.upper(),
                "metadata": metadata or {},
                "sha256_prev": self._prev,
                "sha256_self": "",
            }
            e["sha256_self"] = self._hash(e)
            self._prev = e["sha256_self"]
            if self._path:
                with open(self._path, "a", buffering=1) as f:
                    f.write(json.dumps(e) + "\n")
            return e

    def threat_event(self, threat_type, src_ip, score, blocked):
        return self.write(
            "cyberwall", f"threat.{threat_type}",
            f"network/{src_ip}", "BLOCKED" if blocked else "DETECTED",
            {"score": score, "src_ip": src_ip}, "cyberwall"
        )


class CyberwallAuditWriter:
    """
    Unified audit writer for cyberwall.
    Uses canonical AuditWriter if available, falls back to _FallbackWriter.
    Provides cyberwall-specific convenience methods.
    """
    def __init__(self, node_id: str = None):
        self._node_id = node_id or os.environ.get("SORABBYNGO_NODE_ID", "unknown")
        log_path = None
        for candidate in [
            Path("/var/log/sorabbyngo/cyberwall-audit.jsonl"),
            Path("/tmp/cyberwall-audit.jsonl"),
        ]:
            try:
                candidate.parent.mkdir(parents=True, exist_ok=True)
                candidate.touch()
                log_path = candidate
                break
            except Exception:
                continue

        WriterClass = _AuditWriter if _AuditWriter is not None else _FallbackWriter
        self._w = WriterClass(log_path=log_path, node_id=self._node_id)

    def ip_blocked(self, ip: str, reason: str, level: str, ttl: int):
        return self._w.write(
            actor="firewall", action="security.block",
            resource=f"network/ip/{ip}", outcome="BLOCKED",
            metadata={"reason": reason, "level": level, "ttl_seconds": ttl},
            service="cyberwall"
        )

    def ip_unblocked(self, ip: str):
        return self._w.write(
            actor="firewall", action="security.unblock",
            resource=f"network/ip/{ip}", outcome="SUCCESS",
            service="cyberwall"
        )

    def threat_detected(self, threat_type: str, src_ip: str, score: float,
                        blocked: bool, level: str, description: str = ""):
        return self._w.write(
            actor="cyberwall", action=f"security.threat",
            resource=f"network/{src_ip}", outcome="BLOCKED" if blocked else "DETECTED",
            metadata={
                "threat_type": threat_type, "score": score,
                "level": level, "src_ip": src_ip, "description": description
            },
            service="cyberwall"
        )

    def ruleset_applied(self, interface: str, ports: list):
        return self._w.write(
            actor="firewall", action="system.config_change",
            resource="firewall/ruleset", outcome="SUCCESS",
            metadata={"interface": interface, "ports": ports},
            service="cyberwall"
        )

    def close(self):
        """No-op — underlying writer manages its own file handles."""
        pass

    def nats_event(self, subject: str, threat_type: str, level: str):
        return self._w.write(
            actor="sentinel_bridge", action="security.threat",
            resource=f"nats/{subject}", outcome="DETECTED",
            metadata={"subject": subject, "threat_type": threat_type, "level": level},
            service="cyberwall"
        )

    def malware_detected(self, path: str, threat_type: str, score: float,
                         quarantined: bool):
        return self._w.write(
            actor="malware_scanner", action="security.threat",
            resource=f"file/{path}", outcome="BLOCKED" if quarantined else "DETECTED",
            metadata={"threat_type": threat_type, "score": score,
                      "quarantined": quarantined, "path": path},
            service="cyberwall"
        )


# Module-level singleton
_writer: CyberwallAuditWriter | None = None
_writer_lock = threading.Lock()

def get_writer(node_id: str = None) -> CyberwallAuditWriter:
    """Get the process-level singleton audit writer."""
    global _writer
    if _writer is None:
        with _writer_lock:
            if _writer is None:
                _writer = CyberwallAuditWriter(node_id=node_id)
    return _writer
