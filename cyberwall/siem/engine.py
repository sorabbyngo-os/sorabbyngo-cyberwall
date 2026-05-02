"""
Sorabbyngo Cyberwall — SIEM Engine
====================================
Security Information and Event Management with:
  1. Real-time event correlation across all cyberwall subsystems
  2. Rule-based alert escalation (YAML-configurable)
  3. Kenya DPA 2019 compliance audit trail
  4. Syslog (RFC 5424) + CEF ingestion
  5. Quantum-encrypted log storage (Kyber1024 + AES-256-GCM)
  6. Incident timeline reconstruction
  7. Threat actor correlation (same IP/hash across events)

Kenya DPA 2019 references:
  - s.25: Security safeguards for personal data
  - s.43: Breach notification within 72 hours
  - s.46: Data retention limits
"""
from __future__ import annotations

import asyncio
import hashlib
import json
import logging
import os
import re
import socketserver
import threading
import time
from collections import defaultdict, deque
from dataclasses import dataclass, field, asdict
from pathlib import Path
from typing import Callable, Dict, List, Optional, Set, Tuple

from cyberwall.core.event_bus import EventBus, ThreatEvent, ThreatLevel

log = logging.getLogger("cyberwall.siem")

DPA_BREACH_NOTIFY_HOURS = 72
DPA_PERSONAL_DATA_TYPES = {
    "data_exfil", "pii_access", "unauthorized_access",
    "database_dump", "credential_leak", "patient_data_access",
}
DPA_RETENTION_DAYS = 90


@dataclass
class CorrelationRule:
    name:        str
    description: str
    conditions:  List[dict]
    window_s:    int   = 60
    threshold:   int   = 1
    severity:    str   = "HIGH"
    action:      str   = "alert"
    tags:        List[str] = field(default_factory=list)


@dataclass
class Incident:
    id:           str
    rule_name:    str
    severity:     str
    description:  str
    source_ips:   List[str]
    event_ids:    List[str]
    first_seen:   float
    last_seen:    float
    dpa_relevant: bool  = False
    notified:     bool  = False
    closed:       bool  = False
    tags:         List[str] = field(default_factory=list)

    def age_hours(self) -> float:
        return (time.time() - self.first_seen) / 3600

    def to_dict(self) -> dict:
        return asdict(self)


DEFAULT_RULES: List[CorrelationRule] = [
    CorrelationRule(
        name="brute_force_ssh",
        description="5+ auth failures from same IP within 60s",
        conditions=[{"field": "threat_type", "op": "eq", "value": "auth_failure"}],
        window_s=60, threshold=5, severity="HIGH", action="block",
        tags=["brute_force", "authentication"],
    ),
    CorrelationRule(
        name="lateral_movement",
        description="Port scan followed by malware detection from same IP",
        conditions=[
            {"field": "threat_type", "op": "in",
             "value": ["port_scan", "malware_detected"]},
        ],
        window_s=300, threshold=2, severity="CRITICAL", action="escalate",
        tags=["apt", "lateral_movement"],
    ),
    CorrelationRule(
        name="data_exfil_dpa",
        description="Data exfiltration — Kenya DPA s.43 breach notification required",
        conditions=[{"field": "threat_type", "op": "eq", "value": "data_exfil"}],
        window_s=1, threshold=1, severity="CRITICAL", action="dpa_notify",
        tags=["dpa_2019", "breach", "personal_data"],
    ),
    CorrelationRule(
        name="tor_c2_malware_combo",
        description="Tor C2 detected alongside malware — APT indicator",
        conditions=[
            {"field": "threat_type", "op": "in",
             "value": ["tor_c2", "tor_exit_node", "malware_detected"]},
        ],
        window_s=120, threshold=2, severity="CRITICAL", action="escalate",
        tags=["apt", "tor", "c2"],
    ),
    CorrelationRule(
        name="ransomware_indicators",
        description="File tamper + high entropy + mass file ops = ransomware",
        conditions=[
            {"field": "threat_type", "op": "in",
             "value": ["file_tamper", "packed_binary", "mass_file_change"]},
        ],
        window_s=30, threshold=3, severity="CRITICAL", action="block",
        tags=["ransomware"],
    ),
    CorrelationRule(
        name="rootkit_persistence",
        description="Rootkit or syscall anomaly indicating persistence",
        conditions=[
            {"field": "threat_type", "op": "in",
             "value": ["rootkit", "syscall_anomaly", "process_injection"]},
        ],
        window_s=60, threshold=1, severity="CRITICAL", action="escalate",
        tags=["rootkit", "persistence"],
    ),
]


def _match_condition(event: ThreatEvent, cond: dict) -> bool:
    fld = cond["field"]
    op  = cond["op"]
    val = cond["value"]
    ev_val = getattr(event, fld, None)
    if ev_val is None:
        ev_val = (event.data or {}).get(fld)
    if op == "eq":      return ev_val == val
    if op == "neq":     return ev_val != val
    if op == "in":      return ev_val in val
    if op == "contains":return val in str(ev_val or "")
    if op == "gt":      return (ev_val or 0) > val
    if op == "gte":     return (ev_val or 0) >= val
    return False


def _event_matches_rule(event: ThreatEvent, rule: CorrelationRule) -> bool:
    return all(_match_condition(event, c) for c in rule.conditions)


@dataclass
class DPAAuditRecord:
    ts:              float
    event_type:      str
    source_ip:       str
    data_category:   str
    description:     str
    incident_id:     Optional[str]
    notified:        bool = False
    notification_ts: Optional[float] = None

    def to_dict(self) -> dict:
        return asdict(self)

    def hours_until_deadline(self) -> float:
        return max(0.0, DPA_BREACH_NOTIFY_HOURS - (time.time() - self.ts) / 3600)


class SyslogParser:
    _CEF_RE = re.compile(
        r"CEF:(\d+)\|([^|]*)\|([^|]*)\|([^|]*)\|([^|]*)\|([^|]*)\|(\d+)\|(.*)"
    )
    _RFC5424_RE = re.compile(
        r"<(\d+)>(\d+)\s+(\S+)\s+(\S+)\s+(\S+)\s+(\S+)\s+(\S+)\s+(.*)"
    )
    CEF_SEVERITY_MAP = {
        0: ThreatLevel.INFO,   1: ThreatLevel.INFO,   2: ThreatLevel.INFO,
        3: ThreatLevel.LOW,    4: ThreatLevel.LOW,
        5: ThreatLevel.MEDIUM, 6: ThreatLevel.MEDIUM,
        7: ThreatLevel.HIGH,   8: ThreatLevel.HIGH,
        9: ThreatLevel.CRITICAL, 10: ThreatLevel.CRITICAL,
    }

    def parse(self, raw: str) -> Optional[ThreatEvent]:
        raw = raw.strip()
        if not raw:
            return None
        if "CEF:" in raw:
            return self._parse_cef(raw)
        m = self._RFC5424_RE.match(raw)
        if m:
            return self._parse_rfc5424(raw, m)
        return None

    def _parse_cef(self, raw: str) -> Optional[ThreatEvent]:
        m = self._CEF_RE.search(raw)
        if not m:
            return None
        _, vendor, product, _, sig_id, name, sev_str, ext_str = m.groups()
        sev   = int(sev_str)
        level = self.CEF_SEVERITY_MAP.get(sev, ThreatLevel.MEDIUM)
        ext: dict = {}
        for part in ext_str.split(" "):
            if "=" in part:
                k, _, v = part.partition("=")
                ext[k] = v
        src_ip = ext.get("src", ext.get("sourceAddress", "unknown"))
        return ThreatEvent(
            source=f"{vendor}/{product}",
            threat_type=sig_id.lower().replace(" ", "_"),
            description=name,
            level=level,
            score=float(sev),
            data={**ext, "cef_sig": sig_id, "cef_name": name},
            node_id=ext.get("dhost", "external"),
        )

    def _parse_rfc5424(self, raw: str, m) -> Optional[ThreatEvent]:
        pri_str, _, timestamp, hostname, app, _, _, msg = m.groups()
        pri      = int(pri_str)
        severity = pri & 0x7
        level_map = {
            0: ThreatLevel.CRITICAL, 1: ThreatLevel.CRITICAL,
            2: ThreatLevel.CRITICAL, 3: ThreatLevel.HIGH,
            4: ThreatLevel.HIGH,     5: ThreatLevel.MEDIUM,
            6: ThreatLevel.LOW,      7: ThreatLevel.INFO,
        }
        level = level_map.get(severity, ThreatLevel.INFO)
        return ThreatEvent(
            source=f"{hostname}/{app}",
            threat_type="syslog_event",
            description=msg[:200],
            level=level,
            score=float(8 - severity),
            data={"hostname": hostname, "app": app,
                  "timestamp": timestamp, "raw": raw[:300]},
            node_id=hostname,
        )


class QuantumLogStore:
    def __init__(self, path: Path, public_key=None):
        self._path = path
        self._pk   = public_key
        self._qc   = None
        self._fh   = None
        self._lock = threading.Lock()
        self._quantum_available = False
        try:
            from cyberwall.quantum.kyber import QuantumCrypto
            self._qc = QuantumCrypto()
            if public_key is None:
                self._pk, self._sk_hint = self._qc.keygen()
            self._quantum_available = True
        except Exception as e:
            log.warning(f"QuantumLogStore: quantum unavailable ({e}), using plaintext")
        path.parent.mkdir(parents=True, exist_ok=True)
        self._fh = open(path, "ab")
        log.info(f"QuantumLogStore ready: {path} | quantum={self._quantum_available}")

    def write(self, record: dict) -> None:
        line = json.dumps(record, default=str)
        with self._lock:
            if self._quantum_available and self._qc and self._pk:
                try:
                    import base64
                    encrypted = self._qc.encrypt_event(record)
                    self._fh.write(
                        base64.b64encode(json.dumps(encrypted, default=str).encode()) + b"\n"
                    )
                    self._fh.flush()
                    return
                except Exception:
                    pass
            self._fh.write(line.encode() + b"\n")
            self._fh.flush()

    def close(self) -> None:
        with self._lock:
            if self._fh:
                self._fh.close()
                self._fh = None


class SIEMEngine:
    def __init__(
        self,
        bus:         EventBus,
        log_dir:     Path = Path("/var/log/cyberwall/siem"),
        rules:       Optional[List[CorrelationRule]] = None,
        public_key=None,
        on_incident: Optional[Callable] = None,
    ):
        self._bus         = bus
        self._log_dir     = log_dir
        self._rules       = rules or DEFAULT_RULES
        self._on_incident = on_incident
        self._running     = False
        self._buffers: Dict[str, deque] = defaultdict(lambda: deque(maxlen=1000))
        self._incidents:  Dict[str, Incident] = {}
        self._inc_lock    = asyncio.Lock()
        self._dpa_records: List[DPAAuditRecord] = []
        self._dpa_lock    = asyncio.Lock()
        self._actor_map:  Dict[str, List[str]] = defaultdict(list)
        self._stats = {
            "events_ingested": 0, "incidents_created": 0,
            "dpa_breaches": 0, "rules_triggered": 0,
            "start_time": time.time(),
        }
        log_dir.mkdir(parents=True, exist_ok=True)
        self._event_log    = QuantumLogStore(log_dir / "events.qlog", public_key)
        self._incident_log = QuantumLogStore(log_dir / "incidents.qlog", public_key)
        self._dpa_log      = QuantumLogStore(log_dir / "dpa_audit.qlog", public_key)
        self._syslog_parser = SyslogParser()
        bus.subscribe("*", self._on_event)
        log.info(f"SIEMEngine ready | rules={len(self._rules)} | log_dir={log_dir}")

    async def _on_event(self, event: ThreatEvent) -> None:
        self._stats["events_ingested"] += 1
        event_id = hashlib.sha256(
            f"{event.timestamp}{event.source}{event.threat_type}".encode()
        ).hexdigest()[:16]
        rec = {
            "id": event_id, "ts": event.timestamp, "source": event.source,
            "threat_type": event.threat_type, "level": event.level.name,
            "score": event.score, "description": event.description,
            "node_id": event.node_id, "blocked": event.blocked, "data": event.data,
        }
        self._event_log.write(rec)
        src_ip = (event.data or {}).get("src_ip") or (event.data or {}).get("ip")
        if src_ip:
            self._actor_map[src_ip].append(event_id)
        if event.threat_type in DPA_PERSONAL_DATA_TYPES:
            await self._record_dpa_breach(event, event_id)
        await self._correlate(event, event_id)

    async def _correlate(self, event: ThreatEvent, event_id: str) -> None:
        now = time.time()
        for rule in self._rules:
            if not _event_matches_rule(event, rule):
                continue
            buf = self._buffers[rule.name]
            buf.append((now, event_id, event))
            while buf and (now - buf[0][0]) > rule.window_s:
                buf.popleft()
            if len(buf) >= rule.threshold:
                await self._trigger_rule(rule, list(buf), event)

    async def _trigger_rule(self, rule, buf, trigger_event) -> None:
        self._stats["rules_triggered"] += 1
        event_ids  = [b[1] for b in buf]
        source_ips = list({
            (b[2].data or {}).get("src_ip") or (b[2].data or {}).get("ip", "")
            for b in buf
        } - {""})
        inc_id = hashlib.sha256(f"{rule.name}{buf[0][0]}".encode()).hexdigest()[:12]
        async with self._inc_lock:
            existing = next(
                (i for i in self._incidents.values()
                 if i.rule_name == rule.name and not i.closed
                 and (time.time() - i.last_seen) < rule.window_s * 2),
                None,
            )
            if existing:
                existing.last_seen = time.time()
                existing.event_ids.extend(event_ids)
                existing.source_ips = list(set(existing.source_ips + source_ips))
                return
            incident = Incident(
                id=inc_id, rule_name=rule.name, severity=rule.severity,
                description=rule.description, source_ips=source_ips,
                event_ids=event_ids, first_seen=buf[0][0], last_seen=time.time(),
                dpa_relevant="dpa_notify" in rule.action or "dpa_2019" in rule.tags,
                tags=rule.tags,
            )
            self._incidents[inc_id] = incident
            self._stats["incidents_created"] += 1
        log.warning(f"INCIDENT [{incident.severity}] {rule.name} | id={inc_id}")
        self._incident_log.write(incident.to_dict())
        if rule.action == "dpa_notify":
            await self._dpa_notify(incident)
        if self._on_incident:
            self._on_incident(incident)

    async def _record_dpa_breach(self, event: ThreatEvent, event_id: str) -> None:
        async with self._dpa_lock:
            src_ip = (event.data or {}).get("src_ip", "unknown")
            rec = DPAAuditRecord(
                ts=time.time(), event_type=event.threat_type,
                source_ip=src_ip, data_category=self._classify_data(event),
                description=event.description, incident_id=event_id,
            )
            self._dpa_records.append(rec)
            self._stats["dpa_breaches"] += 1
            self._dpa_log.write(rec.to_dict())
            log.warning(
                f"DPA BREACH | type={event.threat_type} "
                f"| notify within {rec.hours_until_deadline():.1f}h [Kenya DPA 2019 s.43]"
            )

    async def _dpa_notify(self, incident: Incident) -> None:
        async with self._inc_lock:
            if not incident.notified:
                incident.notified = True
                incident.dpa_relevant = True
                log.critical(
                    f"DPA NOTIFICATION REQUIRED | incident={incident.id} "
                    f"| Kenya DPA 2019 s.43 — notify within {DPA_BREACH_NOTIFY_HOURS}h"
                )

    def _classify_data(self, event: ThreatEvent) -> str:
        t = event.threat_type
        if any(w in t for w in ("patient", "medical", "health")): return "medical"
        if any(w in t for w in ("financial", "payment", "bank")):  return "financial"
        if any(w in t for w in ("credential", "password", "auth")): return "credentials"
        return "personal"

    async def ingest_raw(self, raw: str) -> Optional[ThreatEvent]:
        event = self._syslog_parser.parse(raw)
        if event:
            await self._on_event(event)
        return event

    def start_syslog_listener(self, host: str = "0.0.0.0", port: int = 5514) -> threading.Thread:
        engine = self
        class Handler(socketserver.BaseRequestHandler):
            def handle(self):
                data = self.request[0].decode(errors="replace")
                asyncio.run_coroutine_threadsafe(engine.ingest_raw(data), engine._loop)
        srv = socketserver.UDPServer((host, port), Handler)
        t = threading.Thread(target=srv.serve_forever, daemon=True)
        t.start()
        log.info(f"Syslog listener: udp://{host}:{port}")
        return t

    def get_incidents(self, severity=None, open_only=True) -> List[Incident]:
        incs = list(self._incidents.values())
        if open_only:   incs = [i for i in incs if not i.closed]
        if severity:    incs = [i for i in incs if i.severity == severity]
        return sorted(incs, key=lambda i: i.last_seen, reverse=True)

    def get_dpa_records(self, unnotified_only=False) -> List[DPAAuditRecord]:
        recs = self._dpa_records
        if unnotified_only: recs = [r for r in recs if not r.notified]
        return recs

    def get_actor_timeline(self, ip: str) -> List[str]:
        return self._actor_map.get(ip, [])

    def stats(self) -> dict:
        return {
            **self._stats,
            "uptime_s":       int(time.time() - self._stats["start_time"]),
            "open_incidents": len([i for i in self._incidents.values() if not i.closed]),
            "tracked_actors": len(self._actor_map),
            "dpa_unnotified": len([r for r in self._dpa_records if not r.notified]),
            "quantum_logging": self._event_log._quantum_available,
        }

    async def start(self) -> None:
        self._running = True
        self._loop = asyncio.get_event_loop()
        log.info("SIEMEngine started")
        while self._running:
            await asyncio.sleep(30)
            await self._maintenance()

    async def _maintenance(self) -> None:
        now = time.time()
        for rec in self._dpa_records:
            if not rec.notified and rec.hours_until_deadline() < 24:
                log.critical(
                    f"DPA DEADLINE WARNING: {rec.hours_until_deadline():.1f}h remaining "
                    f"[{rec.event_type}] — Kenya DPA 2019 s.43"
                )
        async with self._inc_lock:
            for inc in list(self._incidents.values()):
                if not inc.closed and (now - inc.last_seen) > 86400:
                    inc.closed = True

    def stop(self) -> None:
        self._running = False
        self._event_log.close()
        self._incident_log.close()
        self._dpa_log.close()
        log.info("SIEMEngine stopped")
