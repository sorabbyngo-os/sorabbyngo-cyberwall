
from __future__ import annotations
import hashlib, time
from typing import Optional
from suid.generator import SUID
from suid.registry.prefixes import PREFIX
from suid.validator import validate

class AuditLogger:
    @staticmethod
    def log(action: str, entity_id: str,
            metadata: Optional[dict] = None, region: str = "KE047") -> dict:
        audit_id = SUID.generate(PREFIX.AUDIT, region)
        ts = time.time()
        entry = {
            "audit_id":  audit_id,
            "action":    action.upper(),
            "entity_id": entity_id,
            "ts":        ts,
            "region":    region,
            "metadata":  metadata or {},
            "valid":     validate(audit_id),
        }
        payload = f"{audit_id}{action}{entity_id}{ts}".encode()
        entry["integrity"] = hashlib.sha256(payload).hexdigest()[:16]
        return entry
