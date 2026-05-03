
from __future__ import annotations
import time
from collections import defaultdict
from typing import List
from suid.registry.prefixes import PREFIX, PREFIX_LABELS, region_to_country
from suid.validator import validate, is_tampered

class ForensicExtractor:
    @staticmethod
    def entity_report(suid: str) -> dict:
        parts = suid.split("-")
        if len(parts) != 5:
            return {"entity_type": "Unknown", "origin_country": "Unknown",
                    "region": "Unknown", "tampered": True, "valid": False, "raw": suid}
        pfx, reg, ts, rand, chk = parts
        try:
            entity_type = PREFIX_LABELS.get(PREFIX(pfx), "Unknown")
        except ValueError:
            entity_type = f"Unknown ({pfx})"
        return {
            "entity_type":    entity_type,
            "origin_country": region_to_country(reg),
            "region":         reg,
            "prefix":         pfx,
            "timestamp_b36":  ts,
            "tampered":       is_tampered(suid),
            "valid":          validate(suid),
            "raw":            suid,
        }

    @staticmethod
    def law_enforcement_summary(suids: List[str], case_number: str,
                                 requesting_authority: str, authorized_by: str) -> dict:
        valid_ids = [s for s in suids if validate(s)]
        tampered  = [s for s in suids if is_tampered(s)]
        by_entity: dict = defaultdict(int)
        by_region: dict = defaultdict(int)
        by_country: dict = defaultdict(int)
        for suid in suids:
            r = ForensicExtractor.entity_report(suid)
            by_entity[r["entity_type"]]      += 1
            by_region[r["region"]]           += 1
            by_country[r["origin_country"]]  += 1
        return {
            "case_number":          case_number,
            "requesting_authority": requesting_authority,
            "authorized_by":        authorized_by,
            "generated_at":         time.time(),
            "summary": {
                "total_ids":    len(suids),
                "valid_ids":    len(valid_ids),
                "tampered_ids": len(tampered),
                "integrity":    len(tampered) == 0,
            },
            "breakdown": {
                "by_entity_type": dict(by_entity),
                "by_region":      dict(by_region),
                "by_country":     dict(by_country),
            },
            "tampered_suids": tampered,
        }

    @staticmethod
    def chain_of_custody(suids: List[str], actor: str) -> dict:
        return {"actor": actor, "suids": suids, "count": len(suids),
                "all_valid": all(validate(s) for s in suids),
                "timestamp": time.time()}
