
from __future__ import annotations
import hashlib, os, time
from typing import List, Union
from suid.registry.prefixes import PREFIX

def _b36(n: int, w: int = 6) -> str:
    chars = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ"
    r = ""
    while n:
        r = chars[n % 36] + r
        n //= 36
    return r.zfill(w)[:w]

def _chk(parts) -> str:
    d = int(hashlib.sha256("-".join(parts).encode()).hexdigest(), 16)
    return _b36(d % (36**2), 2)

def _rand(w=6) -> str:
    return _b36(int.from_bytes(os.urandom(4), "big"), w)

class SUID:
    @staticmethod
    def generate(prefix: Union[PREFIX, str], region: str) -> str:
        pfx  = str(prefix).upper()
        reg  = region.upper()
        ts   = _b36(int(time.time()), 6)
        rand = _rand(6)
        parts = [pfx, reg, ts, rand]
        return f"{pfx}-{reg}-{ts}-{rand}-{_chk(parts)}"

    @staticmethod
    def batch(prefix: Union[PREFIX, str], region: str, count: int = 10) -> List[str]:
        return [SUID.generate(prefix, region) for _ in range(count)]

    @staticmethod
    def parse(suid: str) -> dict:
        from suid.validator import validate
        parts = suid.split("-")
        if len(parts) != 5:
            return {"valid": False, "raw": suid}
        pfx, reg, ts, rand, chk = parts
        return {"prefix": pfx, "region": reg, "timestamp_b36": ts,
                "random_b36": rand, "checksum": chk,
                "valid": validate(suid), "raw": suid}
