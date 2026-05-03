
from __future__ import annotations
import hashlib

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

def validate(suid: str) -> bool:
    if not isinstance(suid, str): return False
    parts = suid.split("-")
    if len(parts) != 5: return False
    pfx, reg, ts, rand, chk = parts
    if len(pfx) != 3 or len(chk) != 2: return False
    return chk == _chk([pfx, reg, ts, rand])

def is_tampered(suid: str) -> bool:
    return not validate(suid)
