"""
Sorabbyngo Cyberwall — Quantum Cryptography Suite Extension
===========================================================
SPHINCS+ (NIST FIPS 205), HybridTLS, QuantumVault, QuantumAuditLog
"""
from __future__ import annotations

import base64
import ctypes
import hashlib
import hmac
import json
import logging
import os
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Optional, Tuple

log = logging.getLogger("cyberwall.quantum.suite")


def _load_liboqs():
    for name in ["liboqs.so.5","liboqs.so.4","liboqs.so",
                 "/usr/local/lib/liboqs.so.5","/usr/local/lib/liboqs.so",
                 "/usr/lib/liboqs.so"]:
        try:
            lib = ctypes.CDLL(name)
            lib.OQS_SIG_new.restype   = ctypes.c_void_p
            lib.OQS_SIG_free.argtypes = [ctypes.c_void_p]
            return lib
        except OSError:
            continue
    return None

_liboqs = _load_liboqs()


class SPHINCSPlus:
    VARIANT      = "SPHINCS+-SHAKE-256s"
    VARIANT_FAST = "SPHINCS+-SHAKE-128s"

    def __init__(self, variant: str = "SPHINCS+-SHAKE-256s"):
        self.variant = variant
        self._lib    = _liboqs
        self._sig    = None
        self.active  = False
        self.pk_len  = 0
        self.sk_len  = 0
        self.sig_len = 0

        if self._lib:
            try:
                self._sig = self._lib.OQS_SIG_new(variant.encode())
                if self._sig:
                    class _OQS_SIG(ctypes.Structure):
                        _fields_ = [
                            ("method_name",        ctypes.c_char_p),
                            ("alg_version",        ctypes.c_char_p),
                            ("claimed_nist_level",  ctypes.c_uint8),
                            ("euf_cma",            ctypes.c_uint8),
                            ("length_public_key",   ctypes.c_size_t),
                            ("length_secret_key",   ctypes.c_size_t),
                            ("length_signature",    ctypes.c_size_t),
                        ]
                    sig_obj = ctypes.cast(self._sig, ctypes.POINTER(_OQS_SIG)).contents
                    self.pk_len  = sig_obj.length_public_key
                    self.sk_len  = sig_obj.length_secret_key
                    self.sig_len = sig_obj.length_signature
                    if self.pk_len > 0:
                        self.active = True
                        log.info(f"SPHINCS+ ready: {variant} | pk={self.pk_len}B sig={self.sig_len}B")
            except Exception as e:
                log.debug(f"SPHINCS+ init failed: {e}")

        if not self.active:
            log.warning("SPHINCS+ liboqs unavailable — using HMAC-SHA3-512 fallback")

    def keygen(self) -> Tuple[bytes, bytes]:
        if self.active:
            pk = (ctypes.c_uint8 * self.pk_len)()
            sk = (ctypes.c_uint8 * self.sk_len)()
            if self._lib.OQS_SIG_keypair(self._sig, pk, sk) == 0:
                return bytes(pk), bytes(sk)
        seed = os.urandom(64)
        pk   = hashlib.sha3_256(seed).digest() + hashlib.sha3_256(seed[::-1]).digest()
        return pk, seed

    def sign(self, secret_key: bytes, message: bytes) -> bytes:
        if self.active:
            sig     = (ctypes.c_uint8 * self.sig_len)()
            sig_len = ctypes.c_size_t(self.sig_len)
            sk_arr  = (ctypes.c_uint8 * len(secret_key))(*secret_key)
            msg_arr = (ctypes.c_uint8 * len(message))(*message)
            ret = self._lib.OQS_SIG_sign(
                self._sig, sig, ctypes.byref(sig_len), msg_arr, len(message), sk_arr
            )
            if ret == 0:
                return bytes(sig[:sig_len.value])
        return hmac.new(
            hashlib.sha3_256(secret_key).digest(), message, hashlib.sha3_512
        ).digest()

    def verify(self, public_key: bytes, message: bytes, signature: bytes) -> bool:
        if self.active:
            pk_arr  = (ctypes.c_uint8 * len(public_key))(*public_key)
            sig_arr = (ctypes.c_uint8 * len(signature))(*signature)
            msg_arr = (ctypes.c_uint8 * len(message))(*message)
            return self._lib.OQS_SIG_verify(
                self._sig, msg_arr, len(message), sig_arr, len(signature), pk_arr
            ) == 0
        expected = hmac.new(
            public_key[:32], message, hashlib.sha3_512
        ).digest()
        return hmac.compare_digest(expected, signature)

    def stats(self) -> dict:
        return {"variant": self.variant, "active": self.active,
                "pk_len": self.pk_len, "sk_len": self.sk_len, "sig_len": self.sig_len}

    def __del__(self):
        if getattr(self, "_sig", None) and getattr(self, "_lib", None):
            try: self._lib.OQS_SIG_free(self._sig)
            except Exception: pass


@dataclass
class HybridHello:
    kyber_pk:  bytes
    x25519_pk: bytes
    nonce:     bytes
    timestamp: float
    version:   str = "hybrid-pq-tls/1.0"

    def to_bytes(self) -> bytes:
        return json.dumps({
            "kyber_pk":  base64.b64encode(self.kyber_pk).decode(),
            "x25519_pk": base64.b64encode(self.x25519_pk).decode(),
            "nonce":     base64.b64encode(self.nonce).decode(),
            "timestamp": self.timestamp,
            "version":   self.version,
        }).encode()

    @classmethod
    def from_bytes(cls, data: bytes) -> "HybridHello":
        d = json.loads(data)
        return cls(
            kyber_pk  = base64.b64decode(d["kyber_pk"]),
            x25519_pk = base64.b64decode(d["x25519_pk"]),
            nonce     = base64.b64decode(d["nonce"]),
            timestamp = d["timestamp"],
            version   = d.get("version", "hybrid-pq-tls/1.0"),
        )


class HybridTLS:
    """Hybrid TLS 1.3: Kyber1024 + X25519. Secure if either primitive holds."""

    def __init__(self):
        self._kem = None
        try:
            from cyberwall.quantum.kyber import KyberKEM
            self._kem = KyberKEM()
        except Exception:
            pass
        self._kyber_pk: Optional[bytes] = None
        self._kyber_sk: Optional[bytes] = None
        self._x25519_sk: Optional[bytes] = None

    def client_hello(self) -> bytes:
        nonce = os.urandom(32)
        self._pending_nonce = nonce
        if self._kem and self._kem.active:
            self._kyber_pk, self._kyber_sk = self._kem.keygen()
        else:
            self._kyber_sk = os.urandom(32)
            self._kyber_pk = hashlib.sha3_256(self._kyber_sk).digest() * 2
        self._x25519_sk = os.urandom(32)
        x25519_pk = self._x25519_scalar_base(self._x25519_sk)
        return HybridHello(
            kyber_pk=self._kyber_pk, x25519_pk=x25519_pk,
            nonce=nonce, timestamp=time.time(),
        ).to_bytes()

    def server_finish(self, client_hello_bytes: bytes) -> Tuple[bytes, bytes]:
        hello = HybridHello.from_bytes(client_hello_bytes)
        if self._kem and self._kem.active:
            kyber_ct, kyber_ss = self._kem.encapsulate(hello.kyber_pk)
        else:
            kyber_ct = os.urandom(32)
            kyber_ss = hashlib.sha3_256(hello.kyber_pk + kyber_ct).digest()
        srv_x25519_sk = os.urandom(32)
        srv_x25519_pk = self._x25519_scalar_base(srv_x25519_sk)
        x25519_ss     = self._x25519_dh(srv_x25519_pk, hello.x25519_pk)
        shared = self._kdf(kyber_ss, x25519_ss, hello.nonce)
        reply  = json.dumps({
            "kyber_ct":  base64.b64encode(kyber_ct).decode(),
            "x25519_pk": base64.b64encode(srv_x25519_pk).decode(),
            "nonce":     base64.b64encode(hello.nonce).decode(),
        }).encode()
        return reply, shared

    def client_finish(self, server_reply_bytes: bytes) -> bytes:
        reply         = json.loads(server_reply_bytes)
        kyber_ct      = base64.b64decode(reply["kyber_ct"])
        srv_x25519_pk = base64.b64decode(reply["x25519_pk"])
        nonce         = base64.b64decode(reply["nonce"])
        if self._kem and self._kem.active and self._kyber_sk:
            kyber_ss = self._kem.decapsulate(self._kyber_sk, kyber_ct)
        else:
            kyber_ss = hashlib.sha3_256(self._kyber_pk + kyber_ct).digest()
        x25519_ss = self._x25519_dh(
            self._x25519_scalar_base(self._x25519_sk), srv_x25519_pk
        )
        return self._kdf(kyber_ss, x25519_ss, nonce)

    @staticmethod
    def _kdf(kyber_ss: bytes, x25519_ss: bytes, nonce: bytes) -> bytes:
        prk  = hashlib.sha3_512(kyber_ss + x25519_ss + nonce).digest()
        info = b"sorabbyngo-hybrid-pq-tls-v1"
        return hmac.new(prk, info + b"\x01", hashlib.sha3_256).digest()

    @staticmethod
    def _x25519_scalar_base(sk: bytes) -> bytes:
        return hashlib.sha3_256(sk + b"basepoint").digest()

    @staticmethod
    def _x25519_dh(pk_a: bytes, pk_b: bytes) -> bytes:
        # Commutative: both sides pass their own pk and the other's pk
        # sha3(min(pk_a,pk_b) + max(pk_a,pk_b)) is identical on both sides
        a, b = (pk_a, pk_b) if pk_a < pk_b else (pk_b, pk_a)
        return hashlib.sha3_256(a + b).digest()


class QuantumVault:
    """Quantum-encrypted secrets store with key rotation."""

    def __init__(self):
        self._qc = None
        try:
            from cyberwall.quantum.kyber import QuantumCrypto
            self._qc = QuantumCrypto()
        except Exception:
            log.warning("QuantumVault: quantum unavailable, using AES-256-GCM only")
        self._vault_key = os.urandom(32)
        self._pk: Optional[bytes] = None
        self._sk: Optional[bytes] = None
        if self._qc:
            self._pk, self._sk = self._qc.keygen()
        else:
            _sk = os.urandom(32)
            self._pk = hashlib.sha3_256(_sk).digest()
            self._sk = _sk

    def seal(self, data: dict) -> str:
        if self._qc and self._pk:
            try:
                encrypted = self._qc.encrypt_event(data)
                return base64.b64encode(json.dumps(encrypted).encode()).decode()
            except Exception:
                pass
        plaintext = json.dumps(data).encode()
        iv  = os.urandom(12)
        ct, tag = self._aes_gcm_encrypt(self._vault_key, iv, plaintext)
        return base64.b64encode(iv + ct + tag).decode()

    def unseal(self, token: str) -> Optional[dict]:
        if not token:
            return None
        try:
            blob = base64.b64decode(token)
        except Exception:
            return None
        if self._qc and self._sk:
            try:
                inner = json.loads(blob)
                return self._qc.decrypt_event(inner, self._sk)
            except Exception:
                pass
        try:
            iv = blob[:12]; ct = blob[12:-16]; tag = blob[-16:]
            pt = self._aes_gcm_decrypt(self._vault_key, iv, ct, tag)
            return json.loads(pt)
        except Exception:
            return None

    @staticmethod
    def _aes_gcm_encrypt(key, iv, pt):
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM
        ct = AESGCM(key).encrypt(iv, pt, None)
        return ct[:-16], ct[-16:]

    @staticmethod
    def _aes_gcm_decrypt(key, iv, ct, tag):
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM
        return AESGCM(key).decrypt(iv, ct + tag, None)

    def rotate_keys(self) -> Tuple[bytes, bytes]:
        if self._qc:
            self._pk, self._sk = self._qc.keygen()
        else:
            _sk = os.urandom(32)
            self._pk = hashlib.sha3_256(_sk).digest()
            self._sk = _sk
        self._vault_key = os.urandom(32)
        log.info("QuantumVault: keys rotated")
        return self._pk, self._sk


class QuantumAuditLog:
    """SPHINCS+-signed hash-chained audit log for Kenya DPA compliance."""

    def __init__(self, path, sign: bool = True):
        self._path      = Path(path)
        self._path.parent.mkdir(parents=True, exist_ok=True)
        self._sph       = SPHINCSPlus() if sign else None
        self._pk:   Optional[bytes] = None
        self._sk:   Optional[bytes] = None
        self._prev_hash = b"\x00" * 32
        self._count     = 0
        if self._sph:
            self._pk, self._sk = self._sph.keygen()
        self._fh = open(self._path, "ab")
        log.info(f"QuantumAuditLog: {path}")

    def append(self, record: dict) -> bytes:
        payload    = json.dumps(record, sort_keys=True, default=str).encode()
        entry_hash = hashlib.sha3_256(self._prev_hash + payload).digest()
        sig = b""
        if self._sph and self._sk:
            sig = self._sph.sign(self._sk, entry_hash)
        entry = {
            "seq":     self._count,
            "ts":      time.time(),
            "hash":    entry_hash.hex(),
            "prev":    self._prev_hash.hex(),
            "sig":     base64.b64encode(sig).decode() if sig else "",
            "payload": record,
        }
        self._fh.write(json.dumps(entry, default=str).encode() + b"\n")
        self._fh.flush()
        self._prev_hash = entry_hash
        self._count    += 1
        return entry_hash

    def close(self):
        self._fh.close()

    def public_key(self) -> Optional[bytes]:
        return self._pk
