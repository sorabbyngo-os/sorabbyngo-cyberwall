"""
Sorabbyngo Cyberwall — Post-Quantum Encryption
===============================================
Implements CRYSTALS-Kyber (ML-KEM) via liboqs C library (ctypes binding).
Falls back to X25519 + AES-256-GCM (classical) when liboqs unavailable.

NIST FIPS 203 (ML-KEM) — finalized August 2024
NIST FIPS 204 (ML-DSA / Dilithium) — finalized August 2024

Usage:
    from cyberwall.quantum.kyber import QuantumCrypto
    qc = QuantumCrypto()
    pub, priv = qc.keygen()
    ciphertext, shared_secret = qc.encapsulate(pub)
    shared_secret2 = qc.decapsulate(priv, ciphertext)
    encrypted = qc.encrypt_event(event_dict)
    decrypted = qc.decrypt_event(encrypted, priv)
"""
import ctypes
import hashlib
import hmac
import json
import logging
import os
import struct
import time
from pathlib import Path
from typing import Optional, Tuple

log = logging.getLogger("cyberwall.quantum")

# ── liboqs constants ──────────────────────────────────────────────────────────
KYBER_VARIANT    = "Kyber1024"   # highest security (256-bit quantum / 512-bit classical)
DILITHIUM_VARIANT = "Dilithium5" # highest security digital signatures

# ── liboqs loader ─────────────────────────────────────────────────────────────
def _load_liboqs():
    """Load liboqs shared library. Returns ctypes CDLL or None."""
    candidates = [
        "liboqs.so.5", "liboqs.so.4", "liboqs.so",
        "/usr/local/lib/liboqs.so.5",
        "/usr/local/lib/liboqs.so",
        "/usr/lib/liboqs.so",
    ]
    for name in candidates:
        try:
            lib = ctypes.CDLL(name)
            # Verify it has the KEM API
            lib.OQS_KEM_new.restype  = ctypes.c_void_p
            lib.OQS_KEM_free.argtypes = [ctypes.c_void_p]
            log.info(f"liboqs loaded: {name}")
            return lib
        except OSError:
            continue
    log.warning("liboqs not found — using classical X25519+AES-256-GCM fallback")
    return None

_liboqs = _load_liboqs()


# ── Kyber KEM wrapper ─────────────────────────────────────────────────────────
class KyberKEM:
    """
    CRYSTALS-Kyber Key Encapsulation Mechanism via liboqs.
    Kyber1024 = 256-bit post-quantum security level.
    """

    def __init__(self, variant: str = KYBER_VARIANT):
        self.variant  = variant
        self._lib     = _liboqs
        self._kem     = None
        self.active   = False

        if not self._lib:
            return

        try:
            name_b = variant.encode()
            self._kem = self._lib.OQS_KEM_new(name_b)
            if not self._kem:
                log.warning(f"Kyber variant {variant} not available in liboqs build")
                return

            # Read sizes from the KEM struct
            # OQS_KEM struct layout: method_name, alg_version, claimed_nist_level,
            #   ind_cca, length_public_key, length_secret_key, length_ciphertext,
            #   length_shared_secret, ...
            class OQS_KEM(ctypes.Structure):
                _fields_ = [
                    ("method_name",          ctypes.c_char_p),
                    ("alg_version",          ctypes.c_char_p),
                    ("claimed_nist_level",   ctypes.c_uint8),
                    ("ind_cca",              ctypes.c_uint8),
                    ("length_public_key",    ctypes.c_size_t),
                    ("length_secret_key",    ctypes.c_size_t),
                    ("length_ciphertext",    ctypes.c_size_t),
                    ("length_shared_secret", ctypes.c_size_t),
                ]

            kem_struct = ctypes.cast(self._kem, ctypes.POINTER(OQS_KEM)).contents
            self.pk_len = kem_struct.length_public_key
            self.sk_len = kem_struct.length_secret_key
            self.ct_len = kem_struct.length_ciphertext
            self.ss_len = kem_struct.length_shared_secret
            self.active = True
            log.info(
                f"Kyber KEM ready: {variant} | "
                f"pk={self.pk_len}B sk={self.sk_len}B ct={self.ct_len}B ss={self.ss_len}B"
            )
        except Exception as e:
            log.warning(f"Kyber init error: {e} — falling back to classical")
            self._kem   = None
            self.active = False

    def keygen(self) -> Tuple[bytes, bytes]:
        """Generate Kyber keypair. Returns (public_key, secret_key)."""
        if not self.active:
            return self._classical_keygen()

        pk = (ctypes.c_uint8 * self.pk_len)()
        sk = (ctypes.c_uint8 * self.sk_len)()
        ret = self._lib.OQS_KEM_keypair(self._kem, pk, sk)
        if ret != 0:
            raise RuntimeError(f"Kyber keygen failed: {ret}")
        return bytes(pk), bytes(sk)

    def encapsulate(self, public_key: bytes) -> Tuple[bytes, bytes]:
        """Encapsulate — returns (ciphertext, shared_secret)."""
        if not self.active:
            return self._classical_encap(public_key)

        ct = (ctypes.c_uint8 * self.ct_len)()
        ss = (ctypes.c_uint8 * self.ss_len)()
        pk_arr = (ctypes.c_uint8 * len(public_key))(*public_key)
        ret = self._lib.OQS_KEM_encaps(self._kem, ct, ss, pk_arr)
        if ret != 0:
            raise RuntimeError(f"Kyber encaps failed: {ret}")
        return bytes(ct), bytes(ss)

    def decapsulate(self, secret_key: bytes, ciphertext: bytes) -> bytes:
        """Decapsulate — returns shared_secret."""
        if not self.active:
            return self._classical_decap(secret_key, ciphertext)

        ss = (ctypes.c_uint8 * self.ss_len)()
        sk_arr = (ctypes.c_uint8 * len(secret_key))(*secret_key)
        ct_arr = (ctypes.c_uint8 * len(ciphertext))(*ciphertext)
        ret = self._lib.OQS_KEM_decaps(self._kem, ss, ct_arr, sk_arr)
        if ret != 0:
            raise RuntimeError(f"Kyber decaps failed: {ret}")
        return bytes(ss)

    def __del__(self):
        if self._kem and self._lib:
            try:
                self._lib.OQS_KEM_free(self._kem)
            except Exception:
                pass

    # ── Classical fallback (X25519 + HKDF) ────────────────────────────────────
    def _classical_keygen(self) -> Tuple[bytes, bytes]:
        """X25519 keypair as fallback."""
        from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
        priv = X25519PrivateKey.generate()
        pub  = priv.public_key()
        from cryptography.hazmat.primitives.serialization import (
            Encoding, PublicFormat, PrivateFormat, NoEncryption
        )
        pk = pub.public_bytes(Encoding.Raw, PublicFormat.Raw)
        sk = priv.private_bytes(Encoding.Raw, PrivateFormat.Raw, NoEncryption())
        return pk, sk

    def _classical_encap(self, public_key: bytes) -> Tuple[bytes, bytes]:
        from cryptography.hazmat.primitives.asymmetric.x25519 import (
            X25519PrivateKey, X25519PublicKey
        )
        from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
        ephemeral = X25519PrivateKey.generate()
        peer_pub  = X25519PublicKey.from_public_bytes(public_key)
        shared    = ephemeral.exchange(peer_pub)
        ss        = hashlib.sha256(shared).digest()
        ct        = ephemeral.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
        return ct, ss

    def _classical_decap(self, secret_key: bytes, ciphertext: bytes) -> bytes:
        from cryptography.hazmat.primitives.asymmetric.x25519 import (
            X25519PrivateKey, X25519PublicKey
        )
        priv    = X25519PrivateKey.from_private_bytes(secret_key)
        peer    = X25519PublicKey.from_public_bytes(ciphertext)
        shared  = priv.exchange(peer)
        return hashlib.sha256(shared).digest()


# ── AES-256-GCM symmetric encryption ─────────────────────────────────────────
def aes_encrypt(key: bytes, plaintext: bytes) -> bytes:
    """AES-256-GCM encrypt. Returns nonce(12) + tag(16) + ciphertext."""
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    # Derive 256-bit key via SHA3-256 if needed
    if len(key) != 32:
        key = hashlib.sha3_256(key).digest()
    nonce = os.urandom(12)
    aes   = AESGCM(key)
    ct    = aes.encrypt(nonce, plaintext, None)
    return nonce + ct  # ct already includes GCM tag


def aes_decrypt(key: bytes, data: bytes) -> bytes:
    """AES-256-GCM decrypt. data = nonce(12) + tag(16) + ciphertext."""
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    if len(key) != 32:
        key = hashlib.sha3_256(key).digest()
    nonce = data[:12]
    ct    = data[12:]
    aes   = AESGCM(key)
    return aes.decrypt(nonce, ct, None)


# ── Dilithium DSA wrapper ─────────────────────────────────────────────────────
class DilithiumDSA:
    """
    CRYSTALS-Dilithium digital signatures via liboqs.
    Dilithium5 = NIST security level 5 (256-bit post-quantum).
    Used to sign every threat event with the node's hardware identity.
    """

    def __init__(self, variant: str = DILITHIUM_VARIANT):
        self.variant = variant
        self._lib    = _liboqs
        self._sig    = None
        self.active  = False

        if not self._lib:
            return
        try:
            self._lib.OQS_SIG_new.restype   = ctypes.c_void_p
            self._lib.OQS_SIG_free.argtypes = [ctypes.c_void_p]
            self._sig = self._lib.OQS_SIG_new(variant.encode())
            if not self._sig:
                return

            class OQS_SIG(ctypes.Structure):
                _fields_ = [
                    ("method_name",        ctypes.c_char_p),
                    ("alg_version",        ctypes.c_char_p),
                    ("claimed_nist_level", ctypes.c_uint8),
                    ("euf_cma",            ctypes.c_uint8),
                    ("length_public_key",  ctypes.c_size_t),
                    ("length_secret_key",  ctypes.c_size_t),
                    ("length_signature",   ctypes.c_size_t),
                ]
            s = ctypes.cast(self._sig, ctypes.POINTER(OQS_SIG)).contents
            self.pk_len  = s.length_public_key
            self.sk_len  = s.length_secret_key
            self.sig_len = s.length_signature
            self.active  = True
            log.info(f"Dilithium DSA ready: {variant}")
        except Exception as e:
            log.warning(f"Dilithium init error: {e} — using HMAC-SHA3 fallback")

    def keygen(self) -> Tuple[bytes, bytes]:
        if not self.active:
            sk = os.urandom(32)
            return sk, sk   # symmetric fallback: pk == sk
        pk = (ctypes.c_uint8 * self.pk_len)()
        sk = (ctypes.c_uint8 * self.sk_len)()
        self._lib.OQS_SIG_keypair(self._sig, pk, sk)
        return bytes(pk), bytes(sk)

    def sign(self, secret_key: bytes, message: bytes) -> bytes:
        if not self.active:
            return hmac.new(secret_key, message, hashlib.sha3_256).digest()
        sig     = (ctypes.c_uint8 * self.sig_len)()
        sig_len = ctypes.c_size_t(self.sig_len)
        sk_arr  = (ctypes.c_uint8 * len(secret_key))(*secret_key)
        self._lib.OQS_SIG_sign(
            self._sig, sig, ctypes.byref(sig_len),
            (ctypes.c_uint8 * len(message))(*message), len(message), sk_arr
        )
        return bytes(sig)[:sig_len.value]

    def verify(self, public_key: bytes, message: bytes, signature: bytes) -> bool:
        if not self.active:
            expected = hmac.new(public_key, message, hashlib.sha3_256).digest()
            return hmac.compare_digest(expected, signature)
        pk_arr  = (ctypes.c_uint8 * len(public_key))(*public_key)
        sig_arr = (ctypes.c_uint8 * len(signature))(*signature)
        msg_arr = (ctypes.c_uint8 * len(message))(*message)
        ret = self._lib.OQS_SIG_verify(
            self._sig, msg_arr, len(message), sig_arr, len(signature), pk_arr
        )
        return ret == 0

    def __del__(self):
        if self._sig and self._lib:
            try:
                self._lib.OQS_SIG_free(self._sig)
            except Exception:
                pass


# ── High-level API ────────────────────────────────────────────────────────────
class QuantumCrypto:
    """
    Unified post-quantum crypto API for Cyberwall.
    - Encrypts threat events with Kyber1024 + AES-256-GCM
    - Signs events with Dilithium5
    - Falls back to X25519 + AES-256-GCM + HMAC-SHA3 when liboqs unavailable
    """

    def __init__(self):
        self.kem = KyberKEM()
        self.dsa = DilithiumDSA()
        mode = "Kyber1024+Dilithium5" if (self.kem.active and self.dsa.active) else "X25519+AES256GCM+HMAC-SHA3"
        log.info(f"QuantumCrypto initialized — mode: {mode}")

    def keygen(self) -> Tuple[bytes, bytes]:
        """Generate KEM keypair."""
        return self.kem.keygen()

    def encapsulate(self, public_key: bytes) -> Tuple[bytes, bytes]:
        """Encapsulate — returns (ciphertext, shared_secret)."""
        return self.kem.encapsulate(public_key)

    def decapsulate(self, secret_key: bytes, ciphertext: bytes) -> bytes:
        """Decapsulate — returns shared_secret."""
        return self.kem.decapsulate(secret_key, ciphertext)

    def sign_keygen(self) -> Tuple[bytes, bytes]:
        """Generate DSA keypair for signing."""
        return self.dsa.keygen()

    def encrypt_event(self, event: dict, recipient_public_key: bytes) -> dict:
        """
        Encrypt a threat event for secure transport.
        Returns envelope: {alg, ciphertext_kem, ciphertext_data, timestamp}
        """
        plaintext = json.dumps(event).encode()
        ct_kem, ss = self.kem.encapsulate(recipient_public_key)
        ct_data    = aes_encrypt(ss, plaintext)
        return {
            "alg":            "Kyber1024+AES256GCM" if self.kem.active else "X25519+AES256GCM",
            "ciphertext_kem": ct_kem.hex(),
            "ciphertext_data": ct_data.hex(),
            "timestamp":      int(time.time()),
        }

    def decrypt_event(self, envelope: dict, secret_key: bytes) -> dict:
        """Decrypt an encrypted threat event envelope."""
        ct_kem  = bytes.fromhex(envelope["ciphertext_kem"])
        ct_data = bytes.fromhex(envelope["ciphertext_data"])
        ss      = self.kem.decapsulate(secret_key, ct_kem)
        plain   = aes_decrypt(ss, ct_data)
        return json.loads(plain)

    def sign_event(self, event: dict, signing_key: bytes) -> str:
        """Sign a threat event dict. Returns hex signature."""
        msg = json.dumps(event, sort_keys=True).encode()
        return self.dsa.sign(signing_key, msg).hex()

    def verify_event(self, event: dict, signature: str, verify_key: bytes) -> bool:
        """Verify a threat event signature."""
        msg = json.dumps(event, sort_keys=True).encode()
        try:
            return self.dsa.verify(verify_key, msg, bytes.fromhex(signature))
        except Exception:
            return False

    @property
    def mode(self) -> str:
        if self.kem.active and self.dsa.active:
            return "post-quantum (Kyber1024 + Dilithium5)"
        return "classical (X25519 + AES-256-GCM + HMAC-SHA3-256)"
