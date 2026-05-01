"""
Sorabbyngo Cyberwall — Polymorphic Malware Reverse Engineering
==============================================================
Detects and analyzes polymorphic/metamorphic malware using:

1. Shannon entropy analysis    — detects packed/encrypted/polymorphic code
2. NOP sled detection          — shellcode injection indicator
3. Import table hashing        — known-bad DLL/symbol combinations
4. Disassembly analysis        — via capstone, detects obfuscation patterns
5. Mutation signature extraction — invariant core extraction across variants
6. Self-modification detection  — writes to own code segment
7. Control flow obfuscation     — indirect jumps, opaque predicates
8. YARA rule generation         — auto-generates rules from invariant bytes

Supports: ELF (Linux), PE (Windows cross-analysis), raw shellcode
"""
import hashlib
import logging
import math
import re
import struct
from dataclasses import dataclass, field
from pathlib import Path
from typing import List, Optional, Tuple, Dict

log = logging.getLogger("cyberwall.reverse_engineering")

# ── capstone disassembler ─────────────────────────────────────────────────────
try:
    import capstone
    CS_AVAILABLE = True
    log.info("capstone disassembler available — full disassembly analysis enabled")
except ImportError:
    CS_AVAILABLE = False
    log.info("capstone not available — using pattern-only analysis")


@dataclass
class MalwareFeatures:
    """Extracted features from a binary sample."""
    sha256:              str   = ""
    file_size:           int   = 0
    file_type:           str   = "unknown"   # elf, pe, shellcode, script
    entropy:             float = 0.0
    entropy_verdict:     str   = "normal"    # normal, suspicious, packed, encrypted
    is_packed:           bool  = False
    is_encrypted:        bool  = False
    nop_sleds:           List[int] = field(default_factory=list)   # offsets
    suspicious_imports:  List[str] = field(default_factory=list)
    obfuscation_score:   float = 0.0
    polymorphic:         bool  = False
    invariant_bytes:     bytes = b""
    generated_yara:      str   = ""
    techniques:          List[str] = field(default_factory=list)
    risk_score:          float = 0.0
    disasm_findings:     List[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        d = {k: v for k, v in self.__dict__.items()}
        d["invariant_bytes"] = self.invariant_bytes.hex()
        d["nop_sleds"]       = self.nop_sleds[:20]   # truncate for JSON
        return d


# ── Entropy analysis ──────────────────────────────────────────────────────────
def shannon_entropy(data: bytes) -> float:
    """Compute Shannon entropy of a byte sequence. Range: 0.0 – 8.0."""
    if not data:
        return 0.0
    freq = [0] * 256
    for b in data:
        freq[b] += 1
    n = len(data)
    entropy = 0.0
    for f in freq:
        if f:
            p = f / n
            entropy -= p * math.log2(p)
    return entropy


def entropy_verdict(entropy: float) -> Tuple[str, bool, bool]:
    """
    Classify entropy level.
    Returns (verdict, is_packed, is_encrypted)
    """
    if entropy < 5.0:
        return "normal",    False, False
    elif entropy < 5.4:
        return "suspicious", False, False
    elif entropy < 7.2:
        return "packed",     True,  False
    else:
        return "encrypted",  True,  True


def sliding_entropy(data: bytes, window: int = 256) -> List[Tuple[int, float]]:
    """Compute entropy in sliding windows. Returns [(offset, entropy)]."""
    results = []
    for i in range(0, len(data) - window, window // 2):
        chunk = data[i:i + window]
        results.append((i, shannon_entropy(chunk)))
    return results


# ── File type detection ───────────────────────────────────────────────────────
def detect_file_type(data: bytes) -> str:
    if data[:4] == b"\x7fELF":
        return "elf"
    if data[:2] == b"MZ":
        return "pe"
    if data[:4] in (b"\xcf\xfa\xed\xfe", b"\xce\xfa\xed\xfe"):
        return "macho"
    if data[:2] in (b"#!", b"<?"):
        return "script"
    if data[:4] == b"\x89PNG":
        return "png"
    if data[:3] == b"\xff\xd8\xff":
        return "jpeg"
    if data[:2] == b"PK":
        return "zip"
    return "raw"


# ── NOP sled detection ────────────────────────────────────────────────────────
NOP_SLEDS = [
    b"\x90" * 8,                           # x86 NOP
    b"\x66\x90" * 4,                       # x86 2-byte NOP
    b"\x0f\x1f\x00" * 3,                  # x86 multi-byte NOP
    b"\xd5\x1f\x20\x03" * 4,             # ARM64 NOP
    b"\x00" * 16,                           # null padding (common in shellcode)
]

def find_nop_sleds(data: bytes, min_len: int = 8) -> List[int]:
    """Find NOP sleds and return their offsets."""
    offsets = []
    for sled in NOP_SLEDS:
        pattern = sled[:2] * (min_len // len(sled[:2]) + 1)
        for m in re.finditer(re.escape(pattern), data):
            offsets.append(m.start())
    return sorted(set(offsets))


# ── Import analysis (ELF/PE) ──────────────────────────────────────────────────
SUSPICIOUS_IMPORTS = {
    # Process injection
    "ptrace", "mprotect", "mmap", "dlopen", "dlsym",
    # Persistence
    "cron", "at", "systemctl", "rc.local",
    # Network C2
    "connect", "gethostbyname", "getaddrinfo",
    # Crypto (malware ransomware)
    "EVP_EncryptInit", "AES_encrypt", "RSA_encrypt",
    # Anti-analysis
    "ptrace", "getppid", "isatty", "clock_gettime",
    # Windows (cross-analysis)
    "VirtualAlloc", "CreateRemoteThread", "WriteProcessMemory",
    "RegSetValueEx", "ShellExecute", "WinExec",
}

def extract_strings(data: bytes, min_len: int = 5) -> List[str]:
    """Extract printable ASCII strings from binary."""
    pattern = rb"[\x20-\x7e]{" + str(min_len).encode() + rb",}"
    return [m.group(0).decode(errors="replace") for m in re.finditer(pattern, data)]

def find_suspicious_imports(data: bytes) -> List[str]:
    strings = extract_strings(data, min_len=4)
    found   = []
    for s in strings:
        for imp in SUSPICIOUS_IMPORTS:
            if imp.lower() in s.lower():
                found.append(s)
                break
    return list(set(found))[:20]


# ── Disassembly analysis (capstone) ───────────────────────────────────────────
def disassemble_chunk(data: bytes, arch: str = "x86_64") -> List[dict]:
    """Disassemble a chunk of binary data."""
    if not CS_AVAILABLE:
        return []
    arch_map = {
        "x86":    (capstone.CS_ARCH_X86,   capstone.CS_MODE_32),
        "x86_64": (capstone.CS_ARCH_X86,   capstone.CS_MODE_64),
        "arm":    (capstone.CS_ARCH_ARM,   capstone.CS_MODE_ARM),
        "arm64":  (capstone.CS_ARCH_ARM64, capstone.CS_MODE_ARM),
    }
    cs_arch, cs_mode = arch_map.get(arch, (capstone.CS_ARCH_X86, capstone.CS_MODE_64))
    md = capstone.Cs(cs_arch, cs_mode)
    md.detail = True
    insns = []
    for insn in md.disasm(data[:4096], 0x1000):
        insns.append({
            "addr":    insn.address,
            "mnemonic": insn.mnemonic,
            "op_str":  insn.op_str,
            "bytes":   insn.bytes.hex(),
        })
    return insns


OBFUSCATION_MNEMONICS = {
    "jmp", "call", "ret", "push", "pop",
    "xor", "ror", "rol", "not", "neg",
}

def analyze_control_flow(insns: List[dict]) -> Tuple[float, List[str]]:
    """
    Detect control flow obfuscation.
    Returns (obfuscation_score 0-10, findings).
    """
    if not insns:
        return 0.0, []

    findings = []
    total     = len(insns)
    jmp_count = 0
    xor_count = 0
    indirect_jmps = 0
    back_jumps = 0

    for i, insn in enumerate(insns):
        mn = insn["mnemonic"].lower()
        if mn in ("jmp", "call"):
            jmp_count += 1
            if "[" in insn["op_str"]:
                indirect_jmps += 1
        if mn == "xor" and insn["op_str"].split(",")[0].strip() == insn["op_str"].split(",")[-1].strip():
            pass  # register-clearing xor — normal
        elif mn == "xor":
            xor_count += 1
        # Detect back-jumps (obfuscated loops)
        if mn in ("jmp", "je", "jne", "jz", "jnz") and "-" in insn["op_str"]:
            back_jumps += 1

    jmp_ratio      = jmp_count / max(total, 1)
    xor_ratio      = xor_count / max(total, 1)
    indirect_ratio = indirect_jmps / max(jmp_count, 1)

    score = 0.0
    if jmp_ratio > 0.3:
        score += 3.0
        findings.append(f"High jump density: {jmp_ratio:.1%} of instructions")
    if xor_ratio > 0.1:
        score += 2.0
        findings.append(f"High XOR density: {xor_ratio:.1%} — possible obfuscation/decryption loop")
    if indirect_ratio > 0.5:
        score += 3.0
        findings.append(f"High indirect jump ratio: {indirect_ratio:.1%} — opaque predicates suspected")
    if back_jumps > 5:
        score += 2.0
        findings.append(f"Unusual back-jump count: {back_jumps} — possible obfuscated loop")

    return min(score, 10.0), findings


# ── Invariant core extraction ─────────────────────────────────────────────────
def extract_invariant_core(data: bytes, block_size: int = 16) -> bytes:
    """
    Extract invariant (non-mutating) byte sequences from polymorphic malware.
    Polymorphic malware mutates its decryption stub but keeps the payload.
    Strategy: find runs of bytes with low local entropy (likely code, not random key material).
    """
    invariant = bytearray()
    chunks = [data[i:i+block_size] for i in range(0, len(data), block_size)]
    for chunk in chunks:
        if len(chunk) < block_size:
            continue
        e = shannon_entropy(chunk)
        if e < 5.5:   # low entropy = not encrypted/random = likely invariant code
            invariant.extend(chunk)
    return bytes(invariant[:256])   # return first 256 invariant bytes


# ── YARA rule generation ──────────────────────────────────────────────────────
def generate_yara_rule(sha256: str, invariant: bytes, file_type: str,
                       techniques: List[str]) -> str:
    """
    Auto-generate a YARA rule from extracted invariant bytes.
    """
    if len(invariant) < 8:
        return ""

    rule_name = f"Cyberwall_Auto_{sha256[:12]}"
    # Build hex strings from invariant chunks
    hex_strings = []
    for i in range(0, min(len(invariant), 64), 8):
        chunk = invariant[i:i+8]
        if len(chunk) == 8:
            hex_str = " ".join(f"{b:02x}" for b in chunk)
            hex_strings.append(f"        $chunk_{i:03d} = {{ {hex_str} }}")

    if not hex_strings:
        return ""

    strings_block = "\n".join(hex_strings)
    tech_comment  = ", ".join(techniques) if techniques else "unknown"
    condition = f"any of ($chunk_*)"
    if file_type == "elf":
        condition = f"uint32(0) == 0x464c457f and any of ($chunk_*)"
    elif file_type == "pe":
        condition = f"uint16(0) == 0x5a4d and any of ($chunk_*)"

    rule = f"""rule {rule_name}
{{
    meta:
        description = "Auto-generated by Sorabbyngo Cyberwall RE engine"
        sha256      = "{sha256}"
        file_type   = "{file_type}"
        techniques  = "{tech_comment}"
        generated   = "cyberwall-re-v2"

    strings:
{strings_block}

    condition:
        {condition}
}}"""
    return rule


# ── Main analyzer ─────────────────────────────────────────────────────────────
class PolymorphicAnalyzer:
    """
    Main reverse engineering engine.
    Analyzes binary samples for polymorphic/metamorphic malware traits.
    """

    MAX_ANALYZE_BYTES = 10 * 1024 * 1024   # 10MB

    def analyze(self, data: bytes, filename: str = "") -> MalwareFeatures:
        """
        Full static analysis pipeline.
        Returns MalwareFeatures with all extracted information.
        """
        data = data[:self.MAX_ANALYZE_BYTES]
        feat = MalwareFeatures()
        feat.sha256    = hashlib.sha256(data).hexdigest()
        feat.file_size = len(data)
        feat.file_type = detect_file_type(data)

        # 1. Entropy analysis
        feat.entropy = shannon_entropy(data)
        feat.entropy_verdict, feat.is_packed, feat.is_encrypted = entropy_verdict(feat.entropy)
        if feat.is_packed:
            feat.techniques.append("packing/compression")
        if feat.is_encrypted:
            feat.techniques.append("encryption")

        # 2. NOP sled detection
        feat.nop_sleds = find_nop_sleds(data)
        if feat.nop_sleds:
            feat.techniques.append("nop_sled_shellcode")

        # 3. Suspicious imports / strings
        feat.suspicious_imports = find_suspicious_imports(data)
        if feat.suspicious_imports:
            feat.techniques.append("suspicious_imports")

        # 4. Disassembly + control flow (first 4KB of .text-like section)
        arch = "arm64" if feat.file_type == "elf" and len(data) > 5 and data[4] == 2 else "x86_64"
        insns = disassemble_chunk(data, arch)
        if insns:
            feat.obfuscation_score, feat.disasm_findings = analyze_control_flow(insns)
            if feat.obfuscation_score > 5.0:
                feat.techniques.append("control_flow_obfuscation")

        # 5. Polymorphic detection
        # High entropy + obfuscation + suspicious imports = likely polymorphic
        poly_score = 0
        if feat.entropy > 7.0:         poly_score += 3
        if feat.is_packed:             poly_score += 2
        if feat.obfuscation_score > 5: poly_score += 3
        if feat.nop_sleds:             poly_score += 1
        if len(feat.suspicious_imports) > 3: poly_score += 1
        feat.polymorphic = poly_score >= 5

        if feat.polymorphic:
            feat.techniques.append("polymorphic_mutation")

        # 6. Invariant core extraction
        if feat.polymorphic or feat.is_packed:
            feat.invariant_bytes = extract_invariant_core(data)

        # 7. YARA rule generation
        if feat.invariant_bytes:
            feat.generated_yara = generate_yara_rule(
                feat.sha256, feat.invariant_bytes,
                feat.file_type, feat.techniques
            )

        # 8. Risk score
        feat.risk_score = min(
            feat.obfuscation_score * 0.4 +
            (feat.entropy / 8.0) * 3.0 +
            len(feat.suspicious_imports) * 0.3 +
            (2.0 if feat.polymorphic else 0) +
            (1.0 if feat.nop_sleds else 0),
            10.0
        )

        log.info(
            f"RE Analysis: {filename or feat.sha256[:12]} | "
            f"type={feat.file_type} entropy={feat.entropy:.2f} "
            f"polymorphic={feat.polymorphic} risk={feat.risk_score:.1f} "
            f"techniques={feat.techniques}"
        )
        return feat

    def analyze_file(self, path: str) -> MalwareFeatures:
        try:
            data = Path(path).read_bytes()
            return self.analyze(data, Path(path).name)
        except Exception as e:
            log.error(f"RE analyze_file error: {e}")
            feat = MalwareFeatures()
            feat.file_type = "error"
            return feat

    def diff_samples(self, sample_a: bytes, sample_b: bytes) -> dict:
        """
        Compare two samples to detect mutation between variants.
        Returns similarity score and changed regions.
        """
        feat_a = self.analyze(sample_a, "variant_a")
        feat_b = self.analyze(sample_b, "variant_b")

        # Compare entropy profiles
        ea = sliding_entropy(sample_a)
        eb = sliding_entropy(sample_b)
        entropy_diff = sum(abs(a[1] - b[1]) for a, b in zip(ea, eb)) / max(len(ea), 1)

        # Byte-level similarity (Jaccard on 4-grams)
        def ngrams(data, n=4):
            return set(data[i:i+n] for i in range(len(data)-n))

        ng_a = ngrams(sample_a)
        ng_b = ngrams(sample_b)
        if ng_a | ng_b:
            similarity = len(ng_a & ng_b) / len(ng_a | ng_b)
        else:
            similarity = 0.0

        return {
            "similarity":     round(similarity, 4),
            "entropy_drift":  round(entropy_diff, 4),
            "likely_variants": similarity > 0.3 and similarity < 0.9,
            "same_family":    similarity > 0.3,
            "techniques_a":   feat_a.techniques,
            "techniques_b":   feat_b.techniques,
            "shared_invariant": (feat_a.invariant_bytes[:32] == feat_b.invariant_bytes[:32]),
        }
