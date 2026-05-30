<p align="center">
  <img src="./assets/banner.svg" alt="Sorabbyngo Cyberwall" width="800"/>
</p>

<h2 align="center">Sorabbyngo Cyberwall</h2>
<p align="center">
  AI-native firewall and malware defence for Linux — built in Africa, hardened for Africa
</p>

<p align="center">
  <img src="https://img.shields.io/badge/tests-260%20passing-brightgreen?style=flat-square"/>
  <img src="https://img.shields.io/badge/coverage-78%25-brightgreen?style=flat-square"/>
  <img src="https://img.shields.io/badge/detection-100%25-brightgreen?style=flat-square"/>
  <img src="https://img.shields.io/badge/kernel-eBPF%2FXDP-orange?style=flat-square&logo=linux&logoColor=white"/>
  <img src="https://img.shields.io/badge/offline--first-yes-blue?style=flat-square"/>
  <img src="https://img.shields.io/badge/cloud-none-blue?style=flat-square"/>
</p>

---

## What this is

Cyberwall is a production security daemon that runs on any Linux system. It enforces
firewall rules at the kernel level, detects malware in real time, and serves a live
threat dashboard — all without sending a single byte to the cloud.

It ships as part of Sorabbyngo OS but runs standalone on Ubuntu, Debian, and Kali.
A hospital in Kisii can install it in two minutes and immediately have kernel-level
protection against the exact threats hitting African infrastructure today.

---

## Why it exists

African hospitals, ISPs, and edge deployments face a specific threat landscape that
Western security vendors do not address:

| Threat | Target | Why Western tools miss it |
|---|---|---|
| Mirai / Mozi / Gafgyt | IoT routers, edge devices | Signatures tuned for US/EU infrastructure |
| XMRig ARM | Raspberry Pi, edge-os | Cryptominer variants for ARM ignored |
| FHIR / DICOM ransomware | Hospital EHR systems | Healthcare-specific payloads, African CERT data |
| PHP webshells on Django | Novela health endpoints | Africa-specific deployment patterns |
| Sorabbyngo NodeID theft | Hardware identity layer | Unique to Sorabbyngo OS |

Cyberwall ships with signatures and YARA rules built specifically for these threats.
No vendor covers this. We do.

---

## Install in two minutes

```bash
# Standalone — no NATS, no Ollama, no Sorabbyngo OS required
sudo bash scripts/install.sh --standalone

# Monitor-only — no firewall rules (safe to run on live production systems)
sudo bash scripts/install.sh --standalone --monitor-only

# Full stack — with NATS JetStream + AI analyzer
sudo bash scripts/install.sh --full
```

After install:

```bash
cyberwall start          # start the daemon
cyberwall status         # check status
cyberwall logs           # follow logs
cyberwall test           # run detection harness
cyberwall intel          # refresh threat signatures
```

Open the threat dashboard at **http://localhost:8888**

---

## Architecture
┌─────────────────────────────────────────────────────────────┐
│                    Cyberwall Daemon                          │
│                                                             │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────────┐  │
│  │  Firewall    │  │  Malware     │  │  Sentinel        │  │
│  │  Engine      │  │  Scanner     │  │  Bridge          │  │
│  │              │  │              │  │                  │  │
│  │  nftables    │  │  process mon │  │  NATS publisher  │  │
│  │  eBPF XDP    │  │  file integ  │  │  CML feed        │  │
│  │  rate limit  │  │  syscall     │  │  NodeID-signed   │  │
│  │  geo-block   │  │  quarantine  │  │  alerts          │  │
│  └──────┬───────┘  └──────┬───────┘  └────────┬─────────┘  │
│         └─────────────────┴──────────────────┘             │
│                      Core Engine                            │
│        event bus · threat scorer · policy engine            │
│        AI anomaly detection (phi4-mini, on-device)          │
│        Threat Dashboard (http://localhost:8888)             │
└─────────────────────────────────────────────────────────────┘

### Five engines

**Firewall engine** — nftables + eBPF XDP. Packets are inspected and dropped at the
NIC driver level before the kernel network stack. On edge hardware this is the
difference between surviving a DDoS and not. Detects port scans, SYN floods, NULL
scans, XMAS scans. Falls back to nftables userspace if eBPF unavailable.

**Malware scanner** — file integrity baseline across watched paths, process monitor,
deep scanner (SHA256 hash DB + YARA rules + built-in byte patterns). Quarantines
detected files with secure permissions. Runs non-blocking in executor threads.

**Syscall watcher** — scans `/proc` for fileless malware indicators: `memfd_create`,
deleted executables still running, `/dev/shm` execution, suspicious cmdline patterns.
Rate-limited to prevent alert storms.

**Sentinel bridge** — publishes NodeID-signed threat events to NATS JetStream. Every
alert carries hardware identity from the Sorabbyngo NodeID layer. Hot-reload policy
via NATS subscription. Falls back to log-only mode if NATS unavailable.

**AI analyzer** — phi4-mini via Ollama, triggered at MEDIUM+ threat score. Fully
on-device, no external API calls. Returns severity, attack vector, recommended action,
and false positive probability.

---

## Detection
Detection rate (mock mode, no root):  100%  (6/6 file-based scenarios)
Network scenarios (require root):     port_scan, brute_force, syn_flood, lateral_movement
Scenarios tested:
file_drop       PASS  — webshell, miner, reverse shell, UPX-packed ELF
process_spawn   PASS  — dropper artifacts with cryptominer signatures
webshell        PASS  — PHP eval+base64_decode, passthru GET/POST
cryptominer     PASS  — XMRig stratum TCP/SSL patterns
data_exfil      PASS  — patient health records + outbound pattern
memfd           PASS  — fileless payload dump with webshell + nodeid patterns

Run the detection harness yourself:

```bash
python3 -m tests.simulation.detection_harness --mock
```

---

## Threat intelligence

Signatures ship in two layers:

**Built-in (offline, ships with repo)** — 34 signatures across:
- Botnet: Mirai, Mirai.Okiru, Mirai.Satori, Mozi, Gafgyt, Tsunami
- Cryptominer: XMRig x64, XMRig ARM, XMRig Musl
- Ransomware: HealthLocker.A, MedCrypt.Novela, EHR.Ransomware.Africa
- Webshell: c99shell, WSO, r57shell
- Rootkit: SorabbyngoNodeID.Stealer
- Pattern-derived: 15 hashes from exact malware byte signatures

**Live import (network)** — pulls from MalwareBazaar bulk CSV (no auth required):

```bash
python3 scripts/import_threat_intel.py --bulk-csv --africa --db /var/lib/cyberwall/signatures.db
```

With an abuse.ch API key:

```bash
python3 scripts/import_threat_intel.py --all --api-key YOUR_KEY
```

---

## Threat dashboard

Live web UI at **http://localhost:8888** — no frontend build step, no npm, no Node.
Embedded asyncio HTTP + WebSocket server, served from memory.

- Real-time event feed with CRITICAL / HIGH / MEDIUM / LOW badges
- 60-second rolling threat timeline (Chart.js)
- Threat type bar chart (top 8 types)
- Severity doughnut chart
- Stat cards: total events, critical, high, blocked IPs, uptime
- WebSocket auto-reconnect, history replay on connect
- JSON API: `/api/stats`, `/api/events`

---

## Running

```bash
# Development (no root, no firewall rules)
python3 cyberwall_daemon.py --monitor-only --no-root-checks

# Production (requires root for eBPF + nftables)
sudo python3 cyberwall_daemon.py --config /etc/sorabbyngo/cyberwall.yaml

# With custom dashboard port
python3 cyberwall_daemon.py --monitor-only --no-root-checks --dashboard-port 9000

# Disable dashboard
python3 cyberwall_daemon.py --monitor-only --no-root-checks --no-dashboard
```

---

## Testing

```bash
# Full test suite
python -m pytest tests/ -v

# Coverage report
python -m pytest tests/ --cov=cyberwall --cov-report=html

# Detection harness (runs all attack scenarios)
python3 -m tests.simulation.detection_harness --mock

# Single scenario
python3 -m tests.simulation.attack_simulator --scenario webshell
python3 -m tests.simulation.attack_simulator --list
```

Current: **260 tests passing**, **78.81% coverage**

---

## Configuration

```yaml
# /etc/sorabbyngo/cyberwall.yaml

firewall:
  interface: eth0
  allowed_inbound_ports: [22, 80, 443, 8080, 8443]
  rate_limit:
    ssh:  { limit: "5/minute",   burst: 10  }
    http: { limit: "100/minute", burst: 200 }

malware:
  watch_paths: [/etc, /bin, /usr/bin, /opt/sorabbyngo]
  scan_interval_seconds: 30
  auto_quarantine_level: HIGH

response:
  auto_block_level:      HIGH
  auto_quarantine_level: CRITICAL
  alert_level:           LOW

ai:
  enabled:       true
  model:         phi4-mini
  analyze_level: MEDIUM
```

Hot-reload policy without restarting the daemon:

```bash
cyberwall reload
# or via NATS:
nats pub sorabbyngo.cyberwall.policy.reload ""
```

---

## NATS subjects

| Subject | Direction | Description |
|---|---|---|
| `sorabbyngo.cyberwall.alert` | Publish | Threat alert to sentinel |
| `sorabbyngo.cyberwall.block` | Publish | IP/process block event |
| `sorabbyngo.cyberwall.status` | Publish | Heartbeat every 30s |
| `sorabbyngo.cyberwall.policy.reload` | Subscribe | Hot-reload policy |
| `sorabbyngo.cml.filter.request` | Publish | CML safety check for HIGH+ |

---


---

## Advanced Security Capabilities

### Post-Quantum Encryption (CRYSTALS-Kyber + Dilithium)

| Algorithm | Standard | Purpose | Security Level |
|---|---|---|---|
| ML-KEM (Kyber1024) | NIST FIPS 203 | Key encapsulation for threat event transport | 256-bit post-quantum |
| ML-DSA (Dilithium5) | NIST FIPS 204 | NodeID-bound digital signatures on every alert | NIST Level 5 |
| AES-256-GCM | NIST SP 800-38D | Symmetric encryption of event payloads | 256-bit classical |
| X25519 + HKDF | RFC 7748 | Classical KEM fallback when liboqs unavailable | 128-bit classical |
| HMAC-SHA3-256 | FIPS 202 | Signature fallback when liboqs unavailable | 256-bit classical |

**How it works:** Every threat event is encrypted with Kyber1024 (key encapsulation) +
AES-256-GCM (payload). Every alert published to NATS carries a Dilithium5 signature
bound to the node's hardware identity (Sorabbyngo NodeID). Resistant to quantum
adversaries harvesting encrypted traffic today to decrypt later.

**Fallback:** When liboqs C library is not installed, the system automatically uses
X25519 + AES-256-GCM + HMAC-SHA3-256 — classical crypto that's still strong today.

**Install liboqs:**
```bash
sudo apt-get install cmake ninja-build libssl-dev
git clone --depth 1 https://github.com/open-quantum-safe/liboqs.git
cd liboqs && cmake -GNinja -DBUILD_SHARED_LIBS=ON . && ninja && sudo ninja install
sudo ldconfig
```

---

### Blockchain Audit Ledger (SHA3-256 + Merkle Tree)

| Component | Algorithm | Purpose |
|---|---|---|
| Block hash | SHA3-256 | Tamper-evident chaining — each block commits to all predecessors |
| Proof-of-work | SHA3-256 with difficulty prefix | Proves computational effort, prevents retroactive rewriting |
| Merkle tree | SHA3-256 binary tree | O(log n) inclusion proofs — verify any event without full chain |
| Chain linkage | prev_hash field | Every block references predecessor — break one, invalidate all |

**Structure:** Each block contains: `{index, timestamp, node_id, event_type, data,
prev_hash, nonce, hash, merkle_root}`. The chain hash is:
`SHA3-256(prev_hash + index + timestamp + node_id + data + nonce)`.

**Merkle proofs:** Every batch of 64 events gets a Merkle root. Anyone can verify that
a specific event was recorded without downloading the full chain.

**Audit:** Run `ledger.verify()` to check full chain integrity in O(n) time. Export
the JSONL file to any third party — they can verify every event independently.

---

### Polymorphic Malware Reverse Engineering

| Technique | What it detects | Implementation |
|---|---|---|
| Shannon entropy analysis | Packed / encrypted / polymorphic code | Sliding window entropy over 256-byte blocks |
| Entropy profiling | Encrypted sections within binaries | Per-region entropy map |
| NOP sled detection | Shellcode injection staging | Pattern match: x86/ARM NOP variants |
| String extraction | Suspicious imports, C2 URLs, crypto APIs | Printable ASCII extraction + keyword match |
| Disassembly analysis | Control flow obfuscation | Capstone (x86_64/ARM/ARM64) |
| Jump density analysis | Opaque predicates, spaghetti code | Ratio of jmp/call to total instructions |
| XOR density analysis | Decryption loops, key scheduling | XOR instruction frequency |
| Invariant core extraction | Mutation-resistant payload bytes | Low-entropy block selection |
| YARA rule generation | Auto-signature from invariant bytes | Hex string rules from extracted core |
| Variant diffing | Same-family detection across mutations | 4-gram Jaccard similarity + entropy drift |

**Polymorphic detection scoring:** A sample is flagged as polymorphic when:
entropy > 7.0 (+3) + is_packed (+2) + obfuscation_score > 5 (+3) + NOP sleds (+1) + suspicious imports > 3 (+1) ≥ 5.

**Supported architectures:** x86, x86-64, ARM, ARM64 (via Capstone disassembler).

---

### Tor C2 Traffic Detection

| Method | What it catches | Data source |
|---|---|---|
| Exit node IP list | Direct connections from Tor exit nodes | check.torproject.org bulk list (updated every 4h) |
| Known CIDR ranges | torservers.net, Scaleway exits, tor.in.ua | Hardcoded — updated in releases |
| TLS fingerprinting | Tor's distinctive ClientHello cipher suite | Tor cipher suite overlap analysis |
| Tor cell detection | Fixed 514-byte cell-aligned traffic | Traffic size pattern matching |
| .onion DNS leakage | Malware attempting to resolve .onion domains | Regex on DNS query payloads |
| Tor port detection | Direct SOCKS5 proxy / relay connections | Ports: 9001, 9030, 9050, 9051, 9150 |

**Why this matters for Africa:** XMRig variants targeting African edge infrastructure
increasingly route mining pool connections over Tor to evade ISP-level blocking.
Ransomware C2 on African hospital networks uses Tor to hide the operator.
This detector catches both without blocking legitimate Tor browser usage.

**What we do NOT do:** We do not run a Tor node, relay, or exit. We do not block
all Tor traffic. We detect MALWARE using Tor for C2 — flagged as HIGH threat,
routed to Sentinel for operator review.

---

## Cryptographic Algorithms Reference
Encryption layer (outbound alerts):
Primary:  ML-KEM-1024 (Kyber) + AES-256-GCM
NIST FIPS 203 + SP 800-38D
Fallback: X25519 (ECDH) + AES-256-GCM
RFC 7748 + NIST SP 800-38D
KDF:      SHA3-256 (shared secret → AES key)
Signature layer (event integrity):
Primary:  ML-DSA-87 (Dilithium5)
NIST FIPS 204
Fallback: HMAC-SHA3-256
FIPS 202 + RFC 2104
Audit chain:
Block hash:  SHA3-256 (FIPS 202)
Merkle tree: SHA3-256 binary tree
PoW:         SHA3-256 with difficulty-2 prefix
File scanning:
Hash lookup: SHA-256 (FIPS 180-4)
Patterns:    PCRE + YARA
RE engine:   Capstone disassembler + entropy analysis
Transport:
NATS JetStream over TLS 1.3 (OpenSSL 3.6.1)
NodeID binding: hardware-derived identifier
---

## For Future Developers

### Adding a new threat detection module

```python
# 1. Create cyberwall/your_module/detector.py
# 2. Subscribe to EventBus:
bus.subscribe("*", your_handler)
# 3. Publish threat events:
await bus.publish(ThreatEvent(
    source="your_module",
    threat_type="your_threat",
    level=ThreatLevel.HIGH,
    score=7.5,
    description="...",
))
# 4. Wire into cyberwall_daemon.py main()
# 5. Add tests in tests/unit/
```

### Extending the blockchain ledger

The ledger is append-only. To add a new event type:
```python
await ledger.append("your_event_type", {"key": "value"})
```
To verify the full chain at any time:
```python
valid, count = ledger.verify()
proof = ledger.get_proof(block_index)
assert ledger.verify_proof(proof)
```

### Upgrading quantum algorithms

When NIST finalizes additional post-quantum algorithms (ML-KEM-512, SLH-DSA),
update `KYBER_VARIANT` and `DILITHIUM_VARIANT` in `cyberwall/quantum/kyber.py`.
The ctypes binding works with any algorithm string that liboqs supports.
Check available algorithms: `python3 -c "import ctypes; ..."`

### Tor exit list maintenance

The exit list auto-updates from `check.torproject.org` every 4 hours.
To add known Tor CIDR ranges: edit `TOR_KNOWN_CIDR` in `cyberwall/tor/detector.py`.
To increase detection confidence: extend `TOR_TLS_CIPHERS` with new Tor cipher suites.

## Part of Sorabbyngo OS

| Repo | Role |
|---|---|
| [sorabbyngo-os](https://github.com/sorabbyngo-os/sorabbyngo-os) | Kernel (Linux 6.19.10) |
| [sentinel-os](https://github.com/sorabbyngo-os/sentinel-os) | Security operations OS |
| [security](https://github.com/citadel-sec/security) | 7-ring defence architecture |
| [dmz](https://github.com/sorabbyngo-os/dmz) | One-way wall — PRIME isolation |
| [cml](https://github.com/sorabbyngo-os/cml) | Safety and audit layer |
| [byngonet](https://github.com/sorabbyngo-os/byngonet) | Secure mesh protocol |
| [novela](https://github.com/sorabbyngo-os/novela) | Africa-first AI health platform |

Cyberwall also runs standalone on any Ubuntu 20.04+ / Debian 11+ system.

---

## Threat model

Cyberwall is designed for Tier 1 through Tier 3 deployments:

- **Tier 1** (edge, IoT, Raspberry Pi) — monitor-only mode, pattern engine only, no eBPF
- **Tier 2** (hospital server, ISP node) — full nftables + eBPF, malware scanner, AI analyzer
- **Tier 3** (data centre, sentinel node) — full stack + NATS mesh + CML safety layer

Tested against: Kali Linux 2026, Ubuntu 24.04, Debian 12.

---

**Sorabbyngo Company** · Kisii, Kenya · 2026
*Rhythm of Digital Life*
