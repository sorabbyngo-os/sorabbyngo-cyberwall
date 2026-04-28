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

## Part of Sorabbyngo OS

| Repo | Role |
|---|---|
| [sorabbyngo-os](https://github.com/sorabbyngo-Labs/sorabbyngo-os) | Kernel (Linux 6.19.10) |
| [sentinel-os](https://github.com/sorabbyngo-Labs/sentinel-os) | Security operations OS |
| [security](https://github.com/sorabbyngo-Labs/security) | 7-ring defence architecture |
| [dmz](https://github.com/sorabbyngo-Labs/dmz) | One-way wall — PRIME isolation |
| [cml](https://github.com/sorabbyngo-Labs/cml) | Safety and audit layer |
| [byngonet](https://github.com/sorabbyngo-Labs/byngonet) | Secure mesh protocol |
| [novela](https://github.com/sorabbyngo-Labs/novela) | Africa-first AI health platform |

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
