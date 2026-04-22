<p align="center">
  <img src="https://raw.githubusercontent.com/sorabbyngo-Labs/.github/main/assets/sorabbyngo-logo.jpg" alt="Sorabbyngo" width="480"/>
</p>
<p align="center">
  <strong>Sorabbyngo Cyberwall — AI-native firewall and malware defence layer</strong>
</p>
<p align="center">
  Offline-first · Kernel-integrated · NATS-native · Africa-hardened
</p>

---

## What this is

Sorabbyngo Cyberwall is the active defence layer of SORABBYNGO OS. It runs as a
daemon on every OS variant — byngo-os, novela-os, edge-os, server-os — and
provides real-time firewall enforcement, malware detection, process integrity
monitoring, and AI-assisted threat analysis. All intelligence stays on-device.

---

## Architecture
┌─────────────────────────────────────────────────────────────┐
│                    sorabbyngo-cyberwall                      │
│                                                             │
│  ┌─────────────────┐  ┌─────────────────┐  ┌────────────┐  │
│  │  firewall       │  │  malware        │  │ sentinel   │  │
│  │  engine         │  │  scanner        │  │ bridge     │  │
│  │                 │  │                 │  │            │  │
│  │  nftables rules │  │  process mon    │  │ NATS pub   │  │
│  │  eBPF hooks     │  │  file integrity │  │ alerts     │  │
│  │  rate limiting  │  │  syscall watch  │  │ CML feed   │  │
│  │  geo-blocking   │  │  quarantine     │  │ NodeID sig │  │
│  └────────┬────────┘  └────────┬────────┘  └─────┬──────┘  │
│           └───────────────────┴─────────────────┘          │
│                         core engine                         │
│           threat scoring · policy engine · event bus        │
│           AI anomaly detection (phi4-mini via Ollama)       │
└─────────────────────────────────────────────────────────────┘
---

## Components

| Component | Purpose |
|---|---|
| `cyberwall/core/` | Event bus, threat scoring, policy engine |
| `cyberwall/firewall/` | nftables manager, eBPF hooks, rate limiter |
| `cyberwall/malware/` | Process monitor, file integrity, syscall watcher, quarantine |
| `cyberwall/sentinel_bridge/` | NATS publisher, CML integration, alert router |
| `cyberwall/ai/` | Ollama-based anomaly analysis (phi4-mini) |
| `cyberwall/policy/` | Policy loader, rule evaluator |
| `nats/` | NATS subject config for cyberwall |
| `configs/` | Per-variant configs (novela, edge, server, byngo) |
| `scripts/` | Install, start, stop helpers |

---

## NATS Subjects

| Subject | Direction | Description |
|---|---|---|
| `sorabbyngo.cyberwall.alert` | Publish | Threat alert to sentinel |
| `sorabbyngo.cyberwall.block` | Publish | IP/process block event |
| `sorabbyngo.cyberwall.status` | Publish | Heartbeat and health |
| `sorabbyngo.cyberwall.policy.reload` | Subscribe | Hot-reload policy |
| `sorabbyngo.cml.filter.request` | Publish | CML safety check |

---

## Quick Start

```bash
Install dependencies
sudo apt-get install -y nftables python3 python3-pip
pip install nats-py watchdog psutil pyyaml cryptography --break-system-packagesConfigure
cp configs/cyberwall.example.yaml configs/cyberwall.yamlStart (requires root for nftables + eBPF)
sudo python3 cyberwall_daemon.py --config configs/cyberwall.yaml

---

## Threat Levels

| Level | Score | Action |
|---|---|---|
| INFO | 0–2 | Log only |
| LOW | 3–4 | Alert via NATS |
| MEDIUM | 5–6 | Alert + rate limit |
| HIGH | 7–8 | Block + alert + CML |
| CRITICAL | 9–10 | Block + quarantine + emergency alert |

---

## Part of SORABBYNGO OS

| Repo | Role |
|---|---|
| [sorabbyngo-os](https://github.com/sorabbyngo-Labs/sorabbyngo-os) | Kernel source |
| [sentinel-os](https://github.com/sorabbyngo-Labs/sentinel-os) | Security operations OS |
| [security](https://github.com/sorabbyngo-Labs/security) | 7-ring defence architecture |
| [dmz](https://github.com/sorabbyngo-Labs/dmz) | One-way wall — PRIME isolation |
| [cml](https://github.com/sorabbyngo-Labs/cml) | Safety and audit layer |
| [byngonet](https://github.com/sorabbyngo-Labs/byngonet) | Secure mesh protocol |

---

**Sorabbyngo Company** · Kisii, Kenya · 2026
*Rhythm of Digital Life*
