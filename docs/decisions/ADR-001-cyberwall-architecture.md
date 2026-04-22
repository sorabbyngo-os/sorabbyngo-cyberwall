# ADR-001: Cyberwall Architecture

## Status
Accepted

## Decision
Sorabbyngo Cyberwall is a standalone Python asyncio daemon with five
integrated engines communicating over an internal event bus.

## Engines
| Engine | Technology | Purpose |
|---|---|---|
| Firewall | nftables + asyncio | Packet filtering, IP blocking, rate limiting |
| Malware Scanner | psutil + hashlib | File integrity, process monitoring, quarantine |
| Syscall Watcher | /proc scan | Fileless malware, injection detection |
| Sentinel Bridge | NATS JetStream | Publish alerts to sentinel and CML |
| AI Analyzer | phi4-mini via Ollama | Deep threat analysis, local only |

## Design Principles
- All intelligence is local — no external API calls for threat analysis
- NodeID-signed events — every alert carries hardware identity
- CML integration — high threats route through safety layer
- Monitor-only mode — safe deployment on production without firewall risk
- Offline-first — full functionality without internet

## Integration Points
- Feeds into: sentinel_daemon.py (NATS), CML (safety filter)
- Reads from: /proc/sorabbyngo/nodeid, nftables kernel log
- Protects: all OS variants (novela-os, edge-os, server-os, byngo-os)

## Threat Response Matrix
| Level | Score | Auto-block | Quarantine | CML | AI Analysis |
|---|---|---|---|---|---|
| INFO | 1–2 | No | No | No | No |
| LOW | 3–4 | No | No | No | No |
| MEDIUM | 5–6 | No | No | No | Yes |
| HIGH | 7–8 | Yes | No | Yes | Yes |
| CRITICAL | 9–10 | Yes | Yes | Yes | Yes |
