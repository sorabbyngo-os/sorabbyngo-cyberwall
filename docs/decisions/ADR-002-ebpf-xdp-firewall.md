# ADR-002: eBPF XDP Firewall

## Status
Accepted

## Decision
Cyberwall uses a two-layer firewall:
- Layer 1: eBPF XDP (kernel-space, zero-copy) — when available
- Layer 2: nftables (userspace) — always present as fallback

## Why XDP
XDP runs before the kernel network stack. Packets are inspected
and dropped at the NIC driver level — no sk_buff allocation,
no routing, no conntrack overhead. On Tier 1 hardware (edge devices)
this is the difference between surviving a DDoS and not.

## Detection in kernel (bpf_program.c)
| Threat | Method | Action |
|---|---|---|
| Blocked IP | LPM trie lookup | XDP_DROP |
| Port scan | Distinct port bitmap per IP/window | XDP_DROP |
| Rate exceed | Packet counter per IP/window | XDP_DROP |
| SYN flood | SYN-only flag + rate check | XDP_DROP |
| NULL scan | TCP flags == 0 | XDP_DROP |
| XMAS scan | FIN+PSH+URG flags | XDP_DROP |

## Fallback
If bcc/libbpf not available OR not running as root:
- EBPFManager.setup() returns False
- FirewallEngine continues with nftables only
- No functionality lost, just higher CPU cost

## Maps
| Map | Type | Purpose |
|---|---|---|
| blocked_ips | LPM_TRIE | Blocked IP prefixes (CIDR support) |
| rate_limit_map | LRU_HASH | Per-IP packet/port counters |
| threat_events | RINGBUF | Kernel→userspace event stream |
| stats_map | ARRAY | Global packet counters |

## Integration
EBPFManager sits inside FirewallEngine.
block_ip() calls both nftables AND eBPF map update simultaneously.
Events from ring buffer feed the same EventBus as nftables events.
