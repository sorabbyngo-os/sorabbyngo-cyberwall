"""
Sorabbyngo Cyberwall — Firewall Engine
nftables-based firewall with rate limiting and IP blocking.
"""
import asyncio
import logging
import subprocess
import ipaddress
from typing import Set
from cyberwall.core.event_bus import EventBus, ThreatEvent, ThreatLevel
from cyberwall.core.policy_engine import PolicyEngine

logger = logging.getLogger("cyberwall.firewall.engine")


class FirewallEngine:
    def __init__(self, bus: EventBus, policy: PolicyEngine):
        self.bus    = bus
        self.policy = policy
        self._blocked_ips: Set[str] = set()
        self._running = False

        # Load static blocks from policy
        for ip in policy.get("firewall", "blocked_ips", default=[]):
            self._blocked_ips.add(ip)

    async def start(self):
        self._running = True
        logger.info("FirewallEngine starting")
        await self._apply_base_rules()
        await self._monitor_loop()

    async def _apply_base_rules(self):
        """Apply base nftables ruleset for Sorabbyngo."""
        allowed_ports = self.policy.get("firewall", "allowed_inbound_ports", default=[22, 443])
        ports_str = ", ".join(str(p) for p in allowed_ports)

        ruleset = f"""
table inet sorabbyngo_wall {{
    chain input {{
        type filter hook input priority 0; policy drop;
        ct state established,related accept
        iif lo accept
        ip protocol icmp accept
        tcp dport {{ {ports_str} }} accept
        tcp flags & (fin|syn|rst|ack) == syn limit rate 25/second burst 50 packets accept
        log prefix "CYBERWALL_DROP: " drop
    }}
    chain forward {{
        type filter hook forward priority 0; policy drop;
    }}
    chain output {{
        type filter hook output priority 0; policy accept;
    }}
}}
"""
        result = await self._nft(f"nft -f -", input_data=ruleset)
        if result:
            logger.info("Base nftables ruleset applied")
        else:
            logger.warning("nftables apply failed — running in monitor-only mode")

    async def block_ip(self, ip: str, reason: str = "") -> bool:
        """Block an IP immediately."""
        try:
            ipaddress.ip_address(ip)  # validate
        except ValueError:
            logger.error(f"Invalid IP: {ip}")
            return False

        if ip in self._blocked_ips:
            return True

        self._blocked_ips.add(ip)
        result = await self._nft(
            f'nft add rule inet sorabbyngo_wall input ip saddr {ip} drop comment "cyberwall:{reason}"'
        )

        event = ThreatEvent(
            source="firewall",
            threat_type="ip_blocked",
            level=ThreatLevel.HIGH,
            score=7.0,
            description=f"IP {ip} blocked: {reason}",
            data={"ip": ip, "reason": reason},
            blocked=True,
        )
        await self.bus.publish(event)
        logger.warning(f"BLOCKED {ip} — {reason}")
        return result

    async def unblock_ip(self, ip: str):
        if ip in self._blocked_ips:
            self._blocked_ips.discard(ip)
            # Flush and reapply — simplest safe approach
            await self._apply_base_rules()
            for blocked in self._blocked_ips:
                await self._nft(
                    f'nft add rule inet sorabbyngo_wall input ip saddr {blocked} drop'
                )
            logger.info(f"Unblocked {ip}")

    async def _monitor_loop(self):
        """Monitor nftables log for drop events and score them."""
        logger.info("Firewall monitor loop running")
        proc = await asyncio.create_subprocess_exec(
            "journalctl", "-f", "-k", "--grep=CYBERWALL_DROP",
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.DEVNULL,
        )
        while self._running and proc.stdout:
            try:
                line = await asyncio.wait_for(proc.stdout.readline(), timeout=2.0)
                if line:
                    await self._parse_drop(line.decode(errors="replace"))
            except asyncio.TimeoutError:
                continue
            except Exception as e:
                logger.error(f"Monitor loop error: {e}")
                await asyncio.sleep(5)

    async def _parse_drop(self, line: str):
        """Parse a kernel drop log line and emit a threat event."""
        import re
        src_match = re.search(r'SRC=(\S+)', line)
        dst_match = re.search(r'DPT=(\d+)', line)
        if not src_match:
            return

        src_ip  = src_match.group(1)
        dst_port = int(dst_match.group(1)) if dst_match else 0

        # Simple heuristic — rapid drops from same IP = scan
        threat_type = "port_scan" if dst_port in range(1, 1024) else "unknown"

        event = ThreatEvent(
            source="firewall",
            threat_type=threat_type,
            level=ThreatLevel.LOW,
            score=3.0,
            description=f"Dropped packet from {src_ip}:{dst_port}",
            data={"src_ip": src_ip, "dst_port": dst_port, "raw": line.strip()},
        )
        await self.bus.publish(event)

    async def _nft(self, cmd: str, input_data: str = None) -> bool:
        try:
            if input_data:
                proc = await asyncio.create_subprocess_exec(
                    *cmd.split(),
                    stdin=asyncio.subprocess.PIPE,
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE,
                )
                _, stderr = await proc.communicate(input_data.encode())
            else:
                proc = await asyncio.create_subprocess_shell(
                    cmd,
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE,
                )
                _, stderr = await proc.communicate()

            if proc.returncode != 0:
                logger.debug(f"nft error: {stderr.decode().strip()}")
                return False
            return True
        except FileNotFoundError:
            logger.warning("nftables not found — firewall rules disabled")
            return False

    def stop(self):
        self._running = False
