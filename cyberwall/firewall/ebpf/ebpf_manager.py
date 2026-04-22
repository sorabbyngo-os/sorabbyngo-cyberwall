"""
Sorabbyngo Cyberwall — eBPF Manager
Coordinates eBPF loader with the firewall engine.
Provides graceful fallback to nftables if eBPF unavailable.
"""
import asyncio
import logging
from cyberwall.core.event_bus import EventBus
from cyberwall.core.policy_engine import PolicyEngine
from cyberwall.firewall.ebpf.bpf_loader import EBPFLoader

logger = logging.getLogger("cyberwall.firewall.ebpf.manager")


class EBPFManager:
    def __init__(self, bus: EventBus, policy: PolicyEngine):
        self.bus      = bus
        self.policy   = policy
        interface     = policy.get("firewall", "interface", default="eth0")
        self.loader   = EBPFLoader(bus, interface=interface)
        self._active  = False

    def setup(self) -> bool:
        """Load eBPF program. Returns True if active."""
        self._active = self.loader.load()
        if self._active:
            logger.info("eBPF firewall active — XDP kernel-level filtering enabled")
        else:
            logger.info("eBPF unavailable — falling back to nftables userspace firewall")
        return self._active

    async def start(self):
        if self._active:
            await self.loader.start()

    def block_ip(self, ip: str) -> bool:
        if self._active:
            return self.loader.block_ip(ip)
        return False

    def unblock_ip(self, ip: str):
        if self._active:
            self.loader.unblock_ip(ip)

    def stats(self) -> dict:
        return self.loader.get_stats()

    def is_active(self) -> bool:
        return self._active

    def stop(self):
        self.loader.stop()
