"""
Sorabbyngo Cyberwall -- eBPF Loader (stub)
Loads XDP BPF program via bcc. Gracefully falls back if unavailable.
"""
import asyncio
import logging
import os
import socket
import struct
from pathlib import Path

logger = logging.getLogger("cyberwall.firewall.ebpf.bpf_loader")
BPF_PROGRAM = Path(__file__).parent / "bpf_program.c"

class EBPFLoader:
    def __init__(self, bus, interface: str = "eth0"):
        self.bus       = bus
        self.interface = interface
        self._bpf      = None
        self._loaded   = False
        self._running  = False
        self._stats    = {"total": 0, "dropped": 0, "threats": 0}

    def load(self) -> bool:
        if not BPF_PROGRAM.exists():
            logger.info("eBPF: bpf_program.c not found -- skipping")
            return False
        try:
            from bcc import BPF
        except ImportError:
            logger.info("eBPF: bcc not installed -- falling back to nftables")
            return False
        if os.geteuid() != 0:
            logger.info("eBPF: not root -- skipping XDP load")
            return False
        try:
            self._bpf = BPF(src_file=str(BPF_PROGRAM))
            fn = self._bpf.load_func("cyberwall_xdp", BPF.XDP)
            self._bpf.attach_xdp(self.interface, fn, 0)
            self._loaded = True
            logger.info(f"eBPF XDP loaded on {self.interface}")
            return True
        except Exception as e:
            logger.warning(f"eBPF load failed ({e}) -- falling back to nftables")
            self._loaded = False
            return False

    async def start(self):
        if not self._loaded or not self._bpf:
            return
        self._running = True
        while self._running:
            try:
                self._bpf.ring_buffer_poll(timeout=100)
            except Exception:
                pass
            await asyncio.sleep(0.1)

    def block_ip(self, ip: str) -> bool:
        if not self._loaded or not self._bpf:
            return False
        try:
            import ctypes
            key = self._bpf["blocked_ips"].Key()
            key.prefixlen = 32
            key.addr = struct.unpack("=I", socket.inet_aton(ip))[0]
            self._bpf["blocked_ips"][key] = ctypes.c_uint8(1)
            return True
        except Exception:
            return False

    def unblock_ip(self, ip: str) -> bool:
        if not self._loaded or not self._bpf:
            return False
        try:
            import ctypes
            key = self._bpf["blocked_ips"].Key()
            key.prefixlen = 32
            key.addr = struct.unpack("=I", socket.inet_aton(ip))[0]
            self._bpf["blocked_ips"].__delitem__(key)
            logger.info(f"eBPF: unblocked {ip}")
            return True
        except Exception as e:
            logger.warning(f"eBPF unblock failed for {ip}: {e}")
            return False

    def get_stats(self) -> dict:
        return dict(self._stats)

    def stop(self):
        self._running = False
        if self._loaded and self._bpf:
            try:
                self._bpf.remove_xdp(self.interface, 0)
            except Exception:
                pass
        self._loaded = False
