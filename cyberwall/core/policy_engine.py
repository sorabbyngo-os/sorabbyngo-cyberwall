"""
Sorabbyngo Cyberwall — Policy Engine
Loads and evaluates firewall + defence policy.
"""
import yaml
import logging
import os
import copy
from typing import Dict, Any
from cyberwall.core.event_bus import ThreatEvent, ThreatLevel

logger = logging.getLogger("cyberwall.core.policy_engine")

DEFAULT_POLICY = {
    "firewall": {
        "default_input":   "drop",
        "default_forward": "drop",
        "default_output":  "accept",
        "interface": "eth0",
        "allowed_inbound_ports": [22, 80, 443, 4222, 8080, 8443],
        "rate_limit": {
            "ssh":   {"limit": "5/minute",   "burst": 10},
            "http":  {"limit": "100/minute", "burst": 200},
            "nats":  {"limit": "1000/minute","burst": 2000},
        },
        "blocked_ips": [],
        "geo_block":   [],
    },
    "malware": {
        "watch_paths": [
            "/etc", "/bin", "/sbin", "/usr/bin", "/usr/sbin",
            "/lib/modules", "/opt/sorabbyngo", "/var/lib/sorabbyngo",
        ],
        "quarantine_path": "/var/lib/cyberwall/quarantine",
        "scan_interval_seconds": 30,
        "auto_quarantine_level": "HIGH",
    },
    "response": {
        "auto_block_level":      "HIGH",
        "auto_quarantine_level": "CRITICAL",
        "alert_level":           "LOW",
        "notify_sentinel":       True,
        "notify_cml":            True,
    },
    "ai": {
        "enabled": True,
        "model":   "phi4-mini",
        "ollama_url": "http://localhost:11434/api/generate",
        "analyze_level": "MEDIUM",
    },
}


class PolicyEngine:
    def __init__(self, config_path: str = None):
        self.policy = copy.deepcopy(DEFAULT_POLICY)
        if config_path and os.path.exists(config_path):
            self._load(config_path)

    def _load(self, path: str):
        with open(path) as f:
            override = yaml.safe_load(f)
        self._deep_merge(self.policy, override or {})
        logger.info(f"Policy loaded from {path}")

    def _deep_merge(self, base: dict, override: dict):
        for k, v in override.items():
            if isinstance(v, dict) and isinstance(base.get(k), dict):
                self._deep_merge(base[k], v)
            else:
                base[k] = v

    def _level(self, key: str) -> ThreatLevel:
        """Safely resolve a policy level string to ThreatLevel enum."""
        name = self.policy["response"].get(key, "HIGH")
        try:
            return ThreatLevel[name]
        except KeyError:
            return ThreatLevel.HIGH

    def should_block(self, event: ThreatEvent) -> bool:
        return event.level >= self._level("auto_block_level")

    def should_quarantine(self, event: ThreatEvent) -> bool:
        return event.level >= self._level("auto_quarantine_level")

    def should_alert(self, event: ThreatEvent) -> bool:
        return event.level >= self._level("alert_level")

    def should_ai_analyze(self, event: ThreatEvent) -> bool:
        if not self.policy["ai"]["enabled"]:
            return False
        name = self.policy["ai"].get("analyze_level", "MEDIUM")
        try:
            threshold = ThreatLevel[name]
        except KeyError:
            threshold = ThreatLevel.MEDIUM
        return event.level >= threshold

    def get(self, *keys, default=None) -> Any:
        node = self.policy
        for k in keys:
            if not isinstance(node, dict):
                return default
            node = node.get(k, default)
        return node

    def reload(self, config_path: str):
        self.policy = copy.deepcopy(DEFAULT_POLICY)
        self._load(config_path)
        logger.info("Policy hot-reloaded")
