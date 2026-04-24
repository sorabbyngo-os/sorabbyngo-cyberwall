"""
Sorabbyngo Cyberwall — Policy Engine  (patched v2)

Patches over v1:
  - Atomic reload — no bare-default window during hot-reload
  - Schema validation — catches malformed YAML before applying
  - Required-section guard raises on startup if config is corrupt
  - _load() split into _load_into() for reuse in atomic reload
"""
import copy
import logging
import os
from typing import Any

import yaml

from cyberwall.core.event_bus import ThreatEvent, ThreatLevel

logger = logging.getLogger("cyberwall.core.policy_engine")

REQUIRED_SECTIONS = ["firewall", "malware", "response", "ai"]

DEFAULT_POLICY: dict = {
    "firewall": {
        "default_input":          "drop",
        "default_forward":        "drop",
        "default_output":         "accept",
        "interface":              "eth0",
        "allowed_inbound_ports":  [22, 80, 443, 4222, 8080, 8443],
        "rate_limit": {
            "ssh":  {"limit": "5/minute",    "burst": 10},
            "http": {"limit": "100/minute",  "burst": 200},
            "nats": {"limit": "1000/minute", "burst": 2000},
        },
        "blocked_ips": [],
        "geo_block":   [],
    },
    "malware": {
        "watch_paths": [
            "/etc", "/bin", "/sbin", "/usr/bin", "/usr/sbin",
            "/lib/modules", "/opt/sorabbyngo", "/var/lib/sorabbyngo",
        ],
        "quarantine_path":        "/var/lib/cyberwall/quarantine",
        "scan_interval_seconds":  30,
        "auto_quarantine_level":  "HIGH",
    },
    "response": {
        "auto_block_level":      "HIGH",
        "auto_quarantine_level": "CRITICAL",
        "alert_level":           "LOW",
        "notify_sentinel":       True,
        "notify_cml":            True,
    },
    "ai": {
        "enabled":       True,
        "model":         "phi4-mini",
        "ollama_url":    "http://localhost:11434/api/generate",
        "analyze_level": "MEDIUM",
    },
    "nats": {
        "url": "nats://localhost:4222",
    },
}


class PolicyValidationError(ValueError):
    pass


class PolicyEngine:
    def __init__(self, config_path: str | None = None):
        self.policy = copy.deepcopy(DEFAULT_POLICY)
        self._config_path = config_path
        if config_path and os.path.exists(config_path):
            self._load_into(self.policy, config_path)
        self._validate(self.policy)

    # ── Load ───────────────────────────────────────────────────────────────────

    def _load_into(self, target: dict, path: str):
        """Load YAML from path and deep-merge into target dict."""
        with open(path) as f:
            override = yaml.safe_load(f)
        if override:
            self._deep_merge(target, override)
        logger.info(f"Policy loaded from {path}")

    def _deep_merge(self, base: dict, override: dict):
        for k, v in override.items():
            if isinstance(v, dict) and isinstance(base.get(k), dict):
                self._deep_merge(base[k], v)
            else:
                base[k] = v

    # ── Validate ───────────────────────────────────────────────────────────────

    def _validate(self, policy: dict):
        for section in REQUIRED_SECTIONS:
            if section not in policy:
                raise PolicyValidationError(
                    f"Policy missing required section: '{section}'"
                )
        # Type checks on critical keys
        ports = policy["firewall"].get("allowed_inbound_ports", [])
        if not isinstance(ports, list):
            raise PolicyValidationError("firewall.allowed_inbound_ports must be a list")

        for level_key in ("auto_block_level", "auto_quarantine_level", "alert_level"):
            val = policy["response"].get(level_key)
            if val and val not in ThreatLevel.__members__:
                raise PolicyValidationError(
                    f"response.{level_key} invalid value: '{val}'. "
                    f"Must be one of {list(ThreatLevel.__members__)}"
                )

    # ── Reload (atomic) ───────────────────────────────────────────────────────

    def reload(self, config_path: str | None = None):
        """
        Hot-reload policy atomically.
        If validation fails the live policy is unchanged.
        """
        path = config_path or self._config_path
        if not path:
            logger.warning("reload() called with no config path — skipping")
            return

        tmp = copy.deepcopy(DEFAULT_POLICY)
        self._load_into(tmp, path)
        self._validate(tmp)      # validate before swap
        self.policy = tmp        # atomic swap
        logger.info("Policy hot-reloaded (atomic)")

    # ── Query helpers ──────────────────────────────────────────────────────────

    def _level(self, key: str) -> ThreatLevel:
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

    def get(self, *keys, default: Any = None) -> Any:
        node = self.policy
        for k in keys:
            if not isinstance(node, dict):
                return default
            node = node.get(k, default)
            if node is None:
                return default
        return node
