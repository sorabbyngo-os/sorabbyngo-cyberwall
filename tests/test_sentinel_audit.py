"""
Tests — Sentinel AuditLedger
"""
import tempfile
import pytest
from pathlib import Path

import sys
sys.path.insert(0, str(Path(__file__).parent.parent / ".."))

# Import from sorabbyngo-os sentinel
# Since it's a separate repo, we test the logic inline here
import hashlib
import json
from datetime import datetime, timezone


class AuditLedger:
    """Copy of sentinel AuditLedger for isolated testing."""
    def __init__(self, path):
        self.path = path
        self._prev_hash = "0" * 64

    def write(self, event_type, data):
        entry = {
            "timestamp":  datetime.now(timezone.utc).isoformat(),
            "event_type": event_type,
            "data":       data,
            "prev_hash":  self._prev_hash,
        }
        entry_str  = json.dumps(entry, sort_keys=True)
        chain_hash = hashlib.sha256(
            (self._prev_hash + entry_str).encode()
        ).hexdigest()
        entry["chain_hash"] = chain_hash
        self._prev_hash = chain_hash
        with open(self.path, "a") as f:
            f.write(json.dumps(entry) + "\n")

    def verify(self):
        if not Path(self.path).exists():
            return True, 0
        prev  = "0" * 64
        count = 0
        for line in Path(self.path).read_text().strip().splitlines():
            entry       = json.loads(line)
            stored_hash = entry.pop("chain_hash")
            entry_str   = json.dumps(entry, sort_keys=True)
            expected    = hashlib.sha256(
                (prev + entry_str).encode()
            ).hexdigest()
            if expected != stored_hash:
                return False, count
            prev = stored_hash
            count += 1
        return True, count


@pytest.fixture
def ledger():
    with tempfile.NamedTemporaryFile(suffix=".jsonl", delete=False) as f:
        yield AuditLedger(f.name)


def test_empty_ledger_verifies(ledger):
    ok, count = ledger.verify()
    assert ok is True
    assert count == 0


def test_single_entry_verifies(ledger):
    ledger.write("test_event", {"key": "value"})
    ok, count = ledger.verify()
    assert ok is True
    assert count == 1


def test_multiple_entries_verify(ledger):
    for i in range(10):
        ledger.write("event", {"index": i})
    ok, count = ledger.verify()
    assert ok is True
    assert count == 10


def test_tampered_entry_fails(ledger):
    ledger.write("real_event", {"data": "clean"})
    # Tamper the file
    content = Path(ledger.path).read_text()
    tampered = content.replace('"clean"', '"TAMPERED"')
    Path(ledger.path).write_text(tampered)
    ok, count = ledger.verify()
    assert ok is False


def test_chain_links_correctly(ledger):
    ledger.write("event_1", {"a": 1})
    ledger.write("event_2", {"b": 2})
    entries = [
        json.loads(l)
        for l in Path(ledger.path).read_text().strip().splitlines()
    ]
    assert entries[1]["prev_hash"] == entries[0]["chain_hash"]
