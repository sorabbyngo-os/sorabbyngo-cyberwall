"""
Tests — Hash Database
"""
import tempfile
import json
import pytest
from pathlib import Path
from cyberwall.malware.signatures.hash_db import HashDatabase

KNOWN_MALWARE_HASH = "4a6b2c1d3e5f6789abcdef01234567890abcdef01234567890abcdef01234567"
CLEAN_HASH         = "0" * 64


@pytest.fixture
def db():
    with tempfile.TemporaryDirectory() as d:
        db = HashDatabase(db_path=Path(d) / "test_signatures.db")
        yield db
        db.close()


def test_lookup_known_malware(db):
    result = db.lookup(KNOWN_MALWARE_HASH)
    assert result is not None
    assert result["name"] == "XMRig"
    assert result["threat_type"] == "cryptominer"


def test_lookup_clean_hash_returns_none(db):
    result = db.lookup(CLEAN_HASH)
    assert result is None


def test_add_and_lookup(db):
    sha = "a" * 64
    db.add(sha, "TestMalware", "test_family", "backdoor", "CRITICAL", "test")
    result = db.lookup(sha)
    assert result is not None
    assert result["name"] == "TestMalware"
    assert result["severity"] == "CRITICAL"


def test_whitelist_overrides_malware(db):
    db.whitelist(KNOWN_MALWARE_HASH, "false positive")
    result = db.lookup(KNOWN_MALWARE_HASH)
    assert result is None


def test_bulk_import(db):
    with tempfile.NamedTemporaryFile(
        mode="w", suffix=".jsonl", delete=False
    ) as f:
        for i in range(5):
            f.write(json.dumps({
                "sha256":      f"{'b' * 63}{i}",
                "name":        f"Malware{i}",
                "family":      "test",
                "threat_type": "malware",
                "severity":    "HIGH",
            }) + "\n")
        path = f.name

    imported = db.bulk_import(path, source="test_import")
    assert imported == 5


def test_count(db):
    initial = db.count()
    db.add("c" * 64, "Extra", source="test")
    assert db.count() == initial + 1


def test_stats(db):
    stats = db.stats()
    assert isinstance(stats, dict)
    assert "cryptominer" in stats
