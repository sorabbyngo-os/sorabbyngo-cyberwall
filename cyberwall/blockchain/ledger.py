"""
Sorabbyngo Cyberwall — Blockchain Audit Ledger
===============================================
Tamper-evident append-only ledger for all Cyberwall events.
Pure Python — no external blockchain dependency.

Structure:
  Each block: {index, timestamp, node_id, event_type, data,
               prev_hash, nonce, hash, merkle_root}
  Chain hash: SHA3-256(prev_hash + index + timestamp + node_id + data + nonce)
  Merkle:     SHA3-256 binary tree over batches of 64 events

Properties:
  - Append-only: blocks cannot be modified without invalidating all successors
  - Merkle proofs: O(log n) proof that any event is in the chain
  - NodeID-bound: every block carries the hardware identity
  - Offline-first: persisted to JSONL — survives daemon restarts
  - Exportable: full chain can be verified by any third party

Usage:
    from cyberwall.blockchain.ledger import BlockchainLedger
    ledger = BlockchainLedger("/var/lib/cyberwall/audit.chain")
    block = await ledger.append("threat_blocked", {"ip": "1.2.3.4", "score": 8.5})
    ok, count = ledger.verify()
"""
import asyncio
import hashlib
import json
import logging
import os
import time
from dataclasses import dataclass, field, asdict
from pathlib import Path
from typing import List, Optional, Tuple

log = logging.getLogger("cyberwall.blockchain")

GENESIS_HASH = "0" * 64


def sha3(data: str) -> str:
    return hashlib.sha3_256(data.encode()).hexdigest()


def sha3b(data: bytes) -> str:
    return hashlib.sha3_256(data).hexdigest()


@dataclass
class Block:
    index:       int
    timestamp:   float
    node_id:     str
    event_type:  str
    data:        dict
    prev_hash:   str
    nonce:       int   = 0
    hash:        str   = ""
    merkle_root: str   = ""

    def compute_hash(self) -> str:
        content = (
            f"{self.index}{self.timestamp}{self.node_id}"
            f"{self.event_type}{json.dumps(self.data, sort_keys=True)}"
            f"{self.prev_hash}{self.nonce}"
        )
        return sha3(content)

    def mine(self, difficulty: int = 2):
        """
        Simple proof-of-work: find nonce such that hash starts with
        difficulty zeros. Difficulty 2 = fast (~milliseconds).
        """
        prefix = "0" * difficulty
        self.nonce = 0
        self.hash  = self.compute_hash()
        while not self.hash.startswith(prefix):
            self.nonce += 1
            self.hash = self.compute_hash()

    def to_dict(self) -> dict:
        return asdict(self)

    @classmethod
    def from_dict(cls, d: dict) -> "Block":
        return cls(**d)


def merkle_root(hashes: List[str]) -> str:
    """Compute Merkle root of a list of hashes."""
    if not hashes:
        return GENESIS_HASH
    layer = list(hashes)
    while len(layer) > 1:
        if len(layer) % 2:
            layer.append(layer[-1])  # duplicate last if odd
        layer = [sha3(layer[i] + layer[i+1]) for i in range(0, len(layer), 2)]
    return layer[0]


def merkle_proof(hashes: List[str], index: int) -> List[Tuple[str, str]]:
    """
    Generate Merkle inclusion proof for element at index.
    Returns list of (sibling_hash, direction) where direction in ("left","right").
    """
    proof = []
    layer = list(hashes)
    idx   = index
    while len(layer) > 1:
        if len(layer) % 2:
            layer.append(layer[-1])
        if idx % 2 == 0:
            sibling = layer[idx + 1] if idx + 1 < len(layer) else layer[idx]
            proof.append((sibling, "right"))
        else:
            proof.append((layer[idx - 1], "left"))
        layer = [sha3(layer[i] + layer[i+1]) for i in range(0, len(layer), 2)]
        idx //= 2
    return proof


def verify_merkle_proof(leaf_hash: str, proof: List[Tuple[str, str]], root: str) -> bool:
    """Verify a Merkle inclusion proof."""
    current = leaf_hash
    for sibling, direction in proof:
        if direction == "right":
            current = sha3(current + sibling)
        else:
            current = sha3(sibling + current)
    return current == root


class BlockchainLedger:
    """
    Append-only blockchain audit ledger.
    Persisted to a JSONL file — one block per line.
    """

    DIFFICULTY = 2   # PoW prefix zeros — low for speed, proves integrity

    def __init__(
        self,
        path: Path = Path("/var/lib/cyberwall/audit.chain"),
        node_id: str = "",
    ):
        # Fallback to /tmp
        for candidate in [path, Path("/tmp/cyberwall-audit.chain")]:
            try:
                candidate.parent.mkdir(parents=True, exist_ok=True)
                self._path = candidate
                break
            except PermissionError:
                continue

        self._node_id = node_id or os.environ.get("SORABBYNGO_NODE_ID", "unknown")
        self._chain:  List[Block] = []
        self._lock    = asyncio.Lock()
        self._load()
        log.info(
            f"BlockchainLedger ready: {self._path} | "
            f"{len(self._chain)} blocks | node={self._node_id[:12]}"
        )

    # ── Load ──────────────────────────────────────────────────────────────────
    def _load(self):
        if not self._path.exists():
            self._chain = [self._genesis()]
            self._save_block(self._chain[0])
            return
        self._chain = []
        with open(self._path) as f:
            for line in f:
                line = line.strip()
                if line:
                    try:
                        self._chain.append(Block.from_dict(json.loads(line)))
                    except Exception as e:
                        log.warning(f"Ledger parse error: {e}")
        if not self._chain:
            self._chain = [self._genesis()]
            self._save_block(self._chain[0])

    def _genesis(self) -> Block:
        b = Block(
            index=0,
            timestamp=time.time(),
            node_id=self._node_id,
            event_type="genesis",
            data={"message": "Sorabbyngo Cyberwall — Genesis Block"},
            prev_hash=GENESIS_HASH,
        )
        b.mine(self.DIFFICULTY)
        return b

    def _save_block(self, block: Block):
        with open(self._path, "a") as f:
            f.write(json.dumps(block.to_dict()) + "
")

    # ── Append ────────────────────────────────────────────────────────────────
    async def append(self, event_type: str, data: dict) -> Block:
        """Append a new block. Thread-safe via asyncio lock."""
        async with self._lock:
            prev  = self._chain[-1]
            block = Block(
                index=len(self._chain),
                timestamp=time.time(),
                node_id=self._node_id,
                event_type=event_type,
                data=data,
                prev_hash=prev.hash,
            )
            # Compute Merkle root over last 64 blocks
            recent_hashes = [b.hash for b in self._chain[-63:]] + [block.compute_hash()]
            block.merkle_root = merkle_root(recent_hashes)
            # Mine (PoW)
            loop = asyncio.get_event_loop()
            await loop.run_in_executor(None, block.mine, self.DIFFICULTY)
            self._chain.append(block)
            self._save_block(block)
            log.debug(
                f"Block #{block.index} | {event_type} | "
                f"hash={block.hash[:12]}... | nonce={block.nonce}"
            )
            return block

    # ── Verify ────────────────────────────────────────────────────────────────
    def verify(self) -> Tuple[bool, int]:
        """
        Verify full chain integrity.
        Returns (valid: bool, verified_count: int).
        """
        prefix = "0" * self.DIFFICULTY
        for i, block in enumerate(self._chain):
            # Recompute hash
            expected = block.compute_hash()
            if block.hash != expected:
                log.error(f"Chain broken at block #{i}: hash mismatch")
                return False, i
            # Check PoW
            if not block.hash.startswith(prefix):
                log.error(f"Block #{i} fails PoW check")
                return False, i
            # Check chain linkage (skip genesis)
            if i > 0 and block.prev_hash != self._chain[i-1].hash:
                log.error(f"Chain broken at block #{i}: prev_hash mismatch")
                return False, i
        return True, len(self._chain)

    def get_proof(self, block_index: int) -> Optional[dict]:
        """Get Merkle inclusion proof for a specific block."""
        if block_index >= len(self._chain):
            return None
        block = self._chain[block_index]
        # Rebuild the batch this block belongs to
        batch_start = max(0, block_index - 63)
        batch = self._chain[batch_start:block_index + 1]
        hashes = [b.hash for b in batch]
        idx_in_batch = block_index - batch_start
        proof = merkle_proof(hashes, idx_in_batch)
        return {
            "block_index":  block_index,
            "block_hash":   block.hash,
            "merkle_root":  block.merkle_root,
            "proof":        [(h, d) for h, d in proof],
        }

    def verify_proof(self, proof: dict) -> bool:
        """Verify a Merkle inclusion proof."""
        return verify_merkle_proof(
            proof["block_hash"],
            [(h, d) for h, d in proof["proof"]],
            proof["merkle_root"],
        )

    def tail(self, n: int = 10) -> List[dict]:
        return [b.to_dict() for b in self._chain[-n:]]

    def stats(self) -> dict:
        return {
            "blocks":    len(self._chain),
            "path":      str(self._path),
            "node_id":   self._node_id[:12],
            "tip_hash":  self._chain[-1].hash[:16] if self._chain else "",
            "tip_index": self._chain[-1].index if self._chain else 0,
        }
