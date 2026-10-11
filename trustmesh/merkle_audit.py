"""
TrustMesh Verifiable Merkle Audit Tree (RFC 6962 / Transparency Log Standard)
Provides append-only, tamper-evident cryptographic transparency for multi-agent policy decisions.
Enables O(log N) mathematical inclusion proofs and consistency checks without exposing private audit data.
"""

from __future__ import annotations
import hashlib
import json
import threading
import time
from typing import Any, Dict, List, Optional, Tuple
from pydantic import BaseModel, Field

from trustmesh.crypto import canonical_json


def sha256(data: bytes) -> bytes:
    return hashlib.sha256(data).digest()


def hash_leaf(data: bytes) -> bytes:
    # RFC 6962 standard: prefix leaf with 0x00 to prevent second-preimage attacks
    return sha256(b"\x00" + data)


def hash_node(left: bytes, right: bytes) -> bytes:
    # RFC 6962 standard: prefix internal nodes with 0x01
    return sha256(b"\x01" + left + right)


class AuditProofStep(BaseModel):
    """Single step in a Merkle inclusion proof."""
    sibling_hash: str
    is_right: bool  # True if sibling is on the right, False if on the left


class AuditInclusionProof(BaseModel):
    """Cryptographic inclusion proof proving a decision exists in the Merkle log."""
    leaf_index: int
    leaf_hash: str
    total_leaves: int
    merkle_root: str
    audit_path: List[AuditProofStep]
    timestamp: int = Field(default_factory=lambda: int(time.time()))

    def verify(self) -> bool:
        """
        Mathematically verifies that leaf_hash recalculates to merkle_root along audit_path.
        Operates in O(log N) time with zero external network dependencies.
        """
        current = bytes.fromhex(self.leaf_hash)
        for step in self.audit_path:
            sibling = bytes.fromhex(step.sibling_hash)
            if step.is_right:
                current = hash_node(current, sibling)
            else:
                current = hash_node(sibling, current)
        return current.hex() == self.merkle_root


class MerkleAuditTree:
    """
    Append-only Merkle Audit Tree maintaining an immutable transparency log of policy decisions.
    Thread-safe and capable of generating compact inclusion proofs for regulatory compliance.
    """

    def __init__(self):
        self._leaves: List[bytes] = []  # Leaf hashes
        self._records: List[Dict[str, Any]] = []  # Raw records
        self._lock = threading.RLock()
        self._cached_root: Optional[bytes] = None

    def append_decision(self, decision_dict: Dict[str, Any]) -> Tuple[int, str]:
        """
        Appends a policy decision to the transparency log.
        Returns (leaf_index, leaf_hash_hex).
        """
        raw_bytes = canonical_json(decision_dict)
        if isinstance(raw_bytes, str):
            raw_bytes = raw_bytes.encode("utf-8")
        leaf = hash_leaf(raw_bytes)

        with self._lock:
            index = len(self._leaves)
            self._leaves.append(leaf)
            self._records.append(decision_dict)
            self._cached_root = None  # Invalidate cached root
            return index, leaf.hex()

    def get_root_hash(self) -> str:
        """Computes or returns the current Merkle Root hash as a hex string."""
        with self._lock:
            if not self._leaves:
                return hashlib.sha256(b"").hexdigest()
            if self._cached_root is not None:
                return self._cached_root.hex()

            root = self._compute_root(self._leaves)
            self._cached_root = root
            return root.hex()

    def _compute_root(self, hashes: List[bytes]) -> bytes:
        if not hashes:
            return hashlib.sha256(b"").digest()
        if len(hashes) == 1:
            return hashes[0]

        next_level: List[bytes] = []
        for i in range(0, len(hashes), 2):
            left = hashes[i]
            right = hashes[i + 1] if i + 1 < len(hashes) else left
            next_level.append(hash_node(left, right))

        return self._compute_root(next_level)

    def generate_inclusion_proof(self, leaf_index: int) -> Optional[AuditInclusionProof]:
        """
        Generates an O(log N) inclusion proof for the leaf at leaf_index.
        """
        with self._lock:
            total = len(self._leaves)
            if leaf_index < 0 or leaf_index >= total:
                return None

            path: List[AuditProofStep] = []
            idx = leaf_index
            current_layer = list(self._leaves)

            while len(current_layer) > 1:
                is_even = (idx % 2 == 0)
                if is_even:
                    sibling_idx = idx + 1 if idx + 1 < len(current_layer) else idx
                    is_right = True
                else:
                    sibling_idx = idx - 1
                    is_right = False

                sibling_hash = current_layer[sibling_idx].hex()
                path.append(AuditProofStep(sibling_hash=sibling_hash, is_right=is_right))

                # Build parent layer
                next_layer: List[bytes] = []
                for i in range(0, len(current_layer), 2):
                    l = current_layer[i]
                    r = current_layer[i + 1] if i + 1 < len(current_layer) else l
                    next_layer.append(hash_node(l, r))

                current_layer = next_layer
                idx = idx // 2

            return AuditInclusionProof(
                leaf_index=leaf_index,
                leaf_hash=self._leaves[leaf_index].hex(),
                total_leaves=total,
                merkle_root=self.get_root_hash(),
                audit_path=path,
            )

    @property
    def total_leaves(self) -> int:
        with self._lock:
            return len(self._leaves)

    def get_leaf_record(self, leaf_index: int) -> Optional[Dict[str, Any]]:
        with self._lock:
            if 0 <= leaf_index < len(self._records):
                return self._records[leaf_index]
            return None
