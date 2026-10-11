"""
TrustMesh Scalable Cryptographic Revocation Registry
Provides space-efficient Bloom Filter revocation sets, epoch synchronization,
and verifiable signed revocation receipts for enterprise agent meshes.
"""

from __future__ import annotations
import hashlib
import time
from typing import List, Optional, Set
from pydantic import BaseModel, Field

from trustmesh.crypto import AgentKeypair, canonical_json, verify_signature


class RevocationReceipt(BaseModel):
    """Verifiable disavowal receipt proving an agent or token has been revoked."""
    target_id: str  # Token ID or Agent DID
    target_type: str  # "AGENT" | "TOKEN"
    reason: str
    revoked_at: int = Field(default_factory=lambda: int(time.time()))
    authority_did: str
    signature: str = ""

    def to_signable_dict(self) -> dict:
        d = self.model_dump()
        d.pop("signature", None)
        return d

    def sign(self, authority_key: AgentKeypair) -> None:
        if authority_key.did != self.authority_did:
            raise ValueError("Authority DID mismatch")
        raw = canonical_json(self.to_signable_dict())
        self.signature = authority_key.sign(raw)

    def verify(self) -> bool:
        if not self.signature:
            return False
        raw = canonical_json(self.to_signable_dict())
        return verify_signature(self.authority_did, raw, self.signature)


class BloomRevocationRegistry:
    """
    Space-efficient probabilistic revocation registry.
    Can store 100,000+ revoked agent identities and tokens in < 150 KB.
    """

    def __init__(self, size_bits: int = 100000, num_hashes: int = 5, authority_key: Optional[AgentKeypair] = None):
        self.size = size_bits
        self.num_hashes = num_hashes
        self.bits = bytearray((size_bits + 7) // 8)
        self.authority_key = authority_key or AgentKeypair.generate(name="RevocationAuthority")
        self.receipts: List[RevocationReceipt] = []

    def _get_indices(self, item: str) -> List[int]:
        indices = []
        for i in range(self.num_hashes):
            salt = f"salt_{i}_".encode("ascii")
            h = hashlib.sha256(salt + item.encode("utf-8")).digest()
            idx = int.from_bytes(h[:4], "big") % self.size
            indices.append(idx)
        return indices

    def revoke(self, target_id: str, target_type: str = "AGENT", reason: str = "Administrative revocation") -> RevocationReceipt:
        """Add an item to the revocation set and issue a signed receipt."""
        for idx in self._get_indices(target_id):
            byte_idx = idx // 8
            bit_idx = idx % 8
            self.bits[byte_idx] |= (1 << bit_idx)

        receipt = RevocationReceipt(
            target_id=target_id,
            target_type=target_type,
            reason=reason,
            authority_did=self.authority_key.did,
        )
        receipt.sign(self.authority_key)
        self.receipts.append(receipt)
        return receipt

    def is_revoked(self, target_id: str) -> bool:
        """Check whether target_id is present in the revocation set."""
        for idx in self._get_indices(target_id):
            byte_idx = idx // 8
            bit_idx = idx % 8
            if not (self.bits[byte_idx] & (1 << bit_idx)):
                return False
        return True
