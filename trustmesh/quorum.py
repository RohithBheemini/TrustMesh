"""
TrustMesh Multi-Agent Threshold Quorum Delegation (M-of-N Multi-Sig)
Enables multi-stakeholder governance for high-value agent actions (wire transfers, deployments).
Requires M distinct valid cryptographic signatures from an authorized pool of N agents before execution.
"""

from __future__ import annotations
import time
import uuid
from typing import Any, Dict, List, Optional, Set, Tuple
from pydantic import BaseModel, Field

from trustmesh.crypto import AgentKeypair, canonical_json, verify_signature
from trustmesh.tokens import Capability, Caveat


class QuorumSignature(BaseModel):
    """Cryptographic cosignature stamped by an authorized stakeholder."""
    signer_did: str
    signature: str
    timestamp: int = Field(default_factory=lambda: int(time.time()))


class QuorumDelegationToken(BaseModel):
    """
    High-Assurance Delegation Token requiring M-of-N threshold cosignatures.
    Prevents single-agent compromised keys from unilaterally authorizing high-risk transactions.
    """
    token_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    aud: str  # Intended executing agent DID
    capabilities: List[Capability]
    authorized_signers: List[str]  # The pool of N authorized stakeholder DIDs
    threshold_m: int  # Minimum number of valid signatures required (M)
    signatures: List[QuorumSignature] = Field(default_factory=list)
    created_at: int = Field(default_factory=lambda: int(time.time()))
    expires_at: int

    def to_signable_dict(self) -> dict:
        d = self.model_dump()
        d.pop("signatures", None)
        return d

    def add_cosignature(self, keypair: AgentKeypair) -> "QuorumDelegationToken":
        """
        An authorized stakeholder adds their Ed25519 signature to this quorum token.
        """
        if keypair.did not in self.authorized_signers:
            raise ValueError(f"Keypair DID {keypair.did} is not in authorized signers pool")

        # Check if already signed
        for sig in self.signatures:
            if sig.signer_did == keypair.did:
                return self  # Already signed

        raw = canonical_json(self.to_signable_dict())
        sig_str = keypair.sign(raw)
        self.signatures.append(QuorumSignature(signer_did=keypair.did, signature=sig_str))
        return self

    def verify_quorum(self) -> Tuple[bool, str, List[str]]:
        """
        Verifies that at least threshold_m distinct authorized stakeholders have signed.
        Returns (is_satisfied, message, list_of_valid_signers).
        """
        now = int(time.time())
        if now > self.expires_at:
            return False, "ERR_TOKEN_EXPIRED: Quorum token validity period expired", []

        raw = canonical_json(self.to_signable_dict())
        valid_signers: Set[str] = set()

        for sig in self.signatures:
            if sig.signer_did not in self.authorized_signers:
                continue  # Ignore signers not in the pool

            if sig.signer_did in valid_signers:
                continue  # Prevent replay/duplicate signatures from the same identity

            # Cryptographically verify the Ed25519 signature
            if verify_signature(sig.signer_did, raw, sig.signature):
                valid_signers.add(sig.signer_did)

        count = len(valid_signers)
        if count >= self.threshold_m:
            return True, f"Quorum satisfied ({count}/{self.threshold_m} valid signatures)", list(valid_signers)
        else:
            return False, f"ERR_INSUFFICIENT_QUORUM: Only {count} valid signatures out of {self.threshold_m} required", list(valid_signers)
