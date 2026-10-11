"""
TrustMesh Capability Tokens & Delegation Chains
Implements cryptographically signed, attenuated delegation tokens (UCAN/Biscuit-style)
and dynamic Proof-of-Possession (PoP) verification envelopes.
"""

from __future__ import annotations
import copy
import time
import uuid
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field

from trustmesh.crypto import (
    AgentKeypair,
    canonical_json,
    hash_payload,
    verify_signature,
)


class Caveat(BaseModel):
    """
    Constraints and caveats attached to an authorized capability.
    Under monotonic attenuation, child tokens can only restrict or tighten these caveats.
    """
    max_spend: Optional[float] = None
    allowed_actions: Optional[List[str]] = None
    allowed_resources: Optional[List[str]] = None
    disallowed_resources: Optional[List[str]] = None
    expiry: Optional[int] = None
    rate_limit: Optional[int] = None
    predicates: Dict[str, Any] = Field(default_factory=dict)

    def is_tighter_or_equal_to(self, parent: "Caveat") -> tuple[bool, str]:
        """
        Verify that this (child) caveat is mathematically tighter than or equal to the parent caveat.
        Returns (is_valid, failure_reason).
        """
        # 1. Max spend attenuation: child max_spend cannot exceed parent max_spend
        if parent.max_spend is not None:
            if self.max_spend is None:
                return False, f"Child removed spend limit from parent limit of ${parent.max_spend:.2f}"
            if self.max_spend > parent.max_spend:
                return False, f"Privilege Escalation: Child spend limit ${self.max_spend:.2f} exceeds parent limit ${parent.max_spend:.2f}"

        # 2. Allowed actions attenuation: child actions must be a subset of parent actions
        if parent.allowed_actions is not None:
            if self.allowed_actions is None:
                return False, "Child widened allowed actions to unrestricted"
            parent_set = set(parent.allowed_actions)
            for act in self.allowed_actions:
                if act not in parent_set and "*" not in parent_set:
                    return False, f"Privilege Escalation: Action '{act}' not permitted by parent caveats"

        # 3. Expiry attenuation: child token cannot outlive parent token
        if parent.expiry is not None:
            if self.expiry is None:
                return False, "Child token removed expiration window"
            if self.expiry > parent.expiry:
                return False, f"Child expiry ({self.expiry}) exceeds parent expiry ({parent.expiry})"

        # 4. Custom predicates: child cannot relax predicate restrictions
        for key, p_val in parent.predicates.items():
            if key not in self.predicates:
                return False, f"Child missing required parent constraint predicate: {key}"
            c_val = self.predicates[key]
            if isinstance(p_val, list):
                if not isinstance(c_val, list):
                    return False, f"Predicate '{key}' must remain a list"
                if not set(c_val).issubset(set(p_val)):
                    return False, f"Privilege Escalation: Predicate '{key}' values {c_val} exceed parent allowed set {p_val}"
            elif c_val != p_val:
                return False, f"Predicate '{key}' changed from '{p_val}' to '{c_val}'"

        return True, ""


class Capability(BaseModel):
    """
    A specific authority grant over a resource pattern with operational caveats.
    Resource patterns support wildcard hierarchy, e.g. 'travel:flight:*' or 'procurement:ledger'.
    """
    resource: str
    action: str
    caveats: Caveat = Field(default_factory=Caveat)

    def matches(self, target_resource: str, target_action: str) -> bool:
        """Check whether this capability pattern covers the target resource and action."""
        # Action match
        action_match = (
            self.action == "*"
            or self.action == target_action
            or (self.caveats.allowed_actions and target_action in self.caveats.allowed_actions)
        )
        if not action_match:
            return False

        # Resource match
        if self.resource == "*":
            return True
        if self.resource.endswith("*"):
            prefix = self.resource[:-1]
            return target_resource.startswith(prefix)
        return self.resource == target_resource


class ProofOfPossession(BaseModel):
    """
    Proof-of-Possession (PoP) header signed by the invoking agent.
    Binds the request method, action, resource, SHA-256 payload hash,
    current timestamp, and single-use nonce to the agent's did:key identity.
    """
    token_id: str
    agent_did: str
    action: str
    resource: str
    payload_hash: str
    timestamp: int
    nonce: str
    signature: str = ""

    def to_signable_dict(self) -> dict:
        d = self.model_dump()
        d.pop("signature", None)
        return d

    def sign(self, keypair: AgentKeypair) -> None:
        if keypair.did != self.agent_did:
            raise ValueError(f"Keypair DID {keypair.did} does not match PoP agent_did {self.agent_did}")
        raw_canonical = canonical_json(self.to_signable_dict())
        self.signature = keypair.sign(raw_canonical)

    def verify(self) -> bool:
        if not self.signature:
            return False
        raw_canonical = canonical_json(self.to_signable_dict())
        return verify_signature(self.agent_did, raw_canonical, self.signature)


class DelegationToken(BaseModel):
    """
    Cryptographically verifiable capability token.
    Can be nested via parent_token to form an unbroken delegation DAG from root authority.
    """
    token_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    iss: str  # Issuer DID
    aud: str  # Audience DID
    capabilities: List[Capability]
    parent_token: Optional[DelegationToken] = None
    issued_at: int = Field(default_factory=lambda: int(time.time()))
    expires_at: int
    nonce: str = Field(default_factory=lambda: str(uuid.uuid4()))
    signature: str = ""

    def to_signable_dict(self) -> dict:
        """Returns dict of token data omitting the signature for canonical signing."""
        d = self.model_dump()
        d.pop("signature", None)
        # Recursively ensure parent_token preserves its own signature
        if self.parent_token:
            d["parent_token"] = self.parent_token.model_dump()
        return d

    def sign(self, keypair: AgentKeypair) -> "DelegationToken":
        """Sign token with the issuer's private key."""
        if keypair.did != self.iss:
            raise ValueError(f"Keypair DID {keypair.did} does not match token issuer {self.iss}")
        signable_bytes = canonical_json(self.to_signable_dict())
        self.signature = keypair.sign(signable_bytes)
        return self

    def verify_token_signature(self) -> bool:
        """Verify the signature on this specific token step."""
        if not self.signature:
            return False
        signable_bytes = canonical_json(self.to_signable_dict())
        return verify_signature(self.iss, signable_bytes, self.signature)

    def attenuate(
        self,
        audience_did: str,
        restricted_capabilities: List[Capability],
        keypair: AgentKeypair,
        validity_seconds: int = 3600,
    ) -> "DelegationToken":
        """
        Derive an attenuated child token delegating a restricted subset of capabilities
        to a new audience agent.
        The current token's audience (self.aud) becomes the new token's issuer (child.iss).
        """
        if keypair.did != self.aud:
            raise ValueError(f"Only the audience of this token ({self.aud}) can delegate further. Keypair is {keypair.did}")

        now = int(time.time())
        child_exp = min(now + validity_seconds, self.expires_at)

        child = DelegationToken(
            token_id=str(uuid.uuid4()),
            iss=keypair.did,
            aud=audience_did,
            capabilities=restricted_capabilities,
            parent_token=copy.deepcopy(self),
            issued_at=now,
            expires_at=child_exp,
            nonce=str(uuid.uuid4()),
        )
        child.sign(keypair)
        return child

    def generate_pop(
        self,
        keypair: AgentKeypair,
        action: str,
        resource: str,
        payload: Any = None,
        nonce: Optional[str] = None,
    ) -> ProofOfPossession:
        """
        Generate a dynamic Proof-of-Possession envelope for an action invocation.
        """
        if keypair.did != self.aud:
            raise ValueError(f"Keypair DID {keypair.did} is not the authorized audience of this token ({self.aud})")

        p_hash = hash_payload(payload)
        pop = ProofOfPossession(
            token_id=self.token_id,
            agent_did=keypair.did,
            action=action,
            resource=resource,
            payload_hash=p_hash,
            timestamp=int(time.time()),
            nonce=nonce or str(uuid.uuid4()),
        )
        pop.sign(keypair)
        return pop

    @property
    def chain_depth(self) -> int:
        """Calculate the delegation depth (1 = root delegation)."""
        depth = 1
        curr = self.parent_token
        while curr:
            depth += 1
            curr = curr.parent_token
        return depth

    def get_delegation_chain(self) -> List[DelegationToken]:
        """Return the chain as a list from root down to this leaf token."""
        chain = []
        curr: Optional[DelegationToken] = self
        while curr:
            chain.append(curr)
            curr = curr.parent_token
        return list(reversed(chain))
