"""
TrustMesh A2A (Agent-to-Agent) Protocol Integration
Implements Linux Foundation / A2A Standard Signed Agent Cards for autonomous agent discovery,
capability advertisement, and public key verification.
"""

from __future__ import annotations
import time
from typing import List, Optional
from pydantic import BaseModel, Field

from trustmesh.crypto import AgentKeypair, canonical_json, verify_signature


class AgentSkill(BaseModel):
    """Declared capability skill in the A2A Agent Card."""
    id: str
    name: str
    description: str
    resource: str
    allowed_actions: List[str] = Field(default_factory=list)
    requires_trustmesh_token: bool = True


class AgentCard(BaseModel):
    """
    Standard Linux Foundation A2A Agent Card with Ed25519 digital signature.
    Published at /.well-known/agent-card.json.
    """
    schema_version: str = "1.0.0"
    name: str
    description: str
    agent_did: str
    public_key_hex: str
    endpoint_url: str
    skills: List[AgentSkill] = Field(default_factory=list)
    protocols_supported: List[str] = Field(default_factory=lambda: ["TrustMesh/1.0", "A2A/1.0", "MCP/1.0"])
    created_at: int = Field(default_factory=lambda: int(time.time()))
    expires_at: Optional[int] = None
    signature: str = ""

    def to_signable_dict(self) -> dict:
        d = self.model_dump()
        d.pop("signature", None)
        return d

    def sign(self, keypair: AgentKeypair) -> "AgentCard":
        if keypair.did != self.agent_did:
            raise ValueError(f"Keypair DID {keypair.did} does not match AgentCard DID {self.agent_did}")
        raw = canonical_json(self.to_signable_dict())
        self.signature = keypair.sign(raw)
        return self

    def verify(self) -> bool:
        if not self.signature:
            return False
        raw = canonical_json(self.to_signable_dict())
        return verify_signature(self.agent_did, raw, self.signature)


def create_agent_card(
    keypair: AgentKeypair,
    name: str,
    description: str,
    endpoint_url: str,
    skills: Optional[List[AgentSkill]] = None,
    ttl_seconds: int = 86400 * 30,
) -> AgentCard:
    """Helper to create and sign a valid A2A Agent Card."""
    now = int(time.time())
    card = AgentCard(
        name=name,
        description=description,
        agent_did=keypair.did,
        public_key_hex=keypair.public_bytes.hex(),
        endpoint_url=endpoint_url,
        skills=skills or [],
        created_at=now,
        expires_at=now + ttl_seconds,
    )
    card.sign(keypair)
    return card
