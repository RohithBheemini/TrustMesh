"""
TrustMesh: Dynamic Agent-to-Agent Authorization Protocol
Open-source zero-trust cryptographic authorization and capability delegation for autonomous AI agents.
"""

from trustmesh.crypto import (
    AgentKeypair,
    pubkey_to_did,
    did_to_pubkey,
    canonical_json,
    hash_payload,
    verify_signature,
)
from trustmesh.tokens import (
    Caveat,
    Capability,
    DelegationToken,
    ProofOfPossession,
)
from trustmesh.policy import (
    DynamicPolicyEngine,
    PolicyDecision,
)
from trustmesh.handshake import (
    HelloMessage,
    ChallengeMessage,
    AuthResponseMessage,
    EstablishedSession,
    MutualHandshakeProtocol,
)
from trustmesh.secure_channel import (
    TrustMeshSecureChannel,
    EncryptedPayload,
)
from trustmesh.revocation import (
    BloomRevocationRegistry,
    RevocationReceipt,
)
from trustmesh.merkle_audit import MerkleAuditTree, AuditInclusionProof
from trustmesh.abac import AgentRateLimiter, ABACPolicyEvaluator
from trustmesh.quorum import QuorumDelegationToken
from trustmesh.tracing import TrustMeshTraceContext
from trustmesh.agent_card import AgentCard, AgentSkill

__version__ = "1.1.0"

__all__ = [
    "AgentKeypair",
    "pubkey_to_did",
    "did_to_pubkey",
    "canonical_json",
    "hash_payload",
    "verify_signature",
    "Caveat",
    "Capability",
    "DelegationToken",
    "ProofOfPossession",
    "DynamicPolicyEngine",
    "PolicyDecision",
    "HelloMessage",
    "ChallengeMessage",
    "AuthResponseMessage",
    "EstablishedSession",
    "MutualHandshakeProtocol",
    "TrustMeshSecureChannel",
    "EncryptedPayload",
    "BloomRevocationRegistry",
    "RevocationReceipt",
    "MerkleAuditTree",
    "AuditInclusionProof",
    "AgentRateLimiter",
    "ABACPolicyEvaluator",
    "QuorumDelegationToken",
    "TrustMeshTraceContext",
    "AgentCard",
    "AgentSkill",
]
