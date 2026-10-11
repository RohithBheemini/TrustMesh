"""
Tests for TrustMesh Multi-Agent Threshold Quorum Delegation (M-of-N Multi-Sig).
Validates stakeholder cosignatures, threshold satisfaction, replay prevention, and expiration.
"""

import time
import pytest
from trustmesh.crypto import AgentKeypair
from trustmesh.tokens import Capability, Caveat
from trustmesh.quorum import QuorumDelegationToken


def test_quorum_delegation_success_2_of_3():
    cso = AgentKeypair.generate(name="CSO_Key")
    cfo = AgentKeypair.generate(name="CFO_Key")
    legal = AgentKeypair.generate(name="Legal_Key")
    worker = AgentKeypair.generate(name="DeploymentWorker")

    token = QuorumDelegationToken(
        aud=worker.did,
        capabilities=[Capability(resource="cloud:prod:deploy", action="deploy", caveats=Caveat(max_spend=10000.0))],
        authorized_signers=[cso.did, cfo.did, legal.did],
        threshold_m=2,  # 2 of 3 required
        expires_at=int(time.time()) + 3600,
    )

    # 1. Initially 0 signatures -> Insufficient
    ok, msg, signers = token.verify_quorum()
    assert ok is False
    assert "ERR_INSUFFICIENT_QUORUM" in msg
    assert len(signers) == 0

    # 2. CSO cosigns (1 of 2) -> Still insufficient
    token.add_cosignature(cso)
    ok, msg, signers = token.verify_quorum()
    assert ok is False
    assert len(signers) == 1

    # 3. CFO cosigns (2 of 2) -> Quorum satisfied!
    token.add_cosignature(cfo)
    ok, msg, signers = token.verify_quorum()
    assert ok is True
    assert "Quorum satisfied" in msg
    assert len(signers) == 2
    assert cso.did in signers
    assert cfo.did in signers


def test_quorum_duplicate_signer_ignored():
    cso = AgentKeypair.generate(name="CSO_Key")
    cfo = AgentKeypair.generate(name="CFO_Key")
    worker = AgentKeypair.generate(name="Worker")

    token = QuorumDelegationToken(
        aud=worker.did,
        capabilities=[Capability(resource="finance:wire", action="send", caveats=Caveat())],
        authorized_signers=[cso.did, cfo.did],
        threshold_m=2,
        expires_at=int(time.time()) + 3600,
    )

    # CSO signs twice
    token.add_cosignature(cso)
    token.add_cosignature(cso)  # Re-signing by same identity

    # Must count as only 1 signature
    ok, msg, signers = token.verify_quorum()
    assert ok is False
    assert len(signers) == 1


def test_quorum_unauthorized_signer_rejected():
    cso = AgentKeypair.generate(name="CSO_Key")
    rogue = AgentKeypair.generate(name="RogueAgent")
    worker = AgentKeypair.generate(name="Worker")

    token = QuorumDelegationToken(
        aud=worker.did,
        capabilities=[Capability(resource="admin:*", action="*", caveats=Caveat())],
        authorized_signers=[cso.did],
        threshold_m=1,
        expires_at=int(time.time()) + 3600,
    )

    # Attempting to cosign with rogue key not in authorized_signers raises ValueError
    with pytest.raises(ValueError, match="not in authorized signers pool"):
        token.add_cosignature(rogue)


def test_quorum_expired_token():
    cso = AgentKeypair.generate(name="CSO_Key")
    worker = AgentKeypair.generate(name="Worker")

    token = QuorumDelegationToken(
        aud=worker.did,
        capabilities=[Capability(resource="admin:*", action="*", caveats=Caveat())],
        authorized_signers=[cso.did],
        threshold_m=1,
        expires_at=int(time.time()) - 100,  # Expired in past
    )
    token.add_cosignature(cso)
    ok, msg, _ = token.verify_quorum()
    assert ok is False
    assert "ERR_TOKEN_EXPIRED" in msg
