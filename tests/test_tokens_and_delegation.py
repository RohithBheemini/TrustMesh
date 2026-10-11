"""
Unit tests for TrustMesh Tokens and Attenuated Delegation
Verifies capability matching, caveat monotonic tightening, token attenuation, and PoP envelopes.
"""

import time
import pytest
from trustmesh.crypto import AgentKeypair
from trustmesh.tokens import Capability, Caveat, DelegationToken, ProofOfPossession


def test_caveat_monotonic_tightening():
    parent_caveat = Caveat(
        max_spend=1000.0,
        allowed_actions=["read", "write", "execute"],
        expiry=2000,
        predicates={"regions": ["us-east", "us-west"]},
    )

    # Valid tighter child
    child_caveat = Caveat(
        max_spend=500.0,
        allowed_actions=["read", "write"],
        expiry=1500,
        predicates={"regions": ["us-east"]},
    )
    is_valid, reason = child_caveat.is_tighter_or_equal_to(parent_caveat)
    assert is_valid is True
    assert reason == ""

    # Invalid: Child increases spend
    bad_spend = Caveat(max_spend=1500.0)
    is_valid, reason = bad_spend.is_tighter_or_equal_to(parent_caveat)
    assert is_valid is False
    assert "exceeds parent limit" in reason

    # Invalid: Child adds unauthorized action (preserving spend limit and expiry)
    bad_action = Caveat(max_spend=500.0, allowed_actions=["delete"], expiry=1500)
    is_valid, reason = bad_action.is_tighter_or_equal_to(parent_caveat)
    assert is_valid is False
    assert "not permitted by parent" in reason

    # Invalid: Child widens predicate (preserving spend, actions, and expiry)
    bad_pred = Caveat(max_spend=500.0, allowed_actions=["read"], expiry=1500, predicates={"regions": ["us-east", "eu-central"]})
    is_valid, reason = bad_pred.is_tighter_or_equal_to(parent_caveat)
    assert is_valid is False
    assert "exceed parent allowed set" in reason


def test_delegation_chain_attenuation():
    root = AgentKeypair.generate(name="Root")
    coord = AgentKeypair.generate(name="Coordinator")
    worker = AgentKeypair.generate(name="Worker")

    root_cap = Capability(
        resource="db:*",
        action="*",
        caveats=Caveat(max_spend=500.0, allowed_actions=["read", "write"]),
    )
    root_token = DelegationToken(
        iss=root.did,
        aud=coord.did,
        capabilities=[root_cap],
        expires_at=int(time.time()) + 3600,
    )
    root_token.sign(root)
    assert root_token.verify_token_signature() is True
    assert root_token.chain_depth == 1

    # Coordinator attenuates to Worker
    worker_cap = Capability(
        resource="db:users:*",
        action="read",
        caveats=Caveat(max_spend=100.0, allowed_actions=["read"]),
    )
    worker_token = root_token.attenuate(
        audience_did=worker.did,
        restricted_capabilities=[worker_cap],
        keypair=coord,
        validity_seconds=1800,
    )
    assert worker_token.verify_token_signature() is True
    assert worker_token.chain_depth == 2

    chain = worker_token.get_delegation_chain()
    assert len(chain) == 2
    assert chain[0].token_id == root_token.token_id
    assert chain[1].token_id == worker_token.token_id


def test_proof_of_possession():
    agent = AgentKeypair.generate(name="Agent")
    impostor = AgentKeypair.generate(name="Impostor")

    payload = {"query": "SELECT * FROM users"}
    pop = ProofOfPossession(
        token_id="tok_123",
        agent_did=agent.did,
        action="query",
        resource="db:users",
        payload_hash="some_hash",
        timestamp=int(time.time()),
        nonce="nonce_456",
    )
    pop.sign(agent)
    assert pop.verify() is True

    # Tampered signature with wrong key
    bad_pop = ProofOfPossession(
        token_id="tok_123",
        agent_did=agent.did,  # Claims to be agent
        action="query",
        resource="db:users",
        payload_hash="some_hash",
        timestamp=int(time.time()),
        nonce="nonce_456",
    )
    with pytest.raises(ValueError, match="does not match PoP agent_did"):
        bad_pop.sign(impostor)
