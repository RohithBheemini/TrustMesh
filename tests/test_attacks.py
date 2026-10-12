"""
Automated Pytest Security Test Suite for TrustMesh
Asserts that all 6 adversary attacks are deterministically blocked by the policy engine.
"""

import pytest
from security.attack_harness import SecurityAttackHarness


@pytest.fixture
def harness():
    return SecurityAttackHarness()


def test_attack_1_impersonation_blocked(harness):
    decision = harness.test_impersonation_attack()
    assert decision.decision == "BLOCKED"
    assert decision.code in ["ERR_AUDIENCE_MISMATCH", "ERR_IMPERSONATION"]


def test_attack_2_replay_blocked(harness):
    decision = harness.test_replay_attack()
    assert decision.decision == "BLOCKED"
    assert decision.code == "ERR_REPLAY_ATTACK"


def test_attack_3_privilege_escalation_blocked(harness):
    decision = harness.test_privilege_escalation_attack()
    assert decision.decision == "BLOCKED"
    assert decision.code == "ERR_PRIVILEGE_ESCALATION"


def test_attack_4_payload_spoofing_blocked(harness):
    decision = harness.test_payload_spoofing_attack()
    assert decision.decision == "BLOCKED"
    assert decision.code == "ERR_PAYLOAD_TAMPERED"


def test_attack_5_expired_token_blocked(harness):
    decision = harness.test_expired_token_attack()
    assert decision.decision == "BLOCKED"
    assert decision.code == "ERR_TOKEN_EXPIRED"


def test_attack_6_chain_tampering_blocked(harness):
    decision = harness.test_chain_tampering_attack()
    assert decision.decision == "BLOCKED"
    assert decision.code in ["ERR_CHAIN_BROKEN", "ERR_CHAIN_TAMPERED"]


def test_dynamic_revocation(harness):
    # Test agent revocation at runtime
    harness.policy_engine.revoke_agent(harness.worker_agent.did)
    pop = harness.valid_worker_token.generate_pop(
        keypair=harness.worker_agent,
        action="purchase",
        resource="cloud:vm:provision",
        payload={"amount": 10.0},
    )
    decision = harness.policy_engine.evaluate_request(
        token=harness.valid_worker_token,
        pop=pop,
        resource="cloud:vm:provision",
        action="purchase",
        payload={"amount": 10.0},
    )
    assert decision.decision == "BLOCKED"
    assert decision.code == "ERR_AGENT_REVOKED"

    # Unrevoke agent and revoke specific token
    harness.policy_engine.unrevoke_agent(harness.worker_agent.did)
    harness.policy_engine.revoke_token(harness.valid_worker_token.token_id)
    # Generate new pop with fresh nonce
    pop2 = harness.valid_worker_token.generate_pop(
        keypair=harness.worker_agent,
        action="purchase",
        resource="cloud:vm:provision",
        payload={"amount": 10.0},
    )
    decision2 = harness.policy_engine.evaluate_request(
        token=harness.valid_worker_token,
        pop=pop2,
        resource="cloud:vm:provision",
        action="purchase",
        payload={"amount": 10.0},
    )
    assert decision2.decision == "BLOCKED"
    assert decision2.code == "ERR_TOKEN_REVOKED"
