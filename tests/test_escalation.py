"""
Tests for Human-in-the-Loop Step-Up Escalation and Supervisor Waiver Issuance.
Validates dynamic overspend challenges, supervisor approvals, and ephemeral waiver tokens.
"""

from trustmesh.crypto import AgentKeypair
from trustmesh.policy import DynamicPolicyEngine
from trustmesh.escalation import EscalationManager


def test_escalation_lifecycle_approval():
    supervisor = AgentKeypair.generate(name="EnterpriseSupervisor")
    worker = AgentKeypair.generate(name="WorkerAgent")

    mgr = EscalationManager(supervisor_keypair=supervisor)
    engine = DynamicPolicyEngine()
    engine.add_trusted_root(supervisor.did)

    # 1. Create escalation challenge for $750 flight when ceiling is $600
    req = mgr.create_escalation(
        agent_name="WorkerAgent",
        invoking_agent_did=worker.did,
        action="book",
        resource="travel:flights:book",
        requested_amount=750.0,
        current_ceiling=600.0,
        payload={"flight_no": "AA-772", "amount": 750.0},
    )

    assert req.status == "PENDING"
    assert req.excess_amount == 150.0
    assert len(mgr.get_pending()) == 1

    # 2. Supervisor approves
    success, waiver_token, msg = mgr.approve_escalation(req.challenge_id)
    assert success is True
    assert waiver_token is not None
    assert req.status == "APPROVED"
    assert len(mgr.get_pending()) == 0

    # 3. Verify the waiver token enables the $750 transaction
    payload = {"flight_no": "AA-772", "amount": 750.0}
    pop = waiver_token.generate_pop(worker, action="book", resource="travel:flights:book", payload=payload)
    decision = engine.evaluate_request(
        token=waiver_token,
        pop=pop,
        resource="travel:flights:book",
        action="book",
        payload=payload,
        context={"spend_amount": 750.0},
    )

    assert decision.decision == "APPROVED"
    assert decision.code == "AUTH_OK"


def test_escalation_rejection():
    supervisor = AgentKeypair.generate(name="EnterpriseSupervisor")
    mgr = EscalationManager(supervisor_keypair=supervisor)

    req = mgr.create_escalation(
        agent_name="UntrustedAgent",
        invoking_agent_did="did:key:untrusted",
        action="wire_transfer",
        resource="finance:wire",
        requested_amount=100000.0,
        current_ceiling=0.0,
        payload={"amount": 100000.0},
    )

    assert len(mgr.get_pending()) == 1

    success, msg = mgr.reject_escalation(req.challenge_id, reason="Policy budget frozen")
    assert success is True
    assert req.status == "REJECTED"
    assert len(mgr.get_pending()) == 0

    # Double reject fails
    success2, msg2 = mgr.reject_escalation(req.challenge_id)
    assert success2 is False
