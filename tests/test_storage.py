"""
Unit tests for TrustMesh Durable Storage & Persistence Layer
Verifies recording, retrieval, and schema integrity using SQLite.
"""

import os
import tempfile
import pytest
from trustmesh.crypto import AgentKeypair
from trustmesh.policy import PolicyDecision
from trustmesh.revocation import RevocationReceipt
from trustmesh.storage import AuditStorage


@pytest.fixture
def temp_db():
    fd, path = tempfile.mkstemp(suffix=".db")
    os.close(fd)
    storage = AuditStorage(db_url=f"sqlite:///{path}")
    yield storage
    try:
        os.remove(path)
    except Exception:
        pass


def test_durable_audit_storage(temp_db):
    admin_key = AgentKeypair.generate(name="AdminVerifier")
    decision = PolicyDecision(
        decision="APPROVED",
        code="AUTH_OK",
        reason="Verified 2-step delegation chain",
        invoking_agent="did:key:z6MkTestAgent",
        target_resource="travel:flights",
        target_action="book",
        chain_depth=2,
        token_id="token-uuid-123",
        evaluated_caveats={"max_spend": 600.0},
    )
    decision.sign(admin_key)

    # Record decision
    temp_db.record_decision(decision)

    # Query decisions
    recent = temp_db.get_recent_decisions(limit=10)
    assert len(recent) == 1
    assert recent[0].decision == "APPROVED"
    assert recent[0].code == "AUTH_OK"
    assert recent[0].invoking_agent == "did:key:z6MkTestAgent"
    assert recent[0].evaluated_caveats["max_spend"] == 600.0


def test_durable_revocation_storage(temp_db):
    authority = AgentKeypair.generate(name="Authority")
    receipt = RevocationReceipt(
        target_id="did:key:z6MkMaliciousRogueAgent",
        target_type="AGENT",
        reason="Private key compromised",
        authority_did=authority.did,
    )
    receipt.sign(authority)

    temp_db.record_revocation(receipt)
    revoked_ids = temp_db.get_revoked_ids()
    assert "did:key:z6MkMaliciousRogueAgent" in revoked_ids
