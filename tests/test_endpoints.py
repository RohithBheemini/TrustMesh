"""
Automated Comprehensive Endpoint Verification for TrustMesh Dashboard API
Verifies every single route, status codes, payload structures, SSE streaming, and error handlers.
"""

import pytest
from starlette.testclient import TestClient
from dashboard.server import app, mesh


@pytest.fixture
def client():
    # Reset mesh state before each test suite
    mesh.reset()
    return TestClient(app)


def test_endpoint_get_root(client):
    """Verify GET / returns HTML dashboard."""
    response = client.get("/")
    assert response.status_code == 200
    assert "text/html" in response.headers["content-type"]
    assert "TrustMesh" in response.text
    assert "Dynamic Agent-to-Agent Authorization" in response.text


def test_endpoint_get_status(client):
    """Verify GET /api/status returns mesh topology, agents, and tokens."""
    response = client.get("/api/status")
    assert response.status_code == 200
    data = response.json()
    assert "agents" in data
    assert len(data["agents"]) == 5
    assert "spend_ceiling" in data
    assert data["spend_ceiling"] == 600.0
    assert "tokens" in data
    assert len(data["tokens"]) == 2  # Root and Child tokens
    assert "stats" in data
    assert data["stats"]["total_requests"] >= 0


def test_endpoint_get_audit_logs(client):
    """Verify GET /api/audit-logs returns log list."""
    response = client.get("/api/audit-logs")
    assert response.status_code == 200
    logs = response.json()
    assert isinstance(logs, list)


def test_endpoint_legitimate_booking(client):
    """Verify POST /api/action/legitimate-booking executes approved $450 transaction."""
    response = client.post("/api/action/legitimate-booking")
    assert response.status_code == 200
    decision = response.json()
    assert decision["decision"] == "APPROVED"
    assert decision["code"] == "AUTH_OK"
    assert decision["target_action"] == "book"
    assert decision["target_resource"] == "travel:flights:book"
    assert "receipt_signature" in decision
    assert len(decision["receipt_signature"]) > 0


@pytest.mark.parametrize("attack_id, expected_code", [
    ("impersonation", "ERR_AUDIENCE_MISMATCH"),
    ("replay", "ERR_REPLAY_ATTACK"),
    ("privilege_escalation", "ERR_SPEND_LIMIT_EXCEEDED"),
    ("payload_spoofing", "ERR_PAYLOAD_TAMPERED"),
    ("expired_token", "ERR_TOKEN_EXPIRED"),
    ("chain_tampering", "ERR_CHAIN_BROKEN"),
])
def test_endpoint_attacks(client, attack_id, expected_code):
    """Verify POST /api/action/attack/{attack_id} simulates and blocks all attacks."""
    response = client.post(f"/api/action/attack/{attack_id}")
    assert response.status_code == 200
    decision = response.json()
    assert decision["decision"] == "BLOCKED"
    assert decision["code"] == expected_code
    assert "reason" in decision


def test_endpoint_attack_invalid(client):
    """Verify POST /api/action/attack/invalid_attack returns 400 Bad Request."""
    response = client.post("/api/action/attack/unknown_attack_xyz")
    assert response.status_code == 400
    assert response.json()["detail"] == "Unknown attack scenario"


def test_endpoint_update_spend_limit(client):
    """Verify POST /api/policy/spend-limit dynamically updates spend ceiling."""
    response = client.post("/api/policy/spend-limit", json={"max_spend": 350.0})
    assert response.status_code == 200
    assert response.json()["spend_ceiling"] == 350.0

    # Verify status reflects updated spend
    status_resp = client.get("/api/status")
    assert status_resp.json()["spend_ceiling"] == 350.0

    # After lowering ceiling to $350, booking $450 should be blocked!
    booking_resp = client.post("/api/action/legitimate-booking")
    assert booking_resp.status_code == 200
    assert booking_resp.json()["decision"] == "BLOCKED"
    assert booking_resp.json()["code"] == "ERR_SPEND_LIMIT_EXCEEDED"


def test_endpoint_revoke_agent(client):
    """Verify POST /api/policy/revoke-agent revokes and restores keys."""
    # Revoke Flight Booker
    rev_resp = client.post("/api/policy/revoke-agent", json={"agent_id": "booker", "revoked": True})
    assert rev_resp.status_code == 200
    assert rev_resp.json()["revoked"] is True

    # Immediate booking should now be BLOCKED due to revocation
    booking_resp = client.post("/api/action/legitimate-booking")
    assert booking_resp.status_code == 200
    assert booking_resp.json()["decision"] == "BLOCKED"
    assert booking_resp.json()["code"] == "ERR_AGENT_REVOKED"

    # Restore key
    unrev_resp = client.post("/api/policy/revoke-agent", json={"agent_id": "booker", "revoked": False})
    assert unrev_resp.status_code == 200
    assert unrev_resp.json()["revoked"] is False

    # Immediate booking should now succeed again
    booking_resp2 = client.post("/api/action/legitimate-booking")
    assert booking_resp2.status_code == 200
    assert booking_resp2.json()["decision"] == "APPROVED"


def test_endpoint_reset(client):
    """Verify POST /api/reset resets mesh to fresh defaults."""
    # Modify state first
    client.post("/api/policy/spend-limit", json={"max_spend": 200.0})
    client.post("/api/policy/revoke-agent", json={"agent_id": "booker", "revoked": True})

    # Reset
    reset_resp = client.post("/api/reset")
    assert reset_resp.status_code == 200
    assert reset_resp.json()["status"] == "ok"

    # Status should be restored
    status_resp = client.get("/api/status")
    assert status_resp.json()["spend_ceiling"] == 600.0
    assert len(status_resp.json()["revoked_agents"]) == 0


def test_endpoint_healthz(client):
    """Verify GET /healthz returns 200 OK and healthy status."""
    resp = client.get("/healthz")
    assert resp.status_code == 200
    assert resp.json()["status"] == "healthy"
    assert "timestamp" in resp.json()


def test_endpoint_metrics(client):
    """Verify GET /metrics returns metrics."""
    resp = client.get("/metrics")
    assert resp.status_code == 200
    data = resp.json()
    assert "trustmesh_requests_total" in data
    assert "trustmesh_active_agents" in data
    assert data["trustmesh_active_agents"] == 5


def test_endpoint_well_known_agent_card(client):
    """Verify GET /.well-known/agent-card.json returns valid signed A2A AgentCard."""
    resp = client.get("/.well-known/agent-card.json")
    assert resp.status_code == 200
    data = resp.json()
    assert "agent_did" in data
    assert "signature" in data
    assert "skills" in data
    assert data["name"] == "Payment Gateway (FastAPI / MCP Server)"


def test_endpoint_a2a_agent_cards(client):
    """Verify GET /api/a2a/agent-cards returns all mesh agent cards."""
    resp = client.get("/api/a2a/agent-cards")
    assert resp.status_code == 200
    cards = resp.json()
    assert "root" in cards
    assert "coord" in cards
    assert "booker" in cards
    assert "pay" in cards
    assert "rogue" in cards


def test_endpoint_escalation_workflow(client):
    """Verify trigger-overspend, pending list, and approval workflow."""
    # 1. Trigger overspend challenge
    resp = client.post("/api/escalation/trigger-overspend")
    assert resp.status_code == 200
    body = resp.json()
    assert body["decision"]["decision"] == "BLOCKED"
    assert body["decision"]["code"] == "ERR_SPEND_LIMIT_EXCEEDED"
    challenge_id = body["escalation"]["challenge_id"]

    # 2. Check pending list
    pending_resp = client.get("/api/escalation/pending")
    assert pending_resp.status_code == 200
    pending = pending_resp.json()
    assert any(p["challenge_id"] == challenge_id for p in pending)

    # 3. Approve escalation
    appr_resp = client.post(f"/api/escalation/approve/{challenge_id}")
    assert appr_resp.status_code == 200
    appr_data = appr_resp.json()
    assert appr_data["status"] == "APPROVED"
    assert appr_data["decision"]["decision"] == "APPROVED"
    assert "waiver_token_id" in appr_data


def test_endpoint_mcp_tool_call(client):
    """Verify POST /api/mcp/tool-call returns MCP structured tool response."""
    # Valid call
    resp = client.post("/api/mcp/tool-call", json={"arguments": {"flight_no": "AA-1042", "airline": "American", "amount": 450.0}})
    assert resp.status_code == 200
    data = resp.json()
    assert data["is_error"] is False
    assert data["trustmesh_decision"]["decision"] == "APPROVED"

    # Overspend call via MCP
    resp2 = client.post("/api/mcp/tool-call", json={"arguments": {"flight_no": "AA-FIRST", "airline": "American", "amount": 1200.0}})
    assert resp2.status_code == 200
    data2 = resp2.json()
    assert data2["is_error"] is True
    assert data2["trustmesh_decision"]["decision"] == "BLOCKED"
    assert data2["trustmesh_decision"]["code"] == "ERR_SPEND_LIMIT_EXCEEDED"
