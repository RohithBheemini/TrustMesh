"""
Unit tests for TrustMesh FastAPI AuthGuard Middleware
Verifies HTTP header extraction, 401 Unauthorized, 403 Forbidden, and 200 OK responses.
"""

import pytest
from fastapi import FastAPI, Depends, Request
from starlette.testclient import TestClient

from trustmesh.crypto import AgentKeypair
from trustmesh.tokens import Capability, Caveat, DelegationToken
from trustmesh.policy import DynamicPolicyEngine
from trustmesh.adapters.fastapi_adapter import require_capability
from trustmesh.adapters.client import encode_header_json

test_app = FastAPI()
policy_engine = DynamicPolicyEngine()
root_user = AgentKeypair.generate(name="RootUser")
agent_user = AgentKeypair.generate(name="AgentUser")
policy_engine.add_trusted_root(root_user.did)

# Build valid token
cap = Capability(resource="payment:charge", action="execute", caveats=Caveat(max_spend=300.0))
valid_token = DelegationToken(
    iss=root_user.did,
    aud=agent_user.did,
    capabilities=[cap],
    expires_at=2000000000,
)
valid_token.sign(root_user)


@test_app.post("/charge", dependencies=[Depends(require_capability("payment:charge", "execute", policy_engine))])
async def charge_endpoint(request: Request):
    return {"status": "charged", "caller": request.state.agent_did}


@pytest.fixture
def api_client():
    return TestClient(test_app)


def test_missing_headers_returns_401(api_client):
    """Missing X-TrustMesh-Token returns 401 Unauthorized."""
    resp = api_client.post("/charge", json={"amount": 100.0})
    assert resp.status_code == 401
    assert resp.json()["detail"]["code"] == "ERR_MISSING_TOKEN"


def test_missing_pop_returns_401(api_client):
    """Missing X-TrustMesh-PoP returns 401 Unauthorized."""
    headers = {"X-TrustMesh-Token": encode_header_json(valid_token.model_dump())}
    resp = api_client.post("/charge", json={"amount": 100.0}, headers=headers)
    assert resp.status_code == 401
    assert resp.json()["detail"]["code"] == "ERR_MISSING_POP"


def test_valid_request_returns_200(api_client):
    """Valid token + PoP executes with 200 OK."""
    payload = {"amount": 150.0}
    pop = valid_token.generate_pop(
        keypair=agent_user,
        action="execute",
        resource="payment:charge",
        payload=payload,
    )
    headers = {
        "X-TrustMesh-Token": encode_header_json(valid_token.model_dump()),
        "X-TrustMesh-PoP": encode_header_json(pop.model_dump()),
    }
    resp = api_client.post("/charge", json=payload, headers=headers)
    assert resp.status_code == 200
    assert resp.json()["status"] == "charged"
    assert resp.json()["caller"] == agent_user.did


def test_overspend_returns_403(api_client):
    """Overspending returns 403 Forbidden with cryptographic reason."""
    payload = {"amount": 500.0}  # Limit is $300.0
    pop = valid_token.generate_pop(
        keypair=agent_user,
        action="execute",
        resource="payment:charge",
        payload=payload,
    )
    headers = {
        "X-TrustMesh-Token": encode_header_json(valid_token.model_dump()),
        "X-TrustMesh-PoP": encode_header_json(pop.model_dump()),
    }
    resp = api_client.post("/charge", json=payload, headers=headers)
    assert resp.status_code == 403
    assert resp.json()["detail"]["code"] == "ERR_SPEND_LIMIT_EXCEEDED"
