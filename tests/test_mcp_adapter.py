"""
Tests for TrustMesh Anthropic Model Context Protocol (MCP) Tool Guard.
Validates zero-trust interception, parameter boundaries, and prompt injection defense.
"""

import time
import pytest
from trustmesh.crypto import AgentKeypair
from trustmesh.tokens import Capability, Caveat, DelegationToken
from trustmesh.policy import DynamicPolicyEngine
from trustmesh.adapters.mcp_adapter import TrustMeshMCPToolGuard, MCPToolResponse


def test_mcp_tool_guard_authorized_call():
    root = AgentKeypair.generate(name="RootPrincipal")
    caller = AgentKeypair.generate(name="MCPCallerAgent")

    engine = DynamicPolicyEngine()
    engine.add_trusted_root(root.did)

    token = DelegationToken(
        iss=root.did,
        aud=caller.did,
        capabilities=[
            Capability(
                resource="filesystem:read",
                action="read",
                caveats=Caveat(allowed_resources=["filesystem:read"], allowed_actions=["read"]),
            )
        ],
        expires_at=int(time.time()) + 3600,
    )
    token.sign(root)

    # Tool handler
    executed = []
    def cat_file(filepath: str):
        executed.append(filepath)
        return f"Content of {filepath}"

    guard = TrustMeshMCPToolGuard(
        tool_name="cat_file",
        resource_pattern="filesystem:read",
        action_name="read",
        handler=cat_file,
        policy_engine=engine,
        spend_arg_name=None,
    )

    args = {"filepath": "/etc/safe.txt"}
    pop = token.generate_pop(caller, action="read", resource="filesystem:read", payload=args)

    resp: MCPToolResponse = guard.handle_call(
        token_data=token.model_dump(),
        pop_data=pop.model_dump(),
        arguments=args,
    )

    assert resp.is_error is False
    assert len(executed) == 1
    assert "Content of /etc/safe.txt" in resp.content[0]["text"]
    assert resp.trustmesh_decision["decision"] == "APPROVED"


def test_mcp_tool_guard_blocks_overspend():
    root = AgentKeypair.generate(name="RootPrincipal")
    caller = AgentKeypair.generate(name="MCPCallerAgent")

    engine = DynamicPolicyEngine()
    engine.add_trusted_root(root.did)

    token = DelegationToken(
        iss=root.did,
        aud=caller.did,
        capabilities=[
            Capability(
                resource="payment:charge",
                action="charge",
                caveats=Caveat(max_spend=500.0, allowed_resources=["payment:charge"], allowed_actions=["charge"]),
            )
        ],
        expires_at=int(time.time()) + 3600,
    )
    token.sign(root)

    # Tool handler
    executed = []
    def charge_customer(amount: float, customer_id: str):
        executed.append(amount)
        return {"status": "CHARGED", "amount": amount}

    guard = TrustMeshMCPToolGuard(
        tool_name="charge_customer",
        resource_pattern="payment:charge",
        action_name="charge",
        handler=charge_customer,
        policy_engine=engine,
        spend_arg_name="amount",
    )

    # Attempt $900 charge (limit is $500)
    args = {"amount": 900.0, "customer_id": "cust_123"}
    pop = token.generate_pop(caller, action="charge", resource="payment:charge", payload=args)

    resp = guard.handle_call(
        token_data=token.model_dump(),
        pop_data=pop.model_dump(),
        arguments=args,
    )

    assert resp.is_error is True
    assert len(executed) == 0  # Handler was never called!
    assert "ERR_SPEND_LIMIT_EXCEEDED" in resp.content[0]["text"]
    assert resp.trustmesh_decision["decision"] == "BLOCKED"
    assert resp.trustmesh_decision["code"] == "ERR_SPEND_LIMIT_EXCEEDED"


def test_mcp_tool_guard_malformed_credentials():
    engine = DynamicPolicyEngine()
    guard = TrustMeshMCPToolGuard(
        tool_name="dummy",
        resource_pattern="dummy:*",
        action_name="dummy",
        handler=lambda: "ok",
        policy_engine=engine,
    )

    resp = guard.handle_call(
        token_data={"invalid": "payload"},
        pop_data={},
        arguments={},
    )
    assert resp.is_error is True
    assert "Malformed TrustMesh credentials" in resp.content[0]["text"]
