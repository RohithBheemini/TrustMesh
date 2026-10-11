"""
Unit tests for TrustMesh LangGraph Adapter
Verifies state graph node protection, capability evaluation, and overspend blocking.
"""

from trustmesh.crypto import AgentKeypair
from trustmesh.tokens import Capability, Caveat, DelegationToken
from trustmesh.policy import DynamicPolicyEngine
from trustmesh.adapters.langgraph_adapter import TrustMeshLangGraphNode, secure_langgraph_node


def test_langgraph_secure_node_execution():
    policy_engine = DynamicPolicyEngine()
    root = AgentKeypair.generate(name="EnterpriseRoot")
    worker = AgentKeypair.generate(name="GraphWorker")
    policy_engine.add_trusted_root(root.did)

    token = DelegationToken(
        iss=root.did,
        aud=worker.did,
        capabilities=[Capability(
            resource="graph:node:compute",
            action="execute",
            caveats=Caveat(max_spend=200.0),
        )],
        expires_at=2000000000,
    )
    token.sign(root)

    # Define a LangGraph node function
    def compute_node_func(state):
        return {**state, "result": "computed_analytics"}

    node = TrustMeshLangGraphNode(
        node_name="analytics_node",
        resource="graph:node:compute",
        action="execute",
        func=compute_node_func,
        policy_engine=policy_engine,
    )

    # 1. Valid invocation state
    pop = token.generate_pop(
        keypair=worker,
        action="execute",
        resource="graph:node:compute",
        payload={"query": "SELECT count(*) FROM analytics"},
    )
    valid_state = {
        "token": token.model_dump(),
        "pop": pop.model_dump(),
        "payload": {"query": "SELECT count(*) FROM analytics"},
        "spend_amount": 100.0,
    }
    out_state = node(valid_state)
    assert out_state["status"] == "SUCCESS"
    assert out_state["result"] == "computed_analytics"
    assert out_state["audit_receipt"]["decision"] == "APPROVED"

    # 2. Overspend invocation state ($350 exceeds $200)
    overspend_pop = token.generate_pop(
        keypair=worker,
        action="execute",
        resource="graph:node:compute",
        payload={"query": "heavy_compute"},
    )
    invalid_state = {
        "token": token.model_dump(),
        "pop": overspend_pop.model_dump(),
        "payload": {"query": "heavy_compute"},
        "spend_amount": 350.0,
    }
    blocked_state = node(invalid_state)
    assert blocked_state["status"] == "BLOCKED"
    assert "ERR_SPEND_LIMIT_EXCEEDED" in blocked_state["error"]
