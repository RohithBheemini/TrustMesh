"""
TrustMesh LangGraph Adapter
Provides native zero-trust authorization decorators and state nodes for LangGraph multi-agent workflows.
"""

from __future__ import annotations
from typing import Any, Callable, Dict, Optional
from pydantic import BaseModel

from trustmesh.crypto import AgentKeypair
from trustmesh.tokens import Capability, Caveat, DelegationToken, ProofOfPossession
from trustmesh.policy import DynamicPolicyEngine, PolicyDecision


class TrustMeshState(BaseModel):
    """
    Standard state envelope for LangGraph state graphs incorporating TrustMesh authorization.
    """
    messages: list[Dict[str, Any]] = []
    token: Optional[Dict[str, Any]] = None
    pop: Optional[Dict[str, Any]] = None
    action: Optional[str] = None
    resource: Optional[str] = None
    spend_amount: Optional[float] = None
    audit_receipt: Optional[Dict[str, Any]] = None
    status: str = "PENDING"


class TrustMeshLangGraphNode:
    """
    A protected LangGraph node wrapper.
    Ensures that incoming graph state is cryptographically authorized before invoking node logic.
    """

    def __init__(
        self,
        node_name: str,
        resource: str,
        action: str,
        func: Callable[[Dict[str, Any]], Dict[str, Any]],
        policy_engine: DynamicPolicyEngine,
    ):
        self.node_name = node_name
        self.resource = resource
        self.action = action
        self.func = func
        self.policy_engine = policy_engine

    def __call__(self, state: Dict[str, Any]) -> Dict[str, Any]:
        """
        Intercepts node execution in LangGraph, evaluates policy, and updates state.
        """
        token_data = state.get("token")
        pop_data = state.get("pop")

        if not token_data or not pop_data:
            decision = self.policy_engine._block(
                "ERR_MISSING_AUTH",
                f"LangGraph node '{self.node_name}' requires active TrustMesh token and PoP envelope",
                state.get("caller_did", "unknown"),
                self.resource,
                self.action,
            )
            return {
                **state,
                "status": "BLOCKED",
                "error": decision.reason,
                "audit_receipt": decision.model_dump(),
            }

        token = DelegationToken.model_validate(token_data)
        pop = ProofOfPossession.model_validate(pop_data)

        # Context evaluation
        ctx = {}
        if "spend_amount" in state:
            ctx["spend_amount"] = state["spend_amount"]

        decision = self.policy_engine.evaluate_request(
            token=token,
            pop=pop,
            resource=self.resource,
            action=self.action,
            payload=state.get("payload", state.get("messages", [])),
            context=ctx,
        )

        if decision.decision != "APPROVED":
            return {
                **state,
                "status": "BLOCKED",
                "error": f"Policy Violation: {decision.reason} ({decision.code})",
                "audit_receipt": decision.model_dump(),
            }

        # Policy passed: invoke underlying node function
        result_state = self.func(state)
        result_state["status"] = "SUCCESS"
        result_state["audit_receipt"] = decision.model_dump()
        return result_state


def secure_langgraph_node(
    node_name: str,
    resource: str,
    action: str,
    policy_engine: DynamicPolicyEngine,
) -> Callable:
    """Decorator for creating secure LangGraph nodes."""
    def decorator(func: Callable[[Dict[str, Any]], Dict[str, Any]]):
        return TrustMeshLangGraphNode(node_name, resource, action, func, policy_engine)
    return decorator
