"""
TrustMesh Adapter for CrewAI Agents & Tools
Provides cryptographic capability enforcement for CrewAI tools and sub-agent delegation.
Supports both native CrewAI installations and zero-dependency standalone execution.
"""

from __future__ import annotations
from typing import Any, Callable, Dict, Optional

from trustmesh.crypto import AgentKeypair
from trustmesh.tokens import Capability, DelegationToken, ProofOfPossession
from trustmesh.policy import DynamicPolicyEngine


class TrustMeshCrewTool:
    """
    Secure Tool Wrapper for CrewAI workflows.
    Ensures that any tool invocation is authorized by a valid TrustMesh token and PoP.
    """

    def __init__(
        self,
        name: str,
        description: str,
        resource: str,
        action: str,
        func: Callable[..., Any],
        policy_engine: DynamicPolicyEngine,
    ):
        self.name = name
        self.description = description
        self.resource = resource
        self.action = action
        self.func = func
        self.policy_engine = policy_engine

    def execute(
        self,
        token: DelegationToken,
        pop: ProofOfPossession,
        payload: Dict[str, Any],
        context: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """
        Evaluate policy before executing the underlying tool.
        """
        ctx = context or {}
        if "amount" in payload and "spend_amount" not in ctx:
            ctx["spend_amount"] = payload["amount"]

        decision = self.policy_engine.evaluate_request(
            token=token,
            pop=pop,
            resource=self.resource,
            action=self.action,
            payload=payload,
            context=ctx,
        )

        if decision.decision != "APPROVED":
            return {
                "status": "BLOCKED",
                "decision": decision.model_dump(),
                "error": f"Security Policy Violation: {decision.reason} (Code: {decision.code})",
            }

        # Authorized: execute tool function
        result = self.func(**payload)
        return {
            "status": "SUCCESS",
            "decision": decision.model_dump(),
            "result": result,
        }

    def __call__(self, *args, **kwargs):
        return self.execute(*args, **kwargs)


class TrustMeshCrewAgent:
    """
    CrewAI Agent wrapper equipped with an Ed25519 identity and active DelegationToken.
    Capable of attenuating capabilities and delegating tasks to sub-agents.
    """

    def __init__(
        self,
        role: str,
        goal: str,
        keypair: AgentKeypair,
        token: Optional[DelegationToken] = None,
    ):
        self.role = role
        self.goal = goal
        self.keypair = keypair
        self.token = token
        self.did = keypair.did

    def delegate_to(
        self,
        target_agent_did: str,
        capabilities: list[Capability],
        validity_seconds: int = 3600,
    ) -> DelegationToken:
        """
        Attenuate current token and delegate scoped capabilities to another agent.
        """
        if not self.token:
            raise ValueError(f"Agent {self.role} does not possess an active delegation token to delegate from")
        
        return self.token.attenuate(
            audience_did=target_agent_did,
            restricted_capabilities=capabilities,
            keypair=self.keypair,
            validity_seconds=validity_seconds,
        )

    def invoke_tool(
        self,
        tool: TrustMeshCrewTool,
        payload: Dict[str, Any],
        context: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """
        Invoke a TrustMesh-protected tool using current token and freshly signed PoP envelope.
        """
        if not self.token:
            raise ValueError(f"Agent {self.role} has no token to authorize tool invocation")

        pop = self.token.generate_pop(
            keypair=self.keypair,
            action=tool.action,
            resource=tool.resource,
            payload=payload,
        )
        return tool.execute(token=self.token, pop=pop, payload=payload, context=context)
