"""
TrustMesh Model Context Protocol (MCP) Adapter
Provides zero-trust capability authorization and excessive agency defense
for Anthropic MCP Servers and AI tool execution pipelines.
"""

from __future__ import annotations
from typing import Any, Callable, Dict, Optional
from pydantic import BaseModel, Field

from trustmesh.tokens import DelegationToken, ProofOfPossession
from trustmesh.policy import DynamicPolicyEngine, PolicyDecision


class MCPToolRequest(BaseModel):
    """Represents a standard Model Context Protocol (MCP) tool execution call."""
    tool_name: str
    arguments: Dict[str, Any] = Field(default_factory=dict)
    metadata: Dict[str, Any] = Field(default_factory=dict)


class MCPToolResponse(BaseModel):
    """Standard Model Context Protocol tool execution response with TrustMesh audit receipt."""
    is_error: bool = False
    content: list[Dict[str, Any]] = Field(default_factory=list)
    trustmesh_decision: Optional[Dict[str, Any]] = None


class TrustMeshMCPToolGuard:
    """
    Zero-Trust Gatekeeper for Anthropic Model Context Protocol (MCP) tools.
    Prevents Prompt Injections and LLM Hallucinations from triggering unauthorized mutations.
    """

    def __init__(
        self,
        tool_name: str,
        resource_pattern: str,
        action_name: str,
        handler: Callable[..., Any],
        policy_engine: DynamicPolicyEngine,
        spend_arg_name: Optional[str] = "amount",
    ):
        self.tool_name = tool_name
        self.resource = resource_pattern
        self.action = action_name
        self.handler = handler
        self.policy_engine = policy_engine
        self.spend_arg = spend_arg_name

    def handle_call(
        self,
        token_data: Dict[str, Any],
        pop_data: Dict[str, Any],
        arguments: Dict[str, Any],
        context: Optional[Dict[str, Any]] = None,
    ) -> MCPToolResponse:
        """
        Intercepts and authorizes an MCP tool invocation before execution.
        """
        try:
            token = DelegationToken.model_validate(token_data)
            pop = ProofOfPossession.model_validate(pop_data)
        except Exception as e:
            return MCPToolResponse(
                is_error=True,
                content=[{"type": "text", "text": f"MCP Security Error: Malformed TrustMesh credentials ({str(e)})"}],
            )

        # Context evaluation (e.g. spend extraction)
        ctx = context or {}
        if self.spend_arg and self.spend_arg in arguments and "spend_amount" not in ctx:
            ctx["spend_amount"] = float(arguments[self.spend_arg])

        decision = self.policy_engine.evaluate_request(
            token=token,
            pop=pop,
            resource=self.resource,
            action=self.action,
            payload=arguments,
            context=ctx,
        )

        if decision.decision != "APPROVED":
            return MCPToolResponse(
                is_error=True,
                content=[{
                    "type": "text",
                    "text": f"TrustMesh Zero-Trust Gatekeeper BLOCKED MCP tool '{self.tool_name}': {decision.reason} [Code: {decision.code}]",
                }],
                trustmesh_decision=decision.model_dump(),
            )

        # Authorized: Execute underlying tool logic
        try:
            result = self.handler(**arguments)
            return MCPToolResponse(
                is_error=False,
                content=[{"type": "text", "text": str(result)}],
                trustmesh_decision=decision.model_dump(),
            )
        except Exception as e:
            return MCPToolResponse(
                is_error=True,
                content=[{"type": "text", "text": f"Tool Internal Error: {str(e)}"}],
                trustmesh_decision=decision.model_dump(),
            )
