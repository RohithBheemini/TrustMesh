"""
TrustMesh FastAPI Middleware and Dependency Adapter
Enables HTTP/REST Agent Microservices to enforce zero-trust capability authorization.
"""

from __future__ import annotations
import base64
import json
from typing import Any, Callable, Dict, Optional
from fastapi import Header, HTTPException, Request, Depends, status

from trustmesh.crypto import canonical_json
from trustmesh.tokens import DelegationToken, ProofOfPossession
from trustmesh.policy import DynamicPolicyEngine, PolicyDecision


def decode_header_json(header_val: str) -> dict:
    """Decode header from raw JSON string or URL-safe base64 string."""
    try:
        # First try base64 decode
        padded = header_val + ("=" * ((4 - len(header_val) % 4) % 4))
        raw_bytes = base64.urlsafe_b64decode(padded.encode("ascii"))
        return json.loads(raw_bytes.decode("utf-8"))
    except Exception:
        # Fallback to direct json parse
        return json.loads(header_val)


class TrustMeshAuthGuard:
    """
    FastAPI Route Dependency to authenticate and authorize agent requests.
    """

    def __init__(
        self,
        resource: str,
        action: str,
        policy_engine: DynamicPolicyEngine,
        extract_spend_from_body: Optional[str] = None,
    ):
        self.resource = resource
        self.action = action
        self.policy_engine = policy_engine
        self.spend_field = extract_spend_from_body

    async def __call__(
        self,
        request: Request,
        x_trustmesh_token: Optional[str] = Header(None, alias="X-TrustMesh-Token"),
        x_trustmesh_pop: Optional[str] = Header(None, alias="X-TrustMesh-PoP"),
    ) -> PolicyDecision:
        if not x_trustmesh_token:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail={"code": "ERR_MISSING_TOKEN", "reason": "Missing required 'X-TrustMesh-Token' header"},
            )
        if not x_trustmesh_pop:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail={"code": "ERR_MISSING_POP", "reason": "Missing required 'X-TrustMesh-PoP' header"},
            )

        try:
            token_dict = decode_header_json(x_trustmesh_token)
            pop_dict = decode_header_json(x_trustmesh_pop)
            token = DelegationToken.model_validate(token_dict)
            pop = ProofOfPossession.model_validate(pop_dict)
        except Exception as e:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail={"code": "ERR_MALFORMED_ENVELOPE", "reason": f"Failed to parse TrustMesh envelopes: {str(e)}"},
            )

        # Extract request body for payload hashing and dynamic spend context
        body_bytes = await request.body()
        body_obj: Any = None
        if body_bytes:
            try:
                body_obj = json.loads(body_bytes.decode("utf-8"))
            except Exception:
                body_obj = body_bytes

        # Context derivation
        ctx: Dict[str, Any] = {}
        if isinstance(body_obj, dict):
            if self.spend_field and self.spend_field in body_obj:
                ctx["spend_amount"] = float(body_obj[self.spend_field])
            elif "amount" in body_obj:
                ctx["spend_amount"] = float(body_obj["amount"])
            elif "price" in body_obj:
                ctx["spend_amount"] = float(body_obj["price"])
            # Pass all fields as potential predicate values
            ctx.update(body_obj)

        decision = self.policy_engine.evaluate_request(
            token=token,
            pop=pop,
            resource=self.resource,
            action=self.action,
            payload=body_obj,
            context=ctx,
        )

        if decision.decision != "APPROVED":
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=decision.model_dump(),
            )

        # Attach to request state for handler access
        request.state.trustmesh_decision = decision
        request.state.agent_did = pop.agent_did
        request.state.token = token
        return decision


def require_capability(
    resource: str,
    action: str,
    policy_engine: DynamicPolicyEngine,
    extract_spend_from_body: Optional[str] = None,
) -> Callable:
    """Factory creating a FastAPI dependency for route authorization."""
    return TrustMeshAuthGuard(resource, action, policy_engine, extract_spend_from_body)
