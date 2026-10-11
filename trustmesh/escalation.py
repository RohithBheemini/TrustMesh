"""
TrustMesh Step-Up Authorization & Human-in-the-Loop Escalation Manager
Enables enterprise supervisors to cryptographically approve out-of-scope budget requests in real-time.
"""

from __future__ import annotations
import threading
import time
import uuid
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field

from trustmesh.crypto import AgentKeypair
from trustmesh.tokens import Capability, Caveat, DelegationToken


class EscalationRequest(BaseModel):
    """Pending authorization waiver request awaiting supervisor review."""
    challenge_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    agent_name: str
    invoking_agent_did: str
    action: str
    resource: str
    requested_amount: float
    current_ceiling: float
    excess_amount: float
    payload: Dict[str, Any] = Field(default_factory=dict)
    status: str = "PENDING"  # "PENDING" | "APPROVED" | "REJECTED"
    created_at: int = Field(default_factory=lambda: int(time.time()))
    resolved_at: Optional[int] = None
    resolver_did: Optional[str] = None
    waiver_token_id: Optional[str] = None


class EscalationManager:
    """
    Manages pending step-up challenges and allows supervisors to grant ephemeral capability waivers.
    """

    def __init__(self, supervisor_keypair: Optional[AgentKeypair] = None):
        self.supervisor_key: AgentKeypair = supervisor_keypair or AgentKeypair.generate(name="HumanSupervisor")
        self._pending: Dict[str, EscalationRequest] = {}
        self._history: List[EscalationRequest] = []
        self._lock = threading.RLock()

    def create_escalation(
        self,
        agent_name: str,
        invoking_agent_did: str,
        action: str,
        resource: str,
        requested_amount: float,
        current_ceiling: float,
        payload: Dict[str, Any],
    ) -> EscalationRequest:
        """Create a new step-up challenge for an out-of-scope transaction."""
        req = EscalationRequest(
            agent_name=agent_name,
            invoking_agent_did=invoking_agent_did,
            action=action,
            resource=resource,
            requested_amount=requested_amount,
            current_ceiling=current_ceiling,
            excess_amount=max(0.0, requested_amount - current_ceiling),
            payload=payload,
        )
        with self._lock:
            self._pending[req.challenge_id] = req
            self._history.append(req)
        return req

    def get_pending(self) -> List[EscalationRequest]:
        with self._lock:
            return [req for req in self._pending.values() if req.status == "PENDING"]

    def get_all(self, limit: int = 50) -> List[EscalationRequest]:
        with self._lock:
            return list(reversed(self._history[-limit:]))

    def approve_escalation(
        self,
        challenge_id: str,
        approver_keypair: Optional[AgentKeypair] = None,
        ttl_seconds: int = 1800,
    ) -> tuple[bool, Optional[DelegationToken], str]:
        """
        Supervisor approves the overspend, issuing an ephemeral single-use waiver token.
        """
        key = approver_keypair or self.supervisor_key
        with self._lock:
            req = self._pending.get(challenge_id)
            if not req:
                return False, None, "Challenge not found"
            if req.status != "PENDING":
                return False, None, f"Challenge already {req.status}"

            req.status = "APPROVED"
            req.resolved_at = int(time.time())
            req.resolver_did = key.did

            # Issue an emergency waiver capability token
            waiver_caveat = Caveat(
                max_spend=req.requested_amount,
                allowed_actions=[req.action],
                allowed_resources=[req.resource],
                expiry=int(time.time()) + ttl_seconds,
            )
            waiver_cap = Capability(resource=req.resource, action=req.action, caveats=waiver_caveat)
            waiver_token = DelegationToken(
                iss=key.did,
                aud=req.invoking_agent_did,
                capabilities=[waiver_cap],
                expires_at=int(time.time()) + ttl_seconds,
            )
            waiver_token.sign(key)
            req.waiver_token_id = waiver_token.token_id
            return True, waiver_token, "Approved: Ephemeral capability waiver stamped"

    def reject_escalation(self, challenge_id: str, reason: str = "Denied by supervisor") -> tuple[bool, str]:
        """Supervisor rejects the request."""
        with self._lock:
            req = self._pending.get(challenge_id)
            if not req:
                return False, "Challenge not found"
            if req.status != "PENDING":
                return False, f"Challenge already {req.status}"

            req.status = "REJECTED"
            req.resolved_at = int(time.time())
            req.resolver_did = self.supervisor_key.did
            return True, f"Rejected: {reason}"
