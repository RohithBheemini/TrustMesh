"""
TrustMesh Adapter for AutoGen Agents
Provides cryptographic message signing, capability verification,
and delegation chaining for AutoGen ConversableAgent conversations.
"""

from __future__ import annotations
from typing import Any, Callable, Dict, List, Optional

from trustmesh.crypto import AgentKeypair
from trustmesh.tokens import Capability, Caveat, DelegationToken, ProofOfPossession
from trustmesh.policy import DynamicPolicyEngine, PolicyDecision


class TrustMeshAutoGenAgent:
    """
    Secure Conversable Agent for AutoGen multi-agent networks.
    Ensures message exchanges are cryptographically verified and bounded by capability caveats.
    """

    def __init__(
        self,
        name: str,
        keypair: AgentKeypair,
        policy_engine: DynamicPolicyEngine,
        token: Optional[DelegationToken] = None,
        system_message: str = "You are a secure AutoGen agent operating within TrustMesh.",
    ):
        self.name = name
        self.keypair = keypair
        self.policy_engine = policy_engine
        self.token = token
        self.system_message = system_message
        self.did = keypair.did
        self.inbox: List[Dict[str, Any]] = []

    def set_token(self, token: DelegationToken) -> None:
        """Receive or update active delegation token."""
        self.token = token

    def prepare_message(
        self,
        content: str,
        resource: str,
        action: str,
        payload_data: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """
        Create a message bundle containing text content, the active delegation token,
        and a cryptographic Proof-of-Possession envelope.
        """
        if not self.token:
            raise ValueError(f"Agent '{self.name}' has no active delegation token to authenticate message")

        payload = payload_data or {"content": content}
        pop = self.token.generate_pop(
            keypair=self.keypair,
            action=action,
            resource=resource,
            payload=payload,
        )

        return {
            "sender": self.name,
            "sender_did": self.did,
            "content": content,
            "resource": resource,
            "action": action,
            "payload": payload,
            "token": self.token.model_dump(),
            "pop": pop.model_dump(),
        }

    def receive_message(
        self,
        message_bundle: Dict[str, Any],
        context: Optional[Dict[str, Any]] = None,
    ) -> PolicyDecision:
        """
        Receive an incoming message bundle and evaluate it against zero-trust policy.
        """
        token_data = message_bundle.get("token")
        pop_data = message_bundle.get("pop")
        resource = message_bundle.get("resource", "*")
        action = message_bundle.get("action", "*")
        payload = message_bundle.get("payload", {})

        if not token_data or not pop_data:
            return self.policy_engine._block(
                "ERR_MISSING_AUTH",
                "Message bundle lacks required TrustMesh token or PoP envelope",
                message_bundle.get("sender_did", "unknown"),
                resource,
                action,
            )

        token = DelegationToken.model_validate(token_data)
        pop = ProofOfPossession.model_validate(pop_data)

        decision = self.policy_engine.evaluate_request(
            token=token,
            pop=pop,
            resource=resource,
            action=action,
            payload=payload,
            context=context,
        )

        if decision.decision == "APPROVED":
            self.inbox.append(message_bundle)

        return decision
