"""
TrustMesh HTTP & In-Memory Agent Client
Generates valid TrustMesh headers (X-TrustMesh-Token, X-TrustMesh-PoP)
and dispatches requests to other agents or microservices.
"""

from __future__ import annotations
import base64
import json
from typing import Any, Dict, Optional
import httpx

from trustmesh.crypto import AgentKeypair, canonical_json
from trustmesh.tokens import DelegationToken, ProofOfPossession


def encode_header_json(data: dict) -> str:
    """Encode dict into compact base64 string for safe HTTP header transport."""
    raw = canonical_json(data)
    return base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=")


class TrustMeshClient:
    """
    HTTP Client that attaches cryptographic Proof-of-Possession and Delegation Tokens
    to all outgoing requests.
    """

    def __init__(self, keypair: AgentKeypair, token: DelegationToken):
        self.keypair = keypair
        self.token = token

    def build_headers(
        self,
        resource: str,
        action: str,
        payload: Any = None,
        custom_nonce: Optional[str] = None,
    ) -> Dict[str, str]:
        """
        Build the required X-TrustMesh-Token and X-TrustMesh-PoP HTTP headers.
        """
        pop = self.token.generate_pop(
            keypair=self.keypair,
            action=action,
            resource=resource,
            payload=payload,
            nonce=custom_nonce,
        )
        return {
            "X-TrustMesh-Token": encode_header_json(self.token.model_dump()),
            "X-TrustMesh-PoP": encode_header_json(pop.model_dump()),
            "Content-Type": "application/json",
        }

    async def post(
        self,
        url: str,
        resource: str,
        action: str,
        json_data: Any = None,
        client: Optional[httpx.AsyncClient] = None,
    ) -> httpx.Response:
        """Execute an authenticated POST request."""
        headers = self.build_headers(resource=resource, action=action, payload=json_data)
        if client:
            return await client.post(url, json=json_data, headers=headers)
        async with httpx.AsyncClient() as default_client:
            return await default_client.post(url, json=json_data, headers=headers)
