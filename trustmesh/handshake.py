"""
TrustMesh Agent-to-Agent Mutual Authentication Handshake
Implements cryptographic challenge-response protocol for mutual verification
between autonomous AI agents before exchanging sensitive requests or capabilities.
"""

from __future__ import annotations
import secrets
import time
import uuid
from typing import Optional, Tuple
from pydantic import BaseModel, Field

from trustmesh.crypto import (
    AgentKeypair,
    canonical_json,
    verify_signature,
)


class HelloMessage(BaseModel):
    """Initial handshake message sent by Agent A (Initiator)."""
    initiator_did: str
    nonce: str = Field(default_factory=lambda: secrets.token_hex(16))
    timestamp: int = Field(default_factory=lambda: int(time.time()))
    signature: str = ""

    def sign(self, keypair: AgentKeypair) -> None:
        if keypair.did != self.initiator_did:
            raise ValueError("Keypair DID mismatch")
        payload = canonical_json({
            "type": "HELLO",
            "initiator_did": self.initiator_did,
            "nonce": self.nonce,
            "timestamp": self.timestamp,
        })
        self.signature = keypair.sign(payload)

    def verify(self) -> bool:
        if not self.signature:
            return False
        payload = canonical_json({
            "type": "HELLO",
            "initiator_did": self.initiator_did,
            "nonce": self.nonce,
            "timestamp": self.timestamp,
        })
        return verify_signature(self.initiator_did, payload, self.signature)


class ChallengeMessage(BaseModel):
    """Challenge message returned by Agent B (Responder)."""
    responder_did: str
    initiator_nonce: str
    challenge_nonce: str = Field(default_factory=lambda: secrets.token_hex(16))
    challenge_payload: str = Field(default_factory=lambda: secrets.token_hex(32))
    timestamp: int = Field(default_factory=lambda: int(time.time()))
    signature: str = ""

    def sign(self, keypair: AgentKeypair) -> None:
        if keypair.did != self.responder_did:
            raise ValueError("Keypair DID mismatch")
        payload = canonical_json({
            "type": "CHALLENGE",
            "responder_did": self.responder_did,
            "initiator_nonce": self.initiator_nonce,
            "challenge_nonce": self.challenge_nonce,
            "challenge_payload": self.challenge_payload,
            "timestamp": self.timestamp,
        })
        self.signature = keypair.sign(payload)

    def verify(self) -> bool:
        if not self.signature:
            return False
        payload = canonical_json({
            "type": "CHALLENGE",
            "responder_did": self.responder_did,
            "initiator_nonce": self.initiator_nonce,
            "challenge_nonce": self.challenge_nonce,
            "challenge_payload": self.challenge_payload,
            "timestamp": self.timestamp,
        })
        return verify_signature(self.responder_did, payload, self.signature)


class AuthResponseMessage(BaseModel):
    """Signed response proving possession of the private key for Initiator."""
    initiator_did: str
    responder_did: str
    challenge_nonce: str
    challenge_solution: str = ""
    timestamp: int = Field(default_factory=lambda: int(time.time()))

    def sign(self, keypair: AgentKeypair, challenge_payload: str) -> None:
        if keypair.did != self.initiator_did:
            raise ValueError("Keypair DID mismatch")
        payload = canonical_json({
            "type": "SOLUTION",
            "challenge_nonce": self.challenge_nonce,
            "challenge_payload": challenge_payload,
            "timestamp": self.timestamp,
        })
        self.challenge_solution = keypair.sign(payload)

    def verify(self, challenge_payload: str) -> bool:
        if not self.challenge_solution:
            return False
        payload = canonical_json({
            "type": "SOLUTION",
            "challenge_nonce": self.challenge_nonce,
            "challenge_payload": challenge_payload,
            "timestamp": self.timestamp,
        })
        return verify_signature(self.initiator_did, payload, self.challenge_solution)


class EstablishedSession(BaseModel):
    """Established mutual trust session between two agents."""
    session_id: str
    initiator_did: str
    responder_did: str
    established_at: int
    expires_at: int
    session_token: str


class MutualHandshakeProtocol:
    """
    Executes or verifies a 3-way mutual authentication handshake between two AI agents.
    """

    @staticmethod
    def initiate_handshake(initiator_keypair: AgentKeypair) -> HelloMessage:
        """Step 1: Agent A creates and signs HELLO message."""
        hello = HelloMessage(initiator_did=initiator_keypair.did)
        hello.sign(initiator_keypair)
        return hello

    @staticmethod
    def respond_with_challenge(
        hello: HelloMessage,
        responder_keypair: AgentKeypair,
    ) -> Tuple[ChallengeMessage, bool]:
        """Step 2: Agent B verifies HELLO and creates signed CHALLENGE."""
        if not hello.verify():
            return None, False  # type: ignore
        challenge = ChallengeMessage(
            responder_did=responder_keypair.did,
            initiator_nonce=hello.nonce,
        )
        challenge.sign(responder_keypair)
        return challenge, True

    @staticmethod
    def solve_challenge(
        challenge: ChallengeMessage,
        initiator_keypair: AgentKeypair,
    ) -> Tuple[AuthResponseMessage, bool]:
        """Step 3: Agent A verifies CHALLENGE and signs the solution."""
        if not challenge.verify():
            return None, False  # type: ignore
        resp = AuthResponseMessage(
            initiator_did=initiator_keypair.did,
            responder_did=challenge.responder_did,
            challenge_nonce=challenge.challenge_nonce,
        )
        resp.sign(initiator_keypair, challenge.challenge_payload)
        return resp, True

    @staticmethod
    def finalize_session(
        auth_response: AuthResponseMessage,
        challenge: ChallengeMessage,
        responder_keypair: AgentKeypair,
        ttl_seconds: int = 3600,
    ) -> Tuple[Optional[EstablishedSession], bool, str]:
        """Step 4: Agent B validates response and issues mutual EstablishedSession."""
        if not auth_response.verify(challenge.challenge_payload):
            return None, False, "Invalid cryptographic challenge response signature"
        
        now = int(time.time())
        session_id = f"sess_{uuid.uuid4().hex[:16]}"
        raw_token_data = canonical_json({
            "session_id": session_id,
            "initiator_did": auth_response.initiator_did,
            "responder_did": responder_keypair.did,
            "established_at": now,
            "expires_at": now + ttl_seconds,
        })
        token_sig = responder_keypair.sign(raw_token_data)

        session = EstablishedSession(
            session_id=session_id,
            initiator_did=auth_response.initiator_did,
            responder_did=responder_keypair.did,
            established_at=now,
            expires_at=now + ttl_seconds,
            session_token=token_sig,
        )
        return session, True, "Mutual trust established successfully"
