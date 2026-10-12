"""
Tests for Linux Foundation A2A (Agent-to-Agent) Signed Agent Cards.
Validates RFC 8785 canonical signing, Ed25519 verification, and anti-tamper detection.
"""

import pytest
from trustmesh.crypto import AgentKeypair
from trustmesh.agent_card import AgentCard, AgentSkill, create_agent_card


def test_create_and_verify_agent_card():
    kp = AgentKeypair.generate(name="ServiceAgent")
    skills = [
        AgentSkill(
            id="sk_flight",
            name="Flight Booking",
            description="Book airline tickets",
            resource="travel:flights:book",
            allowed_actions=["book"],
        )
    ]
    card = create_agent_card(
        keypair=kp,
        name="Service Agent Alpha",
        description="Enterprise travel procurement agent",
        endpoint_url="https://agent.enterprise.internal",
        skills=skills,
    )

    assert card.agent_did == kp.did
    assert card.public_key_hex == kp.public_bytes.hex()
    assert len(card.signature) > 0
    assert card.verify() is True


def test_agent_card_tampering_detected():
    kp = AgentKeypair.generate(name="TamperTest")
    card = create_agent_card(
        keypair=kp,
        name="Authentic Agent",
        description="Legitimate agent description",
        endpoint_url="https://authentic.example.com",
    )
    assert card.verify() is True

    # Tamper with endpoint
    card.endpoint_url = "https://evil-spoof.example.com"
    assert card.verify() is False

    # Tamper with name
    card.endpoint_url = "https://authentic.example.com"
    card.name = "Malicious Impersonator"
    assert card.verify() is False


def test_agent_card_keypair_mismatch():
    kp1 = AgentKeypair.generate(name="Agent1")
    kp2 = AgentKeypair.generate(name="Agent2")

    card = AgentCard(
        name="Mismatch Test",
        description="Testing key mismatch",
        agent_did=kp1.did,
        public_key_hex=kp1.public_bytes.hex(),
        endpoint_url="https://test.internal",
    )

    # Attempting to sign with kp2 when agent_did is kp1 must raise ValueError
    with pytest.raises(ValueError, match="does not match AgentCard DID"):
        card.sign(kp2)


def test_agent_card_serialization_roundtrip():
    kp = AgentKeypair.generate(name="Serializer")
    card = create_agent_card(
        keypair=kp,
        name="Serializer Agent",
        description="Test serialization",
        endpoint_url="https://serializer.internal",
    )
    dumped = card.model_dump()
    loaded = AgentCard.model_validate(dumped)
    assert loaded.agent_did == card.agent_did
    assert loaded.signature == card.signature
    assert loaded.verify() is True
