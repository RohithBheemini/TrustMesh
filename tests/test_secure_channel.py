"""
Unit tests for TrustMesh Secure Cryptographic Channel
Verifies X25519 Key Agreement, ChaCha20-Poly1305 AEAD, and digital signature binding.
"""

import pytest
from trustmesh.crypto import AgentKeypair
from trustmesh.secure_channel import TrustMeshSecureChannel


def test_end_to_end_encryption():
    alice_kp = AgentKeypair.generate(name="Alice")
    bob_kp = AgentKeypair.generate(name="Bob")

    alice_chan = TrustMeshSecureChannel(alice_kp)
    bob_chan = TrustMeshSecureChannel(bob_kp)

    secret_message = "Confidential Prompt: Process financial transfer #9981"

    # Alice encrypts for Bob
    encrypted_envelope = alice_chan.encrypt_for(
        recipient_dh_public_bytes=bob_chan.public_dh_bytes,
        recipient_did=bob_kp.did,
        plaintext=secret_message,
        associated_data=b"session-id-42",
    )

    # Bob decrypts from Alice
    decrypted_bytes = bob_chan.decrypt_from(
        envelope=encrypted_envelope,
        associated_data=b"session-id-42",
    )

    assert decrypted_bytes.decode("utf-8") == secret_message


def test_tampered_ciphertext_fails_decryption():
    alice_kp = AgentKeypair.generate(name="Alice")
    bob_kp = AgentKeypair.generate(name="Bob")

    alice_chan = TrustMeshSecureChannel(alice_kp)
    bob_chan = TrustMeshSecureChannel(bob_kp)

    envelope = alice_chan.encrypt_for(
        recipient_dh_public_bytes=bob_chan.public_dh_bytes,
        recipient_did=bob_kp.did,
        plaintext="Classified Intelligence",
    )

    # Adversary tampers with signature
    envelope.signature = "tampered_signature"

    with pytest.raises(ValueError, match="signature verification failed"):
        bob_chan.decrypt_from(envelope)


def test_wrong_recipient_fails_decryption():
    alice_kp = AgentKeypair.generate(name="Alice")
    bob_kp = AgentKeypair.generate(name="Bob")
    eve_kp = AgentKeypair.generate(name="Eve")

    alice_chan = TrustMeshSecureChannel(alice_kp)
    bob_chan = TrustMeshSecureChannel(bob_kp)
    eve_chan = TrustMeshSecureChannel(eve_kp)

    # Encrypted for Bob
    envelope = alice_chan.encrypt_for(
        recipient_dh_public_bytes=bob_chan.public_dh_bytes,
        recipient_did=bob_kp.did,
        plaintext="Private data for Bob only",
    )

    # Eve tries to decrypt
    with pytest.raises(Exception):
        eve_chan.decrypt_from(envelope)
