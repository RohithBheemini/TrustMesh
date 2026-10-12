"""
Unit tests for TrustMesh Cryptographic Primitives
Verifies Ed25519 key generation, did:key W3C encoding/decoding, RFC 8785 canonical JSON, and digital signatures.
"""

from trustmesh.crypto import (
    AgentKeypair,
    pubkey_to_did,
    did_to_pubkey,
    canonical_json,
    hash_payload,
    verify_signature,
    b58encode,
    b58decode,
)


def test_base58_roundtrip():
    data = b"Hello, TrustMesh Cryptography!"
    encoded = b58encode(data)
    decoded = b58decode(encoded)
    assert decoded == data


def test_did_key_roundtrip():
    keypair = AgentKeypair.generate(name="TestAgent")
    assert keypair.did.startswith("did:key:z6Mk")
    pub_bytes = did_to_pubkey(keypair.did)
    assert pub_bytes == keypair.public_bytes
    assert pubkey_to_did(pub_bytes) == keypair.did


def test_ed25519_sign_and_verify():
    alice = AgentKeypair.generate(name="Alice")
    message = b"Authorize transfer of $500 to Bob"
    signature = alice.sign(message)
    assert len(signature) > 0
    # Valid signature
    assert verify_signature(alice.did, message, signature) is True
    # Tampered message
    assert verify_signature(alice.did, b"Authorize transfer of $9000 to Eve", signature) is False
    # Wrong public key
    bob = AgentKeypair.generate(name="Bob")
    assert verify_signature(bob.did, message, signature) is False


def test_rfc8785_canonical_json():
    # Order of keys must be deterministic
    dict_a = {"z": 1, "a": 2, "m": {"b": 3, "a": 4}}
    dict_b = {"a": 2, "m": {"a": 4, "b": 3}, "z": 1}
    assert canonical_json(dict_a) == canonical_json(dict_b)
    # Ensure compact separators (no spaces after comma or colon)
    assert canonical_json({"k": "v"}) == b'{"k":"v"}'


def test_payload_hashing():
    payload_1 = {"user": "Alice", "amount": 100}
    payload_2 = {"amount": 100, "user": "Alice"}
    # Because of JCS canonicalization, different key orders yield identical hash
    assert hash_payload(payload_1) == hash_payload(payload_2)
    # Different content produces different hash
    assert hash_payload(payload_1) != hash_payload({"user": "Bob", "amount": 100})


def test_agent_keypair_from_seed():
    seed = b"32_byte_secret_seed_for_agent_01"
    kp1 = AgentKeypair.from_seed(seed, name="DeterministicAgent1")
    kp2 = AgentKeypair.from_seed(seed, name="DeterministicAgent2")
    assert kp1.did == kp2.did
    assert kp1.public_bytes == kp2.public_bytes
