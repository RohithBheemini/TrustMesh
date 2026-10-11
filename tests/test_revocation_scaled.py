"""
Unit tests for Scalable BloomRevocationRegistry and RevocationReceipts
Verifies zero false negatives, capacity handling, and cryptographic disavowal proofs.
"""

from trustmesh.crypto import AgentKeypair
from trustmesh.revocation import BloomRevocationRegistry, RevocationReceipt


def test_bloom_revocation_and_receipts():
    authority = AgentKeypair.generate(name="EnterpriseTrustAdmin")
    registry = BloomRevocationRegistry(size_bits=50000, num_hashes=5, authority_key=authority)

    # Initially not revoked
    target_did = "did:key:z6MkVendorCompromisedAgent123"
    assert registry.is_revoked(target_did) is False

    # Issue revocation
    receipt = registry.revoke(target_did, target_type="AGENT", reason="Private key leaked in public GitHub repo")
    assert receipt.verify() is True
    assert receipt.target_id == target_did
    assert receipt.authority_did == authority.did

    # Now is_revoked returns True
    assert registry.is_revoked(target_did) is True

    # Other agents are not revoked
    innocent_did = "did:key:z6MkInnocentWorkerAgent456"
    assert registry.is_revoked(innocent_did) is False


def test_multiple_token_revocations():
    registry = BloomRevocationRegistry(size_bits=20000)
    tokens = [f"token-uuid-{i}" for i in range(200)]

    for tok in tokens:
        registry.revoke(tok, target_type="TOKEN")

    # Assert zero false negatives across all 200 revoked tokens
    for tok in tokens:
        assert registry.is_revoked(tok) is True
