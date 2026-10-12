"""
Tests for TrustMesh Merkle Audit Tree (RFC 6962 / Transparency Log Standard).
Validates append-only immutability, root updates, O(log N) inclusion proofs, and tamper detection.
"""

from trustmesh.merkle_audit import MerkleAuditTree


def test_merkle_tree_empty():
    tree = MerkleAuditTree()
    assert tree.total_leaves == 0
    # Empty tree root is sha256 of empty bytes
    assert len(tree.get_root_hash()) == 64


def test_merkle_tree_append_and_root_update():
    tree = MerkleAuditTree()
    idx1, leaf1 = tree.append_decision({"decision": "APPROVED", "code": "AUTH_OK", "id": 1})
    assert idx1 == 0
    root1 = tree.get_root_hash()
    assert len(root1) == 64

    idx2, leaf2 = tree.append_decision({"decision": "BLOCKED", "code": "ERR_REPLAY_ATTACK", "id": 2})
    assert idx2 == 1
    root2 = tree.get_root_hash()
    assert root1 != root2  # Root changes on every new append
    assert tree.total_leaves == 2


def test_merkle_tree_inclusion_proof_verification():
    tree = MerkleAuditTree()
    for i in range(7):
        tree.append_decision({"event_id": i, "status": "APPROVED", "amount": 100.0 * i})

    assert tree.total_leaves == 7
    root = tree.get_root_hash()

    # Verify inclusion proof for every single leaf
    for i in range(7):
        proof = tree.generate_inclusion_proof(i)
        assert proof is not None
        assert proof.leaf_index == i
        assert proof.total_leaves == 7
        assert proof.merkle_root == root
        assert proof.verify() is True


def test_merkle_proof_tampering_detected():
    tree = MerkleAuditTree()
    for i in range(4):
        tree.append_decision({"action": "transfer", "amount": 500 + i})

    proof = tree.generate_inclusion_proof(1)
    assert proof.verify() is True

    # Tamper with leaf hash
    tampered_leaf = proof.model_copy(update={"leaf_hash": "deadbeef" * 8})
    assert tampered_leaf.verify() is False

    # Tamper with root
    tampered_root = proof.model_copy(update={"merkle_root": "00000000" * 8})
    assert tampered_root.verify() is False

    # Tamper with audit path sibling
    if proof.audit_path:
        bad_steps = list(proof.audit_path)
        bad_steps[0] = bad_steps[0].model_copy(update={"sibling_hash": "11111111" * 8})
        tampered_path = proof.model_copy(update={"audit_path": bad_steps})
        assert tampered_path.verify() is False


def test_merkle_invalid_index():
    tree = MerkleAuditTree()
    tree.append_decision({"test": "data"})
    assert tree.generate_inclusion_proof(-1) is None
    assert tree.generate_inclusion_proof(999) is None
    assert tree.get_leaf_record(999) is None
    assert tree.get_leaf_record(0) == {"test": "data"}
