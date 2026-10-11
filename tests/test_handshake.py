"""
Unit tests for TrustMesh Mutual Authentication Handshake Protocol
Verifies the 3-way challenge-response handshake between autonomous agents.
"""

from trustmesh.crypto import AgentKeypair
from trustmesh.handshake import MutualHandshakeProtocol


def test_successful_mutual_handshake():
    alice = AgentKeypair.generate(name="AliceInitiator")
    bob = AgentKeypair.generate(name="BobResponder")

    # Step 1: Alice creates HELLO
    hello = MutualHandshakeProtocol.initiate_handshake(alice)
    assert hello.verify() is True
    assert hello.initiator_did == alice.did

    # Step 2: Bob verifies HELLO and issues CHALLENGE
    challenge, valid_hello = MutualHandshakeProtocol.respond_with_challenge(hello, bob)
    assert valid_hello is True
    assert challenge.verify() is True
    assert challenge.responder_did == bob.did

    # Step 3: Alice solves Bob's CHALLENGE
    solution, valid_chal = MutualHandshakeProtocol.solve_challenge(challenge, alice)
    assert valid_chal is True

    # Step 4: Bob finalizes session
    session, success, msg = MutualHandshakeProtocol.finalize_session(solution, challenge, bob)
    assert success is True
    assert session is not None
    assert session.initiator_did == alice.did
    assert session.responder_did == bob.did
    assert session.session_id.startswith("sess_")


def test_handshake_impersonation_rejection():
    alice = AgentKeypair.generate(name="AliceInitiator")
    bob = AgentKeypair.generate(name="BobResponder")
    eve = AgentKeypair.generate(name="EveImpostor")

    hello = MutualHandshakeProtocol.initiate_handshake(alice)
    challenge, _ = MutualHandshakeProtocol.respond_with_challenge(hello, bob)

    # Eve tries to solve challenge claiming to be Alice
    bad_solution, _ = MutualHandshakeProtocol.solve_challenge(challenge, eve)
    # Tamper with claiming initiator DID
    bad_solution.initiator_did = alice.did

    session, success, msg = MutualHandshakeProtocol.finalize_session(bad_solution, challenge, bob)
    assert success is False
    assert session is None
    assert "Invalid cryptographic challenge response signature" in msg
