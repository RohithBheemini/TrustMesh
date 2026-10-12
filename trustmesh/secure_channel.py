"""
TrustMesh Secure Cryptographic Channel
Provides Authenticated Encryption with Associated Data (AEAD) using ChaCha20-Poly1305
and X25519 Diffie-Hellman Key Exchange for confidential, tamper-proof agent communication.
"""

from __future__ import annotations
import base64
import os
import time
from cryptography.hazmat.primitives.asymmetric import x25519
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes
from pydantic import BaseModel, Field

from trustmesh.crypto import AgentKeypair, canonical_json, verify_signature


class EncryptedPayload(BaseModel):
    """Encrypted envelope containing ciphertext, nonce, and sender verification."""
    sender_did: str
    recipient_did: str
    ephemeral_public_key_b64: str
    nonce_b64: str
    ciphertext_b64: str
    timestamp: int = Field(default_factory=lambda: int(time.time()))
    signature: str = ""

    def to_signable_dict(self) -> dict:
        d = self.model_dump()
        d.pop("signature", None)
        return d

    def sign(self, sender_signing_key: AgentKeypair) -> None:
        raw = canonical_json(self.to_signable_dict())
        self.signature = sender_signing_key.sign(raw)

    def verify(self) -> bool:
        if not self.signature:
            return False
        raw = canonical_json(self.to_signable_dict())
        return verify_signature(self.sender_did, raw, self.signature)


class TrustMeshSecureChannel:
    """
    End-to-End Encrypted Agent Channel.
    Uses X25519 Key Agreement + HKDF + ChaCha20-Poly1305 AEAD,
    bound with Ed25519 digital signatures.
    """

    def __init__(self, agent_signing_key: AgentKeypair):
        self.signing_key = agent_signing_key
        # Ephemeral X25519 key for DH key agreement
        self.dh_private = x25519.X25519PrivateKey.generate()
        self.dh_public = self.dh_private.public_key()

    @property
    def public_dh_bytes(self) -> bytes:
        return self.dh_public.public_bytes_raw()

    def encrypt_for(
        self,
        recipient_dh_public_bytes: bytes,
        recipient_did: str,
        plaintext: bytes | str,
        associated_data: bytes = b"",
    ) -> EncryptedPayload:
        """
        Encrypt a message for a target agent using their X25519 public key.
        """
        if isinstance(plaintext, str):
            data_bytes = plaintext.encode("utf-8")
        else:
            data_bytes = plaintext

        peer_pub = x25519.X25519PublicKey.from_public_bytes(recipient_dh_public_bytes)
        shared_secret = self.dh_private.exchange(peer_pub)

        # Derive 32-byte symmetric key via HKDF-SHA256
        hkdf = HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=None,
            info=b"TrustMesh-ChaCha20Poly1305-AEAD",
        )
        sym_key = hkdf.derive(shared_secret)

        # ChaCha20-Poly1305 encryption
        nonce = os.urandom(12)
        cipher = ChaCha20Poly1305(sym_key)
        ciphertext = cipher.encrypt(nonce, data_bytes, associated_data)

        envelope = EncryptedPayload(
            sender_did=self.signing_key.did,
            recipient_did=recipient_did,
            ephemeral_public_key_b64=base64.urlsafe_b64encode(self.public_dh_bytes).decode("ascii").rstrip("="),
            nonce_b64=base64.urlsafe_b64encode(nonce).decode("ascii").rstrip("="),
            ciphertext_b64=base64.urlsafe_b64encode(ciphertext).decode("ascii").rstrip("="),
        )
        envelope.sign(self.signing_key)
        return envelope

    def decrypt_from(
        self,
        envelope: EncryptedPayload,
        associated_data: bytes = b"",
    ) -> bytes:
        """
        Decrypt and verify an incoming encrypted envelope.
        """
        # 1. Verify digital signature of the envelope against sender DID
        if not envelope.verify():
            raise ValueError(f"Envelope digital signature verification failed for sender {envelope.sender_did}")

        # 2. Reconstruct peer public key
        ephemeral_str = envelope.ephemeral_public_key_b64
        ephemeral_str += "=" * ((4 - len(ephemeral_str) % 4) % 4)
        peer_dh_bytes = base64.urlsafe_b64decode(ephemeral_str)

        peer_pub = x25519.X25519PublicKey.from_public_bytes(peer_dh_bytes)
        shared_secret = self.dh_private.exchange(peer_pub)

        # 3. Derive symmetric key
        hkdf = HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=None,
            info=b"TrustMesh-ChaCha20Poly1305-AEAD",
        )
        sym_key = hkdf.derive(shared_secret)

        # 4. Decrypt with ChaCha20-Poly1305
        nonce_str = envelope.nonce_b64 + ("=" * ((4 - len(envelope.nonce_b64) % 4) % 4))
        nonce = base64.urlsafe_b64decode(nonce_str)

        ct_str = envelope.ciphertext_b64 + ("=" * ((4 - len(envelope.ciphertext_b64) % 4) % 4))
        ciphertext = base64.urlsafe_b64decode(ct_str)

        cipher = ChaCha20Poly1305(sym_key)
        return cipher.decrypt(nonce, ciphertext, associated_data)
