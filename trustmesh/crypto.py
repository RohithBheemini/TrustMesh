"""
TrustMesh Cryptographic Primitives
Provides Ed25519 key management, W3C did:key format encoding/decoding,
canonical JSON serialization (RFC 8785), SHA-256 payload hashing,
and digital signature creation and verification.
"""

import base64
import hashlib
import json
from typing import Any
from cryptography.hazmat.primitives.asymmetric import ed25519
from cryptography.hazmat.primitives import serialization

# Base58 Bitcoin alphabet
B58_ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"


def b58encode(data: bytes) -> str:
    """Encode bytes using Base58 Bitcoin encoding."""
    num = int.from_bytes(data, "big")
    chars = []
    while num > 0:
        num, rem = divmod(num, 58)
        chars.append(B58_ALPHABET[rem])
    encoded = "".join(reversed(chars))

    # Handle leading zero bytes
    pad = 0
    for byte in data:
        if byte == 0:
            pad += 1
        else:
            break
    return (B58_ALPHABET[0] * pad) + encoded


def b58decode(data: str) -> bytes:
    """Decode a Base58 Bitcoin string to bytes."""
    num = 0
    for char in data:
        idx = B58_ALPHABET.find(char)
        if idx == -1:
            raise ValueError(f"Invalid Base58 character: {char}")
        num = num * 58 + idx

    # Calculate raw bytes
    raw_bytes = bytearray()
    while num > 0:
        num, rem = divmod(num, 256)
        raw_bytes.append(rem)
    raw_bytes.reverse()

    # Prepend leading zeros
    pad = 0
    for char in data:
        if char == B58_ALPHABET[0]:
            pad += 1
        else:
            break
    return bytes([0] * pad) + bytes(raw_bytes)


# Multicodec prefix for Ed25519 public key is 0xed01 (varint: 0xed, 0x01)
ED25519_MULTICODEC_PREFIX = bytes([0xed, 0x01])


def pubkey_to_did(public_bytes: bytes) -> str:
    """
    Encode a 32-byte Ed25519 raw public key into a W3C did:key string.
    Example: did:key:z6Mku...
    """
    if len(public_bytes) != 32:
        raise ValueError(f"Ed25519 public key must be 32 bytes, got {len(public_bytes)}")
    prefixed = ED25519_MULTICODEC_PREFIX + public_bytes
    encoded = b58encode(prefixed)
    return f"did:key:z{encoded}"


def did_to_pubkey(did: str) -> bytes:
    """
    Decode a did:key:z... string to raw 32-byte Ed25519 public key.
    """
    if not did.startswith("did:key:z"):
        raise ValueError(f"Unsupported or malformed DID: {did}")
    mb_str = did[len("did:key:z"):]
    raw = b58decode(mb_str)
    if not raw.startswith(ED25519_MULTICODEC_PREFIX):
        raise ValueError("DID does not contain Ed25519 multicodec prefix (0xed01)")
    pubkey = raw[len(ED25519_MULTICODEC_PREFIX):]
    if len(pubkey) != 32:
        raise ValueError(f"Decoded public key length mismatch: {len(pubkey)} != 32")
    return pubkey


def canonical_json(data: Any) -> bytes:
    """
    Deterministically serialize a Python dict/data structure to JSON bytes
    following RFC 8785 (JSON Canonicalization Scheme - JCS).
    """
    return json.dumps(
        data,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")


def hash_payload(data: Any) -> str:
    """
    Generate SHA-256 hash hex digest of arbitrary request payload using JCS.
    """
    if data is None:
        c_bytes = b""
    elif isinstance(data, (bytes, bytearray)):
        c_bytes = bytes(data)
    elif isinstance(data, str):
        c_bytes = data.encode("utf-8")
    else:
        c_bytes = canonical_json(data)
    return hashlib.sha256(c_bytes).hexdigest()


class AgentKeypair:
    """
    Cryptographic keypair representing an autonomous agent's identity.
    Uses Ed25519 for high-speed, secure digital signatures and zero-trust verification.
    """

    def __init__(self, private_key: ed25519.Ed25519PrivateKey | None = None, name: str = "AnonymousAgent"):
        if private_key is None:
            self._private_key = ed25519.Ed25519PrivateKey.generate()
        else:
            self._private_key = private_key
        
        self.name = name
        self._public_key = self._private_key.public_key()
        self._raw_public = self._public_key.public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw,
        )
        self.did = pubkey_to_did(self._raw_public)

    @classmethod
    def generate(cls, name: str = "AnonymousAgent") -> "AgentKeypair":
        """Generate a new random Ed25519 AgentKeypair."""
        return cls(private_key=ed25519.Ed25519PrivateKey.generate(), name=name)

    @classmethod
    def from_seed(cls, seed: bytes, name: str = "AnonymousAgent") -> "AgentKeypair":
        """Deterministically derive an AgentKeypair from a 32-byte seed."""
        if len(seed) != 32:
            seed = hashlib.sha256(seed).digest()
        priv = ed25519.Ed25519PrivateKey.from_private_bytes(seed)
        return cls(private_key=priv, name=name)

    def sign(self, message: bytes) -> str:
        """Sign a message and return the signature encoded as base64 URL-safe string."""
        sig_bytes = self._private_key.sign(message)
        return base64.urlsafe_b64encode(sig_bytes).decode("ascii").rstrip("=")

    @property
    def public_bytes(self) -> bytes:
        return self._raw_public

    def to_dict(self) -> dict:
        return {
            "name": self.name,
            "did": self.did,
            "public_bytes_hex": self.public_bytes.hex(),
        }


def verify_signature(did: str, message: bytes, signature_b64: str) -> bool:
    """
    Verify an Ed25519 signature against an agent's did:key identifier.
    Returns True if valid, False otherwise.
    """
    try:
        raw_pub = did_to_pubkey(did)
        pub_key = ed25519.Ed25519PublicKey.from_public_bytes(raw_pub)

        # Pad base64 signature if needed
        sig_str = signature_b64
        missing_padding = len(sig_str) % 4
        if missing_padding:
            sig_str += "=" * (4 - missing_padding)
        sig_bytes = base64.urlsafe_b64decode(sig_str)

        pub_key.verify(sig_bytes, message)
        return True
    except Exception:
        return False
