"""
Cryptographic primitives for SecureChat.

Design summary
--------------
1. Each session, both peers generate a fresh, single-use X25519 keypair
   (never persisted, never reused across sessions) and exchange raw public
   keys through the relay.
2. The ECDH shared secret is stretched with HKDF-SHA256 into a 32-byte
   root key, then split into two independent chain keys -- one per
   direction (A->B and B->A) -- so each side's outgoing messages use a
   different key stream than its incoming messages.
3. Every message advances its chain one step: HKDF derives BOTH a
   one-time message key and the next chain key from the current chain
   key. The caller then discards the old chain key. Because the KDF only
   runs forward, recovering a later chain key never lets you recompute an
   earlier one -- this is what gives the scheme forward secrecy.
4. Each message is encrypted individually with AES-256-GCM under its own
   one-time key, so messages also get integrity/authentication: a
   tampered or replayed frame fails to decrypt.
"""

import os

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric.x25519 import (
    X25519PrivateKey,
    X25519PublicKey,
)
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF


def generate_ephemeral_keypair():
    """Generate a fresh X25519 keypair. Never reuse this across sessions."""
    private_key = X25519PrivateKey.generate()
    return private_key, private_key.public_key()


def public_key_to_bytes(public_key: X25519PublicKey) -> bytes:
    return public_key.public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )


def public_key_from_bytes(data: bytes) -> X25519PublicKey:
    return X25519PublicKey.from_public_bytes(data)


def _hkdf(key_material: bytes, info: bytes, length: int = 32) -> bytes:
    return HKDF(
        algorithm=hashes.SHA256(),
        length=length,
        salt=None,
        info=info,
    ).derive(key_material)


def derive_root_key(private_key: X25519PrivateKey, peer_public_key: X25519PublicKey) -> bytes:
    """Run ECDH, then stretch the shared secret into a 32-byte root key."""
    shared_secret = private_key.exchange(peer_public_key)
    return _hkdf(shared_secret, info=b"securechat-root-key")


def derive_chains(root_key: bytes, is_initiator: bool):
    """
    Split one root key into two independent, direction-specific chain
    keys. Both peers derive both chains identically; each peer just
    labels them "send" vs "receive" based on who initiated the session,
    so a message encrypted on A's send-chain lands on B's matching
    receive-chain.
    """
    chain_a_to_b = _hkdf(root_key, info=b"chain-a-to-b")
    chain_b_to_a = _hkdf(root_key, info=b"chain-b-to-a")
    if is_initiator:
        return chain_a_to_b, chain_b_to_a  # send, receive
    return chain_b_to_a, chain_a_to_b      # send, receive


def ratchet_step(chain_key: bytes):
    """
    Advance a chain by one step.

    Returns (message_key, next_chain_key). The caller MUST overwrite its
    stored chain key with next_chain_key and never reuse the old value --
    that discard is what provides forward secrecy.
    """
    message_key = _hkdf(chain_key, info=b"message-key")
    next_chain_key = _hkdf(chain_key, info=b"next-chain-key")
    return message_key, next_chain_key


def encrypt(message_key: bytes, plaintext: bytes) -> bytes:
    """AES-256-GCM encrypt. Returns nonce (12 bytes) || ciphertext+tag."""
    aesgcm = AESGCM(message_key)
    nonce = os.urandom(12)
    return nonce + aesgcm.encrypt(nonce, plaintext, None)


def decrypt(message_key: bytes, data: bytes) -> bytes:
    """Inverse of encrypt(). Raises InvalidTag if authentication fails."""
    aesgcm = AESGCM(message_key)
    nonce, ciphertext = data[:12], data[12:]
    return aesgcm.decrypt(nonce, ciphertext, None)
